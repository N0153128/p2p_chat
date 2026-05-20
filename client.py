import os
import socket
import threading
import struct
import random
import sys
import signal
from colorama import Fore, Style
from time import sleep, time


DISCOVERY_PORT     = 8547       # well-known port used only for LAN beacon broadcast
BROADCAST_INTERVAL = 1          # seconds between LAN discovery beacons
BROADCAST_TIMEOUT  = 30         # seconds to wait for a peer on LAN
PUNCH_INTERVAL     = 0.5
PUNCH_TIMEOUT      = 30
PUNCH_MSG          = b'__punch__'
PUNCH_ACK          = b'__punch_ack__'
DISCONNECT_MSG     = b'__disconnect__'
# Beacon format: b'__beacon__:<session_id>:<chat_port>'
# session_id  — random per run, used to ignore our own broadcast echo
# chat_port   — the sender's main chat socket port, so the peer knows where to send
BEACON_PREFIX      = b'__beacon__:'
SESSION_ID         = '%08x' % random.randint(0, 0xFFFFFFFF)


def stun_get_external(sock, stun_host='stun.l.google.com', stun_port=19302):
    old_timeout = sock.gettimeout()
    sock.settimeout(5)
    try:
        tid = struct.pack('!12B', *[random.randint(0, 255) for _ in range(12)])
        msg = struct.pack('!HHI12s', 0x0001, 0, 0x2112A442, tid)
        sock.sendto(msg, (stun_host, stun_port))
        try:
            data, _ = sock.recvfrom(2048)
        except (TimeoutError, ConnectionRefusedError, OSError):
            return None, None
        i = 20
        while i < len(data):
            attr_type, attr_len = struct.unpack('!HH', data[i:i+4])
            val = data[i+4:i+4+attr_len]
            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                port = struct.unpack('!H', bytes(b ^ m for b, m in zip(val[2:4], b'\x21\x12')))[0]
                ip = '.'.join(str(b ^ m) for b, m in zip(val[4:8], struct.pack('!I', 0x2112A442)))
                return ip, port
            if attr_type == 0x0001:  # MAPPED-ADDRESS
                port = struct.unpack('!H', val[2:4])[0]
                ip = '.'.join(str(b) for b in val[4:8])
                return ip, port
            i += 4 + attr_len + (attr_len % 4 and 4 - attr_len % 4)
    finally:
        sock.settimeout(old_timeout)
    return None, None


def _is_local(ip):
    """Return True if ip is on the same /24 subnet as local_ip, or is loopback."""
    if ip == '127.0.0.1' or ip == local_ip:
        return True
    return ip.rsplit('.', 1)[0] == local_ip.rsplit('.', 1)[0]


def _broadcast_addr():
    """Return the /24 broadcast address for local_ip (e.g. 192.168.1.255)."""
    return local_ip.rsplit('.', 1)[0] + '.255'


print_lock = threading.Lock()


def print_msg(msg):
    with print_lock:
        sys.stdout.write(f'\r{" " * 80}\r')
        print(Fore.LIGHTGREEN_EX + Style.BRIGHT + msg)
        sys.stdout.write('> ')
        sys.stdout.flush()


def lan_discover(chat_port):
    """
    Broadcast beacons on DISCOVERY_PORT using a temporary socket, return (ip, port)
    of the discovered peer's chat socket.

    Each beacon embeds our session ID (to filter our own echo) and our chat_port
    so the peer knows which port to connect to — critical when both peers run on
    the same machine and can't share a single port.
    """
    # Separate discovery socket bound to the well-known port so peers can find us.
    # SO_REUSEADDR lets both peers bind the same discovery port on the same machine.
    disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    disc.bind(('0.0.0.0', DISCOVERY_PORT))
    disc.settimeout(BROADCAST_INTERVAL)

    broadcast = _broadcast_addr()
    my_beacon = BEACON_PREFIX + f'{SESSION_ID}:{chat_port}'.encode()

    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Scanning local network for a peer...')
    deadline = time() + BROADCAST_TIMEOUT
    try:
        while time() < deadline:
            try:
                disc.sendto(my_beacon, (broadcast, DISCOVERY_PORT))
            except Exception:
                pass
            try:
                data, addr = disc.recvfrom(4096)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return None

            if not data.startswith(BEACON_PREFIX):
                continue
            payload = data[len(BEACON_PREFIX):].decode(errors='ignore')
            parts = payload.split(':')
            if len(parts) != 2:
                continue
            peer_sid, peer_port_str = parts
            if peer_sid == SESSION_ID:
                continue  # our own echo

            try:
                peer_port = int(peer_port_str)
            except ValueError:
                continue

            # Reply so the other side exits its loop too.
            try:
                disc.sendto(my_beacon, addr)
            except Exception:
                pass

            return (addr[0], peer_port)
    finally:
        disc.close()
    return None


class UDPClient:

    def __init__(self, ip, sock, port):
        self.sock = sock
        self.remote = (ip, port)
        self.connected = threading.Event()
        self.done = threading.Event()

        signal.signal(signal.SIGINT, self._handle_sigint)

        if _is_local(ip):
            self.connected.set()
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Connected!')
        else:
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Punching through NAT...')
            punch_thread = threading.Thread(target=self._punch)
            punch_thread.daemon = True
            punch_thread.start()

            if not self.connected.wait(timeout=PUNCH_TIMEOUT):
                print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: timed out.')
                print('Your peer may be behind Symmetric NAT, or started too late.')
                return

        send_thread = threading.Thread(target=self._send_loop)
        send_thread.daemon = True
        send_thread.start()

        self._recv_loop()

    def _handle_sigint(self, sig, frame):
        try:
            self.sock.sendto(DISCONNECT_MSG, self.remote)
        except Exception:
            pass
        print()
        self.done.set()
        sys.exit(0)

    def _punch(self):
        deadline = time() + PUNCH_TIMEOUT
        while not self.connected.is_set() and time() < deadline:
            try:
                self.sock.sendto(PUNCH_MSG, self.remote)
            except Exception:
                pass
            sleep(PUNCH_INTERVAL)

    def _recv_loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                break

            if data.startswith(BEACON_PREFIX):
                continue  # stray discovery beacon, ignore

            if data == PUNCH_MSG:
                try:
                    self.sock.sendto(PUNCH_ACK, self.remote)
                except Exception:
                    pass
                if not self.connected.is_set():
                    self.connected.set()
                    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Connected!')
                continue

            if data == PUNCH_ACK:
                if not self.connected.is_set():
                    self.connected.set()
                    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Connected!')
                continue

            if data == DISCONNECT_MSG:
                with print_lock:
                    sys.stdout.write(f'\r{" " * 80}\r')
                    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + 'Peer disconnected.')
                    sys.stdout.flush()
                self.done.set()
                try:
                    os.write(sys.stdin.fileno(), b'\n')
                except Exception:
                    pass
                break

            print_msg(data.decode('utf-8', errors='replace'))

    def _send_loop(self):
        self.connected.wait()
        try:
            self.sock.sendto(f'{username} connected'.encode(), self.remote)
        except Exception:
            pass
        try:
            while not self.done.is_set():
                with print_lock:
                    sys.stdout.write('> ')
                    sys.stdout.flush()
                msg = sys.stdin.readline().rstrip('\n')
                if self.done.is_set():
                    break
                if msg:
                    self.sock.sendto(f'<{username}>: {msg}'.encode('utf-8'), self.remote)
        except (KeyboardInterrupt, EOFError):
            pass


if __name__ == '__main__':
    username = input('Type your name: ')

    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect(('8.8.8.8', 80))
        local_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        local_ip = '127.0.0.1'

    # Chat socket binds to a unique OS-assigned port per instance.
    # This avoids port conflicts when two peers run on the same machine.
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock.bind(('0.0.0.0', 0))
    _chat_port = _sock.getsockname()[1]

    ext_ip, _ = stun_get_external(_sock)
    print(f'Your public IP (internet): {ext_ip or "unavailable"}')
    print()
    print('  l  — find a peer on this network automatically')
    print('  g  — connect to a peer on the internet (enter their IP)')
    print()

    while True:
        try:
            mode = input('Mode (l/g): ').strip().lower()
            if mode == 'l':
                peer_addr = lan_discover(_chat_port)
                if peer_addr is None:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + 'No peer found on the local network.')
                    continue
                UDPClient(peer_addr[0], _sock, port=peer_addr[1])
            elif mode == 'g':
                peer_ip = input('Peer\'s public IP: ').strip()
                if not peer_ip:
                    continue
                peer_port = int(input(f'Peer\'s port (default {DISCOVERY_PORT}): ').strip() or DISCOVERY_PORT)
                UDPClient(peer_ip, _sock, port=peer_port)
            else:
                print('Enter l or g.')
                continue
        except KeyboardInterrupt:
            print('\nExiting...')
            sys.exit(0)
