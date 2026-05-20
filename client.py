import socket
import threading
import struct
import random
import sys
from colorama import Fore, Style
from time import sleep, time


def stun_get_external(sock, stun_host='stun.l.google.com', stun_port=19302):
    """Send a STUN Binding Request on an existing bound socket, return (ext_ip, ext_port)."""
    old_timeout = sock.gettimeout()
    sock.settimeout(5)
    try:
        tid = struct.pack('!12B', *[random.randint(0, 255) for _ in range(12)])
        msg = struct.pack('!HHI12s', 0x0001, 0, 0x2112A442, tid)
        sock.sendto(msg, (stun_host, stun_port))
        data, _ = sock.recvfrom(2048)
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


PUNCH_INTERVAL = 0.5   # seconds between hole-punch probes
PUNCH_TIMEOUT  = 30    # seconds to keep punching before giving up
PUNCH_MSG      = b'__punch__'
PUNCH_ACK      = b'__punch_ack__'


def _is_local(ip, local_ip):
    """Return True if ip is on the same /24 subnet as local_ip, or is loopback."""
    if ip == '127.0.0.1' or ip == local_ip:
        return True
    return ip.rsplit('.', 1)[0] == local_ip.rsplit('.', 1)[0]


print_lock = threading.Lock()


def print_msg(msg):
    """Print an incoming message without clobbering the input prompt."""
    with print_lock:
        sys.stdout.write(f'\r{" " * 80}\r')  # clear the "> " prompt line
        print(Fore.LIGHTGREEN_EX + Style.BRIGHT + msg)
        sys.stdout.write('> ')
        sys.stdout.flush()


class UDPClient:

    def __init__(self, ip, port, sock):
        self.sock = sock

        self.remote = (ip, int(port))
        self.connected = threading.Event()

        if _is_local(ip, local_ip):
            self.connected.set()
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Connected!')
        else:
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Punching through NAT...')
            punch_thread = threading.Thread(target=self._punch)
            punch_thread.daemon = True
            punch_thread.start()

            if not self.connected.wait(timeout=PUNCH_TIMEOUT):
                print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: NAT traversal timed out.')
                print('Your peer may be behind Symmetric NAT, or did not start at the same time.')
                self.sock.close()
                sys.exit(1)

        send_thread = threading.Thread(target=self._send_loop)
        send_thread.daemon = True
        send_thread.start()

        self._recv_loop()

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

            print_msg(data.decode('utf-8', errors='replace'))

    def _send_loop(self):
        self.connected.wait()
        try:
            self.sock.sendto(f'{username} connected'.encode(), self.remote)
        except Exception:
            pass
        try:
            while True:
                with print_lock:
                    sys.stdout.write('> ')
                    sys.stdout.flush()
                msg = sys.stdin.readline().rstrip('\n')
                self.sock.sendto(f'<{username}>: {msg}'.encode('utf-8'), self.remote)
        except (KeyboardInterrupt, EOFError):
            try:
                self.sock.sendto(f'{username} disconnected'.encode(), self.remote)
            except Exception:
                pass
            self.sock.close()
            sys.exit(0)


if __name__ == '__main__':
    username = input('Type your name: ')
    source_ip = '0.0.0.0'

    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect(('8.8.8.8', 80))
        local_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        local_ip = '127.0.0.1'

    # Create the socket early so we know the OS-assigned port before showing
    # addresses to the user — the same socket is passed into UDPClient.
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock.bind((source_ip, 0))
    local_port = _sock.getsockname()[1]

    ext_ip, ext_port = stun_get_external(_sock)
    print(f'Local  address (same network): {local_ip}:{local_port}')
    if ext_ip:
        print(f'Public address (internet):     {ext_ip}:{ext_port}')
    else:
        print('Public address (internet):     unavailable (STUN failed)')
    print('Share your address with your peer and ask for theirs.')
    print('Once both of you have started the app, you have 30 seconds to enter each other\'s address.')

    while True:
        try:
            peer_addr = input('Your peer\'s address (IP:port): ').strip()
            if ':' not in peer_addr:
                print('Invalid format. Please enter address as IP:port (e.g. 1.2.3.4:8547)')
                continue
            remote_ip, remote_port = peer_addr.rsplit(':', 1)
            UDPClient(remote_ip, remote_port, sock=_sock)
            break
        except KeyboardInterrupt:
            print('Exiting...')
            sys.exit(0)
