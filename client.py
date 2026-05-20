import hashlib
import hmac
import os
import socket
import threading
import struct
import random
import sys
import signal
from colorama import Fore, Style
from time import sleep, time

import nacl.public
import nacl.utils


DISCOVERY_PORT     = 8547       # well-known port used only for LAN beacon broadcast
BROADCAST_INTERVAL = 1          # seconds between LAN discovery beacons
BROADCAST_TIMEOUT  = 30         # seconds to wait for a peer on LAN
PUNCH_INTERVAL     = 0.5
PUNCH_TIMEOUT      = 30

# Wire protocol prefixes (all unencrypted — sent before the Box is established)
BEACON_PREFIX      = b'__beacon__:'
# PUNCH_MSG format: b'__punch__:<32-byte-pubkey-hex>'
PUNCH_PREFIX       = b'__punch__:'
# PUNCH_ACK format: b'__punch_ack__:<32-byte-pubkey-hex>'
PUNCH_ACK_PREFIX   = b'__punch_ack__:'
# After the Box is established all payloads are encrypted nacl boxes.
# Control messages sent inside the encrypted channel:
CTRL_DISCONNECT    = b'__disconnect__'
# Metadata message sent once right after connect: __meta__:<colour_id>
CTRL_META_PREFIX   = b'__meta__:'

# Colour palette — readable on both dark and light terminal backgrounds.
# Each entry: (display label, Fore colour code)
COLOURS = [
    ('white',   Fore.WHITE),
    ('cyan',    Fore.CYAN),
    ('magenta', Fore.MAGENTA),
    ('yellow',  Fore.YELLOW),
    ('green',   Fore.GREEN),
    ('blue',    Fore.BLUE + Style.BRIGHT),
    ('red',     Fore.RED + Style.BRIGHT),
]
COLOUR_NAMES = [c[0] for c in COLOURS]

SESSION_ID         = '%08x' % random.randint(0, 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# STUN
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_local(ip):
    """Return True if ip is on the same /24 subnet as local_ip, or is loopback."""
    if ip == '127.0.0.1' or ip == local_ip:
        return True
    return ip.rsplit('.', 1)[0] == local_ip.rsplit('.', 1)[0]


def _broadcast_addr():
    """Return the /24 broadcast address for local_ip (e.g. 192.168.1.255)."""
    return local_ip.rsplit('.', 1)[0] + '.255'


def _beacon_hmac(room_code, session_id):
    """Return a 16-byte hex HMAC-SHA256 tag over session_id using room_code as key."""
    return hmac.new(room_code.encode(), session_id.encode(), hashlib.sha256).hexdigest()[:16]


print_lock = threading.Lock()


def _colour_for(name):
    """Return the Fore code for a colour name, defaulting to white."""
    for label, code in COLOURS:
        if label == name:
            return code
    return Fore.WHITE


def print_msg(username_part, text_part, name_colour=Fore.CYAN, text_colour=Fore.WHITE):
    with print_lock:
        sys.stdout.write(f'\r{" " * 80}\r')
        sys.stdout.write(
            Style.BRIGHT + name_colour + username_part + Style.RESET_ALL +
            text_colour + text_part + Style.RESET_ALL + '\n'
        )
        sys.stdout.write('> ')
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# LAN discovery  (fix for issue #1 — beacon authentication)
# ---------------------------------------------------------------------------

def lan_discover(chat_port, room_code):
    """
    Broadcast authenticated beacons on DISCOVERY_PORT, return (ip, port) of peer.

    Beacon format: __beacon__:<session_id>:<chat_port>:<hmac>
    The HMAC ties the beacon to room_code so only peers sharing the same
    room code can discover each other. Beacons with an invalid HMAC are
    silently dropped, preventing unauthenticated peer hijacking (issue #1).
    """
    disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    disc.bind(('0.0.0.0', DISCOVERY_PORT))
    disc.settimeout(BROADCAST_INTERVAL)

    broadcast = _broadcast_addr()
    tag = _beacon_hmac(room_code, SESSION_ID)
    my_beacon = BEACON_PREFIX + f'{SESSION_ID}:{chat_port}:{tag}'.encode()

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
            if len(parts) != 3:
                continue
            peer_sid, peer_port_str, peer_tag = parts
            if peer_sid == SESSION_ID:
                continue  # our own echo

            # Verify HMAC — rejects beacons from peers with a different room code
            expected = _beacon_hmac(room_code, peer_sid)
            if not hmac.compare_digest(peer_tag, expected):
                continue

            try:
                peer_port = int(peer_port_str)
            except ValueError:
                continue

            try:
                disc.sendto(my_beacon, addr)
            except Exception:
                pass

            return (addr[0], peer_port)
    finally:
        disc.close()
    return None


# ---------------------------------------------------------------------------
# UDPClient  (fixes for issues #2 and #3)
# ---------------------------------------------------------------------------

class UDPClient:
    """
    Encrypted, authenticated peer-to-peer UDP chat session.

    Issue #2 fix — encryption:
      An ephemeral X25519 keypair is generated per session. During the
      hole-punch handshake each peer sends their public key inside the
      PUNCH_MSG / PUNCH_ACK. Once both public keys are known a
      nacl.public.Box (XSalsa20-Poly1305) is established. Every message
      sent after that point is encrypted and authenticated.

    Issue #3 fix — source address validation:
      All packets from addresses other than self.remote are silently
      dropped in _recv_loop, preventing control-message injection.
    """

    def __init__(self, ip, sock, port, name_colour=Fore.CYAN, text_colour=Fore.WHITE):
        self.sock = sock
        self.remote = (ip, port)
        self.connected = threading.Event()
        self.done = threading.Event()
        self.box = None                     # set once key exchange completes
        self.name_colour = name_colour      # our name colour (sent to peer in meta)
        self.text_colour = text_colour      # our text colour (applied locally to sent echo)
        self.peer_name_colour = Fore.CYAN   # updated when peer's meta arrives

        # Ephemeral keypair for this session
        self._privkey = nacl.public.PrivateKey.generate()
        self._pubkey_bytes = bytes(self._privkey.public_key)

        signal.signal(signal.SIGINT, self._handle_sigint)

        if not _is_local(ip):
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Punching through NAT...')

        # Start recv_loop immediately so it can handle incoming PUNCH/PUNCH_ACK
        # and set self.connected — otherwise the punch thread sends into a void.
        recv_thread = threading.Thread(target=self._recv_loop)
        recv_thread.daemon = True
        recv_thread.start()

        punch_thread = threading.Thread(target=self._punch)
        punch_thread.daemon = True
        punch_thread.start()

        if not self.connected.wait(timeout=PUNCH_TIMEOUT):
            print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: timed out.')
            print('Your peer may be behind Symmetric NAT, or started too late.')
            self.done.set()
            return

        send_thread = threading.Thread(target=self._send_loop)
        send_thread.daemon = True
        send_thread.start()

        self.done.wait()

    def _handle_sigint(self, sig, frame):
        try:
            if self.box:
                self.sock.sendto(self.box.encrypt(CTRL_DISCONNECT), self.remote)
        except Exception:
            pass
        print()
        self.done.set()
        sys.exit(0)

    def _make_punch_msg(self):
        return PUNCH_PREFIX + self._pubkey_bytes.hex().encode()

    def _make_punch_ack(self):
        return PUNCH_ACK_PREFIX + self._pubkey_bytes.hex().encode()

    def _build_box(self, peer_pubkey_hex):
        peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pubkey_hex))
        self.box = nacl.public.Box(self._privkey, peer_pub)

    def _punch(self):
        deadline = time() + PUNCH_TIMEOUT
        while not self.connected.is_set() and time() < deadline:
            try:
                self.sock.sendto(self._make_punch_msg(), self.remote)
            except Exception:
                pass
            sleep(PUNCH_INTERVAL)

    def _recv_loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                self.done.set()
                break

            # Issue #3: drop packets from unexpected sources
            if addr != self.remote:
                continue

            if data.startswith(BEACON_PREFIX):
                continue

            if data.startswith(PUNCH_PREFIX):
                peer_pubkey_hex = data[len(PUNCH_PREFIX):].decode(errors='ignore')
                try:
                    self._build_box(peer_pubkey_hex)
                except Exception:
                    continue
                try:
                    self.sock.sendto(self._make_punch_ack(), self.remote)
                except Exception:
                    pass
                if not self.connected.is_set():
                    self.connected.set()
                    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Connected! (encrypted)')
                continue

            if data.startswith(PUNCH_ACK_PREFIX):
                peer_pubkey_hex = data[len(PUNCH_ACK_PREFIX):].decode(errors='ignore')
                try:
                    self._build_box(peer_pubkey_hex)
                except Exception:
                    continue
                if not self.connected.is_set():
                    self.connected.set()
                    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Connected! (encrypted)')
                continue

            # Everything after the handshake is an encrypted box
            if self.box is None:
                continue  # key exchange not done yet, discard

            try:
                plaintext = self.box.decrypt(data)
            except Exception:
                continue  # authentication failed — drop silently

            if plaintext == CTRL_DISCONNECT:
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

            if plaintext.startswith(CTRL_META_PREFIX):
                colour_name = plaintext[len(CTRL_META_PREFIX):].decode(errors='ignore').strip()
                self.peer_name_colour = _colour_for(colour_name)
                continue

            text = plaintext.decode('utf-8', errors='replace')
            # Split "<username>: message" so they can be styled independently.
            # Falls back to rendering the whole string as body if format doesn't match.
            if text.startswith('<') and '>: ' in text:
                bracket_end = text.index('>: ')
                name_part = text[:bracket_end + 1]   # e.g. "<Alice>"
                body_part = text[bracket_end + 2:]   # e.g. ": hello"
                print_msg(name_part, body_part, name_colour=self.peer_name_colour)
            else:
                print_msg('', text, name_colour=self.peer_name_colour)

    def _send_loop(self):
        self.connected.wait()
        try:
            if self.box:
                # Send our colour preference so the peer knows how to render our name
                colour_name = next(
                    (n for n, c in COLOURS if c == self.name_colour), 'cyan')
                self.sock.sendto(
                    self.box.encrypt(CTRL_META_PREFIX + colour_name.encode()),
                    self.remote)
                self.sock.sendto(
                    self.box.encrypt(f'{username} connected'.encode()), self.remote)
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
                if msg and self.box:
                    self.sock.sendto(
                        self.box.encrypt(f'<{username}>: {msg}'.encode('utf-8')),
                        self.remote)
        except (KeyboardInterrupt, EOFError):
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _pick_colour(prompt, default_name):
    """Print a numbered colour menu and return the chosen Fore code."""
    print(prompt)
    for i, (name, code) in enumerate(COLOURS, 1):
        print(f'  {Style.BRIGHT + code}{i}{Style.RESET_ALL}  {code}{name}{Style.RESET_ALL}')
    while True:
        raw = input(f'Choose (1-{len(COLOURS)}, default {default_name}): ').strip()
        if not raw:
            return _colour_for(default_name)
        if raw.isdigit() and 1 <= int(raw) <= len(COLOURS):
            return COLOURS[int(raw) - 1][1]
        print(f'Enter a number between 1 and {len(COLOURS)}.')


if __name__ == '__main__':
    username = input('Type your name: ')
    print()
    name_colour  = _pick_colour('Pick a colour for your name:', 'cyan')
    print()
    text_colour  = _pick_colour('Pick a colour for your message text:', 'white')
    print()

    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect(('8.8.8.8', 80))
        local_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        local_ip = '127.0.0.1'

    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock.bind(('0.0.0.0', 0))
    _chat_port = _sock.getsockname()[1]

    ext_ip, _ = stun_get_external(_sock)
    print(f'Your public IP (internet): {ext_ip or "unavailable"}')
    print(f'Your chat port:            {_chat_port}')
    print()
    print('  l  — find a peer on this network automatically')
    print('  g  — connect to a peer on the internet (enter their IP and port)')
    print()

    while True:
        try:
            mode = input('Mode (l/g): ').strip().lower()
            if mode == 'l':
                room_code = input('Room code (share this with your peer): ').strip()
                if not room_code:
                    print('Room code cannot be empty.')
                    continue
                peer_addr = lan_discover(_chat_port, room_code)
                if peer_addr is None:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + 'No peer found on the local network.')
                    continue
                UDPClient(peer_addr[0], _sock, port=peer_addr[1],
                          name_colour=name_colour, text_colour=text_colour)
            elif mode == 'g':
                peer_ip = input('Peer\'s public IP: ').strip()
                if not peer_ip:
                    continue
                peer_port = int(input(f'Peer\'s port: ').strip())
                UDPClient(peer_ip, _sock, port=peer_port,
                          name_colour=name_colour, text_colour=text_colour)
            else:
                print('Enter l or g.')
                continue
        except KeyboardInterrupt:
            print('\nExiting...')
            sys.exit(0)
