"""
Serverless peer-to-peer encrypted chat over UDP.

Supports two connection modes:

  l (local)   — LAN auto-discovery via authenticated UDP broadcast.
                Both peers enter the same room code; an HMAC-SHA256 tag
                in each beacon ensures only matching peers find each other.

  g (global)  — Internet connection via UDP hole-punching (RFC 5128).
                Both peers exchange their public IP and chat port
                out-of-band, then simultaneously probe each other to
                open a path through their respective NATs.

Encryption
----------
Each session generates a fresh X25519 keypair (nacl.public.PrivateKey).
The public key is embedded in the PUNCH / PUNCH_ACK handshake packets.
Once both keys are known, a nacl.public.Box (XSalsa20-Poly1305) is
established and every subsequent datagram — including control messages —
is encrypted and authenticated.  Packets that fail authentication are
dropped silently.

Source validation
-----------------
_recv_loop rejects datagrams whose source address differs from the
negotiated peer address, preventing third-party control-message injection.
"""

import hashlib
import hmac
import os
import random
import signal
import socket
import struct
import sys
import threading
from time import sleep, time

import nacl.public
import nacl.utils
from colorama import Fore, Style


# ---------------------------------------------------------------------------
# Tuneable constants
# ---------------------------------------------------------------------------

DISCOVERY_PORT = 8547
"""Well-known UDP port used exclusively for LAN discovery beacons."""

BROADCAST_INTERVAL = 1
"""Seconds between consecutive LAN discovery beacon broadcasts."""

BROADCAST_TIMEOUT = 30
"""Seconds to keep broadcasting before giving up on LAN discovery."""

PUNCH_INTERVAL = 0.5
"""Seconds between consecutive hole-punch probe packets."""

PUNCH_TIMEOUT = 30
"""Seconds to keep punching before declaring the connection attempt failed."""


# ---------------------------------------------------------------------------
# Wire protocol constants
# ---------------------------------------------------------------------------
# Pre-handshake messages are plain UDP (unencrypted).
# Post-handshake messages are encrypted nacl.public.Box payloads.

BEACON_PREFIX = b'__beacon__:'
"""
Prefix for LAN discovery beacons (unencrypted).

Full format: ``__beacon__:<session_id>:<chat_port>:<hmac>``

``session_id``  — random 8-hex-char ID generated once per process run.
``chat_port``   — sender's chat socket port (separate from discovery port).
``hmac``        — 16-hex-char HMAC-SHA256(room_code, session_id) prefix,
                  used to authenticate beacons without revealing the code.
"""

PUNCH_PREFIX = b'__punch__:'
"""
Prefix for hole-punch probe packets (unencrypted).

Full format: ``__punch__:<64-hex-char-x25519-pubkey>``
"""

PUNCH_ACK_PREFIX = b'__punch_ack__:'
"""
Prefix for hole-punch acknowledgement packets (unencrypted).

Full format: ``__punch_ack__:<64-hex-char-x25519-pubkey>``
"""

CTRL_DISCONNECT = b'__disconnect__'
"""Encrypted control message sent to notify the peer of a clean disconnect."""

CTRL_META_PREFIX = b'__meta__:'
"""
Prefix for the encrypted metadata message sent once after connect.

Full format: ``__meta__:<colour_name>``

Carries the sender's chosen name colour so the receiver can style
incoming messages appropriately.
"""


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

COLOURS = [
    ('white', Fore.WHITE),
    ('cyan', Fore.CYAN),
    ('magenta', Fore.MAGENTA),
    ('yellow', Fore.YELLOW),
    ('green', Fore.GREEN),
    ('blue', Fore.BLUE + Style.BRIGHT),
    ('red', Fore.RED + Style.BRIGHT),
]
"""
Available terminal colours for username and message text.

Each entry is a ``(name: str, ansi_code: str)`` tuple.  All choices are
legible on both dark and light terminal backgrounds.
"""

COLOUR_NAMES = [name for name, _ in COLOURS]
"""Ordered list of colour name strings, derived from :data:`COLOURS`."""


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

SESSION_ID = '%08x' % random.randint(0, 0xFFFFFFFF)
"""
Random 8-hex-char identifier generated once per process run.

Used in LAN discovery beacons to distinguish our own broadcast echo from
a genuine peer beacon without relying on IP comparison (which fails when
both peers run on the same machine).
"""

print_lock = threading.Lock()
"""Mutex that serialises all terminal writes to prevent interleaved output."""


# ---------------------------------------------------------------------------
# STUN — public address discovery
# ---------------------------------------------------------------------------


def stun_get_external(sock, stun_host='stun.l.google.com', stun_port=19302):
    """Send a STUN Binding Request and return the caller's public (IP, port).

    Reuses an existing bound UDP socket so the mapped address reflects the
    port that will actually be used for chat.  The socket's original timeout
    is always restored, even on error.

    Args:
        sock:       A bound ``socket.SOCK_DGRAM`` socket.
        stun_host:  Hostname of the STUN server (RFC 5389).
        stun_port:  UDP port of the STUN server.

    Returns:
        ``(ip, port)`` strings on success, ``(None, None)`` if the server
        is unreachable or the response cannot be parsed.
    """
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

        # Walk the STUN attribute list starting after the 20-byte header.
        i = 20
        while i < len(data):
            attr_type, attr_len = struct.unpack('!HH', data[i:i + 4])
            val = data[i + 4:i + 4 + attr_len]

            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                port = struct.unpack(
                    '!H',
                    bytes(b ^ m for b, m in zip(val[2:4], b'\x21\x12')),
                )[0]
                ip = '.'.join(
                    str(b ^ m)
                    for b, m in zip(val[4:8], struct.pack('!I', 0x2112A442))
                )
                return ip, port

            if attr_type == 0x0001:  # MAPPED-ADDRESS (non-XOR fallback)
                port = struct.unpack('!H', val[2:4])[0]
                ip = '.'.join(str(b) for b in val[4:8])
                return ip, port

            # Advance past this attribute, aligning to a 4-byte boundary.
            i += 4 + attr_len + (attr_len % 4 and 4 - attr_len % 4)
    finally:
        sock.settimeout(old_timeout)
    return None, None


# ---------------------------------------------------------------------------
# LAN helpers
# ---------------------------------------------------------------------------


def _is_local(ip):
    """Return ``True`` if *ip* is loopback or shares the local /24 subnet.

    Args:
        ip: Dotted-decimal IPv4 string to test.

    Returns:
        ``bool``
    """
    if ip == '127.0.0.1' or ip == local_ip:
        return True
    return ip.rsplit('.', 1)[0] == local_ip.rsplit('.', 1)[0]


def _broadcast_addr():
    """Return the directed broadcast address for the local /24 subnet.

    Example: if ``local_ip`` is ``192.168.1.42`` this returns
    ``'192.168.1.255'``.

    Returns:
        Dotted-decimal broadcast address string.
    """
    return local_ip.rsplit('.', 1)[0] + '.255'


def _beacon_hmac(room_code, session_id):
    """Compute a 16-character hex HMAC-SHA256 tag for a discovery beacon.

    The tag authenticates the beacon without revealing the room code.
    Only a peer that knows the same room code can reproduce it.

    Args:
        room_code:  Shared secret entered by both peers.
        session_id: The sender's :data:`SESSION_ID` string.

    Returns:
        16-character lowercase hex string (64-bit prefix of the digest).
    """
    return hmac.new(
        room_code.encode(), session_id.encode(), hashlib.sha256
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------


def _colour_for(name):
    """Look up the ANSI colour code for a colour name.

    Args:
        name: One of the strings in :data:`COLOUR_NAMES`.

    Returns:
        The corresponding ``colorama.Fore`` code, or ``Fore.WHITE`` if
        *name* is not found.
    """
    for label, code in COLOURS:
        if label == name:
            return code
    return Fore.WHITE


def print_msg(username_part, text_part, name_colour=Fore.CYAN, text_colour=Fore.WHITE):
    """Print an incoming chat message without clobbering the input prompt.

    Clears the current prompt line, writes the coloured message, then
    reprints the ``> `` prompt.  All writes are serialised via
    :data:`print_lock`.

    Args:
        username_part: The ``<Name>`` portion of the message (or ``''``).
        text_part:     The body of the message (including the leading ``': '``
                       separator when *username_part* is non-empty).
        name_colour:   ANSI colour code applied to *username_part*.
        text_colour:   ANSI colour code applied to *text_part*.
    """
    with print_lock:
        sys.stdout.write(f'\r{" " * 80}\r')
        sys.stdout.write(
            Style.BRIGHT + name_colour + username_part + Style.RESET_ALL
            + text_colour + text_part + Style.RESET_ALL + '\n'
        )
        sys.stdout.write('> ')
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# LAN peer discovery
# ---------------------------------------------------------------------------


def lan_discover(chat_port, room_code):
    """Broadcast authenticated beacons and return the first matching peer.

    Opens a temporary UDP socket on :data:`DISCOVERY_PORT` (separate from
    the chat socket so two instances on the same machine don't collide).
    Broadcasts a beacon every :data:`BROADCAST_INTERVAL` seconds and listens
    for beacons from other peers.  A peer is accepted only if its HMAC tag
    matches the expected value for *room_code*, ensuring only peers sharing
    the same room code can discover each other.

    Once a valid peer beacon is received this node sends one final beacon
    directly to the peer's address so the peer can exit its own loop, then
    returns immediately.

    Args:
        chat_port:  Our chat socket's port (embedded in the beacon so the
                    peer knows where to send chat packets).
        room_code:  Shared secret used to authenticate beacons.

    Returns:
        ``(peer_ip, peer_chat_port)`` on success, or ``None`` on timeout.
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
                continue  # our own broadcast echo

            # Reject beacons from peers on a different room code.
            expected = _beacon_hmac(room_code, peer_sid)
            if not hmac.compare_digest(peer_tag, expected):
                continue

            try:
                peer_port = int(peer_port_str)
            except ValueError:
                continue

            # Unicast one final beacon so the peer exits its loop too.
            try:
                disc.sendto(my_beacon, addr)
            except Exception:
                pass

            return (addr[0], peer_port)
    finally:
        disc.close()
    return None


# ---------------------------------------------------------------------------
# Chat session
# ---------------------------------------------------------------------------


class UDPClient:
    """Encrypted, authenticated peer-to-peer UDP chat session.

    Lifecycle
    ---------
    1. An ephemeral X25519 keypair is generated.
    2. ``_recv_loop`` and ``_punch`` start immediately in daemon threads.
    3. ``_punch`` sends :data:`PUNCH_PREFIX` packets carrying our public key
       until ``connected`` is set or :data:`PUNCH_TIMEOUT` expires.
    4. ``_recv_loop`` processes incoming packets:

       - **PUNCH** — builds the shared ``nacl.public.Box``, replies with
         :data:`PUNCH_ACK_PREFIX` + our public key, sets ``connected``.
       - **PUNCH_ACK** — builds the shared ``Box``, sets ``connected``.
       - **Encrypted payload** — decrypts with the ``Box``; handles
         :data:`CTRL_DISCONNECT`, :data:`CTRL_META_PREFIX`, and chat text.

    5. Once ``connected`` is set, ``_send_loop`` starts: it sends our
       colour metadata, announces our arrival, then reads ``stdin`` in a
       loop, encrypting and sending each line.
    6. ``__init__`` blocks on ``done.wait()`` so the caller returns only
       after the session ends (peer disconnect, timeout, or SIGINT).

    Encryption
    ----------
    All post-handshake payloads use ``nacl.public.Box`` (X25519 key
    agreement, XSalsa20-Poly1305 AEAD).  Packets that fail authentication
    are dropped silently.

    Source validation
    -----------------
    ``_recv_loop`` drops any datagram whose source address differs from
    ``self.remote``, preventing injection of control messages from third
    parties.

    Args:
        ip:           Peer's IP address string.
        sock:         Bound ``SOCK_DGRAM`` socket to use for all I/O.
        port:         Peer's UDP port.
        name_colour:  ANSI code for our username colour (sent to peer via
                      :data:`CTRL_META_PREFIX`).
        text_colour:  ANSI code for our outgoing message body colour
                      (applied locally only).
    """

    def __init__(self, ip, sock, port, name_colour=Fore.CYAN, text_colour=Fore.WHITE):
        self.sock = sock
        self.remote = (ip, port)
        self.connected = threading.Event()
        self.done = threading.Event()
        self.box = None
        self.name_colour = name_colour
        self.text_colour = text_colour
        self.peer_name_colour = Fore.CYAN

        self._privkey = nacl.public.PrivateKey.generate()
        self._pubkey_bytes = bytes(self._privkey.public_key)

        signal.signal(signal.SIGINT, self._handle_sigint)

        if not _is_local(ip):
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Punching through NAT...')

        # _recv_loop must start before _punch so it can process the peer's
        # PUNCH/PUNCH_ACK and set self.connected; without it _punch would
        # send into a void and the connection would always time out.
        recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        recv_thread.start()

        punch_thread = threading.Thread(target=self._punch, daemon=True)
        punch_thread.start()

        if not self.connected.wait(timeout=PUNCH_TIMEOUT):
            print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: timed out.')
            print('Your peer may be behind Symmetric NAT, or started too late.')
            self.done.set()
            return

        send_thread = threading.Thread(target=self._send_loop, daemon=True)
        send_thread.start()

        self.done.wait()

    def _handle_sigint(self, sig, frame):
        """Send a disconnect notification to the peer and exit cleanly."""
        try:
            if self.box:
                self.sock.sendto(self.box.encrypt(CTRL_DISCONNECT), self.remote)
        except Exception:
            pass
        print()
        self.done.set()
        sys.exit(0)

    def _make_punch_msg(self):
        """Return a PUNCH packet containing our hex-encoded public key."""
        return PUNCH_PREFIX + self._pubkey_bytes.hex().encode()

    def _make_punch_ack(self):
        """Return a PUNCH_ACK packet containing our hex-encoded public key."""
        return PUNCH_ACK_PREFIX + self._pubkey_bytes.hex().encode()

    def _build_box(self, peer_pubkey_hex):
        """Construct the shared ``nacl.public.Box`` from the peer's public key.

        Args:
            peer_pubkey_hex: 64-character hex string of the peer's X25519
                             public key.

        Raises:
            Exception: Propagated from ``nacl`` if the key is malformed.
        """
        peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pubkey_hex))
        self.box = nacl.public.Box(self._privkey, peer_pub)

    def _punch(self):
        """Repeatedly send PUNCH packets until connected or timed out."""
        deadline = time() + PUNCH_TIMEOUT
        while not self.connected.is_set() and time() < deadline:
            try:
                self.sock.sendto(self._make_punch_msg(), self.remote)
            except Exception:
                pass
            sleep(PUNCH_INTERVAL)

    def _recv_loop(self):
        """Receive and dispatch all incoming UDP packets for this session.

        Runs in a daemon thread from the moment ``__init__`` starts.
        Dispatches each packet to the appropriate handler based on its
        prefix, then decrypts and displays chat messages once the Box is
        established.  Sets ``done`` and returns when the peer disconnects
        or the socket is closed.
        """
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                self.done.set()
                break

            if addr != self.remote:
                continue  # drop packets from unexpected sources

            if data.startswith(BEACON_PREFIX):
                continue  # stray LAN discovery beacon, ignore

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

            if self.box is None:
                continue  # key exchange not yet complete, discard

            try:
                plaintext = self.box.decrypt(data)
            except Exception:
                continue  # authentication failed, drop silently

            if plaintext == CTRL_DISCONNECT:
                with print_lock:
                    sys.stdout.write(f'\r{" " * 80}\r')
                    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + 'Peer disconnected.')
                    sys.stdout.flush()
                self.done.set()
                try:
                    # Unblock the stdin readline() in _send_loop.
                    os.write(sys.stdin.fileno(), b'\n')
                except Exception:
                    pass
                break

            if plaintext.startswith(CTRL_META_PREFIX):
                colour_name = plaintext[len(CTRL_META_PREFIX):].decode(
                    errors='ignore'
                ).strip()
                self.peer_name_colour = _colour_for(colour_name)
                continue

            text = plaintext.decode('utf-8', errors='replace')
            # Split "<Name>: body" so username and body can be coloured
            # independently.  Falls back to rendering the whole string as
            # body text if the expected format is not present.
            if text.startswith('<') and '>: ' in text:
                split_at = text.index('>: ')
                name_part = text[:split_at + 1]   # includes the closing '>'
                body_part = text[split_at + 2:]   # includes the leading ': '
                print_msg(name_part, body_part, name_colour=self.peer_name_colour)
            else:
                print_msg('', text, name_colour=self.peer_name_colour)

    def _send_loop(self):
        """Read stdin and send encrypted chat messages to the peer.

        Waits for ``connected`` before doing anything.  Sends the colour
        metadata message and a join announcement first, then enters the
        interactive read loop.  Returns when ``done`` is set or stdin closes.
        """
        self.connected.wait()
        try:
            if self.box:
                colour_name = next(
                    (n for n, c in COLOURS if c == self.name_colour), 'cyan'
                )
                self.sock.sendto(
                    self.box.encrypt(CTRL_META_PREFIX + colour_name.encode()),
                    self.remote,
                )
                self.sock.sendto(
                    self.box.encrypt(f'{username} connected'.encode()),
                    self.remote,
                )
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
                        self.remote,
                    )
        except (KeyboardInterrupt, EOFError):
            pass


# ---------------------------------------------------------------------------
# Entry point helpers
# ---------------------------------------------------------------------------


def _pick_colour(prompt, default_name):
    """Display a numbered colour menu and return the chosen ANSI code.

    Args:
        prompt:       Introductory line printed above the menu.
        default_name: Name of the colour returned when the user presses
                      Enter without input.

    Returns:
        An ANSI colour code string from :data:`COLOURS`.
    """
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    username = input('Type your name: ')
    print()
    name_colour = _pick_colour('Pick a colour for your name:', 'cyan')
    print()
    text_colour = _pick_colour('Pick a colour for your message text:', 'white')
    print()

    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect(('8.8.8.8', 80))
        local_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        local_ip = '127.0.0.1'

    # Chat socket binds to an OS-assigned port so two instances on the same
    # machine never collide.  The discovery socket (inside lan_discover) uses
    # the fixed DISCOVERY_PORT with SO_REUSEADDR.
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
                UDPClient(
                    peer_addr[0], _sock,
                    port=peer_addr[1],
                    name_colour=name_colour,
                    text_colour=text_colour,
                )
            elif mode == 'g':
                peer_ip = input("Peer's public IP: ").strip()
                if not peer_ip:
                    continue
                peer_port = int(input("Peer's port: ").strip())
                UDPClient(
                    peer_ip, _sock,
                    port=peer_port,
                    name_colour=name_colour,
                    text_colour=text_colour,
                )
            else:
                print('Enter l or g.')
        except KeyboardInterrupt:
            print('\nExiting...')
            sys.exit(0)
