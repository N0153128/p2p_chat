"""
Encrypted peer-to-peer UDP chat session.

:class:`UDPClient` manages the full lifecycle of a single chat session:
key exchange via the hole-punch handshake, encrypted messaging, colour
metadata exchange, and clean disconnect.
"""

import os
import signal
import sys
import threading
from time import sleep, time

import nacl.public
from colorama import Fore, Style

import discovery
from protocol import (
    BEACON_PREFIX,
    CTRL_DISCONNECT,
    CTRL_META_PREFIX,
    PUNCH_ACK_PREFIX,
    PUNCH_INTERVAL,
    PUNCH_PREFIX,
    PUNCH_TIMEOUT,
)
import ui
from ui import COLOURS, colour_for, print_lock


class UDPClient:
    """Encrypted, authenticated peer-to-peer UDP chat session.

    Lifecycle
    ---------
    1. An ephemeral X25519 keypair is generated.
    2. ``_recv_loop`` and ``_punch`` start immediately in daemon threads.
    3. ``_punch`` sends :data:`~protocol.PUNCH_PREFIX` packets carrying our
       public key until ``connected`` is set or
       :data:`~protocol.PUNCH_TIMEOUT` expires.
    4. ``_recv_loop`` processes incoming packets:

       - **PUNCH** — builds the shared ``nacl.public.Box``, replies with
         :data:`~protocol.PUNCH_ACK_PREFIX` + our public key, sets
         ``connected``.
       - **PUNCH_ACK** — builds the shared ``Box``, sets ``connected``.
       - **Encrypted payload** — decrypts with the ``Box``; handles
         :data:`~protocol.CTRL_DISCONNECT`,
         :data:`~protocol.CTRL_META_PREFIX`, and chat text.

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
        username:     Local user's display name.
        name_colour:  ANSI code for our username colour (sent to peer via
                      :data:`~protocol.CTRL_META_PREFIX`).
        text_colour:  ANSI code for our message body colour (applied
                      locally to received message bodies).
    """

    def __init__(
        self,
        ip,
        sock,
        port,
        username,
        name_colour=Fore.CYAN,
        text_colour=Fore.WHITE,
    ):
        self.sock = sock
        self.remote = (ip, port)
        self.username = username
        self.connected = threading.Event()
        self.done = threading.Event()
        self.box = None
        self.name_colour = name_colour
        self.text_colour = text_colour
        self.peer_name_colour = Fore.CYAN
        self.peer_text_colour = Fore.WHITE

        self._privkey = nacl.public.PrivateKey.generate()
        self._pubkey_bytes = bytes(self._privkey.public_key)

        self._prev_sigint = signal.signal(signal.SIGINT, self._handle_sigint)

        if not discovery.is_local(ip):
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
        signal.signal(signal.SIGINT, self._prev_sigint)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Handshake helpers
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Networking threads
    # ------------------------------------------------------------------

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
        established.  Sets ``done`` and returns when the peer disconnects,
        the socket is closed, or ``done`` is set externally (e.g. /exit).
        """
        self.sock.settimeout(0.5)
        while not self.done.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
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
                parts = plaintext[len(CTRL_META_PREFIX):].decode(
                    errors='ignore'
                ).strip().split(',')
                self.peer_name_colour = colour_for(parts[0])
                if len(parts) >= 2:
                    self.peer_text_colour = colour_for(parts[1])
                continue

            text = plaintext.decode('utf-8', errors='replace')
            # Split "<Name>: body" so username and body can be coloured
            # independently.  Falls back to rendering the whole string as
            # body text if the expected format is not present.
            if text.startswith('<') and '>: ' in text:
                split_at = text.index('>: ')
                name_part = text[:split_at + 1]   # includes the closing '>'
                body_part = text[split_at + 2:]   # includes the leading ': '
                ui.print_msg(
                    name_part, body_part,
                    name_colour=self.peer_name_colour,
                    text_colour=self.peer_text_colour,
                )
            else:
                ui.print_msg(
                    '', text,
                    name_colour=self.peer_name_colour,
                    text_colour=self.peer_text_colour,
                )
        try:
            self.sock.settimeout(None)
        except OSError:
            pass

    def _send_loop(self):
        """Read stdin and send encrypted chat messages to the peer.

        Waits for ``connected`` before doing anything.  Sends the colour
        metadata message and a join announcement first, then enters the
        interactive read loop.  Returns when ``done`` is set or stdin closes.
        """
        self.connected.wait()
        try:
            if self.box:
                name_colour_name = next(
                    (n for n, c in COLOURS if c == self.name_colour), 'cyan'
                )
                text_colour_name = next(
                    (n for n, c in COLOURS if c == self.text_colour), 'white'
                )
                meta = f'{name_colour_name},{text_colour_name}'.encode()
                self.sock.sendto(
                    self.box.encrypt(CTRL_META_PREFIX + meta),
                    self.remote,
                )
                self.sock.sendto(
                    self.box.encrypt(f'{self.username} connected'.encode()),
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
                if msg == '/exit':
                    if self.box:
                        try:
                            self.sock.sendto(
                                self.box.encrypt(CTRL_DISCONNECT), self.remote
                            )
                        except Exception:
                            pass
                    with print_lock:
                        sys.stdout.write(f'\r{" " * 80}\r')
                        sys.stdout.write(
                            Fore.LIGHTYELLOW_EX + Style.BRIGHT
                            + 'Left the room.\n' + Style.RESET_ALL
                        )
                        sys.stdout.flush()
                    self.done.set()
                    break
                if msg and self.box:
                    self.sock.sendto(
                        self.box.encrypt(
                            f'<{self.username}>: {msg}'.encode('utf-8')
                        ),
                        self.remote,
                    )
                    ui.print_msg(
                        f'(you) <{self.username}>',
                        f': {msg}',
                        name_colour=self.name_colour,
                        text_colour=self.text_colour,
                    )
        except (KeyboardInterrupt, EOFError):
            pass
