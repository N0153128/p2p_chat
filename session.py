"""
Encrypted peer-to-peer UDP chat session.

:class:`UDPClient` manages a multi-peer chat room session.  Up to
:data:`~protocol.MAX_PEERS` peers can share the same room simultaneously.
Each peer gets its own X25519 key-exchange and ``nacl.public.Box``; outgoing
messages are encrypted and sent to every connected peer individually.

Lifecycle
---------
1. An ephemeral X25519 keypair is generated (shared across all peers).
2. ``_recv_loop`` starts immediately in a daemon thread.
3. For each peer address supplied, a ``_punch`` thread is started.
4. ``_recv_loop`` processes incoming packets from any known peer address:

   - **PUNCH** — builds the per-peer ``Box``, replies with PUNCH_ACK + our
     public key, marks that peer connected.
   - **PUNCH_ACK** — builds the per-peer ``Box``, marks that peer connected.
   - **Encrypted payload** — tries all connected peers' boxes; handles
     CTRL_DISCONNECT, CTRL_META_PREFIX, and chat text.

5. ``__init__`` blocks on ``done.wait()`` so the caller returns only after
   the session ends (all peers left, /exit, or SIGINT).

Encryption
----------
All post-handshake payloads use ``nacl.public.Box`` (X25519 key agreement,
XSalsa20-Poly1305 AEAD).  Packets that fail authentication against every
known peer box are dropped silently.

Source validation
-----------------
``_recv_loop`` only processes packets whose source address appears in the
set of known peer addresses, preventing injection from third parties.
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
    MAX_PEERS,
    PUNCH_ACK_PREFIX,
    PUNCH_INTERVAL,
    PUNCH_PREFIX,
    PUNCH_TIMEOUT,
)
import ui
from ui import COLOURS, colour_for, print_lock


class UDPClient:
    """Encrypted multi-peer UDP chat room session.

    Args:
        peers:        List of ``(ip, port)`` tuples to connect to.
        sock:         Bound ``SOCK_DGRAM`` socket used for all I/O.
        username:     Local user's display name.
        name_colour:  ANSI code for our username colour.
        text_colour:  ANSI code for our message body colour.
    """

    def __init__(self, peers, sock, username, name_colour=Fore.CYAN, text_colour=Fore.WHITE):
        self.sock = sock
        self.username = username
        self.name_colour = name_colour
        self.text_colour = text_colour

        # done is set when the local user exits or all peers have disconnected.
        self.done = threading.Event()
        # Set to True when at least one peer disconnected (vs. local /exit).
        self.peer_disconnected = False

        self._privkey = nacl.public.PrivateKey.generate()
        self._pubkey_bytes = bytes(self._privkey.public_key)

        # Per-peer state, keyed by (ip, port).
        # Each entry: {'box': Box|None, 'connected': Event,
        #              'name_colour': str, 'text_colour': str}
        self._peers_lock = threading.Lock()
        self._peers = {
            addr: {
                'box': None,
                'connected': threading.Event(),
                'name_colour': Fore.CYAN,
                'text_colour': Fore.WHITE,
            }
            for addr in peers
        }

        self._prev_sigint = signal.signal(signal.SIGINT, self._handle_sigint)

        recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        recv_thread.start()

        for addr in peers:
            t = threading.Thread(target=self._punch, args=(addr,), daemon=True)
            t.start()

        # Wait until at least one peer connects (or all time out).
        deadline = time() + PUNCH_TIMEOUT
        while time() < deadline and not self.done.is_set():
            with self._peers_lock:
                if any(p['connected'].is_set() for p in self._peers.values()):
                    break
            sleep(0.1)
        else:
            with self._peers_lock:
                connected = [a for a, p in self._peers.items() if p['connected'].is_set()]
            if not connected:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: timed out.')
                print('Your peer may be behind Symmetric NAT, or started too late.')
                self.done.set()
                signal.signal(signal.SIGINT, self._prev_sigint)
                return

        send_thread = threading.Thread(target=self._send_loop, daemon=True)
        send_thread.start()

        self.done.wait()
        signal.signal(signal.SIGINT, self._prev_sigint)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_sigint(self, sig, frame):
        """Send disconnect to all peers and exit."""
        self._broadcast(CTRL_DISCONNECT)
        print()
        self.done.set()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Handshake helpers
    # ------------------------------------------------------------------

    def _make_punch_msg(self):
        return PUNCH_PREFIX + self._pubkey_bytes.hex().encode()

    def _make_punch_ack(self):
        return PUNCH_ACK_PREFIX + self._pubkey_bytes.hex().encode()

    def _build_box(self, addr, peer_pubkey_hex):
        """Construct the Box for *addr* from the peer's public key hex."""
        peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pubkey_hex))
        box = nacl.public.Box(self._privkey, peer_pub)
        with self._peers_lock:
            if addr in self._peers:
                self._peers[addr]['box'] = box

    # ------------------------------------------------------------------
    # Broadcast helper
    # ------------------------------------------------------------------

    def _broadcast(self, plaintext):
        """Encrypt *plaintext* and send it to every connected peer."""
        with self._peers_lock:
            targets = [
                (addr, p['box'])
                for addr, p in self._peers.items()
                if p['box'] is not None and p['connected'].is_set()
            ]
        for addr, box in targets:
            try:
                self.sock.sendto(box.encrypt(plaintext), addr)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Networking threads
    # ------------------------------------------------------------------

    def _punch(self, addr):
        """Repeatedly send PUNCH packets to *addr* until connected or timed out."""
        deadline = time() + PUNCH_TIMEOUT
        with self._peers_lock:
            peer = self._peers.get(addr)
        if peer is None:
            return
        while not peer['connected'].is_set() and not self.done.is_set() and time() < deadline:
            try:
                self.sock.sendto(self._make_punch_msg(), addr)
            except Exception:
                pass
            sleep(PUNCH_INTERVAL)

    def _recv_loop(self):
        """Receive and dispatch all incoming UDP packets for this session."""
        self.sock.settimeout(0.5)
        while not self.done.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                self.done.set()
                break

            with self._peers_lock:
                known = addr in self._peers

            if not known:
                continue  # drop packets from unknown sources

            if data.startswith(BEACON_PREFIX):
                continue

            if data.startswith(PUNCH_PREFIX):
                peer_pubkey_hex = data[len(PUNCH_PREFIX):].decode(errors='ignore')
                try:
                    self._build_box(addr, peer_pubkey_hex)
                except Exception:
                    continue
                try:
                    self.sock.sendto(self._make_punch_ack(), addr)
                except Exception:
                    pass
                with self._peers_lock:
                    peer = self._peers.get(addr)
                if peer and not peer['connected'].is_set():
                    peer['connected'].set()
                    with print_lock:
                        sys.stdout.write(
                            f'\r{" " * 80}\r'
                            + Fore.LIGHTGREEN_EX + Style.BRIGHT
                            + f'Connected to {addr[0]}:{addr[1]}! (encrypted)\n'
                            + Style.RESET_ALL
                        )
                        sys.stdout.flush()
                continue

            if data.startswith(PUNCH_ACK_PREFIX):
                peer_pubkey_hex = data[len(PUNCH_ACK_PREFIX):].decode(errors='ignore')
                try:
                    self._build_box(addr, peer_pubkey_hex)
                except Exception:
                    continue
                with self._peers_lock:
                    peer = self._peers.get(addr)
                if peer and not peer['connected'].is_set():
                    peer['connected'].set()
                    with print_lock:
                        sys.stdout.write(
                            f'\r{" " * 80}\r'
                            + Fore.LIGHTGREEN_EX + Style.BRIGHT
                            + f'Connected to {addr[0]}:{addr[1]}! (encrypted)\n'
                            + Style.RESET_ALL
                        )
                        sys.stdout.flush()
                continue

            # Try to decrypt with this peer's box.
            with self._peers_lock:
                peer = self._peers.get(addr)
            if peer is None or peer['box'] is None:
                continue

            try:
                plaintext = peer['box'].decrypt(data)
            except Exception:
                continue

            if plaintext == CTRL_DISCONNECT:
                with self._peers_lock:
                    self._peers.pop(addr, None)
                    remaining = len(self._peers)
                with print_lock:
                    sys.stdout.write(f'\r{" " * 80}\r')
                    sys.stdout.write(
                        Fore.LIGHTYELLOW_EX + Style.BRIGHT
                        + f'{addr[0]}:{addr[1]} disconnected.'
                        + (f'  ({remaining} peer{"s" if remaining != 1 else ""} remaining)'
                           if remaining else '')
                        + '\n' + Style.RESET_ALL
                    )
                    sys.stdout.flush()
                self.peer_disconnected = True
                if remaining == 0:
                    self.done.set()
                    try:
                        os.write(sys.stdin.fileno(), b'\n')
                    except Exception:
                        pass
                    break
                continue

            if plaintext.startswith(CTRL_META_PREFIX):
                parts = plaintext[len(CTRL_META_PREFIX):].decode(
                    errors='ignore'
                ).strip().split(',')
                with self._peers_lock:
                    if addr in self._peers:
                        self._peers[addr]['name_colour'] = colour_for(parts[0])
                        if len(parts) >= 2:
                            self._peers[addr]['text_colour'] = colour_for(parts[1])
                continue

            with self._peers_lock:
                peer = self._peers.get(addr, {})
            name_colour = peer.get('name_colour', Fore.CYAN)
            text_colour = peer.get('text_colour', Fore.WHITE)

            text = plaintext.decode('utf-8', errors='replace')
            if text.startswith('<') and '>: ' in text:
                split_at = text.index('>: ')
                name_part = text[:split_at + 1]
                body_part = text[split_at + 2:]
                ui.print_msg(name_part, body_part,
                             name_colour=name_colour, text_colour=text_colour, alert=True)
            else:
                ui.print_msg('', text,
                             name_colour=name_colour, text_colour=text_colour, alert=True)

        try:
            self.sock.settimeout(None)
        except OSError:
            pass

    def _send_loop(self):
        """Read stdin and broadcast encrypted messages to all connected peers."""
        # Send our colour metadata and join announcement to all peers.
        name_colour_name = next((n for n, c in COLOURS if c == self.name_colour), 'cyan')
        text_colour_name = next((n for n, c in COLOURS if c == self.text_colour), 'white')
        meta = f'{name_colour_name},{text_colour_name}'.encode()
        self._broadcast(CTRL_META_PREFIX + meta)
        self._broadcast(f'{self.username} joined'.encode())

        try:
            while not self.done.is_set():
                with print_lock:
                    sys.stdout.write('> ')
                    sys.stdout.flush()
                msg = sys.stdin.readline().rstrip('\n')
                if self.done.is_set():
                    break
                if msg == '/exit':
                    self._broadcast(CTRL_DISCONNECT)
                    with print_lock:
                        sys.stdout.write(f'\r{" " * 80}\r')
                        sys.stdout.write(
                            Fore.LIGHTYELLOW_EX + Style.BRIGHT
                            + 'Left the room.\n' + Style.RESET_ALL
                        )
                        sys.stdout.flush()
                    self.done.set()
                    break
                if msg:
                    self._broadcast(f'<{self.username}>: {msg}'.encode('utf-8'))
                    ui.print_msg(
                        f'(you) <{self.username}>',
                        f': {msg}',
                        name_colour=self.name_colour,
                        text_colour=self.text_colour,
                    )
        except (KeyboardInterrupt, EOFError):
            pass
