"""
Encrypted peer-to-peer UDP chat session.

:class:`UDPClient` manages a multi-peer chat room session.  Up to
:data:`~protocol.MAX_PEERS` peers can share the same room simultaneously.

LAN mode
--------
Pass ``room_code`` and ``chat_port`` to the constructor.  A background
discovery thread broadcasts beacons and punches through to every new peer
it finds for the entire lifetime of the room, so late joiners connect
automatically without restarting.

Internet mode
-------------
Pass a list of explicit ``(ip, port)`` peer addresses.  Discovery is
skipped; hole-punching starts immediately for each address.

Lifecycle
---------
1. An ephemeral X25519 keypair is generated (shared across all peers).
2. ``_recv_loop`` starts immediately.
3. For LAN mode, ``_discover_loop`` broadcasts beacons in the background
   and calls ``_add_peer`` for each new peer found.  For internet mode,
   all peers are added up front.
4. ``_recv_loop`` processes incoming packets:

   - **PUNCH from known peer** — builds the Box, sends PUNCH_ACK, marks
     connected, sends colour meta and join announcement to that peer.
   - **PUNCH from unknown addr** — if room has space, auto-adds the peer
     (late LAN joiner or internet peer we haven't punched yet), then
     processes as above.
   - **PUNCH_ACK** — builds the Box, marks connected.
   - **Encrypted payload** — decrypts with the sender's Box; handles
     CTRL_DISCONNECT, CTRL_META_PREFIX, and chat text.

5. ``__init__`` blocks on ``done.wait()``.

Encryption
----------
All post-handshake payloads use ``nacl.public.Box`` (X25519 + XSalsa20-Poly1305).

Source validation
-----------------
Only PUNCH packets are accepted from unknown addresses (to allow late
joiners).  All other packet types require the source to be a known peer.
"""

import os
import shutil
import signal
import sys
import threading
from time import sleep, time

import nacl.public
from colorama import Fore, Style

import discovery
from protocol import (
    BEACON_PREFIX,
    BROADCAST_INTERVAL,
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
        sock:         Bound ``SOCK_DGRAM`` socket used for all I/O.
        username:     Local user's display name.
        name_colour:  ANSI code for our username colour.
        text_colour:  ANSI code for our message body colour.
        peers:        List of ``(ip, port)`` for internet mode.  Mutually
                      exclusive with *room_code*.
        room_code:    Shared room secret for LAN discovery mode.  Mutually
                      exclusive with *peers*.
        chat_port:    Our chat socket port, embedded in LAN beacons.
    """

    def __init__(
        self,
        sock,
        username,
        name_colour=Fore.CYAN,
        text_colour=Fore.WHITE,
        peers=None,
        room_code=None,
        chat_port=None,
    ):
        self.sock = sock
        self.username = username
        self.name_colour = name_colour
        self.text_colour = text_colour
        self._own_addr = sock.getsockname()

        self.done = threading.Event()
        # True when at least one peer disconnected (not a local /exit).
        self.peer_disconnected = False

        self._privkey = nacl.public.PrivateKey.generate()
        self._pubkey_bytes = bytes(self._privkey.public_key)

        # Per-peer state keyed by (ip, port).
        # {'box': Box|None, 'connected': Event, 'name_colour': code, 'text_colour': code}
        self._peers_lock = threading.Lock()
        self._peers = {}

        # first_connected is set the moment any peer completes the handshake.
        self._first_connected = threading.Event()

        self._prev_sigint = signal.signal(signal.SIGINT, self._handle_sigint)

        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

        if room_code and chat_port:
            # LAN mode: discovery runs for the life of the room.
            disc_thread = threading.Thread(
                target=self._discover_loop,
                args=(chat_port, room_code),
                daemon=True,
            )
            disc_thread.start()
        else:
            # Internet mode: add all peers up front.
            for addr in (peers or []):
                self._add_peer(addr)

        # In LAN mode, wait indefinitely — the discovery loop runs forever
        # and a peer may join at any time.  In internet mode, give up after
        # PUNCH_TIMEOUT seconds if the explicit peer list never connects.
        timeout = None if (room_code and chat_port) else PUNCH_TIMEOUT
        if not self._first_connected.wait(timeout=timeout):
            with print_lock:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: timed out.')
                print('Your peer may be behind Symmetric NAT, or started too late.')
            self.done.set()
            signal.signal(signal.SIGINT, self._prev_sigint)
            return

        send_thread = threading.Thread(target=self._send_loop, daemon=True)
        send_thread.start()

        ui.get_prompt = self._prompt
        ui.get_statusbar = self._statusbar
        with print_lock:
            ui.enable_statusbar()
            sys.stdout.flush()
        self._panel_disabled = False
        self.done.wait()
        with print_lock:
            if not self._panel_disabled:
                ui.disable_statusbar()
            sys.stdout.flush()
        ui.get_prompt = lambda: '> '
        ui.get_statusbar = lambda: ''
        signal.signal(signal.SIGINT, self._prev_sigint)
        # Wait for the recv thread to fully stop before returning so a
        # subsequent session doesn't race on the same socket.
        self._recv_thread.join(timeout=2.0)

    # ------------------------------------------------------------------
    # Prompt
    # ------------------------------------------------------------------

    def _prompt(self):
        return (
            Fore.WHITE + Style.DIM + '(you) ' + Style.RESET_ALL
            + self.name_colour + Style.BRIGHT + f'<{self.username}>' + Style.RESET_ALL
            + self.text_colour + ': ' + Style.RESET_ALL
        )

    def _statusbar(self):
        """Return the status bar string showing room members."""
        with self._peers_lock:
            connected = [
                p for p in self._peers.values() if p['connected'].is_set()
            ]
        total = 1 + len(connected)  # include ourselves
        capacity = MAX_PEERS  # room fits MAX_PEERS people total

        # Member list: us first, then peers in name_colour.
        members = [
            self.name_colour + Style.BRIGHT + self.username + Style.RESET_ALL
        ]
        for p in connected:
            name = p['username'] or '?'
            members.append(
                p['name_colour'] + Style.BRIGHT + name + Style.RESET_ALL
            )

        sep = Fore.WHITE + '  ·  ' + Style.RESET_ALL
        names = sep.join(members)

        count = (
            Fore.CYAN + Style.BRIGHT
            + f'[{total}/{capacity}]'
            + Style.RESET_ALL
        )
        bar = (
            Fore.WHITE + Style.DIM + '─' * 4 + Style.RESET_ALL
            + '  ' + count + '  ' + names + '  '
            + Fore.WHITE + Style.DIM + '─' * 4 + Style.RESET_ALL
        )
        return bar

    def _redraw_statusbar(self):
        """Repaint the full bottom panel from any thread (acquires print_lock)."""
        with print_lock:
            ui._paint_panel()
            sys.stdout.flush()

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------

    def _add_peer(self, addr):
        """Register *addr* as a known peer and start punching to it.

        No-op if the peer is already known or the room is full.
        Returns True if the peer was newly added.
        """
        with self._peers_lock:
            if addr in self._peers or len(self._peers) >= MAX_PEERS - 1:
                return False
            self._peers[addr] = {
                'box': None,
                'connected': threading.Event(),
                'name_colour': Fore.CYAN,
                'text_colour': Fore.WHITE,
                'muted': False,
                'username': '',
            }
        t = threading.Thread(target=self._punch, args=(addr,), daemon=True)
        t.start()
        return True

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_sigint(self, sig, frame):
        if self.done.is_set():
            # Second Ctrl+C after already leaving the room — hard exit.
            sys.exit(0)
        self._broadcast(CTRL_DISCONNECT)
        with print_lock:
            ui.disable_statusbar()
            self._panel_disabled = True
            sys.stdout.write(
                '\n' + Fore.LIGHTYELLOW_EX + Style.BRIGHT
                + 'Left the room.  Press Ctrl+C again to quit.\n'
                + Style.RESET_ALL
            )
            sys.stdout.flush()
        self.done.set()

    # ------------------------------------------------------------------
    # Packet helpers
    # ------------------------------------------------------------------

    def _make_punch_msg(self):
        return PUNCH_PREFIX + self._pubkey_bytes.hex().encode()

    def _make_punch_ack(self):
        return PUNCH_ACK_PREFIX + self._pubkey_bytes.hex().encode()

    def _build_box(self, addr, peer_pubkey_hex):
        """Build and store the Box for *addr*. Returns the Box, or None on error."""
        try:
            peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pubkey_hex))
            box = nacl.public.Box(self._privkey, peer_pub)
        except Exception:
            return None
        with self._peers_lock:
            if addr in self._peers:
                self._peers[addr]['box'] = box
        return box

    def _broadcast(self, plaintext):
        """Encrypt *plaintext* and send to every connected peer."""
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

    def _send_meta_to(self, addr, box):
        """Send our username and colour metadata to a single peer."""
        name_colour_name = next((n for n, c in COLOURS if c == self.name_colour), 'cyan')
        text_colour_name = next((n for n, c in COLOURS if c == self.text_colour), 'white')
        meta = f'{self.username},{name_colour_name},{text_colour_name}'.encode()
        try:
            self.sock.sendto(box.encrypt(CTRL_META_PREFIX + meta), addr)
            self.sock.sendto(
                box.encrypt(f'{self.username} joined'.encode()), addr
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Networking threads
    # ------------------------------------------------------------------

    def _punch(self, addr):
        """Send PUNCH packets to *addr* until connected, done, or timed out."""
        with self._peers_lock:
            peer = self._peers.get(addr)
        if peer is None:
            return
        deadline = time() + PUNCH_TIMEOUT
        while not peer['connected'].is_set() and not self.done.is_set() and time() < deadline:
            try:
                self.sock.sendto(self._make_punch_msg(), addr)
            except Exception:
                pass
            sleep(PUNCH_INTERVAL)

    def _discover_loop(self, chat_port, room_code):
        """Broadcast LAN beacons and add peers for the life of the room.

        Runs as a daemon thread.  Opens its own discovery socket (separate
        from the chat socket) and broadcasts every BROADCAST_INTERVAL seconds.
        Whenever a valid authenticated beacon arrives from a new peer, calls
        _add_peer so it gets punched and connected without interrupting chat.
        """
        import hashlib
        import hmac as hmaclib
        import socket as socklib

        tag = discovery._beacon_hmac(room_code, discovery.SESSION_ID)
        my_beacon = BEACON_PREFIX + f'{discovery.SESSION_ID}:{chat_port}:{tag}'.encode()
        seen_sids = set()

        try:
            disc = socklib.socket(socklib.AF_INET, socklib.SOCK_DGRAM)
            disc.setsockopt(socklib.SOL_SOCKET, socklib.SO_REUSEADDR, 1)
            disc.setsockopt(socklib.SOL_SOCKET, socklib.SO_BROADCAST, 1)
            disc.bind(('0.0.0.0', discovery.DISCOVERY_PORT))
            disc.settimeout(BROADCAST_INTERVAL)
        except OSError:
            return

        broadcast = discovery._broadcast_addr()

        try:
            while not self.done.is_set():
                try:
                    disc.sendto(my_beacon, (broadcast, discovery.DISCOVERY_PORT))
                except Exception:
                    pass

                try:
                    data, addr = disc.recvfrom(4096)
                except (TimeoutError, OSError):
                    continue

                if not data.startswith(BEACON_PREFIX):
                    continue

                payload = data[len(BEACON_PREFIX):].decode(errors='ignore')
                parts = payload.split(':')
                if len(parts) != 3:
                    continue

                peer_sid, peer_port_str, peer_tag = parts

                if peer_sid == discovery.SESSION_ID or peer_sid in seen_sids:
                    continue

                expected = discovery._beacon_hmac(room_code, peer_sid)
                if not hmaclib.compare_digest(peer_tag, expected):
                    continue

                try:
                    peer_port = int(peer_port_str)
                except ValueError:
                    continue

                seen_sids.add(peer_sid)
                peer_addr = (addr[0], peer_port)

                with self._peers_lock:
                    already_known = peer_addr in self._peers
                    full = len(self._peers) >= MAX_PEERS - 1

                if already_known or full:
                    continue

                # Unicast our beacon back so the peer sees us too.
                try:
                    disc.sendto(my_beacon, addr)
                except Exception:
                    pass

                self._add_peer(peer_addr)

        finally:
            disc.close()

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

            if data.startswith(BEACON_PREFIX):
                continue

            # Discard looped-back packets (our own datagrams reflected by the
            # kernel when sending to a local address on the same machine).
            if addr == self._own_addr:
                continue

            with self._peers_lock:
                known = addr in self._peers
                full = len(self._peers) >= MAX_PEERS - 1

            # Accept PUNCH from unknown addresses: this is a late joiner
            # punching us first (common when we sent them a beacon reply).
            if not known:
                if data.startswith(PUNCH_PREFIX) and not full:
                    self._add_peer(addr)
                else:
                    continue

            if data.startswith(PUNCH_PREFIX):
                peer_pubkey_hex = data[len(PUNCH_PREFIX):].decode(errors='ignore')
                box = self._build_box(addr, peer_pubkey_hex)
                if box is None:
                    continue
                try:
                    self.sock.sendto(self._make_punch_ack(), addr)
                except Exception:
                    pass
                with self._peers_lock:
                    peer = self._peers.get(addr)
                if peer and not peer['connected'].is_set():
                    peer['connected'].set()
                    self._first_connected.set()
                    self._send_meta_to(addr, box)
                    with print_lock:
                        sys.stdout.write(
                            f'\r{" " * 80}\r'
                            + Fore.LIGHTGREEN_EX + Style.BRIGHT
                            + f'Peer joined! ({addr[0]}:{addr[1]}, encrypted)\n'
                            + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
                continue

            if data.startswith(PUNCH_ACK_PREFIX):
                peer_pubkey_hex = data[len(PUNCH_ACK_PREFIX):].decode(errors='ignore')
                box = self._build_box(addr, peer_pubkey_hex)
                if box is None:
                    continue
                with self._peers_lock:
                    peer = self._peers.get(addr)
                if peer and not peer['connected'].is_set():
                    peer['connected'].set()
                    self._first_connected.set()
                    self._send_meta_to(addr, box)
                    with print_lock:
                        sys.stdout.write(
                            f'\r{" " * 80}\r'
                            + Fore.LIGHTGREEN_EX + Style.BRIGHT
                            + f'Peer joined! ({addr[0]}:{addr[1]}, encrypted)\n'
                            + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
                continue

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
                        + 'A peer left.'
                        + (f'  ({remaining} peer{"s" if remaining != 1 else ""} remaining)'
                           if remaining else '')
                        + '\n' + Style.RESET_ALL
                    )
                    ui._paint_panel()
                    sys.stdout.flush()
                self.peer_disconnected = True
                # Only end the session if no peers remain AND discovery is done.
                # In LAN mode, done is never set here — the room stays open.
                if remaining == 0 and not self.done.is_set():
                    # In internet mode (no background discovery), end the session.
                    # In LAN mode, keep waiting — _discover_loop will find new peers.
                    pass
                continue

            if plaintext.startswith(CTRL_META_PREFIX):
                parts = plaintext[len(CTRL_META_PREFIX):].decode(
                    errors='ignore'
                ).strip().split(',')
                with self._peers_lock:
                    if addr in self._peers:
                        if len(parts) == 3:
                            # New format: username,name_colour,text_colour
                            self._peers[addr]['username'] = parts[0]
                            self._peers[addr]['name_colour'] = colour_for(parts[1])
                            self._peers[addr]['text_colour'] = colour_for(parts[2])
                        elif len(parts) == 2:
                            # Legacy format: name_colour,text_colour
                            self._peers[addr]['name_colour'] = colour_for(parts[0])
                            self._peers[addr]['text_colour'] = colour_for(parts[1])
                self._redraw_statusbar()
                continue

            with self._peers_lock:
                peer = self._peers.get(addr, {})
            name_colour = peer.get('name_colour', Fore.CYAN)
            text_colour = peer.get('text_colour', Fore.WHITE)
            muted = peer.get('muted', False)

            text = plaintext.decode('utf-8', errors='replace')
            if text.startswith('<') and '>: ' in text:
                split_at = text.index('>: ')
                name_part = text[:split_at + 1]
                body_part = text[split_at + 2:]
                ui.print_msg(name_part, body_part,
                             name_colour=name_colour, text_colour=text_colour, alert=not muted)
            else:
                ui.print_msg('', text,
                             name_colour=name_colour, text_colour=text_colour, alert=not muted)

        try:
            self.sock.settimeout(None)
        except OSError:
            pass

    def _set_all_muted(self, muted):
        """Set the mute flag on every peer and print a confirmation."""
        with self._peers_lock:
            for p in self._peers.values():
                p['muted'] = muted
        action = 'Notifications muted.' if muted else 'Notifications unmuted.'
        with print_lock:
            sys.stdout.write(f'\r{" " * 80}\r')
            sys.stdout.write(Fore.YELLOW + Style.BRIGHT + action + '\n' + Style.RESET_ALL)
            ui._paint_panel()
            sys.stdout.flush()

    def _redraw_input(self, buf):
        """Write prompt + buffer, cursor left after last typed character.

        Called by ui._paint_panel via get_input_redraw — the panel already
        erased the input row before calling this, so just write content.
        Must be called while print_lock is held.
        """
        sys.stdout.write(self._prompt())
        if buf:
            sys.stdout.write(self.text_colour + ''.join(buf) + Style.RESET_ALL)

    def _readline_styled(self):
        """Read one line from stdin in raw mode, echoing each character in
        the user's text colour.  Handles backspace and Ctrl+C/D.

        Returns the completed line string, or raises KeyboardInterrupt /
        EOFError as appropriate.
        """
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setraw(fd)
        buf = []

        # Register a hook so print_msg can redraw our input line after
        # printing an incoming message (otherwise the prompt is left blank
        # and the buffer content is invisible).
        ui.get_input_redraw = lambda: self._redraw_input(buf)

        with print_lock:
            ui._paint_panel()
            sys.stdout.flush()

        try:
            while True:
                ch = sys.stdin.read(1)
                if not ch or ch == '\x04':          # EOF / Ctrl+D
                    raise EOFError
                if ch == '\x03':                    # Ctrl+C
                    raise KeyboardInterrupt
                if ch in ('\r', '\n'):              # Enter
                    return ''.join(buf)
                if ch in ('\x7f', '\x08'):          # Backspace / DEL
                    if buf:
                        buf.pop()
                        with print_lock:
                            sys.stdout.write('\b \b')
                            sys.stdout.flush()
                else:
                    buf.append(ch)
                    with print_lock:
                        sys.stdout.write(
                            self.text_colour + ch + Style.RESET_ALL
                        )
                        sys.stdout.flush()
        finally:
            ui.get_input_redraw = None
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def _send_loop(self):
        """Read stdin and broadcast encrypted messages to all connected peers."""
        try:
            while not self.done.is_set():
                msg = self._readline_styled()
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
                if msg == '/mute':
                    self._set_all_muted(True)
                    continue
                if msg == '/unmute':
                    self._set_all_muted(False)
                    continue
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
