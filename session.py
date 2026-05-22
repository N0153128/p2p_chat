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
    CTRL_BAN_PREFIX,
    CTRL_DISCONNECT,
    CTRL_KICK_PREFIX,
    CTRL_META_PREFIX,
    CTRL_MOTD_PREFIX,
    MAX_PEERS,
    PUNCH_ACK_PREFIX,
    PUNCH_BAN,
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
        is_host=False,
        room_name='',
        motd='',
        passcode='',
        banned_ips=None,
    ):
        self.sock = sock
        self.username = username
        self.name_colour = name_colour
        self.text_colour = text_colour
        self.is_host = is_host
        self.room_name = room_name
        self.motd = motd
        self._passcode = passcode
        # Raw token without the passcode suffix — embedded in beacons so
        # joiners can read it and reconstruct the effective room code themselves.
        self._raw_room_code = room_code[:-len(':' + passcode)] if passcode else room_code
        self._banned_ips = banned_ips if banned_ips is not None else set()
        self._tab_selected = -1
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

        # Host waits indefinitely — discovery runs for the life of the room.
        # Joiners (LAN or internet) time out if they can't reach the host.
        lan_mode = bool(room_code and chat_port)
        timeout = None if (lan_mode and self.is_host) else PUNCH_TIMEOUT
        if not self._first_connected.wait(timeout=timeout):
            with print_lock:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + 'Could not connect: timed out.')
                print('Your peer may be behind Symmetric NAT, or started too late.')
            self.done.set()
            signal.signal(signal.SIGINT, self._prev_sigint)
            return

        # _first_connected may have been set by a ban rejection rather than a
        # real handshake — bail out before enabling the UI.
        if self.done.is_set():
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
            connected = [p for p in self._peers.values() if p['connected'].is_set()]
        total = 1 + len(connected)
        capacity = MAX_PEERS
        members = [self.name_colour + Style.BRIGHT + self.username + Style.RESET_ALL]
        for p in connected:
            name = p['username'] or '?'
            members.append(p['name_colour'] + Style.BRIGHT + name + Style.RESET_ALL)

        # Apply tab-select highlight to the selected peer (index into connected list).
        tab_idx = self._tab_selected
        if tab_idx >= 0 and connected:
            tab_idx = tab_idx % len(connected)
            # Rebuild the selected peer's entry with inverse-video highlight.
            # Index 0 in members is ourselves; peers start at index 1.
            peer_member_idx = tab_idx + 1
            name = connected[tab_idx]['username'] or '?'
            from colorama import Back
            members[peer_member_idx] = (
                Fore.BLACK + Back.WHITE + ' ' + name + ' ' + Style.RESET_ALL
            )

        sep = Fore.WHITE + '  ·  ' + Style.RESET_ALL
        names = sep.join(members)
        count = Fore.CYAN + Style.BRIGHT + f'[{total}/{capacity}]' + Style.RESET_ALL
        bar = (Fore.WHITE + Style.DIM + '─' * 4 + Style.RESET_ALL
               + '  ' + count + '  ' + names + '  '
               + Fore.WHITE + Style.DIM + '─' * 4 + Style.RESET_ALL)
        return bar

    def _redraw_statusbar(self):
        """Repaint the full bottom panel from any thread (acquires print_lock)."""
        with print_lock:
            ui._paint_panel()
            sys.stdout.flush()

    # ------------------------------------------------------------------
    # Host actions
    # ------------------------------------------------------------------

    def _kick_peer(self, addr):
        """Kick a peer (host only). Notifies all others and removes them."""
        with self._peers_lock:
            peer = self._peers.get(addr)
        if peer is None:
            return
        username = peer.get('username') or str(addr)
        box = peer.get('box')
        if box:
            try:
                self.sock.sendto(box.encrypt(CTRL_KICK_PREFIX), addr)
            except Exception:
                pass
        msg = f'[HOST] {username} was kicked.'
        self._broadcast(msg.encode('utf-8'))
        with print_lock:
            sys.stdout.write(
                Fore.YELLOW + Style.BRIGHT + msg + '\n' + Style.RESET_ALL
            )
        with self._peers_lock:
            self._peers.pop(addr, None)
        self._redraw_statusbar()

    def _ban_peer(self, addr):
        """Ban a peer (host only). Adds IP to ban list and removes them."""
        with self._peers_lock:
            peer = self._peers.get(addr)
        if peer is None:
            return
        username = peer.get('username') or str(addr)
        box = peer.get('box')
        if box:
            try:
                self.sock.sendto(box.encrypt(CTRL_BAN_PREFIX), addr)
            except Exception:
                pass
        msg = f'[HOST] {username} was banned.'
        self._broadcast(msg.encode('utf-8'))
        with print_lock:
            sys.stdout.write(
                Fore.YELLOW + Style.BRIGHT + msg + '\n' + Style.RESET_ALL
            )
        self._banned_ips.add(addr[0])
        with self._peers_lock:
            self._peers.pop(addr, None)
        self._redraw_statusbar()

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
                'is_host': False,
                'room_name': '',
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
        """Send our username, colour metadata, host flag, and room name to a single peer."""
        name_colour_name = next((n for n, c in COLOURS if c == self.name_colour), 'cyan')
        text_colour_name = next((n for n, c in COLOURS if c == self.text_colour), 'white')
        is_host_str = '1' if self.is_host else '0'
        meta = f'{self.username},{name_colour_name},{text_colour_name},{is_host_str},{self.room_name}'.encode()
        try:
            self.sock.sendto(box.encrypt(CTRL_META_PREFIX + meta), addr)
            self.sock.sendto(
                box.encrypt(f'{self.username} joined'.encode()), addr
            )
            if self.is_host and self.motd:
                self.sock.sendto(
                    box.encrypt(CTRL_MOTD_PREFIX + self.motd.encode()), addr
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
        import base64
        import hashlib
        import hmac as hmaclib
        import socket as socklib

        tag = discovery._beacon_hmac(room_code, discovery.SESSION_ID)
        # Embed room_code and room_name as base64 so joiners can discover and
        # connect without knowing the code upfront.  has_passcode signals that
        # a passcode prompt is required before the session is accepted.
        # Embed only the raw token (no passcode suffix) so joiners can read it
        # and reconstruct effective_room_code = raw_token + ':' + passcode.
        room_code_b64 = base64.urlsafe_b64encode(self._raw_room_code.encode()).decode()
        room_name_b64 = base64.urlsafe_b64encode(self.room_name.encode()).decode() if self.room_name else ''
        has_passcode_flag = '1' if self._passcode else '0'
        my_beacon = BEACON_PREFIX + (
            f'{discovery.SESSION_ID}:{chat_port}:{tag}'
            f':{room_code_b64}:{room_name_b64}:{has_passcode_flag}'
        ).encode()
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
                # Accept 3-part (old format) or 4-part (new format with room_name_b64).
                if len(parts) < 3:
                    continue

                peer_sid = parts[0]
                peer_port_str = parts[1]
                peer_tag = parts[2]
                # parts[3] is room_name_b64 if present (informational only).

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

            # Banned IP: send an unencrypted rejection so the joiner knows
            # immediately rather than waiting for PUNCH_TIMEOUT to expire.
            if addr[0] in self._banned_ips:
                if data.startswith(PUNCH_PREFIX):
                    try:
                        self.sock.sendto(PUNCH_BAN, addr)
                    except Exception:
                        pass
                continue

            # Joiner side: host sent PUNCH_BAN before any handshake.
            if data == PUNCH_BAN:
                with print_lock:
                    sys.stdout.write(
                        '\n' + Fore.RED + Style.BRIGHT
                        + 'You are banned from this room.\n'
                        + Style.RESET_ALL
                    )
                    sys.stdout.flush()
                self.done.set()
                self._first_connected.set()  # unblock __init__ so it exits cleanly
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
                        if len(parts) >= 3:
                            # Format: username,name_colour,text_colour[,is_host,room_name]
                            self._peers[addr]['username'] = parts[0]
                            self._peers[addr]['name_colour'] = colour_for(parts[1])
                            self._peers[addr]['text_colour'] = colour_for(parts[2])
                            if len(parts) >= 5:
                                self._peers[addr]['is_host'] = parts[3] == '1'
                                self._peers[addr]['room_name'] = parts[4]
                        elif len(parts) == 2:
                            # Legacy format: name_colour,text_colour
                            self._peers[addr]['name_colour'] = colour_for(parts[0])
                            self._peers[addr]['text_colour'] = colour_for(parts[1])
                self._redraw_statusbar()
                continue

            if plaintext == CTRL_KICK_PREFIX:
                ui.print_msg('', Fore.RED + Style.BRIGHT + 'You were kicked from the room.' + Style.RESET_ALL,
                             name_colour='', text_colour='')
                self.done.set()
                continue

            if plaintext == CTRL_BAN_PREFIX:
                ui.print_msg('', Fore.RED + Style.BRIGHT + 'You were banned from the room.' + Style.RESET_ALL,
                             name_colour='', text_colour='')
                self.done.set()
                continue

            if plaintext.startswith(CTRL_MOTD_PREFIX):
                motd = plaintext[len(CTRL_MOTD_PREFIX):].decode('utf-8', errors='replace')
                ui.print_msg('', f'📢 MOTD: {motd}',
                             name_colour=Fore.YELLOW, text_colour=Fore.YELLOW)
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
                    self._tab_selected = -1
                    return ''.join(buf)
                if ch == '\t':                      # Tab — cycle through peers
                    with self._peers_lock:
                        connected = [
                            p for p in self._peers.values() if p['connected'].is_set()
                        ]
                    if connected:
                        if self._tab_selected < 0:
                            self._tab_selected = 0
                        else:
                            self._tab_selected = (self._tab_selected + 1) % len(connected)
                        with print_lock:
                            ui._paint_panel()
                            sys.stdout.flush()
                    continue
                if ch == '\x1b':                    # Escape — clear tab selection
                    self._tab_selected = -1
                    with print_lock:
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                # k = kick selected peer (host only, only in tab-select mode)
                if ch == 'k' and self._tab_selected >= 0 and self.is_host:
                    with self._peers_lock:
                        connected_addrs = [
                            addr for addr, p in self._peers.items() if p['connected'].is_set()
                        ]
                    idx = self._tab_selected % len(connected_addrs) if connected_addrs else -1
                    self._tab_selected = -1
                    if idx >= 0:
                        self._kick_peer(connected_addrs[idx])
                    with print_lock:
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                # B = ban selected peer (host only, only in tab-select mode)
                if ch == 'B' and self._tab_selected >= 0 and self.is_host:
                    with self._peers_lock:
                        connected_addrs = [
                            addr for addr, p in self._peers.items() if p['connected'].is_set()
                        ]
                    idx = self._tab_selected % len(connected_addrs) if connected_addrs else -1
                    self._tab_selected = -1
                    if idx >= 0:
                        self._ban_peer(connected_addrs[idx])
                    with print_lock:
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
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
                if msg == '/clear':
                    with print_lock:
                        # Move to row 1 and erase to bottom of scroll region.
                        sys.stdout.write('\x1b[1;1H\x1b[J')
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                if msg == '/mute':
                    self._set_all_muted(True)
                    continue
                if msg == '/unmute':
                    self._set_all_muted(False)
                    continue
                if msg.startswith('/motd ') and self.is_host:
                    self.motd = msg[6:].strip()
                    self._broadcast(CTRL_MOTD_PREFIX + self.motd.encode('utf-8'))
                    with print_lock:
                        sys.stdout.write(
                            Fore.YELLOW + Style.BRIGHT
                            + f'MOTD updated: {self.motd}\n'
                            + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
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
