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
import random
import shutil
import signal
import sys
import threading
from time import sleep, time

import nacl.public
from colorama import Fore, Style

import db
import discovery
from protocol import (
    BEACON_PREFIX,
    BROADCAST_INTERVAL,
    CTRL_ACK_PREFIX,
    CTRL_BAN_PREFIX,
    CTRL_NICK_PREFIX,
    CTRL_DISCONNECT,
    CTRL_KICK_PREFIX,
    CTRL_META_PREFIX,
    CTRL_MOTD_PREFIX,
    CTRL_ROOM_CLOSED,
    MAX_PEERS,
    MSG_ACK_TIMEOUT,
    PUNCH_ACK_PREFIX,
    PUNCH_BAN,
    PUNCH_INTERVAL,
    PUNCH_PREFIX,
    PUNCH_TIMEOUT,
)
import ui
from ui import COLOURS, colour_for, print_lock


class _MsgTracker:
    """Track delivery acks for a single outgoing message.

    Created when a message is sent.  Each connected peer at send-time is
    added as a pending recipient.  As acks arrive, peers are removed.
    When all acks are received, or MSG_ACK_TIMEOUT elapses, the visual
    status indicator on the message line is updated.

    Args:
        msg_id:      8-hex-char message ID string.
        peer_addrs:  Iterable of ``(ip, port)`` for every peer the message
                     was sent to.
        update_fn:   Callable returned by ``ui.print_msg_pending``; called
                     with ``'ok'``, ``'partial'``, or ``'fail'``.
    """

    def __init__(self, msg_id, peer_addrs, update_fn):
        self._id = msg_id
        self._pending = set(peer_addrs)
        self._total = len(self._pending)
        self._update = update_fn
        self._lock = threading.Lock()
        self._done = False
        if not self._pending:
            # No peers — nothing to wait for.
            update_fn('ok')
            self._done = True
        else:
            t = threading.Timer(MSG_ACK_TIMEOUT, self._timeout)
            t.daemon = True
            t.start()

    def ack(self, addr):
        """Record an ack from *addr*.  Resolves immediately if all acks received."""
        with self._lock:
            if self._done:
                return
            self._pending.discard(addr)
            if not self._pending:
                self._done = True
                self._update('ok')

    def _timeout(self):
        with self._lock:
            if self._done:
                return
            self._done = True
            missed = len(self._pending)
            if missed == self._total:
                self._update('fail')
            else:
                self._update('partial')


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
        max_peers=MAX_PEERS,
        anonymous=False,
    ):
        self.sock = sock
        self.username = username
        self.name_colour = name_colour
        self.text_colour = text_colour
        self.is_host = is_host
        self.room_name = room_name
        self.motd = motd
        self.anonymous = anonymous
        self._passcode = passcode
        self._muted = db.get_setting('muted', '0') == '1'
        # Raw token without the passcode suffix — embedded in beacons so
        # joiners can read it and reconstruct the effective room code themselves.
        self._raw_room_code = room_code[:-len(':' + passcode)] if passcode else room_code
        self._banned_ips = banned_ips if banned_ips is not None else set()
        self._max_peers = max(2, min(int(max_peers), MAX_PEERS))
        self._tab_selected = -1
        self._own_addr = sock.getsockname()

        self.done = threading.Event()
        # True when at least one peer disconnected (not a local /exit).
        self.peer_disconnected = False

        self._privkey = nacl.public.PrivateKey.generate()
        self._pubkey_bytes = bytes(self._privkey.public_key)

        # Per-peer state keyed by (ip, port).
        # {'box': Box|None, 'connected': Event, 'name_colour': code, 'text_colour': code, ...}
        self._peers_lock = threading.Lock()
        self._peers = {}
        # Maps pubkey fingerprint (16-hex) → current (ip, port) for reconnect detection.
        self._peer_by_pubkey: dict[str, tuple] = {}

        # first_connected is set the moment any peer completes the handshake.
        self._first_connected = threading.Event()

        # Pending delivery trackers keyed by msg_id.
        self._ack_trackers: dict[str, _MsgTracker] = {}
        self._ack_lock = threading.Lock()

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

        ui.get_prompt = self._prompt
        ui.get_statusbar = self._statusbar
        with print_lock:
            ui.enable_statusbar()
            if self.room_name:
                history = db.load_history(self.room_name)
                if history:
                    ui.print_history(history)
            sys.stdout.flush()
        self._panel_disabled = False

        # Start send thread AFTER history is printed so tty.setraw doesn't
        # race with print_history (raw mode turns \n into just LF, not CR+LF).
        send_thread = threading.Thread(target=self._send_loop, daemon=True)
        send_thread.start()
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
        capacity = self._max_peers
        members = [self.name_colour + Style.BRIGHT + self.username + Style.RESET_ALL]
        for p in connected:
            name = p['username']
            if name:
                members.append(p['name_colour'] + Style.BRIGHT + name + Style.RESET_ALL)
            else:
                members.append(Fore.WHITE + Style.DIM + '...' + Style.RESET_ALL)

        # Apply tab-select highlight to the selected peer (index into connected list).
        tab_idx = self._tab_selected
        if tab_idx >= 0 and connected:
            tab_idx = tab_idx % len(connected)
            # Rebuild the selected peer's entry with inverse-video highlight.
            # Index 0 in members is ourselves; peers start at index 1.
            peer_member_idx = tab_idx + 1
            name = connected[tab_idx]['username'] or '...'
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

    def _log(self, sender, body, name_colour=None, text_colour=None):
        """Append a message to the room's history log (no-op if no room name)."""
        from ui import COLOURS
        nc_name = next((n for n, c in COLOURS if c == name_colour), 'white') if name_colour else 'white'
        tc_name = next((n for n, c in COLOURS if c == text_colour), 'white') if text_colour else 'white'
        db.log_message(self.room_name, sender, body, nc_name, tc_name)

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
        username = peer.get('username') or (f'***:{addr[1]}' if self.anonymous else str(addr))
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
        username = peer.get('username') or (f'***:{addr[1]}' if self.anonymous else str(addr))
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

    def _add_peer(self, addr, carry=None):
        """Register *addr* as a known peer and start punching to it.

        No-op if the peer is already known or the room is full.
        Returns True if the peer was newly added.

        Args:
            addr:  ``(ip, port)`` tuple.
            carry: Optional existing peer dict to reuse (reconnect case) — the
                   dict is reset for a fresh handshake while preserving display
                   info like username and colours.
        """
        with self._peers_lock:
            if addr in self._peers or len(self._peers) >= self._max_peers - 1:
                return False
            if carry:
                # Reconnecting peer: reset handshake state, keep display info.
                carry['box'] = None
                carry['connected'] = threading.Event()
                self._peers[addr] = carry
            else:
                self._peers[addr] = {
                    'box': None,
                    'connected': threading.Event(),
                    'name_colour': Fore.CYAN,
                    'text_colour': Fore.WHITE,
                    'muted': self._muted,
                    'username': '',
                    'is_host': False,
                    'room_name': '',
                }
        t = threading.Thread(target=self._punch, args=(addr,), daemon=True)
        t.start()
        return True

    def _remove_unconnected_peer(self, addr):
        """Remove a peer that never completed the handshake, freeing its slot."""
        with self._peers_lock:
            peer = self._peers.get(addr)
            if peer and not peer['connected'].is_set():
                self._peers.pop(addr, None)
                # Also remove from pubkey index if still pointing at this addr.
                stale = [fp for fp, a in self._peer_by_pubkey.items() if a == addr]
                for fp in stale:
                    self._peer_by_pubkey.pop(fp, None)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_sigint(self, sig, frame):
        if self.done.is_set():
            # Second Ctrl+C after already leaving the room — hard exit.
            sys.exit(0)
        if self.is_host:
            self._broadcast(CTRL_ROOM_CLOSED)
        else:
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
        """Build and store the Box for *addr*.

        Also maintains the pubkey→addr index for reconnect detection.
        If the pubkey is already known at a *different* address, the stale
        peer entry is migrated to the new address before the box is built.

        Returns the Box, or None on error.
        """
        try:
            peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pubkey_hex))
            box = nacl.public.Box(self._privkey, peer_pub)
        except Exception:
            return None

        fp = peer_pubkey_hex[:16]

        with self._peers_lock:
            old_addr = self._peer_by_pubkey.get(fp)
            if old_addr and old_addr != addr and old_addr in self._peers:
                # Same peer, new address — migrate the peer dict.
                peer_dict = self._peers.pop(old_addr)
                peer_dict['box'] = None
                peer_dict['connected'] = threading.Event()
                self._peers[addr] = peer_dict
            self._peer_by_pubkey[fp] = addr
            if addr in self._peers:
                self._peers[addr]['box'] = box
                self._peers[addr]['pubkey_fp'] = fp

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
        """Send PUNCH packets to *addr* until connected, done, or timed out.

        On timeout without a successful handshake, removes the peer entry so
        the slot is freed for future joiners.
        """
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
        if not peer['connected'].is_set() and not self.done.is_set():
            self._remove_unconnected_peer(addr)

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
            f':{room_code_b64}:{room_name_b64}:{has_passcode_flag}:{self._max_peers}'
        ).encode()
        # Maps peer session ID → last seen (ip, port).  Used to detect
        # reconnects where a peer reappears at a new address.
        seen_sids: dict[str, tuple] = {}

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
                if self.is_host:
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

                if peer_sid == discovery.SESSION_ID:
                    continue

                expected = discovery._beacon_hmac(room_code, peer_sid)
                if not hmaclib.compare_digest(peer_tag, expected):
                    continue

                try:
                    peer_port = int(peer_port_str)
                except ValueError:
                    continue

                peer_addr = (addr[0], peer_port)

                with self._peers_lock:
                    already_at_addr = peer_addr in self._peers
                    full = len(self._peers) >= self._max_peers - 1
                    # Check if this sid was seen before at a different address
                    # (peer reconnected from a new IP/port after a drop).
                    prev_addr = seen_sids.get(peer_sid)
                    reconnecting = (
                        prev_addr is not None
                        and prev_addr != peer_addr
                        and prev_addr in self._peers
                        and not self._peers[prev_addr]['connected'].is_set()
                    )
                    carry = None
                    if reconnecting:
                        carry = self._peers.pop(prev_addr)

                seen_sids[peer_sid] = peer_addr

                if already_at_addr:
                    continue
                if full and not reconnecting:
                    continue

                # Unicast our beacon back so the peer sees us too.
                try:
                    disc.sendto(my_beacon, addr)
                except Exception:
                    pass

                self._add_peer(peer_addr, carry=carry)

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
                full = len(self._peers) >= self._max_peers - 1

            # Accept PUNCH from unknown addresses: late joiner or reconnecting peer.
            if not known:
                if data.startswith(PUNCH_PREFIX):
                    # Check if this is a known pubkey at a new address (reconnect).
                    peer_pubkey_hex = data[len(PUNCH_PREFIX):].decode(errors='ignore')
                    fp = peer_pubkey_hex[:16]
                    with self._peers_lock:
                        old_addr = self._peer_by_pubkey.get(fp)
                        carry = None
                        if old_addr and old_addr != addr and old_addr in self._peers:
                            carry = self._peers.pop(old_addr)
                    if carry is not None:
                        self._add_peer(addr, carry=carry)
                    elif not full:
                        self._add_peer(addr)
                    else:
                        continue
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
                    peer_display = f'***:{addr[1]}' if self.anonymous else f'{addr[0]}:{addr[1]}'
                    rejoining = bool(peer.get('username'))
                    if rejoining:
                        event_msg = f'{peer["username"]} reconnected ({peer_display})'
                        colour = Fore.YELLOW
                    else:
                        event_msg = f'Peer joined! ({peer_display}, encrypted)'
                        colour = Fore.LIGHTGREEN_EX
                    with print_lock:
                        sys.stdout.write(
                            f'\r{" " * 80}\r'
                            + colour + Style.BRIGHT + event_msg + '\n' + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
                    self._log('', event_msg)
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
                    peer_display = f'***:{addr[1]}' if self.anonymous else f'{addr[0]}:{addr[1]}'
                    rejoining = bool(peer.get('username'))
                    if rejoining:
                        event_msg = f'{peer["username"]} reconnected ({peer_display})'
                        colour = Fore.YELLOW
                    else:
                        event_msg = f'Peer joined! ({peer_display}, encrypted)'
                        colour = Fore.LIGHTGREEN_EX
                    with print_lock:
                        sys.stdout.write(
                            f'\r{" " * 80}\r'
                            + colour + Style.BRIGHT + event_msg + '\n' + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
                    self._log('', event_msg)
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
                left_msg = ('A peer left.'
                            + (f'  ({remaining} peer{"s" if remaining != 1 else ""} remaining)'
                               if remaining else ''))
                with print_lock:
                    sys.stdout.write(f'\r{" " * 80}\r')
                    sys.stdout.write(
                        Fore.LIGHTYELLOW_EX + Style.BRIGHT + left_msg + '\n' + Style.RESET_ALL
                    )
                    ui._paint_panel()
                    sys.stdout.flush()
                self._log('', left_msg)
                self.peer_disconnected = True
                if remaining == 0 and not self.done.is_set():
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
                self._log('', 'You were kicked from the room.')
                self.done.set()
                continue

            if plaintext == CTRL_BAN_PREFIX:
                ui.print_msg('', Fore.RED + Style.BRIGHT + 'You were banned from the room.' + Style.RESET_ALL,
                             name_colour='', text_colour='')
                self._log('', 'You were banned from the room.')
                self.done.set()
                continue

            if plaintext == CTRL_ROOM_CLOSED:
                ui.print_msg('', Fore.RED + Style.BRIGHT + 'The host closed the room.' + Style.RESET_ALL,
                             name_colour='', text_colour='')
                self._log('', 'The host closed the room.')
                self.done.set()
                continue

            if plaintext.startswith(CTRL_MOTD_PREFIX):
                motd = plaintext[len(CTRL_MOTD_PREFIX):].decode('utf-8', errors='replace')
                ui.print_msg('', f'📢 MOTD: {motd}',
                             name_colour=Fore.YELLOW, text_colour=Fore.YELLOW)
                self._log('', f'📢 MOTD: {motd}')
                continue

            if plaintext.startswith(CTRL_NICK_PREFIX):
                payload = plaintext[len(CTRL_NICK_PREFIX):].decode('utf-8', errors='replace')
                if '\t' in payload:
                    old_name, new_name = payload.split('\t', 1)
                    with self._peers_lock:
                        if addr in self._peers:
                            self._peers[addr]['username'] = new_name
                    notice = f'{old_name} is now known as {new_name}'
                    ui.print_msg('', notice, name_colour=Fore.CYAN, text_colour=Fore.CYAN)
                    self._log('', notice)
                    self._redraw_statusbar()
                continue

            # Delivery ack from a peer for one of our outgoing messages.
            if plaintext.startswith(CTRL_ACK_PREFIX):
                msg_id = plaintext[len(CTRL_ACK_PREFIX):].decode('ascii', errors='ignore')
                with self._ack_lock:
                    tracker = self._ack_trackers.get(msg_id)
                if tracker:
                    tracker.ack(addr)
                continue

            with self._peers_lock:
                peer = self._peers.get(addr, {})
            name_colour = peer.get('name_colour', Fore.CYAN)
            text_colour = peer.get('text_colour', Fore.WHITE)
            muted = peer.get('muted', False)

            text = plaintext.decode('utf-8', errors='replace')

            # Strip the optional ``<msg_id>|`` prefix and send an ack back.
            msg_id = None
            if len(text) >= 9 and text[8] == '|':
                candidate = text[:8]
                if all(c in '0123456789abcdef' for c in candidate):
                    msg_id = candidate
                    text = text[9:]
            if msg_id is not None:
                with self._peers_lock:
                    box = self._peers.get(addr, {}).get('box')
                if box:
                    try:
                        self.sock.sendto(
                            box.encrypt(CTRL_ACK_PREFIX + msg_id.encode()), addr
                        )
                    except Exception:
                        pass

            if text.startswith('<') and '>: ' in text:
                split_at = text.index('>: ')
                name_part = text[:split_at + 1]
                body_part = text[split_at + 2:]
                ui.print_msg(name_part, body_part,
                             name_colour=name_colour, text_colour=text_colour, alert=not muted)
                self._log(name_part, body_part, name_colour=name_colour, text_colour=text_colour)
            else:
                ui.print_msg('', text,
                             name_colour=name_colour, text_colour=text_colour, alert=not muted)
                self._log('', text, name_colour=name_colour, text_colour=text_colour)

        try:
            self.sock.settimeout(None)
        except OSError:
            pass

    def _set_all_muted(self, muted):
        """Set the mute flag on every peer, persist the preference, and print a confirmation."""
        self._muted = muted
        with self._peers_lock:
            for p in self._peers.values():
                p['muted'] = muted
        db.set_setting('muted', '1' if muted else '0')
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
        prompt = self._prompt()
        buf_text = self.text_colour + ''.join(buf) + Style.RESET_ALL if buf else ''
        sys.stdout.write(ui._center_pad(prompt + ''.join(buf)) + prompt + buf_text)

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

        _ALL_COMMANDS = [
            '/exit', '/clear', '/nick', '/mute', '/unmute',
            '/motd', '/close', '/save_preset', '/dump_presets',
            '/wipe_presets', '/help',
        ]
        _suggestion_rows = [0]  # mutable cell: how many overlay rows currently shown

        def _update_suggestions():
            """Paint or clear the command suggestion overlay above the separator."""
            text = ''.join(buf)
            cols, rows = ui._term_size()
            sep_row = rows - 3  # the separator row above input

            # Clear previous overlay rows.
            n_prev = _suggestion_rows[0]
            if n_prev:
                for r in range(sep_row - n_prev, sep_row):
                    sys.stdout.write(f'\x1b[{r};1H\x1b[2K')
                _suggestion_rows[0] = 0

            if not text.startswith('/') or text == '/':
                return

            matches = [c for c in _ALL_COMMANDS if c.startswith(text.split()[0])][:5]
            if not matches:
                return

            start_row = sep_row - len(matches)
            for i, cmd in enumerate(matches):
                row = start_row + i
                if row < 1:
                    continue
                highlight = (i == 0)
                if highlight:
                    line = (Fore.BLACK + '\x1b[47m'  # white bg
                            + f'  {cmd:<20}' + Style.RESET_ALL)
                else:
                    line = Fore.CYAN + Style.DIM + f'  {cmd}' + Style.RESET_ALL
                sys.stdout.write(f'\x1b[{row};1H\x1b[2K' + line)
            _suggestion_rows[0] = len(matches)

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
                    if _suggestion_rows[0]:
                        cols, rows = ui._term_size()
                        sep_row = rows - 3
                        with print_lock:
                            for r in range(sep_row - _suggestion_rows[0], sep_row):
                                sys.stdout.write(f'\x1b[{r};1H\x1b[2K')
                            _suggestion_rows[0] = 0
                            sys.stdout.flush()
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
                if ch == '\x1b':                    # Escape — clear tab selection + suggestions
                    self._tab_selected = -1
                    buf.clear()
                    with print_lock:
                        _update_suggestions()
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
                            _update_suggestions()
                            sys.stdout.flush()
                else:
                    buf.append(ch)
                    with print_lock:
                        sys.stdout.write(
                            self.text_colour + ch + Style.RESET_ALL
                        )
                        _update_suggestions()
                        sys.stdout.flush()
        finally:
            # Clear any lingering suggestion overlay before releasing the terminal.
            if _suggestion_rows[0]:
                cols, rows = ui._term_size()
                sep_row = rows - 3
                with print_lock:
                    for r in range(sep_row - _suggestion_rows[0], sep_row):
                        sys.stdout.write(f'\x1b[{r};1H\x1b[2K')
                    sys.stdout.flush()
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
                    if self.is_host:
                        self._broadcast(CTRL_ROOM_CLOSED)
                    else:
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
                if msg == '/dump_presets':
                    text = db.dump_room_presets_text()
                    if text:
                        import datetime
                        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                        path = os.path.expanduser(f'~/p2p_presets_{stamp}.txt')
                        try:
                            with open(path, 'w', encoding='utf-8') as f:
                                f.write(text)
                            msg_out = f'Presets exported to {path}'
                            colour = Fore.GREEN
                        except OSError as e:
                            msg_out = f'Export failed: {e}'
                            colour = Fore.RED
                    else:
                        msg_out = 'No presets to export.'
                        colour = Fore.YELLOW
                    with print_lock:
                        sys.stdout.write(f'\r{" " * 80}\r')
                        sys.stdout.write(colour + Style.BRIGHT + msg_out + '\n' + Style.RESET_ALL)
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                if msg == '/wipe_presets':
                    db.wipe_room_presets()
                    with print_lock:
                        sys.stdout.write(f'\r{" " * 80}\r')
                        sys.stdout.write(
                            Fore.YELLOW + Style.BRIGHT + 'All presets deleted.\n' + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                if msg == '/save_preset' and self.is_host:
                    db.save_room_preset(
                        name=self.room_name,
                        slots=self._max_peers,
                        is_host=True,
                        passcode=self._passcode,
                    )
                    with print_lock:
                        sys.stdout.write(f'\r{" " * 80}\r')
                        sys.stdout.write(
                            Fore.GREEN + Style.BRIGHT
                            + f'Preset saved: "{self.room_name}"\n'
                            + Style.RESET_ALL
                        )
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                if msg.startswith('/nick '):
                    new_name = msg[6:].strip()
                    if not new_name:
                        ui.print_msg('', 'Usage: /nick <new name>',
                                     name_colour=Fore.YELLOW, text_colour=Fore.YELLOW)
                    elif new_name == self.username:
                        ui.print_msg('', 'That is already your name.',
                                     name_colour=Fore.YELLOW, text_colour=Fore.YELLOW)
                    else:
                        old_name = self.username
                        self.username = new_name
                        notice = f'{old_name} is now known as {new_name}'
                        self._broadcast(
                            CTRL_NICK_PREFIX
                            + f'{old_name}\t{new_name}'.encode('utf-8')
                        )
                        ui.print_msg('', notice,
                                     name_colour=Fore.CYAN, text_colour=Fore.CYAN)
                        self._log('', notice)
                        with print_lock:
                            ui._paint_panel()
                            sys.stdout.flush()
                    continue
                if msg == '/help':
                    _HELP = [
                        ('/exit',            'Leave the room'),
                        ('/clear',           'Clear chat on your screen'),
                        ('/nick <name>',     'Change your display name'),
                        ('/mute',            'Silence notification sounds'),
                        ('/unmute',          'Restore notification sounds'),
                        ('/motd <text>',     'Set message of the day  [host]'),
                        ('/close',           'Close the room           [host]'),
                        ('/save_preset',     'Save room as a preset    [host]'),
                        ('/dump_presets',    'Export presets to a file'),
                        ('/wipe_presets',    'Delete all presets'),
                        ('/help',            'Show this list'),
                    ]
                    with print_lock:
                        sys.stdout.write(f'\x1b[{ui._term_size()[1] - 4};1H')
                        sys.stdout.write(
                            Fore.WHITE + Style.DIM + '─── commands ───\n' + Style.RESET_ALL
                        )
                        for cmd, desc in _HELP:
                            sys.stdout.write(
                                Fore.CYAN + Style.BRIGHT + f'  {cmd:<20}' + Style.RESET_ALL
                                + Fore.WHITE + desc + '\n' + Style.RESET_ALL
                            )
                        ui._paint_panel()
                        sys.stdout.flush()
                    continue
                if msg == '/close' and self.is_host:
                    self._broadcast(CTRL_ROOM_CLOSED)
                    with print_lock:
                        sys.stdout.write(f'\r{" " * 80}\r')
                        sys.stdout.write(
                            Fore.RED + Style.BRIGHT
                            + 'Room closed.\n' + Style.RESET_ALL
                        )
                        sys.stdout.flush()
                    self.done.set()
                    break
                if msg:
                    msg_id = '%08x' % random.getrandbits(32)
                    wire = f'{msg_id}|<{self.username}>: {msg}'.encode('utf-8')
                    with self._peers_lock:
                        targets = [
                            addr for addr, p in self._peers.items()
                            if p['box'] is not None and p['connected'].is_set()
                        ]
                    for addr in targets:
                        with self._peers_lock:
                            box = self._peers[addr]['box']
                        if box:
                            try:
                                self.sock.sendto(box.encrypt(wire), addr)
                            except Exception:
                                pass
                    update_fn = ui.print_msg_pending(
                        f'(you) <{self.username}>',
                        f': {msg}',
                        name_colour=self.name_colour,
                        text_colour=self.text_colour,
                    )
                    tracker = _MsgTracker(msg_id, targets, update_fn)
                    with self._ack_lock:
                        self._ack_trackers[msg_id] = tracker
                    self._log(f'(you) <{self.username}>', f': {msg}',
                              name_colour=self.name_colour, text_colour=self.text_colour)
        except (KeyboardInterrupt, EOFError):
            if self.is_host and not self.done.is_set():
                self._broadcast(CTRL_ROOM_CLOSED)
