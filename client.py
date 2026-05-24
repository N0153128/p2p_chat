"""
p2p_chat — entry point.

Handles startup prompts, socket setup, and the mode selection loop.
All business logic lives in the dedicated modules:

  config     — preference load/save (~/.p2p_chat.json)
  protocol   — wire constants and tuneable timeouts
  stun       — public IP/port discovery (RFC 5389)
  discovery  — LAN peer discovery via authenticated UDP broadcast
  ui         — colour palette, terminal output, startup colour picker
  session    — encrypted UDP chat session (UDPClient)

Flags
-----
-a / --anonymous   Hide your public and local IP everywhere in the UI.
                   Your port is still shown so peers can connect.
"""

import argparse
import os
import random
import socket
import sys

from colorama import Fore, Style

import config
import db
import discovery
import stun
from session import UDPClient
from ui import cinput, cprint, pick_colour, show_greeting


def _get_local_ip():
    """Detect the local interface IP by connecting to an external address.

    Returns:
        Dotted-decimal IP string, or ``'127.0.0.1'`` as a fallback.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _prompt_with_default(prompt, default):
    """Show *prompt*, return *default* if the user presses Enter without input."""
    raw = cinput(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


def _field(emoji, label, hint=''):
    """Print a styled field label and return the centred input prompt string."""
    hint_str = Fore.WHITE + Style.DIM + f'  {hint}' + Style.RESET_ALL if hint else ''
    content = (Fore.CYAN + Style.BRIGHT + f'  {emoji}  ' + Style.RESET_ALL
               + Fore.WHITE + Style.BRIGHT + label + Style.RESET_ALL
               + hint_str)
    cprint(content)
    prompt = Fore.CYAN + '  › ' + Style.RESET_ALL
    return prompt


def _section(title):
    """Print a coloured section divider."""
    cols = __import__('shutil').get_terminal_size(fallback=(80, 24)).columns
    line = Fore.WHITE + Style.DIM + '─' * cols + Style.RESET_ALL
    cprint(line, end='')
    cprint(Fore.YELLOW + Style.BRIGHT + f'  {title}' + Style.RESET_ALL)
    cprint(line, end='\n')


def _pick_preset():
    """Show saved room presets and return the chosen one, or None if cancelled.

    Returns:
        A preset dict (keys: name, slots, is_host, passcode) or None.
    """
    presets = db.load_room_presets()
    if not presets:
        cprint(Fore.YELLOW + Style.BRIGHT + '  ⊘  No saved presets.' + Style.RESET_ALL)
        return None

    _section('📋  Room Presets')
    for i, p in enumerate(presets, 1):
        lock_icon = ' 🔒' if p['passcode'] else ''
        host_icon = ' 👑' if p['is_host'] else ''
        cprint(
            Fore.MAGENTA + Style.BRIGHT + f'  {i}' + Style.RESET_ALL
            + Fore.WHITE + f'  {p["name"]}{lock_icon}{host_icon}'
            + Fore.WHITE + Style.DIM + f'  [{p["slots"]} slots]' + Style.RESET_ALL
        )

    while True:
        raw = cinput(f'  Choose preset (1–{len(presets)}) or 0 to cancel: ').strip()
        if not raw.isdigit():
            cprint('  Enter a number.')
            continue
        choice = int(raw)
        if choice == 0:
            return None
        if 1 <= choice <= len(presets):
            return presets[choice - 1]
        cprint(f'  Enter a number between 0 and {len(presets)}.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-a', '--anonymous', action='store_true')
    parser.add_argument('-c', '--center', action='store_true')
    args, _ = parser.parse_known_args()
    anonymous = args.anonymous

    import ui as _ui
    _ui.centered = args.center

    show_greeting()

    prefs = config.load()

    # --- username ---
    username = _prompt_with_default('Your name', prefs['username'] or 'anonymous')
    cprint()

    # --- colours ---
    name_colour_name, name_colour = pick_colour(
        'Pick a colour for your name:',
        prefs['name_colour'],
    )
    text_colour_name, text_colour = pick_colour(
        'Pick a colour for your message text:',
        prefs['text_colour'],
    )

    config.save(username, name_colour_name, text_colour_name)

    # --- network setup ---
    discovery.local_ip = _get_local_ip()

    # Chat socket binds to an OS-assigned port so two instances on the same
    # machine never collide.  The discovery socket (inside lan_discover) uses
    # the fixed DISCOVERY_PORT with SO_REUSEADDR.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 0))
    chat_port = sock.getsockname()[1]

    ext_ip, _ = stun.get_external_address(sock)

    display_ip = '***.***.***.***' if anonymous else (ext_ip or 'unavailable')
    cprint(Fore.CYAN + Style.BRIGHT + '  public IP  ' + Style.RESET_ALL
           + Fore.WHITE + Style.BRIGHT + display_ip + Style.RESET_ALL)
    cprint(Fore.CYAN + Style.BRIGHT + '  chat port  ' + Style.RESET_ALL
           + Fore.WHITE + Style.BRIGHT + str(chat_port) + Style.RESET_ALL)
    cprint()
    cprint(Fore.MAGENTA + Style.BRIGHT + '  l' + Style.RESET_ALL
           + Fore.WHITE + '  —  find a peer on this network automatically' + Style.RESET_ALL)
    cprint(Fore.MAGENTA + Style.BRIGHT + '  g' + Style.RESET_ALL
           + Fore.WHITE + '  —  connect to a peer on the internet' + Style.RESET_ALL)
    cprint()

    while True:
        try:
            mode = cinput('Mode (l/g): ').strip().lower()
            if mode == 'l':
                while True:
                    cprint(Fore.CYAN + '  Scanning for active rooms...' + Style.RESET_ALL, end='\r')
                    rooms = discovery.scan_active_rooms(timeout=2.0)
                    sys.stdout.write('\x1b[2K')  # erase the scanning line

                    if rooms:
                        cprint(Fore.CYAN + Style.BRIGHT
                               + f'  {len(rooms)} active room{"s" if len(rooms) != 1 else ""} on this network:'
                               + Style.RESET_ALL)
                        for i, (sid, name, code, has_passcode, max_peers) in enumerate(rooms, 1):
                            label = name if name else '(unnamed)'
                            lock_icon = ' 🔒' if has_passcode else ''
                            cprint(Fore.MAGENTA + Style.BRIGHT + f'  {i}' + Style.RESET_ALL
                                   + Fore.WHITE + f'  {label}{lock_icon}'
                                   + Fore.WHITE + Style.DIM + f'  [{max_peers} slots]' + Style.RESET_ALL)
                        cprint(Fore.MAGENTA + Style.BRIGHT + '  0' + Style.RESET_ALL
                               + Fore.WHITE + Style.DIM + '  create a new room' + Style.RESET_ALL)
                        cprint(Fore.MAGENTA + Style.BRIGHT + '  p' + Style.RESET_ALL
                               + Fore.WHITE + Style.DIM + '  create from preset' + Style.RESET_ALL)

                        while True:
                            raw = cinput(f'  Join room (1–{len(rooms)}), 0 to create, p for preset: ').strip().lower()
                            if raw == 'p':
                                choice = 'p'
                                break
                            if not raw.isdigit():
                                cprint('  Enter a number or p.')
                                continue
                            choice = int(raw)
                            if 1 <= choice <= len(rooms):
                                # --- Join an existing room ---
                                sid, room_name, room_code, has_passcode, max_peers = rooms[choice - 1]
                                passcode = ''
                                if has_passcode:
                                    passcode = cinput(Fore.CYAN + '  🔒 Passcode: ' + Style.RESET_ALL).strip()
                                effective_room_code = room_code + ':' + passcode if passcode else room_code
                                cprint(Fore.CYAN + Style.BRIGHT + 'Joining room...' + Style.RESET_ALL)
                                UDPClient(
                                    sock,
                                    username=username,
                                    name_colour=name_colour,
                                    text_colour=text_colour,
                                    room_code=effective_room_code,
                                    chat_port=chat_port,
                                    room_name=room_name,
                                    max_peers=max_peers,
                                    anonymous=anonymous,
                                )
                                break
                            elif choice == 0:
                                break  # fall through to create flow below
                            else:
                                cprint(f'  Enter a number between 0 and {len(rooms)}, or p.')
                        else:
                            break  # inner while exited normally (joined) — exit outer while
                        if choice not in (0, 'p'):
                            break  # joined a room, exit the scan loop
                        # choice == 0 or 'p': fall through to create/preset flow
                    else:
                        cprint(Fore.YELLOW + Style.BRIGHT + '  ⊘  No active rooms on this network.' + Style.RESET_ALL)
                        action = cinput(
                            Fore.CYAN + '  › ' + Style.RESET_ALL
                            + Fore.WHITE + 'Create a room ' + Style.RESET_ALL
                            + Fore.WHITE + Style.DIM + '(c)' + Style.RESET_ALL
                            + Fore.WHITE + ', use a preset ' + Style.RESET_ALL
                            + Fore.WHITE + Style.DIM + '(p)' + Style.RESET_ALL
                            + Fore.WHITE + ', or re-scan ' + Style.RESET_ALL
                            + Fore.WHITE + Style.DIM + '(r)' + Style.RESET_ALL
                            + Fore.CYAN + ': ' + Style.RESET_ALL
                        ).strip().lower()
                        if action == 'r':
                            continue  # re-scan
                        choice = 'p' if action == 'p' else 0

                    # --- Preset flow ---
                    if choice == 'p':
                        preset = _pick_preset()
                        if preset is None:
                            continue  # cancelled — re-scan
                        room_name = preset['name']
                        max_peers = preset['slots']
                        is_host = preset['is_host']
                        passcode = preset['passcode']
                        motd = ''
                    else:
                        # --- Create a new room ---
                        _section('✦  Create a Room')

                        _field('🏷️', 'Room name')
                        while True:
                            room_name = cinput(Fore.CYAN + '  › ' + Style.RESET_ALL).strip()
                            if room_name:
                                break
                            cprint(Fore.RED + '  ✖  Name cannot be empty.' + Style.RESET_ALL)

                        _field('👥', 'Slots', 'max 32 — how many people can join')
                        while True:
                            raw_slots = cinput(Fore.CYAN + '  › ' + Style.RESET_ALL).strip()
                            if raw_slots.isdigit() and 2 <= int(raw_slots) <= 32:
                                max_peers = int(raw_slots)
                                break
                            cprint(Fore.RED + '  ✖  Enter a number between 2 and 32.' + Style.RESET_ALL)

                        _field('👑', 'Host mode?', 'y = you control kicks, bans and MOTD  /  n = open room')
                        enable_host_str = cinput(Fore.CYAN + '  › (y/N) ' + Style.RESET_ALL).strip().lower()
                        is_host = enable_host_str == 'y'

                        passcode = ''
                        motd = ''
                        if is_host:
                            _field('🔒', 'Passcode', 'digits only — leave blank for an open room')
                            while True:
                                raw_pc = cinput(Fore.CYAN + '  › ' + Style.RESET_ALL).strip()
                                if not raw_pc:
                                    break
                                if raw_pc.isdigit():
                                    passcode = raw_pc
                                    break
                                cprint(Fore.RED + '  ✖  Digits only (or leave blank).' + Style.RESET_ALL)

                            _field('📢', 'Message of the day', 'shown to everyone when they join')
                            motd = cinput(Fore.CYAN + '  › ' + Style.RESET_ALL).strip()

                    # --- Launch the room (shared by create and preset paths) ---
                    room_code = '%016x' % random.getrandbits(64)
                    effective_room_code = room_code + ':' + passcode if passcode else room_code

                    cprint()
                    cprint(Fore.GREEN + Style.BRIGHT + '  ✔  Room created!' + Style.RESET_ALL
                           + Fore.WHITE + Style.DIM + '  Waiting for peers to join...' + Style.RESET_ALL)

                    UDPClient(
                        sock,
                        username=username,
                        name_colour=name_colour,
                        text_colour=text_colour,
                        room_code=effective_room_code,
                        chat_port=chat_port,
                        is_host=is_host,
                        room_name=room_name,
                        motd=motd,
                        passcode=passcode,
                        max_peers=max_peers,
                        anonymous=anonymous,
                    )
                    break
            elif mode == 'g':
                peer_ip = cinput("Peer's public IP: ").strip()
                if not peer_ip:
                    continue
                peer_port = int(cinput("Peer's port: ").strip())
                if anonymous:
                    cprint(Fore.CYAN + Style.BRIGHT + 'Connecting...' + Style.RESET_ALL)
                else:
                    cprint(Fore.CYAN + Style.BRIGHT
                           + 'Connecting... others can join by entering your IP and port above.'
                           + Style.RESET_ALL)
                UDPClient(
                    sock,
                    username=username,
                    name_colour=name_colour,
                    text_colour=text_colour,
                    peers=[(peer_ip, peer_port)],
                    anonymous=anonymous,
                )
            else:
                cprint('Enter l or g.')
        except KeyboardInterrupt:
            cprint('\nExiting...')
            sys.exit(0)
