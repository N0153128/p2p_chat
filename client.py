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
"""

import os
import random
import socket
import sys

from colorama import Fore, Style

import config
import discovery
import stun
from session import UDPClient
from ui import pick_colour, show_greeting


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
    """Show *prompt*, return *default* if the user presses Enter without input.

    Args:
        prompt:  Text shown to the user (should not include the default hint,
                 that is appended automatically).
        default: Value returned on empty input.

    Returns:
        Stripped string — either what the user typed or *default*.
    """
    raw = input(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


if __name__ == '__main__':
    show_greeting()

    prefs = config.load()

    # --- username ---
    username = _prompt_with_default('Your name', prefs['username'] or 'anonymous')
    print()

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

    sys.stdout.write(
        Fore.CYAN + Style.BRIGHT + '  public IP  ' + Style.RESET_ALL
        + Fore.WHITE + Style.BRIGHT + (ext_ip or 'unavailable') + Style.RESET_ALL + '\n'
    )
    sys.stdout.write(
        Fore.CYAN + Style.BRIGHT + '  chat port  ' + Style.RESET_ALL
        + Fore.WHITE + Style.BRIGHT + str(chat_port) + Style.RESET_ALL + '\n'
    )
    sys.stdout.write('\n')
    sys.stdout.write(
        Fore.MAGENTA + Style.BRIGHT + '  l' + Style.RESET_ALL
        + Fore.WHITE + '  —  find a peer on this network automatically\n' + Style.RESET_ALL
    )
    sys.stdout.write(
        Fore.MAGENTA + Style.BRIGHT + '  g' + Style.RESET_ALL
        + Fore.WHITE + '  —  connect to a peer on the internet\n' + Style.RESET_ALL
    )
    sys.stdout.write('\n')
    sys.stdout.flush()

    while True:
        try:
            mode = input('Mode (l/g): ').strip().lower()
            if mode == 'l':
                while True:
                    sys.stdout.write(Fore.CYAN + '  Scanning for active rooms...' + Style.RESET_ALL + '\r')
                    sys.stdout.flush()
                    rooms = discovery.scan_active_rooms(timeout=2.0)
                    sys.stdout.write('\x1b[2K')  # erase the scanning line

                    if rooms:
                        sys.stdout.write(
                            Fore.CYAN + Style.BRIGHT
                            + f'  {len(rooms)} active room{"s" if len(rooms) != 1 else ""} on this network:\n'
                            + Style.RESET_ALL
                        )
                        for i, (sid, name, code, has_passcode, max_peers) in enumerate(rooms, 1):
                            label = name if name else '(unnamed)'
                            lock_icon = ' 🔒' if has_passcode else ''
                            sys.stdout.write(
                                Fore.MAGENTA + Style.BRIGHT + f'  {i}' + Style.RESET_ALL
                                + Fore.WHITE + f'  {label}{lock_icon}'
                                + Fore.WHITE + Style.DIM + f'  [{max_peers} slots]\n' + Style.RESET_ALL
                            )
                        sys.stdout.write(
                            Fore.MAGENTA + Style.BRIGHT + '  0' + Style.RESET_ALL
                            + Fore.WHITE + Style.DIM + '  create a new room\n' + Style.RESET_ALL
                        )
                        sys.stdout.flush()

                        while True:
                            raw = input(f'  Join room (1–{len(rooms)}) or 0 to create new: ').strip()
                            if not raw.isdigit():
                                print('  Enter a number.')
                                continue
                            choice = int(raw)
                            if 1 <= choice <= len(rooms):
                                # --- Join an existing room ---
                                sid, room_name, room_code, has_passcode, max_peers = rooms[choice - 1]
                                passcode = ''
                                if has_passcode:
                                    passcode = input('  Passcode: ').strip()
                                effective_room_code = room_code + ':' + passcode if passcode else room_code
                                print(Fore.CYAN + Style.BRIGHT + 'Joining room...' + Style.RESET_ALL)
                                UDPClient(
                                    sock,
                                    username=username,
                                    name_colour=name_colour,
                                    text_colour=text_colour,
                                    room_code=effective_room_code,
                                    chat_port=chat_port,
                                    room_name=room_name,
                                    max_peers=max_peers,
                                )
                                break
                            elif choice == 0:
                                break  # fall through to create flow below
                            else:
                                print(f'  Enter a number between 0 and {len(rooms)}.')
                        else:
                            break  # inner while exited normally (joined) — exit outer while
                        if choice != 0:
                            break  # joined a room, exit the scan loop
                        # choice == 0: fall through to create flow
                    else:
                        sys.stdout.write(
                            Fore.WHITE + '  No active rooms on this network.\n' + Style.RESET_ALL
                        )
                        sys.stdout.flush()
                        action = input('  Create a new room (c) or re-scan (r)? ').strip().lower()
                        if action == 'r':
                            continue  # re-scan
                        # anything else → create

                    # --- Create a new room ---
                    while True:
                        room_name = input('  Room name: ').strip()
                        if room_name:
                            break
                        print('  Room name cannot be empty.')
                    while True:
                        raw_slots = input('  Slots (2–32): ').strip()
                        if raw_slots.isdigit() and 2 <= int(raw_slots) <= 32:
                            max_peers = int(raw_slots)
                            break
                        print('  Enter a number between 2 and 32.')
                    enable_host_str = input('  Enable host mode? (y/N): ').strip().lower()
                    is_host = enable_host_str == 'y'
                    passcode = ''
                    motd = ''
                    if is_host:
                        passcode = input('  Passcode (digits only, blank = open): ').strip()
                        if passcode and not passcode.isdigit():
                            print('  Passcode must be digits only, ignoring.')
                            passcode = ''
                        motd = input('  Message of the day: ').strip()
                    # Generate a random internal room code — users never see this.
                    room_code = '%016x' % random.getrandbits(64)
                    effective_room_code = room_code + ':' + passcode if passcode else room_code
                    print(Fore.CYAN + Style.BRIGHT
                          + 'Waiting for peers to join your room...'
                          + Style.RESET_ALL)
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
                    )
                    break
            elif mode == 'g':
                peer_ip = input("Peer's public IP: ").strip()
                if not peer_ip:
                    continue
                peer_port = int(input("Peer's port: ").strip())
                print(Fore.CYAN + Style.BRIGHT
                      + 'Connecting... others can join by entering your IP and port above.'
                      + Style.RESET_ALL)
                UDPClient(
                    sock,
                    username=username,
                    name_colour=name_colour,
                    text_colour=text_colour,
                    peers=[(peer_ip, peer_port)],
                )
            else:
                print('Enter l or g.')
        except KeyboardInterrupt:
            print('\nExiting...')
            sys.exit(0)
