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

import socket
import sys

from colorama import Fore, Style

import config
import discovery
import stun
from discovery import lan_discover
from session import UDPClient
from ui import colour_for, pick_colour


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
    prefs = config.load()

    # --- username ---
    username = _prompt_with_default('Your name', prefs['username'] or 'anonymous')
    print()

    # --- colours ---
    name_colour = pick_colour(
        'Pick a colour for your name:',
        prefs['name_colour'],
    )
    print()
    text_colour = pick_colour(
        'Pick a colour for your message text:',
        prefs['text_colour'],
    )
    print()

    # Resolve colour names back from ANSI codes to persist them.
    from ui import COLOURS
    name_colour_name = next((n for n, c in COLOURS if c == name_colour), 'cyan')
    text_colour_name = next((n for n, c in COLOURS if c == text_colour), 'white')
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
    print(f'Your public IP (internet): {ext_ip or "unavailable"}')
    print(f'Your chat port:            {chat_port}')
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
                peer_addr = lan_discover(chat_port, room_code)
                if peer_addr is None:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + 'No peer found on the local network.')
                    continue
                UDPClient(
                    peer_addr[0], sock,
                    port=peer_addr[1],
                    username=username,
                    name_colour=name_colour,
                    text_colour=text_colour,
                )
            elif mode == 'g':
                peer_ip = input("Peer's public IP: ").strip()
                if not peer_ip:
                    continue
                peer_port = int(input("Peer's port: ").strip())
                UDPClient(
                    peer_ip, sock,
                    port=peer_port,
                    username=username,
                    name_colour=name_colour,
                    text_colour=text_colour,
                )
            else:
                print('Enter l or g.')
        except KeyboardInterrupt:
            print('\nExiting...')
            sys.exit(0)
