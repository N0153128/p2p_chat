"""
Terminal UI utilities: colour palette, greeting screen, thread-safe
message printing, and the interactive colour picker shown at startup.
"""

import shutil
import sys
import threading

import pyfiglet
from colorama import Fore, Style


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

COLOURS = [
    ('white',   Fore.WHITE),
    ('cyan',    Fore.CYAN),
    ('magenta', Fore.MAGENTA),
    ('yellow',  Fore.YELLOW),
    ('green',   Fore.GREEN),
    ('blue',    Fore.BLUE + Style.BRIGHT),
    ('red',     Fore.RED + Style.BRIGHT),
]
"""
Available terminal colours for username and message text.

Each entry is a ``(name: str, ansi_code: str)`` tuple.  All choices are
legible on both dark and light terminal backgrounds.
"""

COLOUR_NAMES = [name for name, _ in COLOURS]
"""Ordered list of colour name strings, derived from :data:`COLOURS`."""

print_lock = threading.Lock()
"""Mutex that serialises all terminal writes to prevent interleaved output."""

# Gradient used to colour the ASCII-art title: cyan → magenta.
_TITLE_GRADIENT = [
    Fore.CYAN,
    Fore.CYAN + Style.BRIGHT,
    Fore.BLUE + Style.BRIGHT,
    Fore.MAGENTA + Style.BRIGHT,
    Fore.MAGENTA,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def colour_for(name):
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


def _centre(text, width):
    """Return *text* padded with spaces so it is centred in *width* columns."""
    return text.center(width)


def _rule(width, char='─'):
    """Return a horizontal rule of *char* exactly *width* characters wide."""
    return char * width


# ---------------------------------------------------------------------------
# Greeting screen
# ---------------------------------------------------------------------------


def show_greeting():
    """Print a full-width greeting screen to stdout.

    Renders a gradient ASCII-art title, a decorative border, and a short
    tagline.  Safe to call before colorama.init() — colorama codes work on
    ANSI-capable terminals without explicit initialisation.
    """
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns

    # --- ASCII art title ---
    art = pyfiglet.figlet_format('p2p  chat', font='doom')
    art_lines = art.splitlines()
    art_width = max(len(line) for line in art_lines)

    # Apply a vertical gradient across the title lines.
    gradient_len = len(_TITLE_GRADIENT)
    coloured_lines = []
    for i, line in enumerate(art_lines):
        colour = _TITLE_GRADIENT[i * gradient_len // max(len(art_lines), 1)]
        coloured_lines.append(colour + Style.BRIGHT + line + Style.RESET_ALL)

    # --- top border ---
    sys.stdout.write('\n')
    sys.stdout.write(Fore.CYAN + Style.BRIGHT + _rule(cols, '═') + Style.RESET_ALL + '\n')
    sys.stdout.write('\n')

    # --- centred title ---
    pad = max(0, (cols - art_width) // 2)
    for line in coloured_lines:
        sys.stdout.write(' ' * pad + line + '\n')

    sys.stdout.write('\n')

    # --- tagline ---
    tagline = 'serverless  ·  encrypted  ·  peer-to-peer'
    sys.stdout.write(
        Fore.WHITE + Style.BRIGHT
        + _centre(tagline, cols)
        + Style.RESET_ALL + '\n'
    )

    # --- sub-rule ---
    sys.stdout.write('\n')
    sys.stdout.write(
        Fore.MAGENTA + Style.BRIGHT + _centre(_rule(len(tagline) + 8, '·'), cols) + Style.RESET_ALL + '\n'
    )

    # --- version / help hint ---
    hint = 'press  Ctrl+C  at any time to quit'
    sys.stdout.write(Fore.WHITE + _centre(hint, cols) + Style.RESET_ALL + '\n')

    # --- bottom border ---
    sys.stdout.write('\n')
    sys.stdout.write(Fore.CYAN + Style.BRIGHT + _rule(cols, '═') + Style.RESET_ALL + '\n')
    sys.stdout.write('\n')
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def print_msg(username_part, text_part, name_colour=Fore.CYAN, text_colour=Fore.WHITE, alert=False):
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
        alert:         If ``True``, emit a terminal bell character before the
                       message so the user is notified of an incoming message.
    """
    with print_lock:
        sys.stdout.write(f'\r{" " * 80}\r')
        sys.stdout.write(
            Style.BRIGHT + name_colour + username_part + Style.RESET_ALL
            + text_colour + text_part + Style.RESET_ALL + '\n'
        )
        sys.stdout.write(('\a' if alert else '') + '> ')
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Startup colour picker
# ---------------------------------------------------------------------------


def _erase_lines(n):
    """Move the cursor up *n* lines and erase each one."""
    for _ in range(n):
        sys.stdout.write('\x1b[1A\x1b[2K')
    sys.stdout.flush()


def pick_colour(prompt, default_name):
    """Display a numbered colour menu, erase it on selection, and return ``(name, ansi_code)``.

    Args:
        prompt:       Introductory line printed above the menu.
        default_name: Name of the colour returned when the user presses
                      Enter without input.

    Returns:
        ``(name, ansi_code)`` tuple from :data:`COLOURS`.
    """
    # 1 prompt + len(COLOURS) colour rows + 1 input row
    base_lines = 1 + len(COLOURS) + 1
    extra_lines = 0  # error lines accumulate here

    sys.stdout.write(Style.BRIGHT + Fore.WHITE + prompt + Style.RESET_ALL + '\n')
    for i, (name, code) in enumerate(COLOURS, 1):
        sys.stdout.write(
            f'  {Style.BRIGHT}{code}{i}{Style.RESET_ALL}'
            f'  {code}{name}{Style.RESET_ALL}\n'
        )
    sys.stdout.flush()
    while True:
        raw = input(f'  Choose (1-{len(COLOURS)}, default {default_name}): ').strip()
        if not raw:
            _erase_lines(base_lines + extra_lines)
            return default_name, colour_for(default_name)
        if raw.isdigit() and 1 <= int(raw) <= len(COLOURS):
            _erase_lines(base_lines + extra_lines)
            return COLOURS[int(raw) - 1]
        sys.stdout.write(
            Fore.RED + f'  Enter a number between 1 and {len(COLOURS)}.\n' + Style.RESET_ALL
        )
        sys.stdout.flush()
        extra_lines += 1
