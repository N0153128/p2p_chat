"""
Terminal UI utilities: colour palette, thread-safe message printing,
and the interactive colour picker shown at startup.
"""

import sys
import threading

from colorama import Fore, Style


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

print_lock = threading.Lock()
"""Mutex that serialises all terminal writes to prevent interleaved output."""


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


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


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
# Startup colour picker
# ---------------------------------------------------------------------------


def pick_colour(prompt, default_name):
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
            return colour_for(default_name)
        if raw.isdigit() and 1 <= int(raw) <= len(COLOURS):
            return COLOURS[int(raw) - 1][1]
        print(f'Enter a number between 1 and {len(COLOURS)}.')
