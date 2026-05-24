"""
Terminal UI utilities: colour palette, greeting screen, thread-safe
message printing, and the interactive colour picker shown at startup.
"""

import math
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
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

# Each preset is (font, gradient, top_border_colour, bottom_border_colour).
# Picked randomly on every boot.
_GREETING_PRESETS = [
    (
        'doom',
        [Fore.GREEN, Fore.GREEN + Style.BRIGHT, Fore.YELLOW + Style.BRIGHT,
         Fore.RED + Style.BRIGHT, Fore.RED],
        Fore.GREEN, Fore.RED,
    ),
    (
        'ansi_shadow',
        [Fore.CYAN, Fore.CYAN + Style.BRIGHT, Fore.BLUE + Style.BRIGHT,
         Fore.MAGENTA + Style.BRIGHT, Fore.MAGENTA],
        Fore.CYAN, Fore.MAGENTA,
    ),
    (
        'slant',
        [Fore.YELLOW + Style.BRIGHT, Fore.GREEN + Style.BRIGHT,
         Fore.CYAN + Style.BRIGHT, Fore.BLUE + Style.BRIGHT, Fore.BLUE],
        Fore.YELLOW, Fore.BLUE,
    ),
    (
        'bloody',
        [Fore.RED, Fore.RED + Style.BRIGHT, Fore.MAGENTA + Style.BRIGHT,
         Fore.RED + Style.BRIGHT, Fore.RED],
        Fore.RED + Style.BRIGHT, Fore.RED,
    ),
    (
        'block',
        [Fore.WHITE + Style.BRIGHT, Fore.CYAN + Style.BRIGHT,
         Fore.BLUE + Style.BRIGHT, Fore.MAGENTA + Style.BRIGHT, Fore.MAGENTA],
        Fore.WHITE, Fore.MAGENTA,
    ),
    (
        'graffiti',
        [Fore.MAGENTA + Style.BRIGHT, Fore.BLUE + Style.BRIGHT,
         Fore.CYAN + Style.BRIGHT, Fore.GREEN + Style.BRIGHT, Fore.GREEN],
        Fore.MAGENTA, Fore.GREEN,
    ),
    (
        'colossal',
        [Fore.CYAN + Style.BRIGHT, Fore.BLUE + Style.BRIGHT,
         Fore.BLUE, Fore.MAGENTA, Fore.MAGENTA + Style.BRIGHT],
        Fore.CYAN, Fore.BLUE,
    ),
    (
        'larry3d',
        [Fore.YELLOW + Style.BRIGHT, Fore.YELLOW,
         Fore.RED + Style.BRIGHT, Fore.RED, Fore.RED + Style.BRIGHT],
        Fore.YELLOW, Fore.RED,
    ),
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
    """Print a full-width greeting screen to stdout, scaled to terminal width."""
    from colorama import Back
    font, gradient, top_colour, bot_colour = random.choice(_GREETING_PRESETS)
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns

    # --- ASCII art — pick a font that actually fits the terminal ---
    def _render(f):
        lines = [ln for ln in pyfiglet.figlet_format('p2p  chat', font=f).splitlines() if ln.strip()]
        w = max((len(ln) for ln in lines), default=0)
        return lines, w

    art_lines, art_width = _render(font)
    # If the chosen font is too wide (> 90 % of terminal), fall back to a
    # narrower font while keeping the same colour scheme.
    if art_width > cols * 0.9:
        for fallback in ('slant', 'small', 'banner'):
            alt_lines, alt_width = _render(fallback)
            if alt_width <= cols * 0.9:
                art_lines, art_width = alt_lines, alt_width
                break

    # Pad lines to uniform width for the background block.
    art_lines = [line.ljust(art_width) for line in art_lines]

    # Centre the art block within the terminal.
    pad = max(0, (cols - art_width) // 2)

    # Vertical gradient on foreground; background fills the full terminal width.
    gradient_len = len(gradient)
    coloured_lines = []
    for i, line in enumerate(art_lines):
        fg = gradient[i * gradient_len // max(len(art_lines), 1)]
        # Left padding (plain), art with colour+background, right fill to edge.
        right_fill = cols - pad - art_width
        coloured_lines.append(
            Back.BLACK + ' ' * pad
            + fg + Style.BRIGHT + line
            + Style.RESET_ALL + Back.BLACK + ' ' * max(0, right_fill)
            + Style.RESET_ALL
        )

    # --- top border ---
    sys.stdout.write(top_colour + Style.BRIGHT + _rule(cols, '═') + Style.RESET_ALL + '\n')

    # --- title block (full-width background) ---
    blank_bg = Back.BLACK + ' ' * cols + Style.RESET_ALL
    sys.stdout.write(blank_bg + '\n')
    for line in coloured_lines:
        sys.stdout.write(line + '\n')
    sys.stdout.write(blank_bg + '\n')

    # --- tagline ---
    tagline = 'serverless  ·  encrypted  ·  peer-to-peer'
    sys.stdout.write(Fore.WHITE + Style.BRIGHT + _centre(tagline, cols) + Style.RESET_ALL + '\n')

    # --- hint row ---
    hint = '/exit · leave room    /mute · silence    Ctrl+C · leave / quit'
    sys.stdout.write(Fore.WHITE + Style.DIM + _centre(hint, cols) + Style.RESET_ALL + '\n')

    # --- bottom border ---
    sys.stdout.write(bot_colour + Style.BRIGHT + _rule(cols, '═') + Style.RESET_ALL + '\n')
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Alert sound
# ---------------------------------------------------------------------------

_beep_wav = None  # path to the generated WAV file, created on first use
_beep_lock = threading.Lock()


def _make_beep_wav():
    """Write a short sine-wave beep to a temp WAV file and return its path."""
    sample_rate = 44100
    frequency = 880      # Hz — a clear, high-pitched ping
    duration = 0.12      # seconds
    volume = 0.4         # 0.0–1.0

    n_samples = int(sample_rate * duration)
    # Ramp amplitude up then down over 10 ms to avoid clicks.
    ramp = int(sample_rate * 0.01)
    samples = []
    for i in range(n_samples):
        t = i / sample_rate
        amp = volume
        if i < ramp:
            amp *= i / ramp
        elif i > n_samples - ramp:
            amp *= (n_samples - i) / ramp
        samples.append(int(amp * 32767 * math.sin(2 * math.pi * frequency * t)))

    data = struct.pack(f'<{n_samples}h', *samples)
    data_size = len(data)
    header = struct.pack(
        '<4sI4s4sIHHIIHH4sI',
        b'RIFF', 36 + data_size, b'WAVE',
        b'fmt ', 16, 1, 1,        # PCM, mono
        sample_rate, sample_rate * 2, 2, 16,  # byte rate, block align, bits
        b'data', data_size,
    )
    fd, path = tempfile.mkstemp(suffix='.wav')
    with os.fdopen(fd, 'wb') as f:
        f.write(header + data)
    return path


def _play_beep():
    """Play the alert beep in a background process (non-blocking)."""
    global _beep_wav
    with _beep_lock:
        if _beep_wav is None:
            try:
                _beep_wav = _make_beep_wav()
            except Exception:
                _beep_wav = ''  # mark as failed so we don't retry every message
    if not _beep_wav:
        return
    try:
        # paplay is PulseAudio/PipeWire; aplay is ALSA fallback.
        player = 'paplay' if shutil.which('paplay') else 'aplay'
        subprocess.Popen(
            [player, _beep_wav],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

# Session sets this to a callable that returns the current prompt string,
# so incoming-message reprints stay in sync with the peer-count prompt.
get_prompt = lambda: '> '  # noqa: E731

# Session sets this to a callable that redraws the prompt + in-progress
# typed buffer after an incoming message interrupts the input line.
# None when no readline is active.
get_input_redraw = None

# Session sets this to a callable that returns the status bar string (or '').
# When empty the status bar is not shown and no scroll region is active.
get_statusbar = lambda: ''  # noqa: E731

# ---------------------------------------------------------------------------
# Fixed bottom UI panel (status bar + input area)
#
# Layout (bottom 4 rows, outside the scroll region):
#   rows-3 : thin separator line above input
#   rows-2 : input line  (prompt + typed text)
#   rows-1 : thin separator line above status bar
#   rows   : status bar
#
# Strategy: set a scroll region from row 1 to rows-4 so chat output never
# clobbers these rows.  We move into them explicitly to repaint, then restore
# the cursor with DEC save/restore (\x1b7 / \x1b8) which survives scroll.
# ---------------------------------------------------------------------------

_ERASE_LINE = '\x1b[2K'
_SAVE_CUR   = '\x1b7'
_REST_CUR   = '\x1b8'


def _term_size():
    return shutil.get_terminal_size(fallback=(80, 24))


def _set_scroll_region(rows):
    sys.stdout.write(f'\x1b[1;{rows - 4}r')


def _clear_scroll_region():
    sys.stdout.write('\x1b[r')


def _paint_panel(restore_cursor=True):
    """Repaint the separator, input, and status rows in-place.

    Two cursor-restore strategies depending on whether readline is active:

    • readline active (get_input_redraw set):
        Save cursor AFTER writing the input row (cursor is after typed text),
        paint status bar, restore — cursor ends up after typed text, ready for
        the next keystroke.  restore_cursor is ignored.

    • readline not active:
        Save cursor at START (pre-paint position), paint all rows, then restore
        if restore_cursor is True (default).

    Must be called while print_lock is held.
    """
    cols, rows = _term_size()
    bar = get_statusbar()
    sep = Fore.WHITE + Style.DIM + '─' * cols + Style.RESET_ALL

    if get_input_redraw is not None:
        # rows-3: separator above input
        sys.stdout.write(f'\x1b[{rows - 3};1H' + _ERASE_LINE + sep)
        # rows-2: input row — write prompt + buffer, save cursor after typed text
        sys.stdout.write(f'\x1b[{rows - 2};1H' + _ERASE_LINE)
        get_input_redraw()          # cursor now after typed text in rows-2
        sys.stdout.write(_SAVE_CUR)
        # rows-1: separator above status bar
        sys.stdout.write(f'\x1b[{rows - 1};1H' + _ERASE_LINE + sep)
        # rows: status bar
        sys.stdout.write(f'\x1b[{rows};1H' + _ERASE_LINE + (bar or ''))
        sys.stdout.write(_REST_CUR)
    else:
        # No active readline: save pre-paint cursor, paint all, optionally restore.
        sys.stdout.write(_SAVE_CUR)
        # rows-3: separator above input
        sys.stdout.write(f'\x1b[{rows - 3};1H' + _ERASE_LINE + sep)
        # rows-2: input row
        sys.stdout.write(f'\x1b[{rows - 2};1H' + _ERASE_LINE)
        sys.stdout.write(get_prompt())
        # rows-1: separator above status bar
        sys.stdout.write(f'\x1b[{rows - 1};1H' + _ERASE_LINE + sep)
        # rows: status bar
        sys.stdout.write(f'\x1b[{rows};1H' + _ERASE_LINE + (bar or ''))
        if restore_cursor:
            sys.stdout.write(_REST_CUR)


def _write_statusbar():
    """Update only the status bar row, preserving the cursor position."""
    bar = get_statusbar()
    if not bar:
        return
    _, rows = _term_size()
    sys.stdout.write(
        _SAVE_CUR
        + f'\x1b[{rows};1H' + _ERASE_LINE + bar
        + _REST_CUR
    )


def enable_statusbar():
    """Reserve the bottom 4 rows and paint the initial panel.

    Call once when a session starts, while print_lock is held.
    """
    _, rows = _term_size()
    _set_scroll_region(rows)
    # Move cursor into the scroll region so it doesn't sit on the panel.
    sys.stdout.write(f'\x1b[{rows - 4};1H')
    _paint_panel()


def disable_statusbar():
    """Erase the panel and restore full-terminal scrolling.

    Call once when a session ends, while print_lock is held.
    """
    _, rows = _term_size()
    # Erase all four reserved rows.
    for r in (rows - 3, rows - 2, rows - 1, rows):
        sys.stdout.write(f'\x1b[{r};1H' + _ERASE_LINE)
    _clear_scroll_region()
    # Leave cursor at a clean position.
    sys.stdout.write(f'\x1b[{rows - 3};1H')


def redraw_statusbar():
    """Thread-safe redraw of status bar only (acquires print_lock)."""
    with print_lock:
        _write_statusbar()
        sys.stdout.flush()


def print_history(messages):
    """Replay stored history messages into the scroll region.

    Prints a dim divider, then each message as ``HH:MM  sender: body``,
    then a second divider marking where live chat begins.  Must be called
    after enable_statusbar() and while print_lock is held.

    Args:
        messages: List of dicts with keys ``sender``, ``body``, ``ts``,
                  ``name_colour``, ``text_colour``, as returned by
                  ``db.load_history()``.
    """
    if not messages:
        return
    cols, rows = _term_size()
    dim_line = Fore.WHITE + Style.DIM + '─' * cols + Style.RESET_ALL
    label = ' chat history '
    pad = (cols - len(label)) // 2
    header = (Fore.WHITE + Style.DIM
              + '─' * pad + label + '─' * (cols - pad - len(label))
              + Style.RESET_ALL)
    # Clear the scroll region, then write history from the top so messages
    # fill downward and scroll naturally.  Repaint the panel afterwards so
    # the separator/input/status rows are intact.
    sys.stdout.write('\x1b[1;1H\x1b[J')   # go to row 1, erase to bottom of scroll region
    sys.stdout.write(header + '\r\n')
    for m in messages:
        ts = Fore.WHITE + Style.DIM + m['ts'] + Style.RESET_ALL
        nc = colour_for(m.get('name_colour', 'white'))
        tc = colour_for(m.get('text_colour', 'white'))
        sender = Style.BRIGHT + nc + m['sender'] + Style.RESET_ALL
        body = tc + m['body'] + Style.RESET_ALL
        sys.stdout.write(f'{ts}  {sender}{body}\r\n')
    sys.stdout.write(dim_line + '\r\n')
    _paint_panel()
    sys.stdout.flush()


def print_msg(username_part, text_part, name_colour=Fore.CYAN, text_colour=Fore.WHITE, alert=False):
    """Print an incoming chat message and repaint the input panel.

    Clears the current line, writes the coloured message, then repaints the
    separator + input + status rows.  All writes are serialised via
    :data:`print_lock`.

    Args:
        username_part: The ``<Name>`` portion of the message (or ``''``).
        text_part:     The body of the message (including the leading ``': '``
                       separator when *username_part* is non-empty).
        name_colour:   ANSI colour code applied to *username_part*.
        text_colour:   ANSI colour code applied to *text_part*.
        alert:         If ``True``, play the notification sound.
    """
    if alert:
        _play_beep()
    with print_lock:
        # Move to the last row of the scroll region so the message scrolls up
        # into chat history regardless of where the cursor currently is.
        _, rows = _term_size()
        sys.stdout.write(f'\x1b[{rows - 4};1H')
        sys.stdout.write(f'\r{" " * 80}\r')
        sys.stdout.write(
            Style.BRIGHT + name_colour + username_part + Style.RESET_ALL
            + text_colour + text_part + Style.RESET_ALL + '\n'
        )
        _paint_panel()
        sys.stdout.flush()


def print_msg_pending(username_part, text_part, name_colour=Fore.CYAN, text_colour=Fore.WHITE):
    """Print an outgoing message with a pending indicator and return an updater.

    Prints the message followed by a dim ``⧖`` to signal delivery is awaited.
    Returns a callable ``update(status)`` where *status* is one of:

    - ``'ok'``  — replace indicator with green ``✓``
    - ``'partial'`` — replace with yellow ``✓`` (some peers missed)
    - ``'fail'`` — replace with red ``✗``

    The updater uses absolute row positioning to overwrite the indicator.
    If the message has scrolled out of the scroll region the update is a no-op.
    The updater is thread-safe and idempotent (only fires once).

    Args:
        username_part: The ``<Name>`` portion of the message.
        text_part:     The body of the message.
        name_colour:   ANSI colour code for *username_part*.
        text_colour:   ANSI colour code for *text_part*.

    Returns:
        ``update(status)`` callable.
    """
    cols, rows = _term_size()
    # The message is written at the bottom of the scroll region (rows-4).
    # After the \n the terminal scrolls, so the message ends up at rows-5.
    msg_row = rows - 5
    indicator_col = max(cols - 3, 1)
    _fired = threading.Event()

    with print_lock:
        sys.stdout.write(f'\x1b[{rows - 4};1H')
        sys.stdout.write(f'\r{" " * 80}\r')
        line = (
            Style.BRIGHT + name_colour + username_part + Style.RESET_ALL
            + text_colour + text_part + Style.RESET_ALL
        )
        pending = Fore.WHITE + Style.DIM + ' ⧖' + Style.RESET_ALL
        sys.stdout.write(line + pending + '\n')
        _paint_panel()
        sys.stdout.flush()

    def update(status):
        if _fired.is_set():
            return
        _fired.set()
        if status == 'ok':
            icon = Fore.GREEN + Style.BRIGHT + ' ✓' + Style.RESET_ALL
        elif status == 'partial':
            icon = Fore.YELLOW + Style.BRIGHT + ' ✓' + Style.RESET_ALL
        else:
            icon = Fore.RED + Style.BRIGHT + ' ✗' + Style.RESET_ALL
        with print_lock:
            # Use absolute positioning to the row where we printed the message.
            # If msg_row < 1 the message has scrolled out of the region; skip.
            if msg_row >= 1:
                sys.stdout.write(
                    _SAVE_CUR
                    + f'\x1b[{msg_row};{indicator_col}H'
                    + icon
                    + _REST_CUR
                )
                sys.stdout.flush()

    return update


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
