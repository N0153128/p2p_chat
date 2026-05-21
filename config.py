"""
User preference persistence for p2p_chat.

Preferences are stored as JSON in ``~/.p2p_chat.json``.  The file is
read at startup to pre-fill prompts and written back whenever the user
completes the setup flow.

Stored fields
-------------
``username``    — display name string.
``name_colour`` — colour name string for the username (see :data:`ui.COLOUR_NAMES`).
``text_colour`` — colour name string for message body text.
"""

import json
import os

CONFIG_PATH = os.path.expanduser('~/.p2p_chat.json')

_DEFAULTS = {
    'username': '',
    'name_colour': 'cyan',
    'text_colour': 'white',
}


def load():
    """Load preferences from disk.

    Returns:
        A dict with keys ``username``, ``name_colour``, ``text_colour``.
        Missing or unreadable fields fall back to defaults silently.
    """
    prefs = dict(_DEFAULTS)
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            stored = json.load(f)
        for key in _DEFAULTS:
            if key in stored and isinstance(stored[key], str) and stored[key]:
                prefs[key] = stored[key]
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return prefs


def save(username, name_colour_name, text_colour_name):
    """Persist preferences to disk.

    Args:
        username:          Display name string.
        name_colour_name:  Colour name for the username (e.g. ``'cyan'``).
        text_colour_name:  Colour name for message body text.
    """
    data = {
        'username': username,
        'name_colour': name_colour_name,
        'text_colour': text_colour_name,
    }
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass
