"""
Local SQLite persistence for p2p_chat.

Database location: ``~/.p2p_chat.db``

Tables
------
``meta``
    Single-row key/value store for internal values (e.g. the encryption key).

``room_presets``
    Host-created room configurations saved with /save_preset.
    Passcodes are stored encrypted using a ``nacl.secret.SecretBox`` whose
    key is generated once and kept in the ``meta`` table.

``user_settings``
    Per-user preference flags (e.g. mute state).  One row per key.

``message_log``
    Rolling chat history, capped at ``MSG_LOG_LIMIT`` rows per room.
    Keyed by room name.  Messages are stored as plain text (ANSI stripped).
    Oldest rows are pruned on every insert to stay within the cap.
"""

import os
import re
import sqlite3

import nacl.secret
import nacl.utils

DB_PATH = os.path.expanduser('~/.p2p_chat.db')

MSG_LOG_LIMIT = 2000
"""Maximum number of messages retained per room in message_log."""

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mKHJrABCDsu]|\x1b[78]')


def _strip_ansi(text):
    """Remove ANSI escape sequences from *text* for plain-text storage."""
    return _ANSI_RE.sub('', text)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS room_presets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            slots           INTEGER NOT NULL,
            is_host         INTEGER NOT NULL,
            passcode_enc    BLOB,
            passcode_nonce  BLOB,
            created_at      TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS user_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS message_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            room      TEXT    NOT NULL,
            sender    TEXT    NOT NULL,
            body      TEXT    NOT NULL,
            ts        TEXT    DEFAULT (strftime('%H:%M', 'now', 'localtime'))
        );

        CREATE INDEX IF NOT EXISTS message_log_room ON message_log(room, id);
    """)
    conn.commit()


def _get_box(conn):
    """Return a SecretBox, creating and persisting its key on first call."""
    row = conn.execute("SELECT value FROM meta WHERE key='enc_key'").fetchone()
    if row:
        key = bytes(row['value'])
    else:
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        conn.execute("INSERT INTO meta (key, value) VALUES ('enc_key', ?)", (key,))
        conn.commit()
    return nacl.secret.SecretBox(key)


# ---------------------------------------------------------------------------
# Room presets
# ---------------------------------------------------------------------------

def save_room_preset(name, slots, is_host, passcode=''):
    """Persist a room preset, overwriting any existing preset with the same name.

    Passcode is stored encrypted; the plaintext is never written to disk.

    Args:
        name:     Room name string (used as the unique key).
        slots:    Integer slot count (2–32).
        is_host:  Bool — whether host mode was enabled.
        passcode: Plain-text passcode string (may be empty).
    """
    conn = _connect()
    _init(conn)
    box = _get_box(conn)
    passcode_enc = box.encrypt(passcode.encode('utf-8')) if passcode else None
    # Delete any existing preset with the same name, then insert fresh so the
    # row gets a new id and updated created_at (simpler than an ON CONFLICT
    # UPDATE that would require a UNIQUE constraint added after table creation).
    conn.execute("DELETE FROM room_presets WHERE name=?", (name,))
    conn.execute(
        "INSERT INTO room_presets (name, slots, is_host, passcode_enc, passcode_nonce)"
        " VALUES (?, ?, ?, ?, NULL)",
        (name, slots, int(is_host), passcode_enc),
    )
    conn.commit()
    conn.close()


def load_room_presets():
    """Return all saved room presets with decrypted passcodes.

    Returns:
        List of dicts with keys: ``id``, ``name``, ``slots``, ``is_host``,
        ``passcode``, ``created_at``.
    """
    conn = _connect()
    _init(conn)
    box = _get_box(conn)
    rows = conn.execute(
        "SELECT id, name, slots, is_host, passcode_enc, created_at"
        " FROM room_presets ORDER BY id"
    ).fetchall()
    presets = []
    for row in rows:
        passcode = ''
        if row['passcode_enc']:
            try:
                passcode = box.decrypt(bytes(row['passcode_enc'])).decode('utf-8')
            except Exception:
                passcode = ''
        presets.append({
            'id': row['id'],
            'name': row['name'],
            'slots': row['slots'],
            'is_host': bool(row['is_host']),
            'passcode': passcode,
            'created_at': row['created_at'],
        })
    conn.close()
    return presets


def delete_room_preset(preset_id):
    """Delete a preset by its database ID."""
    conn = _connect()
    _init(conn)
    conn.execute("DELETE FROM room_presets WHERE id=?", (preset_id,))
    conn.commit()
    conn.close()


def wipe_room_presets():
    """Delete all room presets from the database."""
    conn = _connect()
    _init(conn)
    conn.execute("DELETE FROM room_presets")
    conn.commit()
    conn.close()


def dump_room_presets_text():
    """Return a plain-text representation of all room presets (passcodes included).

    Returns:
        String suitable for writing to a file, or an empty string if no presets.
    """
    presets = load_room_presets()
    if not presets:
        return ''
    lines = ['p2p_chat room presets', '=' * 40]
    for p in presets:
        lines.append(f"\nRoom     : {p['name']}")
        lines.append(f"Slots    : {p['slots']}")
        lines.append(f"Host mode: {'yes' if p['is_host'] else 'no'}")
        lines.append(f"Passcode : {p['passcode'] if p['passcode'] else '(none)'}")
        lines.append(f"Saved at : {p['created_at']}")
    lines.append('')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# User settings
# ---------------------------------------------------------------------------

def get_setting(key, default=None):
    """Return the stored string value for *key*, or *default* if absent."""
    conn = _connect()
    _init(conn)
    row = conn.execute(
        "SELECT value FROM user_settings WHERE key=?", (key,)
    ).fetchone()
    conn.close()
    return row['value'] if row else default


def set_setting(key, value):
    """Upsert a string *value* for *key* in user_settings."""
    conn = _connect()
    _init(conn)
    conn.execute(
        "INSERT INTO user_settings (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Message log
# ---------------------------------------------------------------------------

def log_message(room, sender, body):
    """Append a message to the rolling log for *room*.

    ANSI codes are stripped before storage.  If the room's row count
    exceeds MSG_LOG_LIMIT the oldest rows are pruned immediately.

    Args:
        room:   Room name string used as the partition key.
        sender: Display name of the sender (plain text).
        body:   Message body text (plain text or ANSI — ANSI is stripped).
    """
    if not room:
        return
    conn = _connect()
    _init(conn)
    conn.execute(
        "INSERT INTO message_log (room, sender, body) VALUES (?, ?, ?)",
        (room, _strip_ansi(sender), _strip_ansi(body)),
    )
    # Prune oldest rows beyond the cap for this room.
    conn.execute(
        """DELETE FROM message_log WHERE room=? AND id NOT IN (
               SELECT id FROM message_log WHERE room=?
               ORDER BY id DESC LIMIT ?
           )""",
        (room, room, MSG_LOG_LIMIT),
    )
    conn.commit()
    conn.close()


def load_history(room, limit=MSG_LOG_LIMIT):
    """Return the most recent *limit* messages for *room*, oldest first.

    Args:
        room:  Room name string.
        limit: Maximum number of rows to return.

    Returns:
        List of dicts with keys: ``sender``, ``body``, ``ts``.
    """
    if not room:
        return []
    conn = _connect()
    _init(conn)
    rows = conn.execute(
        """SELECT sender, body, ts FROM (
               SELECT sender, body, ts, id FROM message_log
               WHERE room=? ORDER BY id DESC LIMIT ?
           ) ORDER BY id ASC""",
        (room, limit),
    ).fetchall()
    conn.close()
    return [{'sender': r['sender'], 'body': r['body'], 'ts': r['ts']} for r in rows]
