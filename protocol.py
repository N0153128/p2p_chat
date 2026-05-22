"""
Wire protocol constants for the p2p chat application.

Pre-handshake packets are plain UDP.  Post-handshake packets are
nacl.public.Box payloads (XSalsa20-Poly1305 AEAD).
"""

# ---------------------------------------------------------------------------
# Tuneable constants
# ---------------------------------------------------------------------------

DISCOVERY_PORT = 8547
"""Well-known UDP port used exclusively for LAN discovery beacons."""

BROADCAST_INTERVAL = 1
"""Seconds between consecutive LAN discovery beacon broadcasts."""

BROADCAST_TIMEOUT = 30
"""Seconds to keep broadcasting before giving up on LAN discovery."""

PUNCH_INTERVAL = 0.5
"""Seconds between consecutive hole-punch probe packets."""

PUNCH_TIMEOUT = 30
"""Seconds to keep punching before declaring the connection attempt failed."""

MAX_PEERS = 16
"""Maximum number of peers allowed in a single chat room."""


# ---------------------------------------------------------------------------
# Pre-handshake message prefixes (unencrypted)
# ---------------------------------------------------------------------------

BEACON_PREFIX = b'__beacon__:'
"""
Prefix for LAN discovery beacons (unencrypted).

Full format: ``__beacon__:<session_id>:<chat_port>:<hmac>``

``session_id``  — random 8-hex-char ID generated once per process run.
``chat_port``   — sender's chat socket port (separate from discovery port).
``hmac``        — 16-hex-char HMAC-SHA256(room_code, session_id) prefix,
                  used to authenticate beacons without revealing the code.
"""

PUNCH_PREFIX = b'__punch__:'
"""
Prefix for hole-punch probe packets (unencrypted).

Full format: ``__punch__:<64-hex-char-x25519-pubkey>``
"""

PUNCH_ACK_PREFIX = b'__punch_ack__:'
"""
Prefix for hole-punch acknowledgement packets (unencrypted).

Full format: ``__punch_ack__:<64-hex-char-x25519-pubkey>``
"""


# ---------------------------------------------------------------------------
# Post-handshake control message constants (encrypted)
# ---------------------------------------------------------------------------

CTRL_DISCONNECT = b'__disconnect__'
"""Encrypted control message sent to notify the peer of a clean disconnect."""

CTRL_META_PREFIX = b'__meta__:'
"""
Prefix for the encrypted metadata message sent once after connect.

Full format: ``__meta__:<username>,<name_colour>,<text_colour>``

Carries the sender's username and chosen colours so the receiver can
render the sender's messages exactly as the sender intended and show
the username in the status bar.
"""
