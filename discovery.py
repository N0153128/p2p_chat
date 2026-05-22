"""
LAN peer discovery via authenticated UDP broadcast.

Both peers bind a temporary socket to :data:`protocol.DISCOVERY_PORT` and
broadcast beacons containing their session ID, chat port, and an
HMAC-SHA256 tag derived from the shared room code.  Only peers that know
the same room code can verify the tag, preventing unauthenticated peer
hijacking.

``SESSION_ID`` is generated once per process run and embedded in every
beacon so each node can filter its own broadcast echo without relying on
IP comparison (which fails when both peers run on the same machine).
"""

import hashlib
import hmac
import random
import socket
from time import time

from colorama import Fore, Style

from protocol import (
    BEACON_PREFIX,
    BROADCAST_INTERVAL,
    BROADCAST_TIMEOUT,
    DISCOVERY_PORT,
)


SESSION_ID = '%08x' % random.randint(0, 0xFFFFFFFF)
"""
Random 8-hex-char identifier generated once per process run.

Used to distinguish our own broadcast echo from a genuine peer beacon.
"""

# Populated by client.py after detecting the local interface address.
local_ip = '127.0.0.1'


def is_local(ip):
    """Return ``True`` if *ip* is loopback or shares the local /24 subnet.

    Args:
        ip: Dotted-decimal IPv4 string to test.

    Returns:
        ``bool``
    """
    if ip == '127.0.0.1' or ip == local_ip:
        return True
    return ip.rsplit('.', 1)[0] == local_ip.rsplit('.', 1)[0]


def _broadcast_addr():
    """Return the directed broadcast address for the local /24 subnet.

    Example: if ``local_ip`` is ``192.168.1.42`` this returns
    ``'192.168.1.255'``.

    Returns:
        Dotted-decimal broadcast address string.
    """
    return local_ip.rsplit('.', 1)[0] + '.255'


def _beacon_hmac(room_code, session_id):
    """Compute a 16-character hex HMAC-SHA256 tag for a discovery beacon.

    The tag authenticates the beacon without revealing the room code.
    Only a peer that knows the same room code can reproduce it.

    Args:
        room_code:  Shared secret entered by both peers.
        session_id: The sender's :data:`SESSION_ID` string.

    Returns:
        16-character lowercase hex string (64-bit prefix of the digest).
    """
    return hmac.new(
        room_code.encode(), session_id.encode(), hashlib.sha256
    ).hexdigest()[:16]


def scan_active_rooms(timeout=2.0):
    """Listen on the discovery port and return the number of distinct active rooms.

    Collects beacons for *timeout* seconds without broadcasting anything.
    Each unique session ID is counted as one room.  Because beacons are
    authenticated with the room code, we cannot read the room name — only
    that a room exists.

    Args:
        timeout: How long to listen in seconds.

    Returns:
        Number of distinct rooms detected (int).
    """
    seen_sids = set()
    try:
        disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        disc.bind(('0.0.0.0', DISCOVERY_PORT))
        disc.settimeout(0.2)
    except OSError:
        return 0

    from time import time as _time
    deadline = _time() + timeout
    try:
        while _time() < deadline:
            try:
                data, _ = disc.recvfrom(4096)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            if not data.startswith(BEACON_PREFIX):
                continue
            payload = data[len(BEACON_PREFIX):].decode(errors='ignore')
            parts = payload.split(':')
            if len(parts) != 3:
                continue
            peer_sid = parts[0]
            if peer_sid != SESSION_ID:
                seen_sids.add(peer_sid)
    finally:
        disc.close()
    return len(seen_sids)


def lan_discover(chat_port, room_code):
    """Broadcast authenticated beacons and return the first matching peer.

    Used by tests and internet-fallback flows.  For LAN room sessions,
    discovery runs continuously inside :class:`~session.UDPClient`.

    Args:
        chat_port:  Our chat socket's port.
        room_code:  Shared secret used to authenticate beacons.

    Returns:
        ``(peer_ip, peer_chat_port)`` on success, or ``None`` on timeout.
    """
    disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    disc.bind(('0.0.0.0', DISCOVERY_PORT))
    disc.settimeout(BROADCAST_INTERVAL)

    broadcast = _broadcast_addr()
    tag = _beacon_hmac(room_code, SESSION_ID)
    my_beacon = BEACON_PREFIX + f'{SESSION_ID}:{chat_port}:{tag}'.encode()

    deadline = time() + BROADCAST_TIMEOUT
    try:
        while time() < deadline:
            try:
                disc.sendto(my_beacon, (broadcast, DISCOVERY_PORT))
            except Exception:
                pass
            try:
                data, addr = disc.recvfrom(4096)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return None

            if not data.startswith(BEACON_PREFIX):
                continue
            payload = data[len(BEACON_PREFIX):].decode(errors='ignore')
            parts = payload.split(':')
            if len(parts) != 3:
                continue
            peer_sid, peer_port_str, peer_tag = parts
            if peer_sid == SESSION_ID:
                continue
            expected = _beacon_hmac(room_code, peer_sid)
            if not hmac.compare_digest(peer_tag, expected):
                continue
            try:
                peer_port = int(peer_port_str)
            except ValueError:
                continue
            try:
                disc.sendto(my_beacon, addr)
            except Exception:
                pass
            return (addr[0], peer_port)
    finally:
        disc.close()
    return None
