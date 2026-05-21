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
    MAX_PEERS,
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


def lan_discover(chat_port, room_code):
    """Broadcast authenticated beacons and return all matching peers found.

    Opens a temporary UDP socket on :data:`~protocol.DISCOVERY_PORT`
    (separate from the chat socket so two instances on the same machine
    don't collide).  Broadcasts a beacon every
    :data:`~protocol.BROADCAST_INTERVAL` seconds and collects beacons from
    other peers for the full :data:`~protocol.BROADCAST_TIMEOUT` window.
    A peer is accepted only if its HMAC tag matches the expected value for
    *room_code*.

    Once the window closes (or :data:`~protocol.MAX_PEERS` peers are found),
    a final unicast beacon is sent to each discovered peer so they know we
    found them, then the function returns.

    Args:
        chat_port:  Our chat socket's port (embedded in the beacon so the
                    peer knows where to send chat packets).
        room_code:  Shared secret used to authenticate beacons.

    Returns:
        List of ``(peer_ip, peer_chat_port)`` tuples (possibly empty).
    """
    disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    disc.bind(('0.0.0.0', DISCOVERY_PORT))
    disc.settimeout(BROADCAST_INTERVAL)

    broadcast = _broadcast_addr()
    tag = _beacon_hmac(room_code, SESSION_ID)
    my_beacon = BEACON_PREFIX + f'{SESSION_ID}:{chat_port}:{tag}'.encode()

    peers = {}   # (ip, chat_port) → source addr for unicast reply
    seen_sids = set()

    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 'Scanning local network for peers...')
    deadline = time() + BROADCAST_TIMEOUT
    try:
        while time() < deadline and len(peers) < MAX_PEERS:
            try:
                disc.sendto(my_beacon, (broadcast, DISCOVERY_PORT))
            except Exception:
                pass

            try:
                data, addr = disc.recvfrom(4096)
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

            peer_sid, peer_port_str, peer_tag = parts

            if peer_sid == SESSION_ID or peer_sid in seen_sids:
                continue

            expected = _beacon_hmac(room_code, peer_sid)
            if not hmac.compare_digest(peer_tag, expected):
                continue

            try:
                peer_port = int(peer_port_str)
            except ValueError:
                continue

            seen_sids.add(peer_sid)
            peer_key = (addr[0], peer_port)
            if peer_key not in peers:
                peers[peer_key] = addr
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT
                      + f'  Found peer: {addr[0]}:{peer_port}')
    finally:
        # Unicast a final beacon to each discovered peer so they know we're here.
        for peer_key, src_addr in peers.items():
            try:
                disc.sendto(my_beacon, src_addr)
            except Exception:
                pass
        disc.close()

    return list(peers.keys())
