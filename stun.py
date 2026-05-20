"""
STUN client for public address discovery (RFC 5389).

Sends a single Binding Request on an existing bound UDP socket and parses
the response to determine the socket's public-facing IP and port.  This
avoids the need for a separate socket, ensuring the mapped address matches
the port the application will actually use for chat.
"""

import random
import struct


def get_external_address(sock, stun_host='stun.l.google.com', stun_port=19302):
    """Send a STUN Binding Request and return the caller's public (IP, port).

    Reuses *sock* so the mapped address reflects the port that will be used
    for chat traffic.  The socket's original timeout is always restored,
    even on error.

    Args:
        sock:       A bound ``socket.SOCK_DGRAM`` socket.
        stun_host:  Hostname of the STUN server (RFC 5389).
        stun_port:  UDP port of the STUN server.

    Returns:
        ``(ip, port)`` strings on success, ``(None, None)`` if the server
        is unreachable or the response cannot be parsed.
    """
    old_timeout = sock.gettimeout()
    sock.settimeout(5)
    try:
        tid = struct.pack('!12B', *[random.randint(0, 255) for _ in range(12)])
        msg = struct.pack('!HHI12s', 0x0001, 0, 0x2112A442, tid)
        sock.sendto(msg, (stun_host, stun_port))
        try:
            data, _ = sock.recvfrom(2048)
        except (TimeoutError, ConnectionRefusedError, OSError):
            return None, None

        # Walk the STUN attribute list starting after the 20-byte header.
        i = 20
        while i < len(data):
            attr_type, attr_len = struct.unpack('!HH', data[i:i + 4])
            val = data[i + 4:i + 4 + attr_len]

            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                port = struct.unpack(
                    '!H',
                    bytes(b ^ m for b, m in zip(val[2:4], b'\x21\x12')),
                )[0]
                ip = '.'.join(
                    str(b ^ m)
                    for b, m in zip(val[4:8], struct.pack('!I', 0x2112A442))
                )
                return ip, port

            if attr_type == 0x0001:  # MAPPED-ADDRESS (non-XOR fallback)
                port = struct.unpack('!H', val[2:4])[0]
                ip = '.'.join(str(b) for b in val[4:8])
                return ip, port

            # Advance past this attribute, aligning to a 4-byte boundary.
            i += 4 + attr_len + (attr_len % 4 and 4 - attr_len % 4)
    finally:
        sock.settimeout(old_timeout)
    return None, None
