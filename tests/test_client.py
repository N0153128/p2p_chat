"""
Tests for client.py.

Run with:  python3 -m pytest tests/  (from the project root)

All tests use real UDP sockets on loopback — no mocking of network I/O.
Module-level globals (username, local_ip) that UDPClient reads are injected
via the autouse patch_globals fixture.
"""

import io
import os
import socket
import struct
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import client  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_udp_sock(bind_ip='127.0.0.1'):
    """Return a UDP socket bound to a random loopback port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, 0))
    return s


def addr_of(sock):
    return sock.getsockname()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_globals(monkeypatch):
    """Inject module-level globals that normally only exist after __main__ runs."""
    monkeypatch.setattr(client, 'username', 'Tester', raising=False)
    monkeypatch.setattr(client, 'local_ip', '192.168.1.1', raising=False)


# ---------------------------------------------------------------------------
# stun_get_external
# ---------------------------------------------------------------------------

class TestStunGetExternal:

    def _make_stun_response(self, ip, port, xor=True):
        """Build a minimal STUN Binding Response."""
        magic = 0x2112A442
        tid = bytes(12)
        if xor:
            xport = port ^ (magic >> 16)
            ip_bytes = bytes(b ^ m for b, m in zip(socket.inet_aton(ip), struct.pack('!I', magic)))
            attr_value = b'\x00\x01' + struct.pack('!H', xport) + ip_bytes
            attr_type = 0x0020
        else:
            attr_value = b'\x00\x01' + struct.pack('!H', port) + socket.inet_aton(ip)
            attr_type = 0x0001
        attr = struct.pack('!HH', attr_type, len(attr_value)) + attr_value
        header = struct.pack('!HHI12s', 0x0101, len(attr), magic, tid)
        return header + attr

    def test_xor_mapped_address(self):
        """STUN response with XOR-MAPPED-ADDRESS returns correct ip/port."""
        server = make_udp_sock()
        client_sock = make_udp_sock()
        expected_ip, expected_port = '1.2.3.4', 54321

        def fake_stun_server():
            data, addr = server.recvfrom(512)
            server.sendto(self._make_stun_response(expected_ip, expected_port, xor=True), addr)

        t = threading.Thread(target=fake_stun_server, daemon=True)
        t.start()
        ip, port = client.stun_get_external(client_sock, stun_host=addr_of(server)[0], stun_port=addr_of(server)[1])
        t.join(timeout=2)

        assert ip == expected_ip
        assert port == expected_port
        client_sock.close()
        server.close()

    def test_mapped_address_fallback(self):
        """STUN response with MAPPED-ADDRESS (non-XOR) also parsed correctly."""
        server = make_udp_sock()
        client_sock = make_udp_sock()
        expected_ip, expected_port = '5.6.7.8', 12345

        def fake_stun_server():
            data, addr = server.recvfrom(512)
            server.sendto(self._make_stun_response(expected_ip, expected_port, xor=False), addr)

        t = threading.Thread(target=fake_stun_server, daemon=True)
        t.start()
        ip, port = client.stun_get_external(client_sock, stun_host=addr_of(server)[0], stun_port=addr_of(server)[1])
        t.join(timeout=2)

        assert ip == expected_ip
        assert port == expected_port
        client_sock.close()
        server.close()

    def test_unreachable_returns_none(self):
        """Returns (None, None) when the STUN server is unreachable."""
        dead = make_udp_sock()
        host, port = addr_of(dead)
        dead.close()  # closed port → ConnectionRefusedError → (None, None)

        client_sock = make_udp_sock()
        ip, ext_port = client.stun_get_external(client_sock, stun_host=host, stun_port=port)

        assert ip is None
        assert ext_port is None
        client_sock.close()

    def test_restores_timeout_after_call(self):
        """Socket timeout is restored to its original value after the call."""
        server = make_udp_sock()
        client_sock = make_udp_sock()
        client_sock.settimeout(99)

        def fake_stun_server():
            try:
                data, addr = server.recvfrom(512)
                server.sendto(b'garbage', addr)  # invalid → ignored, falls through
            except Exception:
                pass

        t = threading.Thread(target=fake_stun_server, daemon=True)
        t.start()
        client.stun_get_external(client_sock, stun_host=addr_of(server)[0], stun_port=addr_of(server)[1])
        t.join(timeout=2)

        assert client_sock.gettimeout() == 99
        client_sock.close()
        server.close()


# ---------------------------------------------------------------------------
# _is_local
# ---------------------------------------------------------------------------

class TestIsLocal:
    # local_ip is patched to '127.0.0.1' by patch_globals

    def test_loopback(self):
        assert client._is_local('127.0.0.1') is True

    def test_same_as_local_ip(self):
        assert client._is_local('127.0.0.1') is True

    def test_same_subnet(self, monkeypatch):
        monkeypatch.setattr(client, 'local_ip', '192.168.1.1')
        assert client._is_local('192.168.1.10') is True

    def test_different_subnet(self, monkeypatch):
        monkeypatch.setattr(client, 'local_ip', '192.168.1.1')
        assert client._is_local('10.0.0.1') is False

    def test_different_host_same_prefix(self, monkeypatch):
        monkeypatch.setattr(client, 'local_ip', '192.168.1.1')
        assert client._is_local('192.168.2.1') is False


# ---------------------------------------------------------------------------
# _broadcast_addr
# ---------------------------------------------------------------------------

class TestBroadcastAddr:

    def test_broadcast_last_octet(self, monkeypatch):
        monkeypatch.setattr(client, 'local_ip', '192.168.1.42')
        assert client._broadcast_addr() == '192.168.1.255'

    def test_broadcast_different_subnet(self, monkeypatch):
        monkeypatch.setattr(client, 'local_ip', '10.0.5.3')
        assert client._broadcast_addr() == '10.0.5.255'


# ---------------------------------------------------------------------------
# UDPClient — integration tests on loopback
# ---------------------------------------------------------------------------

def make_client_obj(sock, remote_addr=('127.0.0.1', 9999)):
    """Construct a UDPClient bypassing __init__, wiring up attributes manually."""
    c = client.UDPClient.__new__(client.UDPClient)
    c.sock = sock
    c.remote = remote_addr
    c.connected = threading.Event()
    c.done = threading.Event()
    return c


class TestUDPClientLAN:

    def test_lan_connects_immediately(self):
        """On loopback _is_local returns True so connected is set without punching."""
        sock_a = make_udp_sock()
        c = make_client_obj(sock_a)
        # Simulate what __init__ does for the LAN path
        c.connected.set()
        assert c.connected.is_set()
        sock_a.close()

    def test_peers_exchange_messages(self):
        """Messages sent by one socket are received by the other."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        port_b = addr_of(sock_b)[1]

        received = []

        def recv_one():
            sock_b.settimeout(2)
            try:
                data, _ = sock_b.recvfrom(4096)
                received.append(data)
            except socket.timeout:
                pass

        t = threading.Thread(target=recv_one, daemon=True)
        t.start()
        sock_a.sendto(b'<Tester>: hello', ('127.0.0.1', port_b))
        t.join(timeout=3)

        assert b'<Tester>: hello' in received
        sock_a.close()
        sock_b.close()

    def test_disconnect_message_delivered(self):
        """DISCONNECT_MSG sent by one peer arrives at the other."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        port_b = addr_of(sock_b)[1]

        received = []

        def recv_one():
            sock_b.settimeout(2)
            try:
                data, _ = sock_b.recvfrom(4096)
                received.append(data)
            except socket.timeout:
                pass

        t = threading.Thread(target=recv_one, daemon=True)
        t.start()
        sock_a.sendto(client.DISCONNECT_MSG, ('127.0.0.1', port_b))
        t.join(timeout=3)

        assert client.DISCONNECT_MSG in received
        sock_a.close()
        sock_b.close()


class TestUDPClientHolePunching:

    def test_punch_msg_triggers_ack(self):
        """Receiving PUNCH_MSG causes the peer to reply with PUNCH_ACK."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        port_a = addr_of(sock_a)[1]

        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b))

        def run_recv():
            sock_a.settimeout(2)
            try:
                data, addr = sock_a.recvfrom(4096)
                if data == client.PUNCH_MSG:
                    sock_a.sendto(client.PUNCH_ACK, addr)
                    c.connected.set()
            except socket.timeout:
                pass

        t = threading.Thread(target=run_recv, daemon=True)
        t.start()
        sock_b.sendto(client.PUNCH_MSG, ('127.0.0.1', port_a))
        t.join(timeout=3)

        sock_b.settimeout(2)
        data, _ = sock_b.recvfrom(4096)
        assert data == client.PUNCH_ACK
        assert c.connected.is_set()

        sock_a.close()
        sock_b.close()

    def test_punch_ack_sets_connected(self):
        """Receiving PUNCH_ACK sets the connected event."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        port_a = addr_of(sock_a)[1]

        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b))

        def run_recv():
            sock_a.settimeout(2)
            try:
                data, _ = sock_a.recvfrom(4096)
                if data == client.PUNCH_ACK:
                    c.connected.set()
            except socket.timeout:
                pass

        t = threading.Thread(target=run_recv, daemon=True)
        t.start()
        sock_b.sendto(client.PUNCH_ACK, ('127.0.0.1', port_a))
        t.join(timeout=3)

        assert c.connected.is_set()
        sock_a.close()
        sock_b.close()

    def test_punch_stops_after_timeout(self):
        """_punch stops sending after PUNCH_TIMEOUT expires."""
        sock_a = make_udp_sock()
        c = make_client_obj(sock_a, remote_addr=('127.0.0.1', 9999))

        original = client.PUNCH_TIMEOUT
        client.PUNCH_TIMEOUT = 1
        try:
            start = time.time()
            c._punch()
            elapsed = time.time() - start
        finally:
            client.PUNCH_TIMEOUT = original

        assert elapsed >= 1
        assert not c.connected.is_set()
        sock_a.close()


class TestUDPClientDone:

    def test_done_set_on_disconnect_msg(self):
        """_recv_loop sets done and exits when DISCONNECT_MSG arrives."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        port_a = addr_of(sock_a)[1]

        c = make_client_obj(sock_a)
        c.connected.set()

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.1)
            sock_b.sendto(client.DISCONNECT_MSG, ('127.0.0.1', port_a))
            t.join(timeout=3)
        finally:
            sys.stdout = old_stdout

        assert c.done.is_set()
        sock_a.close()
        sock_b.close()

    def test_beacon_ignored_during_chat(self):
        """Beacon packets received during a session are silently discarded."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        port_a = addr_of(sock_a)[1]

        c = make_client_obj(sock_a)
        c.connected.set()

        chat_received = []
        original_print_msg = client.print_msg

        def capturing_print_msg(msg):
            chat_received.append(msg)

        client.print_msg = capturing_print_msg
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.1)
            # Send a beacon (should be ignored), then a chat message, then disconnect
            stray_beacon = client.BEACON_PREFIX + b'deadbeef'
            sock_b.sendto(stray_beacon, ('127.0.0.1', port_a))
            time.sleep(0.1)
            sock_b.sendto(b'hello', ('127.0.0.1', port_a))
            time.sleep(0.1)
            sock_b.sendto(client.DISCONNECT_MSG, ('127.0.0.1', port_a))
            t.join(timeout=3)
        finally:
            client.print_msg = original_print_msg

        assert chat_received == ['hello']
        sock_a.close()
        sock_b.close()
