"""
Test suite for p2p_chat.

Run with:  python3 -m pytest tests/  (from the project root)

All tests use real UDP sockets on loopback — no mocking of network I/O.
"""

import io
import os
import socket
import struct
import sys
import threading
import time

import pytest
import nacl.public

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)

import discovery       # noqa: E402
import protocol        # noqa: E402
import stun            # noqa: E402
import ui              # noqa: E402
from session import UDPClient  # noqa: E402


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


def make_box_pair():
    """Return two nacl.public.Box objects that can decrypt each other's output."""
    priv_a = nacl.public.PrivateKey.generate()
    priv_b = nacl.public.PrivateKey.generate()
    box_a = nacl.public.Box(priv_a, priv_b.public_key)
    box_b = nacl.public.Box(priv_b, priv_a.public_key)
    return box_a, box_b


def make_client_obj(sock, remote_addr=('127.0.0.1', 9999), box=None):
    """Construct a UDPClient bypassing __init__, wiring up attributes manually.

    Sets up a single peer at *remote_addr* with an optional pre-built *box*.
    """
    from colorama import Fore
    c = UDPClient.__new__(UDPClient)
    c.sock = sock
    c.username = 'Tester'
    c.done = threading.Event()
    c.peer_disconnected = False
    c.name_colour = Fore.CYAN
    c.text_colour = Fore.WHITE
    priv = nacl.public.PrivateKey.generate()
    c._privkey = priv
    c._pubkey_bytes = bytes(priv.public_key)
    c._peers_lock = threading.Lock()
    c._first_connected = threading.Event()
    connected_event = threading.Event()
    if box is not None:
        connected_event.set()
        c._first_connected.set()
    c._own_addr = sock.getsockname()
    c._peers = {
        remote_addr: {
            'box': box,
            'connected': connected_event,
            'name_colour': Fore.CYAN,
            'text_colour': Fore.WHITE,
            'muted': False,
            'username': '',
        }
    }
    return c


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_globals(monkeypatch):
    """Pin discovery.local_ip for all tests."""
    monkeypatch.setattr(discovery, 'local_ip', '192.168.1.1')


# ---------------------------------------------------------------------------
# stun.get_external_address
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
        ip, port = stun.get_external_address(client_sock, stun_host=addr_of(server)[0], stun_port=addr_of(server)[1])
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
        ip, port = stun.get_external_address(client_sock, stun_host=addr_of(server)[0], stun_port=addr_of(server)[1])
        t.join(timeout=2)

        assert ip == expected_ip
        assert port == expected_port
        client_sock.close()
        server.close()

    def test_unreachable_returns_none(self):
        """Returns (None, None) when the STUN server is unreachable."""
        dead = make_udp_sock()
        host, port = addr_of(dead)
        dead.close()

        client_sock = make_udp_sock()
        ip, ext_port = stun.get_external_address(client_sock, stun_host=host, stun_port=port)

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
                server.sendto(b'garbage', addr)
            except Exception:
                pass

        t = threading.Thread(target=fake_stun_server, daemon=True)
        t.start()
        stun.get_external_address(client_sock, stun_host=addr_of(server)[0], stun_port=addr_of(server)[1])
        t.join(timeout=2)

        assert client_sock.gettimeout() == 99
        client_sock.close()
        server.close()


# ---------------------------------------------------------------------------
# discovery.is_local
# ---------------------------------------------------------------------------

class TestIsLocal:

    def test_loopback(self):
        assert discovery.is_local('127.0.0.1') is True

    def test_same_as_local_ip(self, monkeypatch):
        monkeypatch.setattr(discovery, 'local_ip', '192.168.1.1')
        assert discovery.is_local('192.168.1.1') is True

    def test_same_subnet(self, monkeypatch):
        monkeypatch.setattr(discovery, 'local_ip', '192.168.1.1')
        assert discovery.is_local('192.168.1.10') is True

    def test_different_subnet(self, monkeypatch):
        monkeypatch.setattr(discovery, 'local_ip', '192.168.1.1')
        assert discovery.is_local('10.0.0.1') is False

    def test_different_host_same_prefix(self, monkeypatch):
        monkeypatch.setattr(discovery, 'local_ip', '192.168.1.1')
        assert discovery.is_local('192.168.2.1') is False


# ---------------------------------------------------------------------------
# discovery._broadcast_addr
# ---------------------------------------------------------------------------

class TestBroadcastAddr:

    def test_broadcast_last_octet(self, monkeypatch):
        monkeypatch.setattr(discovery, 'local_ip', '192.168.1.42')
        assert discovery._broadcast_addr() == '192.168.1.255'

    def test_broadcast_different_subnet(self, monkeypatch):
        monkeypatch.setattr(discovery, 'local_ip', '10.0.5.3')
        assert discovery._broadcast_addr() == '10.0.5.255'


# ---------------------------------------------------------------------------
# discovery._beacon_hmac
# ---------------------------------------------------------------------------

class TestBeaconHmac:

    def test_same_room_code_same_session_matches(self):
        """Same room code + session ID always produces the same tag."""
        tag1 = discovery._beacon_hmac('secret', 'abc123')
        tag2 = discovery._beacon_hmac('secret', 'abc123')
        assert tag1 == tag2

    def test_different_room_code_differs(self):
        """Different room codes produce different tags for the same session."""
        tag1 = discovery._beacon_hmac('room-a', 'abc123')
        tag2 = discovery._beacon_hmac('room-b', 'abc123')
        assert tag1 != tag2

    def test_different_session_differs(self):
        """Same room code but different session IDs produce different tags."""
        tag1 = discovery._beacon_hmac('secret', 'aaa')
        tag2 = discovery._beacon_hmac('secret', 'bbb')
        assert tag1 != tag2

    def test_tag_is_16_hex_chars(self):
        """Output is exactly 16 lowercase hex characters."""
        tag = discovery._beacon_hmac('myroom', 'sid1234')
        assert len(tag) == 16
        assert all(c in '0123456789abcdef' for c in tag)


# ---------------------------------------------------------------------------
# UDPClient — key exchange helpers
# ---------------------------------------------------------------------------

class TestUDPClientKeyExchange:

    def test_make_punch_msg_starts_with_prefix(self):
        """_make_punch_msg returns PUNCH_PREFIX + pubkey hex."""
        sock = make_udp_sock()
        c = make_client_obj(sock)
        msg = c._make_punch_msg()
        assert msg.startswith(protocol.PUNCH_PREFIX)
        pubkey_hex = msg[len(protocol.PUNCH_PREFIX):].decode()
        assert len(pubkey_hex) == 64
        sock.close()

    def test_make_punch_ack_starts_with_prefix(self):
        """_make_punch_ack returns PUNCH_ACK_PREFIX + pubkey hex."""
        sock = make_udp_sock()
        c = make_client_obj(sock)
        ack = c._make_punch_ack()
        assert ack.startswith(protocol.PUNCH_ACK_PREFIX)
        pubkey_hex = ack[len(protocol.PUNCH_ACK_PREFIX):].decode()
        assert len(pubkey_hex) == 64
        sock.close()

    def test_build_box_enables_encrypt_decrypt(self):
        """After _build_box the UDPClient can encrypt and decrypt with the peer's key."""
        priv_peer = nacl.public.PrivateKey.generate()
        peer_pub_hex = bytes(priv_peer.public_key).hex()

        sock = make_udp_sock()
        remote = ('127.0.0.1', 9999)
        c = make_client_obj(sock, remote_addr=remote)
        c._build_box(remote, peer_pub_hex)

        with c._peers_lock:
            box = c._peers[remote]['box']
        assert box is not None

        box_peer = nacl.public.Box(priv_peer, c._privkey.public_key)
        ciphertext = box.encrypt(b'hello')
        plaintext = box_peer.decrypt(ciphertext)
        assert plaintext == b'hello'
        sock.close()

    def test_build_box_invalid_hex_returns_none(self):
        """_build_box returns None and leaves the peer's box unset on bad pubkey hex."""
        sock = make_udp_sock()
        remote = ('127.0.0.1', 9999)
        c = make_client_obj(sock, remote_addr=remote)
        result = c._build_box(remote, 'not-valid-hex')
        assert result is None
        with c._peers_lock:
            assert c._peers[remote]['box'] is None
        sock.close()


# ---------------------------------------------------------------------------
# UDPClient — source address validation
# ---------------------------------------------------------------------------

class TestSourceAddressValidation:

    def test_packets_from_wrong_source_are_dropped(self):
        """_recv_loop ignores packets that do not originate from a known peer."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        sock_c = make_udp_sock()

        box_b, box_a = make_box_pair()
        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b), box=box_a)

        received = []
        original = ui.print_msg

        def capture(name_part, text_part, **kwargs):
            received.append(name_part + text_part)

        ui.print_msg = capture
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            sock_c.sendto(box_b.encrypt(b'injected'), addr_of(sock_a))
            time.sleep(0.05)
            sock_b.sendto(box_b.encrypt(b'real message'), addr_of(sock_a))
            time.sleep(0.05)
            c.done.set()
            t.join(timeout=3)
        finally:
            ui.print_msg = original

        assert any('real message' in r for r in received)
        assert not any('injected' in r for r in received)
        sock_a.close()
        sock_b.close()
        sock_c.close()


# ---------------------------------------------------------------------------
# UDPClient — encryption
# ---------------------------------------------------------------------------

class TestEncryption:

    def test_encrypted_message_decrypted_and_displayed(self):
        """An encrypted message from the legitimate peer is decrypted and shown."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        box_b, box_a = make_box_pair()
        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b), box=box_a)

        received = []
        original = ui.print_msg

        def capture(name_part, text_part, **kwargs):
            received.append(name_part + text_part)

        ui.print_msg = capture
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            sock_b.sendto(box_b.encrypt(b'secret text'), addr_of(sock_a))
            time.sleep(0.1)
            c.done.set()
            t.join(timeout=3)
        finally:
            ui.print_msg = original

        assert any('secret text' in r for r in received)
        sock_a.close()
        sock_b.close()

    def test_unauthenticated_payload_dropped(self):
        """A plaintext (non-Box) payload is dropped without crashing or displaying."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        _, box_a = make_box_pair()
        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b), box=box_a)

        received = []
        original = ui.print_msg

        def capture(name_part, text_part, **kwargs):
            received.append(name_part + text_part)

        ui.print_msg = capture
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            sock_b.sendto(b'not encrypted', addr_of(sock_a))
            time.sleep(0.1)
            c.done.set()
            t.join(timeout=3)
        finally:
            ui.print_msg = original

        assert received == []
        sock_a.close()
        sock_b.close()

    def test_pre_handshake_payload_discarded(self):
        """Encrypted payloads arriving before box is set are silently dropped."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        # box=None means no key exchange yet
        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b), box=None)

        received = []
        original = ui.print_msg

        def capture(name_part, text_part, **kwargs):
            received.append(name_part + text_part)

        def stop_recv():
            time.sleep(0.2)
            sock_a.close()

        ui.print_msg = capture
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            stopper = threading.Thread(target=stop_recv, daemon=True)
            t.start()
            stopper.start()
            time.sleep(0.05)
            sock_b.sendto(b'some data before handshake', addr_of(sock_a))
            t.join(timeout=3)
        finally:
            ui.print_msg = original

        assert received == []
        sock_b.close()


# ---------------------------------------------------------------------------
# UDPClient — PUNCH handshake via _recv_loop
# ---------------------------------------------------------------------------

class TestPunchHandshakeInRecvLoop:

    def test_punch_msg_triggers_ack_and_sets_connected(self):
        """Receiving a PUNCH message causes a PUNCH_ACK reply and sets connected."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b))

        priv_b = nacl.public.PrivateKey.generate()
        punch_from_b = protocol.PUNCH_PREFIX + bytes(priv_b.public_key).hex().encode()

        replies = []

        def run():
            sock_b.settimeout(2)
            sock_b.sendto(punch_from_b, addr_of(sock_a))
            try:
                data, _ = sock_b.recvfrom(4096)
                replies.append(data)
            except socket.timeout:
                pass
            time.sleep(0.05)
            sock_a.close()

        t_helper = threading.Thread(target=run, daemon=True)
        t_recv = threading.Thread(target=c._recv_loop, daemon=True)
        t_recv.start()
        t_helper.start()
        t_helper.join(timeout=4)
        t_recv.join(timeout=2)

        with c._peers_lock:
            connected = c._peers[addr_of(sock_b)]['connected'].is_set()
        assert connected
        assert any(r.startswith(protocol.PUNCH_ACK_PREFIX) for r in replies)
        sock_b.close()

    def test_punch_ack_sets_connected(self):
        """Receiving a PUNCH_ACK sets the connected event."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b))

        priv_b = nacl.public.PrivateKey.generate()
        ack_from_b = protocol.PUNCH_ACK_PREFIX + bytes(priv_b.public_key).hex().encode()

        def run():
            time.sleep(0.05)
            sock_b.sendto(ack_from_b, addr_of(sock_a))
            time.sleep(0.1)
            sock_a.close()

        t_helper = threading.Thread(target=run, daemon=True)
        t_recv = threading.Thread(target=c._recv_loop, daemon=True)
        t_recv.start()
        t_helper.start()
        t_helper.join(timeout=3)
        t_recv.join(timeout=2)

        with c._peers_lock:
            connected = c._peers[addr_of(sock_b)]['connected'].is_set()
        assert connected
        sock_b.close()


# ---------------------------------------------------------------------------
# UDPClient — disconnect handling
# ---------------------------------------------------------------------------

class TestDisconnect:

    def test_ctrl_disconnect_sets_peer_disconnected(self):
        """Receiving CTRL_DISCONNECT sets peer_disconnected; room stays open."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        box_b, box_a = make_box_pair()
        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b), box=box_a)

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            sock_b.sendto(box_b.encrypt(protocol.CTRL_DISCONNECT), addr_of(sock_a))
            time.sleep(0.1)
            assert c.peer_disconnected
            assert not c.done.is_set()  # room stays open
            c.done.set()
            t.join(timeout=3)
        finally:
            sys.stdout = old_stdout

        sock_a.close()
        sock_b.close()

    def test_beacon_ignored_during_chat(self):
        """Beacon packets received during a session are silently discarded."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()

        box_b, box_a = make_box_pair()
        c = make_client_obj(sock_a, remote_addr=addr_of(sock_b), box=box_a)

        received = []
        original = ui.print_msg

        def capture(name_part, text_part, **kwargs):
            received.append(name_part + text_part)

        ui.print_msg = capture
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            stray_beacon = protocol.BEACON_PREFIX + b'deadbeef:1234:abcd1234abcd1234'
            sock_b.sendto(stray_beacon, addr_of(sock_a))
            time.sleep(0.05)
            sock_b.sendto(box_b.encrypt(b'hello'), addr_of(sock_a))
            time.sleep(0.05)
            c.done.set()
            t.join(timeout=3)
        finally:
            ui.print_msg = original

        assert received == ['hello']
        sock_a.close()
        sock_b.close()


# ---------------------------------------------------------------------------
# UDPClient — _punch timeout
# ---------------------------------------------------------------------------

class TestPunchTimeout:

    def test_punch_stops_after_timeout(self):
        """_punch stops sending after PUNCH_TIMEOUT expires."""
        sock_a = make_udp_sock()
        remote = ('127.0.0.1', 9999)
        c = make_client_obj(sock_a, remote_addr=remote)

        original = protocol.PUNCH_TIMEOUT
        protocol.PUNCH_TIMEOUT = 1
        try:
            start = time.time()
            c._punch(remote)
            elapsed = time.time() - start
        finally:
            protocol.PUNCH_TIMEOUT = original

        with c._peers_lock:
            connected = c._peers[remote]['connected'].is_set()
        assert elapsed >= 1
        assert not connected
        sock_a.close()


# ---------------------------------------------------------------------------
# UDPClient — multi-peer
# ---------------------------------------------------------------------------

class TestMultiPeer:

    def test_messages_received_from_two_peers(self):
        """Messages from two separate peers are both displayed."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        sock_c = make_udp_sock()

        box_b, box_a_b = make_box_pair()
        box_c, box_a_c = make_box_pair()

        from colorama import Fore
        c = UDPClient.__new__(UDPClient)
        c.sock = sock_a
        c.username = 'Tester'
        c.done = threading.Event()
        c.peer_disconnected = False
        c.name_colour = Fore.CYAN
        c.text_colour = Fore.WHITE
        priv = nacl.public.PrivateKey.generate()
        c._privkey = priv
        c._pubkey_bytes = bytes(priv.public_key)
        c._peers_lock = threading.Lock()
        c._first_connected = threading.Event()
        c._first_connected.set()
        c._own_addr = addr_of(sock_a)
        peer_base = {'name_colour': Fore.CYAN, 'text_colour': Fore.WHITE, 'muted': False, 'username': ''}
        c._peers = {
            addr_of(sock_b): {**peer_base, 'box': box_a_b, 'connected': threading.Event()},
            addr_of(sock_c): {**peer_base, 'box': box_a_c, 'connected': threading.Event()},
        }
        c._peers[addr_of(sock_b)]['connected'].set()
        c._peers[addr_of(sock_c)]['connected'].set()

        received = []
        original = ui.print_msg

        def capture(name_part, text_part, **kwargs):
            received.append(name_part + text_part)

        ui.print_msg = capture
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            sock_b.sendto(box_b.encrypt(b'from B'), addr_of(sock_a))
            sock_c.sendto(box_c.encrypt(b'from C'), addr_of(sock_a))
            time.sleep(0.1)
            c.done.set()
            t.join(timeout=3)
        finally:
            ui.print_msg = original

        assert any('from B' in r for r in received)
        assert any('from C' in r for r in received)
        sock_a.close()
        sock_b.close()
        sock_c.close()

    def test_session_ends_only_when_all_peers_disconnect(self):
        """done is NOT set when peers disconnect — room stays open for new joiners."""
        sock_a = make_udp_sock()
        sock_b = make_udp_sock()
        sock_c = make_udp_sock()

        box_b, box_a_b = make_box_pair()
        box_c, box_a_c = make_box_pair()

        from colorama import Fore
        c = UDPClient.__new__(UDPClient)
        c.sock = sock_a
        c.username = 'Tester'
        c.done = threading.Event()
        c.peer_disconnected = False
        c.name_colour = Fore.CYAN
        c.text_colour = Fore.WHITE
        priv = nacl.public.PrivateKey.generate()
        c._privkey = priv
        c._pubkey_bytes = bytes(priv.public_key)
        c._peers_lock = threading.Lock()
        c._first_connected = threading.Event()
        c._first_connected.set()
        c._own_addr = addr_of(sock_a)
        peer_base = {'name_colour': Fore.CYAN, 'text_colour': Fore.WHITE, 'muted': False, 'username': ''}
        c._peers = {
            addr_of(sock_b): {**peer_base, 'box': box_a_b, 'connected': threading.Event()},
            addr_of(sock_c): {**peer_base, 'box': box_a_c, 'connected': threading.Event()},
        }
        c._peers[addr_of(sock_b)]['connected'].set()
        c._peers[addr_of(sock_c)]['connected'].set()

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            t = threading.Thread(target=c._recv_loop, daemon=True)
            t.start()
            time.sleep(0.05)
            sock_b.sendto(box_b.encrypt(protocol.CTRL_DISCONNECT), addr_of(sock_a))
            sock_c.sendto(box_c.encrypt(protocol.CTRL_DISCONNECT), addr_of(sock_a))
            time.sleep(0.1)
            # Room stays open even after all peers disconnect.
            assert not c.done.is_set()
            assert c.peer_disconnected
            c.done.set()
            t.join(timeout=3)
        finally:
            sys.stdout = old_stdout

        sock_a.close()
        sock_b.close()
        sock_c.close()
