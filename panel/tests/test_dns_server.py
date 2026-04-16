import threading
import socket
import struct
import time
import pytest
from panel.dns_server import _meta, _b32d, _b32e, DnsServer
from panel.registry import Registry


def test_meta_data():
    s, t, i = _meta("aabbcc0305")
    assert s == "aabbcc" and t == 3 and i == 5


def test_meta_heartbeat():
    _, t, i = _meta("ff00110000")
    assert t == 0 and i == 0


def test_b32_roundtrip():
    d = bytes(range(32))
    assert _b32d(_b32e(d)) == d


def test_server_udp_responds():
    reg = Registry()
    srv = DnsServer(15053, "oxide-lab-psk", b"test-salt-must-be-32-bytes-long!", reg)
    threading.Thread(target=srv.start, daemon=True).start()
    time.sleep(0.15)
    qname = "aabbcc0000.hb.c2.oxide.lab"
    pkt = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    for lbl in qname.split("."):
        pkt += bytes([len(lbl)]) + lbl.encode()
    pkt += b"\x00" + struct.pack("!HH", 16, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    s.sendto(pkt, ("127.0.0.1", 15053))
    data, _ = s.recvfrom(512)
    s.close()
    assert data[2] & 0x80  # QR bit set
