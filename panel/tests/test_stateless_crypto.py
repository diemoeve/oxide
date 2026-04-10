import pytest
from panel.crypto import StatelessCrypto

PSK = "oxide-lab-psk"
SALT = b"test-salt-must-be-32-bytes-long!"


def test_stateless_roundtrip():
    sc = StatelessCrypto(PSK, SALT)
    ct = sc.encrypt(b"hello oxide")
    assert sc.decrypt(ct) == b"hello oxide"


def test_stateless_nonces_differ():
    sc = StatelessCrypto(PSK, SALT)
    c1 = sc.encrypt(b"same")
    c2 = sc.encrypt(b"same")
    assert c1[:12] != c2[:12]


def test_stateless_wrong_key_fails():
    enc = StatelessCrypto(PSK, SALT)
    dec = StatelessCrypto("wrong-psk", SALT)
    ct = enc.encrypt(b"secret")
    with pytest.raises(Exception):
        dec.decrypt(ct)


def test_stateless_too_short_fails():
    sc = StatelessCrypto(PSK, SALT)
    with pytest.raises(ValueError, match="too short"):
        sc.decrypt(b"\x00" * 10)
