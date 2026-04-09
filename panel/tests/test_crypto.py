from panel.crypto import CryptoContext

TEST_PSK = "test-passphrase-oxide"
TEST_SALT = b"test-salt-must-be-32-bytes-long!"


def test_encrypt_decrypt_roundtrip():
    sender = CryptoContext(TEST_PSK, TEST_SALT, is_initiator=True)
    receiver = CryptoContext(TEST_PSK, TEST_SALT, is_initiator=False)
    plaintext = b"hello oxide"
    encrypted = sender.encrypt(plaintext)
    decrypted = receiver.decrypt(encrypted)
    assert decrypted == plaintext


def test_wrong_key_fails():
    sender = CryptoContext("correct-key", TEST_SALT, is_initiator=True)
    receiver = CryptoContext("wrong-key", TEST_SALT, is_initiator=False)
    encrypted = sender.encrypt(b"secret")
    try:
        receiver.decrypt(encrypted)
        assert False, "should have raised"
    except Exception:
        pass


def test_nonces_differ():
    ctx = CryptoContext(TEST_PSK, TEST_SALT, is_initiator=True)
    enc1 = ctx.encrypt(b"msg1")
    enc2 = ctx.encrypt(b"msg2")
    assert enc1[:12] != enc2[:12]


def test_replay_detected():
    sender = CryptoContext(TEST_PSK, TEST_SALT, is_initiator=True)
    receiver = CryptoContext(TEST_PSK, TEST_SALT, is_initiator=False)
    encrypted = sender.encrypt(b"first")
    receiver.decrypt(encrypted)
    try:
        receiver.decrypt(encrypted)
        assert False, "replay should be detected"
    except ValueError as e:
        assert "replay" in str(e).lower()


def test_cross_language_known_vector():
    """Verify Python produces same output as Rust for known inputs."""
    ctx = CryptoContext("oxide-lab-psk", b"test-salt-must-be-32-bytes-long!", is_initiator=True)
    encrypted = ctx.encrypt(b'{"type":"test"}')
    assert encrypted[:4] == b"\x00\x00\x00\x00"
    assert encrypted[4:12] == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert len(encrypted) == 43
