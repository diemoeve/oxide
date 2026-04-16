import os as _os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 600_000
AES_KEY_SIZE = 32
NONCE_SIZE = 12
MAX_MESSAGE_SIZE = 16_777_216


class CryptoContext:
    def __init__(self, psk: str, salt: bytes, is_initiator: bool):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(psk.encode())
        self._aesgcm = AESGCM(key)
        self._send_counter = 0
        self._last_recv_counter = None
        if is_initiator:
            self._direction_prefix = b"\x00\x00\x00\x00"
        else:
            self._direction_prefix = b"\x01\x00\x00\x00"

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = self._make_nonce(self._send_counter)
        self._send_counter += 1
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < NONCE_SIZE + 16:
            raise ValueError("data too short")
        nonce = data[:NONCE_SIZE]
        counter = struct.unpack("<Q", nonce[4:12])[0]
        if self._last_recv_counter is not None and counter <= self._last_recv_counter:
            raise ValueError("replay detected")
        plaintext = self._aesgcm.decrypt(nonce, data[NONCE_SIZE:], None)
        self._last_recv_counter = counter
        return plaintext

    def _make_nonce(self, counter: int) -> bytes:
        return self._direction_prefix + struct.pack("<Q", counter)



class StatelessCrypto:
    """AES-256-GCM with random nonces. No replay protection. Use over HTTPS only."""

    def __init__(self, psk: str, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        self._key = kdf.derive(psk.encode())

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = _os.urandom(NONCE_SIZE)
        ct = AESGCM(self._key).encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < NONCE_SIZE + 16:
            raise ValueError("data too short")
        nonce, ct = data[:NONCE_SIZE], data[NONCE_SIZE:]
        return AESGCM(self._key).decrypt(nonce, ct, None)


def derive_key(psk: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=AES_KEY_SIZE, salt=salt,
                     iterations=PBKDF2_ITERATIONS)
    return kdf.derive(psk.encode())


def encrypt_stateless(key: bytes, plaintext: bytes) -> bytes:
    nonce = _os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_stateless(key: bytes, data: bytes) -> bytes:
    if len(data) < NONCE_SIZE + 16:
        raise ValueError("data too short")
    return AESGCM(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None)
