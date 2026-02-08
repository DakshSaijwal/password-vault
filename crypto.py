import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
SALT_LEN = 16


def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(master_password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=102400,  # 100 MB
        parallelism=2,
        hash_len=KEY_LEN,
        type=Type.ID
    )


def encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None).decode()
