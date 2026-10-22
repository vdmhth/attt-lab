"""AES-CBC."""

import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16


def _aes_block(key: bytes, block: bytes, *, decrypt: bool = False) -> bytes:
    """Transform one AES block."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must contain 16, 24, or 32 bytes")
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must contain exactly 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    operation = cipher.decryptor() if decrypt else cipher.encryptor()
    return operation.update(block) + operation.finalize()


def pad_pkcs5(data: bytes) -> bytes:
    """Add PKCS#7 padding."""
    missing = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([missing]) * missing


def unpad_pkcs5(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Invalid PKCS5/PKCS#7 padding")
    missing = data[-1]
    if not 1 <= missing <= BLOCK_SIZE:
        raise ValueError("Invalid PKCS5/PKCS#7 padding")
    if data[-missing:] != bytes([missing]) * missing:
        raise ValueError("Invalid PKCS5/PKCS#7 padding")
    return data[:-missing]


def _xor_block(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt; prepend a random IV."""
    iv = secrets.token_bytes(BLOCK_SIZE)
    previous = iv
    result = bytearray(iv)
    padded = pad_pkcs5(plaintext)
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        previous = _aes_block(key, _xor_block(block, previous))
        result.extend(previous)
    return bytes(result)


def cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and validate padding."""
    if len(ciphertext) < 2 * BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("CBC ciphertext must contain a 16-byte IV and complete blocks")
    previous = ciphertext[:BLOCK_SIZE]
    padded = bytearray()
    for i in range(BLOCK_SIZE, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        padded.extend(_xor_block(_aes_block(key, block, decrypt=True), previous))
        previous = block
    return unpad_pkcs5(bytes(padded))
