from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16


def _aes_block(key: bytes, block: bytes, *, decrypt: bool = False) -> bytes:

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must contain 16, 24, or 32 bytes")
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must contain exactly 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    operation = cipher.decryptor() if decrypt else cipher.encryptor()
    return operation.update(block) + operation.finalize()


def pad_10star(data: bytes) -> bytes:
    missing = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + b"\x80" + b"\x00" * (missing - 1)


def unpad_10star(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Invalid 10* padding")
    # Padding must be entirely within the final block (at most 16 bytes).
    marker = len(data) - 1
    while marker >= len(data) - BLOCK_SIZE and data[marker] == 0:
        marker -= 1
    if marker < len(data) - BLOCK_SIZE or data[marker] != 0x80:
        raise ValueError("Invalid 10* padding")
    return data[:marker]


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    padded = pad_10star(plaintext)
    return b"".join(
        _aes_block(key, padded[i:i + BLOCK_SIZE])
        for i in range(0, len(padded), BLOCK_SIZE)
    )


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ECB ciphertext must be a nonempty sequence of 16-byte blocks")
    padded = b"".join(
        _aes_block(key, ciphertext[i:i + BLOCK_SIZE], decrypt=True)
        for i in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return unpad_10star(padded)
