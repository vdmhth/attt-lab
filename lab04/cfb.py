import os
from Crypto.Cipher import AES

BLOCK = 16

def aes_enc_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK
    return AES.new(key, AES.MODE_ECB).encrypt(block)

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def split_blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]

def cfb_encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    if iv is None:
        iv = os.urandom(BLOCK)
    if len(iv) != BLOCK:
        raise ValueError(f"IV must be exactly {BLOCK} bytes")

    prev = iv
    out = []
    for x in split_blocks(plaintext):
        s = aes_enc_block(key, prev)         
        y = xor(x, s[:len(x)])
        out.append(y)
        prev = y if len(y) == BLOCK else y + prev[len(y):]
    return iv + b"".join(out)

def cfb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < BLOCK:
        raise ValueError("Ciphertext must contain a 16-byte IV")

    iv, body = ciphertext[:BLOCK], ciphertext[BLOCK:]
    prev = iv
    out = []
    for y in split_blocks(body):
        s = aes_enc_block(key, prev)         
        x = xor(y, s[:len(y)])
        out.append(x)
        prev = y if len(y) == BLOCK else y + prev[len(y):]
    return b"".join(out)
