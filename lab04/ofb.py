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

def ofb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(BLOCK)

    s = iv
    out = []
    for x in split_blocks(plaintext):
        s = aes_enc_block(key, s)             
        out.append(xor(x, s[:len(x)]))        
    return iv + b"".join(out)

def ofb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < BLOCK:
        raise ValueError("Ciphertext must contain a 16-byte IV")
    
    iv, body = ciphertext[:BLOCK], ciphertext[BLOCK:]
    s = iv
    out = []
    for y in split_blocks(body):
        s = aes_enc_block(key, s)
        out.append(xor(y, s[:len(y)]))
    return b"".join(out)
