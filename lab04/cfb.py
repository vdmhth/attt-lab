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

QUESTIONS = (
    (
        10,
        "418d6b6d8bf2f8a873509336c64cbb4d",
        """0e31aac86c0532fde5e69aa86e6d2c3ecb9fce6486b716e54cc60c396e31f7b13feed1aa150ac46ad65bd7540e55a5e602a206a7a42007d4663c82ad281f21cbf59f9127e2f2b5""",
    ),
    (
        11,
        "418d6b6d8bf2f8a873509336c64cbb4d",
        """3debb9636423ee952ee93717209eb264595366f2ca9ab6c73536624ab717d1197a7518a6a945e3d2b280585f156a6090e725a6eef315ab252a3b23557231b03966c4f19dd8155e4d8f""",
    ),
)

def main() -> None:
    for number, key_hex, ciphertext_hex in QUESTIONS:
        plaintext = cfb_decrypt(bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex))
        print(f"Question {number}: {plaintext.decode('utf-8')}")

if __name__ == "__main__":
    main()
