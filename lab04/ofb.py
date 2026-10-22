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

def ofb_encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    if iv is None:
        iv = os.urandom(BLOCK)
    if len(iv) != BLOCK:
        raise ValueError(f"IV must be exactly {BLOCK} bytes")

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

QUESTIONS = (
    (
        8,
        "01a1babc3cbfc48932761127997cdc40",
        """
        423b1d6d0d11d3fab1236e2e03294345
        eaa47185fedf20251c5c1e2bcb3ef400
        35003d37cdd5cae757a2d59483437a27
        9fa215ee7d0045596bd0474c981c76fd
        47c946be17c4e91238ff
        """,
    ),
    (
        9,
        "01a1babc3cbfc48932761127997cdc40",
        """
        bbc9645adb9a7020010481aa0bfcde49
        1a4ff192b902dc63f5b44ce05cce36ff
        dbe35a2b779e46ca10bd773abfea383a
        b89afb7d9b5667dbc6be72adc15558
        """,
    ),
)

def main() -> None:
    for number, key_hex, ciphertext_hex in QUESTIONS:
        plaintext = ofb_decrypt(bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex))
        print(f"Question {number}: {plaintext.decode('utf-8')}")

if __name__ == "__main__":
    main()
