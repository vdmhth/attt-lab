import os
from Crypto.Cipher import AES

BLOCK = 16
COUNTER_MAX = (1 << (BLOCK * 8)) - 1

def aes_enc_block(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK
    return AES.new(key, AES.MODE_ECB).encrypt(block)

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def split_blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]

def _int_to_block(n: int) -> bytes:
    return (n % (1 << 128)).to_bytes(BLOCK, "big")

def ctr_encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    if iv is None:
        iv = os.urandom(BLOCK)
    if len(iv) != BLOCK:
        raise ValueError(f"Initial counter must be exactly {BLOCK} bytes")

    counter = int.from_bytes(iv, "big")
    out = []
    for i, x in enumerate(split_blocks(plaintext)):
        s = aes_enc_block(key, _int_to_block(counter + i))
        out.append(xor(x, s[:len(x)]))
    return iv + b"".join(out)

def ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < BLOCK:
        raise ValueError("Ciphertext must contain a 16-byte initial counter")
    iv, body = ciphertext[:BLOCK], ciphertext[BLOCK:]
    counter = int.from_bytes(iv, "big")
    out = []
    for i, y in enumerate(split_blocks(body)):
        s = aes_enc_block(key, _int_to_block(counter + i))
        out.append(xor(y, s[:len(y)]))
    return b"".join(out)

QUESTIONS = (
    (
        12,
        "36f18357be4dbd77f050515c73fcf9f2",
        """69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329""",
    ),
    (
        13,
        "36f18357be4dbd77f050515c73fcf9f2",
        """770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451""",
    ),
    (
        14,
        "66341ce0412db5c6d90712e055a3b8c6",
        """10adedeb5d4e5264fffffffffffffffdeb48463612a0a7764c1434dd7b57b5d740f974dc2ceae4be9cf2b9011621596dd67844d0e4189d1b177f022baadaa16b850fd53bd3454a7b47ae30b56ea35962ca956e""",
    ),
    (
        15,
        "66341ce0412db5c6d90712e055a3b8c6",
        """fffffffffffffffffffffffffffffffee9ff9dcc6eeb5317b03dc5deae2b18ba61cf47788632076829a111f416c377a38a5c""",
    ),
)

def main() -> None:
    for number, key_hex, ciphertext_hex in QUESTIONS:
        plaintext = ctr_decrypt(bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex))
        print(f"Question {number}: {plaintext.decode('utf-8')}")

if __name__ == "__main__":
    main()
