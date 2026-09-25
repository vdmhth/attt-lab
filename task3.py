import nacl.utils
from nacl.secret import SecretBox

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."

TAG = 16
KEY_SIZE = 32
NONCE_SIZE = 24

def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def G(key: bytes, nonce: bytes, n: int) -> bytes:
    ct = SecretBox(key).encrypt(bytes(n), nonce).ciphertext
    return ct[TAG:]

def encrypt(key: bytes, m: bytes) -> bytes:
    nonce = nacl.utils.random(NONCE_SIZE)
    return nonce + strxor(m, G(key, nonce, len(m)))

def decrypt(key: bytes, c: bytes) -> bytes:
    nonce, body = c[:NONCE_SIZE], c[NONCE_SIZE:]
    return strxor(body, G(key, nonce, len(body)))

if __name__ == "__main__":
    key = nacl.utils.random(KEY_SIZE)
    nonce = nacl.utils.random(NONCE_SIZE)
    print("key    :", key.hex())
    print("nonce  :", nonce.hex())
    print("G(k, nonce, 64):", G(key, nonce, 64).hex())

    print("\nEncrypt M1 twice")
    ca = encrypt(key, M1)
    cb = encrypt(key, M1)
    print("c (1st):", ca.hex())
    print("c (2nd):", cb.hex())
    print("decrypt 1st :", decrypt(key, ca).decode())
    print("decrypt 2nd :", decrypt(key, cb).decode())

    print("\nM1 and M2 with the same nonce")
    pad = G(key, nonce, max(len(M1), len(M2)))
    c1 = strxor(M1, pad)
    c2 = strxor(M2, pad)
    print("c1 ^ c2  :", strxor(c1, c2).hex())
    print("M1 ^ M2  :", strxor(M1, M2).hex())
    print("c1 ^ c2 == M1 ^ M2 :", strxor(c1, c2) == strxor(M1, M2))

    print("\nDifferent nonces")
    ca, cb = encrypt(key, M1), encrypt(key, M2)
    print("c1 ^ c2 == M1 ^ M2 :", strxor(ca[NONCE_SIZE:], cb[NONCE_SIZE:]) == strxor(M1, M2))