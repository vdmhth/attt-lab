import os

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."
M3 = b"Lunch will be served in the main hall at half past twelve."
MSGS = [M1, M2, M3]

def random(size=16):
    return os.urandom(size)

def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(key: bytes, msg: bytes) -> bytes:
    if len(msg) > len(key):
        raise ValueError(f"message ({len(msg)} bytes) is longer than the key ({len(key)} bytes)")
    c = strxor(key, msg)
    print()
    print(c.hex())
    return c

def decrypt(key: bytes, c: bytes) -> bytes:
    return strxor(key, c)

def main():
    key = random(1024)
    print("key length:", len(key), "bytes")
    print("key (first 32 bytes):", key[:32].hex())

    print("\nciphertexts:")
    ciphertexts = [encrypt(key, m) for m in MSGS]

    print("\ndecrypted:")
    for c in ciphertexts:
        print(decrypt(key, c).decode())

    with open("ciphertexts.txt", "w") as f:
        for c in ciphertexts:
            f.write(c.hex() + "\n")

    long_msg = b"A" * 1500
    try:
        encrypt(key, long_msg)
    except ValueError as e:
        print("\nValueError:", e)


if __name__ == "__main__":
    main()
    
