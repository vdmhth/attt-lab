"""
python3 encrypt_file.py genkey  key.bin ->run this to generate a random 10-byte key
python3 encrypt_file.py enc     key.bin  plain.txt   cipher.bin -> encrypts plain.txt to cipher.bin using key.bin and a fresh random IV
python3 encrypt_file.py dec     key.bin  cipher.bin  plain_out.txt -> decrypts cipher.bin to plain_out.txt using key.bin
python3 encrypt_file.py selftest -> round-trip + fresh-IV check
"""
import os
import sys
from trivium import keystream
IV_LEN = 10
KEY_LEN = 10
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
def encrypt(key: bytes, data: bytes, iv: bytes = None) -> bytes:
    assert len(key) == KEY_LEN
    if iv is None:
        iv = os.urandom(IV_LEN)          
    assert len(iv) == IV_LEN
    ks = keystream(key, iv, len(data))
    return iv + xor_bytes(data, ks)
def decrypt(key: bytes, blob: bytes) -> bytes:
    assert len(key) == KEY_LEN and len(blob) >= IV_LEN
    iv, ct = blob[:IV_LEN], blob[IV_LEN:]
    ks = keystream(key, iv, len(ct))
    return xor_bytes(ct, ks)

def encrypt_file(key: bytes, in_path: str, out_path: str) -> None:
    with open(in_path, "rb") as f:
        data = f.read()
    with open(out_path, "wb") as f:
        f.write(encrypt(key, data))

def decrypt_file(key: bytes, in_path: str, out_path: str) -> None:
    with open(in_path, "rb") as f:
        blob = f.read()
    with open(out_path, "wb") as f:
        f.write(decrypt(key, blob))
def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != KEY_LEN:
        sys.exit(f"key file must be exactly {KEY_LEN} bytes, got {len(key)}")
    return key
def selftest() -> None:
    key = os.urandom(KEY_LEN)
    msg = b"Trivium A2 self-test: attack at dawn!\n" * 3
    c1, c2 = encrypt(key, msg), encrypt(key, msg)
    print("round trip OK          :", decrypt(key, c1) == msg)
    print("two ciphertexts differ :", c1 != c2)
    print("IVs differ             :", c1[:IV_LEN] != c2[:IV_LEN])
    print("ciphertext length      :", len(c1), "=", IV_LEN, "+", len(msg))
def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) == 3 and argv[1] == "genkey":
        with open(argv[2], "wb") as f:
            f.write(os.urandom(KEY_LEN))
        return print("wrote", argv[2])
    if len(argv) == 5 and argv[1] in ("enc", "dec"):
        key = load_key(argv[2])
        (encrypt_file if argv[1] == "enc" else decrypt_file)(key, argv[3], argv[4])
        return print(("encrypted" if argv[1] == "enc" else "decrypted"), argv[3], "->", argv[4])
    print(__doc__)
if __name__ == "__main__":
    main(sys.argv)