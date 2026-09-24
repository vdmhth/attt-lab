import argparse
import hashlib
from pathlib import Path
from time import perf_counter
from nacl.secret import SecretBox
from nacl.utils import random
CHUNK_SIZE = 1024 * 1024  
PREFIX_SIZE = 16
def G(key, nonce, n): # create keystream
    return SecretBox(key).encrypt(bytes(n), nonce).ciphertext[SecretBox.MACBYTES:]
def strxor(a, b):
    if len(a) != len(b):
        raise ValueError("XOR operands must have equal lengths")
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")
def transform_file(source, destination, key, decrypt=False, forget_counter=False):
    with open(source, "rb") as src, open(destination, "wb") as dst:
        if decrypt:
            prefix = src.read(PREFIX_SIZE)
            if len(prefix) != PREFIX_SIZE:
                raise ValueError("Missing 16B prefix")
        else:
            prefix = random(PREFIX_SIZE)
            dst.write(prefix)
        i = 0
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            counter = 0 if forget_counter else i # buggy encryption 
            nonce = prefix + counter.to_bytes(8, "little")
            dst.write(strxor(chunk, G(key, nonce, len(chunk))))
            i += 1
    return prefix
def sha256(path):
    digest = hashlib.sha256() 
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
def first_two_chunks(path, skip=0): 
    with open(path, "rb") as f:
        f.seek(skip)
        return f.read(CHUNK_SIZE), f.read(CHUNK_SIZE)
def reuse_check(book, encrypted): # check if the same keystream is used for two diff chunks of plaintext
    m0, m1 = first_two_chunks(book)
    c0, c1 = first_two_chunks(encrypted, skip=PREFIX_SIZE)
    n = min(len(m0), len(m1), len(c0), len(c1))
    if n == 0:
        raise ValueError("The comparison needs at least two nonempty chunks")
    return strxor(c0[:n], c1[:n]) == strxor(m0[:n], m1[:n])
parser = argparse.ArgumentParser()
parser.add_argument("book", nargs="?", type=Path, default=Path("book.pdf"))
parser.add_argument("--out-dir", type=Path, default=Path("."))
args = parser.parse_args()
args.out_dir.mkdir(parents=True, exist_ok=True)
book = args.book
enc = args.out_dir / "book.enc"
dec = args.out_dir / "book.dec.pdf"
bad_enc = args.out_dir / "book.buggy.enc"
bad_dec = args.out_dir / "book.buggy.dec.pdf"
if book.resolve() in {p.resolve() for p in (enc, dec, bad_enc, bad_dec)}:
    raise ValueError("Input must differ from output paths")
key = random(SecretBox.KEY_SIZE)
start = perf_counter()
prefix = transform_file(book, enc, key)
elapsed = perf_counter() - start
transform_file(enc, dec, key, decrypt=True)
with open(book, "rb") as f:
    first_plain = f.read(16)
with open(enc, "rb") as f:
    f.seek(PREFIX_SIZE)
    first_cipher = f.read(16)
original_hash = sha256(book)
decrypted_hash = sha256(dec)
print("Key (hex):", key.hex())
print("Key size:", len(key), "bytes")
print("Prefix (hex):", prefix.hex())
print("book.pdf size:", book.stat().st_size, "bytes")
print("book.enc size:", enc.stat().st_size, "bytes")
print("First 16 plaintext bytes (hex):", first_plain.hex())
print("First 16 ciphertext bytes after prefix (hex):", first_cipher.hex())
print("SHA-256 book.pdf:", original_hash)
print("SHA-256 book.dec.pdf:", decrypted_hash)
print("Hashes match:", original_hash == decrypted_hash)
print(f"Encryption time: {elapsed:.6f} seconds")
print("Correct counter: c0 XOR c1 == m0 XOR m1:", reuse_check(book, enc))
bad_prefix = transform_file(book, bad_enc, key, forget_counter=True)
transform_file(bad_enc, bad_dec, key, decrypt=True, forget_counter=True)
print("Buggy prefix (hex):", bad_prefix.hex())
print("Forgotten counter: c0 XOR c1 == m0 XOR m1:", reuse_check(book, bad_enc))
buggy_hash = sha256(bad_dec)
print("SHA-256 book.buggy.dec.pdf:", buggy_hash)
print("Buggy decryption matches the original:", original_hash == buggy_hash)
assert enc.stat().st_size == book.stat().st_size + PREFIX_SIZE
assert original_hash == decrypted_hash == buggy_hash
assert reuse_check(book, bad_enc)
