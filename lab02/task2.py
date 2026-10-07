M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."

def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

with open("ciphertexts.txt") as f:
    c1, c2, c3 = [bytes.fromhex(line.strip()) for line in f if line.strip()]

x = strxor(c1, c2)
print("c1 ^ c2 :", x.hex())
print("M1 ^ M2 :", strxor(M1, M2).hex())
print("equal   :", x == strxor(M1, M2))

crib = b" the "
ALLOWED = set(b"abcdefghijklmnopqrstuvwxyz ")
print()
for pos in range(len(x) - len(crib) + 1):
    r = strxor(x[pos:pos + len(crib)], crib)
    if all(ch in ALLOWED for ch in r):
        print(f"pos {pos:2d}: {r!r}")

fake = b"Nothing to see here.".ljust(len(c1), b" ")
k_prime = strxor(c1, fake)
print()
print("k'      :", k_prime.hex())
print("c1 ^ k' :", strxor(c1, k_prime))
print("check   :", strxor(c1, k_prime) == fake)