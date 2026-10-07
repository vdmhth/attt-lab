import os
from encrypt_file import encrypt, xor_bytes, IV_LEN
P1 = b"Meeting at 9am in meeting room AI4Life. Bring the slides.\n"
P2 = b"Transfer 5000 VND to account 0123456 later.\n"
with open("msg1.txt", "wb") as f: f.write(P1)
with open("msg2.txt", "wb") as f: f.write(P2)
key = os.urandom(10)
iv = bytes(10)                            
C1 = encrypt(key, P1, iv)[IV_LEN:]
C2 = encrypt(key, P2, iv)[IV_LEN:]
print("C1           :", C1.hex())
print("C2           :", C2.hex())
x = xor_bytes(C1, C2)
print("C1 xor C2 :", x.hex())
print("P1 xor P2:", xor_bytes(P1, P2).hex())
print("is equal?:", x == xor_bytes(P1, P2), " (C1 xor C2) == (P1 xor P2)")
# attacker knows P1 but never sees the key:
recovered_P2 = xor_bytes(x, P1)
print("recovered P2 :", recovered_P2)
recovered_K = xor_bytes(C1, P1)
print("recovered keystream (first 16 bytes):", recovered_K[:16].hex())
# Same experiment with fresh IVs: the XOR is just noise
C1f = encrypt(key, P1)[IV_LEN:]
C2f = encrypt(key, P2)[IV_LEN:]
print("\nwith fresh IVs,(C1 xor C2 xor P1) =", xor_bytes(xor_bytes(C1f, C2f), P1)[:32])