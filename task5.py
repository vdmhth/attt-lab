from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.utils import random
def strxor(a, b):
    if len(a) != len(b):
        raise ValueError("XOR operands must have equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))
def G(key, nonce, n):
    return SecretBox(key).encrypt(bytes(n), nonce).ciphertext[SecretBox.MACBYTES:]
def encrypt(key, msg):
    nonce = random(SecretBox.NONCE_SIZE)
    return nonce + strxor(msg, G(key, nonce, len(msg)))
def decrypt(key, ciphertext):
    if len(ciphertext) < SecretBox.NONCE_SIZE:
        raise ValueError("Missing 24B nonce")
    nonce = ciphertext[:SecretBox.NONCE_SIZE]
    body = ciphertext[SecretBox.NONCE_SIZE:]
    return strxor(body, G(key, nonce, len(body)))
def forge(ciphertext, known_plaintext, desired_plaintext, body_offset):
    delta = strxor(known_plaintext, desired_plaintext)
    if len(ciphertext) - body_offset != len(delta):
        raise ValueError("Unexpected ciphertext body length")
    return ciphertext[:body_offset] + strxor(ciphertext[body_offset:], delta)
msg = b"PAY BOB 0100 USD"
target = b"PAY BOB 9900 USD"
key = random(SecretBox.KEY_SIZE)
print("Key (hex):", key.hex())
print("Known plaintext:", msg.decode())
print("Desired plaintext:", target.decode())
print("XOR delta (hex):", strxor(msg, target).hex())
ciphertext = encrypt(key, msg)
forged = forge(ciphertext, msg, target, body_offset=SecretBox.NONCE_SIZE)
recovered = decrypt(key, forged)
print("Task 3 ciphertext (nonce || body, hex):\n" + ciphertext.hex())
print("Task 3 forged ciphertext (hex):\n " + forged.hex())
print("Task 3 forged decryption:", recovered.decode())
assert recovered == target
box = SecretBox(key)
authenticated = bytes(box.encrypt(msg))
forged_authenticated = forge(authenticated, msg, target,body_offset=SecretBox.NONCE_SIZE + SecretBox.MACBYTES)
print("SecretBox ciphertext (nonce || tag || body, hex):\n" + authenticated.hex())
print("SecretBox original decryption:", box.decrypt(authenticated).decode())
print("SecretBox forged ciphertext (hex):\n" + forged_authenticated.hex())
try:
    box.decrypt(forged_authenticated)
except CryptoError as exc:
    print(f"SecretBox forged decryption: {type(exc).__name__}: {exc}")
else:
    raise AssertionError("SecretBox unexpectedly accepted the forgery")
