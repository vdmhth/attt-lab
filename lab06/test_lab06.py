"""Test suite for Lab 06. Put your functions in lab06.py, then run:
    python3 test_lab06.py        (or: pytest test_lab06.py)
"""
from lab06 import (extended_euclid, mod_inv,
                   poly_mul, poly_divmod, poly_mulmod, poly_ext_euclid,
                   poly_inv, inverse_table)

A = 340282366920938463463374607431768211457                          # 2^128 + 1
N = 6277101735386680763835789423207666416102355444464034512896       # 2^192
AES = 0x11B                    # P(x) = x^8 + x^4 + x^3 + x + 1
GF512 = 0x211                  # P(x) = x^9 + x^4 + 1
GCM = (1 << 128) | 0x87        # P(x) = x^128 + x^7 + x^2 + x + 1


# ----------------------------- Part A -----------------------------
def test_A1_extended_euclid():
    assert extended_euclid(5, 12) == (1, 5, -2)
    assert extended_euclid(12, 5) == (1, -2, 5)
    assert extended_euclid(391, 299) == (23, -3, 4)
    for a in range(1, 60):
        for b in range(0, 60):
            d, x, y = extended_euclid(a, b)
            assert a * x + b * y == d and a % d == 0 and b % d == 0


def test_A2_mod_inv():
    assert mod_inv(5, 12) == 5
    assert mod_inv(3, 7) == 5
    try:
        mod_inv(6, 9)
        assert False, "expected ValueError"
    except ValueError:
        pass
    b = mod_inv(A, N)
    assert b == 6277101735386680763495507056286727952638980837032266301441
    assert b == 2**192 - 2**128 + 1 and A * b % N == 1


# ----------------------------- Part B -----------------------------
def test_B1_poly_arithmetic():
    assert poly_mul(0x57, 0x83) == 0x2B79
    assert poly_mulmod(0x57, 0x83, AES) == 0xC1          # FIPS-197 example
    assert poly_mulmod(0x57, 0x13, AES) == 0xFE          # FIPS-197 example
    assert poly_divmod(0x11B, 0x53) == (0x5, 0x4)
    for a in range(1, 300):
        for b in (0x3, 0x53, AES):
            q, r = poly_divmod(a, b)
            assert poly_mul(q, b) ^ r == a and r.bit_length() < b.bit_length()


def test_B2_poly_ext_euclid():
    assert poly_ext_euclid(0x53, AES) == (0x1, 0xCA, 0x3D)
    assert poly_ext_euclid(AES, 0x53) == (0x1, 0x3D, 0xCA)
    assert poly_ext_euclid(0x3, 0x101)[0] == 0x3          # gcd = x + 1
    for P in (AES, 0x101, GF512):                        # Bezout: a*x + P*y = d
        for a in range(1, 1 << (P.bit_length() - 1)):
            d, x, y = poly_ext_euclid(a, P)
            assert poly_mul(a, x) ^ poly_mul(P, y) == d


def test_B3_poly_inv():
    assert poly_inv(0x53, AES) == 0xCA
    assert poly_inv(0x01, AES) == 0x01
    for a in range(1, 256):
        assert poly_mulmod(a, poly_inv(a, AES), AES) == 1
    for a in (0x00, 0x03):                               # 0, and x+1 | x^8+1
        try:
            poly_inv(a, 0x101)
            assert False, "expected ValueError"
        except ValueError:
            pass
    b = poly_inv((1 << 64) + 1, GCM)
    assert b == 0xFE08629E8E4B766AFE08629E8E4B7617
    assert poly_mulmod((1 << 64) + 1, b, GCM) == 1


def test_B4_inverse_table():
    t = inverse_table(GF512)
    assert len(t) == 512 and t[0] == 0
    assert t[:4] == [0x000, 0x001, 0x108, 0x1F0] and t[0x100] == 0x023 and t[0x1FF] == 0x063
    assert sorted(t[1:]) == list(range(1, 512))          # a permutation
    for a in range(1, 512):
        assert t[t[a]] == a and poly_mulmod(a, t[a], GF512) == 1
    t8 = inverse_table(AES)
    assert t8[0x53] == 0xCA and sorted(t8[1:]) == list(range(1, 256))


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"{name:28s} PASSED")
