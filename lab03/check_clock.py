"""
Bit-level self-test of your Trivium CLOCK (Task A1, step 1).
    python3 check_clock.py


This test does not use bytes at all: keys, IVs and outputs are given directly as
lists of bits (K_1..K_80, IV_1..IV_80, z_1..z_64). So it checks only the state
loading and the clock, independent of any byte/bit convention.


Once this passes, your cipher is correct and only the byte conventions remain;
then run check_vectors.py.
"""
from trivium import Trivium


CASES = [
    ("key = all 0, IV = all 0", [0]*80, [0]*80,
     "1101111100000111111111010110010000011010100110101010000011011000"),
    ("key bit K_1 = 1, rest 0; IV = all 0", [1] + [0]*79, [0]*80,
     "1011101010010010011101001110111000011111011111110100011011101011"),
    ("key = all 0; IV bit IV_80 = 1, rest 0", [0]*80, [0]*79 + [1],
     "1100000101011010001001001000001011011001011010010000000001011001"),
]


def main():
    ok = 0
    for name, key, iv, expected in CASES:
        try:
            got = "".join(map(str, Trivium(key, iv).keystream_bits(64)))
        except NotImplementedError as e:
            print("trivium.py is not finished yet:", e); return
        good = got == expected
        ok += good
        print(("OK   " if good else "FAIL ") + name)
        if not good:
            first = next(i for i in range(64) if got[i] != expected[i])
            print(f"     expected z_1..z_64 = {expected}")
            print(f"     yours              = {got}")
            print(f"     first difference at z_{first + 1}")
    print(f"{ok}/{len(CASES)} clock tests OK")
    if ok == len(CASES):
        print("Your clock is correct. Next: python3 check_vectors.py")
    elif ok == 0:
        print("Hint: check the taps, the AND terms and the three shifts.")
    else:
        print("Hint: the all-zero case works, so the clock itself is probably fine;"
              " check WHERE the key and IV bits are loaded into the state.")


if __name__ == "__main__":
    main()
