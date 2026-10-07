"""
Self-test for Task A1.  Run:   python3 check_vectors.py
It checks your trivium.py against the 84 official eSTREAM test vectors and
prints how many pass.  You are done when it prints  84/84 vectors OK.


The check is entirely offline: vectors.json holds the official key/IV inputs
and the expected key stream.  No reference implementation is provided --- the
vectors ARE the reference.
"""
import json, os, time
from trivium import keystream


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    V = json.load(open(os.path.join(here, 'vectors.json')))
    ok = 0; t0 = time.time(); first_fail = None
    for v in V:
        key, iv = bytes.fromhex(v['key']), bytes.fromhex(v['iv'])
        last = max(int(r.split('..')[1]) for r in v['stream']) + 1   # bytes needed
        try:
            ks = keystream(key, iv, last)
        except NotImplementedError as e:
            print("trivium.py is not finished yet:", e)
            print("Fill in the TODOs in trivium.py, then run this again.")
            return
        good = all(ks[int(a):int(b)+1].hex().upper() == h
                   for r, h in v['stream'].items() for a, b in [r.split('..')])
        # xor-digest: XOR of all 64-byte blocks of the whole stream
        d = bytearray(64)
        for i in range(0, last, 64):
            for j in range(64):
                d[j] ^= ks[i + j]
        good = good and d.hex().upper() == v['xor_digest']
        ok += good
        if not good and first_fail is None:
            first_fail = (v['set'], v['vector'])
    print(f"{ok}/{len(V)} vectors OK  ({time.time()-t0:.1f}s)")
    if ok == len(V):
        return
    print(f"first failing vector: set {first_fail[0]}, vector {first_fail[1]}")
    if ok == 0:
        print("Nothing matches. First run  python3 check_clock.py :")
        print("  - if it FAILS, fix the clock / state loading first;")
        print("  - if it PASSES, your cipher is right and the problem is the")
        print("    byte conventions. When NOTHING matches, look first at how you")
        print("    pack the output bits z_1, z_2, ... into bytes.")
    else:
        print("Some vectors pass, some fail: your clock and your output packing")
        print("are right. The failing vectors have keys/IVs that are not")
        print("symmetric, so look at how bytes_to_bits orders the key/IV bits.")
        print("Compare the key/IV of a passing vector with a failing one.")


if __name__ == '__main__':
    main()
