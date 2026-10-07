"""
Task A3 --- watch diffusion appear as the warm-up grows (avalanche test).

Full Trivium clocks 1152 times before it emits any key stream. Why so many?
A good cipher must make EVERY output bit depend on EVERY key/IV bit: flipping
a single IV bit should change about half of the output bits (the "avalanche
effect"). Right after loading, that is not yet the case.

Experiment: for a warm-up of R rounds,
  1. pick a random key and IV, take the first 64 output bits;
  2. flip ONE IV bit (the first one), take the first 64 output bits again;
  3. count how many of the 64 bits differ.
Average the fraction of changed bits over many random (key, IV) pairs.

An ideal cipher gives 0.5. Fill in avalanche(R) below, then run:
    python3 reduced_rounds.py
It prints a table and (if matplotlib is installed) saves reduced_rounds.png.

Questions for your report:
  * What is the value at R = 0? Explain it from the structure of Trivium.
  * Around which R does the curve reach about 0.5?
  * The designers chose 1152 rounds. What does your curve say about the
    safety margin? (Attacks on reduced-round Trivium work in the region where
    the curve has NOT yet fully settled in a way that simple tests can see.)
"""
import os
from trivium import Trivium, bytes_to_bits

def avalanche(R, n_pairs=100, n_bits=64):
    """Average fraction of the first n_bits output bits that change when the
    first IV bit is flipped, for Trivium warmed up only R rounds."""
    changed = 0
    for _ in range(n_pairs):
        key = bytes_to_bits(os.urandom(10))
        iv  = bytes_to_bits(os.urandom(10))
        iv2 = iv[:]
        iv2[0] ^= 1                         # flip one IV bit
        # TODO: out1 = first n_bits output bits of Trivium(key, iv,  init_rounds=R)
        #       out2 = first n_bits output bits of Trivium(key, iv2, init_rounds=R)
        #       changed += number of positions where out1 and out2 differ

        out1 = Trivium(key, iv, init_rounds=R).keystream_bits(n_bits)
        out2 = Trivium(key, iv2, init_rounds=R).keystream_bits(n_bits)
        changed += sum (a != b for a, b in zip(out1, out2))
    return changed / (n_pairs * n_bits)

def main():
    Rs = [0, 50, 100, 150, 200, 250, 300, 350, 400, 500, 600, 800, 1152]
    vals = []
    print(f"{'R':>6}  {'fraction changed':>16}")
    for R in Rs:
        a = avalanche(R)
        vals.append(a)
        print(f"{R:>6}  {a:>16.3f}")
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        plt.axhline(0.5, color='gray', ls='--', lw=1, label='ideal (0.5)')
        plt.plot(Rs, vals, 'o-', label='Trivium')
        plt.xlabel('initialization rounds R')
        plt.ylabel('fraction of output bits changed')
        plt.title('Avalanche: flipping one IV bit')
        plt.legend()
        plt.savefig('reduced_rounds.png', dpi=120, bbox_inches='tight')
        print("saved reduced_rounds.png")
    except ImportError:
        print("(install matplotlib to also get a plot)")

if __name__ == '__main__':
    main()
