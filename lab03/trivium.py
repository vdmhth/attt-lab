"""
Trivium stream cipher --- Task A1 (fill in the TODOs).


Goal: make  python3 check_vectors.py  print  84/84 vectors OK.


Trivium keeps 288 state bits in three shift registers. We number them
s[1..288] exactly as in the official specification (s[0] is unused so the
indices match the paper). One "clock" does this:


    t1 = s[66]  XOR s[93]
    t2 = s[162] XOR s[177]
    t3 = s[243] XOR s[288]
    z  = t1 XOR t2 XOR t3                 # <- the output (key stream) bit
    t1 = t1 XOR (s[91]  AND s[92])  XOR s[171]
    t2 = t2 XOR (s[175] AND s[176]) XOR s[264]
    t3 = t3 XOR (s[286] AND s[287]) XOR s[69]
    shift A: (s[1..93])   <- (t3, s[1..92])
    shift B: (s[94..177]) <- (t1, s[94..176])
    shift C: (s[178..288])<- (t2, s[178..287])


Initialization: load the key into s[1..80], the IV into s[94..173], set
s[286]=s[287]=s[288]=1, everything else 0, then clock 1152 times WITHOUT
keeping any output. After that, every clock produces one key stream bit.


Specification (pseudocode is on page 1):
    https://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf


------------------------------------------------------------------------
THE ONE THING NOT WRITTEN IN THE SPEC: how the key/IV bytes and the key
stream bytes map to bits. The test vectors use a specific convention and
YOUR JOB in bytes_to_bits / bits_to_bytes is to find it. There are only a
few combinations; try them until check_vectors passes, then write down the
convention you found here:


    key/IV byte -> bits order : reverse byte order, MSB first within each byte
    key stream bits -> byte   : LSB first within each byte
------------------------------------------------------------------------
"""


def bytes_to_bits(b):
    """10 bytes (key or IV) -> list of 80 bits, in the order Trivium loads them."""
    # TODO: return a list of 80 zeros/ones built from the 10 bytes in `b`.
    # Hint: each byte has 8 bits; you must decide byte order and, inside a
    # byte, whether the most- or least-significant bit comes first.
    bits = []
    #LSB
    """for byte in b:
        for i in range(8):
            bits.append((byte >> i) & 1)"""
    #MSB: normal 29/84 -> thử reverse: 84/84
    for byte in reversed(b):
        for i in range(7,-1,-1):
            bits.append((byte >> i) & 1)
    return bits
    



def bits_to_bytes(bits):
    """Key stream bits z_1, z_2, ... -> bytes."""
    # TODO: pack the bits back into bytes (8 bits per byte). Must use the same
    # within-byte convention that makes the test vectors match.
    
    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        #MSB: LSB1+MSB2=0/84 OK
        """for bit in bits[i:i+8]:
            value = (value << 1) | bit"""
        #LSB: LSB1+LSB2=6/84 OK
        for j, bit in enumerate(bits[i:i+8]):
            value |= bit << j
        out.append(value)
    return bytes(out)



class Trivium:
    def __init__(self, key_bits, iv_bits, init_rounds=1152):
        assert len(key_bits) == 80 and len(iv_bits) == 80
        s = [0] * 289                     # s[0] unused; state is s[1..288]
        # TODO: load key into s[1..80], iv into s[94..173],
        #       set s[286]=s[287]=s[288]=1, leave the rest 0.
        s[1:81]=key_bits
        s[94:174]=iv_bits
        s[286]=s[287]=s[288]=1

        self.s = s
        for _ in range(init_rounds):      # warm-up: 1152 clocks, no output kept
            self._clock()


    def _clock(self):
        s = self.s
        # TODO: implement one clock exactly as in the docstring, and return z.
        t1=s[66]^s[93]
        t2=s[162]^s[177]
        t3=s[243]^s[288]
        z=t1^t2^t3
        t1=t1^(s[91]&s[92])^s[171]
        t2=t2^(s[175]&s[176])^s[264]
        t3=t3^(s[286]&s[287])^s[69]
        s[2:94]=s[1:93]
        s[1]=t3
        s[95:178]=s[94:177]
        s[94]=t1
        s[179:289]=s[178:288]
        s[178]=t2
        return z


    def keystream_bits(self, n):
        """Return the next n key stream bits."""
        return [self._clock() for _ in range(n)]




def keystream(key: bytes, iv: bytes, nbytes: int) -> bytes:
    """Convenience wrapper used by check_vectors.py and Task A2."""
    t = Trivium(bytes_to_bits(key), bytes_to_bits(iv))
    return bits_to_bytes(t.keystream_bits(8 * nbytes))
