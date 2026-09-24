n=4
seed=0b1001
taps=[0,1]
def output_bit(n,seed,taps,printed=None):
    output = seed & 1 #and với 0...01 thì sẽ trả về 0...0x: rightmost bit
    if printed==True:
        print(output)
    feedback=0
    for tap in taps:
        feedback^=(seed>>tap)&1 #xor với bit ở vị trí tap
    seed>>=1 #shift right 1 bit
    seed|=feedback<<(n - 1) #đưa feedback tới vị trí n-1 (leftmost bit)
    return output,seed
print("1. First 16 output bits:")
cnt=0
while(cnt<16):
    _,seed=output_bit(n,seed,taps,printed=True)
    cnt+=1
print("2. Number of steps:")
def times_to_seed(n,init_seed,taps):
    _,seed=output_bit(n,init_seed,taps)
    cnt=1
    while(seed!=init_seed):
        _,seed=output_bit(n,seed,taps)
        cnt+=1
    return cnt
print("n=4, taps=[0,1], seed=1001: ",times_to_seed(4,0b1001,[0,1]))
print("n=16, taps=[0,2,3,5], seed=1: ",times_to_seed(16,1,[0,2,3,5]))
print("n=16, taps=[0,8], seed=1: ",times_to_seed(16,1,[0,8]))

import random
n=32
taps=[0,10,30,31]
init_seed=random.randint(1,2**32-1)
message="From: exam-office@example.edu\nSubject: final exam\nRoom B1-401, 8:00 on Monday."
#8 output bit 1 byte: 7 6 5 4 3 2 1 0
def output_byte(n,seed,taps):
    byte=0
    for i in range(8):
        output,seed=output_bit(n,seed,taps)
        byte|=output<<i #bit thứ i ở vị trí i
    return byte,seed
seed=init_seed
cpt=[]
for c in message:
    key,seed=output_byte(n,seed,taps)
    cpt.append(f"{ord(c)^key:02x}")
cpt=''.join(cpt)
print("3. Seed: ", f"{init_seed:032b}")
print("Ciphertext in hex: ",cpt)

seed=init_seed
no1=0
for _ in range(64*1024):
    obyte,seed=output_byte(n,seed,taps)
    no1+=obyte.bit_count()
frac=no1/(64*1024*8)
print("Fraction of 1-bits in 64KiB: ",frac)