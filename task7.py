cpts=[
    '3d5cae3331120fe78d2359b8998d846d5230dc78741f3880d0e36e3fb4659796', #64: 32 hexa: 32 byte
    '4a5841c015c4e29f25bbdcb0f946993cd2af3984176325a9688ab8ab6d07dfda',
    'f2f680eee88923ccc31738ce4c3c9962a5b92873b3064e64a69054def9c71331',
]

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
def output_byte(n,seed,taps):
    byte=0
    for i in range(8):
        output,seed=output_bit(n,seed,taps)
        byte|=output<<i #bit thứ i ở vị trí i
    return byte,seed

key=[-1 for i in range(8)]
n=32 #seed 32 bit=4 byte

start="From: ex" #8 byte
start_message=[ord(c) for c in start]
cpt=cpts[0]
#pt[i:i+2]=cpt[i:i+2]^key[int(i/2)]
for i in range(0,16,2): #chỉ xét 8 chữ đầu
    key[int(i/2)]=f"{int(cpt[i:i+2],16)^start_message[int(i/2)]:08b}"
#key là 76543210: 8 output bit của seed
#4 key đầu là 32 bit của seed
init_seed=key[3]+key[2]+key[1]+key[0]
init_seed=int(init_seed,2) #convert string nhị phân về số thập phân
print(f"Seed: {init_seed:04x}") #có 32 bit nên sẽ có 4 bytes

#message recover using taps
n=32
taps=[0,10,30,31]
message=[[-1 for j in range(32)] for i in range(3)]
seed=init_seed
full_message=''
for j in range(3):
    cpt=cpts[j]
    for i in range(0,64,2):
        k,seed=output_byte(n,seed,taps)
        message[j][int(i/2)]=chr(int(cpt[i:i+2],16)^k)
    full_message+=''.join(message[j])
    print(f"Message {j+1}: ")
    print(f"{''.join(message[j])}")
print(f"Full message:\n{full_message}")