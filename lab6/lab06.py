import pandas as pd


def extended_euclid(a, b):
    old_r,r=a,b
    old_x,x=1,0
    old_y,y=0,1
    while r!=0:
        q=old_r//r
        old_r,r=r,old_r%r
        old_x,x=x,old_x-q*x
        old_y,y=y,old_y-q*y
    return old_r,old_x,old_y


def mod_inv(a, n):
    d, x, y = extended_euclid(a, n)
    if d != 1:
        raise ValueError(f"{a} has no inverse mod {n}")
    return x%n


def poly_mul(a,b):
    res=0
    while b!=0:
        if b&1:
            res^=a
        a<<=1
        b>>=1
    return res


def poly_divmod(a,b):
    if b==0:
        raise ZeroDivisionError("polynomial division by zero")
    q=0
    while a!=0 and a.bit_length()>=b.bit_length():
        shift=a.bit_length()-b.bit_length()
        q^=1<<shift
        a^=b<<shift
    return q,a


def poly_mulmod(a,b,p):
    mul=poly_mul(a,b)
    q,r=poly_divmod(mul,p)
    return r


def poly_ext_euclid(a,b):
    old_r,r=a,b
    old_x,x=1,0
    old_y,y=0,1
    while r!=0:
        q,new_r=poly_divmod(old_r,r)
        old_r,r=r,new_r
        old_x,x=x,old_x^poly_mul(q,x)
        old_y,y=y,old_y^poly_mul(q,y)
    return old_r,old_x,old_y


def poly_inv(a,p):
    d,x,y=poly_ext_euclid(a,p)
    if d!=1:
        raise ValueError(f"{hex(a)} has no inverse mod {hex(p)}")
    q,r=poly_divmod(x,p)
    return r


def inverse_table(p):
    n=1<<(p.bit_length()-1)
    table=[0]*n
    for i in range(1,n):
        table[i]=poly_inv(i,p)
    return table


def extended_table(a,b):
    rows=[]
    cur_a=a
    cur_b=b
    while cur_b!=0:
        q=cur_a//cur_b
        d,x,y=extended_euclid(cur_a,cur_b)
        rows.append([cur_a,cur_b,q,d,x,y])
        cur_a,cur_b=cur_b,cur_a%cur_b
    d,x,y=extended_euclid(cur_a,cur_b)
    rows.append([cur_a,cur_b,"-",d,x,y])
    return pd.DataFrame(rows,columns=["a","b","q","d","x","y"])


def poly_extended_table(a,b):
    rows=[]
    cur_a=a
    cur_b=b
    while cur_b!=0:
        q,r=poly_divmod(cur_a,cur_b)
        d,x,y=poly_ext_euclid(cur_a,cur_b)
        rows.append([hex(cur_a),hex(cur_b),hex(q),hex(d),hex(x),hex(y)])
        cur_a,cur_b=cur_b,r
    d,x,y=poly_ext_euclid(cur_a,cur_b)
    rows.append([hex(cur_a),hex(cur_b),"-",hex(d),hex(x),hex(y)])
    return pd.DataFrame(rows,columns=["a","b","q","d","x","y"])


def inverse_grid(p):
    table=inverse_table(p)
    width=3 if len(table)>256 else 2
    rows=[]
    for i in range(0,len(table),16):
        rows.append([f"{x:0{width}X}" for x in table[i:i+16]])
    index=[f"{i:X}" for i in range(len(rows))]
    columns=[f"{i:X}" for i in range(16)]
    return pd.DataFrame(rows,index=index,columns=columns)


def check_all_inverses(p):
    table=inverse_table(p)
    failed=[]
    for a in range(1,len(table)):
        if poly_mulmod(a,table[a],p)!=1:
            failed.append(a)
    return len(failed)==0,failed


def check_inverse_twice(p):
    table=inverse_table(p)
    failed=[]
    for a in range(1,len(table)):
        inv=table[a]
        if table[inv]!=a:
            failed.append(a)
    return len(failed)==0,failed


if __name__ == "__main__":
    print("A1")
    print(extended_table(5,12).to_string(index=False))

    print("\nA2")
    a=2**128+1
    n=2**192
    print(mod_inv(a,n))

    print("\nB1")
    print("poly_mul(0x57,0x83) =",hex(poly_mul(0x57,0x83)))
    print("poly_mulmod(0x57,0x83,0x11B) =",hex(poly_mulmod(0x57,0x83,0x11B)))
    print("poly_divmod(0x11B,0x53) =",tuple(hex(x) for x in poly_divmod(0x11B,0x53)))

    print("\nB2")
    print(poly_extended_table(0x53,0x11B).to_string(index=False))

    print("\nB3")
    print("poly_inv(0x53,0x11B) =",hex(poly_inv(0x53,0x11B)))
    try:
        print("poly_inv(0x3,0x101) =",hex(poly_inv(0x3,0x101)))
    except ValueError:
        print("poly_inv(0x3,0x101) = none")
    p128=(1<<128)|0x87
    print("128-bit inverse =",hex(poly_inv((1<<64)|1,p128)))
    valid,failed=check_all_inverses(0x11B)
    print("all non-zero a satisfy a*a^-1 mod 0x11B = 1:",valid)
    if not valid:
        print("failed:",[hex(x) for x in failed])

    print("\nB4 GF(2^9)")
    print(inverse_grid(0x211).to_string())
    valid,failed=check_inverse_twice(0x211)
    print("inverse twice gives back a:",valid)
    if not valid:
        print("failed:",[hex(x) for x in failed])

    print("\nB4 GF(2^8)")
    print(inverse_grid(0x11B).to_string())
    valid,failed=check_inverse_twice(0x11B)
    print("inverse twice gives back a:",valid)
    if not valid:
        print("failed:",[hex(x) for x in failed])

    print("\nP1")
    for a,b in [(240,46),(1071,462),(99,78),(17,3120)]:
        print("\n",a,b)
        print(extended_table(a,b).to_string(index=False))

    print("\nP2")
    rows=[]
    for a,n in [(7,40),(17,3120),(6,9),(65537,2**64),(2**64+13,2**127-1)]:
        try:
            inv=mod_inv(a,n)
        except ValueError:
            inv="none"
        rows.append([a,n,inv])
    print(pd.DataFrame(rows,columns=["a","n","a^-1 mod n"]).to_string(index=False))

    print("\nP3")
    rows=[
        ["poly_mul(0x1B,0x35)",hex(poly_mul(0x1B,0x35))],
        ["poly_mul(0xFF,0xFF)",hex(poly_mul(0xFF,0xFF))],
        ["poly_mulmod(0x02,0x87,0x11B)",hex(poly_mulmod(0x02,0x87,0x11B))],
        ["poly_mulmod(0xCA,0x53,0x11B)",hex(poly_mulmod(0xCA,0x53,0x11B))],
        ["poly_mulmod(0x1FF,0x100,0x211)",hex(poly_mulmod(0x1FF,0x100,0x211))],
        ["poly_divmod(0x1234,0x11B)",tuple(hex(x) for x in poly_divmod(0x1234,0x11B))],
        ["poly_divmod(0xFFFF,0x211)",tuple(hex(x) for x in poly_divmod(0xFFFF,0x211))]
    ]
    print(pd.DataFrame(rows,columns=["Call","Result"]).to_string(index=False))
    print("0xCA is the multiplicative inverse of 0x53 modulo 0x11B because their product modulo 0x11B is 1.")

    print("\nP4")
    print(poly_extended_table(0x95,0x11B).to_string(index=False))
    print()
    print(poly_extended_table(0x1FF,0x211).to_string(index=False))

    print("\nP5")
    rows=[]
    cases=[(0x11B,0x02),(0x11B,0x03),(0x11B,0x95),(0x11B,0xFF),(0x211,0x0F0),(0x211,0x123),(0x101,0x02),(0x101,0x05),((1<<128)|0x87,0x02)]
    for p,a in cases:
        try:
            inv=hex(poly_inv(a,p))
        except ValueError:
            inv="none"
        rows.append([hex(p),hex(a),inv])
    print(pd.DataFrame(rows,columns=["P","a","a^-1 mod P"]).to_string(index=False))

    print("\nP6")
    table9=inverse_table(0x211)
    table8=inverse_table(0x11B)
    rows=[]
    for a in [0x0AB,0x0FF,0x155,0x1A0]:
        rows.append(["GF(2^9)",hex(a),hex(table9[a])])
    for a in [0x10,0xC6]:
        rows.append(["GF(2^8)",hex(a),hex(table8[a])])
    print(pd.DataFrame(rows,columns=["Field","a","a^-1"]).to_string(index=False))
