"""IT4010E - Lab 07: RSA Decryption with the CRT"""
import json
import time
from pathlib import Path

DATA_FILE = Path(__file__).with_name("lab07_testdata.json")


def load_keys(path: str | Path = DATA_FILE) -> dict:
    with open(path) as f:
        return {k["name"]: k for k in json.load(f)["keys"]}


# ---------- Task 1 ----------
def rsa_decrypt(y: int, d: int, n: int) -> int:
    """Standard RSA decryption: y^d mod n."""
    return pow(y,d,n)


# ---------- Task 2 ----------
def crt_precompute(d: int, p: int, q: int) -> tuple[int, int, int, int]:
    """Return (dp, dq, cp, cq)."""
    dp=d%(p-1)
    dq=d%(q-1)
    cp=pow(q,-1,p)
    cq=pow(p,-1,q)
    return dp,dq,cp,cq


def rsa_decrypt_crt(y: int, d: int, p: int, q: int, pre=None) -> int:
    """RSA decryption using the CRT."""
    if pre is None:
        pre = crt_precompute(d, p, q)
    # Step 1: transformation to the CRT domain
    # Step 2: exponentiation in the CRT domain
    # Step 3: inverse transformation (recombination)
    dp,dq,cp,cq=pre
    yp=y%p
    yq=y%q
    xp=pow(yp,dp,p)
    xq=pow(yq,dq,q)
    n=p*q
    x=((q*cp)*xp+(p*cq)*xq)%n
    return x

def test_toy(keys: dict) -> None:
    k=keys["toy-143"]
    y=15

    p=k["p"]
    q=k["q"]
    d=k["d"]

    dp,dq,cp,cq=crt_precompute(d,p,q)

    yp=y%p
    yq=y%q

    xp=pow(yp,dp,p)
    xq=pow(yq,dq,q)

    x=((q*cp)*xp+(p*cq)*xq)%(p*q)

    print("toy-143")
    print("yp =",yp)
    print("yq =",yq)
    print("dp =",dp)
    print("dq =",dq)
    print("xp =",xp)
    print("xq =",xq)
    print("cp =",cp)
    print("cq =",cq)
    print("x =",x)

# ---------- Task 3 ----------
def test_given(keys: dict) -> None:
    k = keys["given-190"]
    y = k["vectors"][0]["y"]
    x1 = rsa_decrypt(y, k["d"], k["n"])
    x2 = rsa_decrypt_crt(y, k["d"], k["p"], k["q"])
    print("x (standard) =", x1)
    print("x (CRT)      =", x2)
    print("check x^e mod n == y:", pow(x2, k["e"], k["n"]) == y)


def test_all(keys: dict) -> None:
    for name, k in keys.items():
        n, d, p, q = k["n"], k["d"], k["p"], k["q"]
        c = k["crt"]
        pre = crt_precompute(d, p, q)
        assert pre == (c["dp"], c["dq"], c["cp"], c["cq"]), name
        ok = 0
        for v in k["vectors"]:
            if (rsa_decrypt(v["y"], d, n) == v["x"]
                    and rsa_decrypt_crt(v["y"], d, p, q, pre) == v["x"]):
                ok += 1
            else:
                print(f"  FAIL {name}: {v['label']}")
        print(f"{name}: {ok}/{len(k['vectors'])} vectors OK")


# ---------- Task 4 ----------
def benchmark(keys: dict, repeat: int = 10) -> list[dict]:
    results = []
    for name in ("rsa-1024", "rsa-2048", "rsa-4096"):
        k = keys[name]
        vectors = k["vectors"]
        total_ops = len(vectors) * repeat

        start = time.perf_counter()
        for _ in range(repeat):
            for v in vectors:
                rsa_decrypt(v["y"], k["d"], k["n"])
        standard_ms = (time.perf_counter() - start) * 1000.0 / total_ops

        pre = crt_precompute(k["d"], k["p"], k["q"])
        start = time.perf_counter()
        for _ in range(repeat):
            for v in vectors:
                rsa_decrypt_crt(v["y"], k["d"], k["p"], k["q"], pre)
        crt_ms = (time.perf_counter() - start) * 1000.0 / total_ops

        speedup = standard_ms / crt_ms if crt_ms else float("inf")
        result = {
            "key": name,
            "bits": k["bits"],
            "standard_ms": standard_ms,
            "crt_ms": crt_ms,
            "speedup": speedup,
        }
        results.append(result)

    print("\nTask 4: execution time comparison")
    print(f"{'Key size':>8} {'Standard (ms)':>16} {'CRT (ms)':>12} {'Speed-up':>10}")
    
    for r in results:
        print(f"{r['bits']:>8} {r['standard_ms']:>15.3f} {r['crt_ms']:>12.3f} {r['speedup']:>9.2f}x")
    return results


if __name__ == "__main__":
    keys = load_keys()
    #Task 2
    test_toy(keys)
    #Task 3
    test_given(keys)
    test_all(keys)
    #Task 4
    benchmark(keys)