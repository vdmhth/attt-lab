"""Print the plaintexts for Questions 1-15 from the lab handout."""

import argparse
from pathlib import Path

from cbc import cbc_decrypt
from ecb import BLOCK_SIZE, ecb_decrypt
from cfb import cfb_decrypt
from ctr import ctr_decrypt
from ofb import ofb_decrypt

DECRYPTORS = {
    "ECB": ecb_decrypt,
    "CBC": cbc_decrypt,
    "OFB": ofb_decrypt,
    "CFB": cfb_decrypt,
    "CTR": ctr_decrypt,
}


def load_questions(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        number, mode, key_hex, ciphertext_hex = line.split()
        yield int(number), mode, bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex)


def solve_questions(path: Path, mode_filter: str | None = None) -> None:
    for number, mode, key, ciphertext in load_questions(path):
        if mode_filter is not None and mode != mode_filter:
            continue
        decrypt = DECRYPTORS[mode]
        plaintext = decrypt(key, ciphertext)
        print(f"Question {number} ({mode}): {plaintext.decode('utf-8')}")
        if number == 1:
            y0 = ciphertext[:BLOCK_SIZE]
            y2 = ciphertext[2 * BLOCK_SIZE:3 * BLOCK_SIZE]
            print(f"  y0 = {y0.hex()}")
            print(f"  y2 = {y2.hex()}")
            print(f"  y0 == y2: {y0 == y2}; equal plaintext blocks give equal ECB blocks.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path,
                        default=Path(__file__).with_name("lab04_questions.txt"),
                        help="Question file: number mode key_hex ciphertext_hex")
    parser.add_argument("--mode", choices=DECRYPTORS, help="Solve only this mode")
    args = parser.parse_args()
    solve_questions(args.file, args.mode)


if __name__ == "__main__":
    main()
