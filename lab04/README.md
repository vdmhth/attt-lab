# Lab 04: Modes of Operation

## Requirements

- Python 3.10 or newer
- Dependencies listed in `requirements.txt`: `cryptography` and `pycryptodome`

## Install and run

Open a terminal in the extracted submission folder containing `solve.py`, then run:

```powershell
python -m pip install -r requirements.txt
python solve.py
```

`solve.py` reads `lab04_questions.txt` and prints all 15 plaintexts in question
order. For Question 1, it also compares ciphertext blocks `y0` and `y2`.
A saved copy of the output is included in `answers.txt`.

To solve only one mode:

```powershell
python solve.py --mode ECB
python solve.py --mode CBC
python solve.py --mode OFB
python solve.py --mode CFB
python solve.py --mode CTR
```

Each mode can also be run directly: `python ecb.py`, `python cbc.py`,
`python ofb.py`, `python cfb.py`, or `python ctr.py`.

To use another question file with the same format:

```powershell
python solve.py --file lab04_questions.txt
```

## Input format

Each non-comment line in `lab04_questions.txt` contains four whitespace-separated fields:

```text
number mode key_hex ciphertext_hex
```

## Implementation

- `ecb.py`: manual ECB and `10…0` padding (`0x80` followed by zero bytes).
- `cbc.py`: manual CBC and PKCS5 padding as defined in the handout
  (PKCS#7 for AES's 16-byte blocks).
- `ofb.py`, `cfb.py`, `ctr.py`: manual feedback/counter processing without padding.
- `solve.py`: input loading, mode selection, and plaintext output.



