# Lab 04: Modes of Operation

Manual implementation of AES encryption and decryption in ECB, CBC, OFB,
CFB (128-bit feedback), and CTR modes. The program prints the plaintexts
for Questions 1–15 from the lab handout.

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

Keys and ciphertexts are hex encoded. Ciphertext lines from the PDF have
already been concatenated. For CBC, OFB, CFB, and CTR, the first 16 bytes of
the decoded ciphertext are the IV. ECB has no IV. Reading the PDF is not
required at runtime.

## Implementation

- `ecb.py`: manual ECB and `10…0` padding (`0x80` followed by zero bytes).
- `cbc.py`: manual CBC and PKCS5 padding as defined in the handout
  (PKCS#7 for AES's 16-byte blocks).
- `ofb.py`, `cfb.py`, `ctr.py`: manual feedback/counter processing without padding.
- `solve.py`: input loading, mode selection, and plaintext output.
- `test_aes_modes.py`: correctness tests.

All five modes and both padding schemes are implemented by hand. Libraries
are used only for single-block AES in the implementation. The ECB API inside
the block helpers processes exactly one 16-byte block per call. Built-in
message modes are used only in the tests as independent reference results.

ECB/CBC always add padding, including a full padding block when the plaintext
is already block aligned, and reject invalid padding during decryption.
Non-ECB encryption generates a random 16-byte IV by default and prepends it
to the ciphertext. CTR uses a 128-bit big-endian counter modulo 2^128.

## Run tests

```powershell
python -m unittest -v
```

Tests cover all 15 answers, encryption/decryption, padding validation,
partial blocks, IV handling, and counter carry/wraparound.

## Submission

Include the five mode modules, `solve.py`, `lab04_questions.txt`,
`requirements.txt`, and this README in `GroupXX_Lab04.zip`, where `XX` is the
group number. The tests and saved output may also be included.
