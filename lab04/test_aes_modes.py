"""Run with python -m unittest -v. Library modes are used only as test oracles."""

from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ecb import _aes_block, ecb_decrypt, ecb_encrypt, pad_10star, unpad_10star
from cbc import cbc_decrypt, cbc_encrypt, pad_pkcs5, unpad_pkcs5
from solve import DECRYPTORS, load_questions
from cfb import QUESTIONS as CFB_QUESTIONS, cfb_encrypt, cfb_decrypt
from ctr import QUESTIONS as CTR_QUESTIONS, ctr_encrypt, ctr_decrypt
from ofb import QUESTIONS as OFB_QUESTIONS, ofb_encrypt, ofb_decrypt


class AESModesTests(unittest.TestCase):
    def test_aes_known_answer(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(_aes_block(key, block), expected)
        self.assertEqual(_aes_block(key, expected, decrypt=True), block)

    def test_roundtrips_and_independent_oracles(self):
        for key_length in (16, 24, 32):
            key = bytes(range(key_length))
            for length in (*range(34), 47, 48, 49, 255, 256, 257):
                plaintext = bytes(i % 256 for i in range(length))
                with self.subTest(key_length=key_length, length=length):
                    ecb = ecb_encrypt(key, plaintext)
                    oracle = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
                    expected = oracle.update(pad_10star(plaintext)) + oracle.finalize()
                    self.assertEqual(ecb, expected)
                    self.assertEqual(ecb_decrypt(key, ecb), plaintext)
                    self.assertEqual(len(ecb), (length // 16 + 1) * 16)

                    cbc = cbc_encrypt(key, plaintext)
                    oracle = Cipher(algorithms.AES(key), modes.CBC(cbc[:16])).encryptor()
                    expected = oracle.update(pad_pkcs5(plaintext)) + oracle.finalize()
                    self.assertEqual(cbc[16:], expected)
                    self.assertEqual(cbc_decrypt(key, cbc), plaintext)
                    self.assertEqual(len(cbc), 16 + (length // 16 + 1) * 16)

    def test_padding_bytes_and_binary_suffixes(self):
        for missing in range(1, 17):
            plaintext = b'A' * (16 - missing)
            self.assertEqual(pad_10star(plaintext), plaintext + b'\x80' + b'\0' * (missing - 1))
            self.assertEqual(pad_pkcs5(plaintext), plaintext + bytes([missing]) * missing)
        for plaintext in (b'', b'\x80', b'\0' * 16, b'A' * 16, b'A\x80\0\x02\x02'):
            self.assertEqual(unpad_10star(pad_10star(plaintext)), plaintext)
            self.assertEqual(unpad_pkcs5(pad_pkcs5(plaintext)), plaintext)

    def test_reject_invalid_padding(self):
        invalid_ecb = (b'', b'A', b'\0' * 16, b'A' * 16,
                       b'\x80' + b'\0' * 31, b'A' * 14 + b'\x80\x01')
        invalid_cbc = (b'', b'A', b'\0' * 16, b'A' * 15 + b'\x11',
                       b'A' * 14 + b'\x01\x02', b'\x20' * 32)
        for unpad, invalid in ((unpad_10star, invalid_ecb), (unpad_pkcs5, invalid_cbc)):
            for data in invalid:
                with self.subTest(unpad=unpad.__name__, data=data):
                    with self.assertRaises(ValueError):
                        unpad(data)
        key = bytes(16)
        # Create ciphertexts that decrypt to known invalid padding.
        with self.assertRaises(ValueError):
            ecb_decrypt(key, _aes_block(key, bytes(16)))
        with self.assertRaises(ValueError):
            cbc_decrypt(key, bytes(16) + _aes_block(key, bytes(16)))

    def test_reject_invalid_lengths_and_keys(self):
        for decrypt, lengths in ((ecb_decrypt, (0, 1, 15, 17, 31)),
                                 (cbc_decrypt, (0, 1, 15, 16, 17, 31, 33))):
            for length in lengths:
                with self.subTest(decrypt=decrypt.__name__, length=length):
                    with self.assertRaises(ValueError):
                        decrypt(bytes(16), bytes(length))
        for key_length in (0, 15, 17, 23, 25, 31, 33):
            for encrypt in (ecb_encrypt, cbc_encrypt):
                with self.assertRaises(ValueError):
                    encrypt(bytes(key_length), b'hello')

    def test_cbc_requests_a_fresh_iv_on_every_encryption(self):
        iv1, iv2 = bytes(range(16)), bytes(range(16, 32))
        with patch('cbc.secrets.token_bytes', side_effect=(iv1, iv2)) as random_bytes:
            first = cbc_encrypt(bytes(16), b'same plaintext')
            second = cbc_encrypt(bytes(16), b'same plaintext')
        self.assertEqual(random_bytes.call_count, 2)
        self.assertEqual(random_bytes.call_args_list[0].args, (16,))
        self.assertEqual(first[:16], iv1)
        self.assertEqual(second[:16], iv2)
        self.assertNotEqual(first[16:], second[16:])

    def test_handout_questions(self):
        expected = [
            b'ECB is not safe.Really, I mean: ECB is not safe.',
            b'Tux is visible!',
            b'Transfer $1.00 from Oscar at bank A to bank B.',
            b'Basic CBC mode encryption needs padding.',
            b'Our implementation uses rand. IV',
            b'Never let a CBC IV be predictable to attackers.',
            b'Hello, SoICT!',
            b'OFB turns a block cipher into a synchronous stream cipher.',
            b'The OFB keystream never depends on the message.',
            b'In CFB mode each ciphertext block feeds the next block.',
            b'CFB recovers from a corrupted block after one more block.',
            b'CTR mode lets you build a stream cipher from a block cipher.',
            b'Always avoid the two time pad!',
            b'A counter is a full 128-bit integer, so every carry must propagate.',
            b'Counters wrap around modulo 2^128.',
        ]
        questions = list(load_questions(Path(__file__).with_name('lab04_questions.txt')))
        self.assertEqual([q[0] for q in questions], list(range(1, 16)))
        for number, mode, key, ciphertext in questions:
            decrypt = DECRYPTORS[mode]
            self.assertEqual(decrypt(key, ciphertext), expected[number - 1])
        ciphertext = questions[0][3]
        self.assertEqual(ciphertext[:16], ciphertext[32:48])

    def test_integrated_data_matches_existing_modules(self):
        questions = list(load_questions(Path(__file__).with_name('lab04_questions.txt')))
        for group in (OFB_QUESTIONS, CFB_QUESTIONS, CTR_QUESTIONS):
            for number, key_hex, ciphertext_hex in group:
                self.assertEqual(questions[number - 1][2], bytes.fromhex(key_hex))
                self.assertEqual(questions[number - 1][3], bytes.fromhex(ciphertext_hex))

    def test_stream_modes_against_independent_oracles(self):
        # Exercise partial blocks and counter carries/wrap, including all-ones IV.
        for encrypt, decrypt, library_mode in (
            (ofb_encrypt, ofb_decrypt, modes.OFB),
            (cfb_encrypt, cfb_decrypt, modes.CFB),
            (ctr_encrypt, ctr_decrypt, modes.CTR),
        ):
            for key_length in (16, 24, 32):
                key = bytes(range(key_length))
                for iv in (bytes(range(16)), bytes.fromhex('10adedeb5d4e5264fffffffffffffffd'),
                           b'\xff' * 16):
                    for length in (0, 1, 15, 16, 17, 31, 32, 33, 80):
                        with self.subTest(mode=encrypt.__name__, key_length=key_length,
                                          iv=iv.hex(), length=length):
                            plaintext = bytes(range(length))
                            ciphertext = encrypt(key, plaintext, iv)
                            oracle = Cipher(algorithms.AES(key), library_mode(iv)).encryptor()
                            expected = oracle.update(plaintext) + oracle.finalize()
                            self.assertEqual(ciphertext, iv + expected)
                            self.assertEqual(decrypt(key, ciphertext), plaintext)


if __name__ == '__main__':
    unittest.main()
