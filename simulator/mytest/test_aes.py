# -*- coding: utf-8 -*-

import unittest

import simulator.aes as aes


class TestAES(unittest.TestCase):
    def setUp(self):
        self.plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        self.key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        self.ciphertext = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
        self.sbox, self.invsbox = aes.genSBox()

    def test_Encrypt(self):
        ciphertext = aes.Encryption(self.plaintext, self.key, self.sbox)
        res = (ciphertext == self.ciphertext)
        self.assertEqual(True, res)

    def test_Decrypt(self):
        plaintext = aes.Decryption(self.ciphertext, self.key, self.sbox, self.invsbox)
        res = (plaintext == self.plaintext)
        self.assertEqual(True, res)


if __name__ == "__main__":
    unittest.main()

