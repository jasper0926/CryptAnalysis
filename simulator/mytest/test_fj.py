# -*- coding: utf-8 -*-

import unittest

import simulator.aes as aes

from simulator.fj import Fault

from simulator.fj import inj_decrypt
from simulator.fj import inj_encrypt


class TestFj(unittest.TestCase):
    def setUp(self):
        self.plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        self.key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        self.sbox, self.invsbox = aes.genSBox()

    def tearDown(self):
        pass

    def test_gen_error(self):
        f = Fault(0, 9, 'sglbit')
        f.error = f.gen_error()
        x = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
        self.assertIn(f.error, x)

    def test_inj_encrypt(self):
        f = Fault(0, 9,  'sglbyte')
        f.error = f.gen_error()
        c_ciphertext = aes.Encryption(self.plaintext, self.key, self.sbox)
        f_ciphertext = inj_encrypt(self.plaintext, self.key, self.sbox, f, inj=True)
        c = (c_ciphertext == f_ciphertext)
        self.assertEqual(False, c)

    def test_inj_decrypt(self):
        f = Fault(0, 9,  'sglbit')
        f.error = f.gen_error()
        c_ciphertext = aes.Decryption(self.plaintext, self.key, self.sbox, self.invsbox)
        f_ciphertext = inj_decrypt(self.plaintext, self.key, self.sbox, self.invsbox, f, inj=True)
        c = (c_ciphertext == f_ciphertext)
        self.assertEqual(False, c)

if __name__ == "__main__":
    unittest.main()

