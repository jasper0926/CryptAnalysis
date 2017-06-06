#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import random

from . imoport aes


class Fault:
    def __init__(self, loc, time, type):
        self.loc = loc
        self.time = time - 1
        self.type = type
        self.error = None
        return

    # def genError(self, x, xp):
    #     assert(len(x) == len(xp))
    #     dis = stats.rv_discrete(values=(x, xp))
    #     error = dis.rvs(size=1)
    #     return error

    def gen_error(self, dist=None):
        if self.type is "sglbit":
            x = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
            if dist is None:
                error = random.sample(x, 1)
            else:
                error = random.sample(x, dist)
        else:
            if dist is None:
                error = np.random.randint(0, 255, 1, np.uint8)
            else:
                error = random.sample(range(0, 256))

        error = np.array(error, dtype=np.uint8).tolist()
        return error[0]


def inj_encrypt(plaintext, key, sbox, fault, inj):
    state = np.array(plaintext, dtype=np.uint8)
    k = np.array(key, dtype=np.uint8)
    w = aes.keyExp(k, sbox)

    state = aes.AddRoundKey(state.reshape(4, 4), w[0:4, :]).reshape(16, )

    for round in range(9):
        if inj is True and round == fault.time:
            state[fault.loc] = state[fault.loc] ^ fault.error
        for i in range(16):
            state[i] = aes.SubByte(state[i], sbox)
        state = aes.ShiftRow(state)
        state = aes.MixColumn(state)
        state = aes.AddRoundKey(state.reshape(4, 4), w[4*(round+1):4*(round+2),:]).reshape(16, )

    for i in range(16):
        state[i] = aes.SubByte(state[i], sbox)
    state = aes.ShiftRow(state)
    state = aes.AddRoundKey(state.reshape(4, 4), w[40:44, :]).reshape(16, )
    return state.tolist()


def inj_decrypt(ciphertext, key, sbox, invsbox, fault, inj):
    state = np.array(ciphertext, dtype=np.uint8)
    k = np.array(key, dtype=np.uint8)
    w = aes.keyExp(k, sbox)

    state = aes.AddRoundKey(state.reshape(4, 4), w[40:44, :]).reshape(16, )

    for round in range(10, 1, -1):
        if round == fault.time + 1 and inj is True:
            state[fault.loc] = state[fault.loc] ^ fault.error

        state = aes.InvShiftRow(state)
        for i in range(16):
            state[i] = aes.InvSubByte(state[i], invsbox)
        state = aes.AddRoundKey(state.reshape(4, 4), w[(round-1)*4: round*4, :]).reshape(16, )
        state = aes.InvMixColumn(state)

    state = aes.InvShiftRow(state)
    for i in range(16):
        state[i] = aes.InvSubByte(state[i], invsbox)
    state = aes.AddRoundKey(state.reshape(4, 4), w[0:4, :]).reshape(16, )
    return state.tolist()


