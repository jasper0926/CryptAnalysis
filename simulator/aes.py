# -*- coding: utf-8 -*-

import numpy as np


# function: SubByte
def SubByte(a, sbox):
    '''
    SubByte(a, sbox) : Return the AES SubByte result of a.
    :param a: a byte of AES State, represented by an object of numpy ndarray
    :param sbox: AES Sbox, represented by a 1-dimensional ndarray
    :return: SubByte result
    '''
    return sbox[a]

# function: InvSubByte
def InvSubByte(a, invsbox):
    '''
    SubByte(a, sbox) : Return the AES InvSubByte result of a.
    :param a: a byte of AES State, represented by an object of numpy ndarray
    :param invsbox: AES invSbox, represented by a 1-dimensional ndarray
    :return: InvSubByte result
    '''
    return invsbox[a]


# function: ShiftRow
#    state: 16byte vector
def ShiftRow(state):
    '''
    :param state:
    :return:
    '''
    trans = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    return state[trans]


def InvShiftRow(state):
    trans = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    return state[trans]


# function: MixColumn
def MixColumn(state):
    temp = np.zeros(16, dtype=np.uint8)
    for i in range(4):
        temp[4*i+0] = multi(state[4*i], 0x02) ^ multi(state[4*i+1], 0x03) ^ state[4*i+2] ^ state[4*i+3]
        temp[4*i+1] = state[4*i] ^ multi(state[4*i+1], 0x02) ^ multi(state[4*i+2], 0x03) ^ state[4*i+3]
        temp[4*i+2] = state[4*i] ^ state[4*i+1] ^ multi(state[4*i+2], 0x02) ^ multi(state[4*i+3], 0x03)
        temp[4*i+3] = multi(state[4*i], 0x03) ^ state[4*i+1] ^ state[4*i+2] ^ multi(state[4*i+3], 0x02)
    return temp


def InvMixColumn(state):
    temp = np.zeros(16, dtype=np.uint8)
    for i in range(4):
        temp[4*i+0] = multi(state[4*i], 0x0e) ^ multi(state[4*i+1], 0x0b) ^ multi(state[4*i+2], 0x0d) ^ multi(state[4*i+3], 0x09)
        temp[4*i+1] = multi(state[4*i], 0x09) ^ multi(state[4*i+1], 0x0e) ^ multi(state[4*i+2], 0x0b) ^ multi(state[4*i+3], 0x0d)
        temp[4*i+2] = multi(state[4*i], 0x0d) ^ multi(state[4*i+1], 0x09) ^ multi(state[4*i+2], 0x0e) ^ multi(state[4*i+3], 0x0b)
        temp[4*i+3] = multi(state[4*i], 0x0b) ^ multi(state[4*i+1], 0x0d) ^ multi(state[4*i+2], 0x09) ^ multi(state[4*i+3], 0x0e)
    return temp


# function: AddRoundKey
def AddRoundKey(a, b):
    return np.bitwise_xor(a, b)


# function: multi
#    return a numpy.ndarray object
def multi(a, b):

    res = np.array(0x00, dtype=np.uint8)
    for i in range(8):
        if b & 0x01:
            res = res ^ a
        if a & 0x80:
            a = np.left_shift(a, 1)
            a = a ^ 0x1B
        else:
            a = np.left_shift(a, 1)
        a = np.array(a, dtype=np.uint8)
        b = np.right_shift(b, 1)
        b = np.array(b, dtype=np.uint8)
    return res


# function: invMulti
#    get multiplicative inverse of parameter a
#    乘法逆元的求解采用的是穷举的方式……
def invMulti(a):

    res = np.array(0x01, dtype=np.uint8)
    for i in range(1, 256):
        if multi(i, a) == 1:
            break
    res = np.array(i, dtype=np.uint8)
    return res


# function: genSBox
#    generate SBox and InvSBox
def genSBox():
    sbox = np.zeros(256, dtype=np.uint8)
    invsbox = np.zeros(256, dtype=np.uint8)
    sbox[0] = 0x63
    invsbox[0x63] = 0
    for i in range(1, 256):
        temp = invMulti(i)
        sbox[i] = temp ^ (temp << 4 | temp >> 4) ^ (temp << 3 | temp >> 5) ^ (temp << 2 | temp >> 6) \
                  ^ (temp << 1 | temp >> 7) ^ 0x63
        invsbox[sbox[i]] = i

    sbox = np.array(sbox, dtype=np.uint8)
    invsbox = np.array(invsbox, dtype=np.uint8)
    return sbox, invsbox


# functions for key expansion
#    key —— 128bit/196bit/256bit ndarray向量
def keyExp(key, sbox, Nk=4, Nb=4, Nr=10):
    Rcon = __genRcon(Nr)
    w = np.zeros((Nb * (Nr + 1), Nk), dtype=np.uint8)
    for i in range(Nk):
        for j in range(4):
            w[i, j] = key[4*i+j]
    for i in range(Nk, Nb * (Nr+1)):
        temp = w[i-1, :]
        if (i % Nk == 0):
            # temp = SubWord(RotWord(temp), sbox)
            temp = np.bitwise_xor(__SubWord(__RotWord(temp), sbox), Rcon[i//Nk - 1, :])
        elif (Nk > 6 and i % Nk == 4):
            temp = __SubWord(temp)
        w[i, :] = w[i-Nk, :] ^ temp
    return w


def __RotWord(word):
    trans = [1, 2, 3, 0]
    return word[trans]


# function: SubWord
#
def __SubWord(word, sbox):
    return np.array([SubByte(t, sbox) for t in word], dtype=np.uint8)


# function: genRcon
#    Generate Rcon --- the round constant
def __genRcon(Nr):
    rcon = np.zeros((Nr, 4), dtype=np.uint8)
    rcon[0, 0] = 1
    for i in range(1, Nr):
        rcon[i, 0] = multi(rcon[i-1, 0], 2)
    return rcon


# function: Encryption
def Encryption(plaintext, key, sbox):
    state = np.array(plaintext, dtype=np.uint8)
    k = np.array(key, dtype=np.uint8)
    w = keyExp(k, sbox)

    state = AddRoundKey(state.reshape(4, 4), w[0:4,:]).reshape(16, )

    for round in range(9):
        for i in range(16):
            state[i] = SubByte(state[i], sbox)
        state = ShiftRow(state)
        state = MixColumn(state)
        state = AddRoundKey(state.reshape(4, 4), w[4*(round+1):4*(round+2),:]).reshape(16, )

    for i in range(16):
        state[i] = SubByte(state[i], sbox)
    state = ShiftRow(state)
    state = AddRoundKey(state.reshape(4, 4), w[40:44,:]).reshape(16, )
    return state.tolist()


# function:
def Decryption(ciphertext, key, sbox, invsbox):
    state = np.array(ciphertext, dtype=np.uint8)
    k = np.array(key, dtype=np.uint8)
    w = keyExp(k, sbox)

    state = AddRoundKey(state.reshape(4, 4), w[40:44, :]).reshape(16, )

    for round in range(10, 1, -1):
        state = InvShiftRow(state)
        for i in range(16):
            state[i] = InvSubByte(state[i], invsbox)
        state = AddRoundKey(state.reshape(4, 4), w[(round-1)*4: round*4, :]).reshape(16, )
        state = InvMixColumn(state)

    state = InvShiftRow(state)
    for i in range(16):
        state[i] = InvSubByte(state[i], invsbox)
    state = AddRoundKey(state.reshape(4, 4), w[0:4, :]).reshape(16, )
    return state.tolist()


if __name__ == "__main__":
    #plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    #key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
#
    sbox, invsbox = genSBox()
    #ciphertext = Encryption(plaintext, key, sbox)
#
    #after_dec = Decryption(ciphertext, key, sbox, invsbox)
#
    #for item in after_dec:
    #    print(hex(item))

    key = [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60]
    w = keyExp(key, sbox)
    print(w)

# test keyExp
    # key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    # sbox, invsbox = genSBox()
    # npkey = np.array(key, dtype=np.uint8)
    # w = keyExp(npkey, sbox=sbox)
    # for i in range(44):
    #     for j in range(4):
    #         print(hex(w[i, j]), end=' ')
    #     print("")

# test Encryption
    # f = open("result.txt", "w")
    # sbox, invsbox = genSBox()
    # plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
    # #print("plaintext", file = f)
    # #print(plaintext, file = f)
    # key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    # correct_result = Encryption(plaintext, key, sbox)
    # #print("ciphertext", file = f)
    # #print(correct_result.tolist(), file = f)
    # #print("fault_text", file = f)
    # #for i in range(1):
    # fault_result = Encryption(plaintext, key, sbox, 1)
    #     print(fault_result.tolist(), file = f)
##
##     #f.close()
##     x1 = correct_result[0]
##     x2 = correct_result[13]
##     x3 = correct_result[10]
##     x4 = correct_result[7]
##     fault_x1 = fault_result[0]
##     fault_x2 = fault_result[13]
##     fault_x3 = fault_result[10]
##     fault_x4 = fault_result[7]
##     res = []
##
##     for k2 in range(256):
##         for k1 in range(256):
##             if InvSubByte(x1 ^ k1, invsbox) ^ InvSubByte(fault_x1 ^ k1, invsbox) == \
##                     multi(2, InvSubByte(x2 ^ k2, invsbox) ^ InvSubByte(fault_x2 ^ k2, invsbox)):
##                 res.append((k2, k1))
##
##     res_2 = []
##     for k2 in range(256):
##         for k3 in range(256):
##             if InvSubByte(x2 ^ k2, invsbox) ^ InvSubByte(fault_x2 ^ k2, invsbox) == \
##                             InvSubByte(x3 ^ k3, invsbox) ^ InvSubByte(fault_x3 ^ k3, invsbox):
##                 res_2.append((k2, k3))
##
##     res_3 = []
##     for k2 in range(256):
##         for k4 in range(256):
##             if InvSubByte(x4 ^ k4, invsbox) ^ InvSubByte(fault_x4 ^ k4, invsbox) == \
##                     multi(3, InvSubByte(x2 ^ k2, invsbox) ^ InvSubByte(fault_x2 ^ k2, invsbox)):
##                 res_3.append((k2, k4))
##
##     print(res)
##     print(len(res))
##
##     print(res_2)
##     print(len(res_2))
##
##     print(res_3)
##     print(len(res_3))
##
##     list_1 = []
##     for i, j in res:
##         if i not in list_1:
##             list_1.append(i)
##     print(list_1)
##
##     list_2 = []
##     for i, j in res_2:
##         if i not in list_2:
##             list_2.append(i)
##
##     print(list_2)
##
##     list_3 = []
##     for i, j in res_3:
##         if i not in list_3:
##             list_3.append(i)
##     print(list_3)
##
##     c = list(set(list_1).intersection(list_2).intersection(list_3))
##     print(c)
##     print(len(c))