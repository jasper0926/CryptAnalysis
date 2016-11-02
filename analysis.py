#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import getopt
import sys
import json

import simulator.aes as aes


def parse_data(dic):
    ciphertext = dic['ciphertext']
    plaintext = dic['plaintext']
    result = dic['result']
    return ciphertext, plaintext, result


def key_space_reduction(result, ciphertext):

    sbox, invsbox = aes.genSBox()

    s1 = ciphertext[0]
    s2 = ciphertext[13]
    s3 = ciphertext[10]
    s4 = ciphertext[7]

    f_ciphertext = []
    for item in result:
        f_ciphertext.append(item['f_ciphertext'])

    collection_key = []
    for num, instance in enumerate(f_ciphertext):
        fault_s1 = instance[0]
        fault_s2 = instance[13]
        fault_s3 = instance[10]
        fault_s4 = instance[7]

        keyspace = []
        for k2 in range(256):
            temp1 = []
            temp3 = []
            temp4 = []
            for k1 in range(256):
                if aes.InvSubByte(s1 ^ k1, invsbox) ^ aes.InvSubByte(fault_s1 ^ k1, invsbox) == \
                         aes.multi(2, aes.InvSubByte(s2 ^ k2, invsbox) ^ aes.InvSubByte(fault_s2 ^ k2, invsbox)):
                    temp1.append(k1)
            for k3 in range(256):
                if aes.InvSubByte(s2 ^ k2, invsbox) ^ aes.InvSubByte(fault_s2 ^ k2, invsbox) == \
                                aes.InvSubByte(s3 ^ k3, invsbox) ^ aes.InvSubByte(fault_s3 ^ k3, invsbox):
                    temp3.append(k3)
            for k4 in range(256):
                if aes.InvSubByte(s4 ^ k4, invsbox) ^ aes.InvSubByte(fault_s4 ^ k4, invsbox) == \
                        aes.multi(3, aes.InvSubByte(s2 ^ k2, invsbox) ^ aes.InvSubByte(fault_s2 ^ k2, invsbox)):
                    temp4.append(k4)
            if temp1 != [] and temp3 !=[] and temp4 != []:
                keyspace.append([k2, temp1, temp3, temp4])

        expand_key = []
        for item in keyspace:
            for i, key1 in enumerate(item[1]):
                for j, key3 in enumerate(item[2]):
                    for k, key4 in enumerate(item[3]):
                        expand_key.append([item[0], key1, key3, key4])

        # res_exp1 = []
        # for k2 in range(256):
        #     for k1 in range(256):
        #         if aes.InvSubByte(s1 ^ k1, invsbox) ^ aes.InvSubByte(fault_s1 ^ k1, invsbox) == \
        #                 aes.multi(2, aes.InvSubByte(s2 ^ k2, invsbox) ^ aes.InvSubByte(fault_s2 ^ k2, invsbox)):
        #             res_exp1.append([k2, k1])
        # # print(res_exp1)
        # # print(len(res_exp1))
        #
        # res_exp2 = []
        # for k2 in range(256):
        #     for k3 in range(256):
        #         if aes.InvSubByte(s2 ^ k2, invsbox) ^ aes.InvSubByte(fault_s2 ^ k2, invsbox) == \
        #                         aes.InvSubByte(s3 ^ k3, invsbox) ^ aes.InvSubByte(fault_s3 ^ k3, invsbox):
        #             res_exp2.append([k2, k3])
        # # print(res_exp2)
        # # print(len(res_exp2))
        #
        # res_exp3 = []
        # for k2 in range(256):
        #     for k4 in range(256):
        #         if aes.InvSubByte(s4 ^ k4, invsbox) ^ aes.InvSubByte(fault_s4 ^ k4, invsbox) == \
        #                 aes.multi(3, aes.InvSubByte(s2 ^ k2, invsbox) ^ aes.InvSubByte(fault_s2 ^ k2, invsbox)):
        #             res_exp3.append([k2, k4])
        #
        # # print(res_exp3)
        # # print(len(res_exp3))
        #
        # list_1 = []
        # for [i, j] in res_exp1:
        #     if i not in list_1:
        #         list_1.append(i)
        #
        # # print(len(list_1))
        #
        # list_2 = []
        # for [i, j] in res_exp2:
        #     if i not in list_2:
        #         list_2.append(i)
        # # print(len(list_2))
        #
        # list_3 = []
        # for [i, j] in res_exp3:
        #     if i not in list_3:
        #         list_3.append(i)
        #
        # # print(len(list_3))
        #
        # key2 = []
        # for subkey in list_1:
        #     if subkey in list_2 and subkey in list_3:
        #         key2.append(subkey)

        # key1 = [x for [y, x] in res_exp1 if y in key2]
        # key3 = [x for [y, x] in res_exp2 if y in key2]
        # key4 = [x for [y, x] in res_exp3 if y in key2]

        collection_key.append(expand_key)
        f = open('resolve.txt', 'a')
        print(expand_key, file=f)
        print("in fault experiment %d the key space is %d" % (num, len(expand_key)), file=f)
        f.close()

    data0 = collection_key[0]
    data1 = collection_key[1]
    specific_key = [x for x in data0 if x in data1]
    print(specific_key)
    print(len(specific_key))


if __name__ == "__main__":

    shortargs = "o:t"
    opts, args = getopt.getopt(sys.argv[1:], shortargs)
    with open(args[0], 'rt') as f:
        dic = json.load(f)

    ciphertext, plaintext, result = parse_data(dic[1])
    f = open('resolve.txt', 'w')
    print("plaintext:", file=f)
    print(plaintext, file=f)
    f.close()
    key_space_reduction(result, ciphertext)
