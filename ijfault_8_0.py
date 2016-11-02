# -*- coding: utf-8 -*-

import json
import sys
import getopt
import os

import simulator.fj as fj
import simulator.aes as aes


def serialize_instance(obj):
    d = {}
    d.update(vars(obj))
    return d


if __name__ == "__main__":

    # command line arguments parser
    shortargs = "o:"
    opts,  args = getopt.getopt(sys.argv[1:], shortargs)
    output = 'data.json'
    for opt, arg in opts:
        if opt == '-o':
            output = arg
        if opt == '-i':
            in_f = arg

    with open(args[0], 'rt') as f:
        results = json.load(f)

    if os.path.exists(output):
        print("file %s has been exist." % output)
        exit(0)

    # 怎么样把sbox和invsbox封装起来，而且不影响encrypt的多次执行（最简单的方法是把他们的结果封装到aes模块中，
    # 而不是用这两个函数；另一种方法是创建一个aes类，将这些常量作为aes的类属性，留待日后改进）
    # plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    # key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    sbox, invsbox = aes.genSBox()
    dics = []
    for item in results:
        plaintext = item['plaintext']
        key = item['key']
        ciphertext = aes.Encryption(plaintext, key, sbox)

        result = []
        for i in range(10):
            ft = fj.Fault(0, 9, 'sglbyte')
            ft.error = ft.gen_error()
            f_ciphertext = fj.inj_encrypt(plaintext, key, sbox, ft, inj=True)
            result.append({'fault': serialize_instance(ft), 'f_ciphertext': f_ciphertext})

        dic = {'plaintext': plaintext, 'result': result, 'ciphertext':ciphertext}
        dics.append(dic)


    with open(output, 'wt') as f:
        json.dump(dics, f)

