#!/usr/bin/env python3

import lzma
import os
import sys
from timeit import default_timer as timer

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if __name__ == '__main__':
    timelist = []
    SAMPLES = 1000

    f = open("testblock.data", "rb")
    datablock = f.read()
    print("datablock size: ", sys.getsizeof(datablock))
    f.close()

    sym_key = os.urandom(32)
    nonce = os.urandom(12)

    for i in range(SAMPLES):
        start = timer()

        # 1x compress
        compressed_datablock = lzma.compress(datablock)

        # 1x AE
        aesgcm = AESGCM(sym_key)
        ciphertext = aesgcm.encrypt(nonce, compressed_datablock, None)

        end = timer()
        timelist.append(end - start)

    print("Average time in sec:", sum(timelist) / SAMPLES)
