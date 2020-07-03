#!/usr/bin/env python3

import sys
from timeit import default_timer as timer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def encrypt_datablock(iteration, private_key, datablock):
    print(f"\nENTER FUNC ITERATION #{iteration}")

    appendix = iteration % 255
    signature = private_key.sign(datablock + appendix.to_bytes(2, byteorder='big', signed=True))

    print(f"EXIT FUNC ITERATION  #{iteration}")
    return signature


if __name__ == '__main__':
    timelist = []
    SAMPLES = 1000

    f = open("testblock.data", "rb")
    datablock = f.read()
    print("datablock size: ", sys.getsizeof(datablock))
    f.close()

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(encoding=serialization.Encoding.Raw,
                                              format=serialization.PrivateFormat.Raw,
                                              encryption_algorithm=serialization.NoEncryption())
    loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    print(private_bytes)

    public_key = private_key.public_key()
    print(private_key, public_key)

    for i in range(SAMPLES):
        start = timer()

        # Do the actual work here
        signature = encrypt_datablock(i, private_key, datablock)

        end = timer()
        timelist.append(end - start)

    print("Average time in sec:", sum(timelist) / SAMPLES)

    try:
        public_key.verify(encrypt_datablock(-1, private_key, datablock), datablock)
        print("Signature OK!")
    except InvalidSignature:
        print("INVALID SIGNATURE!")


