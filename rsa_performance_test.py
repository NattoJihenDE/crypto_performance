#  Copyright (c) 2019  Nico Vinzenz
"""
Python script to measure the average execution time of cryptographic primitives.
Requires: pycryptodome
"""

from timeit import default_timer as timer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import os

if __name__ == '__main__':

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=15360, backend=default_backend())
    public_key = private_key.public_key()

    timelist = []
    SAMPLES = 1000
    for i in range(SAMPLES):
        start = timer()

        # 1x session key generation
        session_key = os.urandom(32)

        # 1x asymmetric encryption
        ciphertext = public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))

        end = timer()
        timelist.append(end - start)

    print("Average time in sec:", sum(timelist) / SAMPLES)
