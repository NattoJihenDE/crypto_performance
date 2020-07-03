#!/usr/bin/env python3

import sys
from timeit import default_timer as timer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if __name__ == '__main__':
    timelist = []
    SAMPLES = 1000

    # static Bpub
    peer_public_key = X25519PrivateKey.generate().public_key()

    for i in range(SAMPLES):
        start = timer()

        # Do the actual work here

        # Generate a private key for use in the exchange.
        # ephemeral Apriv
        private_key = X25519PrivateKey.generate()

        # ephemeral S
        shared_key = private_key.exchange(peer_public_key)

        # KDF
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                           backend=default_backend()).derive(shared_key)
        # derived_key = Ksym

        end = timer()
        timelist.append(end - start)

    print("Average time in sec:", sum(timelist) / SAMPLES)

    # Demonstrate privA * pubB == privB * pubA
    privA = X25519PrivateKey.generate()
    pubA = privA.public_key()
    privB = X25519PrivateKey.generate()
    pubB = privB.public_key()

    print(privA.exchange(pubB) == privB.exchange(pubA))
