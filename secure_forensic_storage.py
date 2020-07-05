#!/usr/bin/env python3

import sys
from timeit import default_timer as timer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DataBlockCryptography:
    def __init__(self, datablock, b_pub, nonce, predecessor_tag=None):
        self.datablock = datablock
        self.b_pub = b_pub
        self.nonce = nonce
        self.predecessor_tag = predecessor_tag
        self.a_priv = X25519PrivateKey.generate()
        self.a_pub = self.a_priv.public_key()
        self.k_sym = self.generate_k_sym()

    def generate_k_sym(self):
        shared_key = self.a_priv.exchange(self.b_pub)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'',
                           backend=default_backend()).derive(shared_key)
        return derived_key

    def auth_enc_data(self):
        if self.predecessor_tag:
            input_data = self.datablock + self.predecessor_tag
        else:
            input_data = self.datablock
        aesgcm = AESGCM(self.k_sym)
        ct = aesgcm.encrypt(self.nonce, input_data, None)


if __name__ == '__main__':
    timelist = []
    SAMPLES = 10

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

        # BEGIN AE
        data = b"a secret message"
        aesgcm = AESGCM(derived_key)
        nonce = i.to_bytes(12, sys.byteorder)
        ct = aesgcm.encrypt(nonce, data, None)
        print(ct)
        print(ct[-16:])
        # print(aesgcm.decrypt(nonce, ct, None))
        print("CT", len(ct))

        end = timer()
        timelist.append(end - start)

    print("Average time in sec:", sum(timelist) / SAMPLES)

    # Demonstrate privA * pubB == privB * pubA
    privA = X25519PrivateKey.generate()
    pubA = privA.public_key()
    privB = X25519PrivateKey.generate()
    pubB = privB.public_key()

    print(pubA.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    print(privA.exchange(pubB) == privB.exchange(pubA))
