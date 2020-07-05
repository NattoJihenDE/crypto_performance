#!/usr/bin/env python3

import mmap
import os.path
import sys
import struct
from timeit import default_timer as timer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# DEFINES
_FILENAME = "circular_buffer.data"
_FILESIZE = 2 ** 20
_POINTERSIZE_BYTE = 8
_INDEXSIZE_BYTE = 8
_PREDECESSOR_POINTERSIZE = 8
_LENGTHSIZE_BYTE = 8


class CircularBuffer:
    def __init__(self, filename, filesize):
        self.filename = filename
        self.filesize = filesize
        self.most_recent_element_pointer = _POINTERSIZE_BYTE
        self.next_empty_space_pointer = _POINTERSIZE_BYTE
        self.curr_idx = 0
        self.curr_predecessor = 0

        if not os.path.isfile(self.filename):
            print(f"Generate empty binary file: {self.filename}")
            self.generate_empty_file()

        self.update_state()

    def generate_empty_file(self):
        with open(self.filename, 'wb') as f:
            f.write(b'\0' * self.filesize)

    def update_state(self):
        pass
        with open(self.filename, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 0)
            self.most_recent_element_pointer = struct.unpack("Q", mm.read(_POINTERSIZE_BYTE))[0]

            mm.seek(self.most_recent_element_pointer, 0)
            self.curr_idx = struct.unpack("Q", mm.read(_INDEXSIZE_BYTE))[0]
            self.curr_predecessor = struct.unpack("Q", mm.read(_PREDECESSOR_POINTERSIZE))[0]
            mm.seek(struct.unpack("Q", mm.read(_LENGTHSIZE_BYTE))[0], 1)
            self.next_empty_space_pointer = mm.tell()

    def get_most_recent_element(self):
        with open(self.filename, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 0)
            self.most_recent_element_pointer = mm[0:_POINTERSIZE_BYTE]
            start_pointer = self.most_recent_element_pointer
            idx = struct.unpack("Q", mm[start_pointer:start_pointer + _INDEXSIZE_BYTE])[0]
            predecessor = struct.unpack("Q", mm[
                                             start_pointer + _INDEXSIZE_BYTE:start_pointer + _INDEXSIZE_BYTE
                                                                             + _PREDECESSOR_POINTERSIZE])[0]
            length = struct.unpack("Q", mm[
                                        start_pointer + _INDEXSIZE_BYTE + _PREDECESSOR_POINTERSIZE:start_pointer
                                                                                                   + _INDEXSIZE_BYTE + _PREDECESSOR_POINTERSIZE + _LENGTHSIZE_BYTE])[
                0]

            start_content = start_pointer + _INDEXSIZE_BYTE + _PREDECESSOR_POINTERSIZE + _LENGTHSIZE_BYTE
            content = mm[start_content:start_content + length]
            self.next_empty_space_pointer = start_content + length
            self.curr_idx = idx
            self.curr_predecessor = predecessor
            return content

    def put_new_element(self, element):
        '''
        |curr_idx|curr_predecessor|len|element|
        :param element:
        :return:
        '''
        self.curr_idx += 1
        self.curr_predecessor = self.most_recent_element_pointer

        with open(self.filename, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 0)
            mm.seek(self.next_empty_space_pointer, 0)

            mm.write(struct.pack("Q", self.curr_idx))
            mm.write(struct.pack("Q", self.curr_predecessor))
            mm.write(struct.pack("Q", len(element)))
            mm.write(element)

            self.next_empty_space_pointer = mm.tell()
            mm.seek(0, 0)
            mm.write(struct.pack("Q", self.next_empty_space_pointer))

            self.update_state()


if __name__ == '__main__':
    f = open("testblock.data", "rb")
    datablock = f.read()
    print("datablock size: ", sys.getsizeof(datablock))
    f.close()

    privA = X25519PrivateKey.generate()
    pubA = privA.public_key()
    pubA_out = pubA.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    aesgcm = AESGCM(os.urandom(32))
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, datablock, None)

    entry = bytearray(ciphertext) + bytearray(pubA_out)

    print(entry)
    cb = CircularBuffer(_FILENAME, _FILESIZE)

    cb.put_new_element(entry)
