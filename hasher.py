from io import BufferedReader, BytesIO
from os import path
from glob import glob
import argparse
import re
import sys

# Heavily modified PyZMQ base85 encoder

"""Python implementation of Z85 85-bit encoding
Z85 encoding is a plaintext encoding for a bytestring interpreted as 32bit integers.
Since the chunks are 32bit, a bytestring must be a multiple of 4 bytes.
See ZMQ RFC 32 for details.
"""

# Copyright (C) PyZMQ Developers
# Distributed under the terms of the Modified BSD License.

# Z85CHARS is the base 85 symbol table
Z85CHARS = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-;+=^!/*?&<>()[]{}@%$#"

_85s = [85 ** i for i in range(5)][::-1]


def encb85(i32num):
    i32num = i32num & 0xffffffff
    encoded = []
    for offset in _85s:
        encoded.append(Z85CHARS[(i32num // offset) % 85])
    return bytes(encoded)


class Adler32:

    mod_val = 65521

    def __init__(self):
        self._init_state()


    def update(self, data):
        assert isinstance(data, bytes)
        for byte in data:
            self.low = (self.low + byte) % Adler32.mod_val
            self.high = (self.low + self.high) % Adler32.mod_val


    def finalize(self):
        return (self.high << 16 | self.low) & 0xffffffff


    def _init_state(self):
        self.high = 0
        self.low = 1


    def reset(self):
        self._init_state()


class Hasher:

    space = re.compile(b"(?:\\0{4,})|(?:\n{4,})|(?:(?:\r\n){2,})")

    def __init__(self, fileobj, size = 512):
        assert isinstance(fileobj, BufferedReader)
        self.buff = bytearray()
        self.hashes = []
        self.file = fileobj
        self.size = size


    def _fill_buffer(self):
        needed = self.size - len(self.buff)
        try:
            data = self.file.read(needed)
        except IOError:
            self.file.close()
            return False
        if len(data) == 0:
            self.file.close()
            return False
        self.buff.append(data)
        return True


    def _split(self):
        split_val = Hasher.space.split(self.buff, 1)
        if len(split_val) == 1:
            if len(split_val[0]) == 0:
                return None
            elif len(split_val[0]) > 0 and len(split_val[0]) < 5:
                ret_val = split_val[0]
                self.buff = bytearray()
                return ret_val
            elif len(split_val[0]) > 4:
                ret_val = self.buff[0:-4]
                self.buff = self.buff[:-4]
                return ret_val
        elif len(split_val) == 2:
            self.buff = bytearray(split_val[1])
            return split_val[0]


    def getHashes(self):
        pass


def openfile(file):
    assert isinstance(file, str)
    if path.isfile(file):
        return open(file, "rb")
    else:
        return None


# TODO: hash
def create_hash(file_path):
    space = re.compile(b"((\0){8,})|(\r{4,})|((\r\n){4,})")
    file = openfile(file_path)
    buffer = BytesIO()
    first_hash = None
    last_hash = None
    hashes = []
    while file.readable():
        buffer.seek(0)
        print(buffer)
    if first_hash != None:
        hashes.insert(0, first_hash)
    if last_hash != None:
        hashes.append(last_hash)
    return ":".join(hashes)


def arg():
    pass


# TODO: add glob support
def main():
    pass


space = re.compile(b"(?:\\0{4,})|(?:\n{4,})|(?:(?:\r\n){2,})")
test = space.split(b"\n\n\n\nhi", 1) # should be 2 and 0: break 1:buffer "hi"
test2 = space.split(b"hi\n\n\n\n", 1) # should be 2 and 0: hash 1:break returned to buffer "\n\n\n\n"
test3 = space.split(b"\0\0\0\0\0\0\0\0hi\0\0", 1) # should be 2 and 0: break 1: buffer "hi\0\0"
test4 = space.split(b"\n\n\n\n\n\n", 1) # should be 2 and 0: break 1: break buffer "\n\n\n\n"

test5 = space.split(b"\n\n\n", 1) # should be 1 and 0: hash buffer ""
test6 = space.split(b"kljsdhioah", 1) # should be 1 and 0: hash buffer "ioah"
test7 = space.split(b"", 1) # should be 1 and 0: null (EOF)
test8 = space.split(b"abcd", 1) # should be 1 and 0: hash (EOF)



create_hash(sys.argv[0])
test = Adler32()
test.update(b"Wikipedia")
print(encb85(test.finalize()))
#print(open(sys.argv[0], "rb"))
