#!/usr/bin/env python3
import argparse
import re
from glob import glob
from io import BufferedReader
from os import path
from sys import version_info, stderr

# Heavily modified PyZMQ base85 encoder
# Copyright (C) PyZMQ Developers
# Distributed under the terms of the Modified BSD License.

# Z85CHARS is the base 85 symbol table with minor change
Z85CHARS = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_?+=^!/*&<>()[]{}@%$~"
_85s = [85 ** i for i in range(5)][::-1]


def _encb85(i32num):
    i32num &= 0xffffffff
    encoded = []
    for offset in _85s:
        encoded.append(Z85CHARS[(i32num // offset) % 85])
    return bytes(encoded).decode("utf-8")


class Adler32:
    mod_val = 65521

    def __init__(self):
        self._high = 0
        self._low = 1
        self._bytes = 0

    def update(self, data):
        assert isinstance(data, bytes) or isinstance(data, bytearray)
        self._bytes += len(data)
        for byte in data:
            self._low = (self._low + byte) % Adler32.mod_val
            self._high = (self._low + self._high) % Adler32.mod_val

    def bytes_seen(self):
        return self._bytes

    def finalize(self):
        ret_val = (self._high << 16 | self._low) & 0xffffffff
        self._high = 0
        self._low = 1
        return ret_val


class HashSig:
    _break_space = re.compile(b"(?:\\0{4,})|(?:\n{4,})|(?:(?:\r\n){2,})")
    _min_space_to_match = 4

    def __init__(self, fileobj, max_hash, size=512):
        assert isinstance(fileobj, BufferedReader)
        self._buff = bytearray()
        self._hashes = []
        self._file = fileobj
        self._buff_size = size
        self._has_data = True
        self._max_hash_size = max_hash
        self._hash_comp_loc = 1

    def _fill_buffer(self):
        needed = self._buff_size - len(self._buff)
        while self._has_data and needed > 0:
            try:
                data = self._file.read(needed)
            except IOError:
                self._file.close()
                self._has_data = False
            if len(data) == 0:
                self._file.close()
                self._has_data = False
            self._buff += data
            needed = self._buff_size - len(self._buff)

    def _split(self):
        split_val = HashSig._break_space.split(self._buff, 1)
        first_len = len(split_val[0])
        if len(split_val) == 1:
            if first_len == 0:
                return None
            elif first_len <= HashSig._min_space_to_match:
                ret_val = split_val[0]
                self._buff = bytearray()
            else:
                ret_val = self._buff[0:len(self._buff) - HashSig._min_space_to_match]
                self._buff = self._buff[-HashSig._min_space_to_match:]
            return ret_val
        elif len(split_val) == 2:
            second_len = len(split_val[1])
            buff_len = len(self._buff)
            if buff_len == HashSig._min_space_to_match:
                if first_len == 0 and second_len == 0:
                    self._buff = bytearray()
                    return None
            else:
                if second_len > 0:
                    if first_len == 0:
                        self._buff = bytearray(split_val[1])
                        return None
                    self._buff = self._buff[buff_len - second_len - HashSig._min_space_to_match:]
                else:
                    self._buff = self._buff[:-HashSig._min_space_to_match]
                return split_val[0]

    # TODO: specify a max hash size.
    def hash_data(self):
        hasher = Adler32()
        self._fill_buffer()
        hasher.update(self._buff)
        self._hashes.append(hasher.finalize())
        while self._has_data or len(self._buff) > 0:
            data = self._split()
            while data is not None:
                hasher.update(data)
                self._fill_buffer()
                data = self._split()
            hashed_val = hasher.finalize()
            # Don't allow identical hashes to be constantly added
            if hashed_val not in self._hashes:
                self._hashes.append(hashed_val)
        return self._hashes


def _openfile(file, min_size, max_size):
    assert isinstance(file, str)
    if path.isfile(file):
        try:
            _file_size = path.getsize(file)
            if min_size <= _file_size <= max_size:
                return open(file, "rb")
        except OSError:
            pass
    return None


def _format_hash(hash_list):
    assert isinstance(hash_list, list)
    ret_val = []
    for hash_val in hash_list:
        ret_val.append(_encb85(hash_val))
    return ":".join(ret_val)


def print_hashes(file_path, parsinfo, rec=False):
    if rec:
        _glob_val = glob(file_path, recursive=True)
    else:
        _glob_val = glob(file_path)
    for globbed_file in _glob_val:
        file_ctx = _openfile(globbed_file, parsinfo.a, parsinfo.b)
        if file_ctx is not None:
            hashy_mc_hasherton = HashSig(file_ctx, parsinfo.h)
            print("{1}\t{0}".format(_format_hash(hashy_mc_hasherton.hash_data()), globbed_file))


def arg():
    _parser = argparse.ArgumentParser(description="File Stream Hasher")
    _parser.add_argument('-a', '-min', type=int, default=0, help="Minimum size of file.")
    _parser.add_argument('-b', '-max', type=int, default=(1 << 24), help="Maximum size of file.")
    _parser.add_argument('-h', '-maxhash', type=int, default=(1 << 24), help="Maximum size of hash to create")
    _parser.add_argument('-r', '-recursive', action='store_const', const=True, required=False,
                         help="Hash files recursively")
    _parser.add_argument('files', nargs='*', help="Files to hash")
    return _parser


if __name__ == "__main__":
    args = arg()
    parser = args.parse_args()
    if len(parser.files) > 0:
        if version_info >= (3, 5) and parser.r is not None:
            for _file in parser.files:
                print_hashes(_file, parser, True)
        else:
            if version_info < (3, 5):
                print("Python version < 3.5 glob recursion is not fully supported", file=stderr)
            for _file in parser.files:
                print_hashes(_file, parser)
    else:
        args.print_help()

# test1 = HashSig._break_space.split(b"\n\n\n\nhi", 1) # should be 2 and 0: break 1:buffer "hi"
# test2 = HashSig._break_space.split(b"hi\n\n\n\n", 1) # should be 2 and 0: hash 1:break returned to buffer "\n\n\n\n"
# test3 = HashSig._break_space.split(b"\0\0\0\0\0\0\0\0hi\0\0", 1) # should be 2 and 0: break 1: buffer "hi\0\0"
# test4 = HashSig._break_space.split(b"\n\n\n\n\n\n", 1) # should be 2 and 0: break 1: break buffer "\n\n\n\n"
#
# test5 = HashSig._break_space.split(b"\n\n\n", 1) # should be 1 and 0: hash buffer "\n\n\n"
# test6 = HashSig._break_space.split(b"kljsdhioah", 1) # should be 1 and 0: hash buffer "ioah"
# test7 = HashSig._break_space.split(b"", 1) # should be 1 and 0: null (EOF)
# test8 = HashSig._break_space.split(b"abcd", 1) # should be 1 and 0: hash (EOF)
#
# thefile = _openfile(sys.argv[0])
# hashy = HashSig(thefile)
# print(hashy.hash_data())
# test = Adler32()
# test.update(b"Wikipedia")
# print(_encb85(test.finalize()))
# #print(open(sys.argv[0], "rb"))
