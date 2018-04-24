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
        self._bytes = 0
        return ret_val


class HashSig:
    _break_space = re.compile(b"(?:\\0{4,})|(?:\n{4,})|(?:(?:\r\n){2,})")
    _min_space_to_match = 4

    def __init__(self, fileobj, parsed_args, size=512):
        assert isinstance(fileobj, BufferedReader)
        self._buff = bytearray()
        self._hashes = []
        self._file = fileobj
        self._buff_size = size
        self._has_data = True
        self._hash_comp_loc = 1
        self._parsed_args = parsed_args

    def _fill_buffer(self):
        needed = self._buff_size - len(self._buff)
        while self._has_data and needed > 0:
            _data = b''
            try:
                _data = self._file.read(needed)
            except IOError:
                self._file.close()
                self._has_data = False
            if len(_data) == 0:
                self._file.close()
                self._has_data = False
            self._buff += _data
            needed = self._buff_size - len(self._buff)

    def _split(self):
        if len(self._buff) > 3 or (0 < len(self._buff) < 4 and not self._has_data):
            i = 1
            if self._buff[0] == 0:
                while i < len(self._buff):
                    if self._buff[i] != 0:
                        break
                    i += 1
                if i < 3:
                    ret_val = self._buff[:i]
                    self._buff[:i] = []
                    return ret_val
            elif self._buff[0] == 10:
                while i < len(self._buff):
                    if self._buff[i] != 10:
                        break
                    i += 1
                if i < 3:
                    ret_val = self._buff[:i]
                    self._buff[:i] = []
                    return ret_val
            elif self._buff[0] == 13:
                while i < len(self._buff):
                    if i % 2 == 1:
                        if self._buff[i] != 13:
                            break
                    else:
                        if self._buff[i] != 10:
                            i -= 1
                            break
                    i += 1
                if i < 3:
                    ret_val = self._buff[:i]
                    self._buff[:i] = []
                    return ret_val
            else:
                while i < len(self._buff):
                    if self._buff[i] == 0 or self._buff[i] == 10 or self._buff == 13:
                        break
                    i += 1
                ret_val = self._buff[:i]
                self._buff[:i] = []
                return ret_val
            self._buff[:i] = []
            return None
            # split_val = HashSig._break_space.split(self._buff, 1)
            # first_len = len(split_val[0])
            # if len(split_val) == 1:
            #     if first_len == 0:
            #         return None
            #     elif first_len <= HashSig._min_space_to_match:
            #         ret_val = split_val[0]
            #         self._buff = bytearray()
            #     else:
            #         ret_val = self._buff[0:len(self._buff) - HashSig._min_space_to_match]
            #         self._buff = self._buff[-HashSig._min_space_to_match:]
            #     return ret_val
            # elif len(split_val) == 2:
            #     second_len = len(split_val[1])
            #     buff_len = len(self._buff)
            #     if buff_len == HashSig._min_space_to_match:
            #         if first_len == 0 and second_len == 0:
            #             self._buff = bytearray()
            #             return None
            #     else:
            #         if second_len > 0:
            #             if first_len == 0:
            #                 self._buff = bytearray(split_val[1])
            #                 return None
            #             self._buff = self._buff[buff_len - second_len - HashSig._min_space_to_match:]
            #         else:
            #             self._buff = self._buff[:-HashSig._min_space_to_match]
            #         return split_val[0]

    def hash_data(self):
        hasher = Adler32()
        self._fill_buffer()
        hasher.update(self._buff[:8])
        self._hashes.append(hasher.finalize())
        while self._has_data or len(self._buff) > 0:
            data = self._split()
            self._fill_buffer()
            while data is not None:
                hasher.update(data)
                self._fill_buffer()
                data = self._split()
            if hasher.bytes_seen() < self._parsed_args.m or (
                    len(self._buff) < self._parsed_args.m and not self._has_data):
                hasher.finalize()
                continue
            hashed_val = hasher.finalize()
            # Don't allow identical hashes to be constantly added
            if hashed_val not in self._hashes:
                print("{}\t{}".format(hashed_val, _encb85(hashed_val)))
                self._hashes.append(hashed_val)
                if len(self._hashes) > self._parsed_args.s:
                    self._hashes[self._hash_comp_loc] ^= self._hashes[self._hash_comp_loc + 1]
                    del self._hashes[self._hash_comp_loc + 1]
                    self._hash_comp_loc = (self._hash_comp_loc + 1) % self._parsed_args.s
                    if self._hash_comp_loc < 1:
                        self._hash_comp_loc = 1
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
            hashy_mc_hasherton = HashSig(file_ctx, parsinfo)
            print("{}\t{}".format(_format_hash(hashy_mc_hasherton.hash_data()), globbed_file))


def arg():
    _parser = argparse.ArgumentParser(description="File Stream Hasher")
    _parser.add_argument('-a', '-min', type=int, default=0, help="Minimum size of file. default: 0")
    _parser.add_argument('-b', '-max', type=int, default=(1 << 24), help="Maximum size of file. default: 2^24")
    _parser.add_argument('-m', '-minsize', type=int, default=8, help="Minimum bytes that will generate a hash. default: 8")
    _parser.add_argument('-r', '-recursive', action='store_const', const=True, help="Hash files recursively")
    _parser.add_argument('-s', '-maxhash', type=int, default=(1 << 24),
                         help="Maximum size of hash to create. min: 2, default: 2^24")
    _parser.add_argument('files', nargs='*', help="Files to hash")
    return _parser


if __name__ == "__main__":
    args = arg()
    parser = args.parse_args()
    if len(parser.files) > 0 or parser.s < 2 or parser.a < 0 or parser.b < parser.a:
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
