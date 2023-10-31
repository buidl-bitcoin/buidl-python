#!/usr/bin/python3

from cffi import FFI


source = open("libsec.h", "r").read()

header = """
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
"""

ffi = FFI()
ffi.cdef(source)
ffi.set_source("_libsec", header, libraries=["secp256k1"], include_dirs=["/opt/homebrew/Cellar/libsecp256k1/0.1/include"])
ffi.compile(verbose=True)
