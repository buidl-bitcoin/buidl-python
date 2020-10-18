from cffi import FFI
from unittest import TestCase


source = open('libsec.h', 'r').read()

ffi = FFI()
ffi.cdef(source)
ffi.set_source('_libsec', '#include <secp256k1.h>', libraries=['secp256k1'])
ffi.compile(verbose=True)
