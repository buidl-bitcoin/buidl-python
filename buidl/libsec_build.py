from cffi import FFI


source = open("libsec.h", "r").read()

ffi = FFI()
ffi.cdef(source)
ffi.set_source("_libsec", "#include <secp256k1.h>", libraries=["secp256k1"])
ffi.compile(verbose=True)
