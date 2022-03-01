#! /usr/bin/env bash

# This assumes libsecp256k1 is already installed on the OS

set -o xtrace

python3 -m pip install -r requirements-libsec.txt
python3 -m pip install --editable .
cd buidl
python3 libsec_build.py
cd ..
# TODO: should this fail if libsec doesn't work?
python3 -c "from buidl import *; print('success') if is_libsec_enabled() else print('LIBSEC INSTALL FAIL')"
