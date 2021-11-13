#! /usr/bin/env bash

set -o xtrace
pip3 uninstall buidl -y
rm -rf .venv3/
rm -rf dist/
rm -rf build/
rm -rf buidl.egg-info/
rm buidl/_libsec.c
rm buidl/_libsec.cpython-*-darwin.so
rm buidl/_libsec.o
rm buidl/_libsec.so

find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf
