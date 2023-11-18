#! /usr/bin/env bash

# Verbose printing
set -o xtrace

# Exit virtualenv if we're in one
deactivate

# Abandon if anything errors
set -e;

# Cleanup before getting started
./clean.sh
./clean_libsec.sh

## RUN TESTS ##

# To make tests fast
./install_libsec.sh

# Install testing requirements
if [ -f requirements-test.txt ]; then python3 -m pip install -r requirements-test.txt; fi

# Run tests
black --check .
flake8 .
pytest -v buidl/test/
pytest -v test_*.py

# Cleanup and reinstall build for pypi
./clean.sh
./clean_libsec.sh

# Safety
git push

## UPDATE PYPI ##

# Virtualenv
python3 --version
# Install virtualenv (if not installed)
# python3 -m pip uninstall virtualenv -y
python3 -m pip install virtualenv
# Create virtualenv and install our software inside it
python3 -m virtualenv .venv3
source .venv3/bin/activate
# python3 -m pip uninstall pyinstaller -y
if [ -f requirements.txt ]; then python3 -m pip install -r requirements.txt; fi
python3 setup.py install
python3 -m pip freeze
# Package
python3 setup.py sdist bdist_wheel
# Upload to PyPI
python3 -m pip install --upgrade twine
# Use this line to upload to pypi testing repo instead:
# python3 -m twine upload --repository testpypi dist/*
python3 -m twine testpypi dist/*

# Cleanup
./clean.sh

# Libsec is nice to have installed by default
./install_libsec.sh

# Hackey timer
# https://askubuntu.com/questions/1028924/how-do-i-use-seconds-inside-a-bash-script
hrs=$(( SECONDS/3600 ))
mins=$(( (SECONDS-hrs*3600)/60))
secs=$(( SECONDS-hrs*3600-mins*60 ))
printf 'Time spent: %02d:%02d:%02d\n' $hrs $mins $secs
