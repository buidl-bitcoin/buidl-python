#! /usr/bin/env bash

# Verbose printing
set -o xtrace

# Exit virtualenv if we're in one
deactivate

# Abandon if anything errors
set -e;

# Remove old files
rm -rf .venv3/
rm -rf dist/
rm -rf build/
rm -rf buidl.egg-info/
find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf

# Tests
black --check .
flake8 .
# pytest -v

# Safety
git push

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
python3 -m twine upload dist/*

# Cleanup
rm -rfv dist/
rm -rfv buidl.egg-info/
rm -rfv build/
find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf

# Hackey timer
# https://askubuntu.com/questions/1028924/how-do-i-use-seconds-inside-a-bash-script
hrs=$(( SECONDS/3600 ))
mins=$(( (SECONDS-hrs*3600)/60))
secs=$(( SECONDS-hrs*3600-mins*60 ))
printf 'Time spent: %02d:%02d:%02d\n' $hrs $mins $secs
