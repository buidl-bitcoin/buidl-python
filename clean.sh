rm -rf .venv3/
rm -rf dist/
rm -rf build/
rm -rf buidl.egg-info/
find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf
