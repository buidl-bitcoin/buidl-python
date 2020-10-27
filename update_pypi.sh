date && black --check . && pytest -v && flake8 . && git push && python3 setup.py sdist bdist_wheel && python3 -m pip install --upgrade twine && python3 -m twine upload dist/* && rm -rf dist/ && date
