black --diff --check . && pytest -v buidl/test && flake8 . && printf "\nSUCCESS!\n" || printf "\n-----------------\nFAIL\n-----------------\n"
