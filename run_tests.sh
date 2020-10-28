black --diff --check . && pytest -v && flake8 . && printf "\nSUCCESS!\n" || printf "\n-----------------\nFAIL\n-----------------\n"
