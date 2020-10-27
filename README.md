# THIS REPOSITORY COMES WITH ZERO GUARANTEES! USE AT YOUR OWN RISK!

`buidl` is a `python3` bitcoin library with no dependencies, designed to make it easy to BUIDL.
`buidl` has extensive test coverage, which you can use as documentation.

## Installation
```bash
$ pip3 install buidl
```

## Tests

Run tests with `pytest`:
```bash
$ git clone git@github.com:buidl-bitcoin/buidl-python.git && cd buidl-python
$ pytest -v
```

Run `black`:
```bash
$ black . --diff --check
```

Run `flake8`:
```bash
$ flake8 .
```

## Performance

You can speed this library up ~100x by using C-bindings to [bitcoin core's `libsecp256k1` library](https://github.com/bitcoin-core/secp256k1).

#### OS Installation

On Ubuntu:
```bash
$ sudo apt install libsecp256k1-dev
```

On MacOS (HT [cuber](https://github.com/cuber/homebrew-libsecp256k1)):
```bash
$ brew tap cuber/homebrew-libsecp256k1 && brew install pkg-config libffi libsecp256k1
```

#### Python Installation

```bash
$ git clone git@github.com:buidl-bitcoin/buidl-python.git && cd buidl-python && pip3 install --editable . && pip3 install cffi && cd buidl && python libsec_build.py
```

# TODO:
* Add back in `wallet.py` (see [here](https://github.com/jimmysong/pw-exercises/blob/master/session6/wallet.py)) without `PyCryptodome` dependency
* `FIXME` in `test_network.py`
* Add libsec support/instructions to pypi version
