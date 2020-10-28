# THIS REPOSITORY COMES WITH ZERO GUARANTEES! USE AT YOUR OWN RISK!

`buidl` is a `python3` bitcoin library with no dependencies.
It is easy-to-read and has extensive test coverage.

Because `buidl` has no dependencies, it is easy to install on airgapped computers (just copy over this directory).

## Installation
```bash
$ pip3 install buidl --upgrade
Welcome to multiwallet...
```

## Multiwallet
`multiwallet` is a stateless CLI multisig PSBT wallet.
Since `buidl` has no dependencies, you can run multiwallet by just `cd`ing to the root directory of this project:
```bash
$ python multiwallet.py
Welcome to multiwallet...
```

If you have instlled `buidl`, you can run `multiwallet.py` from any directory as follows:
```bash
$ multiwallet.py
Welcome to multiwallet...
```
TODO: install without strange `.py` name (while also keeping it installation-free over airgap)

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

## TODO:
* `FIXME` in `test_network.py`
* Add libsec support/instructions to pypi version
