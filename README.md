# `buidl` Bitcoin Library

`buidl` is a `python3` bitcoin library with 0 dependencies.
It is easy-to-read, has extensive test coverage, simple to install on airgapped computers (just copy over this directory).

`buidl` has extensive feature support for the bitcoin blockchain:
* **Trust-minimized** - easy-to-read cryptography implemented in straightforward/way with no third-party dependencies
* **Performant** - optional [secp256k1 library bindings](https://github.com/bitcoin-core/secp256k1) offers a ~100x speedup, see [performance section below](#performance)
* **Wallet tools** for various script types (`p2pkh`, `p2sh`, `p2sh-wrapped-p2wsh`, `p2wsh` and `p2tr` (coming soon) ), compressed/uncompressed pubkeys, address encodings, HD support (BIP32, BIP39, BIP44, seedpicker, etc), PSBT generation/decoding/validation, etc
* **Extensive multisig support**/tooling for output descriptors, receive address validation, change address detection, fee verification, blinding xpubs, PSBTs, [BCUR v0](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) (v1 coming soon), airgap signing, etc
* **SPV proofs and compact block filters** (Neutrino) - build powerful trust-minimized apps without scanning the whole blockchain
* **P2P gossip network** - connect directly to the bitcoin network
* **Footgun protection** - from elegantly structured OOP classes to [RFC6979](https://datatracker.ietf.org/doc/html/rfc6979) deterministic k-values, `buidl` is designed to be usable for non-cryptographers
* **0 altcoins** - for maximum readability/focus. The only other supported coins are bitcoin's `testnet` and `signet`, which intentionally have no value.

*This repository comes with zero guarantees, use at your own risk.*

## Installation

#### Online
```bash
$ pip3 install buidl --upgrade
```

#### Offline
Download this repo and then run:
```bash
$ python3 setup.py install
```
(alternatively, because `buidl` has no dependencies you can just `cd` into this root directory and call `buidl` without installation)

## Multiwallet
`multiwallet` is a stateless CLI multisig PSBT wallet.
Since `buidl` has no dependencies, you can run multiwallet by just `cd`ing to the root directory of this project:

```bash
$ python3 multiwallet.py
Welcome to multiwallet...
```

If you have installed `buidl`, you can run `multiwallet.py` from any directory:
```bash
$ multiwallet.py
Welcome to multiwallet...
```

For more information on installing multiwallet, see [multiwallet.md](docs/multiwallet.md) or check out [this demo](https://twitter.com/mflaxman/status/1321503036724989952).

`singlesweep.py` works the same way for sweeping out of paper wallets, but is intentionally undocumented.

## Tests

Run tests with `pytest`:
```bash
$ git clone https://github.com/buidl-bitcoin/buidl-python.git && cd buidl-python
$ pytest -v
```
(these will be 1-2 orders of magnitue faster with libsec bindings, see [performance section below](#performance))

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

#### `libsec256k1` Dependency Installation

Note that you'll have to compile libsecp256k1 from scratch with experimental modules enabled to make Schnorr signatures work.

Here are the instructions on Linux/Mac:

```bash
$ git clone https://github.com/bitcoin-core/secp256k1
$ cd secp256k1
$ ./autogen.sh
$ ./configure --enable-module-extrakeys --enable-module-schnorrsig --enable-experimental
$ make
$ sudo make install
```

#### `buidl` Installation

```bash
$ git clone git@github.com:buidl-bitcoin/buidl-python.git && cd buidl-python && python3 -m pip install -r requirements-libsec.txt && python3 -m pip install --editable . && cd buidl && python libsec_build.py && cd ..
```
