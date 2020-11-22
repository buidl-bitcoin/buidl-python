# Multiwallet

Multiwallet CLI multisig wallet tool built with the `buidl` library.
Most people looking at the readme for this repository are programmers trying to use `buidl` in their applications.
This page has installation instructions just for using multiwallet CLI multisig wallet.

#### Telegram Community Chat Group
Ask Qs here: 
<https://t.me/multiwallet>

## Install

#### Online Computer

Easy, but not secure. Great for testing.

```
$ pip3 install buidl --upgrade
```

You can test this worked by running the following:
```bash
$ multiwallet.py
Welcome to multiwallet...
```

#### Offline (Airgap) Computer
`buidl` has no dependencies, so this is relatively easy.

Download repo with `git` (while online):
```
$ git clone https://github.com/buidl-bitcoin/buidl-python.git
```
(you can also download a [.zip file from github](https://github.com/buidl-bitcoin/buidl-python/archive/main.zip) and then expand it)

Go to the `buidl-python` directory:
```bash
$ cd buidl-python
```

Start multiwallet:
```bash
$ python3 multiwallet.py
Welcome to multiwallet...
```

If you get a `permission denied` error, you will need to run `$ sudo python3 multiwallet.py`.
On TAILs, you need to setup an [Administration Password](https://tails.boum.org/doc/first_steps/welcome_screen/administration_password/).

## Product Roadmap

* Add multiple paths
* Add passphrase
* Show change addresses (not just receiving addresses)
* Save outputs to a file?
* Dispay QR codes?
