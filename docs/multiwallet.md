# Multiwallet

Multiwallet is a Command Line Interface (CLI) multisig wallet tool built with the `buidl` python library.
Most people looking at the readme for this repository are programmers trying to use `buidl` in their applications.
This page has installation instructions for using the multiwallet CLI tool.

## Telegram Community Chat Group
Ask Qs here: 
<https://t.me/multiwallet>

## Install

#### Online Computer

Easy, but not as secure.
Great for testing.

```
$ pip3 install buidl --upgrade
```

You can test your installation worked by running the following:
```bash
$ multiwallet.py
Welcome to multiwallet...
```

#### Offline (Airgap) Computer
`buidl` has no dependencies, so this is relatively easy.

Download this repo with `git` (while online):
```
$ git clone https://github.com/buidl-bitcoin/buidl-python.git
```
(you can also download a [.zip file from github](https://github.com/buidl-bitcoin/buidl-python/archive/main.zip) and then decompress it)

Disconnect your computer from the internet, or copy this folder onto your offline computer.
Go to the `buidl-python` directory:
```bash
$ cd buidl-python
```

Start multiwallet without having to install anything:
```bash
$ python3 multiwallet.py
Welcome to multiwallet...
```

If you get a `permission denied` error, you may need to run:
```bash
$ sudo python3 multiwallet.py
```

On TAILs, you need to setup an [Administration Password](https://tails.boum.org/doc/first_steps/welcome_screen/administration_password/) in order to `sudo`.

## Product Roadmap

* Show change addresses (not just receiving addresses)
* Save outputs to a file?
* Dispay QR codes?
