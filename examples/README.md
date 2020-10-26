# CLI "Hardware" Wallet Implmentation

**THIS REPOSITORY COMES WITH ZERO GUARANTEES! USE AT YOUR OWN RISK!**

Airgap use is **highly** recommended.
Practice on testnet first!

## Generate Seed Using Seedpicker
Pick 11, 14, 17, 20, or 23 words out of a hat and pass them to `seedpicker.py` with the `firstWords` flag.
Alternatively, you can use [this GUI](https://seedpicker.net/calculator/last-word.html) (only supports 23+1 word seed phrases).

```bash
$ python examples/seedpicker.py --firstWords="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo" --testnet
SECRET INFO
Full mnemonic (with checksum word): zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract
Full mnemonic length (# words): 12

PUBLIC KEY INFO
Network: Testnet
Specter-Desktop Input Format:
  [f7d04090/48h/1h/0h/2h]Vpub5myBTZx9knAMMmypC51gfX2RXnS8rJWKNMUTCwZNxwajq2tKcrj15SPpbJFdYmG5EgUVDA3Gt5UQgUDoCqc5XaYN3iZNZWhFjH9ScbVPnHh
```

Protect your `SECRET INFO` wherever/however you see fit.
Load the `PUBLIC KEY INFO` into `Specter-Desktop` as described [here](https://btcguide.github.io/setup-wallets/paper).

## Verify Your Recieve Addresses

When all your public keys/devices have been added to `Specter-Desktop`, create a watch-only wallet as described [here](https://btcguide.github.io/setup-wallets/coordinate-multisig).

Then follow these steps:
1. Go to your multisig wallet in `Specter-Desktop`, click on the `Settings` tab.
1. Scroll down to `Export To Wallet Software` and click `Export`.
1. Click `Download wallet file.
It will be saved as `yourwalletname.json`.

```bash
$ python examples/verify-multisig-address.py --descriptor=/path/to/yourwalletname.json 
Address #0: tb1qlrjv2ek09g9aplga83j9mfvelnt6qymen9gd49kpezdz2g5pgwnsfmrucp
Address #1: tb1qn2xhgxqxqcs8cl36f7efgg7jvreus4x6959hnc6mfmygnz435dksa39ygr
Address #2: tb1q2lzh628dmylpf9gr869lgyq9fcc9xqat7unpumnmmn5nph6447cs40k7mw
...
```

Confirm this matches what you see on `Specter-Desktop` as well as your other hardware wallets.

Ideally you would verify this on all `n` wallets, but some users may choose to verify this on only `m` wallets.
Read more about this [here](https://btcguide.github.io/verify-receive-address/).

Deposit funds to these addresses once you feel comfortable that you control the corresonding addresses.

## Spend Bitcoin

1. Create an unsigned transaction as described [here](https://btcguide.github.io/send-bitcoin/).
1. Click `Show Transaction Details` and then `Download file`.
It will have a name like `base64_[txid].psbt`

```bash
$ python examples/psbt-signer.py --psbt-file=/path/to/base64_txid.psbt --mnemonic="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract"

Send 2,000 sats to tb1q3ymmeq9x4r5fa05j8fnzl6lmjgnvsfrcz6p956 with a fee of 181 sats (6.03% of spend) by using this SIGNED PSBT:

cHNidP8BAH0CAAAAARVgWQtftdJCzn1Y5lmUcrYswnXIoNNl0kFrflKrSiEhAAAAAAD...
```

Copy the `SIGNED PSBT` and paste it to `Specter-Desktop` by clicking on the `Paste signed transaction`.

Once your transaction has collected `m` signatures, you can click `Send Transaction`.
