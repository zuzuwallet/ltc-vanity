# Litecoin mainnet parameters

Source: Litecoin Core `src/chainparams.cpp`, `CMainParams`, commit `ec1b6489a900d09cf5991e220dce089c77a232a2`.

These are the bytes this generator uses. Bitcoin mainnet bytes are in the source only so tests can show the Litecoin result is different.

`litecoin.info` lists MWEB HRP `ltc1mweb` and BIP32 public version `0x0488B2E4`. Those values are not in this Core commit. Core uses HRP `ltcmweb` and public version `0x0488B21E`.

Some older write-ups give WIF versions `0x36` and `0x37`. This Core commit sets `SECRET_KEY` to 176 (`0xB0`).

## Mainnet

| Item | Value |
| --- | --- |
| P2PKH version | `0x30` (`L...`) |
| P2SH modern (`SCRIPT_ADDRESS2`) | `0x32` (`M...`) |
| P2SH historical (`SCRIPT_ADDRESS`) | `0x05` (`3...`) |
| WIF version | `0xB0`, compressed marker `0x01` |
| Bech32 HRP | `ltc` |
| MWEB HRP | `ltcmweb` |
| BIP32 public / secret | `0x0488B21E` / `0x0488ADE4` (`xpub` / `xprv`) |
| SLIP-0044 coin type | 2 |
| HMAC key for the master | ASCII `Bitcoin seed` |
| Genesis | `12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2` |
| Segwit height | 1,201,536 |
| Taproot deployment bit 2 | start 2,161,152, timeout 2,370,816 |
| MWEB deployment bit 4 | start 2,217,600, timeout 2,427,264 |
| MWEB peg-out feature height | 3,154,440 |
| MWEB extra-data feature height | 3,172,640 |
| Message start | `fbc0b6db` |
| Default port | 9333 |

SLIP-0132 `Ltpv` (`0x019d9cfe`) and `Ltub` (`0x019da462`) are not what this Core commit writes. This program does not export them. An `xpub` from Core does not identify itself as Litecoin.

The historical P2SH version `0x05` and the BIP32 version bytes are the same bytes Bitcoin uses. A `3...` address is not evidence of the network by itself. `inspect` still checks the checksum and reports that version.

## Version-byte ranges

Every mainnet P2PKH, modern P2SH, and legacy P2SH payload in these version bytes encodes to 34 characters. The inclusive Base58 endpoints are:

| Version | First address | Last address | Second character |
| --- | --- | --- | --- |
| `0x30` | `LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ` | `LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVt` | `K` through `i` |
| `0x32` | `M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF` | `MXEmDYChDCdgi77RFPzFjPt86j97FwkV8a` | `7` through `X` |
| `0x05` | `31h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj` | `3R2cuenjG5nFubqX9Wzuukdin2YfGQVzu4` | `1` through `R` |

`LZuZu` sits inside the `0x30` range. `Lzuzu` does not: Base58 puts `Z` before the lowercase letters, and `z` is past this bucket. `MZuZu` and `3ZuZu` do not sit inside their buckets.

## Other networks, not generated

Testnet, same commit: P2PKH 111, modern P2SH 58, legacy P2SH 196, WIF 239, HRP `tltc`, MWEB HRP `tmweb`, BIP32 `0x043587CF` / `0x04358394`.

Regtest: HRP `rltc`, MWEB HRP `tmweb`, P2PKH 111.

## Bitcoin bytes used only as a negative test

P2PKH `0x00`, WIF `0x80`, HRP `bc`, coin type 0. The generator key (scalar 1) must produce Bitcoin P2PKH `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` on the check stack and a different `L...` address on the Litecoin path. The HASH160 of that compressed generator point is `751e76e8199196d454941c45d1b3a323f1433bd6`. The Bitcoin P2WPKH of that hash is `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`. Replacing `bc` with `ltc` in that string is not a Litecoin address. The checksum covers the HRP.

## Witness checksum

Witness version 0 uses Bech32. Witness version 1 uses Bech32m. Swapping the checksum constant makes `inspect` report the address invalid. MWEB uses Bech32, not Bech32m, and its strings are longer than the 90-character BIP173 limit. The SegWit decoder does not accept an MWEB payload.
