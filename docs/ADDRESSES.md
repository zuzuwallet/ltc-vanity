# Transparent address engines

Each family has its own encoder. A fast prefix compare is accepted only when it agrees with the full reference encoding. The check stack (`k256`, `bitcoin_hashes`, `bs58`, and a local Bech32 checksum) must rebuild the same address. Curve arithmetic stays inside libsecp256k1 and k256.

Private keys are compressed. An uncompressed public key is not produced.

## P2PKH

```text
secret scalar
  -> compressed pubkey
  -> HASH160 = RIPEMD-160(SHA-256(pubkey))
  -> version 0x30 || HASH160
  -> Base58Check
  -> L...
```

Primary target: `LZuZu`.

The fixed protocol prefix is `L`. The vanity portion is `ZuZu`. Probability is the count of 25-byte version||HASH160||checksum integers whose Base58 encoding starts with `LZuZu`, divided by 2^160. It is not 58^4.

Measured by `analyze`:

| Target | Reachable | Expected attempts |
| --- | --- | --- |
| `L` | yes | 1 |
| `LZuZu` | yes | 4,553,521 |
| `Lzuzu` | no | outside version `0x30` |

50% / 90% / 99% for `LZuZu`: 3,156,260 / 10,484,869 / 20,969,737. Those use `ceil(ln(1-p) / ln(1-q))`.

Watch-only descriptor: `pkh(<compressed pubkey>)`.

## P2SH-P2WPKH

```text
compressed pubkey
  -> HASH160
  -> redeem script 0x00 0x14 || HASH160
  -> HASH160(redeem script)
  -> version 0x32 || that hash
  -> Base58Check
  -> M...
```

The private key spends the embedded P2WPKH. The search does not grind an arbitrary redeem script.

`MZuZu` is unreachable. Version `0x32` runs from `M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF` through `MXEmDYChDCdgi77RFPzFjPt86j97FwkV8a`. `Z` is past `X`.

`M8ZuZu` is inside the bucket. Expected attempts: 264,104,224. That is not 58^5. 50% / 90% / 99%: 183,063,098 / 608,122,449 / 1,216,244,897.

The collection uses `M8ZuZu` for that reason.

Watch-only descriptor: `sh(wpkh(<compressed pubkey>))`.

## Historical 3... prefix

Same redeem script, version byte `0x05`. Flag: `--type p2sh-p2wpkh-legacy-prefix`. It is not the default.

`3ZuZu` is unreachable. The bucket is `31h1vYVSYuKP6AhS86fbRdMw9XHiZAvAaj` through `3R2cuenjG5nFubqX9Wzuukdin2YfGQVzu4`. The version byte is Bitcoin's P2SH byte. `inspect` says so when the checksum is valid.

## P2WPKH

```text
compressed pubkey
  -> HASH160 (20 bytes)
  -> witness version 0
  -> HRP ltc
  -> Bech32
  -> ltc1q...
```

20 bytes is 160 bits, which is 32 groups of 5 bits. There is no padding inside the program. Each vanity character after `ltc1q` is one of those groups.

`ltc1qzuzu` is exactly 2^-20. Expected attempts: 1,048,576. 50% / 90% / 99%: 726,818 / 2,414,435 / 4,828,869. Here 32^4 is the same number, because four aligned 5-bit symbols were checked against the program layout. The six-character checksum is not part of the target.

Mixed case is invalid. All-uppercase can checksum under BIP173 and is still rejected as a generate target.

The fast compare for this four-character target checks that HASH160 begins with `0x1705` and that `byte[2] & 0xF0 == 0xC0`. A hit is re-encoded and must `starts_with` the target.

Watch-only descriptor: `wpkh(<compressed pubkey>)`.

## P2TR

```text
secret scalar
  -> compressed public key
  -> if Y is odd, negate the scalar
  -> x-only internal key P
  -> t = tagged hash "TapTweak" of P (empty script tree)
  -> Q = P + t·G
  -> x-only of Q
  -> witness version 1
  -> HRP ltc
  -> Bech32m
  -> ltc1p...
```

The tagged hash is SHA-256(SHA-256("TapTweak") || SHA-256("TapTweak") || P). The tweak is rejected when it is not a scalar below the curve order. Encoding the untweaked internal key fails the self-test: that string must differ from the address.

256 program bits become 52 five-bit symbols, and the last symbol is padded. The first 51 symbols are uniform. `ltc1pzuzu` uses the first 20 bits of the tweaked key, so it is also exactly 2^-20, and only after the tweak. The 52nd symbol is not a free vanity character.

Watch-only descriptor: `tr(<x-only internal key>)`, BIP386. The internal key is not the output key. Litecoin Core on commit `ec1b6489` decodes `ltc1p` and does not offer Taproot as a wallet receive type. `IsMine` on that snapshot does not treat a taproot output as ours. This `tr()` line is for other software.

An odd original public key is stored as the even-Y internal key. The X coordinate matches. The `0x03` prefix does not.

## WIF

Version `0xB0`, 32-byte secret, compressed marker `0x01`, Base58Check. `generate`, `analyze`, `inspect`, `self-test`, and the benchmark do not print it. `export` prints it after `EXPORT`, with the Bitcoin version warning above that prompt. The same scalar's Bitcoin WIF uses `0x80` and must differ.

For Taproot, that WIF is the internal secret. A legacy `importprivkey` does not spend the `ltc1p` output.

## HD

Optional `--hd`. One 256-bit BIP39 entropy value from the OS CSPRNG. Paths, account 0, external branch 0:

| Family | Path |
| --- | --- |
| P2PKH | `m/44'/2'/0'/0/index` |
| Nested, both version bytes | `m/49'/2'/0'/0/index` |
| P2WPKH | `m/84'/2'/0'/0/index` |
| P2TR | `m/86'/2'/0'/0/index` |

Coin type 2 is SLIP-0044. These are not Bitcoin paths with the coin field edited, and they are not Core's older internal `m/0'/0'/k'`. The non-hardened index stops at 2^31-1. Workers take disjoint index ranges.

`m/86'` is the path BIP86 wallets use. Core on this snapshot does not hand out `tr()` addresses itself.

A vanity hit can land at a high index. The wallet records the scheme, path, account, branch, and index. The automated recovery test derives that index from the encrypted seed and requires the address to match. Scanning only the first 20 external addresses does not find index 100 in that test, and it will not find an index such as 728,419,382. Restoring the seed without the path is not a restore of the vanity address.

BIP32 extended public keys use Core's `xpub` bytes. The secret extended form is not printed.

## Difficulty formula

Base58 probabilities come from the integer overlap of the target prefix with the 2^160 payload bucket. Witness and MWEB probabilities come from the 5-bit groups that the encoding actually fixes. `analyze` prints the note that applies. A target with no overlap exits non-zero and is not searched.
