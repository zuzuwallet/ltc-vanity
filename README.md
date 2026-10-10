# ltc-vanity

Offline Litecoin mainnet vanity-address generator. It searches locally, checks every winner on a second cryptographic stack, and stores the secret in an encrypted file. It does not talk to a node, an explorer, or an API.

Passing these tests does not make the program appropriate for a large amount of LTC. Read [docs/THREAT.md](docs/THREAT.md) before funding an address.

Do not paste a mnemonic, WIF, xprv, passphrase, scan secret, or spend secret into a chat, an issue, or a website. This repository's tests use published vectors inside the test source. They are not recovery material for a wallet you fund.

## Address families

The address type is always `--type`. The program does not infer it from the text.

| Type | Flag | Target used here | Encoding |
| --- | --- | --- | --- |
| Legacy P2PKH | `p2pkh` | `LZuZu` | Base58Check, version `0x30`, exact case |
| Nested SegWit | `p2sh-p2wpkh` | `M8ZuZu` | Base58Check, version `0x32`, exact case |
| Historical nested prefix | `p2sh-p2wpkh-legacy-prefix` | not a ZuZu default | Base58Check, version `0x05` |
| Native SegWit | `p2wpkh` | `ltc1qzuzu` | Bech32, witness version 0, lowercase |
| Taproot | `p2tr` | `ltc1pzuzu` | Bech32m, witness version 1, tweaked key |
| MWEB | `mweb` | motif `zuzu` | Bech32 HRP `ltcmweb` |

`MZuZu` cannot exist. Version `0x32` only produces second characters `7` through `X`. The collection uses `M8ZuZu`, the earliest `M?ZuZu` string inside that range. `3ZuZu` is also outside the version `0x05` range. `ltc1mwebzuzu` is not an MWEB address. MWEB addresses start with `ltcmweb1`.

Details, derivations, and the measured attempt counts are in [docs/ADDRESSES.md](docs/ADDRESSES.md) and [docs/MWEB.md](docs/MWEB.md). Network bytes and the Litecoin Core commit are in [docs/NETWORK.md](docs/NETWORK.md).

## Commands

```text
ltc-vanity self-test
ltc-vanity analyze --type p2pkh LZuZu
ltc-vanity analyze --type p2sh-p2wpkh MZuZu
ltc-vanity analyze --type p2sh-p2wpkh M8ZuZu
ltc-vanity analyze --type p2wpkh ltc1qzuzu
ltc-vanity analyze --type p2tr ltc1pzuzu
ltc-vanity analyze --type mweb zuzu
ltc-vanity generate --type p2pkh LZuZu --threads 16
ltc-vanity generate --type p2wpkh ltc1qzuzu --hd --threads 16 --output ltc1qzuzu-wallet.json
ltc-vanity generate --type mweb zuzu --threads 16
ltc-vanity inspect <address>
ltc-vanity verify <wallet.json>
ltc-vanity export <wallet.json>
ltc-vanity benchmark --type p2pkh --threads 4
ltc-vanity collection --threads 16
```

`--network` accepts only `mainnet`.

`generate` refuses an unreachable target. Base58 targets keep their case. Bech32 and MWEB targets must be lowercase. Mixed case such as `ltc1qZuZu` is rejected.

Default search for the transparent types draws a fresh scalar from the OS CSPRNG for every attempt. `--hd` walks one BIP39 seed. MWEB has no independent-key mode and rejects `--hd`. It walks the MWEB address index, starting at 2.

A target whose expected attempt count is at least 1,000,000,000 asks you to type `SEARCH`. An HD or MWEB target whose 50% point sits past the index space asks you to type `EXHAUST` first. HD and MWEB difficulty output shows the index-space size, the maximum success probability inside it, and replaces an unreachable quantile with `not reachable within this mnemonic`. The index is then recorded in the wallet. A gap limit of 20 will not find it.

The public address is printed only after the encrypted file is created. `export` prints secrets only after you type `EXPORT` on a terminal, and only when both stdin and stdout are terminals. The Litecoin-versus-Bitcoin key warning is printed before that prompt.

## Wallet file

The file is JSON. The secret payload is encrypted with Argon2id (RFC 9106 second option: 64 MiB, t=3, p=4) and ChaCha20-Poly1305. The file is created with mode `0600`, `O_EXCL`, and `O_NOFOLLOW`. An existing file is not overwritten. Set `umask 077` before you run a search. A new passphrase must be at least 12 characters. That check only stops short accidents.

`verify` decrypts the file and rebuilds the address. It prints `MATCH: YES` when the stored address equals the derived address. It does not print the seed.

## What this machine verified

`ltc-vanity self-test` checks published hash vectors, the secp256k1 generator point, Litecoin-versus-Bitcoin addresses for that point, Bech32 versus Bech32m, the BIP341 tweak, Litecoin WIF version `0xB0`, HD coin type 2, and MWEB address agreement between the libsecp256k1 stack and the k256 stack. On the build used for this tree, the MWEB forum comparison reported a match. If those strings ever disagree with Litecoin Core's source, the Core source is the specification and the build still passes when the two local stacks agree.

`litecoin-cli` was not on `PATH`. Addresses were not verified by Litecoin Core.

Also not verified:

- `validateaddress` against a local chain
- a Core wallet receiving or spending
- descriptor import into Core
- hardware-wallet or Electrum-LTC restoration
- any funded transaction

Litecoin Core at the pinned commit implements consensus Taproot and can decode `ltc1p`. Its wallet output types on that snapshot do not include a Taproot receive type. A `tr()` line in this program is for other software. It is not a claim that Core will import it. Importing the Taproot WIF as a legacy key does not spend the `ltc1p` output. The WIF is the internal key. Spending needs the empty-tree TapTweak.

## Fedora, then offline

Install the toolchain while the network is up. Review `Cargo.toml` and `Cargo.lock` before building. The lockfile is produced by Cargo.

```text
sudo dnf install rust cargo python3 gcc
source "$HOME/.cargo/env"
cd /path/to/ltc-vanity
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo audit
cargo deny check
cargo tree -i rand --locked
cargo build --locked --release
nm -u target/release/ltc-vanity
```

`cargo tree -i rand --locked` should print nothing. `nm -u` should not list `connect`, `getaddrinfo`, or `sendto`.

Disconnect the network after the build. Then:

```text
./target/release/ltc-vanity self-test
./target/release/ltc-vanity analyze --type p2pkh LZuZu
./target/release/ltc-vanity generate --type p2pkh LZuZu --threads 16
./target/release/ltc-vanity verify ./LZuZu-wallet.json
```

Copy the encrypted file and an offline export to media you control. Run a disposable recovery with `verify` before you fund the address. Do not fund an address whose `verify` line is not `MATCH: YES`.

`cargo bench --bench derive` times the miss path. `ltc-vanity benchmark` prints candidates per second for one second. Neither number is a promise about a ZuZu search.

## Layout

- `src/ltc/` transparent addresses, Base58, Bech32, HD, analyzer, inspect
- `src/mweb/` MWEB stealth addresses only
- `src/independent.rs` second stack (`k256`, `bitcoin_hashes`, `bs58`, a local checksum)
- `src/search.rs` workers
- `src/wallet.rs` encrypted file

There is no GPU code.

## License

MIT OR Apache-2.0. Copyright (c) 2026 ZuZu Wallet.

The GitHub repository is the distribution source. This crate is not published to crates.io. `publish = false`.
