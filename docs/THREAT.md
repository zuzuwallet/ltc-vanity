# Threat model

This program grinds Litecoin addresses on one Fedora machine and writes an encrypted file. A green test run is not a statement that the result is safe to fund with a large amount of LTC.

## What the design tries to hold

- Entropy for seeds and private keys comes from the OS CSPRNG (`getrandom`). Targets, timestamps, counters, and thread ids are not secrets and are not used as secrets.
- Invalid scalars are discarded. They are not wrapped into range and they are not counted.
- Two implementations must agree before a wallet is written: libsecp256k1 plus the reference encoders, and k256 plus `bitcoin_hashes` and `bs58`.
- The encrypted file uses Argon2id and ChaCha20-Poly1305. The KDF parameters, salt, nonce, and metadata are authenticated. A fast test KDF is rejected by the production opener.
- The file is created mode `0600`, without following a symlink, and without replacing an existing file.
- Secrets are not command-line arguments. `export` requires a terminal on stdin and stdout and the word `EXPORT`.
- The process does not open a network connection to derive an address.

## What can still go wrong

Compromised Fedora installation. A modified kernel, `getrandom`, or this binary can keep every key. Review the source and build it yourself. Prefer a machine that does not run other people's software during the search.

Malicious Cargo dependency or a compromised Rust toolchain. `Cargo.lock` pins versions. `cargo deny` and `cargo audit` report the tree that was locked. They do not prove the crates are correct. `rand` is not a direct dependency. `rand_core` can still appear transitively. Do not add a dependency that fetches entropy from the network.

RNG failure. If `getrandom` fails, the search stops. A generator that returned predictable bytes would not be detected by the address-agreement tests.

secp256k1 bugs. The search uses the `secp256k1` crate. The check uses `k256`. Agreement reduces the chance that one library's point code is silently wrong. It does not cover a bug present in both.

Wrong Litecoin constants, or a Bitcoin address by mistake. Constants are taken from Litecoin Core commit `ec1b6489a900d09cf5991e220dce089c77a232a2` and checked in `self-test`. Same-scalar tests require the Litecoin P2PKH, WIF, and `ltc1q` results to differ from Bitcoin. P2SH version `0x05` and the `xpub` version bytes are shared with Bitcoin on purpose. The export warning says that. An `xpub` does not name the coin.

Base58Check bugs and Bech32 versus Bech32m confusion. Checksum tests and swapped-constant tests cover the difference between `ltc1q` and `ltc1p`. A prefix matcher must match the reference string on random keys before it can accept a candidate.

Taproot tweak mistakes. The address is the tweaked output key. A test fails if the untweaked internal key encodes to the same string. Core on this snapshot will not treat the output as a wallet output. Spending still requires a Taproot-aware signer and the internal key plus the empty-tree tweak.

HD path mistakes. Paths use coin type 2 and the purpose numbers 44, 49, 84, and 86. MWEB uses `m/0'/100'/0'` and `m/0'/100'/1'`. A wallet that scans a different path will not see the coins.

High-index recovery. The child index or MWEB index can be far past a gap limit of 20. The file stores the path and the index. Losing that metadata while keeping only the seed can make the address unrecoverable in ordinary wallet software. `verify` checks the recorded index. It does not scan the whole space.

MWEB implementation errors. The engine follows the Core functions named in `docs/MWEB.md`. It was not checked by running Litecoin Core. A mistake in the hash domain, the index endianness, or the payload order would create addresses Core cannot spend. The second stack repeats the preimage construction instead of calling the first module's function. That catches a transcription error. It does not catch a shared misreading of Core.

Mnemonic, WIF, and passphrase exposure. Export prints them. Terminal scrollback, shell history, screenshots, and clipboard tools can keep them. The program does not copy to the clipboard. Memory scraping, swap, and core dumps can still read process memory. Encrypted swap and a disabled core dump reduce that. They are operating-system settings, not features of this binary.

Wallet-password compromise and backup compromise. Argon2id slows guessing. It does not help if the passphrase is short, reused, or stored next to the file. A stolen file plus a stolen passphrase is the seed.

Vanity reuse and linkability. A recognizable address is easier to connect across sites. That includes an MWEB address. Vanity does not add privacy. See `docs/MWEB.md`.

Insufficient independent verification. `litecoin-cli` was not present when this tree was built. No Core `validateaddress`, descriptor import, or signed transaction was run. Do not treat a local Rust agreement as a Core agreement. Before funding, verify the public address with a Litecoin Core you built yourself, offline, and spend a small test amount first if you choose to fund it at all.

## Out of scope

GPU search, testnet generation, remote RPC, and a web service. A later GPU would still have to return a candidate to the CPU, rebuild it with the reference code, and check it on the second stack before a wallet could be written.
