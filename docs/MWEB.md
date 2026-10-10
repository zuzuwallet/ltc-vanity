# MWEB

MWEB is a separate engine in `src/mweb/`. It is not produced by changing a P2WPKH or Taproot encoder.

Source: Litecoin Core commit `ec1b6489a900d09cf5991e220dce089c77a232a2`, `Keychain::GetSpendKey`, `Keychain::GetStealthAddress`, and `LoadMWEBKeychain` in `wallet/scriptpubkeyman.cpp`.

## Address

HRP: `ltcmweb`. Checksum: Bech32, not Bech32m. The string is longer than BIP173's 90-character limit, so decode uses the extended-length path.

Payload: 66 bytes. Scan pubkey `A_i` (33) then spend pubkey `B_i` (33). Both are compressed secp256k1 points. The data part is the version symbol `q` (value 0) plus the 8-to-5 conversion of those 66 bytes. 528 bits is 105 groups of 5 with 3 bits left, so the last symbol contains 2 zero padding bits. Decode rejects non-zero padding. The `bech32` crate's leftover-bit helper is not used to validate this payload.

```text
mi = SecretKey::FromHash(BLAKE3('A' || uint32_le(index) || scan_secret))
b_i = spend_secret + mi
B_i = b_i·G
A_i = scan_secret · B_i
address = Bech32("ltcmweb", version 0 || convertbits(A_i || B_i))
```

`FromHash` keeps the 32-byte hash when it is already a non-zero scalar below the curve order. Otherwise it rehashes `BLAKE3("MWEB hash-to-scalar" || hash || uint32_le(counter))`. Scalar addition is libsecp256k1 tweak-add. A sum of zero is not an address and is not counted as an attempt.

Master keys, from the same BIP39 seed as the transparent HD tree:

- scan secret at `m/0'/100'/0'`
- spend secret at `m/0'/100'/1'`

Purpose 100 is `KeyPurpose::MWEB` in this Core commit. Older paths `m/1/0/100'` and `m/1/0/101'` are not used.

Index 0 is change. Index 1 is peg-in. Receive grinding starts at index 2. The index is a `uint32` in the BLAKE3 input. It is not a BIP32 child, so it is not capped at 2^31. The search stops at 2^32-1. Core will not scan a large index by itself. The wallet records both hardened paths and the index.

There is no independent-key vanity mode. Grinding does not draw new spend secrets, and it does not shrink the seed. `--hd` is rejected because the index walk is already the MWEB mode.

There is no Bitcoin-style output descriptor. The public record is the address, the two paths, and the index.

## Where `zuzu` can sit

Charset: `qpzry9x8gf2tvdw0s3jn54khce6mua7l`. `q` is 0, `z` is 2, `u` is 28.

A compressed scan key starts with `0x02` or `0x03`. After `ltcmweb1` the version symbol is `q`. The next symbol is also `q`, because those version bits plus the start of a compressed key only produce that symbol. The third symbol is one of `g f 2 t v d w 0`. `z` is not in that set.

Unreachable:

- `ltc1mwebzuzu`
- `ltcmweb1zuzu`
- `ltcmweb1qzuzu`
- `ltcmweb1qqzuzu`

Earliest motif: `ltcmweb1qq` + one of those eight characters + `zuzu`. The eight third characters are all legal, so the motif `zuzu` is not charged for that symbol. An enumeration of the first four payload bytes finds 32 windows in 2^25 where the following four symbols are `zuzu`, which is 2^-20. `analyze --type mweb zuzu` reports expected attempts 1,048,576.

One chosen third character, `ltcmweb1qqgzuzu`, costs the 3-bit third symbol plus 20 bits, which is 2^-23. Expected attempts: 8,388,608. The sample bytes `02 05 c1 70` encode as `ltcmweb1qqgzuzu` at the start of the data part. The checksum does not change a prefix probability.

`analyze --type mweb zuzu` places the motif at that earliest offset. A full `ltcmweb1...` string is analyzed as a prefix instead.

## Recovery

The encrypted file holds the seed and the index. `verify` derives that index on both stacks. The unit test uses index 100, drops the working material, opens the file, and checks the address. Indices 0 and 1 are refused as receive targets. A restored Core wallet that only looks near the tip will not see a high index. The path line is required.

The self-test also compares three published MWEB forum vectors. Key material for those vectors stays in the test source. On this tree the forum status was "matches the published strings." A later mismatch does not override the Core source above. The build fails if the two local stacks disagree.

## Privacy

MWEB hides transaction amounts and the link between inputs and outputs inside the extension block, from nodes that do not hold the scan key. A stealth address still has a public encoding. Publishing `ltcmweb1qq…zuzu…` publishes a string people can recognize.

That recognition is the point of a vanity address. It does not improve privacy. Anyone who sees the address can store it, search for it, and connect the payments a sender makes to it. Reusing the address links those payments to the same recipient in the eyes of anyone who was given the address, including people who cannot otherwise scan the extension block.

The scan key identifies outputs. The spend key spends them. This generator does not print either scalar. Export prints the mnemonic and the index, not the raw scalars. The index is not secret from someone who already has the mnemonic: they can recompute it. Publishing the index without the mnemonic tells a watcher which counter was used. It does not reveal the keys. It does tell a later restorer, and anyone who sees the wallet file's public path line, that the address was not one of the first few receive indices.

Vanity search walks the index of one normal keychain. It does not weaken the scan or spend secrets. A recognizable address is easier to correlate across chats, exchanges, and donation pages. Treat that as a linkability choice.
