// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Litecoin address derivation.
//!
//! The search path is libsecp256k1, `sha2`, `ripemd`, and the `bech32` crate's
//! segwit helper. MWEB uses BLAKE3 and the unlimited Bech32 path. The
//! independent check uses `k256`, `bitcoin_hashes`, and `bs58`.

pub(crate) mod address;
pub(crate) mod analyze;
pub(crate) mod base58;
pub(crate) mod hash;
pub(crate) mod hd;
pub(crate) mod inspect;
pub(crate) mod keys;
pub(crate) mod kind;
pub(crate) mod network;
mod uint;
pub(crate) mod witness;

pub use address::{
    derive_transparent, descriptor_for, encode_wif, p2pkh_address, p2sh_p2wpkh_address,
    p2tr_address, p2wpkh_address, p2wpkh_redeem, Derived,
};
pub use analyze::{
    analyze, difficulty_text, finite_block, group_digits, require_searchable, Analysis,
    CONFIRMATION_THRESHOLD,
};
pub use hash::hash160;
pub use hd::{
    derive_path, format_path, mnemonic_from_entropy, seed_from_entropy, transparent_steps,
    GAP_LIMIT, HARDENED,
};
pub use inspect::inspect;
pub use keys::{random_entropy_32, random_scalar, KeyEngine};
pub use kind::{AddressKind, SearchMode};
pub use network::Network;
