// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline Litecoin mainnet vanity address generator.
//!
//! Each receiving-address family has its own encoder. MWEB is not SegWit and
//! not Taproot. Bitcoin mainnet constants are present only so tests can prove
//! this generator did not use them.

#![forbid(unsafe_code)]

pub mod error;
mod hexutil;
mod independent;
pub mod ltc;
pub mod mweb;
pub mod search;
mod secret;
pub mod self_test;
pub mod verify;
pub mod wallet;

pub use error::Error;
pub use ltc::{
    analyze, derive_transparent, difficulty_text, encode_wif, finite_block, group_digits, inspect,
    require_searchable, AddressKind, Analysis, KeyEngine, Network, SearchMode,
    CONFIRMATION_THRESHOLD, GAP_LIMIT, HARDENED,
};
pub use search::{
    counter_would_overflow, measure_miss_rate, search, search_collection, validate_threads,
    CollectionHit, CollectionRequest, SearchHit, SearchRequest, MAX_THREADS,
};
pub use self_test::{litecoin_core_status, mweb_forum_status, run_self_tests};
pub use verify::confirm_material;
pub use wallet::{
    check_new_passphrase, check_passphrase, export_wallet_text, open_and_verify, private_umask,
    write_encrypted_wallet, KdfParams, OpenedWallet, WalletMaterial, LITECOIN_KEY_REUSE_WARNING,
    MIN_NEW_PASSPHRASE_CHARS,
};
