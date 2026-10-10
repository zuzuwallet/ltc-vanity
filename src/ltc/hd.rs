// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Litecoin BIP32 / BIP39.
//!
//! HMAC key is the ASCII string `Bitcoin seed`, because Litecoin Core uses
//! Bitcoin's BIP32. Version bytes are Core's `xpub` / `xprv` bytes, which are
//! the same four bytes Bitcoin uses. SLIP-0132 `Ltub` / `Ltpv` are not used.
//!
//! Transparent receive paths use SLIP-0044 coin type 2:
//! `m/44'/2'/account'/0/index`, `m/49'/2'/…`, `m/84'/2'/…`, `m/86'/2'/…`.
//! That is not Core's internal legacy path `m/0'/0'/k'`.
//!
//! MWEB masters, from `doc/mweb/stealth-addresses.md` and
//! `LoadMWEBKeychain` in the pinned commit: scan `m/0'/100'/0'`, spend
//! `m/0'/100'/1'`. The address index is not a BIP32 child index.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::ltc::keys::KeyEngine;
use crate::ltc::kind::AddressKind;
use crate::ltc::network::{BIP32_PUBLIC, COIN_TYPE};

pub const HARDENED: u32 = 0x8000_0000;
pub const GAP_LIMIT: u32 = 20;
/// `KeyPurpose::MWEB` in the pinned `scriptpubkeyman.cpp`.
pub const MWEB_PURPOSE: u32 = 100;

#[derive(Clone)]
pub struct HdNode {
    pub depth: u8,
    pub child_number: u32,
    pub parent_fingerprint: [u8; 4],
    chain_code: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for HdNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdNode")
            .field("depth", &self.depth)
            .field("child_number", &self.child_number)
            .field("key", &"[redacted]")
            .field("chain_code", &"[redacted]")
            .finish()
    }
}

impl HdNode {
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn from_private(
        key: Zeroizing<[u8; 32]>,
        chain_code: Zeroizing<[u8; 32]>,
        depth: u8,
    ) -> Self {
        Self {
            depth,
            child_number: 0,
            parent_fingerprint: [0; 4],
            chain_code,
            key,
        }
    }
}

pub fn master_from_seed(seed: &[u8]) -> Result<HdNode, Error> {
    if !(16..=64).contains(&seed.len()) {
        return Err(Error::Index);
    }
    let mut mac = hmac_sha512(b"Bitcoin seed", seed)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&mac[..32]);
    chain.copy_from_slice(&mac[32..]);
    mac.zeroize();
    let engine = KeyEngine::new()?;
    engine.public_of(key.as_slice())?;
    Ok(HdNode {
        depth: 0,
        child_number: 0,
        parent_fingerprint: [0; 4],
        chain_code: chain,
        key,
    })
}

pub fn derive_index(engine: &KeyEngine, parent: &HdNode, index: u32) -> Result<HdNode, Error> {
    let mut data = Zeroizing::new(Vec::with_capacity(37));
    if index >= HARDENED {
        data.push(0x00);
        data.extend_from_slice(parent.key.as_slice());
    } else {
        let public = engine.public_of(parent.key.as_slice())?;
        data.extend_from_slice(&public.key);
    }
    data.extend_from_slice(&index.to_be_bytes());
    let mut mac = hmac_sha512(parent.chain_code.as_slice(), &data)?;
    let mut tweak = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    tweak.copy_from_slice(&mac[..32]);
    chain.copy_from_slice(&mac[32..]);
    mac.zeroize();
    let child_key = engine.add_scalar(parent.key.as_slice(), &tweak)?;
    let public = engine.public_of(parent.key.as_slice())?;
    let ripe = crate::ltc::hash::hash160(&public.key);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&ripe[..4]);
    let depth = parent.depth.checked_add(1).ok_or(Error::Index)?;
    Ok(HdNode {
        depth,
        child_number: index,
        parent_fingerprint: fingerprint,
        chain_code: chain,
        key: child_key,
    })
}

pub fn transparent_steps(kind: AddressKind, account: u32, index: u32) -> Result<[u32; 5], Error> {
    if account >= HARDENED || index >= HARDENED {
        return Err(Error::Index);
    }
    let purpose = kind.purpose().ok_or(Error::Index)?;
    Ok([
        purpose | HARDENED,
        COIN_TYPE | HARDENED,
        account | HARDENED,
        0,
        index,
    ])
}

pub fn mweb_scan_steps() -> [u32; 3] {
    [HARDENED, MWEB_PURPOSE | HARDENED, HARDENED]
}

pub fn mweb_spend_steps() -> [u32; 3] {
    [HARDENED, MWEB_PURPOSE | HARDENED, 1 | HARDENED]
}

pub fn format_path(steps: &[u32]) -> String {
    let mut out = String::from("m");
    for step in steps {
        if step & HARDENED == 0 {
            out.push_str(&format!("/{step}"));
        } else {
            out.push_str(&format!("/{}'", step & !HARDENED));
        }
    }
    out
}

pub fn derive_path(engine: &KeyEngine, master: &HdNode, steps: &[u32]) -> Result<HdNode, Error> {
    let mut node = master.clone();
    for step in steps {
        node = derive_index(engine, &node, *step)?;
    }
    Ok(node)
}

pub fn mnemonic_from_entropy(entropy: &[u8; 32]) -> Result<Zeroizing<String>, Error> {
    let mnemonic = bip39::Mnemonic::from_entropy(entropy).map_err(|_| Error::Index)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

pub fn seed_from_entropy(entropy: &[u8]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let entropy: &[u8; 32] = entropy.try_into().map_err(|_| Error::Index)?;
    let mnemonic = bip39::Mnemonic::from_entropy(entropy).map_err(|_| Error::Index)?;
    let seed = mnemonic.to_seed("");
    Ok(Zeroizing::new(seed))
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| Error::Index)?;
    mac.update(data);
    let mut bytes = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

/// Extended public key. The chain code is public BIP32 material.
pub fn encode_xpub(node: &HdNode, engine: &KeyEngine) -> Result<String, Error> {
    let public = engine.public_of(node.key_bytes())?;
    let mut body = Vec::with_capacity(78);
    body.extend_from_slice(&BIP32_PUBLIC);
    body.push(node.depth);
    body.extend_from_slice(&node.parent_fingerprint);
    body.extend_from_slice(&node.child_number.to_be_bytes());
    body.extend_from_slice(node.chain_code());
    body.extend_from_slice(&public.key);
    Ok(crate::ltc::base58::base58check_encode(&body))
}

pub fn xprv_version_prefix() -> [u8; 4] {
    crate::ltc::network::BIP32_SECRET
}

/// External branch parent `m/purpose'/2'/account'/0`.
pub fn external_parent(
    engine: &KeyEngine,
    seed: &[u8],
    kind: AddressKind,
    account: u32,
) -> Result<HdNode, Error> {
    let master = master_from_seed(seed)?;
    let steps = transparent_steps(kind, account, 0)?;
    derive_path(engine, &master, &steps[..4])
}

pub fn child_at(
    engine: &KeyEngine,
    seed: &[u8],
    kind: AddressKind,
    account: u32,
    index: u32,
) -> Result<HdNode, Error> {
    let master = master_from_seed(seed)?;
    let steps = transparent_steps(kind, account, index)?;
    derive_path(engine, &master, &steps)
}

/// Addresses at external indices `0..limit`. A gap limit this small misses a high vanity index.
pub fn scan_gap(
    engine: &KeyEngine,
    seed: &[u8],
    kind: AddressKind,
    account: u32,
    limit: u32,
) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for index in 0..limit {
        let child = child_at(engine, seed, kind, account, index)?;
        let derived = crate::ltc::address::derive_transparent(engine, kind, child.key_bytes())?;
        out.push(derived.address);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        encode_xpub, format_path, master_from_seed, mweb_scan_steps, mweb_spend_steps,
        transparent_steps, xprv_version_prefix, HARDENED,
    };
    use crate::ltc::keys::KeyEngine;
    use crate::ltc::kind::AddressKind;
    use crate::ltc::network::{BIP32_PUBLIC, BIP32_PUBLIC_WIKI_TYPO, SLIP132_LTUB};

    #[test]
    fn bip32_vector_1_master_matches_the_published_key_bytes() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let master = master_from_seed(&seed).unwrap();
        assert_eq!(
            master.key_bytes(),
            &[
                0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93,
                0xc9, 0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17,
                0xc8, 0x43, 0x6b, 0x35
            ]
        );
        let engine = KeyEngine::new().unwrap();
        let xpub = encode_xpub(&master, &engine).unwrap();
        assert!(xpub.starts_with("xpub"));
        assert_eq!(BIP32_PUBLIC, [0x04, 0x88, 0xB2, 0x1E]);
        assert_ne!(BIP32_PUBLIC, BIP32_PUBLIC_WIKI_TYPO);
        assert_ne!(BIP32_PUBLIC, SLIP132_LTUB);
        assert_eq!(xprv_version_prefix(), [0x04, 0x88, 0xAD, 0xE4]);
    }

    #[test]
    fn paths_use_coin_type_2_and_mweb_uses_purpose_100() {
        let steps = transparent_steps(AddressKind::P2pkh, 0, 0).unwrap();
        assert_eq!(format_path(&steps), "m/44'/2'/0'/0/0");
        assert_eq!(
            format_path(&transparent_steps(AddressKind::P2wpkh, 0, 7).unwrap()),
            "m/84'/2'/0'/0/7"
        );
        assert_eq!(
            format_path(&transparent_steps(AddressKind::P2tr, 0, 0).unwrap()),
            "m/86'/2'/0'/0/0"
        );
        assert_ne!(format_path(&steps), "m/44'/0'/0'/0/0");
        assert_ne!(format_path(&steps), "m/0'/0'/0'");
        assert_eq!(format_path(&mweb_scan_steps()), "m/0'/100'/0'");
        assert_eq!(format_path(&mweb_spend_steps()), "m/0'/100'/1'");
        assert!(transparent_steps(AddressKind::P2pkh, 0, HARDENED).is_err());
    }
}
