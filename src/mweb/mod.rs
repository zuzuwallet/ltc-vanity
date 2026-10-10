// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Litecoin MWEB stealth addresses.
//!
//! This is not SegWit and not Taproot. The rules are `Keychain::GetSpendKey`
//! and `Keychain::GetStealthAddress` from Litecoin Core commit
//! `ec1b6489a900d09cf5991e220dce089c77a232a2`:
//!
//! ```text
//! mi = SecretKey::FromHash(BLAKE3('A' || uint32_le(index) || scan_secret))
//! b_i = spend_secret + mi
//! B_i = b_i·G
//! A_i = scan_secret·B_i
//! address = Bech32("ltcmweb", version 0 || convertbits(A_i || B_i))
//! ```
//!
//! `SecretKey::FromHash` uses the 32-byte hash when it is already a valid
//! scalar. Otherwise it retries BLAKE3("MWEB hash-to-scalar" || hash ||
//! uint32_le(counter)). Addition is `secp256k1_ec_privkey_tweak_add`, which
//! rejects a tweak that is not a scalar and a sum that is zero.
//!
//! `LoadMWEBKeychain` marks index 0 as change and index 1 as peg-in before any
//! user address exists. Receive grinding starts at index 2. The index is a
//! counter in the hash, not a private key.

use secp256k1::SecretKey;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::ltc::hd::{
    derive_path, format_path, master_from_seed, mweb_scan_steps, mweb_spend_steps, HdNode,
};
use crate::ltc::keys::KeyEngine;
use crate::ltc::witness::{compressed_pair, encode_mweb};

/// First index that is neither the reserved change address nor the peg-in address.
pub const FIRST_RECEIVE_INDEX: u32 = 2;

pub const ADDRESS_DOMAIN: u8 = b'A';
const HASH_TO_SCALAR_TAG: &[u8] = b"MWEB hash-to-scalar";

#[derive(Clone)]
pub struct Stealth {
    pub scan_pub: [u8; 33],
    pub spend_pub: [u8; 33],
    pub payload: [u8; 66],
    pub address: String,
    spend_scalar: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Stealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stealth")
            .field("address", &self.address)
            .field("spend_scalar", &"[redacted]")
            .finish()
    }
}

impl Stealth {
    pub fn spend_scalar(&self) -> &[u8; 32] {
        &self.spend_scalar
    }
}

fn accept_scalar(bytes: &[u8; 32]) -> bool {
    match SecretKey::from_slice(bytes) {
        Ok(mut secret) => {
            secret.non_secure_erase();
            true
        }
        Err(_) => false,
    }
}

pub fn hash_to_scalar(hash: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if accept_scalar(hash) {
        return Ok(Zeroizing::new(*hash));
    }
    let mut counter = 0u32;
    for _ in 0..1024 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(HASH_TO_SCALAR_TAG);
        hasher.update(hash);
        hasher.update(&counter.to_le_bytes());
        let digest = Zeroizing::new(*hasher.finalize().as_bytes());
        counter = counter.checked_add(1).ok_or(Error::InvalidKey)?;
        if accept_scalar(&digest) {
            return Ok(digest);
        }
    }
    Err(Error::InvalidKey)
}

pub fn address_preimage(index: u32, scan_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[ADDRESS_DOMAIN]);
    hasher.update(&index.to_le_bytes());
    hasher.update(scan_secret);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

pub fn spend_scalar(
    engine: &KeyEngine,
    spend_secret: &[u8; 32],
    scan_secret: &[u8; 32],
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let preimage = address_preimage(index, scan_secret);
    let mi = hash_to_scalar(&preimage)?;
    engine.add_scalar(spend_secret, &mi)
}

pub fn stealth_at(
    engine: &KeyEngine,
    scan_secret: &[u8; 32],
    spend_secret: &[u8; 32],
    index: u32,
) -> Result<Stealth, Error> {
    let spend_scalar = spend_scalar(engine, spend_secret, scan_secret, index)?;
    let spend_pub = engine.public_of(spend_scalar.as_slice())?.key;
    let scan_pub = engine.mul_point(&spend_pub, scan_secret)?;
    let mut payload = [0u8; 66];
    payload[..33].copy_from_slice(&scan_pub);
    payload[33..].copy_from_slice(&spend_pub);
    if !compressed_pair(&payload) {
        return Err(Error::InvalidKey);
    }
    let address = encode_mweb(&payload)?;
    Ok(Stealth {
        scan_pub,
        spend_pub,
        payload,
        address,
        spend_scalar,
    })
}

pub struct MwebMasters {
    pub scan: Zeroizing<[u8; 32]>,
    pub spend: Zeroizing<[u8; 32]>,
    pub scan_node: HdNode,
    pub spend_node: HdNode,
}

impl std::fmt::Debug for MwebMasters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MwebMasters")
            .field("scan", &"[redacted]")
            .field("spend", &"[redacted]")
            .finish()
    }
}

pub fn mweb_record(index: u32) -> String {
    format!(
        "scan {} spend {} index {index}",
        format_path(&mweb_scan_steps()),
        format_path(&mweb_spend_steps())
    )
}

pub fn masters_from_seed(engine: &KeyEngine, seed: &[u8]) -> Result<MwebMasters, Error> {
    let master = master_from_seed(seed)?;
    let scan_node = derive_path(engine, &master, &mweb_scan_steps())?;
    let spend_node = derive_path(engine, &master, &mweb_spend_steps())?;
    Ok(MwebMasters {
        scan: Zeroizing::new(*scan_node.key_bytes()),
        spend: Zeroizing::new(*spend_node.key_bytes()),
        scan_node,
        spend_node,
    })
}

#[cfg(test)]
mod tests {
    use super::{stealth_at, FIRST_RECEIVE_INDEX};
    use crate::ltc::keys::KeyEngine;

    #[test]
    fn reserved_indices_differ_and_addresses_start_ltcmweb1qq() {
        let mut scan = [0u8; 32];
        let mut spend = [0u8; 32];
        scan[31] = 2;
        spend[31] = 3;
        let engine = KeyEngine::new().unwrap();
        let a0 = stealth_at(&engine, &scan, &spend, 0).unwrap();
        let a1 = stealth_at(&engine, &scan, &spend, 1).unwrap();
        let a2 = stealth_at(&engine, &scan, &spend, FIRST_RECEIVE_INDEX).unwrap();
        assert!(a0.address.starts_with("ltcmweb1qq"));
        assert!(a1.address.starts_with("ltcmweb1qq"));
        assert!(a2.address.starts_with("ltcmweb1qq"));
        assert_ne!(a0.address, a1.address);
        assert_ne!(a1.address, a2.address);
        assert!(a0.address.len() > 90);
    }
}
