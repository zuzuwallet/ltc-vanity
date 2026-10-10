// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuild a winning address on two stacks.
//!
//! The search stack is libsecp256k1, `sha2`, `ripemd`, and the `bech32` crate.
//! The check stack is `k256`, `bitcoin_hashes`, `bs58`, and a local Bech32
//! checksum. HD path math is one BIP32 implementation. The child scalar then
//! goes through both address stacks. A mismatch is fatal.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::error::Error;
use crate::independent::{
    bitcoin_hash160, independent_mweb, independent_p2pkh, independent_p2sh, independent_taproot,
    independent_witness, k256_compressed, wif_differs_from_bitcoin,
};
use crate::ltc::address::{
    derive_transparent, descriptor_for, encode_wif, p2tr_address, p2wpkh_address, p2wpkh_redeem,
};
use crate::ltc::hash::hash160;
use crate::ltc::hd::{child_at, format_path, seed_from_entropy, transparent_steps, HARDENED};
use crate::ltc::keys::KeyEngine;
use crate::ltc::kind::{AddressKind, SearchMode};
use crate::ltc::network::{BITCOIN_COIN_TYPE, BITCOIN_HRP, COIN_TYPE};
use crate::mweb::{masters_from_seed, mweb_record, stealth_at, FIRST_RECEIVE_INDEX};
use crate::wallet::{CollectionItem, WalletMaterial};

pub fn confirm_material(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let outcome = catch_unwind(AssertUnwindSafe(|| confirm_inner(material, address)));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::VerificationFailed),
    }
}

fn confirm_inner(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    if material.network_name() != "mainnet" || address.is_empty() {
        return Err(Error::VerificationFailed);
    }
    match material.mode() {
        SearchMode::Independent => confirm_independent(material, address),
        SearchMode::HdIndex => confirm_hd(material, address),
        SearchMode::MwebIndex => confirm_mweb(material, address),
        SearchMode::Collection => confirm_collection(material, address),
    }
}

fn confirm_independent(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    if material.kind() == AddressKind::Mweb || !material.path().is_empty() {
        return Err(Error::VerificationFailed);
    }
    let key = material.sole_key()?;
    let engine = KeyEngine::new().map_err(|_| Error::VerificationFailed)?;
    let derived =
        derive_transparent(&engine, material.kind(), key).map_err(|_| Error::VerificationFailed)?;
    if derived.address != address {
        return Err(Error::VerificationFailed);
    }
    let other_public = k256_compressed(key)?;
    if !same_public_point(material.kind(), &derived.compressed, &other_public)
        || bitcoin_hash160(&derived.compressed) != hash160(&derived.compressed)
    {
        return Err(Error::VerificationFailed);
    }
    match material.kind() {
        AddressKind::P2pkh => {
            let (ltc, bitcoin) = independent_p2pkh(key)?;
            if ltc != address || ltc == bitcoin || !address.starts_with('L') {
                return Err(Error::VerificationFailed);
            }
        }
        AddressKind::P2shP2wpkh | AddressKind::P2shP2wpkhLegacy => {
            confirm_nested(material, key, &derived.compressed, address)?;
        }
        AddressKind::P2wpkh => {
            let other = independent_witness(0, &derived.hash160)?;
            let bitcoin =
                crate::independent::encode_bech32_program(BITCOIN_HRP, 0, &derived.hash160, false)?;
            if other != address || other == bitcoin || !address.starts_with("ltc1q") {
                return Err(Error::VerificationFailed);
            }
        }
        AddressKind::P2tr => confirm_taproot(key, &derived, address)?,
        AddressKind::Mweb => return Err(Error::VerificationFailed),
    }
    let wif = encode_wif(key).map_err(|_| Error::VerificationFailed)?;
    if !wif_differs_from_bitcoin(key, wif.as_str()) {
        return Err(Error::VerificationFailed);
    }
    if derived.descriptor
        != descriptor_for(
            material.kind(),
            &derived.compressed,
            xonly_of(material.kind(), &derived),
        )
    {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_nested(
    material: &WalletMaterial,
    key: &[u8; 32],
    compressed: &[u8; 33],
    address: &str,
) -> Result<(), Error> {
    let public_hash = hash160(compressed);
    let redeem = p2wpkh_redeem(&public_hash);
    if material.redeem() != redeem.as_slice() {
        return Err(Error::VerificationFailed);
    }
    if redeem[0] != 0x00 || redeem[1] != 0x14 || redeem[2..] != public_hash {
        return Err(Error::VerificationFailed);
    }
    let legacy = material.kind() == AddressKind::P2shP2wpkhLegacy;
    let other = independent_p2sh(&public_hash, legacy);
    let native = p2wpkh_address(&public_hash).map_err(|_| Error::VerificationFailed)?;
    if other != address || !native.starts_with("ltc1q") {
        return Err(Error::VerificationFailed);
    }
    let (ltc_p2pkh, bitcoin_p2pkh) = independent_p2pkh(key)?;
    if ltc_p2pkh == bitcoin_p2pkh || ltc_p2pkh == address {
        return Err(Error::VerificationFailed);
    }
    let expect = if legacy { '3' } else { 'M' };
    if !address.starts_with(expect) {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_taproot(
    key: &[u8; 32],
    derived: &crate::ltc::address::Derived,
    address: &str,
) -> Result<(), Error> {
    let output = independent_taproot(key)?;
    if output != derived.output_xonly || output == derived.internal_xonly {
        return Err(Error::VerificationFailed);
    }
    let other = independent_witness(1, &output)?;
    let untweaked = p2tr_address(&derived.internal_xonly).map_err(|_| Error::VerificationFailed)?;
    let swapped = crate::independent::encode_bech32_program("ltc", 1, &output, true)
        .map_err(|_| Error::VerificationFailed)?;
    if other != address
        || untweaked == address
        || swapped == address
        || !address.starts_with("ltc1p")
    {
        return Err(Error::VerificationFailed);
    }
    if !derived.descriptor.starts_with("tr(")
        || derived.descriptor.contains(&hex_of(&derived.output_xonly))
    {
        return Err(Error::VerificationFailed);
    }
    if !derived
        .descriptor
        .contains(&hex_of(&derived.internal_xonly))
    {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_hd(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    if material.kind() == AddressKind::Mweb {
        return Err(Error::VerificationFailed);
    }
    let seed = seed_from_entropy(material.entropy().map_err(|_| Error::VerificationFailed)?)
        .map_err(|_| Error::VerificationFailed)?;
    let engine = KeyEngine::new().map_err(|_| Error::VerificationFailed)?;
    let child = child_at(
        &engine,
        seed.as_slice(),
        material.kind(),
        material.account(),
        material.index(),
    )
    .map_err(|_| Error::VerificationFailed)?;
    let derived = derive_transparent(&engine, material.kind(), child.key_bytes())
        .map_err(|_| Error::VerificationFailed)?;
    let steps = transparent_steps(material.kind(), material.account(), material.index())
        .map_err(|_| Error::VerificationFailed)?;
    let path = format_path(&steps);
    if path != material.path() || derived.address != address {
        return Err(Error::VerificationFailed);
    }
    if steps.len() != 5 || steps[1] != (COIN_TYPE | HARDENED) {
        return Err(Error::VerificationFailed);
    }
    let mut bitcoin_steps = steps;
    bitcoin_steps[1] = BITCOIN_COIN_TYPE | HARDENED;
    if path == format_path(&bitcoin_steps) || path.starts_with("m/0'/0'/") {
        return Err(Error::VerificationFailed);
    }
    if !path.contains("2'") {
        return Err(Error::VerificationFailed);
    }
    confirm_child_address(material.kind(), child.key_bytes(), &derived, address)
}

fn confirm_child_address(
    kind: AddressKind,
    key: &[u8; 32],
    derived: &crate::ltc::address::Derived,
    address: &str,
) -> Result<(), Error> {
    let other_public = k256_compressed(key)?;
    if !same_public_point(kind, &derived.compressed, &other_public) {
        return Err(Error::VerificationFailed);
    }
    match kind {
        AddressKind::P2pkh => {
            let (ltc, bitcoin) = independent_p2pkh(key)?;
            if ltc != address || ltc == bitcoin {
                return Err(Error::VerificationFailed);
            }
        }
        AddressKind::P2shP2wpkh | AddressKind::P2shP2wpkhLegacy => {
            let legacy = kind == AddressKind::P2shP2wpkhLegacy;
            if independent_p2sh(&derived.hash160, legacy) != address
                || derived.redeem != p2wpkh_redeem(&derived.hash160)
            {
                return Err(Error::VerificationFailed);
            }
        }
        AddressKind::P2wpkh => {
            if independent_witness(0, &derived.hash160)? != address {
                return Err(Error::VerificationFailed);
            }
        }
        AddressKind::P2tr => {
            if independent_taproot(key)? != derived.output_xonly
                || independent_witness(1, &derived.output_xonly)? != address
            {
                return Err(Error::VerificationFailed);
            }
        }
        AddressKind::Mweb => return Err(Error::VerificationFailed),
    }
    Ok(())
}

fn confirm_mweb(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    if material.kind() != AddressKind::Mweb || material.index() < FIRST_RECEIVE_INDEX {
        return Err(Error::VerificationFailed);
    }
    let record = mweb_record(material.index());
    if material.path() != record || !address.starts_with("ltcmweb1qq") {
        return Err(Error::VerificationFailed);
    }
    let seed = seed_from_entropy(material.entropy().map_err(|_| Error::VerificationFailed)?)
        .map_err(|_| Error::VerificationFailed)?;
    let engine = KeyEngine::new().map_err(|_| Error::VerificationFailed)?;
    let masters =
        masters_from_seed(&engine, seed.as_slice()).map_err(|_| Error::VerificationFailed)?;
    let stealth = stealth_at(&engine, &masters.scan, &masters.spend, material.index())
        .map_err(|_| Error::VerificationFailed)?;
    let other = independent_mweb(&masters.scan, &masters.spend, material.index())?;
    if stealth.address != address || other != address {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn confirm_collection(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let items = material.collection();
    if items.len() != 5 || join_addresses(items) != address {
        return Err(Error::VerificationFailed);
    }
    let expected = [
        AddressKind::P2pkh,
        AddressKind::P2shP2wpkh,
        AddressKind::P2wpkh,
        AddressKind::P2tr,
        AddressKind::Mweb,
    ];
    let seed = seed_from_entropy(material.entropy().map_err(|_| Error::VerificationFailed)?)
        .map_err(|_| Error::VerificationFailed)?;
    let engine = KeyEngine::new().map_err(|_| Error::VerificationFailed)?;
    let mut joined_paths = Vec::new();
    for (item, kind) in items.iter().zip(expected) {
        if item.kind != kind {
            return Err(Error::VerificationFailed);
        }
        let (derived_address, path, descriptor) =
            derive_part(&engine, seed.as_slice(), kind, item.index)?;
        if derived_address != item.address || path != item.path || descriptor != item.descriptor {
            return Err(Error::VerificationFailed);
        }
        joined_paths.push(path);
    }
    if material.path() != joined_paths.join("|") {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn derive_part(
    engine: &KeyEngine,
    seed: &[u8],
    kind: AddressKind,
    index: u32,
) -> Result<(String, String, String), Error> {
    if kind == AddressKind::Mweb {
        if index < FIRST_RECEIVE_INDEX {
            return Err(Error::VerificationFailed);
        }
        let masters = masters_from_seed(engine, seed)?;
        let stealth = stealth_at(engine, &masters.scan, &masters.spend, index)?;
        let other = independent_mweb(&masters.scan, &masters.spend, index)?;
        if other != stealth.address {
            return Err(Error::VerificationFailed);
        }
        return Ok((stealth.address, mweb_record(index), String::new()));
    }
    let child = child_at(engine, seed, kind, 0, index)?;
    let derived = derive_transparent(engine, kind, child.key_bytes())?;
    let path = format_path(&transparent_steps(kind, 0, index)?);
    confirm_child_address(kind, child.key_bytes(), &derived, &derived.address)?;
    Ok((derived.address, path, derived.descriptor))
}

/// Taproot stores the even-Y internal key. An odd original pubkey shares its X
/// and differs only in the `0x03` prefix. Every other family stores the original
/// compressed pubkey.
fn same_public_point(kind: AddressKind, derived: &[u8; 33], other: &[u8; 33]) -> bool {
    if kind == AddressKind::P2tr {
        derived[0] == 0x02 && derived[1..] == other[1..]
    } else {
        derived == other
    }
}

fn xonly_of(kind: AddressKind, derived: &crate::ltc::address::Derived) -> Option<[u8; 32]> {
    if kind == AddressKind::P2tr {
        Some(derived.internal_xonly)
    } else {
        None
    }
}

fn hex_of(bytes: &[u8]) -> String {
    crate::hexutil::encode_lower(bytes)
}

pub fn join_addresses(items: &[CollectionItem]) -> String {
    items
        .iter()
        .map(|item| item.address.as_str())
        .collect::<Vec<_>>()
        .join("|")
}

#[cfg(test)]
mod tests {
    use super::confirm_material;
    use crate::ltc::address::{derive_transparent, encode_wif};
    use crate::ltc::keys::KeyEngine;
    use crate::ltc::kind::AddressKind;
    use crate::wallet::WalletMaterial;

    #[test]
    fn key_nine_p2pkh_and_p2tr_confirm() {
        let mut raw = [0u8; 32];
        raw[31] = 9;
        let key = zeroize::Zeroizing::new(raw);
        let engine = KeyEngine::new().unwrap();
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2tr,
            AddressKind::P2wpkh,
            AddressKind::P2shP2wpkh,
        ] {
            let derived = derive_transparent(&engine, kind, key.as_slice()).unwrap();
            if kind == AddressKind::P2tr {
                let original = engine.public_of(key.as_slice()).unwrap();
                assert_eq!(original.key[0], 0x03, "fixture must have odd Y");
                assert_eq!(derived.compressed[0], 0x02);
                assert_eq!(derived.compressed[1..], original.key[1..]);
            }
            let wif = encode_wif(&key).unwrap();
            assert!(
                crate::independent::wif_differs_from_bitcoin(&key, wif.as_str()),
                "{}",
                kind.label()
            );
            if kind == AddressKind::P2tr {
                let output = crate::independent::independent_taproot(&key).expect("taproot stack");
                assert_eq!(output, derived.output_xonly, "taproot x-only mismatch");
                let other = crate::independent::independent_witness(1, &output).expect("witness");
                assert_eq!(other, derived.address, "taproot address mismatch");
            }
            let material = WalletMaterial::independent(kind, key.clone(), &derived);
            confirm_material(&material, &derived.address)
                .unwrap_or_else(|_| panic!("{}", kind.label()));
        }
    }
}
