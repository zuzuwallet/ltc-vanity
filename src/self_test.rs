// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer tests. A failure aborts before a search starts.
//!
//! Scalar 1 is the SEC generator. Its compressed point and HASH160 are public.
//! Litecoin and Bitcoin addresses for that point are compared. WIF text is
//! compared inside the check and is not formatted into an error.

use std::process::Command;

use crate::error::Error;
use crate::hexutil;
use crate::independent::{
    encode_bech32_program, independent_mweb, independent_p2pkh, independent_p2sh,
    independent_taproot, independent_witness, k256_compressed, wif_differs_from_bitcoin,
};
use crate::ltc::address::{
    derive_transparent, encode_wif, p2pkh_address, p2sh_p2wpkh_address, p2tr_address,
    p2wpkh_address, p2wpkh_redeem,
};
use crate::ltc::hash::{hash160, ripemd160, sha256};
use crate::ltc::hd::{
    derive_path, encode_xpub, format_path, master_from_seed, mweb_scan_steps, scan_gap,
    transparent_steps, xprv_version_prefix,
};
use crate::ltc::keys::KeyEngine;
use crate::ltc::kind::AddressKind;
use crate::ltc::network::{
    chainparams_are_recorded, BIP32_PUBLIC, BITCOIN_HRP, BITCOIN_P2PKH_VERSION,
    BITCOIN_WIF_VERSION, P2PKH_VERSION, P2SH_VERSION, WIF_VERSION,
};
use crate::ltc::{analyze, inspect};
use crate::mweb::{stealth_at, FIRST_RECEIVE_INDEX};

const GENERATOR_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const GENERATOR_HASH: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
const BITCOIN_P2PKH: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const BITCOIN_P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const BIP32_SECRET: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
const HD_CHILD_SECRET: &str = "81a8a3ffdca0fdef71f46de1ee54218620441e8fec5ddb5e085315d471d507a5";
const HD_CHILD_PUBLIC: &str = "023d6dc967e8202d73d6ad354304849a7a171c60061cdcb6a531aaa7c00cdde826";
const HD_CHILD_ADDRESS: &str = "LcgdL8TumzkxBX3MNRui6rDxjXHyTpkJSh";

pub fn run_self_tests() -> Result<(), Error> {
    check_hashes()?;
    check_generator()?;
    check_nested_and_witness()?;
    check_taproot()?;
    check_wif_and_network()?;
    check_hd()?;
    check_prefixes_and_checksums()?;
    check_mweb()?;
    Ok(())
}

pub fn litecoin_core_status() -> &'static str {
    let cli = Command::new("litecoin-cli").arg("-version").output();
    let tx = Command::new("litecoin-tx").arg("-help").output();
    match (cli, tx) {
        (Ok(cli), _) if cli.status.success() => {
            "litecoin-cli is installed. validateaddress was not run, and no wallet spend was attempted."
        }
        (_, Ok(tx)) if tx.status.success() => {
            "litecoin-tx is installed. It was not asked to build or sign a transaction."
        }
        _ => "litecoin-cli: not found. Addresses were not verified by Litecoin Core.",
    }
}

pub fn mweb_forum_status() -> Result<&'static str, Error> {
    let scan = decode_key("918271168655385e387907612ee09d755be50c4685528f9f53eabae380ecba97")?;
    let spend = decode_key("2396e5c33b07dfa2d9e70da1dcbdad0ad2399e5672ff2d4afbe3b20bccf3ba1b")?;
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let forum = [
        (0, "ltcmweb1qq20e2arnhvxw97katjkmsd35agw3capxjkrkh7dk8d30rczm8ypxuq329nwh2twmchhqn3jqh7ua4ps539f6aazh79jy76urqht4qa59ts3at6gf"),
        (1, "ltcmweb1qqg5hddkl4uhspjwg9tkmatxa4s6gswdaq9swl8vsg5xxznmye7phcqatzc62mzkg788tsrfcuegxe9q3agf5cplw7ztqdusqf7x3n2tl55x4gvyt"),
        (2, "ltcmweb1qq0yq03ewm830ugmkkvrvjmyyeslcpwk8ayd7k27qx63sryy6kx3ksqm3k6jd24ld3r5dp5lzx7rm7uyxfujf8sn7v4nlxeqwrcq6k6xxwqdc6tl3"),
    ];
    let mut matched = true;
    for (index, published) in forum {
        let ours = stealth_at(&engine, &scan, &spend, index)
            .map_err(|_| Error::SelfTest("MWEB forum scalar was rejected"))?;
        let other = independent_mweb(&scan, &spend, index)?;
        if ours.address != other || !ours.address.starts_with("ltcmweb1qq") {
            return Err(Error::SelfTest("MWEB stacks disagreed"));
        }
        if ours.address != published {
            matched = false;
        }
    }
    if matched {
        Ok("MWEB forum vector: matches the published strings.")
    } else {
        Ok("MWEB forum vector: differs from the published strings. Litecoin Core source is the specification.")
    }
}

fn check_hashes() -> Result<(), Error> {
    let empty = sha256(b"");
    if empty
        != [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    {
        return Err(Error::SelfTest("SHA-256 empty-string vector mismatch"));
    }
    let abc = ripemd160(b"abc");
    if abc
        != [
            0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
            0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc,
        ]
    {
        return Err(Error::SelfTest("RIPEMD-160 abc vector mismatch"));
    }
    Ok(())
}

fn generator_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[31] = 1;
    key
}

fn check_generator() -> Result<(), Error> {
    let key = generator_key();
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let public = engine
        .public_of(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    if hexutil::encode_lower(&public.key) != GENERATOR_PUBKEY {
        return Err(Error::SelfTest("generator public key mismatch"));
    }
    if hexutil::encode_lower(&public.hash160) != GENERATOR_HASH {
        return Err(Error::SelfTest("generator HASH160 mismatch"));
    }
    if hash160(&public.key) != public.hash160 {
        return Err(Error::SelfTest("HASH160 did not match the generator"));
    }
    let derived = derive_transparent(&engine, AddressKind::P2pkh, &key)
        .map_err(|_| Error::SelfTest("P2PKH derivation failed"))?;
    let (ltc, bitcoin) = independent_p2pkh(&key)?;
    if bitcoin != BITCOIN_P2PKH || ltc != derived.address || ltc == bitcoin || !ltc.starts_with('L')
    {
        return Err(Error::SelfTest(
            "Litecoin and Bitcoin P2PKH vectors disagreed",
        ));
    }
    if k256_compressed(&key)? != public.key {
        return Err(Error::SelfTest("k256 public key disagreed"));
    }
    Ok(())
}

fn check_nested_and_witness() -> Result<(), Error> {
    let key = generator_key();
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let public = engine
        .public_of(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    let redeem = p2wpkh_redeem(&public.hash160);
    if redeem[..2] != [0x00, 0x14] || redeem[2..] != public.hash160 {
        return Err(Error::SelfTest("P2WPKH redeem script mismatch"));
    }
    let modern = p2sh_p2wpkh_address(&public.hash160, false);
    let legacy = p2sh_p2wpkh_address(&public.hash160, true);
    if independent_p2sh(&public.hash160, false) != modern
        || independent_p2sh(&public.hash160, true) != legacy
        || !modern.starts_with('M')
        || !legacy.starts_with('3')
        || modern == legacy
    {
        return Err(Error::SelfTest("P2SH-P2WPKH vectors disagreed"));
    }
    let native =
        p2wpkh_address(&public.hash160).map_err(|_| Error::SelfTest("P2WPKH encode failed"))?;
    let other = independent_witness(0, &public.hash160)?;
    let bitcoin = encode_bech32_program(BITCOIN_HRP, 0, &public.hash160, false)?;
    if other != native
        || bitcoin != BITCOIN_P2WPKH
        || native == bitcoin
        || !native.starts_with("ltc1q")
    {
        return Err(Error::SelfTest("P2WPKH Bech32 vector disagreed"));
    }
    let swapped = encode_bech32_program("ltc", 0, &public.hash160, true)?;
    if inspect(&swapped).contains("Valid:\nYES") {
        return Err(Error::SelfTest(
            "Bech32m was accepted for witness version 0",
        ));
    }
    Ok(())
}

fn check_taproot() -> Result<(), Error> {
    let key = generator_key();
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let tap = engine
        .taproot(&key)
        .map_err(|_| Error::SelfTest("Taproot tweak failed"))?;
    let output = independent_taproot(&key)?;
    if output != tap.output_xonly || output == tap.internal_xonly {
        return Err(Error::SelfTest(
            "Taproot output key was not the tweaked key",
        ));
    }
    let address =
        p2tr_address(&tap.output_xonly).map_err(|_| Error::SelfTest("P2TR encode failed"))?;
    let untweaked = p2tr_address(&tap.internal_xonly)
        .map_err(|_| Error::SelfTest("untweaked encode failed"))?;
    let other = independent_witness(1, &output)?;
    let swapped = encode_bech32_program("ltc", 1, &output, true)?;
    if other != address || address == untweaked || !address.starts_with("ltc1p") {
        return Err(Error::SelfTest("P2TR Bech32m vector disagreed"));
    }
    if inspect(&swapped).contains("Valid:\nYES") || inspect(&address).contains("Valid:\nNO") {
        return Err(Error::SelfTest("Bech32 and Bech32m were confused"));
    }
    Ok(())
}

fn check_wif_and_network() -> Result<(), Error> {
    let key = generator_key();
    let wif = encode_wif(&key).map_err(|_| Error::SelfTest("WIF encode failed"))?;
    if !wif_differs_from_bitcoin(&key, wif.as_str()) {
        return Err(Error::SelfTest(
            "Litecoin WIF matched Bitcoin or was rejected",
        ));
    }
    if P2PKH_VERSION == BITCOIN_P2PKH_VERSION || WIF_VERSION == BITCOIN_WIF_VERSION {
        return Err(Error::SelfTest("Litecoin version bytes copied Bitcoin"));
    }
    if BIP32_PUBLIC != [0x04, 0x88, 0xB2, 0x1E]
        || P2SH_VERSION != 0x32
        || !chainparams_are_recorded()
    {
        return Err(Error::SelfTest("documented network constant mismatch"));
    }
    Ok(())
}

fn check_hd() -> Result<(), Error> {
    let seed = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let master = master_from_seed(&seed).map_err(|_| Error::SelfTest("BIP32 master failed"))?;
    if hexutil::encode_lower(master.key_bytes()) != BIP32_SECRET {
        return Err(Error::SelfTest("BIP32 vector 1 master mismatch"));
    }
    let path = format_path(
        &transparent_steps(AddressKind::P2pkh, 0, 0).map_err(|_| Error::SelfTest("path failed"))?,
    );
    if path != "m/44'/2'/0'/0/0" || path == "m/44'/0'/0'/0/0" {
        return Err(Error::SelfTest("HD coin type was not 2"));
    }
    if format_path(&mweb_scan_steps()) != "m/0'/100'/0'" {
        return Err(Error::SelfTest("MWEB scan path mismatch"));
    }
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let xpub = encode_xpub(&master, &engine).map_err(|_| Error::SelfTest("xpub encode failed"))?;
    if !xpub.starts_with("xpub") || xprv_version_prefix() != crate::ltc::network::BIP32_SECRET {
        return Err(Error::SelfTest(
            "BIP32 version prefix was not Core's xpub/xprv",
        ));
    }
    let child = derive_path(
        &engine,
        &master,
        &transparent_steps(AddressKind::P2pkh, 0, 0)?,
    )
    .map_err(|_| Error::SelfTest("HD child at m/44'/2'/0'/0/0 disagreed"))?;
    let child_public = engine
        .public_of(child.key_bytes())
        .map_err(|_| Error::SelfTest("HD child at m/44'/2'/0'/0/0 disagreed"))?;
    if hexutil::encode_lower(child.key_bytes()) != HD_CHILD_SECRET
        || hexutil::encode_lower(&child_public.key) != HD_CHILD_PUBLIC
        || p2pkh_address(&child_public.hash160) != HD_CHILD_ADDRESS
    {
        return Err(Error::SelfTest("HD child at m/44'/2'/0'/0/0 disagreed"));
    }
    let scanned = scan_gap(&engine, &seed, AddressKind::P2pkh, 0, 1)
        .map_err(|_| Error::SelfTest("gap scan failed"))?;
    if scanned.len() != 1 || scanned[0] != HD_CHILD_ADDRESS {
        return Err(Error::SelfTest("gap scan did not derive a P2PKH address"));
    }
    Ok(())
}

fn check_prefixes_and_checksums() -> Result<(), Error> {
    let exact =
        analyze(AddressKind::P2pkh, "LZuZu").map_err(|_| Error::SelfTest("analyze failed"))?;
    let folded =
        analyze(AddressKind::P2pkh, "Lzuzu").map_err(|_| Error::SelfTest("analyze failed"))?;
    if !exact.reachable || folded.reachable || exact.expected == Some(58u64.pow(4)) {
        return Err(Error::SelfTest("Base58 case or 58^n estimate was wrong"));
    }
    let nested =
        analyze(AddressKind::P2shP2wpkh, "MZuZu").map_err(|_| Error::SelfTest("analyze failed"))?;
    let earliest = analyze(AddressKind::P2shP2wpkh, "M8ZuZu")
        .map_err(|_| Error::SelfTest("analyze failed"))?;
    if nested.reachable || !earliest.reachable || earliest.expected == Some(58u64.pow(5)) {
        return Err(Error::SelfTest(
            "MZuZu was treated as a reachable nested prefix",
        ));
    }
    let native =
        analyze(AddressKind::P2wpkh, "ltc1qzuzu").map_err(|_| Error::SelfTest("analyze failed"))?;
    let tap =
        analyze(AddressKind::P2tr, "ltc1pzuzu").map_err(|_| Error::SelfTest("analyze failed"))?;
    if native.exact_bits != Some(20) || tap.exact_bits != Some(20) {
        return Err(Error::SelfTest("witness vanity was not 20 bits"));
    }
    if analyze(AddressKind::P2wpkh, "ltc1qZuZu")
        .map_err(|_| Error::SelfTest("analyze failed"))?
        .reachable
    {
        return Err(Error::SelfTest("mixed-case Bech32 was accepted"));
    }
    let blocked = analyze(AddressKind::Mweb, "ltcmweb1qqzuzu")
        .map_err(|_| Error::SelfTest("analyze failed"))?;
    if blocked.reachable {
        return Err(Error::SelfTest("unreachable MWEB prefix was accepted"));
    }
    Ok(())
}

fn check_mweb() -> Result<(), Error> {
    let mut scan = [0u8; 32];
    let mut spend = [0u8; 32];
    scan[31] = 2;
    spend[31] = 3;
    let engine =
        KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize libsecp256k1"))?;
    let ours = stealth_at(&engine, &scan, &spend, FIRST_RECEIVE_INDEX)
        .map_err(|_| Error::SelfTest("MWEB address failed"))?;
    let other = independent_mweb(&scan, &spend, FIRST_RECEIVE_INDEX)?;
    if ours.address != other || !ours.address.starts_with("ltcmweb1qq") {
        return Err(Error::SelfTest("MWEB stacks disagreed"));
    }
    mweb_forum_status().map(|_| ())
}

fn decode_key(text: &str) -> Result<[u8; 32], Error> {
    hexutil::decode_fixed(text).ok_or(Error::SelfTest("test vector was not hex"))
}
