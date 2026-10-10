// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Second derivation stack.
//!
//! Public keys and Taproot points use `k256`. Hashes use `bitcoin_hashes`.
//! Base58Check uses `bs58`. Bech32 and Bech32m use a BIP173/BIP350 checksum
//! written here, not `bech32::segwit`. MWEB uses the same BLAKE3 domain as
//! Core and this point stack.

use bitcoin_hashes::{hash160, sha256};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{Group, PrimeField};
use k256::{ProjectivePoint, Scalar, SecretKey};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::ltc::network::{
    BECH32_HRP, BITCOIN_WIF_VERSION, MWEB_HRP, P2PKH_VERSION, P2SH_LEGACY_VERSION, P2SH_VERSION,
    WIF_COMPRESSED_FLAG, WIF_VERSION,
};
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

pub fn bitcoin_hash160(data: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(data).to_byte_array()
}

pub fn k256_compressed(key: &[u8; 32]) -> Result<[u8; 33], Error> {
    let secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
    let encoded = secret.public_key().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(Error::InvalidKey);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub fn independent_p2pkh(key: &[u8; 32]) -> Result<(String, String), Error> {
    let public = k256_compressed(key)?;
    let hash = bitcoin_hash160(&public);
    Ok((
        base58_address(P2PKH_VERSION, &hash),
        base58_address(0x00, &hash),
    ))
}

pub fn independent_p2sh(pubkey_hash: &[u8; 20], legacy: bool) -> String {
    let mut redeem = [0u8; 22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    redeem[2..].copy_from_slice(pubkey_hash);
    let hash = bitcoin_hash160(&redeem);
    let version = if legacy {
        P2SH_LEGACY_VERSION
    } else {
        P2SH_VERSION
    };
    base58_address(version, &hash)
}

pub fn independent_witness(version: u8, program: &[u8]) -> Result<String, Error> {
    encode_bech32_program(BECH32_HRP, version, program, false)
}

pub fn encode_bech32_program(
    hrp: &str,
    version: u8,
    program: &[u8],
    swap_checksum: bool,
) -> Result<String, Error> {
    let bech32m = version != 0;
    let spec = if bech32m ^ swap_checksum {
        BECH32M_CONST
    } else {
        BECH32_CONST
    };
    let mut data = vec![version];
    data.extend(convert_bits(program, 8, 5, true).ok_or(Error::Encoding)?);
    encode_bech32(hrp, &data, spec)
}

pub fn independent_taproot(key: &[u8; 32]) -> Result<[u8; 32], Error> {
    let scalar = scalar_from(key)?;
    let public = k256_compressed(key)?;
    let scalar = if public[0] == 0x03 { -scalar } else { scalar };
    let internal = ProjectivePoint::GENERATOR * scalar;
    let encoded = internal.to_encoded_point(true);
    let x = &encoded.as_bytes()[1..33];
    let tweak = scalar_from(&tagged_sha256(b"TapTweak", x))?;
    let output = ProjectivePoint::GENERATOR * (scalar + tweak);
    if bool::from(output.is_identity()) {
        return Err(Error::InvalidKey);
    }
    let encoded = output.to_encoded_point(true);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&encoded.as_bytes()[1..33]);
    Ok(xonly)
}

pub fn independent_mweb(
    scan_secret: &[u8; 32],
    spend_secret: &[u8; 32],
    index: u32,
) -> Result<String, Error> {
    let preimage = mweb_address_hash(index, scan_secret);
    let mi = mweb_hash_to_scalar(&preimage)?;
    let spend = scalar_from(spend_secret)? + scalar_from(&mi)?;
    if bool::from(spend.is_zero()) {
        return Err(Error::InvalidKey);
    }
    let spend_point = ProjectivePoint::GENERATOR * spend;
    let scan_scalar = scalar_from(scan_secret)?;
    let scan_point = spend_point * scan_scalar;
    let spend_pub = compressed_point(&spend_point)?;
    let scan_pub = compressed_point(&scan_point)?;
    let mut payload = [0u8; 66];
    payload[..33].copy_from_slice(&scan_pub);
    payload[33..].copy_from_slice(&spend_pub);
    let mut data = vec![0u8];
    data.extend(convert_bits(&payload, 8, 5, true).ok_or(Error::Encoding)?);
    encode_bech32(MWEB_HRP, &data, BECH32_CONST)
}

pub fn wif_differs_from_bitcoin(key: &[u8; 32], litecoin: &str) -> bool {
    let expected_ltc = wif_text(WIF_VERSION, key);
    let expected_btc = wif_text(BITCOIN_WIF_VERSION, key);
    expected_ltc.as_str() == litecoin && expected_btc.as_str() != litecoin
}

fn wif_text(version: u8, key: &[u8; 32]) -> Zeroizing<String> {
    let mut body = Zeroizing::new([0u8; 34]);
    body[0] = version;
    body[1..33].copy_from_slice(key);
    body[33] = WIF_COMPRESSED_FLAG;
    Zeroizing::new(base58check(body.as_slice()))
}

fn compressed_point(point: &ProjectivePoint) -> Result<[u8; 33], Error> {
    if bool::from(point.is_identity()) {
        return Err(Error::InvalidKey);
    }
    let encoded = point.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn mweb_address_hash(index: u32, scan_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"A");
    hasher.update(&index.to_le_bytes());
    hasher.update(scan_secret);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn mweb_hash_to_scalar(hash: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if SecretKey::from_slice(hash).is_ok() {
        return Ok(Zeroizing::new(*hash));
    }
    let mut counter = 0u32;
    for _ in 0..1024 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"MWEB hash-to-scalar");
        hasher.update(hash);
        hasher.update(&counter.to_le_bytes());
        let digest = Zeroizing::new(*hasher.finalize().as_bytes());
        counter = counter.checked_add(1).ok_or(Error::InvalidKey)?;
        if SecretKey::from_slice(digest.as_slice()).is_ok() {
            return Ok(digest);
        }
    }
    Err(Error::InvalidKey)
}

fn scalar_from(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    let mut wide = k256::FieldBytes::default();
    wide.copy_from_slice(bytes);
    Option::from(Scalar::from_repr(wide)).ok_or(Error::InvalidKey)
}

fn tagged_sha256(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag).to_byte_array();
    let mut body = Vec::with_capacity(64 + msg.len());
    body.extend_from_slice(&tag_hash);
    body.extend_from_slice(&tag_hash);
    body.extend_from_slice(msg);
    sha256::Hash::hash(&body).to_byte_array()
}

fn base58_address(version: u8, hash: &[u8; 20]) -> String {
    let mut body = [0u8; 21];
    body[0] = version;
    body[1..].copy_from_slice(hash);
    base58check(&body)
}

fn base58check(payload: &[u8]) -> String {
    let first = sha256::Hash::hash(payload);
    let second = sha256::Hash::hash(first.as_byte_array());
    let mut raw = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    raw.extend_from_slice(payload);
    raw.extend_from_slice(&second.as_byte_array()[..4]);
    bs58::encode(raw.as_slice()).into_string()
}

fn encode_bech32(hrp: &str, data: &[u8], constant: u32) -> Result<String, Error> {
    let checksum = create_checksum(hrp, data, constant);
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for value in data.iter().chain(checksum.iter()) {
        out.push(CHARSET[*value as usize] as char);
    }
    if out.len() > 1023 {
        return Err(Error::Encoding);
    }
    Ok(out)
}

fn create_checksum(hrp: &str, data: &[u8], constant: u32) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = polymod(&values) ^ constant;
    let mut out = [0u8; 6];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = ((polymod >> (5 * (5 - index))) & 31) as u8;
    }
    out
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for byte in hrp.bytes() {
        out.push(byte >> 5);
    }
    out.push(0);
    for byte in hrp.bytes() {
        out.push(byte & 31);
    }
    out
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (bit, constant) in GENERATOR.into_iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                chk ^= constant;
            }
        }
    }
    chk
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for value in data {
        if u32::from(*value) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(*value);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{independent_p2pkh, independent_taproot, independent_witness, k256_compressed};
    use crate::ltc::address::{p2pkh_address, p2tr_address, p2wpkh_address};
    use crate::ltc::keys::KeyEngine;

    #[test]
    fn published_bitcoin_bech32_vector_and_litecoin_disagrees() {
        let program = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];
        let ltc = independent_witness(0, &program).unwrap();
        assert!(ltc.starts_with("ltc1q"));
        assert_ne!(ltc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let bc = super::encode_bech32(
            "bc",
            &{
                let mut data = vec![0u8];
                data.extend(super::convert_bits(&program, 8, 5, true).unwrap());
                data
            },
            super::BECH32_CONST,
        )
        .unwrap();
        assert_eq!(bc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn stacks_agree_on_scalar_one_and_the_tweak_changes_the_output() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let engine = KeyEngine::new().unwrap();
        let public = engine.public_of(&key).unwrap();
        assert_eq!(k256_compressed(&key).unwrap(), public.key);
        let (ltc, bitcoin) = independent_p2pkh(&key).unwrap();
        assert_eq!(ltc, p2pkh_address(&public.hash160));
        assert_eq!(bitcoin, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_ne!(ltc, bitcoin);
        let native = p2wpkh_address(&public.hash160).unwrap();
        assert_eq!(independent_witness(0, &public.hash160).unwrap(), native);
        let tap = engine.taproot(&key).unwrap();
        assert_eq!(independent_taproot(&key).unwrap(), tap.output_xonly);
        let tweaked = p2tr_address(&tap.output_xonly).unwrap();
        let untweaked = p2tr_address(&tap.internal_xonly).unwrap();
        assert_ne!(tweaked, untweaked);
        assert_eq!(independent_witness(1, &tap.output_xonly).unwrap(), tweaked);
    }
}
