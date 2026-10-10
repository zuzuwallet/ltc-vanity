// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Base58Check. The alphabet matches Bitcoin's. The version byte does not.
//! Decode wipes its working buffer because the same decoder reads a WIF.

use zeroize::Zeroizing;

use crate::error::Error;
use crate::ltc::hash::checksum4;

pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn alphabet_index(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    let mut work = Zeroizing::new(bytes.to_vec());
    let mut digits = Zeroizing::new(Vec::with_capacity(bytes.len() * 138 / 100 + 2));
    while work.iter().any(|byte| *byte != 0) {
        let remainder = divmod58(&mut work);
        digits.push(ALPHABET[remainder as usize]);
    }
    for _ in bytes.iter().take_while(|byte| **byte == 0) {
        digits.push(b'1');
    }
    digits.reverse();
    String::from_utf8(digits.to_vec()).expect("base58 alphabet is ASCII")
}

pub fn base58check_encode(payload: &[u8]) -> String {
    let mut raw = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    raw.extend_from_slice(payload);
    raw.extend_from_slice(&checksum4(payload));
    base58_encode(&raw)
}

pub fn base58check_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let raw = base58_decode(text)?;
    if raw.len() < 4 {
        return Err(Error::Checksum);
    }
    let split = raw.len() - 4;
    let (payload, checksum) = raw.split_at(split);
    let expected = checksum4(payload);
    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(checksum.iter()) {
        diff |= left ^ right;
    }
    if diff != 0 {
        return Err(Error::Checksum);
    }
    let canonical = base58_encode(&raw);
    if canonical != text {
        return Err(Error::Encoding);
    }
    let mut payload_out = Zeroizing::new(Vec::with_capacity(payload.len()));
    payload_out.extend_from_slice(payload);
    Ok(payload_out)
}

pub fn base58_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut zeros = 0usize;
    let bytes = text.as_bytes();
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }
    let mut value = Zeroizing::new(vec![0u8; text.len()]);
    let mut length = 0usize;
    for byte in &bytes[zeros..] {
        let digit = u16::from(alphabet_index(*byte).ok_or(Error::Encoding)?);
        let mut carry = digit;
        for slot in value.iter_mut().take(length) {
            let acc = u16::from(*slot) * 58 + carry;
            *slot = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            if length >= value.len() {
                return Err(Error::Encoding);
            }
            value[length] = (carry & 0xff) as u8;
            length += 1;
            carry >>= 8;
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(zeros + length));
    out.extend(std::iter::repeat_n(0u8, zeros));
    for byte in value[..length].iter().rev() {
        out.push(*byte);
    }
    Ok(out)
}

fn divmod58(bytes: &mut [u8]) -> u8 {
    let mut remainder = 0u16;
    for byte in bytes.iter_mut() {
        let acc = remainder * 256 + u16::from(*byte);
        *byte = (acc / 58) as u8;
        remainder = acc % 58;
    }
    remainder as u8
}

/// 21-byte body plus its 4-byte checksum, as one 25-byte payload.
pub fn payload25(version: u8, hash: &[u8; 20]) -> [u8; 25] {
    let mut body = [0u8; 21];
    body[0] = version;
    body[1..].copy_from_slice(hash);
    let sum = checksum4(&body);
    let mut payload = [0u8; 25];
    payload[..21].copy_from_slice(&body);
    payload[21..].copy_from_slice(&sum);
    payload
}

pub fn address_from_hash(version: u8, hash: &[u8; 20]) -> String {
    base58check_encode(&payload25(version, hash)[..21])
}
