// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HASH160 and the Base58Check checksum.
//!
//! HASH160 is RIPEMD-160(SHA-256(data)). The Base58Check checksum is the first
//! four bytes of SHA-256(SHA-256(payload)).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let digest = Ripemd160::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

pub fn checksum4(payload: &[u8]) -> [u8; 4] {
    let second = sha256(&sha256(payload));
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

/// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut body = Vec::with_capacity(64 + msg.len());
    body.extend_from_slice(&tag_hash);
    body.extend_from_slice(&tag_hash);
    body.extend_from_slice(msg);
    sha256(&body)
}

#[cfg(test)]
mod tests {
    use super::{hash160, ripemd160, sha256};

    #[test]
    fn sha256_of_empty_is_the_nist_vector() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn ripemd160_of_abc_is_the_published_vector() {
        assert_eq!(
            ripemd160(b"abc"),
            [
                0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
                0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc
            ]
        );
    }

    #[test]
    fn hash160_of_the_generator_is_the_published_bitcoin_hash() {
        let pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        assert_eq!(
            hash160(&pubkey),
            [
                0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
                0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
            ]
        );
    }
}
