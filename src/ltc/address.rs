// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference address encoders.
//!
//! P2SH-P2WPKH hashes the witness program `OP_0 PUSH20 <HASH160(pubkey)>`.
//! The private key controls that embedded P2WPKH output. P2TR encodes the
//! tweaked output key, not the internal key.

use secp256k1::SecretKey;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::ltc::base58::address_from_hash;
use crate::ltc::hash::hash160;
use crate::ltc::keys::{KeyEngine, TaprootKeys};
use crate::ltc::kind::AddressKind;
use crate::ltc::network::{P2PKH_VERSION, P2SH_LEGACY_VERSION, P2SH_VERSION};
use crate::ltc::witness::encode_segwit;
use crate::secret::SecretString;

pub fn p2wpkh_redeem(pubkey_hash: &[u8; 20]) -> [u8; 22] {
    let mut script = [0u8; 22];
    script[0] = 0x00;
    script[1] = 0x14;
    script[2..].copy_from_slice(pubkey_hash);
    script
}

pub fn p2pkh_address(pubkey_hash: &[u8; 20]) -> String {
    address_from_hash(P2PKH_VERSION, pubkey_hash)
}

pub fn p2sh_p2wpkh_address(pubkey_hash: &[u8; 20], legacy: bool) -> String {
    let redeem = p2wpkh_redeem(pubkey_hash);
    let script_hash = hash160(&redeem);
    let version = if legacy {
        P2SH_LEGACY_VERSION
    } else {
        P2SH_VERSION
    };
    address_from_hash(version, &script_hash)
}

pub fn p2wpkh_address(pubkey_hash: &[u8; 20]) -> Result<String, Error> {
    encode_segwit(0, pubkey_hash)
}

pub fn p2tr_address(output_xonly: &[u8; 32]) -> Result<String, Error> {
    encode_segwit(1, output_xonly)
}

pub fn descriptor_for(kind: AddressKind, compressed: &[u8; 33], xonly: Option<[u8; 32]>) -> String {
    let hex_key = crate::hexutil::encode_lower(compressed);
    match kind {
        AddressKind::P2pkh => format!("pkh({hex_key})"),
        AddressKind::P2shP2wpkh | AddressKind::P2shP2wpkhLegacy => {
            format!("sh(wpkh({hex_key}))")
        }
        AddressKind::P2wpkh => format!("wpkh({hex_key})"),
        AddressKind::P2tr => {
            let xonly = xonly.unwrap_or([0; 32]);
            format!("tr({})", crate::hexutil::encode_lower(&xonly))
        }
        AddressKind::Mweb => String::new(),
    }
}

#[derive(Clone)]
pub struct Derived {
    pub address: String,
    pub compressed: [u8; 33],
    pub hash160: [u8; 20],
    pub redeem: Vec<u8>,
    pub output_xonly: [u8; 32],
    pub internal_xonly: [u8; 32],
    pub descriptor: String,
}

impl std::fmt::Debug for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Derived")
            .field("address", &self.address)
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

pub fn derive_transparent(
    engine: &KeyEngine,
    kind: AddressKind,
    secret: &[u8],
) -> Result<Derived, Error> {
    let public = engine.public_of(secret)?;
    match kind {
        AddressKind::P2pkh => Ok(from_hash(kind, &public.key, &public.hash160, None)),
        AddressKind::P2shP2wpkh | AddressKind::P2shP2wpkhLegacy => {
            let legacy = kind == AddressKind::P2shP2wpkhLegacy;
            let redeem = p2wpkh_redeem(&public.hash160).to_vec();
            let address = p2sh_p2wpkh_address(&public.hash160, legacy);
            Ok(Derived {
                address,
                compressed: public.key,
                hash160: public.hash160,
                redeem,
                output_xonly: [0; 32],
                internal_xonly: [0; 32],
                descriptor: descriptor_for(kind, &public.key, None),
            })
        }
        AddressKind::P2wpkh => {
            let address = p2wpkh_address(&public.hash160)?;
            Ok(from_hash(kind, &public.key, &public.hash160, Some(address)))
        }
        AddressKind::P2tr => {
            let tap = engine.taproot(secret)?;
            from_taproot(tap)
        }
        AddressKind::Mweb => Err(Error::Encoding),
    }
}

fn from_hash(
    kind: AddressKind,
    compressed: &[u8; 33],
    hash: &[u8; 20],
    address: Option<String>,
) -> Derived {
    let address = address.unwrap_or_else(|| p2pkh_address(hash));
    Derived {
        address,
        compressed: *compressed,
        hash160: *hash,
        redeem: Vec::new(),
        output_xonly: [0; 32],
        internal_xonly: [0; 32],
        descriptor: descriptor_for(kind, compressed, None),
    }
}

fn from_taproot(tap: TaprootKeys) -> Result<Derived, Error> {
    let address = p2tr_address(&tap.output_xonly)?;
    Ok(Derived {
        address,
        compressed: tap.internal_compressed,
        hash160: [0; 20],
        redeem: Vec::new(),
        output_xonly: tap.output_xonly,
        internal_xonly: tap.internal_xonly,
        descriptor: descriptor_for(
            AddressKind::P2tr,
            &tap.internal_compressed,
            Some(tap.internal_xonly),
        ),
    })
}

/// Compressed WIF. Rejects 0 and any integer at or above the curve order.
pub fn encode_wif(key: &[u8; 32]) -> Result<SecretString, Error> {
    let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
    secret.non_secure_erase();
    let mut body = Zeroizing::new([0u8; 34]);
    body[0] = crate::ltc::network::WIF_VERSION;
    body[1..33].copy_from_slice(key);
    body[33] = crate::ltc::network::WIF_COMPRESSED_FLAG;
    Ok(SecretString::new(crate::ltc::base58::base58check_encode(
        body.as_slice(),
    )))
}

#[cfg(test)]
mod tests {
    use super::encode_wif;

    #[test]
    fn invalid_scalars_are_rejected_and_scalar_one_encodes() {
        assert!(encode_wif(&[0u8; 32]).is_err());
        let order = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(encode_wif(&order).is_err());
        let mut next = order;
        next[31] = 0x42;
        assert!(encode_wif(&next).is_err());
        let mut key = [0u8; 32];
        key[31] = 1;
        assert!(encode_wif(&key).is_ok());
    }
}
