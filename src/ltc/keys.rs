// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compressed secp256k1 keys and the BIP341 key-path tweak.
//!
//! The context is `Secp256k1<All>` because x-only tweaking and point
//! multiplication require `Verification`. The `rand` feature stays off.
//! `new` draws 32 bytes from `getrandom` and passes them to `seeded_randomize`.
//!
//! `SecretKey::from_slice` rejects 0 and scalars at or above the curve order.
//! This crate does not reduce a candidate modulo the order and it does not
//! walk sequential private keys.

use secp256k1::{Keypair, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::ltc::hash::tagged_hash;

/// One worker's libsecp256k1 context.
pub struct KeyEngine {
    secp: Secp256k1<secp256k1::All>,
}

struct EraseGuard<'a>(&'a mut SecretKey);

impl Drop for EraseGuard<'_> {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub key: [u8; 33],
    pub hash160: [u8; 20],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaprootKeys {
    pub internal_compressed: [u8; 33],
    pub internal_xonly: [u8; 32],
    /// Even-Y internal key was odd before normalization.
    pub internal_parity_odd: bool,
    pub output_xonly: [u8; 32],
}

impl KeyEngine {
    pub fn new() -> Result<Self, Error> {
        let mut secp = Secp256k1::new();
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(|_| Error::Rng)?;
        secp.seeded_randomize(&seed);
        Ok(Self { secp })
    }

    pub fn public_of(&self, key: &[u8]) -> Result<Public, Error> {
        let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let guard = EraseGuard(&mut secret);
        let public = PublicKey::from_secret_key(&self.secp, guard.0);
        drop(guard);
        let compressed = public.serialize();
        if compressed[0] != 0x02 && compressed[0] != 0x03 {
            return Err(Error::InvalidKey);
        }
        Ok(Public {
            key: compressed,
            hash160: crate::ltc::hash::hash160(&compressed),
        })
    }

    pub fn add_scalar(&self, key: &[u8], tweak: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut scalar = Scalar::from_be_bytes(*tweak).map_err(|_| Error::InvalidKey)?;
        let mut parent = match SecretKey::from_slice(key) {
            Ok(parent) => parent,
            Err(_) => {
                scalar.non_secure_erase();
                return Err(Error::InvalidKey);
            }
        };
        let tweaked = {
            let guard = EraseGuard(&mut parent);
            let result = guard.0.add_tweak(&scalar);
            scalar.non_secure_erase();
            result
        };
        let mut child = tweaked.map_err(|_| Error::InvalidKey)?;
        let out = Zeroizing::new(child.secret_bytes());
        child.non_secure_erase();
        Ok(out)
    }

    /// `point * scalar`. Used for an MWEB scan pubkey `A_i = a·B_i`.
    pub fn mul_point(&self, point: &[u8; 33], scalar: &[u8; 32]) -> Result<[u8; 33], Error> {
        let public = PublicKey::from_slice(point).map_err(|_| Error::InvalidKey)?;
        let mut tweak = Scalar::from_be_bytes(*scalar).map_err(|_| Error::InvalidKey)?;
        let product = public.mul_tweak(&self.secp, &tweak);
        tweak.non_secure_erase();
        let product = product.map_err(|_| Error::InvalidKey)?;
        let compressed = product.serialize();
        if compressed[0] != 0x02 && compressed[0] != 0x03 {
            return Err(Error::InvalidKey);
        }
        Ok(compressed)
    }

    /// BIP341/BIP86 key path. Empty script tree. The output key is tweaked.
    pub fn taproot(&self, key: &[u8]) -> Result<TaprootKeys, Error> {
        let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let guard = EraseGuard(&mut secret);
        let keypair = Keypair::from_secret_key(&self.secp, guard.0);
        drop(guard);
        let (internal, parity) = XOnlyPublicKey::from_keypair(&keypair);
        let internal_xonly = internal.serialize();
        let tweak_bytes = tagged_hash("TapTweak", &internal_xonly);
        let mut tweak = Scalar::from_be_bytes(tweak_bytes).map_err(|_| Error::InvalidKey)?;
        let tweaked = keypair
            .add_xonly_tweak(&self.secp, &tweak)
            .map_err(|_| Error::InvalidKey)?;
        tweak.non_secure_erase();
        let (output, _) = XOnlyPublicKey::from_keypair(&tweaked);
        let internal_compressed =
            PublicKey::from_x_only_public_key(internal, Parity::Even).serialize();
        Ok(TaprootKeys {
            internal_compressed,
            internal_xonly,
            internal_parity_odd: parity == Parity::Odd,
            output_xonly: output.serialize(),
        })
    }
}

/// 256 bits from the OS CSPRNG. BIP39 entropy is not itself a secp256k1 scalar.
pub fn random_entropy_32() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(entropy.as_mut_slice()).map_err(|_| Error::Rng)?;
    Ok(entropy)
}

/// One uniform valid scalar. Rejected draws are not returned.
pub fn random_scalar() -> Result<Zeroizing<[u8; 32]>, Error> {
    for _ in 0..1024 {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(key.as_mut_slice()).map_err(|_| Error::Rng)?;
        let mut secret = match SecretKey::from_slice(key.as_slice()) {
            Ok(secret) => secret,
            Err(_) => continue,
        };
        secret.non_secure_erase();
        return Ok(key);
    }
    Err(Error::Rng)
}

#[cfg(test)]
mod tests {
    use super::KeyEngine;

    #[test]
    fn generator_key_is_compressed_and_taproot_is_tweaked() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let engine = KeyEngine::new().unwrap();
        let public = engine.public_of(&key).unwrap();
        assert_eq!(public.key[0], 0x02);
        assert_eq!(
            public.hash160,
            [
                0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
                0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
            ]
        );
        let tap = engine.taproot(&key).unwrap();
        assert!(!tap.internal_parity_odd);
        assert_ne!(tap.internal_xonly, tap.output_xonly);
    }

    #[test]
    fn zero_and_the_curve_order_are_rejected() {
        let engine = KeyEngine::new().unwrap();
        assert!(engine.public_of(&[0u8; 32]).is_err());
        let order = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(engine.public_of(&order).is_err());
    }
}
