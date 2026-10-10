// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Litecoin mainnet constants.
//!
//! Source: Litecoin Core `src/chainparams.cpp` `CMainParams`, commit
//! `ec1b6489a900d09cf5991e220dce089c77a232a2`. Testnet and regtest values are
//! recorded so a test can prove this generator never emits them. They are not
//! generation parameters.
//!
//! `litecoin.info` lists MWEB HRP `ltc1mweb` and BIP32 public version
//! `0x0488B2E4`. Those bytes are not in Core. Core uses `ltcmweb` and
//! `{0x04, 0x88, 0xB2, 0x1E}`.

/// SLIP-0044 coin type for Litecoin. Bitcoin's coin type is 0.
pub const COIN_TYPE: u32 = 2;

pub const P2PKH_VERSION: u8 = 0x30;
/// Modern P2SH version. `EncodeDestination` writes this byte. Addresses start with `M`.
pub const P2SH_VERSION: u8 = 0x32;
/// Historical P2SH version. Decode accepts it. Encode uses it only in the named legacy mode.
pub const P2SH_LEGACY_VERSION: u8 = 0x05;
pub const WIF_VERSION: u8 = 0xB0;
pub const WIF_COMPRESSED_FLAG: u8 = 0x01;

pub const BECH32_HRP: &str = "ltc";
pub const MWEB_HRP: &str = "ltcmweb";

pub const BIP32_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
pub const BIP32_SECRET: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

/// Wiki typo. Must not be used.
pub const BIP32_PUBLIC_WIKI_TYPO: [u8; 4] = [0x04, 0x88, 0xB2, 0xE4];

/// SLIP-0132 Litecoin prefixes. Core does not use them.
pub const SLIP132_LTPV: [u8; 4] = [0x01, 0x9d, 0x9c, 0xfe];
pub const SLIP132_LTUB: [u8; 4] = [0x01, 0x9d, 0xa4, 0x62];

pub const GENESIS: &str = "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2";

pub const SEGWIT_HEIGHT: u32 = 1_201_536;
pub const TAPROOT_START_HEIGHT: u32 = 2_161_152;
pub const TAPROOT_TIMEOUT_HEIGHT: u32 = 2_370_816;
pub const MWEB_START_HEIGHT: u32 = 2_217_600;
pub const MWEB_TIMEOUT_HEIGHT: u32 = 2_427_264;
/// One expected week after height 3,150,408. Not consulted at generation time.
pub const MWEB_PEGOUT_FEATURE_HEIGHT: u32 = 3_154_440;
pub const MWEB_EXTRADATA_FEATURE_HEIGHT: u32 = 3_172_640;
pub const MESSAGE_START: [u8; 4] = [0xfb, 0xc0, 0xb6, 0xdb];
pub const DEFAULT_PORT: u16 = 9333;

/// Bitcoin mainnet values. Same-scalar tests must not produce these.
pub const BITCOIN_P2PKH_VERSION: u8 = 0x00;
pub const BITCOIN_WIF_VERSION: u8 = 0x80;
pub const BITCOIN_HRP: &str = "bc";
pub const BITCOIN_COIN_TYPE: u32 = 0;

/// Testnet parameters from `CTestNetParams` of the same commit. Never generated.
pub mod testnet {
    pub const P2PKH_VERSION: u8 = 111;
    /// `SCRIPT_ADDRESS2` in `CTestNetParams`. Not generated.
    pub const P2SH_VERSION: u8 = 58;
    /// `SCRIPT_ADDRESS` in `CTestNetParams`. Not generated.
    pub const P2SH_LEGACY_VERSION: u8 = 196;
    pub const WIF_VERSION: u8 = 239;
    pub const HRP: &str = "tltc";
    pub const MWEB_HRP: &str = "tmweb";
    pub const BIP32_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
    pub const BIP32_SECRET: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
}

/// Regtest HRPs from the same commit. Never generated.
pub mod regtest {
    pub const HRP: &str = "rltc";
    pub const MWEB_HRP: &str = "tmweb";
    pub const P2PKH_VERSION: u8 = 111;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
}

impl Network {
    pub fn parse(text: &str) -> Result<Self, super::super::error::Error> {
        if text.eq_ignore_ascii_case("mainnet") {
            Ok(Self::Mainnet)
        } else {
            Err(super::super::error::Error::prefix(
                "only Litecoin mainnet is supported",
            ))
        }
    }

    pub fn name(self) -> &'static str {
        "mainnet"
    }

    pub fn label(self) -> &'static str {
        "Mainnet"
    }
}

/// Every recorded chain parameter is read here so a release build cannot drop it.
pub(crate) fn chainparams_are_recorded() -> bool {
    BIP32_SECRET == [0x04, 0x88, 0xAD, 0xE4]
        && BIP32_PUBLIC_WIKI_TYPO != BIP32_PUBLIC
        && SLIP132_LTPV != BIP32_SECRET
        && SLIP132_LTUB != BIP32_PUBLIC
        && GENESIS == "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"
        && SEGWIT_HEIGHT == 1_201_536
        && TAPROOT_START_HEIGHT == 2_161_152
        && TAPROOT_TIMEOUT_HEIGHT == 2_370_816
        && MWEB_START_HEIGHT == 2_217_600
        && MWEB_TIMEOUT_HEIGHT == 2_427_264
        && MWEB_PEGOUT_FEATURE_HEIGHT == 3_154_440
        && MWEB_EXTRADATA_FEATURE_HEIGHT == 3_172_640
        && MESSAGE_START == [0xfb, 0xc0, 0xb6, 0xdb]
        && DEFAULT_PORT == 9333
        && BITCOIN_HRP == "bc"
        && testnet::P2PKH_VERSION == 111
        && testnet::P2SH_VERSION == 58
        && testnet::P2SH_LEGACY_VERSION == 196
        && testnet::WIF_VERSION == 239
        && testnet::HRP == "tltc"
        && testnet::MWEB_HRP == "tmweb"
        && testnet::BIP32_PUBLIC == [0x04, 0x35, 0x87, 0xCF]
        && testnet::BIP32_SECRET == [0x04, 0x35, 0x83, 0x94]
        && regtest::HRP == "rltc"
        && regtest::MWEB_HRP == "tmweb"
        && regtest::P2PKH_VERSION == 111
        && testnet::P2SH_VERSION != P2SH_VERSION
}

#[cfg(test)]
mod tests {
    use super::{
        regtest, testnet, BIP32_SECRET, BITCOIN_COIN_TYPE, BITCOIN_HRP, BITCOIN_P2PKH_VERSION,
        BITCOIN_WIF_VERSION, COIN_TYPE, DEFAULT_PORT, GENESIS, MESSAGE_START,
        MWEB_EXTRADATA_FEATURE_HEIGHT, MWEB_HRP, MWEB_PEGOUT_FEATURE_HEIGHT, MWEB_START_HEIGHT,
        MWEB_TIMEOUT_HEIGHT, P2PKH_VERSION, P2SH_LEGACY_VERSION, P2SH_VERSION, SEGWIT_HEIGHT,
        SLIP132_LTPV, TAPROOT_START_HEIGHT, TAPROOT_TIMEOUT_HEIGHT, WIF_VERSION,
    };

    #[test]
    fn mainnet_constants_differ_from_bitcoin_and_the_other_ltc_networks_are_recorded() {
        assert_eq!(P2PKH_VERSION, 0x30);
        assert_eq!(P2SH_VERSION, 0x32);
        assert_eq!(P2SH_LEGACY_VERSION, 0x05);
        assert_eq!(WIF_VERSION, 0xB0);
        assert_eq!(MWEB_HRP, "ltcmweb");
        assert_eq!(COIN_TYPE, 2);
        assert_eq!(BITCOIN_P2PKH_VERSION, 0x00);
        assert_eq!(BITCOIN_WIF_VERSION, 0x80);
        assert_eq!(BITCOIN_HRP, "bc");
        assert_eq!(BITCOIN_COIN_TYPE, 0);
        assert_ne!(P2PKH_VERSION, BITCOIN_P2PKH_VERSION);
        assert_ne!(WIF_VERSION, BITCOIN_WIF_VERSION);
        assert_ne!(COIN_TYPE, BITCOIN_COIN_TYPE);
        assert_eq!(testnet::P2PKH_VERSION, 111);
        assert_eq!(testnet::P2SH_VERSION, 58);
        assert_eq!(testnet::P2SH_LEGACY_VERSION, 196);
        assert_eq!(testnet::WIF_VERSION, 239);
        assert_eq!(testnet::HRP, "tltc");
        assert_eq!(testnet::MWEB_HRP, "tmweb");
        assert_eq!(testnet::BIP32_PUBLIC, [0x04, 0x35, 0x87, 0xCF]);
        assert_eq!(testnet::BIP32_SECRET, [0x04, 0x35, 0x83, 0x94]);
        assert_eq!(regtest::HRP, "rltc");
        assert_eq!(regtest::MWEB_HRP, "tmweb");
        assert_eq!(regtest::P2PKH_VERSION, 111);
        assert_ne!(testnet::P2PKH_VERSION, P2PKH_VERSION);
        assert_ne!(testnet::P2SH_VERSION, P2SH_VERSION);
        assert_eq!(MWEB_PEGOUT_FEATURE_HEIGHT, 3_154_440);
        assert_eq!(MWEB_EXTRADATA_FEATURE_HEIGHT, 3_172_640);
        assert_eq!(MESSAGE_START, [0xfb, 0xc0, 0xb6, 0xdb]);
        assert_eq!(DEFAULT_PORT, 9333);
        assert_eq!(
            GENESIS,
            "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"
        );
        assert_eq!(SEGWIT_HEIGHT, 1_201_536);
        assert_eq!(TAPROOT_START_HEIGHT, 2_161_152);
        assert_eq!(TAPROOT_TIMEOUT_HEIGHT, 2_370_816);
        assert_eq!(MWEB_START_HEIGHT, 2_217_600);
        assert_eq!(MWEB_TIMEOUT_HEIGHT, 2_427_264);
        assert_eq!(SLIP132_LTPV, [0x01, 0x9d, 0x9c, 0xfe]);
        assert_ne!(SLIP132_LTPV, BIP32_SECRET);
    }
}
