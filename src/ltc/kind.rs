// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::Error;

/// One Litecoin receiving-address engine. The CLI never infers this from the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2shP2wpkh,
    P2shP2wpkhLegacy,
    P2wpkh,
    P2tr,
    Mweb,
}

impl AddressKind {
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "p2pkh" => Ok(Self::P2pkh),
            "p2sh-p2wpkh" => Ok(Self::P2shP2wpkh),
            "p2sh-p2wpkh-legacy-prefix" => Ok(Self::P2shP2wpkhLegacy),
            "p2wpkh" => Ok(Self::P2wpkh),
            "p2tr" => Ok(Self::P2tr),
            "mweb" => Ok(Self::Mweb),
            _ => Err(Error::prefix(
                "type must be p2pkh, p2sh-p2wpkh, p2sh-p2wpkh-legacy-prefix, p2wpkh, p2tr, or mweb",
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2shP2wpkh => "p2sh-p2wpkh",
            Self::P2shP2wpkhLegacy => "p2sh-p2wpkh-legacy-prefix",
            Self::P2wpkh => "p2wpkh",
            Self::P2tr => "p2tr",
            Self::Mweb => "mweb",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::P2pkh => "P2PKH",
            Self::P2shP2wpkh => "P2SH-P2WPKH",
            Self::P2shP2wpkhLegacy => "P2SH-P2WPKH legacy prefix",
            Self::P2wpkh => "P2WPKH",
            Self::P2tr => "P2TR",
            Self::Mweb => "MWEB",
        }
    }

    pub fn encoding_label(self) -> &'static str {
        match self {
            Self::P2pkh | Self::P2shP2wpkh | Self::P2shP2wpkhLegacy => "Base58Check",
            Self::P2wpkh => "Bech32",
            Self::P2tr => "Bech32m",
            Self::Mweb => "Bech32",
        }
    }

    pub fn purpose(self) -> Option<u32> {
        match self {
            Self::P2pkh => Some(44),
            Self::P2shP2wpkh | Self::P2shP2wpkhLegacy => Some(49),
            Self::P2wpkh => Some(84),
            Self::P2tr => Some(86),
            Self::Mweb => None,
        }
    }

    pub fn version_byte(self) -> Option<u8> {
        match self {
            Self::P2pkh => Some(crate::ltc::network::P2PKH_VERSION),
            Self::P2shP2wpkh => Some(crate::ltc::network::P2SH_VERSION),
            Self::P2shP2wpkhLegacy => Some(crate::ltc::network::P2SH_LEGACY_VERSION),
            _ => None,
        }
    }

    pub fn fixed_prefix(self) -> &'static str {
        match self {
            Self::P2pkh => "L",
            Self::P2shP2wpkh => "M",
            Self::P2shP2wpkhLegacy => "3",
            Self::P2wpkh => "ltc1q",
            Self::P2tr => "ltc1p",
            Self::Mweb => "ltcmweb1qq",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchMode {
    Independent,
    HdIndex,
    MwebIndex,
    Collection,
}

impl SearchMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Independent => "independent",
            Self::HdIndex => "hd-index",
            Self::MwebIndex => "mweb-index",
            Self::Collection => "collection",
        }
    }

    pub fn for_kind(kind: AddressKind, hd: bool) -> Self {
        if kind == AddressKind::Mweb {
            Self::MwebIndex
        } else if hd {
            Self::HdIndex
        } else {
            Self::Independent
        }
    }
}
