// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Witness and MWEB string encoding.
//!
//! Segwit v0 uses Bech32. Segwit v1 uses Bech32m. The `bech32` crate's segwit
//! helper selects that checksum and rejects a program length Core would reject.
//! MWEB is not segwit: its string is longer than BIP173's 90 characters, so it
//! uses the crate's unlimited Bech32 path with an explicit version symbol.
//! Litecoin Core calls `bech32::Decode(str, true)` for the same reason
//! (`src/key_io.cpp`).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{segwit, Bech32, ByteIterExt, Fe32, Fe32IterExt, Hrp};

use crate::error::Error;
use crate::ltc::network::{BECH32_HRP, MWEB_HRP};

pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn charset_index(byte: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

pub fn mixed_case(text: &str) -> bool {
    let lower = text.bytes().any(|byte| byte.is_ascii_lowercase());
    let upper = text.bytes().any(|byte| byte.is_ascii_uppercase());
    lower && upper
}

fn ltc_hrp() -> Hrp {
    Hrp::parse(BECH32_HRP).expect("ltc is a valid HRP")
}

fn mweb_hrp() -> Hrp {
    Hrp::parse(MWEB_HRP).expect("ltcmweb is a valid HRP")
}

pub fn encode_segwit(version: u8, program: &[u8]) -> Result<String, Error> {
    let witness_version = Fe32::try_from(version).map_err(|_| Error::Encoding)?;
    segwit::encode(ltc_hrp(), witness_version, program).map_err(|_| Error::Encoding)
}

/// Version symbol 0, then convertbits of `payload`, Bech32, HRP `ltcmweb`.
pub fn encode_mweb(payload: &[u8]) -> Result<String, Error> {
    if payload.len() != 66 {
        return Err(Error::Encoding);
    }
    let version = Fe32::try_from(0u8).map_err(|_| Error::Encoding)?;
    let mut out = String::new();
    let iter = payload.iter().copied().bytes_to_fes();
    for ch in iter
        .with_checksum::<Bech32>(&mweb_hrp())
        .with_witness_version(version)
        .chars()
    {
        out.push(ch);
    }
    if out.len() > 1023 {
        return Err(Error::Encoding);
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegwitDecoded {
    pub hrp: String,
    pub version: u8,
    pub program: Vec<u8>,
}

pub fn decode_segwit(text: &str) -> Result<SegwitDecoded, Error> {
    if mixed_case(text) {
        return Err(Error::Encoding);
    }
    let (hrp, version, program) = segwit::decode(text).map_err(|_| Error::Checksum)?;
    let version = u8::from(version);
    Ok(SegwitDecoded {
        hrp: hrp.to_lowercase(),
        version,
        program,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MwebDecoded {
    pub payload: [u8; 66],
}

pub fn decode_mweb(text: &str) -> Result<MwebDecoded, Error> {
    if mixed_case(text) {
        return Err(Error::Encoding);
    }
    let checked = CheckedHrpstring::new::<Bech32>(text).map_err(|_| Error::Checksum)?;
    if checked.hrp().to_lowercase() != MWEB_HRP {
        return Err(Error::Encoding);
    }
    let data = checked.data_part_ascii_no_checksum();
    if data.first().copied() != Some(b'q') {
        return Err(Error::Encoding);
    }
    let mut symbols = Vec::with_capacity(data.len().saturating_sub(1));
    for byte in data.iter().skip(1) {
        symbols.push(charset_index(*byte).ok_or(Error::Encoding)?);
    }
    let bytes = convert_bits(&symbols, 5, 8, false).ok_or(Error::Encoding)?;
    if bytes.len() != 66 {
        return Err(Error::Encoding);
    }
    let mut payload = [0u8; 66];
    payload.copy_from_slice(&bytes);
    if !compressed_pair(&payload) {
        return Err(Error::Encoding);
    }
    Ok(MwebDecoded { payload })
}

pub fn compressed_pair(payload: &[u8; 66]) -> bool {
    (payload[0] == 0x02 || payload[0] == 0x03) && (payload[33] == 0x02 || payload[33] == 0x03)
}

/// Bitcoin `ConvertBits`. `from` and `to` are 5 or 8.
pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    if from == 0 || to == 0 || from > 8 || to > 8 {
        return None;
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
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

pub fn program_symbols(program: &[u8]) -> Result<Vec<u8>, Error> {
    convert_bits(program, 8, 5, true).ok_or(Error::Encoding)
}

#[cfg(test)]
mod tests {
    use super::encode_segwit;

    #[test]
    fn bip173_program_with_bitcoin_hrp_is_the_published_vector() {
        // The published vector uses HRP bc. Swapping in ltc must change the checksum.
        let program = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];
        let ltc = encode_segwit(0, &program).unwrap();
        assert!(ltc.starts_with("ltc1q"));
        assert_ne!(ltc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let bc = bech32::segwit::encode(bech32::hrp::BC, bech32::Fe32::Q, &program).unwrap();
        assert_eq!(bc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }
}
