// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decode an address. A leading character is not enough.
//!
//! WIF input is recognized only to avoid printing the secret. The payload is
//! dropped.

use crate::ltc::base58::base58check_decode;
use crate::ltc::network::{
    self, BECH32_HRP, MWEB_HRP, P2PKH_VERSION, P2SH_LEGACY_VERSION, P2SH_VERSION, WIF_VERSION,
};
use crate::ltc::witness::{decode_mweb, decode_segwit, mixed_case};

pub fn inspect(address: &str) -> String {
    if address.is_empty() || address.len() > 130 {
        return report(
            "unknown",
            "unknown",
            "unknown",
            "FAIL",
            "NO",
            "the input is empty or too long",
        );
    }
    if looks_bech32(address) {
        inspect_bech32(address)
    } else {
        inspect_base58(address)
    }
}

fn looks_bech32(address: &str) -> bool {
    let lower = address.to_ascii_lowercase();
    lower.starts_with("ltc1")
        || lower.starts_with("ltcmweb1")
        || lower.starts_with("tltc1")
        || lower.starts_with("rltc1")
        || lower.starts_with("tmweb1")
        || lower.starts_with("bc1")
}

fn inspect_bech32(address: &str) -> String {
    if mixed_case(address) {
        return report(
            "Litecoin mainnet",
            "unknown",
            "Bech32",
            "FAIL",
            "NO",
            "mixed-case Bech32 is invalid",
        );
    }
    let canonical = !address.bytes().any(|byte| byte.is_ascii_uppercase());
    let text = address.to_ascii_lowercase();
    let case_note = if canonical {
        String::new()
    } else {
        "All-uppercase Bech32 is not the canonical form this generator writes.".to_owned()
    };
    if text.starts_with(&format!("{MWEB_HRP}1")) || text.starts_with("tmweb1") {
        return inspect_mweb(&text, &case_note);
    }
    match decode_segwit(&text) {
        Ok(decoded) => {
            let (network, mainnet) = match decoded.hrp.as_str() {
                BECH32_HRP => ("Litecoin mainnet", true),
                network::testnet::HRP => ("Litecoin testnet", false),
                network::regtest::HRP => ("Litecoin regtest", false),
                "bc" => ("Bitcoin mainnet", false),
                other => (other, false),
            };
            let (kind, encoding) = match (decoded.version, decoded.program.len()) {
                (0, 20) => ("P2WPKH", "Bech32"),
                (0, 32) => ("P2WSH", "Bech32"),
                (1, 32) => ("P2TR", "Bech32m"),
                (version, length) => {
                    let note = format!(
                        "Witness version {version} with program length {length} is not a standard generated script. {case_note}"
                    );
                    return report(
                        network,
                        "witness",
                        if version == 0 { "Bech32" } else { "Bech32m" },
                        "PASS",
                        "NO",
                        note.trim(),
                    );
                }
            };
            report(
                network,
                kind,
                encoding,
                "PASS",
                if mainnet { "YES" } else { "NO" },
                case_note.trim(),
            )
        }
        Err(_) => {
            let note = if checksum_swapped(&text) {
                "the checksum variant does not match the witness version"
            } else {
                "checksum or witness program rejected"
            };
            report("Litecoin mainnet", "unknown", "Bech32", "FAIL", "NO", note)
        }
    }
}

fn inspect_mweb(text: &str, case_note: &str) -> String {
    if text.starts_with("tmweb1") {
        return report(
            "Litecoin testnet",
            "MWEB",
            "Bech32",
            "FAIL",
            "NO",
            "testnet MWEB is not a mainnet address",
        );
    }
    match decode_mweb(text) {
        Ok(_) => report(
            "Litecoin mainnet",
            "MWEB",
            "Bech32",
            "PASS",
            "YES",
            case_note,
        ),
        Err(_) => report(
            "Litecoin mainnet",
            "MWEB",
            "Bech32",
            "FAIL",
            "NO",
            "MWEB checksum failed or the payload is not two compressed keys",
        ),
    }
}

fn checksum_swapped(text: &str) -> bool {
    use bech32::primitives::decode::CheckedHrpstring;
    use bech32::{Bech32, Bech32m};
    let Some((_, data)) = text.rsplit_once('1') else {
        return false;
    };
    let Some(version) = data.bytes().next() else {
        return false;
    };
    let bech32_ok = CheckedHrpstring::new::<Bech32>(text).is_ok();
    let bech32m_ok = CheckedHrpstring::new::<Bech32m>(text).is_ok();
    if version == b'q' {
        !bech32_ok && bech32m_ok
    } else {
        bech32_ok && !bech32m_ok
    }
}

fn inspect_base58(address: &str) -> String {
    let payload = match base58check_decode(address) {
        Ok(payload) => payload,
        Err(_) => {
            return report(
                "Litecoin mainnet",
                "unknown",
                "Base58Check",
                "FAIL",
                "NO",
                "checksum failed or the text is not canonical Base58",
            );
        }
    };
    if payload.len() == 34 && payload[0] == WIF_VERSION {
        return report(
            "Litecoin mainnet",
            "not an address",
            "Base58Check",
            "PASS",
            "NO",
            "The input is Litecoin private-key material. It was not printed.",
        );
    }
    if payload.len() != 21 {
        return report(
            "Litecoin mainnet",
            "unknown",
            "Base58Check",
            "PASS",
            "NO",
            "checksum passed, but the payload length is not a Litecoin address",
        );
    }
    match payload[0] {
        P2PKH_VERSION => report("Litecoin mainnet", "P2PKH", "Base58Check", "PASS", "YES", ""),
        P2SH_VERSION => report("Litecoin mainnet", "P2SH", "Base58Check", "PASS", "YES", ""),
        P2SH_LEGACY_VERSION => report(
            "Litecoin mainnet",
            "P2SH",
            "Base58Check",
            "PASS",
            "YES",
            "Historical P2SH version 0x05. This is the legacy 3... form, and the version byte is the same byte Bitcoin uses.",
        ),
        0x00 => report(
            "Bitcoin mainnet",
            "P2PKH",
            "Base58Check",
            "PASS",
            "NO",
            "Version 0x00 is Bitcoin P2PKH.",
        ),
        network::testnet::P2PKH_VERSION => report(
            "Litecoin testnet",
            "P2PKH",
            "Base58Check",
            "PASS",
            "NO",
            "This generator does not create testnet addresses.",
        ),
        _ => report(
            "unknown",
            "unknown",
            "Base58Check",
            "PASS",
            "NO",
            "Checksum passed, but the version byte is not Litecoin mainnet.",
        ),
    }
}

fn report(
    network: &str,
    kind: &str,
    encoding: &str,
    checksum: &str,
    valid: &str,
    note: &str,
) -> String {
    let mut out = String::new();
    out.push_str("Network:\n");
    out.push_str(network);
    out.push_str("\n\nAddress type:\n");
    out.push_str(kind);
    out.push_str("\n\nEncoding:\n");
    out.push_str(encoding);
    out.push_str("\n\nChecksum:\n");
    out.push_str(checksum);
    out.push_str("\n\nValid:\n");
    out.push_str(valid);
    out.push('\n');
    if !note.is_empty() {
        out.push('\n');
        out.push_str(note);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::inspect;
    use crate::ltc::address::{p2pkh_address, p2sh_p2wpkh_address, p2tr_address, p2wpkh_address};
    use crate::ltc::keys::KeyEngine;

    #[test]
    fn scalar_one_addresses_validate_and_bitcoin_forms_do_not() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let engine = KeyEngine::new().unwrap();
        let public = engine.public_of(&key).unwrap();
        let p2pkh = p2pkh_address(&public.hash160);
        let report = inspect(&p2pkh);
        assert!(report.contains("Address type:\nP2PKH"), "{report}");
        assert!(report.contains("Valid:\nYES"), "{report}");
        assert!(report.contains("Checksum:\nPASS"), "{report}");
        let nested = p2sh_p2wpkh_address(&public.hash160, false);
        assert!(inspect(&nested).contains("Address type:\nP2SH"));
        assert!(nested.starts_with('M'));
        let legacy = p2sh_p2wpkh_address(&public.hash160, true);
        assert!(legacy.starts_with('3'));
        assert!(inspect(&legacy).contains("Historical P2SH"));
        let native = p2wpkh_address(&public.hash160).unwrap();
        assert!(inspect(&native).contains("Address type:\nP2WPKH"));
        let mixed: String = native
            .chars()
            .enumerate()
            .map(|(index, ch)| {
                if index == 5 {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                }
            })
            .collect();
        assert!(inspect(&mixed).contains("Valid:\nNO"));
        let tap = engine.taproot(&key).unwrap();
        let p2tr = p2tr_address(&tap.output_xonly).unwrap();
        assert!(inspect(&p2tr).contains("Bech32m"));
        assert!(inspect(&p2tr).contains("Valid:\nYES"));
        assert!(inspect("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").contains("Valid:\nNO"));
        assert!(inspect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").contains("Valid:\nNO"));
    }
}
