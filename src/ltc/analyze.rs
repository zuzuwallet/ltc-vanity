// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact vanity reachability.
//!
//! Base58 probabilities are the count of 21-byte version||HASH160 bodies whose
//! Base58Check integer lies in the target prefix range, divided by 2^160.
//! That count is not 58^n. Bech32 probabilities are 2^(-5n) only for n symbols
//! that sit in a uniform program window. MWEB charges 3 bits for the
//! constrained third payload character and 5 bits for each later uniform
//! symbol. The 2^-20 figure for `zuzu` is the convertbits count 32/2^25.

use crate::error::Error;
use crate::ltc::base58::{alphabet_index as base58_index, payload25, ALPHABET};
use crate::ltc::hash::checksum4;
use crate::ltc::kind::{AddressKind, SearchMode};
use crate::ltc::network::{P2PKH_VERSION, P2SH_LEGACY_VERSION, P2SH_VERSION};
use crate::ltc::uint::U256;
use crate::ltc::witness::{charset_index, convert_bits, program_symbols};

pub const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000;
pub(crate) const SEARCH_COUNTER_HEADROOM: u64 = 1_048_576;
const ADDRESS_LEN: u32 = 34;
/// Non-hardened BIP32 receive indices.
pub const HD_INDEX_SPACE: u64 = 1 << 31;
/// MWEB indices from [`crate::mweb::FIRST_RECEIVE_INDEX`] through `u32::MAX`.
pub const MWEB_INDEX_SPACE: u64 = (1u64 << 32) - 2;

const MWEB_HRP_SEP: &str = "ltcmweb1";
const MWEB_FIXED: &str = "ltcmweb1qq";
/// Charset values 8..=15. Symbol 1 of an MWEB payload is one of these.
const MWEB_THIRD: &[u8] = b"gf2tvdw0";

#[derive(Clone, Debug)]
enum Engine {
    Base58 { lo: U256, hi: U256 },
    Witness { symbols: Vec<u8> },
    Mweb { start: usize, values: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Analysis {
    pub requested: String,
    pub kind: AddressKind,
    pub encoding: &'static str,
    pub fixed_prefix: String,
    pub vanity: String,
    pub reachable: bool,
    pub reason: String,
    pub note: String,
    pub probability: String,
    pub expected: Option<u64>,
    pub median: Option<u64>,
    pub p90: Option<u64>,
    pub p99: Option<u64>,
    pub too_rare: bool,
    /// `Some(bits)` when q is exactly 2^(-bits).
    pub exact_bits: Option<u32>,
    target: String,
    engine: Option<Engine>,
}

impl Analysis {
    pub fn is_searchable(&self) -> bool {
        self.reachable && !self.too_rare && self.expected.is_some() && self.engine.is_some()
    }

    pub fn needs_large_search_confirmation(&self) -> bool {
        self.expected
            .is_some_and(|count| count >= CONFIRMATION_THRESHOLD)
    }

    pub fn needs_exhaust_confirmation(&self, hd: bool) -> bool {
        let space = match self.kind {
            AddressKind::Mweb => MWEB_INDEX_SPACE,
            _ if hd => HD_INDEX_SPACE,
            _ => return false,
        };
        match self.median {
            Some(median) => median > space,
            None => true,
        }
    }

    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str("Litecoin Vanity Target Analyzer\n\n");
        push_field(&mut out, "Network:", "Mainnet");
        push_field(&mut out, "Address type:", self.kind.label());
        push_field(&mut out, "Encoding:", self.encoding);
        push_field(&mut out, "Requested:", &self.requested);
        push_field(&mut out, "Fixed/protocol prefix:", &self.fixed_prefix);
        push_field(&mut out, "Vanity portion:", &self.vanity);
        push_field(
            &mut out,
            "Reachable:",
            if self.reachable { "YES" } else { "NO" },
        );
        if !self.reason.is_empty() {
            push_field(&mut out, "Reason:", &self.reason);
        }
        if self.reachable {
            push_field(&mut out, "Probability per candidate:", &self.probability);
            push_field(&mut out, "Expected attempts:", &display_u64(self.expected));
            push_field(&mut out, "50% probability:", &display_u64(self.median));
            push_field(&mut out, "90% probability:", &display_u64(self.p90));
            push_field(&mut out, "99% probability:", &display_u64(self.p99));
        }
        if !self.note.is_empty() {
            out.push_str(&self.note);
            if !self.note.ends_with('\n') {
                out.push('\n');
            }
        }
        out
    }

    pub fn reference_accepts(&self, address: &str) -> bool {
        match &self.engine {
            Some(Engine::Mweb { start, values }) => mweb_string_matches(address, *start, values),
            Some(_) => address.starts_with(&self.target),
            None => false,
        }
    }

    pub fn fast_accepts_hash(&self, hash: &[u8; 20]) -> Result<bool, Error> {
        match &self.engine {
            Some(Engine::Base58 { lo, hi }) => {
                let version = self.kind.version_byte().ok_or(Error::SearchFailed)?;
                Ok(payload_in_range(&payload25(version, hash), *lo, *hi))
            }
            Some(Engine::Witness { symbols }) if self.kind == AddressKind::P2wpkh => {
                let encoded = program_symbols(hash)?;
                Ok(encoded.starts_with(symbols))
            }
            _ => Err(Error::SearchFailed),
        }
    }

    pub fn fast_accepts_xonly(&self, xonly: &[u8; 32]) -> Result<bool, Error> {
        match &self.engine {
            Some(Engine::Witness { symbols }) if self.kind == AddressKind::P2tr => {
                let encoded = program_symbols(xonly)?;
                Ok(encoded.starts_with(symbols))
            }
            _ => Err(Error::SearchFailed),
        }
    }

    pub fn fast_accepts_mweb(&self, payload: &[u8; 66]) -> Result<bool, Error> {
        match &self.engine {
            Some(Engine::Mweb { start, values }) => {
                let symbols = convert_bits(payload, 8, 5, true).ok_or(Error::Encoding)?;
                Ok(symbols_match(&symbols, *start, values))
            }
            _ => Err(Error::SearchFailed),
        }
    }
}

pub fn analyze(kind: AddressKind, requested: &str) -> Result<Analysis, Error> {
    if requested.is_empty() || requested.len() > 130 {
        return Err(Error::prefix("target is empty or too long"));
    }
    match kind {
        AddressKind::P2pkh => analyze_base58(kind, P2PKH_VERSION, requested),
        AddressKind::P2shP2wpkh => analyze_base58(kind, P2SH_VERSION, requested),
        AddressKind::P2shP2wpkhLegacy => analyze_base58(kind, P2SH_LEGACY_VERSION, requested),
        AddressKind::P2wpkh => analyze_witness(kind, 0, 32, requested),
        AddressKind::P2tr => analyze_witness(kind, 1, 51, requested),
        AddressKind::Mweb => analyze_mweb(requested),
    }
}

pub fn require_searchable(analysis: &Analysis) -> Result<(), Error> {
    if !analysis.reachable {
        return Err(Error::prefix(if analysis.reason.is_empty() {
            "target is not reachable".to_owned()
        } else {
            analysis.reason.clone()
        }));
    }
    if analysis.too_rare || analysis.expected.is_none() {
        return Err(Error::prefix("target is too rare for the attempt counter"));
    }
    Ok(())
}

pub fn group_digits(digits: &str) -> String {
    let bytes = digits.as_bytes();
    let mut out = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && (bytes.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*byte as char);
    }
    out
}

fn analyze_base58(kind: AddressKind, version: u8, requested: &str) -> Result<Analysis, Error> {
    if requested.len() > ADDRESS_LEN as usize {
        return unreachable_analysis(kind, requested, "target is longer than a Litecoin address");
    }
    if requested.bytes().any(|byte| base58_index(byte).is_none()) {
        return unreachable_analysis(
            kind,
            requested,
            "target uses a character outside the Base58 alphabet",
        );
    }
    let (low, high) = version_bounds(version)?;
    let last = high
        .checked_sub(U256::from_u64(1))
        .ok_or_else(|| Error::prefix("empty version bucket"))?;
    let (low_text, high_text) = (encode_amount(low)?, encode_amount(last)?);
    if low_text.len() != ADDRESS_LEN as usize || high_text.len() != ADDRESS_LEN as usize {
        return Err(Error::prefix(
            "version bucket does not have one Base58 length",
        ));
    }
    let fixed = common_prefix(&low_text, &high_text);
    if !fixed.starts_with(kind.fixed_prefix()) {
        return Err(Error::prefix(
            "computed Base58 prefix does not match the version byte",
        ));
    }
    if !requested.starts_with(&fixed) {
        return unreachable_analysis(
            kind,
            requested,
            "target does not start with this address type's protocol prefix",
        );
    }
    let (range_lo, range_hi) = prefix_bounds(requested)?;
    let count = overlapping_bodies(version, range_lo, range_hi)?;
    if count.is_zero() {
        return unreachable_analysis(
            kind,
            requested,
            &format!(
                "no payload integer has this prefix. Version 0x{version:02x} only covers {low_text} through {high_text}"
            ),
        );
    }
    let vanity = requested[fixed.len()..].to_owned();
    let mut analysis = finish_ratio(
        kind,
        requested,
        fixed,
        vanity,
        requested.to_owned(),
        count,
        160,
        "Probability is the number of version||HASH160 payloads whose Base58Check integer starts with the target, divided by 2^160. Checksum bytes are included. This is not 58^n.",
    )?;
    analysis.engine = Some(Engine::Base58 {
        lo: range_lo,
        hi: range_hi,
    });
    Ok(analysis)
}

fn analyze_witness(
    kind: AddressKind,
    version: u8,
    uniform_symbols: usize,
    requested: &str,
) -> Result<Analysis, Error> {
    if crate::ltc::witness::mixed_case(requested) {
        return unreachable_analysis(kind, requested, "mixed-case Bech32 is rejected");
    }
    if requested.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return unreachable_analysis(kind, requested, "Bech32 targets must be lowercase");
    }
    let fixed = kind.fixed_prefix();
    if !requested.starts_with(fixed) {
        return unreachable_analysis(
            kind,
            requested,
            "target does not start with this address type's protocol prefix",
        );
    }
    let vanity = &requested[fixed.len()..];
    if vanity.len() > uniform_symbols {
        return unreachable_analysis(
            kind,
            requested,
            "target leaves the uniform witness-program window or enters the checksum",
        );
    }
    let mut symbols = Vec::with_capacity(vanity.len());
    for byte in vanity.bytes() {
        let value = charset_index(byte)
            .ok_or_else(|| Error::prefix("target uses a character outside the Bech32 alphabet"))?;
        symbols.push(value);
    }
    let bits = u32::try_from(symbols.len() * 5).map_err(|_| Error::prefix("target is too long"))?;
    let note = if version == 0 {
        "Witness version 0 uses Bech32. Each matched character is one aligned 5-bit group of HASH160. 2^(-5n) is exact inside the 32-symbol program. The 6-character checksum is not part of this target."
    } else {
        "Witness version 1 uses Bech32m. The address encodes the tweaked x-only output key. The first 51 symbols are uniform 5-bit groups. The final padded symbol is not part of this target. 2^(-5n) applies only after the TapTweak."
    };
    let mut analysis = finish_bits(
        kind,
        requested,
        fixed.to_owned(),
        vanity.to_owned(),
        requested.to_owned(),
        bits,
        note,
    )?;
    analysis.engine = Some(Engine::Witness { symbols });
    Ok(analysis)
}

fn analyze_mweb(requested: &str) -> Result<Analysis, Error> {
    if crate::ltc::witness::mixed_case(requested) {
        return unreachable_analysis(
            AddressKind::Mweb,
            requested,
            "mixed-case Bech32 is rejected",
        );
    }
    if requested.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return unreachable_analysis(
            AddressKind::Mweb,
            requested,
            "MWEB addresses are canonical lowercase Bech32",
        );
    }
    if requested.contains('1') {
        analyze_mweb_prefix(requested)
    } else {
        analyze_mweb_motif(requested)
    }
}

fn analyze_mweb_prefix(requested: &str) -> Result<Analysis, Error> {
    if !requested.starts_with(MWEB_HRP_SEP) {
        return unreachable_analysis(
            AddressKind::Mweb,
            requested,
            "an MWEB address starts with ltcmweb1, not ltc1mweb",
        );
    }
    let data = &requested[MWEB_HRP_SEP.len()..];
    let bits = match mweb_prefix_bits(data) {
        Ok(bits) => bits,
        Err(reason) => return unreachable_analysis(AddressKind::Mweb, requested, reason),
    };
    let values = data
        .bytes()
        .skip(1)
        .map(|byte| charset_index(byte).unwrap_or(0))
        .collect::<Vec<_>>();
    let vanity = requested.strip_prefix(MWEB_FIXED).unwrap_or("").to_owned();
    let note = "MWEB HRP is ltcmweb. Version symbol q and the next symbol q are fixed by the compressed scan key. A specified third character costs 3 bits. Later characters inside the scan-key window cost 5 bits each. This is not 32^n.";
    let mut analysis = finish_bits(
        AddressKind::Mweb,
        requested,
        MWEB_FIXED.to_owned(),
        vanity,
        requested.to_owned(),
        bits,
        note,
    )?;
    analysis.engine = Some(Engine::Mweb { start: 0, values });
    Ok(analysis)
}

fn analyze_mweb_motif(requested: &str) -> Result<Analysis, Error> {
    let mut values = Vec::with_capacity(requested.len());
    for byte in requested.bytes() {
        match charset_index(byte) {
            Some(value) => values.push(value),
            None => {
                return unreachable_analysis(
                    AddressKind::Mweb,
                    requested,
                    "motif uses a character outside the Bech32 alphabet",
                );
            }
        }
    }
    let Some(start) = earliest_mweb_start(&values) else {
        return unreachable_analysis(
            AddressKind::Mweb,
            requested,
            "motif does not fit in the uniform MWEB scan-key window",
        );
    };
    let mut bits = 0u32;
    for (offset, value) in values.iter().enumerate() {
        bits = bits.saturating_add(
            mweb_slot_cost(start + offset, *value)
                .ok_or_else(|| Error::prefix("motif is not reachable at its earliest offset"))?,
        );
    }
    let mut note = String::from(
        "Earliest placement accepts any third character from g, f, 2, t, v, d, w, 0 and then the motif. ",
    );
    note.push_str("That third character is not charged, because all eight are legal. ");
    note.push_str("A convertbits enumeration of the four-character motif zuzu finds 32 windows in 2^25, which is 2^-20. ");
    note.push_str("A single third character, such as ltcmweb1qqgzuzu, is 2^-23. ");
    note.push_str(
        "ltc1mwebzuzu, ltcmweb1zuzu, ltcmweb1qzuzu, and ltcmweb1qqzuzu are not reachable.",
    );
    let mut analysis = finish_bits(
        AddressKind::Mweb,
        requested,
        MWEB_FIXED.to_owned(),
        requested.to_owned(),
        format!(
            "{MWEB_FIXED}[{}]",
            std::str::from_utf8(MWEB_THIRD).unwrap_or("")
        ),
        bits,
        &note,
    )?;
    analysis.engine = Some(Engine::Mweb { start, values });
    Ok(analysis)
}

fn finish_bits(
    kind: AddressKind,
    requested: &str,
    fixed: String,
    vanity: String,
    target: String,
    bits: u32,
    note: &str,
) -> Result<Analysis, Error> {
    let probability = if bits == 0 {
        "1 / 1".to_owned()
    } else {
        format!("1 / 2^{bits}")
    };
    let expected = if bits == 0 {
        Some(1)
    } else if bits < 64 {
        Some(1u64 << bits)
    } else {
        None
    };
    Ok(probabilities(
        kind,
        requested,
        fixed,
        vanity,
        target,
        true,
        String::new(),
        probability,
        expected,
        bits,
        note,
    ))
}

#[allow(clippy::too_many_arguments)]
fn finish_ratio(
    kind: AddressKind,
    requested: &str,
    fixed: String,
    vanity: String,
    target: String,
    count: U256,
    shift: u32,
    note: &str,
) -> Result<Analysis, Error> {
    if count.is_zero() {
        return unreachable_analysis(kind, requested, "no payload integer has this prefix");
    }
    let q = count.div_pow2_f64(shift);
    if !q.is_finite() || q <= 0.0 {
        return Err(Error::prefix("probability could not be computed"));
    }
    let q = q.min(1.0);
    let expected = if q >= 1.0 {
        Some(1)
    } else {
        let inverse = 1.0 / q;
        if inverse > u64::MAX as f64 {
            None
        } else {
            Some(inverse.round() as u64)
        }
    };
    let probability = if q >= 1.0 {
        "1 / 1".to_owned()
    } else if let Some(expected) = expected {
        format!("1 / {}", group_digits(&expected.to_string()))
    } else {
        "too small for the attempt counter".to_owned()
    };
    Ok(probabilities(
        kind,
        requested,
        fixed,
        vanity,
        target,
        true,
        String::new(),
        probability,
        expected,
        0,
        note,
    ))
}

#[allow(clippy::too_many_arguments)]
fn probabilities(
    kind: AddressKind,
    requested: &str,
    fixed: String,
    vanity: String,
    target: String,
    reachable: bool,
    reason: String,
    probability: String,
    expected: Option<u64>,
    exact_bits: u32,
    note: &str,
) -> Analysis {
    let q = expected.and_then(|value| {
        if value == 0 {
            None
        } else {
            Some(1.0 / value as f64)
        }
    });
    let median = q.and_then(|q| attempts_for(0.50, q));
    let p90 = q.and_then(|q| attempts_for(0.90, q));
    let p99 = q.and_then(|q| attempts_for(0.99, q));
    let too_rare = expected.is_none()
        || expected.is_some_and(|value| value > u64::MAX.saturating_sub(SEARCH_COUNTER_HEADROOM));
    Analysis {
        requested: requested.to_owned(),
        kind,
        encoding: kind.encoding_label(),
        fixed_prefix: fixed,
        vanity,
        reachable,
        reason,
        note: note.to_owned(),
        probability,
        expected: if too_rare { None } else { expected },
        median: if too_rare { None } else { median },
        p90: if too_rare { None } else { p90 },
        p99: if too_rare { None } else { p99 },
        too_rare,
        exact_bits: if exact_bits == 0 && expected != Some(1) {
            None
        } else {
            Some(exact_bits)
        },
        target,
        engine: None,
    }
}

fn unreachable_analysis(
    kind: AddressKind,
    requested: &str,
    reason: &str,
) -> Result<Analysis, Error> {
    Ok(Analysis {
        requested: requested.to_owned(),
        kind,
        encoding: kind.encoding_label(),
        fixed_prefix: kind.fixed_prefix().to_owned(),
        vanity: String::new(),
        reachable: false,
        reason: reason.to_owned(),
        note: String::new(),
        probability: String::new(),
        expected: None,
        median: None,
        p90: None,
        p99: None,
        too_rare: false,
        exact_bits: None,
        target: String::new(),
        engine: None,
    })
}

fn attempts_for(probability: f64, q: f64) -> Option<u64> {
    if !(0.0 < probability && probability < 1.0) || q <= 0.0 {
        return None;
    }
    if q >= 1.0 {
        return Some(1);
    }
    let ratio = f64::ln_1p(-probability) / f64::ln_1p(-q);
    if !ratio.is_finite() || ratio > u64::MAX as f64 {
        return None;
    }
    Some(ratio.ceil() as u64)
}

fn version_bounds(version: u8) -> Result<(U256, U256), Error> {
    let low = U256::from_u64(u64::from(version))
        .checked_shl(192)
        .ok_or_else(|| Error::prefix("version shift overflow"))?;
    let high = U256::from_u64(u64::from(version) + 1)
        .checked_shl(192)
        .ok_or_else(|| Error::prefix("version shift overflow"))?;
    Ok((low, high))
}

fn prefix_bounds(prefix: &str) -> Result<(U256, U256), Error> {
    let mut value = U256::ZERO;
    for byte in prefix.bytes() {
        let digit = u64::from(base58_index(byte).ok_or_else(|| Error::prefix("bad base58"))?);
        value = value
            .checked_mul(U256::from_u64(58))
            .and_then(|item| item.checked_add_u64(digit))
            .ok_or_else(|| Error::prefix("prefix integer overflow"))?;
    }
    let scale = U256::pow_u64(58, ADDRESS_LEN - prefix.len() as u32)
        .ok_or_else(|| Error::prefix("base58 scale overflow"))?;
    let next = value
        .checked_add_u64(1)
        .ok_or_else(|| Error::prefix("prefix integer overflow"))?;
    let lo = value
        .checked_mul(scale)
        .ok_or_else(|| Error::prefix("prefix range overflow"))?;
    let hi = next
        .checked_mul(scale)
        .ok_or_else(|| Error::prefix("prefix range overflow"))?;
    Ok((lo, hi))
}

fn overlapping_bodies(version: u8, lo: U256, hi: U256) -> Result<U256, Error> {
    let (bucket_lo, bucket_hi) = version_bounds(version)?;
    let span_lo = if lo > bucket_lo { lo } else { bucket_lo };
    let span_hi = if hi < bucket_hi { hi } else { bucket_hi };
    if span_lo >= span_hi {
        return Ok(U256::ZERO);
    }
    let full_start = span_lo
        .ceil_shr(32)
        .ok_or_else(|| Error::prefix("body start overflow"))?;
    let full_end = span_hi.shr(32);
    let mut count = if full_end > full_start {
        full_end
            .checked_sub(full_start)
            .ok_or_else(|| Error::prefix("body count underflow"))?
    } else {
        U256::ZERO
    };
    let low_body = span_lo.shr(32);
    let high_body = span_hi
        .checked_sub(U256::from_u64(1))
        .ok_or_else(|| Error::prefix("empty span"))?
        .shr(32);
    for body in [low_body, high_body] {
        if body >= full_start && body < full_end {
            continue;
        }
        if boundary_hit(version, body, span_lo, span_hi)? {
            count = count
                .checked_add_u64(1)
                .ok_or_else(|| Error::prefix("body count overflow"))?;
        }
    }
    Ok(count)
}

fn boundary_hit(version: u8, body: U256, lo: U256, hi: U256) -> Result<bool, Error> {
    let Some(bytes) = body.to_be_fixed::<21>() else {
        return Ok(false);
    };
    if bytes[0] != version {
        return Ok(false);
    }
    let sum = checksum4(&bytes);
    let mut payload = [0u8; 25];
    payload[..21].copy_from_slice(&bytes);
    payload[21..].copy_from_slice(&sum);
    let value = U256::from_be_bytes(&payload).ok_or_else(|| Error::prefix("payload overflow"))?;
    Ok(value >= lo && value < hi)
}

fn payload_in_range(payload: &[u8; 25], lo: U256, hi: U256) -> bool {
    match U256::from_be_bytes(payload) {
        Some(value) => value >= lo && value < hi,
        None => false,
    }
}

fn encode_amount(mut value: U256) -> Result<String, Error> {
    if value.is_zero() {
        return Ok("1".to_owned());
    }
    let mut digits = Vec::new();
    while !value.is_zero() {
        let (quot, rem) = value
            .div_rem_u64(58)
            .ok_or_else(|| Error::prefix("base58 division failed"))?;
        digits.push(ALPHABET[rem as usize]);
        value = quot;
    }
    digits.reverse();
    String::from_utf8(digits).map_err(|_| Error::prefix("base58 alphabet was not ASCII"))
}

fn common_prefix(left: &str, right: &str) -> String {
    left.chars()
        .zip(right.chars())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect()
}

fn mweb_prefix_bits(data: &str) -> Result<u32, &'static str> {
    if data.len() > 107 {
        return Err("prefix enters the MWEB checksum");
    }
    let mut bits = 0u32;
    for (index, byte) in data.bytes().enumerate() {
        let value = charset_index(byte).ok_or("character is outside the Bech32 alphabet")?;
        if index == 0 {
            if value != 0 {
                return Err("the MWEB version symbol is q");
            }
            continue;
        }
        bits = bits.saturating_add(
            mweb_slot_cost(index - 1, value).ok_or("that MWEB symbol is not reachable")?,
        );
    }
    Ok(bits)
}

fn mweb_slot_cost(index: usize, value: u8) -> Option<u32> {
    match index {
        0 if value == 0 => Some(0),
        1 if (8..=15).contains(&value) => Some(3),
        2..=51 if value < 32 => Some(5),
        _ => None,
    }
}

fn earliest_mweb_start(values: &[u8]) -> Option<usize> {
    if values.is_empty() {
        return None;
    }
    (0..=51).find(|start| {
        values
            .iter()
            .enumerate()
            .all(|(offset, value)| mweb_slot_cost(start + offset, *value).is_some())
    })
}

fn symbols_match(symbols: &[u8], start: usize, values: &[u8]) -> bool {
    let end = start.saturating_add(values.len());
    symbols.len() >= end && symbols[start..end] == *values
}

fn mweb_string_matches(address: &str, start: usize, values: &[u8]) -> bool {
    let Some(data) = address.strip_prefix(MWEB_HRP_SEP) else {
        return false;
    };
    let data = data.as_bytes();
    if data.len() < 1 + start + values.len() {
        return false;
    }
    if data[0] != b'q' {
        return false;
    }
    let payload = &data[1..];
    values.iter().enumerate().all(|(offset, value)| {
        payload
            .get(start + offset)
            .and_then(|byte| charset_index(*byte))
            == Some(*value)
    })
}

fn bounded_space(kind: AddressKind, mode: SearchMode) -> Option<(&'static str, u64)> {
    match mode {
        SearchMode::HdIndex => Some(("HD receive-index space:", HD_INDEX_SPACE)),
        SearchMode::MwebIndex => Some(("MWEB receive-index space:", MWEB_INDEX_SPACE)),
        SearchMode::Collection if kind == AddressKind::Mweb => {
            Some(("MWEB receive-index space:", MWEB_INDEX_SPACE))
        }
        SearchMode::Collection => Some(("HD receive-index space:", HD_INDEX_SPACE)),
        SearchMode::Independent => None,
    }
}

fn push_line(out: &mut String, label: &str, value: &str) {
    out.push_str(label);
    out.push('\n');
    out.push_str(value);
    out.push('\n');
}

/// Unlimited geometric expectation, plus the HD or MWEB index bound when that mode is finite.
pub fn difficulty_text(analysis: &Analysis, mode: SearchMode) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        "Expected attempts:",
        &display_u64(analysis.expected),
    );
    if let Some((label, space)) = bounded_space(analysis.kind, mode) {
        out.push_str(&bounded_lines(analysis, label, space));
    } else {
        push_line(&mut out, "50% probability:", &display_u64(analysis.median));
        push_line(&mut out, "90% probability:", &display_u64(analysis.p90));
        push_line(&mut out, "99% probability:", &display_u64(analysis.p99));
    }
    out
}

/// Index-space correction printed after an analyzer report when a quantile is past the mnemonic.
pub fn finite_block(analysis: &Analysis, mode: SearchMode) -> Option<String> {
    if !analysis.reachable {
        return None;
    }
    let (label, space) = bounded_space(analysis.kind, mode)?;
    let past = match analysis.median {
        Some(median) => median > space,
        None => true,
    };
    if !past {
        return None;
    }
    Some(bounded_lines(analysis, label, space))
}

fn bounded_lines(analysis: &Analysis, label: &str, space: u64) -> String {
    let mut out = String::new();
    push_line(&mut out, label, &group_digits(&space.to_string()));
    push_line(
        &mut out,
        "Maximum success probability:",
        &maximum_success(analysis.expected, space),
    );
    push_line(
        &mut out,
        "50% probability:",
        &quantile_text(analysis.median, space),
    );
    push_line(
        &mut out,
        "90% probability:",
        &quantile_text(analysis.p90, space),
    );
    push_line(
        &mut out,
        "99% probability:",
        &quantile_text(analysis.p99, space),
    );
    out
}

fn quantile_text(count: Option<u64>, space: u64) -> String {
    match count {
        Some(count) if count <= space => group_digits(&count.to_string()),
        _ => "not reachable within this mnemonic".to_owned(),
    }
}

/// `1 - (1 - q)^N`, with `q = 1/expected` and `N` the receive-index space.
fn maximum_success(expected: Option<u64>, space: u64) -> String {
    let Some(expected) = expected.filter(|value| *value > 0) else {
        return "too small for the attempt counter".to_owned();
    };
    if expected == 1 {
        return "100%".to_owned();
    }
    let q = 1.0 / (expected as f64);
    let log_miss = (space as f64) * f64::ln_1p(-q);
    if !log_miss.is_finite() {
        return "too small for the attempt counter".to_owned();
    }
    format_percent((-log_miss.exp_m1()).clamp(0.0, 1.0))
}

fn format_percent(probability: f64) -> String {
    if !probability.is_finite() || probability <= 0.0 {
        return "0%".to_owned();
    }
    if probability >= 1.0 {
        return "100%".to_owned();
    }
    let percent = probability * 100.0;
    let two = format!("{percent:.2}");
    if two == "100.00" {
        return "100%".to_owned();
    }
    if two != "0.00" {
        return format!("{two}%");
    }
    let six = format!("{percent:.6}");
    if six == "0.000000" {
        format!("{percent:.3e}%")
    } else {
        format!("{six}%")
    }
}

fn push_field(out: &mut String, label: &str, value: &str) {
    out.push_str(label);
    out.push('\n');
    out.push_str(value);
    out.push_str("\n\n");
}

fn display_u64(value: Option<u64>) -> String {
    match value {
        Some(value) => group_digits(&value.to_string()),
        None => "n/a".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, difficulty_text, earliest_mweb_start, encode_amount, finite_block, version_bounds,
    };
    use crate::ltc::hash::hash160;
    use crate::ltc::keys::KeyEngine;
    use crate::ltc::kind::{AddressKind, SearchMode};
    use crate::ltc::uint::U256;
    use crate::ltc::witness::CHARSET;
    use crate::ltc::witness::{convert_bits, program_symbols};

    #[test]
    fn version_buckets_are_34_characters_and_start_with_the_documented_letter() {
        for (version, prefix) in [(0x30u8, "L"), (0x32, "M"), (0x05, "3")] {
            let (low, high) = version_bounds(version).unwrap();
            let low_text = encode_amount(low).unwrap();
            let high_text = encode_amount(high.checked_sub(U256::from_u64(1)).unwrap()).unwrap();
            assert_eq!(low_text.len(), 34, "{prefix} low {low_text}");
            assert_eq!(high_text.len(), 34, "{prefix} high {high_text}");
            assert!(low_text.starts_with(prefix), "{low_text}");
            assert!(high_text.starts_with(prefix), "{high_text}");
        }
    }

    #[test]
    fn witness_zuzu_is_exactly_20_bits() {
        let native = analyze(AddressKind::P2wpkh, "ltc1qzuzu").unwrap();
        assert!(native.reachable);
        assert_eq!(native.exact_bits, Some(20));
        assert_eq!(native.expected, Some(1 << 20));
        assert_eq!(native.vanity, "zuzu");
        let tap = analyze(AddressKind::P2tr, "ltc1pzuzu").unwrap();
        assert_eq!(tap.exact_bits, Some(20));
        assert!(!analyze(AddressKind::P2wpkh, "ltc1qZuZu").unwrap().reachable);
        assert!(!analyze(AddressKind::P2tr, "ltc1qzuzu").unwrap().reachable);
    }

    #[test]
    fn base58_rejects_a_prefix_for_the_wrong_version_and_keeps_case() {
        let wrong = analyze(AddressKind::P2pkh, "MZuZu").unwrap();
        assert!(!wrong.reachable);
        let exact = analyze(AddressKind::P2pkh, "LZuZu").unwrap();
        let folded = analyze(AddressKind::P2pkh, "Lzuzu").unwrap();
        assert!(exact.reachable, "{}", exact.reason);
        assert!(
            !folded.reachable,
            "lowercase z sits past the version-0x30 Base58 range"
        );
        assert_ne!(exact.expected, Some(58u64.pow(4)));
        let nested = analyze(AddressKind::P2shP2wpkh, "MZuZu").unwrap();
        assert!(
            !nested.reachable,
            "Z is past the version-0x32 second-character range"
        );
        let earliest = analyze(AddressKind::P2shP2wpkh, "M8ZuZu").unwrap();
        assert!(earliest.reachable, "{}", earliest.reason);
        assert_ne!(earliest.expected, Some(58u64.pow(5)));
        let only_l = analyze(AddressKind::P2pkh, "L").unwrap();
        assert_eq!(only_l.expected, Some(1));
    }

    #[test]
    fn mweb_zuzu_is_the_enumerated_window_and_the_shifted_forms_are_not() {
        let motif = analyze(AddressKind::Mweb, "zuzu").unwrap();
        assert!(motif.reachable, "{}", motif.reason);
        assert_eq!(motif.exact_bits, Some(20));
        assert_eq!(motif.fixed_prefix, "ltcmweb1qq");
        let specific = analyze(AddressKind::Mweb, "ltcmweb1qqgzuzu").unwrap();
        assert!(specific.reachable, "{}", specific.reason);
        assert_eq!(specific.exact_bits, Some(23));
        for blocked in [
            "ltc1mwebzuzu",
            "ltcmweb1zuzu",
            "ltcmweb1qzuzu",
            "ltcmweb1qqzuzu",
        ] {
            let analysis = analyze(AddressKind::Mweb, blocked).unwrap();
            assert!(!analysis.reachable, "{blocked} was accepted");
        }
    }

    #[test]
    fn zuzu_window_matches_convertbits_on_32_of_2_to_the_25() {
        let mut matches = 0u32;
        let mut thirds = [false; 8];
        for b0 in [2u8, 3] {
            for b1 in 0u16..=255 {
                for b2 in 0u16..=255 {
                    for b3 in 0u16..=255 {
                        let symbols = inline_symbols(b0, b1 as u8, b2 as u8, b3 as u8);
                        if symbols[2] == 2
                            && symbols[3] == 28
                            && symbols[4] == 2
                            && symbols[5] == 28
                        {
                            matches += 1;
                            let third = symbols[1];
                            assert!((8..=15).contains(&third));
                            thirds[(third - 8) as usize] = true;
                            let via = convert_bits(&[b0, b1 as u8, b2 as u8, b3 as u8], 8, 5, true)
                                .unwrap();
                            assert_eq!(&via[..6], &symbols[..6]);
                        }
                    }
                }
            }
        }
        assert_eq!(matches, 32);
        assert!(thirds.iter().all(|item| *item));
        let sample = [0x02u8, 0x05, 0xC1, 0x70];
        let symbols = convert_bits(&sample, 8, 5, true).unwrap();
        assert_eq!(symbols[0], 0);
        assert_eq!(CHARSET[symbols[1] as usize], b'g');
        assert_eq!(&symbols[2..6], &[2, 28, 2, 28]);
        assert_eq!(earliest_mweb_start(&[2, 28, 2, 28]), Some(2));
    }

    fn inline_symbols(b0: u8, b1: u8, b2: u8, b3: u8) -> [u8; 6] {
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut out = [0u8; 6];
        let mut count = 0usize;
        for value in [b0, b1, b2, b3] {
            acc = (acc << 8) | u32::from(value);
            bits += 8;
            while bits >= 5 && count < 6 {
                bits -= 5;
                out[count] = ((acc >> bits) & 31) as u8;
                count += 1;
            }
        }
        out
    }

    #[test]
    fn optimized_base58_and_witness_matchers_agree_with_the_reference_string() {
        let analysis = analyze(AddressKind::P2pkh, "L").unwrap();
        let nested = analyze(AddressKind::P2shP2wpkh, "M").unwrap();
        let native = analyze(AddressKind::P2wpkh, "ltc1q").unwrap();
        let engine = KeyEngine::new().unwrap();
        for last in 1u8..40 {
            let mut key = [0u8; 32];
            key[31] = last;
            let public = engine.public_of(&key).unwrap();
            let address = crate::ltc::address::p2pkh_address(&public.hash160);
            let fast = analysis.fast_accepts_hash(&public.hash160).unwrap();
            assert_eq!(fast, analysis.reference_accepts(&address));
            let specific = analyze(AddressKind::P2pkh, &address[..4]).unwrap();
            assert!(specific.fast_accepts_hash(&public.hash160).unwrap());
            assert!(specific.reference_accepts(&address));
            let mut wrong = address[..4].to_owned();
            wrong.replace_range(
                1..2,
                if wrong.as_bytes()[1] == b'Z' {
                    "Y"
                } else {
                    "Z"
                },
            );
            if wrong != address[..4] {
                let missed = analyze(AddressKind::P2pkh, &wrong).unwrap();
                if missed.reachable {
                    assert!(!missed.fast_accepts_hash(&public.hash160).unwrap());
                    assert!(!missed.reference_accepts(&address));
                }
            }
            let redeem_hash = hash160(&crate::ltc::address::p2wpkh_redeem(&public.hash160));
            let nested_address = crate::ltc::address::p2sh_p2wpkh_address(&public.hash160, false);
            assert_eq!(
                nested.fast_accepts_hash(&redeem_hash).unwrap(),
                nested.reference_accepts(&nested_address)
            );
            let native_address = crate::ltc::address::p2wpkh_address(&public.hash160).unwrap();
            assert_eq!(
                native.fast_accepts_hash(&public.hash160).unwrap(),
                native.reference_accepts(&native_address)
            );
            let symbols = program_symbols(&public.hash160).unwrap();
            assert_eq!(native_address.starts_with("ltc1q"), symbols[0] < 32);
        }
    }

    #[test]
    fn finite_modes_replace_quantiles_past_the_index_space() {
        let hard = analyze(AddressKind::P2wpkh, "ltc1qzuzuzuz").unwrap();
        assert_eq!(hard.expected, Some(34_359_738_368));
        let text = difficulty_text(&hard, SearchMode::HdIndex);
        assert!(text.contains("Expected attempts:\n34,359,738,368\n"));
        assert!(text.contains("HD receive-index space:\n2,147,483,648\n"));
        assert!(text.contains("Maximum success probability:\n6.06%\n"));
        assert_eq!(
            text.matches("not reachable within this mnemonic").count(),
            3
        );
        let report = hard.report();
        assert!(report.contains("Expected attempts:\n34,359,738,368"));
        assert!(!report.contains("One HD mnemonic"));
        assert!(!report.contains("does not reach a 50% chance"));
        assert!(!report.contains("not reachable within this mnemonic"));
        let independent = difficulty_text(&hard, SearchMode::Independent);
        assert!(!independent.contains("HD receive-index space"));
        assert!(!independent.contains("not reachable within this mnemonic"));

        let easy = analyze(AddressKind::P2wpkh, "ltc1q").unwrap();
        let easy_text = difficulty_text(&easy, SearchMode::HdIndex);
        assert!(easy_text.contains("Maximum success probability:\n100%\n"));
        assert!(easy_text.contains("50% probability:\n1\n"));
        assert!(!easy_text.contains("not reachable"));
        assert!(finite_block(&easy, SearchMode::HdIndex).is_none());
        assert!(!easy.report().contains("does not reach a 50% chance"));

        let mweb = analyze(AddressKind::Mweb, "zuzuzuzu").unwrap();
        assert!(mweb.reachable, "{}", mweb.reason);
        assert_eq!(mweb.exact_bits, Some(40));
        let mweb_text = difficulty_text(&mweb, SearchMode::MwebIndex);
        assert!(mweb_text.contains("MWEB receive-index space:\n4,294,967,294\n"));
        assert_eq!(
            mweb_text
                .matches("not reachable within this mnemonic")
                .count(),
            3
        );
        let mweb_report = mweb.report();
        assert!(!mweb_report.contains("One MWEB keychain"));
        assert!(!mweb_report.contains("does not reach a 50% chance"));
        assert!(finite_block(&mweb, SearchMode::MwebIndex).is_some());
        assert!(finite_block(
            &analyze(AddressKind::P2pkh, "LZuZu").unwrap(),
            SearchMode::HdIndex
        )
        .is_none());
    }
}
