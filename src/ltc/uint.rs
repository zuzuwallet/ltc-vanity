// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 256-bit integers for Base58 prefix ranges.
//!
//! A 25-byte Base58Check payload is 200 bits. Four little-endian `u64` limbs
//! cover it. This is not a field implementation and it is not used for keys.

use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct U256 {
    limbs: [u64; 4],
}

impl U256 {
    pub const ZERO: Self = Self { limbs: [0; 4] };

    pub fn from_u64(value: u64) -> Self {
        Self {
            limbs: [value, 0, 0, 0],
        }
    }

    pub fn is_zero(self) -> bool {
        self.limbs.iter().all(|limb| *limb == 0)
    }

    pub fn checked_add_u64(self, value: u64) -> Option<Self> {
        let mut out = self;
        let (sum, mut carry) = out.limbs[0].overflowing_add(value);
        out.limbs[0] = sum;
        if carry {
            for limb in &mut out.limbs[1..] {
                if !carry {
                    break;
                }
                let (sum, next) = limb.overflowing_add(1);
                *limb = sum;
                carry = next;
            }
        }
        if carry {
            None
        } else {
            Some(out)
        }
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        let mut out = self;
        let mut borrow = false;
        for index in 0..4 {
            let (diff, borrowed) = out.limbs[index].overflowing_sub(other.limbs[index]);
            let (diff, borrowed_again) = diff.overflowing_sub(u64::from(borrow));
            out.limbs[index] = diff;
            borrow = borrowed || borrowed_again;
        }
        if borrow {
            None
        } else {
            Some(out)
        }
    }

    pub fn checked_mul(self, other: Self) -> Option<Self> {
        let mut out = Self::ZERO;
        for left in 0..4 {
            if self.limbs[left] == 0 {
                continue;
            }
            let mut carry = 0u128;
            for right in 0..4 {
                let product = u128::from(self.limbs[left]) * u128::from(other.limbs[right]);
                if left + right >= 4 {
                    if product != 0 || carry != 0 {
                        return None;
                    }
                    break;
                }
                let slot = left + right;
                let sum = u128::from(out.limbs[slot]) + product + carry;
                out.limbs[slot] = sum as u64;
                carry = sum >> 64;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(out)
    }

    pub fn shl(self, bits: u32) -> Self {
        if bits == 0 {
            return self;
        }
        if bits >= 256 {
            return Self::ZERO;
        }
        let limb_shift = (bits / 64) as usize;
        let bit_shift = bits % 64;
        let mut out = Self::ZERO;
        for index in 0..4 {
            if index < limb_shift {
                continue;
            }
            let source = index - limb_shift;
            out.limbs[index] |= self.limbs[source] << bit_shift;
            if bit_shift != 0 && source > 0 {
                out.limbs[index] |= self.limbs[source - 1] >> (64 - bit_shift);
            }
        }
        out
    }

    pub fn shr(self, bits: u32) -> Self {
        if bits == 0 {
            return self;
        }
        if bits >= 256 {
            return Self::ZERO;
        }
        let limb_shift = (bits / 64) as usize;
        let bit_shift = bits % 64;
        let mut out = Self::ZERO;
        for index in 0..4 {
            let source = index + limb_shift;
            if source >= 4 {
                break;
            }
            out.limbs[index] |= self.limbs[source] >> bit_shift;
            if bit_shift != 0 && source + 1 < 4 {
                out.limbs[index] |= self.limbs[source + 1] << (64 - bit_shift);
            }
        }
        out
    }

    pub fn bit_length(self) -> u32 {
        for index in (0..4).rev() {
            if self.limbs[index] != 0 {
                return index as u32 * 64 + (64 - self.limbs[index].leading_zeros());
            }
        }
        0
    }

    /// `self / 2^shift` as `f64`. Exact when the value is a small power of two.
    pub fn div_pow2_f64(self, shift: u32) -> f64 {
        let bits = self.bit_length();
        if bits == 0 {
            return 0.0;
        }
        let top = self.top_bits(53);
        let exp = bits as i32 - 53 - shift as i32;
        (top as f64) * 2f64.powi(exp)
    }

    fn top_bits(self, width: u32) -> u64 {
        let bits = self.bit_length();
        if bits <= width {
            return self.limbs[0];
        }
        let drop = bits - width;
        self.shr(drop).limbs[0]
    }

    pub fn checked_shl(self, bits: u32) -> Option<Self> {
        if bits == 0 {
            return Some(self);
        }
        if bits >= 256 {
            return if self.is_zero() {
                Some(Self::ZERO)
            } else {
                None
            };
        }
        if self.bit_length().saturating_add(bits) > 256 {
            return None;
        }
        Some(self.shl(bits))
    }

    /// Smallest integer `q` such that `q << bits >= self`.
    pub fn ceil_shr(self, bits: u32) -> Option<Self> {
        if bits >= 256 {
            return if self.is_zero() {
                Some(Self::ZERO)
            } else {
                None
            };
        }
        let quot = self.shr(bits);
        let aligned = quot.shl(bits);
        if aligned == self {
            Some(quot)
        } else {
            quot.checked_add_u64(1)
        }
    }

    pub fn div_rem_u64(self, divisor: u64) -> Option<(Self, u64)> {
        if divisor == 0 {
            return None;
        }
        let mut quot = Self::ZERO;
        let mut rem = 0u128;
        for index in (0..4).rev() {
            rem = (rem << 64) | u128::from(self.limbs[index]);
            quot.limbs[index] = (rem / u128::from(divisor)) as u64;
            rem %= u128::from(divisor);
        }
        Some((quot, rem as u64))
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut out = Self::ZERO;
        for byte in bytes {
            out = out.checked_shl(8)?;
            out = out.checked_add_u64(u64::from(*byte))?;
        }
        Some(out)
    }

    pub fn to_be_fixed<const N: usize>(self) -> Option<[u8; N]> {
        if N > 32 || self.bit_length() > (N as u32).saturating_mul(8) {
            return None;
        }
        let mut out = [0u8; N];
        for (index, slot) in out.iter_mut().enumerate() {
            let shift = (N - 1 - index) as u32 * 8;
            *slot = self.shr(shift).limbs[0] as u8;
        }
        Some(out)
    }

    pub fn pow_u64(base: u64, exp: u32) -> Option<Self> {
        let mut result = Self::from_u64(1);
        for _ in 0..exp {
            result = result.checked_mul(Self::from_u64(base))?;
        }
        Some(result)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..4).rev() {
            match self.limbs[index].cmp(&other.limbs[index]) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::U256;

    #[test]
    fn powers_and_shifts_match_small_values() {
        assert_eq!(U256::pow_u64(58, 2), Some(U256::from_u64(3364)));
        assert_eq!(U256::from_u64(1).shl(192).shr(192), U256::from_u64(1));
        let pow33 = U256::pow_u64(58, 33).unwrap();
        let pow34 = U256::pow_u64(58, 34).unwrap();
        assert!(U256::from_u64(48).shl(192) > pow33);
        assert!(U256::from_u64(49).shl(192) < pow34);
        assert_eq!(
            U256::from_u64(10).checked_sub(U256::from_u64(3)),
            Some(U256::from_u64(7))
        );
        assert!(U256::from_u64(3).checked_sub(U256::from_u64(10)).is_none());
    }
}
