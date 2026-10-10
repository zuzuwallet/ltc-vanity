// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use zeroize::Zeroizing;

/// Fixed-length secret. `Debug` does not print the bytes.
#[cfg(test)]
pub struct SecretBytes<const N: usize> {
    bytes: Zeroizing<[u8; N]>,
}

#[cfg(test)]
impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn from_zeroizing(bytes: Zeroizing<[u8; N]>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

#[cfg(test)]
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>([redacted])")
    }
}

/// Secret text such as a WIF string, a mnemonic, or a passphrase.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{SecretBytes, SecretString};

    #[test]
    fn debug_redacts_and_the_bytes_stay_available_to_the_owner() {
        let secret = SecretBytes::new([9u8; 32]);
        assert!(format!("{secret:?}").contains("redacted"));
        assert!(!format!("{secret:?}").contains("09"));
        assert_eq!(secret.as_bytes().len(), 32);
        let wrapped = SecretBytes::from_zeroizing(Zeroizing::new([4u8; 32]));
        assert_eq!(wrapped.as_bytes().len(), 32);
        let text = SecretString::from_zeroizing(Zeroizing::new("hidden".to_owned()));
        assert!(format!("{text:?}").contains("redacted"));
        assert!(!format!("{text:?}").contains("hidden"));
        assert_eq!(text.as_str().len(), 6);
    }
}
