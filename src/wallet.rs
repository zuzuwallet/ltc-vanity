// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted wallet file.
//!
//! Argon2id uses the RFC 9106 second option: 64 MiB, t=3, p=4, version 0x13.
//! The cipher is ChaCha20-Poly1305. Associated data binds the address, network,
//! type, mode, compression flag, threshold, participant count, redeem script,
//! and derivation path.
//!
//! The file is created mode 0600 with `O_CREAT|O_EXCL` and opened with
//! `O_NOFOLLOW`. `umask` is 077. `hard_link` publishes the file only when the
//! destination is absent. `confirm_material` runs before ciphertext is written.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::hexutil;
use crate::ltc::address::{derive_transparent, encode_wif, Derived};
use crate::ltc::hd::{child_at, mnemonic_from_entropy, seed_from_entropy};
use crate::ltc::keys::KeyEngine;
use crate::ltc::kind::{AddressKind, SearchMode};
use crate::mweb::mweb_record;
use crate::secret::SecretString;
use crate::verify::{confirm_material, join_addresses};

const FORMAT_VERSION: u32 = 1;
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 19;
const CIPHER_NAME: &str = "chacha20poly1305";
const AAD_PREFIX: &[u8] = b"ltc-vanity-wallet-v1\0";
const MAX_WALLET_BYTES: u64 = 1_048_576;
const MAX_PLAINTEXT: usize = 4096;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MAX_ITERATIONS: u32 = 100;
const MAX_PARALLELISM: u32 = 16;
const TAG_LEN: usize = 16;
/// Linux `O_NOFOLLOW`. Do not follow a symlink.
const O_NOFOLLOW: i32 = 0x20000;

pub const MIN_NEW_PASSPHRASE_CHARS: usize = 12;

/// Printed before any secret. The text has no `WIF:` label.
pub const LITECOIN_KEY_REUSE_WARNING: &str = "\
WARNING: Litecoin mainnet private-key version is 0xB0. Bitcoin mainnet uses 0x80. Do not import this key into a Bitcoin wallet.\n\
The historical P2SH version 0x05 and the BIP32 version bytes 0x0488B21E and 0x0488ADE4 are the same bytes Bitcoin uses.\n\
An xpub string does not say it is Litecoin. A 3... address shares Bitcoin's version byte.\n";

pub fn private_umask() {
    let _previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const PRODUCTION: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
    };

    pub fn is_production(self) -> bool {
        self == Self::PRODUCTION
    }

    pub(crate) fn within_caps(self) -> bool {
        self.iterations >= 1
            && self.iterations <= MAX_ITERATIONS
            && self.parallelism >= 1
            && self.parallelism <= MAX_PARALLELISM
            && self.memory_kib >= self.parallelism.saturating_mul(8)
            && self.memory_kib <= MAX_MEMORY_KIB
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionItem {
    pub kind: AddressKind,
    pub index: u32,
    pub address: String,
    pub path: String,
    pub descriptor: String,
}

/// Secret material for one wallet. `Debug` redacts keys and entropy.
pub struct WalletMaterial {
    kind: AddressKind,
    mode: SearchMode,
    key: Zeroizing<[u8; 32]>,
    has_key: bool,
    entropy: Zeroizing<[u8; 32]>,
    has_entropy: bool,
    account: u32,
    index: u32,
    redeem: Vec<u8>,
    path: String,
    public_key: [u8; 33],
    collection: Vec<CollectionItem>,
}

impl std::fmt::Debug for WalletMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletMaterial")
            .field("kind", &self.kind)
            .field("mode", &self.mode)
            .field("key", &"[redacted]")
            .field("entropy", &"[redacted]")
            .field("path", &self.path)
            .field("index", &self.index)
            .finish()
    }
}

impl WalletMaterial {
    pub(crate) fn independent(
        kind: AddressKind,
        key: Zeroizing<[u8; 32]>,
        derived: &Derived,
    ) -> Self {
        Self {
            kind,
            mode: SearchMode::Independent,
            key,
            has_key: true,
            entropy: Zeroizing::new([0; 32]),
            has_entropy: false,
            account: 0,
            index: 0,
            redeem: derived.redeem.clone(),
            path: String::new(),
            public_key: derived.compressed,
            collection: Vec::new(),
        }
    }

    pub(crate) fn hd(
        kind: AddressKind,
        entropy: Zeroizing<[u8; 32]>,
        account: u32,
        index: u32,
        path: String,
        derived: &Derived,
    ) -> Self {
        Self {
            kind,
            mode: SearchMode::HdIndex,
            key: Zeroizing::new([0; 32]),
            has_key: false,
            entropy,
            has_entropy: true,
            account,
            index,
            redeem: derived.redeem.clone(),
            path,
            public_key: derived.compressed,
            collection: Vec::new(),
        }
    }

    pub(crate) fn mweb(entropy: Zeroizing<[u8; 32]>, index: u32) -> Self {
        Self {
            kind: AddressKind::Mweb,
            mode: SearchMode::MwebIndex,
            key: Zeroizing::new([0; 32]),
            has_key: false,
            entropy,
            has_entropy: true,
            account: 0,
            index,
            redeem: Vec::new(),
            path: mweb_record(index),
            public_key: [0; 33],
            collection: Vec::new(),
        }
    }

    pub(crate) fn from_collection(
        entropy: Zeroizing<[u8; 32]>,
        items: Vec<CollectionItem>,
    ) -> Self {
        let path = items
            .iter()
            .map(|item| item.path.as_str())
            .collect::<Vec<_>>()
            .join("|");
        Self {
            kind: AddressKind::P2pkh,
            mode: SearchMode::Collection,
            key: Zeroizing::new([0; 32]),
            has_key: false,
            entropy,
            has_entropy: true,
            account: 0,
            index: 0,
            redeem: Vec::new(),
            path,
            public_key: [0; 33],
            collection: items,
        }
    }

    pub fn kind(&self) -> AddressKind {
        self.kind
    }
    pub fn mode(&self) -> SearchMode {
        self.mode
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn redeem(&self) -> &[u8] {
        &self.redeem
    }
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn public_key(&self) -> [u8; 33] {
        self.public_key
    }
    pub fn collection(&self) -> &[CollectionItem] {
        &self.collection
    }
    pub fn network_name(&self) -> &'static str {
        "mainnet"
    }
    pub fn type_name(&self) -> &'static str {
        if self.mode == SearchMode::Collection {
            "collection"
        } else {
            self.kind.name()
        }
    }
    pub(crate) fn sole_key(&self) -> Result<&[u8; 32], Error> {
        if self.has_key {
            Ok(&self.key)
        } else {
            Err(Error::VerificationFailed)
        }
    }
    pub(crate) fn entropy(&self) -> Result<&[u8; 32], Error> {
        if self.has_entropy {
            Ok(&self.entropy)
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

pub struct OpenedWallet {
    pub address: String,
    pub kind: AddressKind,
    pub mode: SearchMode,
    pub path: String,
    pub redeem_hex: String,
    pub index: u32,
    pub account: u32,
    pub public_key: [u8; 33],
    pub collection: Vec<CollectionItem>,
    pub(crate) material: WalletMaterial,
}

impl OpenedWallet {
    pub fn type_name(&self) -> &'static str {
        self.material.type_name()
    }
}

impl std::fmt::Debug for OpenedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedWallet")
            .field("address", &self.address)
            .field("mode", &self.mode)
            .field("path", &self.path)
            .field("material", &self.material)
            .finish()
    }
}

pub fn check_passphrase(passphrase: &str) -> Result<(), Error> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn check_new_passphrase(passphrase: &str) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if passphrase.chars().count() < MIN_NEW_PASSPHRASE_CHARS {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn write_encrypted_wallet(
    path: &Path,
    passphrase: &str,
    material: &WalletMaterial,
    address: &str,
) -> Result<(), Error> {
    check_new_passphrase(passphrase)?;
    if path.exists() {
        return Err(Error::OutputExists);
    }
    write_encrypted_wallet_with_kdf(path, passphrase, material, address, &KdfParams::PRODUCTION)
}

pub(crate) fn write_encrypted_wallet_with_kdf(
    path: &Path,
    passphrase: &str,
    material: &WalletMaterial,
    address: &str,
    kdf: &KdfParams,
) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if !kdf.within_caps() {
        return Err(Error::WalletFormat);
    }
    if path.exists() {
        return Err(Error::OutputExists);
    }
    confirm_material(material, address)?;
    let meta = public_meta(material, address);
    let plaintext = encode_plaintext(material)?;
    let mut salt = Zeroizing::new([0u8; 16]);
    let mut nonce = Zeroizing::new([0u8; 12]);
    getrandom::getrandom(salt.as_mut_slice()).map_err(|_| Error::Rng)?;
    getrandom::getrandom(nonce.as_mut_slice()).map_err(|_| Error::Rng)?;
    let ciphertext = encrypt(passphrase, &plaintext, &meta, kdf, &salt, &nonce)?;
    let file = WalletFile {
        format_version: FORMAT_VERSION,
        network: meta.network,
        address_type: meta.kind,
        mode: meta.mode,
        public_address: meta.address,
        public_key_compression: "compressed".to_owned(),
        derivation_path: meta.path,
        threshold: 0,
        participants: 0,
        redeem_script_hex: meta.redeem_hex,
        kdf: KDF_NAME.to_owned(),
        kdf_parameters: KdfFile {
            version: KDF_VERSION,
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
        },
        salt: STANDARD.encode(salt.as_slice()),
        cipher: CIPHER_NAME.to_owned(),
        nonce: STANDARD.encode(nonce.as_slice()),
        ciphertext: STANDARD.encode(&ciphertext),
        collection: meta.collection,
    };
    let mut json = serde_json::to_string_pretty(&file).map_err(|_| Error::WalletFormat)?;
    json.push('\n');
    write_private_file(path, json.as_bytes())
}

pub fn export_wallet_text(opened: &OpenedWallet) -> Result<SecretString, Error> {
    export_text(&opened.material, &opened.address)
}

pub fn open_and_verify(path: &Path, passphrase: &str) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, true)
}

#[cfg(test)]
pub(crate) fn open_and_verify_with_kdf(
    path: &Path,
    passphrase: &str,
) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, false)
}

fn open_and_verify_inner(
    path: &Path,
    passphrase: &str,
    require_production: bool,
) -> Result<OpenedWallet, Error> {
    check_passphrase(passphrase)?;
    let file = read_wallet(path)?;
    if file.format_version != FORMAT_VERSION
        || file.kdf != KDF_NAME
        || file.cipher != CIPHER_NAME
        || file.kdf_parameters.version != KDF_VERSION
        || file.public_key_compression != "compressed"
        || file.threshold != 0
        || file.participants != 0
    {
        return Err(Error::WalletFormat);
    }
    let kdf = KdfParams {
        memory_kib: file.kdf_parameters.memory_kib,
        iterations: file.kdf_parameters.iterations,
        parallelism: file.kdf_parameters.parallelism,
    };
    let accepted = if require_production {
        kdf.is_production()
    } else {
        kdf.within_caps()
    };
    if !accepted {
        return Err(Error::WalletFormat);
    }
    let meta = Meta {
        address: file.public_address.clone(),
        network: file.network.clone(),
        kind: file.address_type.clone(),
        mode: file.mode.clone(),
        path: file.derivation_path.clone(),
        redeem_hex: file.redeem_script_hex.clone(),
        collection: file.collection.clone(),
    };
    let salt = decode_len::<16>(&file.salt)?;
    let nonce = decode_len::<12>(&file.nonce)?;
    let ciphertext = STANDARD
        .decode(&file.ciphertext)
        .map_err(|_| Error::WalletFormat)?;
    if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_PLAINTEXT + TAG_LEN {
        return Err(Error::WalletFormat);
    }
    let plaintext = decrypt(passphrase, &ciphertext, &meta, &kdf, &salt, &nonce)?;
    let material = decode_plaintext(&plaintext, &meta)?;
    confirm_material(&material, &meta.address)?;
    Ok(OpenedWallet {
        address: meta.address,
        kind: material.kind(),
        mode: material.mode(),
        path: material.path().to_owned(),
        redeem_hex: hexutil::encode_lower(material.redeem()),
        index: material.index(),
        account: material.account(),
        public_key: material.public_key(),
        collection: material.collection().to_vec(),
        material,
    })
}

pub(crate) fn export_text(material: &WalletMaterial, address: &str) -> Result<SecretString, Error> {
    confirm_material(material, address)?;
    let mut text = Zeroizing::new(String::new());
    text.push_str("NETWORK:\nLITECOIN\n");
    text.push_str(LITECOIN_KEY_REUSE_WARNING);
    match material.mode() {
        SearchMode::Independent => export_independent(&mut text, material)?,
        SearchMode::HdIndex => export_hd(&mut text, material, address)?,
        SearchMode::MwebIndex => export_mweb(&mut text, material)?,
        SearchMode::Collection => export_collection(&mut text, material)?,
    }
    Ok(SecretString::from_zeroizing(text))
}

fn export_independent(text: &mut String, material: &WalletMaterial) -> Result<(), Error> {
    match material.kind() {
        AddressKind::P2tr => text.push_str(
            "The following private key is the BIP341 internal key. Spending the ltc1p output requires the empty-tree TapTweak. Importing it as a legacy key does not spend that output. Litecoin Core on the pinned snapshot does not treat Taproot outputs as wallet outputs.\n",
        ),
        AddressKind::P2shP2wpkh | AddressKind::P2shP2wpkhLegacy => text.push_str(
            "This key controls the embedded P2WPKH witness program inside the P2SH redeem script.\n",
        ),
        _ => {}
    }
    let wif = encode_wif(material.sole_key()?)?;
    text.push_str("WIF:\n");
    text.push_str(wif.as_str());
    text.push('\n');
    Ok(())
}

fn export_hd(text: &mut String, material: &WalletMaterial, address: &str) -> Result<(), Error> {
    let phrase = mnemonic_from_entropy(material.entropy()?)?;
    let seed = seed_from_entropy(material.entropy()?)?;
    let engine = KeyEngine::new()?;
    let child = child_at(
        &engine,
        seed.as_slice(),
        material.kind(),
        material.account(),
        material.index(),
    )?;
    let derived = derive_transparent(&engine, material.kind(), child.key_bytes())?;
    if derived.address != address {
        return Err(Error::VerificationFailed);
    }
    let wif = encode_wif(child.key_bytes())?;
    text.push_str("Mnemonic:\n");
    text.push_str(phrase.as_str());
    text.push_str("\nDerivation path:\n");
    text.push_str(material.path());
    text.push_str("\nChild WIF:\n");
    text.push_str(wif.as_str());
    text.push_str(
        "\nimportprivkey of the child WIF spends this one address.\nA gap limit of 20 will not discover this index.\nSeed-only restore is not claimed.\nThe path uses SLIP-0044 coin type 2.\n",
    );
    if material.kind() == AddressKind::P2tr {
        text.push_str(
            "The child private key is the Taproot internal key. The ltc1p output also needs the empty-tree TapTweak.\n",
        );
    }
    Ok(())
}

fn export_mweb(text: &mut String, material: &WalletMaterial) -> Result<(), Error> {
    let phrase = mnemonic_from_entropy(material.entropy()?)?;
    text.push_str("Mnemonic:\n");
    text.push_str(phrase.as_str());
    text.push_str("\nScan path:\nm/0'/100'/0'\nSpend path:\nm/0'/100'/1'\nAddress index:\n");
    text.push_str(&material.index().to_string());
    text.push_str(
        "\nLitecoin Core will not scan to this index by itself. Identification uses the master scan secret. This export does not print the scan or spend scalars.\n",
    );
    Ok(())
}

fn export_collection(text: &mut String, material: &WalletMaterial) -> Result<(), Error> {
    let phrase = mnemonic_from_entropy(material.entropy()?)?;
    text.push_str("Mnemonic:\n");
    text.push_str(phrase.as_str());
    text.push('\n');
    for item in material.collection() {
        text.push_str("Address type:\n");
        text.push_str(item.kind.label());
        text.push_str("\nPath:\n");
        text.push_str(&item.path);
        text.push_str("\nIndex:\n");
        text.push_str(&item.index.to_string());
        text.push('\n');
    }
    text.push_str(
        "A gap limit of 20 will not discover these indexes. Seed-only restore is not claimed. Litecoin Core will not scan the MWEB index by itself.\n",
    );
    Ok(())
}

struct Meta {
    address: String,
    network: String,
    kind: String,
    mode: String,
    path: String,
    redeem_hex: String,
    collection: Vec<CollectionFile>,
}

fn public_meta(material: &WalletMaterial, address: &str) -> Meta {
    Meta {
        address: address.to_owned(),
        network: "mainnet".to_owned(),
        kind: material.type_name().to_owned(),
        mode: material.mode().name().to_owned(),
        path: material.path().to_owned(),
        redeem_hex: hexutil::encode_lower(material.redeem()),
        collection: material
            .collection()
            .iter()
            .map(|item| CollectionFile {
                address_type: item.kind.name().to_owned(),
                public_address: item.address.clone(),
                derivation_path: item.path.clone(),
                child_index: item.index,
            })
            .collect(),
    }
}

fn encode_plaintext(material: &WalletMaterial) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(b"LT1");
    let tag = match material.mode() {
        SearchMode::Independent => kind_tag(material.kind())?,
        SearchMode::HdIndex => 6,
        SearchMode::MwebIndex => 7,
        SearchMode::Collection => 8,
    };
    out.push(tag);
    out.push(1);
    match tag {
        1 | 4 | 5 => out.extend_from_slice(material.sole_key()?),
        2 | 3 => {
            out.extend_from_slice(material.sole_key()?);
            push_bytes(&mut out, material.redeem())?;
        }
        6 => {
            out.push(kind_tag(material.kind())?);
            out.extend_from_slice(material.entropy()?);
            out.extend_from_slice(&material.account().to_be_bytes());
            out.extend_from_slice(&material.index().to_be_bytes());
        }
        7 => {
            out.extend_from_slice(material.entropy()?);
            out.extend_from_slice(&material.index().to_be_bytes());
        }
        8 => {
            out.extend_from_slice(material.entropy()?);
            let count =
                u8::try_from(material.collection().len()).map_err(|_| Error::WalletFormat)?;
            out.push(count);
            for item in material.collection() {
                out.push(kind_tag(item.kind)?);
                out.extend_from_slice(&item.index.to_be_bytes());
            }
        }
        _ => return Err(Error::WalletFormat),
    }
    if out.len() > MAX_PLAINTEXT {
        return Err(Error::WalletFormat);
    }
    Ok(Zeroizing::new(out))
}

fn kind_tag(kind: AddressKind) -> Result<u8, Error> {
    match kind {
        AddressKind::P2pkh => Ok(1),
        AddressKind::P2shP2wpkh => Ok(2),
        AddressKind::P2shP2wpkhLegacy => Ok(3),
        AddressKind::P2wpkh => Ok(4),
        AddressKind::P2tr => Ok(5),
        AddressKind::Mweb => Ok(7),
    }
}

fn kind_from_tag(tag: u8) -> Result<AddressKind, Error> {
    match tag {
        1 => Ok(AddressKind::P2pkh),
        2 => Ok(AddressKind::P2shP2wpkh),
        3 => Ok(AddressKind::P2shP2wpkhLegacy),
        4 => Ok(AddressKind::P2wpkh),
        5 => Ok(AddressKind::P2tr),
        7 => Ok(AddressKind::Mweb),
        _ => Err(Error::WalletFormat),
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::WalletFormat)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_plaintext(bytes: &[u8], meta: &Meta) -> Result<WalletMaterial, Error> {
    if bytes.len() < 5 || &bytes[..3] != b"LT1" || bytes[4] != 1 || meta.network != "mainnet" {
        return Err(Error::WalletFormat);
    }
    let engine = KeyEngine::new()?;
    let material = match bytes[3] {
        1 | 4 | 5 => decode_key(&engine, &bytes[5..], bytes[3], false)?,
        2 | 3 => decode_key(&engine, &bytes[5..], bytes[3], true)?,
        6 => decode_hd(&engine, &bytes[5..])?,
        7 => decode_mweb(&engine, &bytes[5..])?,
        8 => decode_collection(&engine, &bytes[5..], meta)?,
        _ => return Err(Error::WalletFormat),
    };
    if material.type_name() != meta.kind || material.mode().name() != meta.mode {
        return Err(Error::VerificationFailed);
    }
    if material.path() != meta.path || hexutil::encode_lower(material.redeem()) != meta.redeem_hex {
        return Err(Error::VerificationFailed);
    }
    Ok(material)
}

fn decode_key(
    engine: &KeyEngine,
    rest: &[u8],
    tag: u8,
    with_redeem: bool,
) -> Result<WalletMaterial, Error> {
    let kind = kind_from_tag(tag)?;
    let key = take_key(rest, 0)?;
    let redeem = if with_redeem {
        let script = take_blob(&rest[32..])?;
        if rest.len() != 32 + 2 + script.len() {
            return Err(Error::WalletFormat);
        }
        script
    } else if rest.len() != 32 {
        return Err(Error::WalletFormat);
    } else {
        Vec::new()
    };
    let derived = derive_transparent(engine, kind, key.as_slice())?;
    if derived.redeem != redeem {
        return Err(Error::VerificationFailed);
    }
    Ok(WalletMaterial::independent(kind, key, &derived))
}

fn decode_hd(engine: &KeyEngine, rest: &[u8]) -> Result<WalletMaterial, Error> {
    if rest.len() != 1 + 32 + 8 {
        return Err(Error::WalletFormat);
    }
    let kind = kind_from_tag(rest[0])?;
    if kind == AddressKind::Mweb {
        return Err(Error::WalletFormat);
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&rest[1..33]);
    let account = u32::from_be_bytes(rest[33..37].try_into().map_err(|_| Error::WalletFormat)?);
    let index = u32::from_be_bytes(rest[37..41].try_into().map_err(|_| Error::WalletFormat)?);
    let seed = seed_from_entropy(entropy.as_slice())?;
    let child = child_at(engine, seed.as_slice(), kind, account, index)?;
    let derived = derive_transparent(engine, kind, child.key_bytes())?;
    let path =
        crate::ltc::hd::format_path(&crate::ltc::hd::transparent_steps(kind, account, index)?);
    Ok(WalletMaterial::hd(
        kind, entropy, account, index, path, &derived,
    ))
}

fn decode_mweb(engine: &KeyEngine, rest: &[u8]) -> Result<WalletMaterial, Error> {
    if rest.len() != 36 {
        return Err(Error::WalletFormat);
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&rest[..32]);
    let index = u32::from_be_bytes(rest[32..36].try_into().map_err(|_| Error::WalletFormat)?);
    let seed = seed_from_entropy(entropy.as_slice())?;
    let masters = crate::mweb::masters_from_seed(engine, seed.as_slice())?;
    let _stealth = crate::mweb::stealth_at(engine, &masters.scan, &masters.spend, index)?;
    Ok(WalletMaterial::mweb(entropy, index))
}

fn decode_collection(
    engine: &KeyEngine,
    rest: &[u8],
    meta: &Meta,
) -> Result<WalletMaterial, Error> {
    if rest.len() < 33 {
        return Err(Error::WalletFormat);
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&rest[..32]);
    let count = rest[32] as usize;
    if count != 5 || rest.len() != 33 + count * 5 || meta.collection.len() != count {
        return Err(Error::WalletFormat);
    }
    let seed = seed_from_entropy(entropy.as_slice())?;
    let mut items = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 33 + index * 5;
        let kind = kind_from_tag(rest[offset])?;
        let child = u32::from_be_bytes(
            rest[offset + 1..offset + 5]
                .try_into()
                .map_err(|_| Error::WalletFormat)?,
        );
        let file = &meta.collection[index];
        if file.address_type != kind.name() || file.child_index != child {
            return Err(Error::VerificationFailed);
        }
        let (address, path, descriptor) = match kind {
            AddressKind::Mweb => {
                let masters = crate::mweb::masters_from_seed(engine, seed.as_slice())?;
                let stealth =
                    crate::mweb::stealth_at(engine, &masters.scan, &masters.spend, child)?;
                (stealth.address, mweb_record(child), String::new())
            }
            _ => {
                let node = child_at(engine, seed.as_slice(), kind, 0, child)?;
                let derived = derive_transparent(engine, kind, node.key_bytes())?;
                let path = crate::ltc::hd::format_path(&crate::ltc::hd::transparent_steps(
                    kind, 0, child,
                )?);
                (derived.address, path, derived.descriptor)
            }
        };
        if address != file.public_address || path != file.derivation_path {
            return Err(Error::VerificationFailed);
        }
        items.push(CollectionItem {
            kind,
            index: child,
            address,
            path,
            descriptor,
        });
    }
    let material = WalletMaterial::from_collection(entropy, items);
    if join_addresses(material.collection()) != meta.address {
        return Err(Error::VerificationFailed);
    }
    Ok(material)
}

fn take_key(bytes: &[u8], offset: usize) -> Result<Zeroizing<[u8; 32]>, Error> {
    let end = offset.checked_add(32).ok_or(Error::WalletFormat)?;
    if end > bytes.len() {
        return Err(Error::WalletFormat);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes[offset..end]);
    Ok(key)
}

fn take_blob(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() < 2 {
        return Err(Error::WalletFormat);
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + len {
        return Err(Error::WalletFormat);
    }
    Ok(bytes[2..2 + len].to_vec())
}

fn encrypt(
    passphrase: &str,
    plaintext: &[u8],
    meta: &Meta,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, Error> {
    let derived = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(derived.as_slice()).map_err(|_| Error::WalletFormat)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce.as_slice()),
            Payload {
                msg: plaintext,
                aad: &aad_bytes(meta),
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn decrypt(
    passphrase: &str,
    ciphertext: &[u8],
    meta: &Meta,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let derived = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(derived.as_slice()).map_err(|_| Error::WalletFormat)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce.as_slice()),
            Payload {
                msg: ciphertext,
                aad: &aad_bytes(meta),
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plain))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::WalletFormat)?;
    let block_count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::default(); block_count].into_boxed_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *memory)
        .map_err(|_| Error::WalletFormat)?;
    Ok(key)
}

fn aad_bytes(meta: &Meta) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(AAD_PREFIX);
    for part in [
        meta.address.as_str(),
        meta.network.as_str(),
        meta.kind.as_str(),
        meta.mode.as_str(),
        "compressed",
        "0",
        "0",
        meta.redeem_hex.as_str(),
        meta.path.as_str(),
    ] {
        out.extend_from_slice(part.as_bytes());
        out.push(0);
    }
    out
}

fn decode_len<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let bytes = STANDARD.decode(text).map_err(|_| Error::WalletFormat)?;
    if bytes.len() != N {
        return Err(Error::WalletFormat);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_wallet(path: &Path) -> Result<WalletFile, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|err| map_wallet_open_error(path, err))?;
    let meta = file.metadata().map_err(|err| Error::io(path, err))?;
    if meta.len() > MAX_WALLET_BYTES || !meta.is_file() {
        return Err(Error::WalletFormat);
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_WALLET_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|err| Error::io(path, err))?;
    if text.len() as u64 > MAX_WALLET_BYTES {
        return Err(Error::WalletFormat);
    }
    serde_json::from_str(&text).map_err(|_| Error::WalletFormat)
}

fn map_wallet_open_error(path: &Path, err: std::io::Error) -> Error {
    if err.raw_os_error() == Some(40) {
        Error::Io(format!(
            "{}: wallet path must be a regular file",
            path.display()
        ))
    } else {
        Error::io(path, err)
    }
}

fn write_private_file(dest: &Path, contents: &[u8]) -> Result<(), Error> {
    private_umask();
    if dest.exists() {
        return Err(Error::OutputExists);
    }
    let parent = parent_dir(dest);
    if !parent.is_dir() {
        return Err(Error::OutputDir);
    }
    let file_name = dest.file_name().ok_or(Error::OutputDir)?;
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).map_err(|_| Error::Rng)?;
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        hexutil::encode_upper(&suffix)
    ));
    let mut guard = RemoveOnDrop {
        path: tmp_path.clone(),
        armed: true,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|err| Error::io(&tmp_path, err))?;
    let mode = file
        .metadata()
        .map_err(|err| Error::io(&tmp_path, err))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Io(format!(
            "{}: created file was not private",
            tmp_path.display()
        )));
    }
    file.write_all(contents)
        .map_err(|err| Error::io(&tmp_path, err))?;
    file.sync_all().map_err(|err| Error::io(&tmp_path, err))?;
    drop(file);
    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::OutputExists);
        }
        Err(err) => return Err(Error::io(dest, err)),
    }
    fs::remove_file(&tmp_path).map_err(|err| Error::io(&tmp_path, err))?;
    guard.armed = false;
    sync_directory(dest, parent)?;
    Ok(())
}

fn sync_directory(dest: &Path, parent: &Path) -> Result<(), Error> {
    let dir = File::open(parent).map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but opening its directory for sync failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })?;
    dir.sync_all().map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but syncing its directory failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

struct RemoveOnDrop {
    path: PathBuf,
    armed: bool,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    format_version: u32,
    network: String,
    address_type: String,
    mode: String,
    public_address: String,
    public_key_compression: String,
    derivation_path: String,
    threshold: u32,
    participants: u32,
    redeem_script_hex: String,
    kdf: String,
    kdf_parameters: KdfFile,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
    #[serde(default)]
    collection: Vec<CollectionFile>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct CollectionFile {
    address_type: String,
    public_address: String,
    derivation_path: String,
    child_index: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfFile {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use zeroize::Zeroizing;

    use super::{
        check_new_passphrase, export_text, open_and_verify, open_and_verify_with_kdf,
        write_encrypted_wallet, write_encrypted_wallet_with_kdf, KdfParams, WalletMaterial,
        LITECOIN_KEY_REUSE_WARNING,
    };
    use crate::error::Error;
    use crate::ltc::address::derive_transparent;
    use crate::ltc::hd::{child_at, scan_gap, seed_from_entropy, GAP_LIMIT};
    use crate::ltc::keys::KeyEngine;
    use crate::ltc::kind::AddressKind;
    use crate::mweb::{masters_from_seed, mweb_record, stealth_at};

    fn scratch(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ltc-vanity-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn cheap() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn sample(kind: AddressKind) -> (WalletMaterial, String) {
        let mut key = Zeroizing::new([0u8; 32]);
        key[31] = 9;
        let engine = KeyEngine::new().unwrap();
        let derived = derive_transparent(&engine, kind, key.as_slice()).unwrap();
        let address = derived.address.clone();
        (WalletMaterial::independent(kind, key, &derived), address)
    }

    #[test]
    fn cheap_round_trip_is_private_and_the_public_opener_rejects_it() {
        let dir = scratch("wallet");
        let path = dir.join("sample-wallet.json");
        let (material, address) = sample(AddressKind::P2pkh);
        write_encrypted_wallet_with_kdf(
            &path,
            "correct horse battery",
            &material,
            &address,
            &cheap(),
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("0000000000000000000000000000000000000000000000000000000000000009"));
        assert!(text.contains(&address));
        assert!(!text.contains("ltc-vanity"));
        assert!(!text.contains("bch-vanity"));
        let opened = open_and_verify_with_kdf(&path, "correct horse battery").unwrap();
        assert_eq!(opened.address, address);
        assert!(open_and_verify(&path, "correct horse battery").is_err());
        assert_eq!(
            write_encrypted_wallet(&path, "correct horse battery", &material, &address)
                .unwrap_err(),
            Error::OutputExists
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn short_passphrase_does_not_create_a_file() {
        let dir = scratch("short");
        let path = dir.join("nope-wallet.json");
        let (material, address) = sample(AddressKind::P2wpkh);
        assert_eq!(
            write_encrypted_wallet(&path, "short", &material, &address).unwrap_err(),
            Error::Passphrase
        );
        assert!(!path.exists());
        assert!(check_new_passphrase("short").is_err());
        assert!(check_new_passphrase("  twelve chars").is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_is_rejected() {
        let dir = scratch("link");
        let real = dir.join("real-wallet.json");
        let link = dir.join("link-wallet.json");
        let (material, address) = sample(AddressKind::P2tr);
        write_encrypted_wallet_with_kdf(
            &real,
            "correct horse battery",
            &material,
            &address,
            &cheap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = open_and_verify_with_kdf(&link, "correct horse battery").unwrap_err();
        assert!(err.to_string().contains("regular file"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nested_redeem_is_bound_and_hd_gap_misses_a_high_index() {
        let dir = scratch("hd");
        let nested = dir.join("nested-wallet.json");
        let (material, address) = sample(AddressKind::P2shP2wpkh);
        assert!(address.starts_with('M'));
        assert_eq!(material.redeem().len(), 22);
        write_encrypted_wallet_with_kdf(
            &nested,
            "correct horse battery",
            &material,
            &address,
            &cheap(),
        )
        .unwrap();
        let opened = open_and_verify_with_kdf(&nested, "correct horse battery").unwrap();
        assert_eq!(opened.address, address);
        assert_eq!(opened.redeem_hex.len(), 44);

        let hd_path = dir.join("hd-wallet.json");
        let entropy = Zeroizing::new([0xffu8; 32]);
        let seed = seed_from_entropy(entropy.as_slice()).unwrap();
        let engine = KeyEngine::new().unwrap();
        let child = child_at(&engine, seed.as_slice(), AddressKind::P2pkh, 0, 100).unwrap();
        let derived = derive_transparent(&engine, AddressKind::P2pkh, child.key_bytes()).unwrap();
        let material = WalletMaterial::hd(
            AddressKind::P2pkh,
            entropy,
            0,
            100,
            "m/44'/2'/0'/0/100".to_owned(),
            &derived,
        );
        write_encrypted_wallet_with_kdf(
            &hd_path,
            "correct horse battery",
            &material,
            &derived.address,
            &cheap(),
        )
        .unwrap();
        drop(material);
        let opened = open_and_verify_with_kdf(&hd_path, "correct horse battery").unwrap();
        assert_eq!(opened.address, derived.address);
        assert_eq!(opened.index, 100);
        let scanned = scan_gap(&engine, seed.as_slice(), AddressKind::P2pkh, 0, GAP_LIMIT).unwrap();
        assert!(!scanned.contains(&derived.address));
        assert_eq!(scanned.len(), GAP_LIMIT as usize);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mweb_restore_uses_the_recorded_index() {
        let dir = scratch("mweb");
        let path = dir.join("mweb-wallet.json");
        let entropy = Zeroizing::new([0x11u8; 32]);
        let seed = seed_from_entropy(entropy.as_slice()).unwrap();
        let engine = KeyEngine::new().unwrap();
        let masters = masters_from_seed(&engine, seed.as_slice()).unwrap();
        let stealth = stealth_at(&engine, &masters.scan, &masters.spend, 100).unwrap();
        let material = WalletMaterial::mweb(entropy, 100);
        assert_eq!(material.path(), mweb_record(100));
        write_encrypted_wallet_with_kdf(
            &path,
            "correct horse battery",
            &material,
            &stealth.address,
            &cheap(),
        )
        .unwrap();
        drop(material);
        let opened = open_and_verify_with_kdf(&path, "correct horse battery").unwrap();
        assert_eq!(opened.address, stealth.address);
        assert_eq!(opened.index, 100);
        assert!(opened.address.starts_with("ltcmweb1qq"));
        let _ = fs::remove_dir_all(&dir);
    }

    fn label_index(body: &str, label: &str) -> Option<usize> {
        body.match_indices('\n').find_map(|(index, _)| {
            let start = index + 1;
            body.get(start..)?.starts_with(label).then_some(start)
        })
    }

    #[test]
    fn export_warns_before_the_secret_label() {
        let (material, address) = sample(AddressKind::P2pkh);
        let text = export_text(&material, &address).unwrap();
        let body = text.as_str();
        let warning = body.find("Litecoin mainnet private-key version is 0xB0");
        let wif = label_index(body, "WIF:");
        assert!(warning.is_some());
        assert!(wif.is_some());
        assert!(warning.unwrap() < wif.unwrap());
        assert!(body.contains(LITECOIN_KEY_REUSE_WARNING));
        assert!(!format!("{material:?}").contains("WIF"));
        let (tap_material, tap_address) = sample(AddressKind::P2tr);
        let tap = export_text(&tap_material, &tap_address).unwrap();
        assert!(tap.as_str().contains("BIP341 internal key"));
        assert!(
            tap.as_str().find("BIP341 internal key").unwrap()
                < label_index(tap.as_str(), "WIF:").unwrap()
        );
    }
}
