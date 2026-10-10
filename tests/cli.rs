// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

use ltc_vanity::{derive_transparent, AddressKind, KeyEngine};

fn bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_ltc_vanity") {
        return PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_ltc-vanity") {
        return PathBuf::from(path);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("ltc-vanity");
    path
}

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("ltc-vanity binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn self_test_passes_and_records_core_status() {
    let (ok, stdout, stderr) = run(&["self-test"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("Cryptographic self-tests:\nPASS"));
    assert!(stdout.contains("MWEB forum vector:"));
    assert!(
        stdout.contains("not verified by Litecoin Core")
            || stdout.contains("validateaddress was not run")
            || stdout.contains("was not asked to build")
    );
    assert!(!stdout.contains("WIF:"));
}

#[test]
fn analyze_reports_the_measured_targets() {
    let (ok, stdout, _) = run(&["analyze", "--type", "p2pkh", "LZuZu"]);
    assert!(ok);
    assert!(stdout.contains("Reachable:\nYES"));
    assert!(stdout.contains("Expected attempts:\n4,553,521"));
    assert!(stdout.contains("This is not 58^n."));

    let (ok, stdout, stderr) = run(&["analyze", "--type", "p2sh-p2wpkh", "MZuZu"]);
    assert!(!ok);
    assert!(stdout.contains("Reachable:\nNO"));
    assert!(stderr.contains("Version 0x32"));
    assert!(stdout.contains("M7uAERuQW2AotfyLDyewFGcLUDtAYiAepF"));

    let (ok, stdout, _) = run(&["analyze", "--type", "p2sh-p2wpkh", "M8ZuZu"]);
    assert!(ok);
    assert!(stdout.contains("Expected attempts:\n264,104,224"));
    assert!(stdout.contains("Vanity portion:\n8ZuZu"));

    let (ok, stdout, _) = run(&["analyze", "--type", "p2wpkh", "ltc1qzuzu"]);
    assert!(ok);
    assert!(stdout.contains("Probability per candidate:\n1 / 2^20"));
    assert!(stdout.contains("Encoding:\nBech32"));

    let (ok, stdout, _) = run(&["analyze", "--type", "p2tr", "ltc1pzuzu"]);
    assert!(ok);
    assert!(stdout.contains("Encoding:\nBech32m"));
    assert!(stdout.contains("1 / 2^20"));

    let (ok, stdout, _) = run(&["analyze", "--type", "mweb", "zuzu"]);
    assert!(ok);
    assert!(stdout.contains("Fixed/protocol prefix:\nltcmweb1qq"));
    assert!(stdout.contains("1 / 2^20"));

    let (ok, _, stderr) = run(&["analyze", "--type", "mweb", "ltc1mwebzuzu"]);
    assert!(!ok);
    assert!(stderr.contains("ltcmweb1"));

    let (ok, stdout, _) = run(&["analyze", "--type", "p2wpkh", "ltc1qZuZu"]);
    assert!(!ok);
    assert!(stdout.contains("Reachable:\nNO"));

    let (ok, _, stderr) = run(&["analyze", "--type", "p2pkh", "--network", "testnet", "L"]);
    assert!(!ok);
    assert!(stderr.contains("only Litecoin mainnet"));
}

#[test]
fn inspect_decodes_a_derived_address_and_rejects_bitcoin() {
    let mut key = [0u8; 32];
    key[31] = 1;
    let engine = KeyEngine::new().expect("context");
    let derived = derive_transparent(&engine, AddressKind::P2pkh, &key).expect("p2pkh");
    let (ok, stdout, _) = run(&["inspect", &derived.address]);
    assert!(ok);
    assert!(stdout.contains("Network:\nLitecoin mainnet"));
    assert!(stdout.contains("Address type:\nP2PKH"));
    assert!(stdout.contains("Encoding:\nBase58Check"));
    assert!(stdout.contains("Checksum:\nPASS"));
    assert!(stdout.contains("Valid:\nYES"));

    let (ok, stdout, _) = run(&["inspect", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]);
    assert!(ok);
    assert!(stdout.contains("Bitcoin mainnet"));
    assert!(stdout.contains("Valid:\nNO"));
    assert!(stdout.contains("Checksum:\nPASS"));

    let (ok, stdout, _) = run(&["inspect", "LZuZu"]);
    assert!(ok);
    assert!(stdout.contains("Valid:\nNO"));
    assert!(stdout.contains("Checksum:\nFAIL"));
}

#[test]
fn unreachable_generate_and_headless_generate_do_not_write_a_wallet() {
    let (ok, stdout, _) = run(&[
        "generate",
        "--type",
        "p2sh-p2wpkh",
        "MZuZu",
        "--threads",
        "1",
    ]);
    assert!(!ok);
    assert!(stdout.contains("Reachable:\nNO"));
    assert!(!stdout.contains("Searching..."));

    let (ok, _, stderr) = run(&[
        "generate",
        "--hd",
        "--type",
        "mweb",
        "zuzu",
        "--threads",
        "1",
    ]);
    assert!(!ok);
    assert!(stderr.contains("Do not pass --hd"));

    let dir = std::env::temp_dir().join(format!("ltc-vanity-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("L-wallet.json");
    let run = Command::new(bin())
        .args([
            "generate",
            "--type",
            "p2pkh",
            "L",
            "--threads",
            "1",
            "--output",
        ])
        .arg(&output)
        .output()
        .expect("generate");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "{stderr}");
    assert!(stderr.contains("a terminal is required"), "{stderr}");
    assert!(!output.exists());
    let _ = std::fs::remove_dir_all(&dir);
}
