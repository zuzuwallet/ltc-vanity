// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::process::Command;

fn bin() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_ltc_vanity") {
        return std::path::PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_ltc-vanity") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("ltc-vanity");
    path
}

#[test]
fn ctrl_c_on_a_pty_restores_echo_and_hides_secrets() {
    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pty_ctrlc.py");
    let output = Command::new("python3")
        .arg(&script)
        .env("LTC_VANITY_BIN", bin())
        .output()
        .expect("python3 is required for the PTY test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pty test failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("PTY_OK"), "{stdout}");
}
