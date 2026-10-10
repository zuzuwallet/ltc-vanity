// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use zeroize::Zeroize;

use ltc_vanity::{analyze, AddressKind, KeyEngine};

fn bench_derive(c: &mut Criterion) {
    let mut key = [0u8; 32];
    key[31] = 1;
    let analysis = analyze(AddressKind::P2pkh, "LZuZu").unwrap();
    let engine = KeyEngine::new().expect("libsecp256k1 context seed");
    c.bench_function("miss_without_base58", |b| {
        b.iter(|| {
            let public = engine.public_of(black_box(&key)).unwrap();
            let matched = analysis
                .fast_accepts_hash(black_box(&public.hash160))
                .unwrap();
            black_box(matched);
        });
    });
    c.bench_function("getrandom_and_miss", |b| {
        b.iter(|| {
            let mut entropy = [0u8; 32];
            getrandom::getrandom(&mut entropy).unwrap();
            let public = engine.public_of(black_box(&entropy));
            let matched = public
                .as_ref()
                .map(|item| analysis.fast_accepts_hash(&item.hash160).unwrap_or(false))
                .unwrap_or(false);
            black_box(matched);
            entropy.zeroize();
        });
    });
}

criterion_group!(benches, bench_derive);
criterion_main!(benches);
