// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parallel vanity search.
//!
//! Independent mode draws a fresh scalar from the OS CSPRNG for every attempt.
//! Workers do not walk sequential private keys. HD mode strides one external
//! branch. MWEB strides the stealth-address index, starting at 2. A fast
//! compare has to agree with the full reference encoding. A panic, an RNG
//! failure, or a disagreement cancels the search and discards every candidate.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::Error;
use crate::ltc::address::{derive_transparent, p2wpkh_redeem};
use crate::ltc::analyze::SEARCH_COUNTER_HEADROOM;
use crate::ltc::hash::hash160;
use crate::ltc::hd::{
    derive_index, external_parent, format_path, seed_from_entropy, transparent_steps, HdNode,
};
use crate::ltc::keys::{random_entropy_32, random_scalar, KeyEngine};
use crate::ltc::kind::{AddressKind, SearchMode};
use crate::ltc::{analyze, require_searchable, Analysis, HARDENED};
use crate::mweb::{masters_from_seed, stealth_at, FIRST_RECEIVE_INDEX};
use crate::verify::confirm_material;
use crate::wallet::{CollectionItem, WalletMaterial};

pub const MAX_THREADS: usize = 256;
pub const COUNTER_HEADROOM: u64 = SEARCH_COUNTER_HEADROOM;
const ATTEMPT_CHUNK: u64 = 1024;

struct WorkerParent {
    key: Zeroizing<[u8; 32]>,
    chain: Zeroizing<[u8; 32]>,
    depth: u8,
}

struct MwebParent {
    scan: Zeroizing<[u8; 32]>,
    spend: Zeroizing<[u8; 32]>,
}

pub fn counter_would_overflow(current: u64) -> bool {
    current >= u64::MAX.saturating_sub(COUNTER_HEADROOM)
}

pub struct SearchRequest {
    pub kind: AddressKind,
    pub hd: bool,
    pub target: String,
    pub account: u32,
    pub index_limit: u64,
    pub entropy: Option<Zeroizing<[u8; 32]>>,
    /// Set only by the worker-panic test. Production searches leave this false.
    #[cfg(test)]
    pub panic_worker: bool,
}

impl SearchRequest {
    pub fn new(
        kind: AddressKind,
        hd: bool,
        target: impl Into<String>,
        account: u32,
        index_limit: u64,
        entropy: Option<Zeroizing<[u8; 32]>>,
    ) -> Self {
        Self {
            kind,
            hd,
            target: target.into(),
            account,
            index_limit,
            entropy,
            #[cfg(test)]
            panic_worker: false,
        }
    }
}

pub struct SearchHit {
    pub address: String,
    pub attempts: u64,
    pub descriptor: String,
    pub material: WalletMaterial,
}

impl std::fmt::Debug for SearchHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchHit")
            .field("address", &self.address)
            .field("attempts", &self.attempts)
            .field("descriptor", &self.descriptor)
            .field("material", &self.material)
            .finish()
    }
}

enum RawHit {
    Key(Zeroizing<[u8; 32]>),
    Index(u32),
}

pub fn validate_threads(threads: usize) -> Result<(), Error> {
    if threads == 0 || threads > MAX_THREADS {
        Err(Error::Threads)
    } else {
        Ok(())
    }
}

pub fn search<F>(
    request: &SearchRequest,
    threads: usize,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> Result<SearchHit, Error>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    let mode = SearchMode::for_kind(request.kind, request.hd);
    if request.kind == AddressKind::Mweb && request.hd {
        return Err(Error::prefix(
            "MWEB grinding is the keychain index, not an extra HD flag",
        ));
    }
    validate_limit(mode, request)?;
    let analysis = analyze(request.kind, &request.target)?;
    require_searchable(&analysis)?;
    validate_threads(threads)?;

    let entropy = match mode {
        SearchMode::HdIndex | SearchMode::MwebIndex => Some(match &request.entropy {
            Some(value) => Zeroizing::new(**value),
            None => random_entropy_32()?,
        }),
        _ => None,
    };
    let hd_parent = if mode == SearchMode::HdIndex {
        let seed = seed_from_entropy(entropy.as_ref().ok_or(Error::SearchFailed)?.as_slice())?;
        let engine = KeyEngine::new()?;
        let parent = external_parent(&engine, seed.as_slice(), request.kind, request.account)?;
        Some(WorkerParent {
            key: Zeroizing::new(*parent.key_bytes()),
            chain: Zeroizing::new(*parent.chain_code()),
            depth: parent.depth,
        })
    } else {
        None
    };
    let mweb_parent = if mode == SearchMode::MwebIndex {
        let seed = seed_from_entropy(entropy.as_ref().ok_or(Error::SearchFailed)?.as_slice())?;
        let engine = KeyEngine::new()?;
        let masters = masters_from_seed(&engine, seed.as_slice())?;
        Some(MwebParent {
            scan: Zeroizing::new(*masters.scan),
            spend: Zeroizing::new(*masters.spend),
        })
    } else {
        None
    };

    let attempts = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let overflow = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<RawHit>();
    let reporter = spawn_reporter(Arc::clone(&attempts), Arc::clone(&cancel), progress);
    let mut handles = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let tx = tx.clone();
        let cancel_worker = Arc::clone(&cancel);
        let attempts = Arc::clone(&attempts);
        let failed_worker = Arc::clone(&failed);
        let overflow = Arc::clone(&overflow);
        let analysis = analysis.clone();
        let kind = request.kind;
        let index_limit = request.index_limit;
        let parent = hd_parent.as_ref().map(|node| WorkerParent {
            key: Zeroizing::new(*node.key),
            chain: Zeroizing::new(*node.chain),
            depth: node.depth,
        });
        let mweb = mweb_parent.as_ref().map(|node| MwebParent {
            scan: Zeroizing::new(*node.scan),
            spend: Zeroizing::new(*node.spend),
        });
        #[cfg(test)]
        let panic_worker = request.panic_worker && worker_id == 0;
        match thread::Builder::new()
            .name("ltc-vanity".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("search worker test panic");
                    }
                    worker(
                        &analysis,
                        kind,
                        mode,
                        worker_id,
                        threads,
                        index_limit,
                        parent,
                        mweb,
                        &cancel_worker,
                        &attempts,
                        &overflow,
                        &tx,
                    )
                }));
                if !matches!(outcome, Ok(Ok(()))) {
                    failed_worker.store(true, Ordering::Release);
                    cancel_worker.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                failed.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                break;
            }
        }
    }
    drop(tx);
    let first = rx.recv();
    let user_cancelled = cancel.load(Ordering::Acquire);
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let _ = reporter.join();
    while rx.try_recv().is_ok() {}
    let total = attempts.load(Ordering::Relaxed);
    let overflowed = overflow.load(Ordering::Acquire) && first.is_err();
    if failed.load(Ordering::Acquire) || overflowed {
        return Err(Error::SearchFailed);
    }
    let Some(raw) = first.ok() else {
        return Err(empty_channel(mode, user_cancelled, total));
    };
    finish_hit(request, mode, &analysis, raw, total, entropy)
}

fn validate_limit(mode: SearchMode, request: &SearchRequest) -> Result<(), Error> {
    match mode {
        SearchMode::HdIndex => {
            if request.account >= HARDENED
                || request.index_limit == 0
                || request.index_limit > u64::from(HARDENED)
            {
                Err(Error::Index)
            } else {
                Ok(())
            }
        }
        SearchMode::MwebIndex => {
            if request.index_limit <= u64::from(FIRST_RECEIVE_INDEX)
                || request.index_limit > (1u64 << 32)
            {
                Err(Error::Index)
            } else {
                Ok(())
            }
        }
        SearchMode::Independent => Ok(()),
        SearchMode::Collection => Err(Error::SearchFailed),
    }
}

fn empty_channel(mode: SearchMode, user_cancelled: bool, attempts: u64) -> Error {
    if matches!(mode, SearchMode::HdIndex | SearchMode::MwebIndex) && !user_cancelled {
        Error::RangeExhausted { attempts }
    } else {
        Error::Cancelled { attempts }
    }
}

fn finish_hit(
    request: &SearchRequest,
    mode: SearchMode,
    analysis: &Analysis,
    raw: RawHit,
    attempts: u64,
    entropy: Option<Zeroizing<[u8; 32]>>,
) -> Result<SearchHit, Error> {
    let engine = KeyEngine::new()?;
    let (address, descriptor, material) = match (mode, raw) {
        (SearchMode::Independent, RawHit::Key(key)) => {
            let derived = derive_transparent(&engine, request.kind, key.as_slice())?;
            if !analysis.reference_accepts(&derived.address) {
                return Err(Error::SearchFailed);
            }
            let address = derived.address.clone();
            let descriptor = derived.descriptor.clone();
            let material = WalletMaterial::independent(request.kind, key, &derived);
            (address, descriptor, material)
        }
        (SearchMode::HdIndex, RawHit::Index(index)) => {
            let entropy = entropy.ok_or(Error::SearchFailed)?;
            let seed = seed_from_entropy(entropy.as_slice())?;
            let child = crate::ltc::hd::child_at(
                &engine,
                seed.as_slice(),
                request.kind,
                request.account,
                index,
            )?;
            let derived = derive_transparent(&engine, request.kind, child.key_bytes())?;
            if !analysis.reference_accepts(&derived.address) {
                return Err(Error::SearchFailed);
            }
            let steps = transparent_steps(request.kind, request.account, index)?;
            let path = format_path(&steps);
            let address = derived.address.clone();
            let descriptor = derived.descriptor.clone();
            let material = WalletMaterial::hd(
                request.kind,
                entropy,
                request.account,
                index,
                path,
                &derived,
            );
            (address, descriptor, material)
        }
        (SearchMode::MwebIndex, RawHit::Index(index)) => {
            let entropy = entropy.ok_or(Error::SearchFailed)?;
            let seed = seed_from_entropy(entropy.as_slice())?;
            let masters = masters_from_seed(&engine, seed.as_slice())?;
            let stealth = stealth_at(&engine, &masters.scan, &masters.spend, index)?;
            if !analysis.reference_accepts(&stealth.address) {
                return Err(Error::SearchFailed);
            }
            let address = stealth.address.clone();
            let material = WalletMaterial::mweb(entropy, index);
            (address, String::new(), material)
        }
        _ => return Err(Error::SearchFailed),
    };
    confirm_material(&material, &address)?;
    Ok(SearchHit {
        address,
        attempts,
        descriptor,
        material,
    })
}

pub struct CollectionRequest {
    pub targets: Vec<(AddressKind, String)>,
    pub threads: usize,
    pub account: u32,
}

pub struct CollectionHit {
    pub attempts: u64,
    pub items: Vec<CollectionItem>,
    pub material: WalletMaterial,
}

pub fn search_collection(
    request: &CollectionRequest,
    cancel: Arc<AtomicBool>,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
) -> Result<CollectionHit, Error> {
    if request.targets.len() != 5 {
        return Err(Error::SearchFailed);
    }
    let entropy = random_entropy_32()?;
    let mut items = Vec::with_capacity(5);
    let mut attempts = 0u64;
    for (kind, target) in &request.targets {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Cancelled { attempts });
        }
        let limit = if *kind == AddressKind::Mweb {
            1u64 << 32
        } else {
            u64::from(HARDENED)
        };
        let progress = Arc::clone(&progress);
        let hit = search(
            &SearchRequest::new(
                *kind,
                *kind != AddressKind::Mweb,
                target.clone(),
                request.account,
                limit,
                Some(Zeroizing::new(*entropy)),
            ),
            request.threads,
            Arc::clone(&cancel),
            move |attempts, rate| progress(attempts, rate),
        )?;
        attempts = attempts.saturating_add(hit.attempts);
        items.push(CollectionItem {
            kind: *kind,
            index: hit.material.index(),
            address: hit.address,
            path: hit.material.path().to_owned(),
            descriptor: hit.descriptor,
        });
    }
    let address_check = items
        .iter()
        .map(|item| item.address.as_str())
        .collect::<Vec<_>>()
        .join("|");
    let material = WalletMaterial::from_collection(entropy, items.clone());
    confirm_material(&material, &address_check)?;
    Ok(CollectionHit {
        attempts,
        items,
        material,
    })
}

pub fn measure_miss_rate(
    kind: AddressKind,
    threads: usize,
    duration: Duration,
) -> Result<u64, Error> {
    validate_threads(threads)?;
    let target = match kind {
        AddressKind::P2pkh => "LZuZu",
        AddressKind::P2shP2wpkh => "M8ZuZu",
        AddressKind::P2shP2wpkhLegacy => "31h1v",
        AddressKind::P2wpkh => "ltc1qzuzu",
        AddressKind::P2tr => "ltc1pzuzu",
        AddressKind::Mweb => "zuzu",
    };
    let analysis = analyze(kind, target)?;
    require_searchable(&analysis)?;
    let attempts = Arc::new(AtomicU64::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let mode = SearchMode::for_kind(kind, false);
    let mut handles = Vec::new();
    for worker_id in 0..threads {
        let attempts = Arc::clone(&attempts);
        let cancel = Arc::clone(&cancel);
        let analysis = analysis.clone();
        handles.push(thread::spawn(move || {
            let _ = worker(
                &analysis,
                kind,
                mode,
                worker_id,
                threads,
                if kind == AddressKind::Mweb {
                    1 << 32
                } else {
                    u64::from(HARDENED)
                },
                None,
                None,
                &cancel,
                &attempts,
                &AtomicBool::new(false),
                &{
                    let (tx, _rx) = mpsc::channel();
                    tx
                },
            );
        }));
    }
    while started.elapsed() < duration {
        thread::sleep(Duration::from_millis(20));
    }
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let total = attempts.load(Ordering::Relaxed);
    let seconds = started.elapsed().as_secs_f64();
    if seconds <= 0.0 {
        Ok(total)
    } else {
        Ok((total as f64 / seconds) as u64)
    }
}

fn spawn_reporter<F>(
    attempts: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> JoinHandle<()>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    thread::spawn(move || {
        let mut last_count = 0u64;
        let mut last_report = Instant::now();
        while !cancel.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(50));
            if cancel.load(Ordering::Acquire) {
                break;
            }
            if last_report.elapsed() < Duration::from_secs(1) {
                continue;
            }
            let now = attempts.load(Ordering::Relaxed);
            let elapsed = last_report.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                ((now.saturating_sub(last_count)) as f64 / elapsed) as u64
            } else {
                0
            };
            let _ = catch_unwind(AssertUnwindSafe(|| progress(now, rate)));
            last_count = now;
            last_report = Instant::now();
        }
    })
}

fn join_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

#[allow(clippy::too_many_arguments)]
fn worker(
    analysis: &Analysis,
    kind: AddressKind,
    mode: SearchMode,
    worker_id: usize,
    threads: usize,
    index_limit: u64,
    parent: Option<WorkerParent>,
    mweb: Option<MwebParent>,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
) -> Result<(), Error> {
    let engine = KeyEngine::new()?;
    let mut local = 0u64;
    let result = match mode {
        SearchMode::HdIndex => {
            let parent = parent.ok_or(Error::SearchFailed)?;
            index_worker(
                analysis,
                kind,
                &engine,
                Some(HdNode::from_private(parent.key, parent.chain, parent.depth)),
                None,
                worker_id,
                threads,
                index_limit,
                cancel,
                attempts,
                overflow,
                tx,
                &mut local,
            )
        }
        SearchMode::MwebIndex => {
            let mweb = mweb.ok_or(Error::SearchFailed)?;
            index_worker(
                analysis,
                kind,
                &engine,
                None,
                Some(mweb),
                worker_id,
                threads,
                index_limit,
                cancel,
                attempts,
                overflow,
                tx,
                &mut local,
            )
        }
        SearchMode::Independent => single_worker(
            analysis, kind, &engine, cancel, attempts, overflow, tx, &mut local,
        ),
        SearchMode::Collection => Err(Error::SearchFailed),
    };
    if local > 0 {
        let _ = add_attempts(attempts, overflow, cancel, local);
    }
    result
}

fn add_attempts(
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    cancel: &AtomicBool,
    count: u64,
) -> Result<(), Error> {
    let mut current = attempts.load(Ordering::Relaxed);
    loop {
        if counter_would_overflow(current) || current.checked_add(count).is_none() {
            overflow.store(true, Ordering::Release);
            cancel.store(true, Ordering::Release);
            return Err(Error::SearchFailed);
        }
        match attempts.compare_exchange_weak(
            current,
            current + count,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn bump(
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    local: &mut u64,
) -> Result<bool, Error> {
    if cancel.load(Ordering::Acquire) {
        return Ok(false);
    }
    let observed = attempts.load(Ordering::Relaxed).saturating_add(*local);
    if counter_would_overflow(observed) {
        overflow.store(true, Ordering::Release);
        cancel.store(true, Ordering::Release);
        return Ok(false);
    }
    *local += 1;
    if *local >= ATTEMPT_CHUNK {
        add_attempts(attempts, overflow, cancel, *local)?;
        *local = 0;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn single_worker(
    analysis: &Analysis,
    kind: AddressKind,
    engine: &KeyEngine,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
    local: &mut u64,
) -> Result<(), Error> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let secret = random_scalar()?;
        let matched = match candidate_matches(analysis, kind, engine, secret.as_slice()) {
            Ok(Some(matched)) => matched,
            Ok(None) => continue,
            Err(err) => return Err(err),
        };
        if !bump(cancel, attempts, overflow, local)? {
            return Ok(());
        }
        if matched {
            let _ = tx.send(RawHit::Key(secret));
            cancel.store(true, Ordering::Release);
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn index_worker(
    analysis: &Analysis,
    kind: AddressKind,
    engine: &KeyEngine,
    parent: Option<HdNode>,
    mweb: Option<MwebParent>,
    worker_id: usize,
    threads: usize,
    index_limit: u64,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<RawHit>,
    local: &mut u64,
) -> Result<(), Error> {
    let step = u64::try_from(threads).map_err(|_| Error::Index)?;
    if step == 0 {
        return Err(Error::Index);
    }
    let mut index = match kind {
        AddressKind::Mweb => u64::from(FIRST_RECEIVE_INDEX) + worker_id as u64,
        _ => worker_id as u64,
    };
    while index < index_limit {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let child_index = u32::try_from(index).map_err(|_| Error::Index)?;
        let matched = if let Some(parent) = &parent {
            match derive_index(engine, parent, child_index) {
                Ok(child) => candidate_matches(analysis, kind, engine, child.key_bytes())?,
                Err(Error::InvalidKey) => None,
                Err(err) => return Err(err),
            }
        } else if let Some(mweb) = &mweb {
            match stealth_at(engine, &mweb.scan, &mweb.spend, child_index) {
                Ok(stealth) => {
                    let fast = analysis.fast_accepts_mweb(&stealth.payload)?;
                    if fast && !analysis.reference_accepts(&stealth.address) {
                        return Err(Error::SearchFailed);
                    }
                    Some(fast)
                }
                Err(Error::InvalidKey) => None,
                Err(err) => return Err(err),
            }
        } else {
            return Err(Error::SearchFailed);
        };
        if let Some(matched) = matched {
            if !bump(cancel, attempts, overflow, local)? {
                return Ok(());
            }
            if matched {
                let _ = tx.send(RawHit::Index(child_index));
                cancel.store(true, Ordering::Release);
                return Ok(());
            }
        }
        index = match index.checked_add(step) {
            Some(next) => next,
            None => return Ok(()),
        };
    }
    Ok(())
}

fn candidate_matches(
    analysis: &Analysis,
    kind: AddressKind,
    engine: &KeyEngine,
    secret: &[u8],
) -> Result<Option<bool>, Error> {
    match kind {
        AddressKind::P2tr => {
            let tap = match engine.taproot(secret) {
                Ok(tap) => tap,
                Err(Error::InvalidKey) => return Ok(None),
                Err(err) => return Err(err),
            };
            let fast = analysis.fast_accepts_xonly(&tap.output_xonly)?;
            if fast {
                let address = crate::ltc::address::p2tr_address(&tap.output_xonly)?;
                if !analysis.reference_accepts(&address) {
                    return Err(Error::SearchFailed);
                }
            }
            Ok(Some(fast))
        }
        AddressKind::P2shP2wpkh | AddressKind::P2shP2wpkhLegacy => {
            let public = match engine.public_of(secret) {
                Ok(public) => public,
                Err(Error::InvalidKey) => return Ok(None),
                Err(err) => return Err(err),
            };
            let script_hash = hash160(&p2wpkh_redeem(&public.hash160));
            accept_hash(analysis, &script_hash, secret, kind, engine)
        }
        AddressKind::P2pkh | AddressKind::P2wpkh => {
            let public = match engine.public_of(secret) {
                Ok(public) => public,
                Err(Error::InvalidKey) => return Ok(None),
                Err(err) => return Err(err),
            };
            accept_hash(analysis, &public.hash160, secret, kind, engine)
        }
        AddressKind::Mweb => Err(Error::SearchFailed),
    }
}

fn accept_hash(
    analysis: &Analysis,
    hash: &[u8; 20],
    secret: &[u8],
    kind: AddressKind,
    engine: &KeyEngine,
) -> Result<Option<bool>, Error> {
    let fast = analysis.fast_accepts_hash(hash)?;
    if fast {
        let derived = derive_transparent(engine, kind, secret)?;
        if !analysis.reference_accepts(&derived.address) {
            return Err(Error::SearchFailed);
        }
    }
    Ok(Some(fast))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::{
        counter_would_overflow, search, validate_threads, SearchRequest, COUNTER_HEADROOM,
        MAX_THREADS,
    };
    use crate::error::Error;
    use crate::ltc::kind::AddressKind;
    use crate::ltc::HARDENED;
    use crate::verify::confirm_material;

    fn quiet(_: u64, _: u64) {}

    #[test]
    fn thread_count_and_overflow_headroom_are_bounded() {
        assert!(validate_threads(0).is_err());
        assert!(validate_threads(MAX_THREADS + 1).is_err());
        assert!(validate_threads(1).is_ok());
        assert!(counter_would_overflow(u64::MAX - COUNTER_HEADROOM));
        assert!(!counter_would_overflow(1_000));
    }

    #[test]
    fn independent_prefix_l_verifies_on_both_stacks() {
        let cancel = Arc::new(AtomicBool::new(false));
        let hit = search(
            &SearchRequest::new(AddressKind::P2pkh, false, "L", 0, 0, None),
            2,
            cancel,
            quiet,
        )
        .unwrap();
        assert!(hit.address.starts_with('L'));
        assert!(hit.attempts >= 1);
        confirm_material(&hit.material, &hit.address).unwrap();
        assert!(format!("{hit:?}").contains("redacted"));
    }

    #[test]
    fn cancel_before_start_does_not_return_a_hit() {
        let cancel = Arc::new(AtomicBool::new(true));
        let err = search(
            &SearchRequest::new(AddressKind::P2wpkh, false, "ltc1q", 0, 0, None),
            2,
            cancel,
            quiet,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Cancelled { .. }));
    }

    #[test]
    fn hd_limit_exhausts_when_the_only_index_misses() {
        let cancel = Arc::new(AtomicBool::new(false));
        let err = search(
            &SearchRequest::new(AddressKind::P2wpkh, true, "ltc1qzuzuzuzu", 0, 1, None),
            1,
            cancel,
            quiet,
        )
        .unwrap_err();
        assert!(matches!(err, Error::RangeExhausted { .. }), "{err}");
        assert!(u64::from(HARDENED) > 1);
    }

    #[test]
    fn a_panicking_worker_discards_the_search() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut request = SearchRequest::new(AddressKind::P2pkh, false, "L", 0, 0, None);
        request.panic_worker = true;
        let err = search(&request, 2, cancel, quiet).unwrap_err();
        assert_eq!(err, Error::SearchFailed);
    }

    #[test]
    fn mweb_motif_q_is_found_at_or_after_the_first_receive_index() {
        let cancel = Arc::new(AtomicBool::new(false));
        let hit = search(
            &SearchRequest::new(AddressKind::Mweb, false, "q", 0, 64, None),
            2,
            cancel,
            quiet,
        )
        .unwrap();
        assert!(hit.address.starts_with("ltcmweb1qq"));
        assert!(hit.material.index() >= 2);
        confirm_material(&hit.material, &hit.address).unwrap();
    }
}
