// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI for the offline Litecoin mainnet vanity generator.
//!
//! The address type is always an explicit flag. Secrets are printed only by
//! `export`, after EXPORT is typed, and only when both stdin and stdout are
//! terminals.

#![forbid(unsafe_code)]

use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use ltc_vanity::wallet::private_umask;
use ltc_vanity::{
    analyze, check_new_passphrase, check_passphrase, difficulty_text, export_wallet_text,
    finite_block, group_digits, inspect, litecoin_core_status, measure_miss_rate,
    mweb_forum_status, open_and_verify, require_searchable, run_self_tests, search,
    search_collection, write_encrypted_wallet, AddressKind, Analysis, CollectionRequest, Error,
    Network, SearchMode, SearchRequest, CONFIRMATION_THRESHOLD, HARDENED,
    LITECOIN_KEY_REUSE_WARNING, MAX_THREADS, MIN_NEW_PASSPHRASE_CHARS,
};

#[derive(Parser)]
#[command(
    name = "ltc-vanity",
    about = "Offline Litecoin mainnet vanity address generator",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run known-answer tests and exit.
    SelfTest,
    /// Show whether a vanity target is reachable and how rare it is.
    Analyze {
        target: String,
        #[arg(long = "type")]
        kind: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Measure the miss path. Rates only. No keys.
    Benchmark {
        #[arg(long = "type")]
        kind: String,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Search for one target and store the secret in an encrypted wallet.
    Generate {
        target: String,
        #[arg(long = "type")]
        kind: String,
        /// Derive every attempt from one BIP39 seed. MWEB always uses its keychain index.
        #[arg(long)]
        hd: bool,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Search the ZuZu collection from one seed. This can take a long time.
    Collection {
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Decode an address and check its checksum, encoding, and type.
    Inspect { address: String },
    /// Decrypt a wallet offline and rebuild the stored address.
    Verify { wallet: PathBuf },
    /// Decrypt a wallet and print recovery secrets. Offline only.
    Export { wallet: PathBuf },
}

fn main() -> ExitCode {
    private_umask();
    if let Err(err) = run() {
        eprintln!("error: {err}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::SelfTest => cmd_self_test(),
        Command::Analyze {
            target,
            kind,
            network,
        } => cmd_analyze(&target, &kind, &network),
        Command::Benchmark {
            kind,
            threads,
            network,
        } => cmd_benchmark(&kind, threads, &network),
        Command::Generate {
            target,
            kind,
            hd,
            threads,
            output,
            network,
        } => cmd_generate(GenerateArgs {
            target: &target,
            kind: &kind,
            hd,
            threads,
            output,
            network: &network,
        }),
        Command::Collection {
            threads,
            output,
            network,
        } => cmd_collection(threads, output, &network),
        Command::Inspect { address } => {
            println!("{}", inspect(&address));
            Ok(())
        }
        Command::Verify { wallet } => cmd_verify(&wallet),
        Command::Export { wallet } => cmd_export(&wallet),
    }
}

struct GenerateArgs<'a> {
    target: &'a str,
    kind: &'a str,
    hd: bool,
    threads: Option<usize>,
    output: Option<PathBuf>,
    network: &'a str,
}

fn cmd_self_test() -> Result<(), Error> {
    run_self_tests()?;
    let forum = mweb_forum_status()?;
    println!("Cryptographic self-tests:\nPASS");
    println!();
    println!("Address self-tests:\nPASS");
    println!();
    println!("{forum}");
    println!();
    println!("{}", litecoin_core_status());
    Ok(())
}

fn cmd_analyze(target: &str, kind: &str, network: &str) -> Result<(), Error> {
    let _network = Network::parse(network)?;
    let kind = AddressKind::parse(kind)?;
    let analysis = analyze(kind, target)?;
    println!("{}", analysis.report());
    if !analysis.reachable || analysis.too_rare {
        return Err(Error::prefix(if analysis.reason.is_empty() {
            "target is not searchable".to_owned()
        } else {
            analysis.reason.clone()
        }));
    }
    Ok(())
}

fn cmd_benchmark(kind: &str, threads: Option<usize>, network: &str) -> Result<(), Error> {
    let _network = Network::parse(network)?;
    let kind = AddressKind::parse(kind)?;
    let threads = resolve_threads(threads)?;
    run_self_tests()?;
    println!("Cryptographic self-tests:\nPASS");
    let rate = measure_miss_rate(kind, threads, Duration::from_secs(1))?;
    println!("Litecoin Vanity Benchmark");
    println!();
    println!("Network:\nMainnet");
    println!();
    println!("Address type:\n{}", kind.label());
    println!();
    println!("Threads:\n{threads}");
    println!();
    println!(
        "Measured miss-path rate:\n{} candidates/sec",
        group_u64(rate)
    );
    println!();
    println!("There is no guaranteed completion time.");
    println!("{}", litecoin_core_status());
    Ok(())
}

fn cmd_generate(args: GenerateArgs<'_>) -> Result<(), Error> {
    let _network = Network::parse(args.network)?;
    let kind = AddressKind::parse(args.kind)?;
    if args.hd && kind == AddressKind::Mweb {
        return Err(Error::prefix(
            "MWEB grinding is the keychain index. Do not pass --hd.",
        ));
    }
    let analysis = analyze(kind, args.target)?;
    if let Err(err) = require_searchable(&analysis) {
        println!("{}", analysis.report());
        return Err(err);
    }
    let threads = resolve_threads(args.threads)?;
    let output = match args.output {
        Some(path) => path,
        None => default_output(args.target)?,
    };
    ensure_output_available(&output)?;
    warn_if_output_dir_is_shared(&output);
    let mode = SearchMode::for_kind(kind, args.hd);
    print_banner(&analysis, mode, threads);
    run_self_tests()?;
    println!("Cryptographic self-tests:\nPASS");
    println!();
    println!("Target reachability:\nPASS");
    println!();
    print_difficulty(&analysis, mode);
    require_tty()?;
    if analysis.needs_exhaust_confirmation(args.hd || kind == AddressKind::Mweb) {
        println!("This derivation index space does not reach a 50% chance.");
        println!("The target is not reachable within this mnemonic at a 50% probability.");
        println!("Type EXHAUST to continue:");
        confirm_line("EXHAUST")?;
    }
    if analysis.needs_large_search_confirmation() {
        println!(
            "This prefix is expected to take at least {} attempts.",
            group_digits(&CONFIRMATION_THRESHOLD.to_string())
        );
        println!("Type SEARCH to continue:");
        confirm_line("SEARCH")?;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let interrupt = Arc::new(AtomicBool::new(false));
    install_interrupt(Arc::clone(&cancel), Arc::clone(&interrupt))?;
    println!("Searching...");
    let _ = io::stdout().flush();
    let started = Instant::now();
    let limit = if kind == AddressKind::Mweb {
        1u64 << 32
    } else {
        u64::from(HARDENED)
    };
    let hit = search(
        &SearchRequest::new(kind, args.hd, args.target, 0, limit, None),
        threads,
        Arc::clone(&cancel),
        move |attempts, rate| {
            println!("Attempts: {}", group_u64(attempts));
            println!("Rate: {} candidates/sec", group_u64(rate));
            println!("Elapsed: {}", format_elapsed(started.elapsed()));
            let _ = io::stdout().flush();
        },
    );
    let hit = match hit {
        Ok(hit) if interrupt.load(Ordering::Acquire) => {
            return Err(Error::Cancelled {
                attempts: hit.attempts,
            });
        }
        other => other?,
    };
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }
    println!();
    println!("Match found.");
    println!("Attempts: {}", group_u64(hit.attempts));
    println!("Elapsed: {}", format_elapsed(started.elapsed()));
    println!("The public address is printed after the encrypted wallet is saved.");
    println!();
    let _ = io::stdout().flush();
    save_and_print(SaveArgs {
        output: &output,
        interrupt: &interrupt,
        attempts: hit.attempts,
        elapsed: started.elapsed(),
        address: hit.address.clone(),
        descriptor: hit.descriptor.clone(),
        path: hit.material.path().to_owned(),
        kind: hit.material.kind(),
        mode: hit.material.mode(),
        index: hit.material.index(),
        material: &hit.material,
        collection: Vec::new(),
    })
}

struct SaveArgs<'a> {
    output: &'a Path,
    interrupt: &'a AtomicBool,
    attempts: u64,
    elapsed: Duration,
    address: String,
    descriptor: String,
    path: String,
    kind: AddressKind,
    mode: SearchMode,
    index: u32,
    material: &'a ltc_vanity::WalletMaterial,
    collection: Vec<ltc_vanity::wallet::CollectionItem>,
}

fn save_and_print(args: SaveArgs<'_>) -> Result<(), Error> {
    let passphrase = match prompt_new_passphrase(args.interrupt) {
        Ok(passphrase) => passphrase,
        Err(err) => {
            eprintln!("Wallet was not saved.");
            return match err {
                Error::Cancelled { .. } => Err(Error::Cancelled {
                    attempts: args.attempts,
                }),
                other => Err(other),
            };
        }
    };
    if args.interrupt.load(Ordering::Acquire) {
        eprintln!("Wallet was not saved.");
        return Err(Error::Cancelled {
            attempts: args.attempts,
        });
    }
    warn_if_output_dir_is_shared(args.output);
    if let Err(err) = write_encrypted_wallet(
        args.output,
        passphrase.as_str(),
        args.material,
        &args.address,
    ) {
        eprintln!("Wallet was not saved successfully.");
        return Err(err);
    }
    drop(passphrase);
    print_found(&args);
    Ok(())
}

fn cmd_collection(
    threads: Option<usize>,
    output: Option<PathBuf>,
    network: &str,
) -> Result<(), Error> {
    let _network = Network::parse(network)?;
    let threads = resolve_threads(threads)?;
    let output = output.unwrap_or_else(|| PathBuf::from("litecoin-zuzu-collection-wallet.json"));
    ensure_output_available(&output)?;
    warn_if_output_dir_is_shared(&output);
    let targets = [
        (AddressKind::P2pkh, "LZuZu"),
        (AddressKind::P2shP2wpkh, "M8ZuZu"),
        (AddressKind::P2wpkh, "ltc1qzuzu"),
        (AddressKind::P2tr, "ltc1pzuzu"),
        (AddressKind::Mweb, "zuzu"),
    ];
    let mut analyses = Vec::new();
    let mut exhaust = false;
    let mut large = false;
    println!("LITECOIN ZUZU COLLECTION");
    println!("Nested SegWit uses M8ZuZu. Version 0x32 cannot encode MZuZu.");
    println!();
    for (kind, target) in targets {
        let analysis = analyze(kind, target)?;
        println!("{}", analysis.report());
        if let Some(block) = finite_block(
            &analysis,
            if kind == AddressKind::Mweb {
                SearchMode::MwebIndex
            } else {
                SearchMode::HdIndex
            },
        ) {
            print!("{block}");
        }
        require_searchable(&analysis)?;
        exhaust |= analysis.needs_exhaust_confirmation(true);
        large |= analysis.needs_large_search_confirmation();
        analyses.push(analysis);
    }
    let _ = analyses;
    run_self_tests()?;
    println!("Cryptographic self-tests:\nPASS");
    println!();
    require_tty()?;
    if exhaust {
        println!("This derivation index space does not reach a 50% chance.");
        println!("The target is not reachable within this mnemonic at a 50% probability.");
        println!("Type EXHAUST to continue:");
        confirm_line("EXHAUST")?;
    }
    if large {
        println!(
            "This prefix is expected to take at least {} attempts.",
            group_digits(&CONFIRMATION_THRESHOLD.to_string())
        );
        println!("Type SEARCH to continue:");
        confirm_line("SEARCH")?;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let interrupt = Arc::new(AtomicBool::new(false));
    install_interrupt(Arc::clone(&cancel), Arc::clone(&interrupt))?;
    println!("Searching...");
    let _ = io::stdout().flush();
    let started = Instant::now();
    let started_for_progress = started;
    let hit = search_collection(
        &CollectionRequest {
            targets: targets
                .iter()
                .map(|(kind, target)| (*kind, (*target).to_owned()))
                .collect(),
            threads,
            account: 0,
        },
        Arc::clone(&cancel),
        Arc::new(move |attempts, rate| {
            println!("Attempts: {}", group_u64(attempts));
            println!("Rate: {} candidates/sec", group_u64(rate));
            println!(
                "Elapsed: {}",
                format_elapsed(started_for_progress.elapsed())
            );
            let _ = io::stdout().flush();
        }),
    )?;
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }
    println!();
    println!("Match found.");
    println!("The public addresses are printed after the encrypted wallet is saved.");
    let joined = hit
        .items
        .iter()
        .map(|item| item.address.as_str())
        .collect::<Vec<_>>()
        .join("|");
    save_and_print(SaveArgs {
        output: &output,
        interrupt: &interrupt,
        attempts: hit.attempts,
        elapsed: started.elapsed(),
        address: joined,
        descriptor: String::new(),
        path: hit.material.path().to_owned(),
        kind: AddressKind::P2pkh,
        mode: SearchMode::Collection,
        index: 0,
        material: &hit.material,
        collection: hit.items.clone(),
    })
}

fn print_banner(analysis: &Analysis, mode: SearchMode, threads: usize) {
    println!("Litecoin Vanity Generator");
    println!();
    println!("Network:\nMainnet");
    println!();
    println!("Address type:\n{}", analysis.kind.label());
    println!();
    println!("Mode:\n{}", mode.name());
    println!();
    println!("Threads:\n{threads}");
    println!();
    println!("{}", LITECOIN_KEY_REUSE_WARNING);
}

fn print_difficulty(analysis: &Analysis, mode: SearchMode) {
    print!("{}", difficulty_text(analysis, mode));
    if matches!(mode, SearchMode::HdIndex | SearchMode::MwebIndex) {
        println!("A gap limit of 20 will not discover a high index.");
        println!("The recorded path and index are required for recovery.");
    }
    println!("There is no guaranteed completion time.");
    println!();
}

fn print_found(args: &SaveArgs<'_>) {
    println!("FOUND");
    println!();
    println!("Network:\nMainnet");
    println!();
    println!("Mode:\n{}", args.mode.name());
    println!();
    if args.mode == SearchMode::Collection {
        println!("LITECOIN ZUZU COLLECTION");
        println!();
        for item in &args.collection {
            println!("Address type:\n{}", item.kind.label());
            println!("Address:\n{}", item.address);
            println!("Derivation path:\n{}", item.path);
            println!("Index:\n{}", item.index);
            if !item.descriptor.is_empty() {
                println!("Descriptor:\n{}", item.descriptor);
            }
            println!();
        }
    } else {
        println!("Address type:\n{}", args.kind.label());
        println!();
        println!("Address:\n{}", args.address);
        println!();
        if !args.descriptor.is_empty() {
            println!("Descriptor:\n{}", args.descriptor);
            println!();
            if args.kind == AddressKind::P2tr {
                println!("The descriptor uses the internal key. Litecoin Core on the pinned snapshot has no Taproot receive type. This tr() line is for other software. It is not a claim that Core will import it.");
                println!("Spending this output requires the BIP341 key-path tweak of an empty script tree.");
                println!();
            }
        }
        if !args.path.is_empty() {
            println!("Derivation path:\n{}", args.path);
            println!("Index:\n{}", args.index);
            println!("A gap limit of 20 will not discover this index.");
            println!("Seed-only restore is not claimed.");
            println!();
        }
    }
    println!("Attempts: {}", group_u64(args.attempts));
    println!("Elapsed: {}", format_elapsed(args.elapsed));
    println!(
        "Rate: {} candidates/sec",
        group_u64(rate(args.attempts, args.elapsed))
    );
    println!();
    println!("Encrypted wallet:\n{}", args.output.display());
    println!();
    println!("Independent verification:\nPASS");
    println!();
    println!("Recovery test:\nPENDING");
    println!();
    println!("Run verify on the wallet file before sending Litecoin to this address.");
    println!("This program did not broadcast a transaction and did not contact a node.");
    println!("{}", litecoin_core_status());
}

fn cmd_verify(path: &Path) -> Result<(), Error> {
    require_tty()?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    drop(passphrase);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    println!("Wallet authentication: PASS");
    println!("Secret-to-address reconstruction: PASS");
    println!("Independent verification: PASS");
    println!();
    println!("Network:\nMainnet");
    println!("Address type:\n{}", opened.type_name());
    println!("Mode:\n{}", opened.mode.name());
    if !opened.path.is_empty() {
        println!("Derivation path:\n{}", opened.path);
    }
    println!();
    if opened.mode == SearchMode::Collection {
        for item in &opened.collection {
            println!("Address type:\n{}", item.kind.label());
            println!("Stored:\n{}", item.address);
            println!("Derived:\n{}", item.address);
            println!("Index:\n{}", item.index);
            println!();
        }
    } else {
        println!("Stored:\n{}", opened.address);
        println!();
        println!("Derived:\n{}", opened.address);
        println!();
    }
    println!("MATCH: YES");
    Ok(())
}

fn cmd_export(path: &Path) -> Result<(), Error> {
    require_export_terminals()?;
    println!("WARNING: This operation prints Litecoin recovery secrets to this terminal.");
    println!("Do not paste them into a website, chat, AI, issue tracker, shell history, or online verifier.");
    println!("Only the public address may be shared.");
    println!(
        "Clear the terminal scrollback after the secrets have been copied onto offline media."
    );
    print!("{LITECOIN_KEY_REUSE_WARNING}");
    println!("Type EXPORT to continue:");
    confirm_line("EXPORT")?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    drop(passphrase);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    let secret = export_wallet_text(&opened)?;
    drop(opened);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    print!("{}", secret.as_str());
    Ok(())
}

fn default_output(target: &str) -> Result<PathBuf, Error> {
    if target.is_empty()
        || target.contains('/')
        || target.contains('\\')
        || target.contains("..")
        || target.starts_with('.')
    {
        return Err(Error::prefix(
            "the target cannot be used as a wallet file name; pass --output",
        ));
    }
    Ok(PathBuf::from(format!("{target}-wallet.json")))
}

fn warn_if_output_dir_is_shared(path: &Path) {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(meta) = std::fs::metadata(parent) else {
        return;
    };
    if meta.permissions().mode() & 0o022 != 0 {
        eprintln!(
            "warning: output directory is writable by group or others. Create a private directory with: mkdir -m 700 <dir>"
        );
    }
}

fn ensure_output_available(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::OutputExists);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(Error::OutputDir);
        }
    }
    Ok(())
}

fn resolve_threads(threads: Option<usize>) -> Result<usize, Error> {
    match threads {
        Some(value) => {
            if value == 0 || value > MAX_THREADS {
                Err(Error::Threads)
            } else {
                Ok(value)
            }
        }
        None => Ok(default_threads()),
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, MAX_THREADS)
}

fn require_tty() -> Result<(), Error> {
    if io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(Error::NeedTerminal)
    }
}

fn require_export_terminals() -> Result<(), Error> {
    export_terminals_ok(io::stdin().is_terminal(), io::stdout().is_terminal())
}

fn export_terminals_ok(stdin_tty: bool, stdout_tty: bool) -> Result<(), Error> {
    if stdin_tty && stdout_tty {
        Ok(())
    } else {
        Err(Error::ExportNeedsTerminal)
    }
}

fn confirm_line(expected: &str) -> Result<(), Error> {
    require_tty()?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| Error::Io(format!("stdin: {err}")))?;
    if line.trim() == expected {
        Ok(())
    } else {
        Err(Error::NotConfirmed)
    }
}

fn install_command_interrupt() -> Result<Arc<AtomicBool>, Error> {
    let interrupt = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    install_interrupt(cancel, Arc::clone(&interrupt))?;
    Ok(interrupt)
}

fn secret_output_allowed(interrupted: bool) -> Result<(), Error> {
    if interrupted {
        Err(Error::Cancelled { attempts: 0 })
    } else {
        Ok(())
    }
}

fn prompt_new_passphrase(interrupt: &AtomicBool) -> Result<Zeroizing<String>, Error> {
    require_tty()?;
    for _ in 0..3 {
        if interrupt.load(Ordering::Acquire) {
            return Err(Error::Cancelled { attempts: 0 });
        }
        let first = prompt_password_interruptible("Passphrase: ", interrupt)?;
        let second = prompt_password_interruptible("Confirm passphrase: ", interrupt)?;
        if first.as_str() != second.as_str() {
            eprintln!("error: passphrase did not match");
            continue;
        }
        match check_new_passphrase(first.as_str()) {
            Ok(()) => return Ok(first),
            Err(_) => {
                if check_passphrase(first.as_str()).is_ok() {
                    eprintln!(
                        "error: a new passphrase must be at least {MIN_NEW_PASSPHRASE_CHARS} characters"
                    );
                    eprintln!(
                        "That minimum only stops accidents. It is not a measure of strength."
                    );
                } else {
                    eprintln!("error: passphrase rejected");
                }
            }
        }
    }
    Err(Error::Passphrase)
}

fn prompt_password_interruptible(
    label: &str,
    interrupt: &AtomicBool,
) -> Result<Zeroizing<String>, Error> {
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled { attempts: 0 });
    }
    password_prompt_result(
        rpassword::prompt_password(label),
        interrupt.load(Ordering::Acquire),
    )
}

fn password_prompt_result(
    read: Result<String, std::io::Error>,
    interrupted: bool,
) -> Result<Zeroizing<String>, Error> {
    if interrupted {
        if let Ok(password) = read {
            drop(Zeroizing::new(password));
        }
        return Err(Error::Cancelled { attempts: 0 });
    }
    match read {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            Err(Error::Cancelled { attempts: 0 })
        }
        Err(_) => Err(Error::NeedTerminal),
    }
}

fn install_interrupt(cancel: Arc<AtomicBool>, interrupt: Arc<AtomicBool>) -> Result<(), Error> {
    ctrlc::set_handler(move || {
        interrupt.store(true, Ordering::Release);
        cancel.store(true, Ordering::Release);
    })
    .map_err(|_| Error::Io("could not install the interrupt handler".to_owned()))
}

fn group_u64(value: u64) -> String {
    group_digits(&value.to_string())
}

fn rate(attempts: u64, elapsed: Duration) -> u64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        attempts
    } else {
        (attempts as f64 / seconds) as u64
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    if elapsed.as_secs() < 60 {
        format!("{:.3}s", elapsed.as_secs_f64())
    } else {
        let seconds = elapsed.as_secs();
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::{export_terminals_ok, password_prompt_result, secret_output_allowed, Error};

    #[test]
    fn export_requires_both_terminals() {
        assert!(export_terminals_ok(true, true).is_ok());
        assert_eq!(
            export_terminals_ok(true, false),
            Err(Error::ExportNeedsTerminal)
        );
        assert_eq!(
            export_terminals_ok(false, true),
            Err(Error::ExportNeedsTerminal)
        );
    }

    #[test]
    fn interrupted_passphrase_read_cancels_without_keeping_it() {
        let accepted =
            password_prompt_result(Ok("correct horse battery".to_owned()), false).unwrap();
        assert_eq!(accepted.as_str(), "correct horse battery");
        assert!(matches!(
            password_prompt_result(Ok("secret-passphrase".to_owned()), true),
            Err(Error::Cancelled { attempts: 0 })
        ));
        let interrupted = std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted");
        assert!(matches!(
            password_prompt_result(Err(interrupted), false),
            Err(Error::Cancelled { attempts: 0 })
        ));
    }

    #[test]
    fn cancelled_decrypt_does_not_release_a_secret() {
        assert!(secret_output_allowed(false).is_ok());
        assert!(matches!(
            secret_output_allowed(true),
            Err(Error::Cancelled { attempts: 0 })
        ));
    }
}
