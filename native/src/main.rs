//! Private Proxy native messaging host.
//!
//! Launched by Chromium as `private-proxy-host chrome-extension://<id>/ [--parent-window=N]`.
//! Also offers `install`, `uninstall` and `--version` for the installers. These are only
//! reachable from a command line, because Chromium never passes arbitrary arguments.

use ppcore::protocol::{self, ApiError, ErrorCode};
use ppcore::service::{Msg, Service, Timing};
use ppcore::{install, log, nm, paths, secrets, store, xray};
use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(origin) if origin.starts_with("chrome-extension://") => run_host(origin),
        Some("--version") | Some("version") => {
            println!("private-proxy-host {} (protocol {})", ppcore::NATIVE_VERSION, ppcore::PROTOCOL_VERSION);
            if let Some(x) = xray::locate() {
                println!("xray {} ({})", xray::version(&x).unwrap_or_else(|| "?".into()), x.display());
            } else {
                println!("xray: not found");
            }
            ExitCode::SUCCESS
        }
        Some("install") => cli_install(&args[1..]),
        Some("uninstall") => cli_uninstall(&args[1..]),
        Some("status") => {
            println!("Registered for: {}", install::registered_browsers().join(", "));
            println!("Data directory: {}", paths::data_dir().display());
            println!("Logs:           {}", paths::log_dir().display());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "Private Proxy native runtime {}.\n\nThis program is started automatically by the Private Proxy browser extension;\nthere is nothing to open. Commands: install, uninstall [--purge], status, --version",
                ppcore::NATIVE_VERSION
            );
            if cfg!(windows) && io::stdin().is_terminal() && args.is_empty() {
                pause();
            }
            ExitCode::from(2)
        }
    }
}

fn pause() {
    eprintln!("\nPress Enter to close.");
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
}

fn run_host(origin: &str) -> ExitCode {
    log::init(&paths::log_dir(), false);
    let id = origin.trim_start_matches("chrome-extension://").trim_end_matches('/');
    let allowed = ppcore::allowed_extension_ids();
    if !allowed.iter().any(|a| a == id) {
        // Chromium enforces allowed_origins already; this is defence in depth.
        log::error(format!("rejected caller origin {origin}"));
        return ExitCode::from(3);
    }
    xray::install_signal_handlers();
    log::info(format!("helper {} started", ppcore::NATIVE_VERSION));

    let data_dir = paths::data_dir();
    let store = match store::Store::open(data_dir.clone(), secrets::default_provider(&data_dir)) {
        Ok(s) => s,
        Err(e) => {
            log::error(format!("cannot open data dir: {e}"));
            return ExitCode::from(4);
        }
    };

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
    let (tx, rx) = mpsc::channel::<Msg>();

    // Writer: the only thread that touches stdout.
    let writer = std::thread::spawn(move || {
        let mut stdout = io::stdout().lock();
        for msg in out_rx {
            if nm::write_message(&mut stdout, &msg).is_err() {
                break;
            }
        }
    });

    // Reader: stdin EOF (browser closed the port) triggers shutdown.
    let rtx = tx.clone();
    let out_err = out_tx.clone();
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            match nm::read_message(&mut stdin) {
                Ok(bytes) => {
                    let (id, req) = protocol::decode(&bytes);
                    if id == 0 {
                        // Cannot correlate; report via an event instead.
                        let e = req.err().unwrap_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "invalid"));
                        let _ = out_err.send(protocol::encode_event("protocolError", "error", &serde_json::to_value(e).unwrap_or_default()));
                        continue;
                    }
                    if rtx.send(Msg::Request(id, req)).is_err() {
                        break;
                    }
                }
                Err(nm::ReadError::TooLarge(n)) => {
                    log::error(format!("message too large ({n} bytes); closing"));
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = rtx.send(Msg::Shutdown);
    });

    let ttx = tx.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if ttx.send(Msg::Tick).is_err() {
            break;
        }
    });

    let svc = Service::new(store, xray::locate(), out_tx, tx, Timing::default());
    svc.run_loop(rx); // returns after Shutdown, with Xray stopped
    let _ = writer.join();
    ExitCode::SUCCESS
}

fn flag_value(args: &[String], name: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name && i + 1 < args.len() {
            v.push(args[i + 1].clone());
            i += 2;
        } else if let Some(x) = args[i].strip_prefix(&format!("{name}=")) {
            v.push(x.to_string());
            i += 1;
        } else {
            i += 1;
        }
    }
    v
}

fn cli_install(args: &[String]) -> ExitCode {
    let interactive = args.iter().any(|a| a == "--interactive");
    let mut ids = flag_value(args, "--extension-id");
    if ids.is_empty() {
        ids = ppcore::allowed_extension_ids();
    }
    let source_dir = flag_value(args, "--source")
        .pop()
        .map(Into::into)
        .or_else(|| std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())))
        .unwrap_or_default();
    let target_dir = flag_value(args, "--target").pop().map(Into::into).unwrap_or_else(paths::default_install_dir);
    let opts = install::InstallOptions {
        source_dir,
        target_dir,
        extension_ids: ids,
        all_browsers: args.iter().any(|a| a == "--all-browsers"),
        register_only: args.iter().any(|a| a == "--register-only"),
    };
    let code = match install::install(&opts) {
        Ok(lines) => {
            for l in lines {
                println!("  {l}");
            }
            println!("\nPrivate Proxy runtime installed. Restart your browser, then use the extension.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Installation failed: {e}");
            ExitCode::FAILURE
        }
    };
    if interactive {
        pause();
    }
    code
}

fn cli_uninstall(args: &[String]) -> ExitCode {
    let interactive = args.iter().any(|a| a == "--interactive");
    let mut purge = args.iter().any(|a| a == "--purge");
    if interactive && !purge {
        println!("Uninstalling the Private Proxy runtime.");
        print!("Also delete imported servers and saved credentials? [y/N] ");
        let _ = io::Write::flush(&mut io::stdout());
        let mut s = String::new();
        let _ = io::stdin().read_line(&mut s);
        purge = matches!(s.trim(), "y" | "Y" | "yes");
    }
    let target_dir = flag_value(args, "--target").pop().map(Into::into).unwrap_or_else(paths::default_install_dir);
    let code = match install::uninstall(&target_dir, purge) {
        Ok(lines) => {
            for l in lines {
                println!("  {l}");
            }
            println!("\nPrivate Proxy runtime removed. You can now remove the browser extension.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Uninstall failed: {e}");
            ExitCode::FAILURE
        }
    };
    if interactive {
        pause();
    }
    code
}
