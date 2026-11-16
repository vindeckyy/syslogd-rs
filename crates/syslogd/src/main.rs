mod ingress;

use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use syslog_core::config::parse::{self, Mode};
use syslog_core::engine::Engine;

type EngineHolder = Arc<RwLock<Arc<Engine>>>;

#[derive(Parser, Debug)]
#[command(
    name = "syslogd-rs",
    about = "memory-safe rsyslog-compatible syslog daemon"
)]
struct Cli {
    /// config file
    #[arg(short = 'f', default_value = "/etc/rsyslog.conf")]
    config: PathBuf,
    /// debug; accepted for rsyslogd parity
    #[arg(short = 'd')]
    debug: bool,
    /// run in foreground (always; systemd supervisors require this)
    #[arg(short = 'n')]
    foreground: bool,
    /// config check; rsyslogd's -N1
    #[arg(short = 'N', value_name = "LEVEL")]
    check: Option<u8>,
    /// alias for -N1
    #[arg(long = "check")]
    check_alias: bool,
    /// lenient rsyslog-parity parse
    #[arg(long = "compat")]
    compat: bool,
    /// print the include-expanded config and exit
    #[arg(short = 'o', long = "dump-merged")]
    dump_merged: bool,
    /// pidfile; NONE (default) disables. Ignored under systemd.
    #[arg(short = 'i')]
    pidfile: Option<String>,
    /// print version and exit
    #[arg(short = 'v', action = clap::ArgAction::SetTrue)]
    version_flag: bool,
}

fn mode(compat: bool) -> Mode {
    if compat {
        Mode::Compat
    } else {
        Mode::Strict
    }
}

fn tls_preflight(cfg: &parse::Config) -> Result<(), String> {
    for i in &cfg.inputs {
        if let parse::InputSpec::Tcp { tls: Some(t), .. } = i {
            let cert = t.cert.clone().or_else(|| cfg.globals.tls_cert.clone());
            let key = t.key.clone().or_else(|| cfg.globals.tls_key.clone());
            if cert.is_none() || key.is_none() {
                return Err("tls_cert_missing on TLS listener".into());
            }
            if !cert.unwrap().exists() || !key.unwrap().exists() {
                return Err("tls_cert_missing on TLS listener".into());
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    if cli.version_flag {
        println!("syslogd-rs 0.1.0");
        std::process::exit(0);
    }

    let (cfg, warns) = match parse::parse(&cli.config, mode(cli.compat)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {}", cli.config.display(), e);
            std::process::exit(1);
        }
    };
    for w in &warns {
        eprintln!("warning: {w}");
    }

    if cli.dump_merged {
        for line in &cfg.merged {
            println!("{line}");
        }
        std::process::exit(0);
    }

    if cli.check_alias || cli.check == Some(1) {
        if let Err(e) = tls_preflight(&cfg) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        println!(
            "ok: {} rules, {} listeners",
            cfg.rules.len(),
            cfg.inputs.len()
        );
        std::process::exit(0);
    }

    if let Err(e) = tls_preflight(&cfg) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let engine = Engine::build(cfg.clone());
    let holder: EngineHolder = Arc::new(RwLock::new(engine.clone()));

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (queue_tx, queue_rx) = tokio::sync::mpsc::channel(20000);

    // dispatch runner: reads through the holder so SIGHUP swaps live
    let runner_holder = holder.clone();
    let runner = tokio::spawn(async move {
        let mut queue_rx = queue_rx;
        while let Some(m) = queue_rx.recv().await {
            let eng = runner_holder
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            eng.handle(m);
        }
    });

    let tasks = ingress::spawn_inputs(holder.clone(), &cfg, queue_tx, cancel_rx);

    let _ = sd_notify("READY=1");

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).expect("SIGINT");
    let mut sighup =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).expect("SIGHUP");
    let mut sigusr2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
        .expect("SIGUSR2");

    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            _ = sighup.recv() => {
                // Re-parse; on failure keep the old engine (rsyslog-like).
                match parse::parse(&cli.config, mode(cli.compat)) {
                    Ok((new_cfg, _)) => {
                        if let Err(e) = tls_preflight(&new_cfg) {
                            eprintln!("reload: {e}");
                            continue;
                        }
                        let new_engine = Engine::build(new_cfg);
                        *holder.write().unwrap_or_else(|e| e.into_inner()) = new_engine;
                        eprintln!("config reloaded");
                    }
                    Err(e) => eprintln!("reload failed: {e}"),
                }
            }
            _ = sigusr2.recv() => {
                engine.metrics.dump();
            }
        }
    }

    let _ = sd_notify("STOPPING=1");
    // tasks observe shutdown and exit; single 5s deadline for all.
    let _ = cancel_tx.send(true);
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
    tokio::pin!(deadline);
    for t in tasks {
        tokio::select! {
            _ = &mut deadline => break,
            _ = t => {}
        }
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), runner).await;
    engine.metrics.dump();
}

fn sd_notify(msg: &str) -> std::io::Result<()> {
    let notify = std::env::var("NOTIFY_SOCKET").unwrap_or_default();
    if notify.is_empty() {
        return Ok(());
    }
    let path = notify
        .strip_prefix('@')
        .map(|p| format!("/run/systemd/notify/{}", p))
        .unwrap_or(notify);
    let sock = std::os::unix::net::UnixDatagram::unbound()?;
    sock.send_to(msg.as_bytes(), format!("@{path}"))?;
    Ok(())
}
