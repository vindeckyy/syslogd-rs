use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use syslog_core::config::parse::{Config, InputSpec, TlsSpec};
use syslog_core::engine::Engine;
use syslog_core::msg::Msg;
use syslog_core::parse3164;
use syslog_core::parse5424;
use syslog_core::parse5424::ParseErr;
use time::OffsetDateTime;
use tokio::net::{TcpListener, UdpSocket, UnixDatagram};
use tokio::sync::{mpsc, watch};

pub type EngineHolder = Arc<std::sync::RwLock<Arc<Engine>>>;

pub fn engine_of(holder: &EngineHolder) -> Arc<Engine> {
    holder.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn spawn_inputs(
    engine_holder: EngineHolder,
    cfg: &Config,
    tx: mpsc::Sender<Msg>,
    shutdown: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = Vec::new();
    if let Some(h) = systemd_socket_task(engine_holder.clone(), tx.clone(), shutdown.clone()) {
        tasks.push(h);
    }
    if cfg.modules.imklog {
        tasks.push(kmsg_task(tx.clone(), shutdown.clone()));
    }
    for spec in &cfg.inputs {
        match spec {
            InputSpec::Udp { addr, port } => {
                tasks.push(tokio::spawn(udp_task(
                    engine_holder.clone(),
                    addr.clone(),
                    *port,
                    tx.clone(),
                    shutdown.clone(),
                )));
            }
            InputSpec::Tcp { addr, port, tls } => {
                tasks.push(tokio::spawn(tcp_task(
                    engine_holder.clone(),
                    addr.clone(),
                    *port,
                    tls.clone(),
                    cfg.clone(),
                    tx.clone(),
                    shutdown.clone(),
                )));
            }
        }
    }
    tasks
}

/// Adopt the systemd-provided syslog socket fd when passed; otherwise
/// bind /dev/log on hosts without systemd.
fn systemd_socket_task(
    engine: EngineHolder,
    tx: mpsc::Sender<Msg>,
    mut shutdown: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if let Some(fd) = listen_fds().first().copied() {
        return Some(tokio::spawn(async move {
            if let Some(ud) = fd_datagram(fd) {
                unix_loop(engine, ud, tx, &mut shutdown).await;
            }
        }));
    }
    let journal = std::path::Path::new("/run/systemd/journal/syslog");
    if journal.exists() && std::env::var("INVOCATION_ID").is_err() {
        return Some(tokio::spawn(async move {
            if let Ok(ud) = UnixDatagram::bind("/run/systemd/journal/syslog") {
                unix_loop(engine, ud, tx, &mut shutdown).await;
            }
        }));
    }
    if std::path::Path::new("/dev/log").exists() && std::env::var("INVOCATION_ID").is_err() {
        return Some(tokio::spawn(async move {
            if let Ok(ud) = UnixDatagram::bind("/dev/log") {
                let _ = std::fs::set_permissions(
                    "/dev/log",
                    std::os::unix::fs::PermissionsExt::from_mode(0o666),
                );
                unix_loop(engine, ud, tx, &mut shutdown).await;
            }
        }));
    }
    None
}

fn listen_fds() -> Vec<u32> {
    if std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        != Some(std::process::id())
    {
        return Vec::new();
    }
    let Ok(n) = std::env::var("LISTEN_FDS") else {
        return Vec::new();
    };
    let count: u32 = n.parse().unwrap_or(0);
    (0..count).map(|i| 3 + i).collect()
}

fn fd_datagram(fd: u32) -> Option<UnixDatagram> {
    use std::os::unix::io::FromRawFd;
    let std = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd as i32) };
    UnixDatagram::from_std(std).ok()
}

async fn unix_loop(
    holder: EngineHolder,
    ud: UnixDatagram,
    tx: mpsc::Sender<Msg>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = ud.recv(&mut buf) => match r {
                Ok(n) => {
                    let eng = engine_of(&holder);
                    let m = parse_bytes(&buf[..n], "imuxsock", eng.local_tz(), None);
                    let _ = tx.try_send(m);
                }
                Err(_) => continue,
            }
        }
    }
}

async fn udp_task(
    engine: EngineHolder,
    addr: String,
    port: u16,
    tx: mpsc::Sender<Msg>,
    mut shutdown: watch::Receiver<bool>,
) {
    let sock = match UdpSocket::bind(format!("{addr}:{port}")).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bind udp {addr}:{port}: {e}");
            std::process::exit(2);
        }
    };
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, peer)) => {
                    let eng = engine_of(&engine);
                    if n > eng.max_message_size() {
                        eng.metrics.oversize.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let m = parse_bytes(&buf[..n], "imudp", eng.local_tz(), Some(peer));
                    let _ = tx.try_send(m);
                }
                Err(_) => continue,
            }
        }
    }
}

async fn tcp_task(
    engine: EngineHolder,
    addr: String,
    port: u16,
    tls: Option<TlsSpec>,
    cfg: Config,
    tx: mpsc::Sender<Msg>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener = match TcpListener::bind(format!("{addr}:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind tcp {addr}:{port}: {e}");
            std::process::exit(2);
        }
    };
    let acceptor = match &tls {
        Some(t) => match build_acceptor(t, &cfg) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("tls on {addr}:{port}: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };
    let peer_check: Option<PeerCheck> = acceptor.as_ref().and_then(|a| {
        a.1.as_ref().map(|p| PeerCheck {
            permitted: p.permitted.clone(),
        })
    });
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            r = TcpListener::accept(&listener) => match r {
                Ok((stream, peer)) => {
                    let e = engine_of(&engine);
                    let tx2 = tx.clone();
                    let ac = acceptor.clone();
                    let pc = peer_check.as_ref().map(|p| p.permitted.clone());
                    tokio::spawn(async move {
                        tcp_conn(e, stream, peer, ac, tx2, pc).await;
                    });
                }
                Err(_) => continue,
            }
        }
    }
}

#[derive(Clone)]
struct PeerCheck {
    permitted: Vec<String>,
}

fn build_acceptor(
    t: &TlsSpec,
    cfg: &Config,
) -> Result<(tokio_rustls::TlsAcceptor, Option<PeerCheck>), std::io::Error> {
    let peer =
        matches!(t.auth_mode, syslog_core::config::parse::AuthMode::X509Name).then(|| PeerCheck {
            permitted: t.permitted_peer.clone(),
        });
    let cert_path = t.cert.clone().or_else(|| cfg.globals.tls_cert.clone());
    let key_path = t.key.clone().or_else(|| cfg.globals.tls_key.clone());
    let (Some(cp), Some(kp)) = (cert_path, key_path) else {
        eprintln!("tls_cert_missing on TLS listener");
        return Err(std::io::Error::other("tls_cert_missing"));
    };
    let cert_data = std::fs::read(&cp).map_err(|_| std::io::Error::other("tls_cert_missing"))?;
    let key_data = std::fs::read(&kp).map_err(|_| std::io::Error::other("tls_key_missing"))?;
    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_data[..]))
            .filter_map(Result::ok)
            .collect();
    let key_der = rustls_pemfile::pkcs8_private_keys(&mut std::io::Cursor::new(&key_data[..]))
        .filter_map(Result::ok)
        .next()
        .ok_or_else(|| std::io::Error::other("tls_key_parse"))?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der);
    // Client-cert verification: chain via configured CA (or server's
    // own CA file). x509/name additionally checks SAN names against
    // PermittedPeer after the handshake.
    let builder = rustls::ServerConfig::builder();
    let verifier = client_verifier(t, cfg)?;
    let server = match verifier {
        Some(v) => builder
            .with_client_cert_verifier(v)
            .with_single_cert(certs, key)
            .map_err(|_| std::io::Error::other("tls_cert_invalid"))?,
        None => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| std::io::Error::other("tls_cert_invalid"))?,
    };
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(server)), peer))
}

fn client_verifier(
    t: &TlsSpec,
    cfg: &Config,
) -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier + Send + Sync>>, std::io::Error>
{
    let ca_path = t.ca.clone().or_else(|| cfg.globals.tls_ca.clone());
    let Some(ca_path) = ca_path else {
        return Ok(None);
    };
    let data = std::fs::read(&ca_path).map_err(|_| std::io::Error::other("tls_ca_missing"))?;
    let mut roots = rustls::RootCertStore::empty();
    let mut cur = std::io::Cursor::new(&data[..]);
    let pem: Vec<_> = rustls_pemfile::certs(&mut cur)
        .filter_map(Result::ok)
        .collect();
    if pem.is_empty() {
        let _ = roots.add(rustls::pki_types::CertificateDer::from(data.clone()));
    } else {
        for c in pem {
            let _ = roots.add(c);
        }
    }
    let prov = rustls::crypto::ring::default_provider();
    let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(prov),
    );
    let v = v
        .build()
        .map_err(|_| std::io::Error::other("tls_ca_invalid"))?;
    Ok(Some(
        v as Arc<dyn rustls::server::danger::ClientCertVerifier + Send + Sync>,
    ))
}

async fn tcp_conn(
    engine: Arc<Engine>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: Option<(tokio_rustls::TlsAcceptor, Option<PeerCheck>)>,
    tx: mpsc::Sender<Msg>,
    peer_check: Option<Vec<String>>,
) {
    use tokio::io::AsyncReadExt;

    // Per-frame detection for plain TCP: digit = octet-counted,
    // '<' = LF-delimited. TLS framing is octet-counted only.
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];

    if let Some((acc, _)) = acceptor {
        if let Some(permitted) = &peer_check {
            // name check: chain already done by the verifier
            let mut s = match acc.accept(stream).await {
                Ok(s) => s,
                Err(_) => {
                    engine.metrics.tls_auth_fail.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let der = s
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first().cloned());
            let ok = der
                .as_deref()
                .map(|d| syslog_core::action_fwd::peer_name_ok_pub(d, permitted))
                .unwrap_or(false);
            if !ok {
                engine.metrics.tls_auth_fail.fetch_add(1, Ordering::Relaxed);
                return;
            } else {
                let mut buf = [0u8; 8192];
                let mut pending: Vec<u8> = Vec::new();
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if feed_tls(&mut pending, &buf[..n], peer, &engine, &tx) {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                return;
            }
        }
        let mut s = match acc.accept(stream).await {
            Ok(s) => s,
            Err(_) => {
                engine.metrics.tls_auth_fail.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        loop {
            match s.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if feed_tls(&mut pending, &buf[..n], peer, &engine, &tx) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        return;
    }

    let mut s = stream;
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if feed(&mut pending, &buf[..n], peer, &engine, &tx) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn feed(
    pending: &mut Vec<u8>,
    chunk: &[u8],
    peer: SocketAddr,
    engine: &Arc<Engine>,
    tx: &mpsc::Sender<Msg>,
) -> bool {
    pending.extend_from_slice(chunk);
    loop {
        if pending.is_empty() {
            return false;
        }
        match pending[0] {
            b'0'..=b'9' => {
                let sp = match pending.iter().position(|&b| b == b' ') {
                    Some(i) => i,
                    None => return false,
                };
                let len: usize = match std::str::from_utf8(&pending[..sp]).unwrap_or("").parse() {
                    Ok(v) => v,
                    Err(_) => {
                        pending.drain(..1);
                        continue;
                    }
                };
                let total = sp + 1 + len;
                if pending.len() < total {
                    return false;
                }
                let frame = pending[sp + 1..total].to_vec();
                pending.drain(..total);
                feed_frame(frame, peer, engine, tx);
            }
            b'<' => {
                let lf = match pending.iter().position(|&b| b == b'\n') {
                    Some(i) => i,
                    None => return false,
                };
                let mut frame = pending[..lf].to_vec();
                pending.drain(..lf + 1);
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                feed_frame(frame, peer, engine, tx);
            }
            _ => {
                pending.drain(..1);
            }
        }
    }
}

fn feed_tls(
    pending: &mut Vec<u8>,
    chunk: &[u8],
    peer: SocketAddr,
    engine: &Arc<Engine>,
    tx: &mpsc::Sender<Msg>,
) -> bool {
    pending.extend_from_slice(chunk);
    loop {
        if pending.is_empty() {
            return false;
        }
        if !pending[0].is_ascii_digit() {
            // TLS framing requires octet-counted start.
            return true;
        }
        let sp = match pending.iter().position(|&b| b == b' ') {
            Some(i) => i,
            None => return false,
        };
        let len: usize = match std::str::from_utf8(&pending[..sp]).unwrap_or("").parse() {
            Ok(v) => v,
            Err(_) => return true,
        };
        let total = sp + 1 + len;
        if pending.len() < total {
            return false;
        }
        let frame = pending[sp + 1..total].to_vec();
        pending.drain(..total);
        feed_frame(frame, peer, engine, tx);
    }
}

fn feed_frame(frame: Vec<u8>, peer: SocketAddr, engine: &Arc<Engine>, tx: &mpsc::Sender<Msg>) {
    if frame.len() > engine.max_message_size() {
        engine.metrics.oversize.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let m = parse_bytes(&frame, "imtcp", engine.local_tz(), Some(peer));
    let _ = tx.try_send(m);
}

pub fn parse_bytes(
    input: &[u8],
    input_name: &'static str,
    tz: time::UtcOffset,
    peer: Option<SocketAddr>,
) -> Msg {
    let now = OffsetDateTime::now_utc().to_offset(tz);
    let parsed = parse5424::parse_rfc5424(input).or_else(|e| match e {
        ParseErr::UnsupportedVersion => parse3164::parse_rfc3164(input, now, tz),
        _ => parse3164::parse_rfc3164(input, now, tz),
    });
    match parsed {
        Ok(mut m) => {
            m.input_name = input_name;
            m.fromhost_ip = peer.map(|p| p.ip());
            m
        }
        Err(_) => {
            // Relay fix-up: no identifiable PRI, prepend <13> (T4).
            let mut fixed = String::from("<13>");
            fixed.push_str(&String::from_utf8_lossy(input));
            let mut m = parse3164::parse_rfc3164(fixed.as_bytes(), now, tz).unwrap_or_else(|_| {
                let mut fallback = Msg::new(
                    13,
                    bytes::Bytes::copy_from_slice(input),
                    bytes::Bytes::copy_from_slice(input),
                    input_name,
                );
                fallback.timestamp = Some(now);
                fallback
            });
            m.input_name = input_name;
            m.fromhost_ip = peer.map(|p| p.ip());
            m
        }
    }
}

// /proc/kmsg read forward via a blocking task.
fn kmsg_task(
    tx: mpsc::Sender<Msg>,
    _shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut last_seq: u64 = 0;
        let f = match std::fs::File::open("/proc/kmsg") {
            Ok(f) => f,
            Err(_) => return,
        };
        use std::io::Read;
        let mut f = f;
        let mut buf = [0u8; 8192];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((seq, msg)) = parse_kmsg_line(&buf[..n]) {
                        if seq > last_seq {
                            last_seq = seq;
                            if tx.blocking_send(msg).is_err() {
                                break;
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

fn parse_kmsg_line(line: &[u8]) -> Option<(u64, Msg)> {
    let text = std::str::from_utf8(line).ok()?;
    let (meta, msg) = text.split_once(';')?;
    let mut parts = meta.split(',');
    let seq: u64 = parts.next()?.parse().ok()?;
    let pri: u32 = parts.next()?.parse().ok()?;
    let pri = (pri % 192) as u8;
    let m = Msg::new(
        pri,
        bytes::Bytes::copy_from_slice(msg.as_bytes()),
        bytes::Bytes::copy_from_slice(line),
        "imklog",
    );
    Some((seq, m))
}
