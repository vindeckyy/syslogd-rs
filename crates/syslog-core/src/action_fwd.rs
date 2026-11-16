use crate::config::parse::{AuthMode, FwdAction, Globals};
use crate::engine::Metrics;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

pub struct FwdJob {
    pub bytes: bytes::Bytes,
}

pub fn spawn_worker(
    fa: FwdAction,
    g: Globals,
    _shutdown: watch::Receiver<bool>,
    metrics: Arc<Metrics>,
) -> mpsc::Sender<FwdJob> {
    let (tx, mut rx) = mpsc::channel::<FwdJob>(10000);
    tokio::spawn(async move {
        let _ = _shutdown;
        if fa.tcp {
            tcp_loop(fa, g, &mut rx, metrics).await;
        } else {
            udp_loop(fa, &mut rx, metrics).await;
        }
    });
    tx
}

async fn udp_loop(fa: FwdAction, rx: &mut mpsc::Receiver<FwdJob>, metrics: Arc<Metrics>) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };
    let addr = format!("{}:{}", fa.host, fa.port);
    while let Some(job) = rx.recv().await {
        if job.bytes.is_empty() {
            continue;
        }
        if sock.send_to(&job.bytes, &addr).await.is_err() {
            metrics.fwd_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Conn {
    async fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => AsyncWriteExt::write_all(s, b).await,
            Conn::Tls(s) => AsyncWriteExt::write_all(s, b).await,
        }
    }
}

fn frame_bytes(fa: &FwdAction, b: &[u8]) -> Vec<u8> {
    if fa.octet_counted {
        let mut v = Vec::with_capacity(b.len() + 8);
        v.extend_from_slice(b.len().to_string().as_bytes());
        v.push(b' ');
        v.extend_from_slice(b);
        v
    } else {
        let mut v = Vec::from(b);
        if v.last() != Some(&b'\n') {
            v.push(b'\n');
        }
        v
    }
}

async fn tcp_loop(
    fa: FwdAction,
    g: Globals,
    rx: &mut mpsc::Receiver<FwdJob>,
    metrics: Arc<Metrics>,
) {
    let mut backoff = std::time::Duration::from_millis(0);
    loop {
        match connect(&fa, &g, &metrics).await {
            Ok(mut conn) => {
                backoff = std::time::Duration::from_millis(0);
                loop {
                    let job = match rx.recv().await {
                        Some(j) => j,
                        None => return,
                    };
                    if job.bytes.is_empty() {
                        continue;
                    }
                    if conn.write_all(&frame_bytes(&fa, &job.bytes)).await.is_err() {
                        metrics.fwd_errors.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
            Err(()) => {
                metrics.fwd_errors.fetch_add(1, Ordering::Relaxed);
                match rx.recv().await {
                    Some(_) => {}
                    None => return,
                }
            }
        }
        backoff = if backoff.is_zero() {
            std::time::Duration::from_secs(1)
        } else {
            (backoff * 2).min(std::time::Duration::from_secs(30))
        };
        tokio::time::sleep(backoff).await;
    }
}

async fn connect(fa: &FwdAction, g: &Globals, metrics: &Arc<Metrics>) -> Result<Conn, ()> {
    let tcp = TcpStream::connect((fa.host.as_str(), fa.port))
        .await
        .map_err(|_| ())?;
    if fa.tls.is_none() {
        return Ok(Conn::Plain(tcp));
    }
    let tls = client_tls_config(fa, g, metrics).await?;
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(tls.roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let s = connector
        .connect(tls.server_name, tcp)
        .await
        .map_err(|_| ())?;
    // x509/name: chain already validated, check SAN against PermittedPeer.
    if tls.name_check {
        let der = s
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first().cloned())
            .ok_or(())?;
        if !peer_name_ok(&der, &tls.permitted) {
            metrics.tls_auth_fail.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
    }
    Ok(Conn::Tls(Box::new(s)))
}

struct ClientTls {
    roots: rustls::RootCertStore,
    permitted: Vec<String>,
    name_check: bool,
    server_name: rustls::pki_types::ServerName<'static>,
}

async fn client_tls_config(
    fa: &FwdAction,
    g: &Globals,
    metrics: &Arc<Metrics>,
) -> Result<ClientTls, ()> {
    let tls = fa.tls.as_ref().unwrap();
    let ca_path = tls.ca.clone().or_else(|| g.tls_ca.clone()).ok_or(())?;
    let cert_data = tokio::fs::read(&ca_path).await.map_err(|_| ())?;
    let mut roots = rustls::RootCertStore::empty();
    // PEM (>=1 cert) or single DER.
    let mut cur = std::io::Cursor::new(&cert_data[..]);
    let pem: Vec<_> = rustls_pemfile::certs(&mut cur)
        .filter_map(Result::ok)
        .collect();
    if pem.is_empty() {
        let der = rustls::pki_types::CertificateDer::from(cert_data);
        if roots.add(der).is_err() {
            metrics.tls_auth_fail.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
    } else {
        for c in pem {
            let _ = roots.add(c);
        }
    }
    if roots.is_empty() {
        metrics.tls_auth_fail.fetch_add(1, Ordering::Relaxed);
        return Err(());
    }
    let server_name = rustls::pki_types::ServerName::try_from(fa.host.clone()).map_err(|_| ())?;
    Ok(ClientTls {
        roots,
        permitted: tls.permitted_peer.clone(),
        name_check: matches!(tls.auth_mode, AuthMode::X509Name),
        server_name,
    })
}

pub fn peer_name_ok_pub(der: &[u8], permitted: &[String]) -> bool {
    peer_name_ok(der, permitted)
}

/// Extract dNSName SAN entries from a DER certificate.
pub fn end_entity_dns_names_pub(der: &[u8]) -> Vec<String> {
    end_entity_dns_names(der)
}

fn peer_name_ok(der: &[u8], permitted: &[String]) -> bool {
    let names = end_entity_dns_names(der);
    names
        .iter()
        .any(|n| permitted.iter().any(|p| name_matches(n, p)))
}

/// Extract dNSName SAN entries from a DER certificate.
fn end_entity_dns_names(der: &[u8]) -> Vec<String> {
    use x509_parser::prelude::*;
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return Vec::new();
    };
    match cert.subject_alternative_name() {
        Ok(Some(san)) => san
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(s) => Some(s.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn name_matches(cert_name: &str, pattern: &str) -> bool {
    if pattern.eq_ignore_ascii_case(cert_name) {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        if let Some((left, right)) = cert_name.split_once('.') {
            return !left.is_empty() && right.eq_ignore_ascii_case(rest);
        }
    }
    false
}
