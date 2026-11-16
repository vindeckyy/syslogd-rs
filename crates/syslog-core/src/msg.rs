use bytes::Bytes;
use std::net::IpAddr;
use time::OffsetDateTime;

/// Parsed syslog message. Property names follow rsyslog conventions.
#[derive(Debug, Clone)]
pub struct Msg {
    pub pri: u8,
    pub facility: u8,
    pub severity: u8,
    /// Timereported: timestamp from the message header, if valid.
    pub timestamp: Option<OffsetDateTime>,
    pub hostname: Option<String>,
    /// syslogtag incl. trailing space, e.g. "prog[pid]: ". Empty when no tag.
    pub tag: String,
    pub programname: Option<String>,
    pub app_name: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    /// RFC5424 structured-data raw bytes (without surrounding spaces).
    pub sd_raw: Option<Bytes>,
    /// MSG part only.
    pub msg: Bytes,
    /// Full received bytes (for byte-identical relay, T5).
    pub raw: Bytes,
    /// Peer IP when from network.
    pub fromhost_ip: Option<IpAddr>,
    /// e.g. "imudp", "imuxsock", "imklog", "internal".
    pub input_name: &'static str,
    /// Set when RFC5424 structured data was malformed but MSG was salvaged.
    pub sd_invalid: bool,
}

impl Msg {
    pub fn new(pri: u8, msg: Bytes, raw: Bytes, input_name: &'static str) -> Self {
        Self {
            pri,
            facility: pri >> 3,
            severity: pri & 7,
            timestamp: None,
            hostname: None,
            tag: String::new(),
            programname: None,
            app_name: None,
            procid: None,
            msgid: None,
            sd_raw: None,
            msg,
            raw,
            fromhost_ip: None,
            input_name,
            sd_invalid: false,
        }
    }
}

/// RFC5424 facility names, index = facility number. Slots that are
/// unassigned per RFC5424 get numeric strings like rsyslog does.
pub fn facility_name(f: u8) -> &'static str {
    const NAMES: [&str; 24] = [
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
        "authpriv", "ftp", "12", "13", "audit", "alert", "local0", "local1", "local2", "local3",
        "local4", "local5", "local6", "local7",
    ];
    NAMES.get(f as usize).copied().unwrap_or("invld")
}

pub fn severity_name(s: u8) -> &'static str {
    const NAMES: [&str; 8] = [
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
    ];
    NAMES.get(s as usize).copied().unwrap_or("invld")
}

/// Name -> facility number. rsyslog selector names; `security` aliases auth.
pub fn facility_by_name(name: &str) -> Option<u8> {
    Some(match name.to_ascii_lowercase().as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" | "security" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => return None,
    })
}

pub fn severity_by_name(name: &str) -> Option<u8> {
    Some(match name.to_ascii_lowercase().as_str() {
        "emerg" | "panic" => 0,
        "alert" => 1,
        "crit" => 2,
        "err" | "error" => 3,
        "warning" | "warn" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => return None,
    })
}
