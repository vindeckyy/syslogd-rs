use crate::msg::Msg;
use bytes::Bytes;
use std::sync::Mutex;
use tokio::sync::mpsc;

static INTERNAL: Mutex<Option<mpsc::Sender<Msg>>> = Mutex::new(None);

pub fn init_internal(sender: mpsc::Sender<Msg>) {
    *INTERNAL.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
}

pub fn hostname() -> String {
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        h.trim().to_string()
    } else {
        "localhost".into()
    }
}

/// Internal syslogd log line: `syslogd-rs[pid]: msg` to stderr, plus
/// injection into the ruleset as a facility 3 (syslog) message when the
/// engine is running. Pre-engine calls write stderr only.
pub fn internal_log(sev: u8, msg: &str) {
    eprintln!("syslogd-rs[{}]: {}", std::process::id(), msg);
    let tx = INTERNAL.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(tx) = &tx {
        let pri = (3u8 << 3) | (sev.min(7));
        let m = Msg {
            pri,
            facility: 3,
            severity: sev.min(7),
            timestamp: Some(time::OffsetDateTime::now_utc()),
            hostname: Some(hostname()),
            tag: "syslogd-rs: ".into(),
            programname: Some("syslogd-rs".into()),
            app_name: Some("syslogd-rs".into()),
            procid: Some(std::process::id().to_string()),
            msgid: None,
            sd_raw: None,
            msg: Bytes::copy_from_slice(msg.as_bytes()),
            raw: Bytes::new(),
            fromhost_ip: None,
            input_name: "internal",
            sd_invalid: false,
        };
        let _ = tx.try_send(m);
    }
}
