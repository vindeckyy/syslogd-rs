use crate::config::parse::{Action, Config, Globals, Rule};
use crate::msg::Msg;
use crate::template::Template;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::{OffsetDateTime, UtcOffset};
use tokio::sync::{mpsc, watch};

pub struct Metrics {
    pub msgs_in: AtomicU64,
    pub dup_suppressed: AtomicU64,
    pub action_dropped: AtomicU64,
    pub file_errors: AtomicU64,
    pub fwd_errors: AtomicU64,
    pub oversize: AtomicU64,
    pub tls_auth_fail: AtomicU64,
    pub parse_errors: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            msgs_in: AtomicU64::new(0),
            dup_suppressed: AtomicU64::new(0),
            action_dropped: AtomicU64::new(0),
            file_errors: AtomicU64::new(0),
            fwd_errors: AtomicU64::new(0),
            oversize: AtomicU64::new(0),
            tls_auth_fail: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
        }
    }
    pub fn dump(&self) {
        let msg = format!(
            "metrics: msgs_in={} dup_suppressed={} action_dropped={} file_errors={} fwd_errors={} oversize={} tls_auth_fail={} parse_errors={}",
            self.msgs_in.load(Ordering::Relaxed),
            self.dup_suppressed.load(Ordering::Relaxed),
            self.action_dropped.load(Ordering::Relaxed),
            self.file_errors.load(Ordering::Relaxed),
            self.fwd_errors.load(Ordering::Relaxed),
            self.oversize.load(Ordering::Relaxed),
            self.tls_auth_fail.load(Ordering::Relaxed),
            self.parse_errors.load(Ordering::Relaxed),
        );
        crate::log::internal_log(5, &msg);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
enum ActionHandle {
    File(mpsc::Sender<crate::action_file::FileJob>),
    Fwd(mpsc::Sender<crate::action_fwd::FwdJob>),
    Usrmsg(mpsc::Sender<String>),
    Stdout(mpsc::Sender<String>),
    Discard,
}

#[derive(PartialEq, Eq, Hash, Clone)]
enum ActionKey {
    FileStatic(String),
    FileDyn(String),
    Fwd(String),
    Single(&'static str),
}

/// One compiled action slot in a rule: worker index + render parameters.
#[derive(Clone)]
struct Slot {
    worker: usize,
    template: Option<String>,
    is_dyn: bool,
    dyn_template: Option<String>,
    static_path: Option<std::path::PathBuf>,
    sync: bool,
    flush_interval: Option<u64>,
}

fn slot_for(
    a: &Action,
    map: &mut HashMap<ActionKey, usize>,
    workers: &mut Vec<ActionHandle>,
    shutdown: &watch::Sender<bool>,
    metrics: &Arc<Metrics>,
    g: &Globals,
) -> Option<Slot> {
    match a {
        Action::File(fa) => {
            let key = match &fa.dyn_template {
                Some(dt) => ActionKey::FileDyn(dt.clone()),
                None => {
                    ActionKey::FileStatic(fa.path.as_ref().unwrap().to_string_lossy().into_owned())
                }
            };
            let idx = if let Some(&i) = map.get(&key) {
                i
            } else {
                let i = workers.len();
                workers.push(ActionHandle::File(crate::action_file::spawn_worker(
                    g.clone(),
                    shutdown.subscribe(),
                    metrics.clone(),
                )));
                map.insert(key, i);
                i
            };
            Some(Slot {
                worker: idx,
                template: fa.template.clone(),
                is_dyn: fa.dyn_template.is_some(),
                dyn_template: fa.dyn_template.clone(),
                static_path: fa.path.clone(),
                sync: g.action_file_enable_sync && !fa.no_sync,
                flush_interval: fa.flush_interval_secs,
            })
        }
        Action::Fwd(fa) => {
            let key = ActionKey::Fwd(format!("{}:{}:{}", fa.host, fa.port, fa.tcp));
            let idx = if let Some(&i) = map.get(&key) {
                i
            } else {
                let i = workers.len();
                workers.push(ActionHandle::Fwd(crate::action_fwd::spawn_worker(
                    fa.clone(),
                    g.clone(),
                    shutdown.subscribe(),
                    metrics.clone(),
                )));
                map.insert(key, i);
                i
            };
            Some(Slot {
                worker: idx,
                template: fa.template.clone(),
                is_dyn: false,
                dyn_template: None,
                static_path: None,
                sync: false,
                flush_interval: None,
            })
        }
        Action::Usrmsg { template, .. } => {
            let key = ActionKey::Single("usrmsg");
            let idx = if let Some(&i) = map.get(&key) {
                i
            } else {
                let i = workers.len();
                workers.push(ActionHandle::Usrmsg(crate::action_usrmsg::spawn_worker(
                    shutdown.subscribe(),
                    metrics.clone(),
                )));
                map.insert(key, i);
                i
            };
            Some(Slot {
                worker: idx,
                template: template.clone(),
                is_dyn: false,
                dyn_template: None,
                static_path: None,
                sync: false,
                flush_interval: None,
            })
        }
        Action::Stdout => {
            let key = ActionKey::Single("stdout");
            let idx = if let Some(&i) = map.get(&key) {
                i
            } else {
                let i = workers.len();
                workers.push(ActionHandle::Stdout(crate::action_stdout::spawn_worker(
                    shutdown.subscribe(),
                )));
                map.insert(key, i);
                i
            };
            Some(Slot {
                worker: idx,
                template: None,
                is_dyn: false,
                dyn_template: None,
                static_path: None,
                sync: false,
                flush_interval: None,
            })
        }
        Action::Discard => None,
    }
}

struct DupState {
    last_key: Option<Vec<u8>>,
    last_msg: Option<Msg>,
    count: u64,
    expires: std::time::Instant,
}

pub struct Engine {
    rules: Vec<Rule>,
    slots: Vec<Vec<Option<Slot>>>,
    templates: HashMap<String, Template>,
    workers: Vec<ActionHandle>,
    globals: Globals,
    local_tz: UtcOffset,
    dup: Mutex<DupState>,
    shutdown: watch::Sender<bool>,
    pub metrics: Arc<Metrics>,
}

impl Engine {
    pub fn build(cfg: Config) -> Arc<Self> {
        let (shutdown, _rx) = watch::channel(false);
        let metrics = Arc::new(Metrics::new());
        let local_tz = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
        let g = cfg.globals.clone();
        let mut workers: Vec<ActionHandle> = Vec::new();
        let mut map: HashMap<ActionKey, usize> = HashMap::new();
        let mut slots: Vec<Vec<Option<Slot>>> = Vec::new();
        for rule in &cfg.rules {
            let mut rs: Vec<Option<Slot>> = Vec::new();
            for a in &rule.actions {
                rs.push(slot_for(a, &mut map, &mut workers, &shutdown, &metrics, &g));
            }
            slots.push(rs);
        }
        let eng = Arc::new(Engine {
            rules: cfg.rules,
            slots,
            templates: cfg.templates,
            workers,
            globals: g,
            local_tz,
            dup: Mutex::new(DupState {
                last_key: None,
                last_msg: None,
                count: 0,
                expires: std::time::Instant::now(),
            }),
            shutdown,
            metrics,
        });
        // internal logger runner: consumes synthetic messages from the
        // global internal sender and dispatches them through the rules.
        let (tx, mut rx) = mpsc::channel::<Msg>(5000);
        crate::log::init_internal(tx);
        let eng_arc = Arc::clone(&eng);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                eng_arc.metrics.dump();
                eng_arc.dup_flush();
            }
        });
        let eng2 = eng.clone();
        tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                eng2.dispatch(&m);
            }
        });
        eng
    }
    pub fn local_tz(&self) -> UtcOffset {
        self.local_tz
    }

    pub fn max_message_size(&self) -> usize {
        self.globals.max_message_size
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn handle(&self, m: Msg) {
        self.metrics.msgs_in.fetch_add(1, Ordering::Relaxed);
        if self.globals.repeated_msg_reduction && m.input_name != "internal" {
            self.suppress_dup(&m);
        } else {
            self.dispatch(&m);
        }
    }

    fn suppress_dup(&self, m: &Msg) {
        let mut dup = self.dup.lock().unwrap_or_else(|e| e.into_inner());
        let key = m.raw.to_vec();
        let now = std::time::Instant::now();
        if dup.last_key.as_deref() == Some(key.as_slice()) && now < dup.expires {
            dup.count += 1;
            self.metrics.dup_suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if dup.count > 0 {
            if let Some(orig) = dup.last_msg.take() {
                let n = dup.count;
                let mut notice = orig.clone();
                let text = if n == 1 {
                    format!("last message repeated {} time", n)
                } else {
                    format!("last message repeated {} times", n)
                };
                notice.msg = bytes::Bytes::from(text);
                dup.count = 0;
                drop(dup);
                self.dispatch(&notice);
                return;
            }
        }
        dup.last_key = Some(key);
        dup.last_msg = Some(m.clone());
        dup.count = 0;
        dup.expires = now + std::time::Duration::from_secs(60);
        drop(dup);
        self.dispatch(m);
    }

    /// Emit the "last message repeated N times" notice if a run expired.
    fn dup_flush(&self) {
        let mut dup = self.dup.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if dup.count > 0 && now >= dup.expires {
            if let Some(orig) = dup.last_msg.take() {
                let n = std::mem::replace(&mut dup.count, 0);
                let text = if n == 1 {
                    format!("last message repeated {} time", n)
                } else {
                    format!("last message repeated {} times", n)
                };
                let mut notice = orig.clone();
                notice.msg = bytes::Bytes::from(text);
                notice.input_name = "internal";
                drop(dup);
                self.dispatch(&notice);
            }
        }
    }

    fn dispatch(&self, m: &Msg) {
        let tg = OffsetDateTime::now_utc().to_offset(self.local_tz);
        for (ri, rule) in self.rules.iter().enumerate() {
            if !rule.matcher.matches(m.facility, m.severity) {
                continue;
            }
            for slot in &self.slots[ri] {
                let Some(s) = slot else { continue };
                let Some(w) = self.workers.get(s.worker) else {
                    continue;
                };
                match w {
                    ActionHandle::File(tx) => {
                        let target: std::path::PathBuf;
                        
                        let content: bytes::Bytes = if s.is_dyn {
                            let dt = s.dyn_template.as_ref().unwrap();
                            let t = match self.templates.get(dt) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            target = std::path::PathBuf::from(t.render_string(m, &tg));
                            let name = s
                                .template
                                .clone()
                                .unwrap_or_else(|| "RSYSLOG_FileFormat".into());
                            let ct = self.templates.get(&name).cloned().unwrap_or(t);
                            ct.render(m, &tg).into()
                        } else {
                            target = s.static_path.clone().unwrap_or_default();
                            let name = s
                                .template
                                .clone()
                                .unwrap_or_else(|| "RSYSLOG_FileFormat".into());
                            let t = match self.templates.get(&name) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            t.render(m, &tg).into()
                        };
                        if target.as_os_str().is_empty() {
                            continue;
                        }
                        let job = crate::action_file::FileJob {
                            path: target,
                            bytes: content,
                            sync: s.sync,
                            flush_interval: s.flush_interval,
                        };
                        if tx.try_send(job).is_err() {
                            self.metrics.action_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    ActionHandle::Fwd(tx) => {
                        let name = s
                            .template
                            .clone()
                            .unwrap_or_else(|| "RSYSLOG_ForwardFormat".into());
                        let t = match self.templates.get(&name) {
                            Some(t) => t.clone(),
                            None => continue,
                        };
                        let bytes = bytes::Bytes::copy_from_slice(&t.render(m, &tg));
                        if tx.try_send(crate::action_fwd::FwdJob { bytes }).is_err() {
                            self.metrics.action_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    ActionHandle::Usrmsg(tx) => {
                        let name = s
                            .template
                            .clone()
                            .unwrap_or_else(|| "RSYSLOG_WallFmt".into());
                        if let Some(t) = self.templates.get(&name) {
                            let _ = tx.try_send(t.render_string(m, &tg));
                        }
                    }
                    ActionHandle::Stdout(tx) => {
                        if let Some(t) = self.templates.get("RSYSLOG_FileFormat") {
                            let _ = tx.try_send(t.render_string(m, &tg));
                        }
                    }
                    ActionHandle::Discard => {}
                }
            }
            if rule.stop {
                break;
            }
        }
    }
}
