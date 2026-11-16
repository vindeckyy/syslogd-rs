use crate::template::{builtins, compile, Template};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Strict,
    Compat,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read {path}")]
    Io { path: String },
    #[error("{file}:{line}:{col}: {msg}")]
    Parse {
        file: String,
        line: usize,
        col: usize,
        msg: String,
    },
    #[error("{file}:{line}: unsupported construct '{construct}'")]
    Unsupported {
        file: String,
        line: usize,
        construct: String,
    },
}

impl ConfigError {
    fn parse(file: &str, line: usize, msg: &str) -> Self {
        ConfigError::Parse {
            file: file.into(),
            line,
            col: 1,
            msg: msg.into(),
        }
    }
    fn unsup(file: &str, line: usize, construct: &str) -> Self {
        ConfigError::Unsupported {
            file: file.into(),
            line,
            construct: construct.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub globals: Globals,
    pub modules: ModulesUsed,
    pub inputs: Vec<InputSpec>,
    pub rules: Vec<Rule>,
    pub templates: HashMap<String, Template>,
    pub template_seq: usize,
    pub template_def_order: std::collections::HashMap<String, (String, usize, usize)>,
    pub template_uses: Vec<(String, String, usize, usize)>,
    pub merged: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Globals {
    pub action_file_default_template: Option<String>,
    pub action_forward_default_template: Option<String>,
    pub action_file_enable_sync: bool,
    pub repeated_msg_reduction: bool,
    pub file_owner: Option<String>,
    pub file_group: Option<String>,
    pub file_create_mode: u32,
    pub dir_create_mode: u32,
    pub dir_owner: Option<String>,
    pub dir_group: Option<String>,
    pub umask: Option<u32>,
    pub priv_drop_user: Option<String>,
    pub priv_drop_group: Option<String>,
    pub work_directory: Option<PathBuf>,
    pub max_message_size: usize,
    pub escape_control_on_receive: bool,
    pub control_char_escape_prefix: u8,
    pub drop_trailing_lf_on_reception: bool,
    pub space_lf_on_receive: bool,
    pub tls_ca: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_driver: Option<String>,
}

impl Default for Globals {
    fn default() -> Self {
        Globals {
            action_file_default_template: None,
            action_forward_default_template: None,
            action_file_enable_sync: false,
            repeated_msg_reduction: false,
            file_owner: None,
            file_group: None,
            file_create_mode: 0o644,
            dir_create_mode: 0o755,
            dir_owner: None,
            dir_group: None,
            umask: None,
            priv_drop_user: None,
            priv_drop_group: None,
            work_directory: None,
            max_message_size: 65536,
            escape_control_on_receive: true,
            control_char_escape_prefix: b'\\',
            drop_trailing_lf_on_reception: false,
            space_lf_on_receive: false,
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            tls_driver: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModulesUsed {
    pub imuxsock: bool,
    pub imklog: bool,
    pub imudp: bool,
    pub imtcp: bool,
    pub imuxsock_ignore_own: bool,
    pub imuxsock_rate_interval: Option<u32>,
    pub imuxsock_rate_burst: Option<u32>,
    pub imklog_permit_non_kernel: bool,
    pub udp_servers: Vec<u16>,
    pub tcp_servers: Vec<u16>,
}

#[derive(Debug, Clone)]
pub enum InputSpec {
    Udp {
        addr: String,
        port: u16,
    },
    Tcp {
        addr: String,
        port: u16,
        tls: Option<TlsSpec>,
    },
}

#[derive(Debug, Clone)]
pub struct TlsSpec {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub ca: Option<PathBuf>,
    pub auth_mode: AuthMode,
    pub permitted_peer: Vec<String>,
    pub driver_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMode {
    X509Name,
    CertValid,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub matcher: Matcher,
    pub actions: Vec<Action>,
    pub stop: bool,
}

#[derive(Debug, Clone)]
pub enum Matcher {
    All,
    Sel(Vec<SelItem>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cmp {
    Le(u8),
    Eq(u8),
    NotLe(u8),
    NotEq(u8),
}

#[derive(Debug, Clone)]
pub struct SelItem {
    pub fac_mask: u32,
    pub cmp: Cmp,
}

impl Matcher {
    /// Does this matcher select (fac, sev)? None-severity never selected.
    pub fn matches(&self, fac: u8, sev: u8) -> bool {
        match self {
            Matcher::All => true,
            Matcher::Sel(items) => items.iter().any(|it| {
                (it.fac_mask >> fac) & 1 == 1
                    && match it.cmp {
                        Cmp::Le(n) => sev <= n,
                        Cmp::Eq(n) => sev == n,
                        Cmp::NotLe(n) => sev > n,
                        Cmp::NotEq(n) => sev != n,
                    }
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    File(FileAction),
    Fwd(FwdAction),
    Usrmsg {
        users: String,
        template: Option<String>,
    },
    Stdout,
    Discard,
}

#[derive(Debug, Clone)]
pub struct FileAction {
    pub path: Option<PathBuf>,
    pub dyn_template: Option<String>,
    pub template: Option<String>,
    pub no_sync: bool,
    pub flush_interval_secs: Option<u64>,
    pub create_dirs: bool,
}

#[derive(Debug, Clone)]
pub struct FwdAction {
    pub host: String,
    pub port: u16,
    pub tcp: bool,
    pub template: Option<String>,
    pub tls: Option<TlsSpec>,
    pub octet_counted: bool,
}

struct Diag {
    mode: Mode,
    warns: Vec<String>,
}

impl Diag {
    fn unsup(&self, file: &str, line: usize, construct: &str) -> Result<(), ConfigError> {
        match self.mode {
            Mode::Strict => Err(ConfigError::unsup(file, line, construct)),
            Mode::Compat => Ok(()),
        }
    }
    fn parse_err(&self, file: &str, line: usize, msg: &str) -> ConfigError {
        ConfigError::parse(file, line, msg)
    }
}

/// Parse a config file. `path` must exist.
pub fn parse(path: &Path, mode: Mode) -> Result<(Config, Vec<String>), ConfigError> {
    let mut lines: Vec<(String, usize, String)> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    expand(path, mode, &mut lines, &mut seen)?;
    let mut d = Diag {
        mode,
        warns: Vec::new(),
    };
    let cfg = parse_lines(&lines, &mut d)?;
    Ok((cfg, d.warns))
}

fn expand(
    path: &Path,
    _mode: Mode,
    out: &mut Vec<(String, usize, String)>,
    seen: &mut HashSet<PathBuf>,
) -> Result<(), ConfigError> {
    let canon = path
        .canonicalize()
        .map(|p| p)
        .unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(canon.clone()) {
        return Err(ConfigError::parse(
            &canon.to_string_lossy(),
            0,
            "include cycle",
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|_| ConfigError::Io {
        path: canon.to_string_lossy().into_owned(),
    })?;
    // join continuations, then strip comments per-line (quote-aware)
    let mut logical = Vec::new();
    let mut buf = String::new();
    for line in text.lines() {
        let t = line.trim_end();
        if t.ends_with('\\') && !t.ends_with("\\\\") {
            buf.push_str(&t[..t.len() - 1]);
            buf.push(' ');
            continue;
        }
        buf.push_str(t);
        logical.push(buf.clone());
        buf.clear();
    }
    if !buf.is_empty() {
        logical.push(buf);
    }
    for (idx, raw) in logical.iter().enumerate() {
        let file = canon.to_string_lossy().into_owned();
        let lineno = idx + 1;
        let code = strip_comment(raw);
        let code = code.trim().to_string();
        if code.is_empty() {
            continue;
        }
        // include directives?
        if let Some(glob) = include_glob(&code) {
            for p in glob_expand(&glob) {
                expand(&p, _mode, out, seen)?;
            }
            continue;
        }
        out.push((file, lineno, code));
    }
    Ok(())
}

/// Strip `#` comment outside double quotes. `//` comments only count
/// on RainerScript lines (start with letters/indent then //): rsyslog
/// treats `#` as comment everywhere; handle both: strip `//` too when
/// it appears outside quotes and line looks RainerScript.
fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_q = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            in_q = !in_q;
            out.push(c);
            continue;
        }
        if !in_q {
            if c == '#' {
                break;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                // RainerScript comment
                break;
            }
        }
        out.push(c);
    }
    out
}

fn include_glob(line: &str) -> Option<String> {
    let t = line.trim();
    if t.starts_with("$IncludeConfig") {
        let v = t["$IncludeConfig".len()..].trim();
        if v.is_empty() {
            return None;
        }
        return Some(v.to_string());
    }
    if t.starts_with("include(") && t.ends_with(')') {
        let params = parse_params(&t["include(".len()..t.len() - 1]);
        for (k, v) in params {
            if k == "file" || k == "config" {
                return Some(v);
            }
        }
    }
    None
}

fn glob_expand(g: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = glob::glob(g)
        .ok()
        .map(|paths| paths.filter_map(Result::ok).collect())
        .unwrap_or_default();
    v.sort();
    v.into_iter()
        .filter(|p| {
            // skip dotfiles, directories
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            !n.starts_with('.') && p.is_file()
        })
        .collect()
}

fn parse_lines(lines: &[(String, usize, String)], d: &mut Diag) -> Result<Config, ConfigError> {
    let mut cfg = Config {
        globals: Globals::default(),
        modules: ModulesUsed::default(),
        inputs: Vec::new(),
        rules: Vec::new(),
        templates: builtins(),
        template_seq: 0,
        template_def_order: std::collections::HashMap::new(),
        template_uses: Vec::new(),
        merged: Vec::new(),
    };
    // merged dump: origin headers
    let mut last_file = String::new();
    for (f, l, t) in lines {
        if *f != last_file {
            cfg.merged.push(format!("# file: {}", f));
            last_file = f.clone();
        }
        cfg.merged.push(format!("{}: {}", l, t));
    }

    for (file, lineno, text) in lines {
        cfg.template_seq += 1;
        let line = text.trim_end();
        if line.is_empty() {
            continue;
        }
        // RainerScript object statements
        if (line.starts_with("module(") || line.starts_with("input("))
            || line.starts_with("action(")
            || line.starts_with("template(")
        {
            parse_object_statement(line, file, *lineno, &mut cfg, d)?;
            continue;
        }
        if line.starts_with("$") {
            parse_dollar(line, file, *lineno, &mut cfg, d)?;
            continue;
        }
        if line.starts_with('!') || line.starts_with('+') || line.starts_with('-') {
            // BSD-style blocks; '-' as program-block modifier. But legacy
            // file actions use '-' prefix AFTER selectors, not line-start.
            // Line-start -,+,! is BSD block syntax.
            d.unsup(file, *lineno, "BSD property block")?;
            continue;
        }
        if line == "stop" {
            if let Some(last) = cfg.rules.last_mut() {
                last.stop = true;
            }
            continue;
        }
        // legacy selector line or & continuation
        parse_legacy_rule(line, file, *lineno, &mut cfg, d)?;
    }
    finalize(&mut cfg, d)?;
    Ok(cfg)
}

fn parse_object_statement(
    line: &str,
    file: &str,
    lineno: usize,
    cfg: &mut Config,
    d: &mut Diag,
) -> Result<(), ConfigError> {
    let open = line
        .find('(')
        .ok_or_else(|| d.parse_err(file, lineno, "malformed object"))?;
    let name = &line[..open];
    if !line.ends_with(')') {
        return Err(d.parse_err(file, lineno, "unbalanced parentheses"));
    }
    let params = parse_params(&line[open + 1..line.len() - 1]);
    let get = |k: &str| {
        params
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    match name {
        "module" => {
            let load =
                get("load").ok_or_else(|| d.parse_err(file, lineno, "module() without load"))?;
            match load.to_ascii_lowercase().as_str() {
                "imuxsock" => {
                    cfg.modules.imuxsock = true;
                    if let Some(v) = get("syssock.ignoreownmessages") {
                        cfg.modules.imuxsock_ignore_own = v == "on";
                    }
                    if let Some(v) = get("syssock.ratelimit.interval") {
                        cfg.modules.imuxsock_rate_interval = v.parse().ok();
                    }
                    if let Some(v) = get("syssock.ratelimit.burst") {
                        cfg.modules.imuxsock_rate_burst = v.parse().ok();
                    }
                }
                "imklog" => {
                    cfg.modules.imklog = true;
                    if let Some(v) = get("permitnonkernelfacility") {
                        cfg.modules.imklog_permit_non_kernel = v == "on";
                    }
                }
                "imudp" => cfg.modules.imudp = true,
                "imtcp" => cfg.modules.imtcp = true,
                "imptcp" => {
                    d.unsup(file, lineno, "imptcp")?;
                    cfg.modules.imtcp = true;
                }
                other => {
                    d.unsup(file, lineno, &format!("module {other}"))?;
                }
            }
            Ok(())
        }
        "input" => {
            let ty = get("type").unwrap_or_default();
            match ty.to_ascii_lowercase().as_str() {
                "imudp" => {
                    let port = get("port").and_then(|v| v.parse().ok()).unwrap_or(514);
                    let addr = get("address").unwrap_or_else(|| "0.0.0.0".into());
                    cfg.inputs.push(InputSpec::Udp { addr, port });
                }
                "imtcp" => {
                    let port = get("port").and_then(|v| v.parse().ok()).unwrap_or(514);
                    let addr = get("address").unwrap_or_else(|| "0.0.0.0".into());
                    let tls = tls_from_params(&params, file, lineno, d)?;
                    cfg.inputs.push(InputSpec::Tcp { addr, port, tls });
                }
                other => {
                    d.unsup(file, lineno, &format!("input type {other}"))?;
                }
            }
            Ok(())
        }
        "template" => {
            let n =
                get("name").ok_or_else(|| d.parse_err(file, lineno, "template() without name"))?;
            let s = get("string")
                .ok_or_else(|| d.parse_err(file, lineno, "template() without string"))?;
            match compile(&n, &s) {
                Ok(t) => {
                    cfg.templates.insert(n.clone(), t);
                    cfg.template_def_order
                        .insert(n, (file.to_string(), lineno, cfg.template_seq));
                    Ok(())
                }
                Err(e) => Err(d.parse_err(file, lineno, &format!("template {n}: {e}"))),
            }
        }
        "action" => {
            let a = action_from_object(&params, file, lineno, &cfg.globals, &cfg.templates, d)?;
            if let Some(tn) = action_template_name(&a) {
                let tn = tn.to_string();
                cfg.template_uses
                    .push((tn, file.to_string(), lineno, cfg.template_seq));
            }
            push_rule(cfg, Matcher::All, vec![a]);
            Ok(())
        }
        _ => {
            d.unsup(file, lineno, &format!("{name}()"))?;
            Ok(())
        }
    }
}

fn tls_from_params(
    params: &[(String, String)],
    file: &str,
    lineno: usize,
    d: &mut Diag,
) -> Result<Option<TlsSpec>, ConfigError> {
    let get = |k: &str| {
        params
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    let mode1 = get("streamdriver.mode").map(|v| v == "1").unwrap_or(false);
    let tls_on = get("streamdriver").map(|v| v != "tcp").unwrap_or(false);
    if !mode1 && !tls_on {
        // streamdriver.name!=tcp but mode 0 = plain
        return Ok(None);
    }
    let driver_name = get("streamdriver.name");
    let auth = get("streamdriver.authmode").unwrap_or_else(|| "x509/name".into());
    validate_auth_mode(&auth, file, lineno, d)?;
    Ok(Some(TlsSpec {
        cert: get("streamdriver.certfile").map(PathBuf::from),
        key: get("streamdriver.keyfile").map(PathBuf::from),
        ca: get("streamdriver.cafile").map(PathBuf::from),
        auth_mode: if auth.eq_ignore_ascii_case("x509/certvalid") {
            AuthMode::CertValid
        } else {
            AuthMode::X509Name
        },
        permitted_peer: get("permittedpeer")
            .map(|v| v.split_whitespace().map(String::from).collect())
            .unwrap_or_default(),
        driver_name,
    }))
}

fn validate_auth_mode(
    auth: &str,
    file: &str,
    lineno: usize,
    d: &mut Diag,
) -> Result<(), ConfigError> {
    match auth.to_ascii_lowercase().as_str() {
        "x509/name" => Ok(()),
        "x509/certvalid" => Ok(()),
        "x509/fingerprint" | "anon" => d.unsup(file, lineno, &format!("authmode {auth}")),
        other => Err(d.parse_err(file, lineno, &format!("unknown authmode '{other}'"))),
    }
}

fn action_from_object(
    params: &[(String, String)],
    file: &str,
    lineno: usize,
    g: &Globals,
    _templates: &std::collections::HashMap<String, crate::template::Template>,
    d: &mut Diag,
) -> Result<Action, ConfigError> {
    let get = |k: &str| {
        params
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    let ty = get("type").ok_or_else(|| d.parse_err(file, lineno, "action() without type"))?;
    match ty.to_ascii_lowercase().as_str() {
        "omfile" => {
            if get("file").is_none() && get("dynaFile").is_none() {
                return Err(d.parse_err(file, lineno, "omfile without file"));
            }
            let dyn_t = get("dynaFile");
            let tmpl = get("template").or_else(|| g.action_file_default_template.clone());
            Ok(Action::File(FileAction {
                path: get("file").map(PathBuf::from),
                dyn_template: dyn_t,
                template: tmpl,
                no_sync: false,
                flush_interval_secs: get("flushinterval").and_then(|v| v.parse().ok()),
                create_dirs: get("createdirs").map(|v| v == "on").unwrap_or(true),
            }))
        }
        "omfwd" => {
            let host =
                get("target").ok_or_else(|| d.parse_err(file, lineno, "omfwd without target"))?;
            let port = get("port").and_then(|v| v.parse().ok()).unwrap_or(514);
            let proto = get("protocol").unwrap_or_else(|| "udp".into());
            check_queue_params(params, file, lineno, d)?;
            let framing = get("tcp.framing").unwrap_or_else(|| "traditional".into());
            Ok(Action::Fwd(FwdAction {
                host,
                port,
                tcp: proto.eq_ignore_ascii_case("tcp"),
                template: get("template").or_else(|| g.action_forward_default_template.clone()),
                tls: tls_from_params(params, file, lineno, d)?,
                octet_counted: framing.eq_ignore_ascii_case("octet-counted"),
            }))
        }
        "omusrmsg" => {
            let users =
                get("users").ok_or_else(|| d.parse_err(file, lineno, "omusrmsg without users"))?;
            if users != "*" {
                d.unsup(file, lineno, "omusrmsg users=<name>")?;
            }
            Ok(Action::Usrmsg {
                users,
                template: get("template"),
            })
        }
        "omstdout" => Ok(Action::Stdout),
        "omdiscard" => Ok(Action::Discard),
        other => {
            d.unsup(file, lineno, &format!("action type={other}"))?;
            Ok(Action::Discard)
        }
    }
}
/// Returns true for bytes that end an unquoted parameter value.
#[inline]
fn b_end(b: u8) -> bool {
    b.is_ascii_whitespace() || b == b','
}

fn input_key(i: &InputSpec) -> (u16, u8) {
    match i {
        InputSpec::Udp { port, .. } => (*port, 0),
        InputSpec::Tcp { port, .. } => (*port, 1),
    }
}

/// Parse RainerScript object parameters: `key="value" key2="v2" ...
/// Also tolerates unquoted values and spaces around `=`.
pub fn parse_params(inner: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = inner.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        // skip separators
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b',') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let ks = i;
        while i < b.len()
            && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_' || b[i] == b'-')
        {
            i += 1;
        }
        if i == ks {
            i += 1;
            continue;
        }
        let key = inner[ks..i].to_string();
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            i += 1;
            continue;
        }
        i += 1;
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let value = if i < b.len() && b[i] == b'"' {
            i += 1;
            let mut v = String::new();
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 1;
                    match b[i] {
                        b'n' => v.push('\n'),
                        b't' => v.push('\t'),
                        b'"' | b'\\' => v.push(b[i] as char),
                        c => {
                            v.push('\\');
                            v.push(c as char);
                        }
                    }
                } else {
                    v.push(b[i] as char);
                }
                i += 1;
            }
            i += 1; // closing quote
            v
        } else {
            let vs = i;
            while i < b.len() && !b_end(b[i]) {
                i += 1;
            }
            inner[vs..i].to_string()
        };
        out.push((key, value));
    }
    out
}

fn check_queue_params(
    params: &[(String, String)],
    file: &str,
    lineno: usize,
    d: &mut Diag,
) -> Result<(), ConfigError> {
    for (k, v) in params {
        let lk = k.to_ascii_lowercase();
        if lk == "queue.type" {
            match v.to_ascii_lowercase().as_str() {
                "direct" | "linkedlist" | "fixedarray" => {}
                _ => {
                    d.unsup(file, lineno, "queue.type=Disk")?;
                }
            }
        }
        if lk.starts_with("queue.filename")
            || lk.starts_with("queue.max")
            || lk.starts_with("queue.timeout")
            || lk.starts_with("queue.saveonshutdown")
            || lk.starts_with("queue.hiwatermark")
            || lk.starts_with("queue.lowatermark")
            || lk.starts_with("actionresumeretrycount")
        {
            if lk.starts_with("queue.filename") {
                d.unsup(file, lineno, "disk queue params")?;
            }
        }
    }
    Ok(())
}

fn parse_dollar(
    line: &str,
    file: &str,
    lineno: usize,
    cfg: &mut Config,
    d: &mut Diag,
) -> Result<(), ConfigError> {
    let rest = &line[1..];
    let (name, arg) = match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], rest[i..].trim().to_string()),
        None => (rest, String::new()),
    };
    let n = name.to_ascii_lowercase();
    let g = &mut cfg.globals;
    match n.as_str() {
        "modload" => {
            match arg.to_ascii_lowercase().as_str() {
                "imuxsock" => cfg.modules.imuxsock = true,
                "imklog" => cfg.modules.imklog = true,
                "imudp" => cfg.modules.imudp = true,
                "imtcp" => cfg.modules.imtcp = true,
                "imptcp" => {
                    d.unsup(file, lineno, "$ModLoad imptcp")?;
                    cfg.modules.imtcp = true;
                }
                other => {
                    d.unsup(file, lineno, &format!("$ModLoad {other}"))?;
                }
            }
            Ok(())
        }
        "udpserverrun" => {
            let p: u16 = arg
                .parse()
                .map_err(|_| d.parse_err(file, lineno, "bad port"))?;
            cfg.modules.udp_servers.push(p);
            Ok(())
        }
        "inputtcpserverrun" => {
            let p: u16 = arg
                .parse()
                .map_err(|_| d.parse_err(file, lineno, "bad port"))?;
            cfg.modules.tcp_servers.push(p);
            Ok(())
        }
        "actionfiledefaulttemplate" => {
            g.action_file_default_template = Some(arg);
            Ok(())
        }
        "actionforwarddefaulttemplate" => {
            g.action_forward_default_template = Some(arg);
            Ok(())
        }
        "actionfileenablesync" => {
            g.action_file_enable_sync = arg == "on";
            Ok(())
        }
        "repeatedmsgreduction" => {
            g.repeated_msg_reduction = arg == "on";
            Ok(())
        }
        "fileowner" => {
            g.file_owner = Some(arg);
            Ok(())
        }
        "filegroup" => {
            g.file_group = Some(arg);
            Ok(())
        }
        "filecreatemode" => {
            g.file_create_mode = parse_octal(&arg).unwrap_or(0o644);
            Ok(())
        }
        "dircreatemode" => {
            g.dir_create_mode = parse_octal(&arg).unwrap_or(0o755);
            Ok(())
        }
        "dirowner" => {
            g.dir_owner = Some(arg);
            Ok(())
        }
        "dirgroup" => {
            g.dir_group = Some(arg);
            Ok(())
        }
        "umask" => {
            g.umask = parse_octal(&arg);
            Ok(())
        }
        "privdroptouser" => {
            g.priv_drop_user = Some(arg);
            Ok(())
        }
        "privdroptogroup" => {
            g.priv_drop_group = Some(arg);
            Ok(())
        }
        "workdirectory" => {
            g.work_directory = Some(PathBuf::from(arg));
            Ok(())
        }
        "maxmessagesize" => {
            g.max_message_size = parse_size(&arg).unwrap_or(65536);
            Ok(())
        }
        "escapecontrolcharactersonreceive" => {
            g.escape_control_on_receive = arg == "on";
            Ok(())
        }
        "controlcharacterescapeprefix" => {
            g.control_char_escape_prefix = arg.bytes().next().unwrap_or(b'\\');
            Ok(())
        }
        "droptrailinglfonreception" => {
            g.drop_trailing_lf_on_reception = arg == "on";
            Ok(())
        }
        "spacelfonreceive" => {
            g.space_lf_on_receive = arg == "on";
            Ok(())
        }
        "defaultnetstreamdriver" => {
            let v = arg.to_ascii_lowercase();
            if v == "gtls" || v == "ossl" {
                g.tls_driver = Some(arg);
            } else {
                d.unsup(file, lineno, &format!("$DefaultNetstreamDriver {arg}"))?;
            }
            Ok(())
        }
        "defaultnetstreamdrivercafile" => {
            g.tls_ca = Some(PathBuf::from(arg));
            Ok(())
        }
        "defaultnetstreamdrivercertfile" => {
            g.tls_cert = Some(PathBuf::from(arg));
            Ok(())
        }
        "defaultnetstreamdriverkeyfile" => {
            g.tls_key = Some(PathBuf::from(arg));
            Ok(())
        }
        "template" => {
            // $template name,"string"
            if let Some(c) = arg.find(',') {
                let tname = arg[..c].trim();
                let sarg = arg[c + 1..].trim();
                let sarg = sarg.trim_matches('"');
                match compile(tname, sarg) {
                    Ok(t) => {
                        cfg.templates.insert(tname.to_string(), t);
                        cfg.template_def_order.insert(
                            tname.to_string(),
                            (file.to_string(), lineno, cfg.template_seq),
                        );
                        return Ok(());
                    }
                    Err(e) => return Err(d.parse_err(file, lineno, &format!("$template: {e}"))),
                }
            }
            Err(d.parse_err(file, lineno, "malformed $template"))
        }
        other => d.unsup(file, lineno, &format!("${other}")),
    }
}

fn parse_octal(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim(), 8).ok()
}

fn parse_size(s: &str) -> Option<usize> {
    let t = s.trim();
    if let Some(k) = t.strip_suffix('k').or_else(|| t.strip_suffix('K')) {
        k.parse::<usize>().ok().map(|n| n * 1024)
    } else if let Some(m) = t.strip_suffix('m').or_else(|| t.strip_suffix('M')) {
        m.parse::<usize>().ok().map(|n| n * 1024 * 1024)
    } else {
        t.parse().ok()
    }
}

fn parse_legacy_rule(
    line: &str,
    file: &str,
    lineno: usize,
    cfg: &mut Config,
    d: &mut Diag,
) -> Result<(), ConfigError> {
    // & continuation
    if line.starts_with('&') {
        let rest = line[1..].trim();
        if rest == "stop" || rest.starts_with("stop") && rest.len() == 4 {
            if let Some(last) = cfg.rules.last_mut() {
                last.stop = true;
            }
            return Ok(());
        }
        if rest == "~" || rest == "discard" {
            if let Some(last) = cfg.rules.last_mut() {
                last.actions.push(Action::Discard);
            }
            return Ok(());
        }
        if rest == "stop" {
            if let Some(last) = cfg.rules.last_mut() {
                last.stop = true;
            }
            return Ok(());
        }
        // append action to previous rule
        let a = parse_legacy_action(rest, file, lineno, cfg, d)?;
        if let Some(tn) = action_template_name(&a) {
            let tn = tn.to_string();
            cfg.template_uses
                .push((tn, file.to_string(), lineno, cfg.template_seq));
        }
        if let Some(last) = cfg.rules.last_mut() {
            last.actions.push(a);
        } else {
            return Err(d.parse_err(file, lineno, "& without preceding selector"));
        }
        return Ok(());
    }
    // split selectors vs action at first whitespace
    let split = line
        .find(char::is_whitespace)
        .ok_or_else(|| d.parse_err(file, lineno, "selector without action"))?;
    let sel_str = &line[..split];
    let action_str = line[split..].trim();
    if action_str.is_empty() {
        return Err(d.parse_err(file, lineno, "empty action"));
    }
    // property filter line? selectors start with ':' (legacy prop filter)
    if sel_str.starts_with(':') {
        d.unsup(file, lineno, "property-filter rule")?;
        return Ok(());
    }
    let m = parse_selector(sel_str, file, lineno, d)?;
    if action_str == "stop" || action_str == "~" || action_str == "discard" {
        let acts = if action_str == "stop" {
            vec![]
        } else {
            vec![Action::Discard]
        };
        cfg.rules.push(Rule {
            matcher: m,
            actions: acts,
            stop: true,
        });
        return Ok(());
    }
    let a = parse_legacy_action(action_str, file, lineno, cfg, d)?;
    if let Some(tn) = action_template_name(&a) {
        let tn = tn.to_string();
        cfg.template_uses
            .push((tn, file.to_string(), lineno, cfg.template_seq));
    }
    push_rule(cfg, m, vec![a]);
    Ok(())
}

fn push_rule(cfg: &mut Config, m: Matcher, acts: Vec<Action>) {
    cfg.rules.push(Rule {
        matcher: m,
        actions: acts,
        stop: false,
    });
}

fn parse_selector(
    sel: &str,
    file: &str,
    lineno: usize,
    d: &mut Diag,
) -> Result<Matcher, ConfigError> {
    // Left-to-right overwrite per facility.
    let mut per_fac: std::collections::HashMap<u8, Cmp> = std::collections::HashMap::new();
    let mut all: Option<Cmp> = None;
    for part in sel.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let dot = part
            .find('.')
            .ok_or_else(|| d.parse_err(file, lineno, "bad selector"))?;
        let (facs, pri) = (&part[..dot], &part[dot + 1..]);
        let cmp = parse_pri(pri, file, lineno, d)?;
        if facs == "*" {
            all = Some(cmp);
        } else {
            for f in facs.split(',') {
                let f = f.trim();
                if f == "*" {
                    all = Some(cmp);
                    continue;
                }
                match crate::msg::facility_by_name(f) {
                    Some(fv) => {
                        per_fac.insert(fv, cmp);
                    }
                    None => {
                        // bare "*fac"? no; unknown facility
                        return Err(d.parse_err(file, lineno, &format!("unknown facility '{f}'")));
                    }
                }
            }
        }
    }
    let mut items = Vec::new();
    if let Some(c) = all {
        let mut mask = 0u32;
        for f in 0..24u8 {
            if per_fac.get(&f) != Some(&c) {
                // '*' filter only applies to facilities not explicitly set
                mask |= 1 << f;
            }
        }
        items.push(SelItem {
            fac_mask: mask,
            cmp: c,
        });
    }
    for (f, c) in per_fac {
        items.push(SelItem {
            fac_mask: 1 << f,
            cmp: c,
        });
    }
    if items.is_empty() {
        Ok(Matcher::Sel(vec![])) // selects nothing (e.g. "!-only" chain)
    } else {
        Ok(Matcher::Sel(items))
    }
}

fn parse_pri(p: &str, file: &str, lineno: usize, d: &mut Diag) -> Result<Cmp, ConfigError> {
    let t = p.trim().to_ascii_lowercase();
    if t == "*" || t == "none" {
        // '*' = all; 'none' = no priorities (only valid as facility suffix effect)
        return Ok(Cmp::Le(7));
    }
    let (op, v) = if let Some(v) = t.strip_prefix('!') {
        if let Some(v2) = v.strip_prefix('=') {
            (1, v2)
        } else {
            (2, v)
        }
    } else if let Some(v) = t.strip_prefix('=') {
        (0, v)
    } else {
        (3, t.as_str())
    };
    let n: u8 = if let Ok(n) = v.parse::<u8>() {
        if n > 7 {
            return Err(d.parse_err(file, lineno, "priority out of range"));
        }
        n
    } else {
        match crate::msg::severity_by_name(v) {
            Some(n) => n,
            None => return Err(d.parse_err(file, lineno, &format!("unknown priority '{v}'"))),
        }
    };
    Ok(match op {
        0 => Cmp::Eq(n),
        1 => Cmp::NotEq(n),
        2 => Cmp::NotLe(n),
        _ => Cmp::Le(n),
    })
}

fn parse_legacy_action(
    s: &str,
    file: &str,
    lineno: usize,
    cfg: &mut Config,
    d: &mut Diag,
) -> Result<Action, ConfigError> {
    let s = s.trim();
    if s.starts_with('|') || s.starts_with('^') {
        d.unsup(file, lineno, "pipe/shell action")?;
        return Ok(Action::Discard);
    }
    if s.starts_with(':') {
        // :omusrmsg:* etc.
        let body = s[1..].to_string();
        if body.starts_with("omusrmsg:") {
            let users = body["omusrmsg:".len()..].to_string();
            if users != "*" {
                d.unsup(file, lineno, "omusrmsg named users")?;
            }
            return Ok(Action::Usrmsg {
                users,
                template: None,
            });
        }
        d.unsup(file, lineno, &format!(":{body}"))?;
        return Ok(Action::Discard);
    }
    if s.starts_with("@@") || s.starts_with('@') {
        let tcp = s.starts_with("@@");
        let hostport = &s[if tcp { 2 } else { 1 }..];
        // split template suffix ;(...)
        let (hp, tmpl) = split_template_suffix(hostport);
        let (host, port) = parse_host_port(hp, 514)?;
        return Ok(Action::Fwd(FwdAction {
            host,
            port,
            tcp,
            template: tmpl.or_else(|| cfg.globals.action_forward_default_template.clone()),
            tls: None,
            octet_counted: false,
        }));
    }
    if s == "stop" {
        // handled by caller; here return discard placeholder
        return Ok(Action::Discard);
    }
    if s == "discard" || s == "~" {
        return Ok(Action::Discard);
    }
    // file or dynafile: path[;template] ; dynafile uses ?tmpl or ;tmpl
    let (pathtok, tmpl) = split_template_suffix(s);
    let mut no_sync = false;
    let mut p = pathtok.trim();
    if let Some(stripped) = p.strip_prefix('-') {
        no_sync = true;
        p = stripped;
    }
    if let Some(stripped) = p.strip_prefix('"') {
        if stripped.ends_with('"') {
            p = &stripped[..stripped.len() - 1];
        }
    }
    if p.starts_with("/dev/tty") {
        d.unsup(file, lineno, "device action")?;
        return Ok(Action::Discard);
    }
    let (path, dyn_t) = match p.find('?') {
        Some(i) => (Some(PathBuf::from(&p[..i])), Some(p[i + 1..].to_string())),
        None => (Some(PathBuf::from(p)), None),
    };
    let _ = &dyn_t;
    let template = tmpl.or_else(|| cfg.globals.action_file_default_template.clone());
    Ok(Action::File(FileAction {
        path,
        dyn_template: dyn_t,
        template,
        no_sync,
        flush_interval_secs: None,
        create_dirs: true,
    }))
}

fn split_template_suffix(s: &str) -> (&str, Option<String>) {
    // legacy: action;template (rsyslog legacy action format). Split on last ';'
    // only when suffix has no spaces... templates don't contain ';' unquoted.
    // We split on ';' if there is exactly one and suffix is a plausible template name.
    let t = s.trim();
    if let Some(i) = t.rfind(';') {
        let suffix = &t[i + 1..];
        if !suffix.contains(' ') && !suffix.is_empty() {
            return (&t[..i], Some(suffix.to_string()));
        }
    }
    (t, None)
}

fn parse_host_port(hp: &str, default: u16) -> Result<(String, u16), ConfigError> {
    if let Some(stripped) = hp.strip_prefix('[') {
        // [v6]:port
        if let Some(end) = stripped.find(']') {
            let host = stripped[..end].to_string();
            let port = stripped[end + 1..]
                .strip_prefix(':')
                .and_then(|v| v.parse().ok())
                .unwrap_or(default);
            return Ok((host, port));
        }
        return Err(ConfigError::parse("-", 0, "bad [host]"));
    }
    if let Some(i) = hp.rfind(':') {
        if let Ok(p) = hp[i + 1..].parse::<u16>() {
            return Ok((hp[..i].to_string(), p));
        }
    }
    Ok((hp.to_string(), default))
}

fn action_template_name(a: &Action) -> Option<&str> {
    match a {
        Action::File(fa) => fa.template.as_deref().or(fa.dyn_template.as_deref()),
        Action::Fwd(fa) => fa.template.as_deref(),
        _ => None,
    }
}

fn finalize(cfg: &mut Config, _d: &mut Diag) -> Result<(), ConfigError> {
    // fill listener defaults from legacy $*ServerRun
    for p in std::mem::take(&mut cfg.modules.udp_servers) {
        cfg.inputs.push(InputSpec::Udp {
            addr: "0.0.0.0".into(),
            port: p,
        });
    }
    for p in std::mem::take(&mut cfg.modules.tcp_servers) {
        cfg.inputs.push(InputSpec::Tcp {
            addr: "0.0.0.0".into(),
            port: p,
            tls: None,
        });
    }
    cfg.inputs.sort_by_key(|i| input_key(i));
    cfg.inputs.dedup_by_key(|i| input_key(i));
    // template define-before-use + dynafile secpath check
    for r in &cfg.rules {
        for a in &r.actions {
            match a {
                Action::File(fa) if fa.dyn_template.is_some() => {
                    let tname = fa.dyn_template.as_ref().unwrap();
                    let t = match cfg.templates.get(tname) {
                        Some(t) => t,
                        None => {
                            return Err(ConfigError::parse(
                                "-",
                                0,
                                &format!("unknown dynafile template '{tname}'"),
                            ));
                        }
                    };
                    let _ = t;
                }
                Action::File(fa) => {
                    if let Some(tn) = &fa.template {
                        if !cfg.templates.contains_key(tn) {
                            return Err(ConfigError::parse(
                                "-",
                                0,
                                &format!("unknown template '{tn}'"),
                            ));
                        }
                    }
                }
                Action::Fwd(fa) => {
                    if let Some(tn) = &fa.template {
                        if !cfg.templates.contains_key(tn) {
                            return Err(ConfigError::parse(
                                "-",
                                0,
                                &format!("unknown template '{tn}'"),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // Order + existence validation for template references.
    // Definitions and uses recorded with a global sequence; a use
    // before its definition is a strict error, compat ignores the
    // action (rsyslog semantics: unknown/early template, no action).
    for (tname, uf, ul, useq) in cfg.template_uses.clone() {
        let defseq = cfg
            .template_def_order
            .get(&tname)
            .map(|(_, _, s)| *s)
            .or(Some(0));
        let bad = match defseq {
            None => true,
            Some(dseq) => dseq > useq,
        };
        if bad {
            match _d.mode {
                Mode::Compat => {
                    // remove the offending action from all rules;
                    // engine later renders nothing for it.
                    for r in cfg.rules.iter_mut() {
                        r.actions
                            .retain(|a| action_template_name(a) != Some(tname.as_str()));
                    }
                }
                Mode::Strict => {
                    let kind = if defseq.is_none() {
                        format!("unknown template '{tname}'")
                    } else {
                        format!("template '{tname}' used before definition")
                    };
                    return Err(ConfigError::parse(&uf, ul, &kind));
                }
            }
        }
    }
    // Dynafile templates must sanitize user-controlled path props.
    for r in &cfg.rules {
        for a in &r.actions {
            if let Action::File(fa) = a {
                if let Some(dt) = &fa.dyn_template {
                    if let Some(t) = cfg.templates.get(dt) {
                        if t.missing_secpath() {
                            match _d.mode {
                                Mode::Compat => {}
                                Mode::Strict => {
                                    return Err(ConfigError::parse(
                                        "-",
                                        0,
                                        &format!(
                                            "dynafile template '{dt}' uses unsanitized property (secpath-replace required)"
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse_str(s: &str, mode: Mode) -> Result<(Config, Vec<String>), ConfigError> {
        let file = if std::env::var_os("CARGO").is_some() {
            // test threads share this env; use a per-test unique dir via name
            let count: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "scfg{}-{count}-{}",
                std::process::id(),
                std::thread::current()
                    .name()
                    .unwrap_or("t")
                    .replace(':', "_")
            ));
            std::fs::create_dir_all(&dir).ok();
            dir.join("t.conf")
        } else {
            std::env::temp_dir().join("scfg-t.conf")
        };
        {
            let mut f = std::fs::File::create(&file).unwrap();
            f.write_all(s.as_bytes()).unwrap();
        }
        let r = parse(&file, mode);
        let _ = std::fs::remove_file(&file);
        r
    }

    #[test]
    fn dynafile_without_secpath_fails_strict() {
        let c = "$template DynFile,\"/var/log/%HOSTNAME%/%programname%.log\"\n*.info /var/log/x?DynFile\n";
        assert!(parse_str(c, Mode::Strict).is_err());
    }

    #[test]
    fn dynafile_with_secpath_passes() {
        let c = "$template DynFile,\"/var/log/%HOSTNAME:::secpath-replace%/%programname:::secpath-replace%.log\"\n*.info /var/log/x?DynFile\n";
        assert!(parse_str(c, Mode::Strict).is_ok());
    }

    #[test]
    fn debian_min() {
        let c = "$ModLoad imuxsock\n$ModLoad imklog\n$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat\n$RepeatedMsgReduction on\n*.*;auth,authpriv.none /var/log/syslog\n*.emerg :omusrmsg:*\n";
        let (cfg, _) = parse_str(c, Mode::Strict).unwrap();
        assert!(cfg.modules.imuxsock && cfg.modules.imklog);
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(
            cfg.globals.action_file_default_template.as_deref(),
            Some("RSYSLOG_TraditionalFileFormat")
        );
    }

    #[test]
    fn star_debug_local6() {
        let (cfg, _) = parse_str("*.debug;local6.err /var/log/x\n", Mode::Strict).unwrap();
        match &cfg.rules[0].matcher {
            Matcher::Sel(items) => {
                let m22 = items.iter().find(|i| i.fac_mask == 1 << 22);
                assert_eq!(m22.unwrap().cmp, Cmp::Le(3)); // err = 3
            }
            _ => panic!("sel"),
        }
    }

    #[test]
    fn unsupported_strict_and_compat() {
        let c = "action(type=\"omrelp\" target=\"h\" port=\"2514\")\n";
        assert!(parse_str(c, Mode::Strict).is_err());
        assert!(parse_str(c, Mode::Compat).is_ok());
    }
}
