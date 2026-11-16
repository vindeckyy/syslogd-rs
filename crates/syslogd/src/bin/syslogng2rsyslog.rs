// Convert the most common syslog-ng constructs into the supported
// rsyslog subset. Unknown blocks fail closed with a line number.
use std::io::Read;

fn main() {
    let mut src = String::new();
    std::io::stdin()
        .read_to_string(&mut src)
        .expect("read stdin");
    match convert(&src) {
        Ok(out) => {
            print!("{out}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("syslogng2rsyslog: {e}");
            std::process::exit(1);
        }
    }
}

fn convert(src: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut sources: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut dests: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut filters: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for (ln, raw) in src.lines().enumerate() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with("source") && l.contains('{') {
            let name = block_name(l, "source", ln)?;
            let inner = inner_of(l, ln)?;
            if inner.contains("udp(") && !inner.contains("tcp(") {
                let port = inner
                    .split(';')
                    .find(|s| s.contains("udp("))
                    .map(|p| param(&p, "port"))
                    .unwrap_or_else(|| "514".into());
                sources.insert(name, format!("$ModLoad imudp\n$UDPServerRun {port}\n"));
            } else if inner.contains("tcp(") {
                let port = inner
                    .split(';')
                    .find(|s| s.contains("tcp("))
                    .map(|p| param(&p, "port"))
                    .unwrap_or_else(|| "514".into());
                sources.insert(name, format!("$ModLoad imtcp\n$InputTCPServerRun {port}\n"));
            } else if inner.contains("unix-dgram") || inner.contains("/dev/log") {
                sources.insert(name, "$ModLoad imuxsock\n".into());
            } else {
                return Err(format!("line {}: unsupported source", ln + 1));
            }
            continue;
        }
        if l.starts_with("destination") && l.contains('{') {
            let name = block_name(l, "destination", ln)?;
            let inner = inner_of(l, ln)?;
            if inner.contains("file(") {
                let path = inner
                    .split(';')
                    .find(|s| s.contains("file("))
                    .and_then(|s| quoted_in_parens(s, "file("))
                    .ok_or_else(|| format!("line {}: file() without path", ln + 1))?;
                dests.insert(name, format!("action(type=\"omfile\" file=\"{path}\")\n"));
            } else if inner.contains("udp(") {
                let p = inner
                    .split(';')
                    .find(|s| s.contains("udp("))
                    .and_then(|s| inside_parens(s, "udp("))
                    .map(|x| x.trim())
                    .unwrap_or("");
                let host = quoted_in_parens(p, "\"").unwrap_or_default();
                let port = param(&p, "port");
                dests.insert(name, format!("*.* @{host}:{port}\n"));
            } else if inner.contains("tcp(") {
                let p = inner
                    .split(';')
                    .find(|s| s.contains("tcp("))
                    .and_then(|s| inside_parens(s, "tcp("))
                    .map(|x| x.trim())
                    .unwrap_or("");
                let host = quoted_in_parens(p, "\"").unwrap_or_default();
                let port = param(&p, "port");
                dests.insert(name, format!("*.* @@{host}:{port}\n"));
            } else {
                return Err(format!("line {}: unsupported destination", ln + 1));
            }
            continue;
        }
        if l.starts_with("filter") && l.contains('{') {
            let name = block_name(l, "filter", ln)?;
            let inner = inner_of(l, ln)?;
            if inner.contains("facility(authpriv)") {
                filters.insert(name, "authpriv.*".into());
            } else if inner.contains("facility(kern)") {
                filters.insert(name, "kern.*".into());
            } else if inner.contains("facility(syslog)") {
                filters.insert(name, "syslog.*".into());
            } else if inner.contains("level(err)") {
                filters.insert(name, "*.err".into());
            } else if inner.contains("level(crit)") {
                filters.insert(name, "*.crit".into());
            } else if inner.contains("level(info)") {
                filters.insert(name, "*.info".into());
            } else {
                return Err(format!("line {}: unsupported filter", ln + 1));
            }
            continue;
        }
        if l.starts_with("log") && l.contains('{') {
            let inner = inner_of(l, ln)?;
            let src_name = call_arg(&inner, "source(")
                .ok_or_else(|| format!("line {}: log without source", ln + 1))?;
            let dst_name = call_arg(&inner, "destination(")
                .ok_or_else(|| format!("line {}: log without destination", ln + 1))?;
            let src = sources.get(&src_name).cloned().unwrap_or_default();
            let dst = dests
                .get(&dst_name)
                .cloned()
                .ok_or_else(|| format!("line {}: unknown destination {dst_name}", ln + 1))?;
            match call_arg(&inner, "filter(") {
                Some(fname) => {
                    let sel = filters.get(&fname).cloned().unwrap_or_else(|| "*.*".into());
                    out.push_str(&src);
                    out.push_str(&format!("{sel} {dst}\n"));
                }
                None => {
                    out.push_str(&src);
                    out.push_str(&dst);
                }
            }
            if inner.contains("flags(final)") {
                out.push_str("stop\n");
            }
            continue;
        }
    }
    Ok(out)
}

fn block_name(l: &str, kw: &str, ln: usize) -> Result<String, String> {
    let rest = l.strip_prefix(kw).unwrap_or(l);
    let rest = rest.split('{').next().unwrap_or("").trim();
    rest.split_whitespace()
        .next()
        .map(String::from)
        .ok_or_else(|| format!("line {}: unnamed block", ln + 1))
}

fn inner_of(l: &str, ln: usize) -> Result<String, String> {
    match (l.find('{'), l.rfind('}')) {
        (Some(a), Some(b)) if b > a => Ok(l[a + 1..b].to_string()),
        _ => Err(format!("line {}: malformed block", ln + 1)),
    }
}

fn inside_parens<'a>(s: &'a str, marker: &str) -> Option<&'a str> {
    let start = s.find(marker)?;
    let open = start + marker.len() - 1;
    let rest = &s[open + 1..];
    let close = rest.find(')')?;
    Some(&rest[..close])
}

fn param(inner: &str, key: &str) -> String {
    // find `key(value)` (possibly preceded by other params)
    let mut search = inner;
    while let Some(idx) = search.find(key) {
        let after = &search[idx + key.len()..];
        if let Some(rest) = after.strip_prefix('(') {
            if let Some(close) = rest.find(')') {
                let v = rest[..close].trim().trim_matches('"');
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
        search = &search[idx + key.len()..];
    }
    "514".into()
}

fn quoted_in_parens(s: &str, marker: &str) -> Option<String> {
    if marker == "\"" {
        let first = s.split(',').next()?;
        return Some(first.trim().trim_matches('"').trim().to_string());
    }
    let p = inside_parens(s, marker)?;
    let first = p.split(',').next()?;
    Some(first.trim().trim_matches('"').to_string())
}

fn call_arg(s: &str, marker: &str) -> Option<String> {
    let inner = inside_parens(s, marker)?;
    Some(inner.trim().trim_matches('"').to_string())
}
