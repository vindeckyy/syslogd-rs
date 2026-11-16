use crate::msg::{facility_name, severity_name, Msg};
use bytes::BytesMut;
use std::collections::HashMap;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum TemplateErr {
    #[error("unterminated '%'")]
    Unterminated,
    #[error("unknown property '{0}'")]
    UnknownProp(String),
    #[error("unsupported option '{0}'")]
    UnsupportedOpt(String),
    #[error("bad substring '{0}'")]
    BadSubstring(String),
}

#[derive(Debug, Clone)]
enum Prop {
    Msg,
    RawMsg,
    Hostname,
    FromhostIp,
    Pri,
    PriText,
    Syslogtag,
    Syslogfacility,
    SyslogfacilityText,
    Syslogseverity,
    SyslogseverityText,
    Programname,
    AppName,
    Procid,
    Msgid,
    StructuredData,
    Timereported,
    Timegenerated,
    Inputname,
    Iut,
    Now,
    TimeNowUnixTimestamp,
}

#[derive(Debug, Clone, PartialEq)]
enum Opt {
    SpIfNo1stSp,
    DropLastLf,
    Lowercase,
    Uppercase,
    SecpathReplace,
    DateRfc3339,
}
#[derive(Debug, Clone)]
enum Seg {
    Lit(Vec<u8>),
    Prop {
        prop: Prop,
        from: Option<usize>,
        to: Option<usize>,
        opts: Vec<Opt>,
    },
}

#[derive(Debug, Clone)]
pub struct Template {
    pub name: String,
    segs: Vec<Seg>,
}

impl Template {
    pub fn render(&self, m: &Msg, timegenerated: &OffsetDateTime) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        for s in &self.segs {
            match s {
                Seg::Lit(b) => out.extend_from_slice(b),
                Seg::Prop {
                    prop,
                    from,
                    to,
                    opts,
                } => {
                    // date-rfc3339 re-renders the instant, not the BSD string
                    let mut v: Vec<u8> = if opts.contains(&Opt::DateRfc3339) {
                        match prop {
                            Prop::Timereported => m
                                .timestamp
                                .map(|t| fmt_rfc3339(&t).into_bytes())
                                .unwrap_or_default(),
                            Prop::Timegenerated | Prop::Now => {
                                fmt_rfc3339(timegenerated).into_bytes()
                            }
                            _ => prop_bytes(prop, m, timegenerated),
                        }
                    } else {
                        prop_bytes(prop, m, timegenerated)
                    };
                    // substring 1-based byte positions, clamp
                    if from.is_some() || to.is_some() {
                        let f = from.unwrap_or(1).saturating_sub(1);
                        let t = to.map(|x| x.min(v.len())).unwrap_or(v.len());
                        let f = f.min(t);
                        v = v[f..t].to_vec();
                    }
                    for o in opts {
                        v = apply_opt(o, v);
                    }
                    out.extend_from_slice(&v);
                }
            }
        }
        out
    }

    /// Render as String for wall/stdout paths.
    pub fn render_string(&self, m: &Msg, tg: &OffsetDateTime) -> String {
        String::from_utf8_lossy(&self.render(m, tg)).into_owned()
    }
}

fn prop_bytes(p: &Prop, m: &Msg, tg: &OffsetDateTime) -> Vec<u8> {
    match p {
        Prop::Msg => m.msg.to_vec(),
        Prop::RawMsg => m.raw.to_vec(),
        Prop::Hostname => m.hostname.clone().unwrap_or_default().into_bytes(),
        Prop::FromhostIp => m
            .fromhost_ip
            .map(|i| i.to_string().into_bytes())
            .unwrap_or_default(),
        Prop::Pri => m.pri.to_string().into_bytes(),
        Prop::PriText => format!(
            "{}.{}",
            facility_name(m.facility),
            severity_name(m.severity)
        )
        .into_bytes(),
        Prop::Syslogtag => m.tag.clone().into_bytes(),
        Prop::Syslogfacility => m.facility.to_string().into_bytes(),
        Prop::SyslogfacilityText => facility_name(m.facility).as_bytes().to_vec(),
        Prop::Syslogseverity => m.severity.to_string().into_bytes(),
        Prop::SyslogseverityText => severity_name(m.severity).as_bytes().to_vec(),
        Prop::Programname => m.programname.clone().unwrap_or_default().into_bytes(),
        Prop::AppName => m.app_name.clone().unwrap_or_default().into_bytes(),
        Prop::Procid => m.procid.clone().unwrap_or_else(|| "-".into()).into_bytes(),
        Prop::Msgid => m.msgid.clone().unwrap_or_else(|| "-".into()).into_bytes(),
        Prop::StructuredData => m
            .sd_raw
            .clone()
            .map(|b| b.to_vec())
            .unwrap_or_else(|| b"-".to_vec()),
        Prop::Timereported => m
            .timestamp
            .map(|t| fmt_bsd(&t))
            .unwrap_or_default()
            .into_bytes(),
        Prop::Timegenerated => fmt_bsd(tg).into_bytes(),
        Prop::Inputname => m.input_name.as_bytes().to_vec(),
        Prop::Iut => b"1".to_vec(),
        Prop::Now => fmt_bsd(tg).into_bytes(),
        Prop::TimeNowUnixTimestamp => (tg.unix_timestamp()).to_string().into_bytes(),
    }
}

/// BSD timestamp "Mmm  d hh:mm:ss" local — used for %TIMESTAMP% default format.
/// Callers pass the instant; local offset applied upstream when formatting.
fn fmt_bsd(t: &OffsetDateTime) -> String {
    let m = match t.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!(
        "{} {:>2} {:02}:{:02}:{:02}",
        m,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn fmt_rfc3339(t: &OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| "-".into())
}

fn apply_opt(o: &Opt, mut v: Vec<u8>) -> Vec<u8> {
    match o {
        Opt::SpIfNo1stSp => {
            if v.first() != Some(&b' ') {
                let mut n = Vec::with_capacity(v.len() + 1);
                n.push(b' ');
                n.extend_from_slice(&v);
                v = n;
            }
            v
        }
        Opt::DropLastLf => {
            if v.last() == Some(&b'\n') {
                v.pop();
            }
            v
        }
        Opt::Lowercase => {
            v.make_ascii_lowercase();
            v
        }
        Opt::Uppercase => {
            v.make_ascii_uppercase();
            v
        }
        Opt::SecpathReplace => secpath(v),
        Opt::DateRfc3339 => {
            // Only valid on timestamp props; caller guarantees. Reformat BSD->RFC3339 not possible;
            // for date opts we re-render from the prop's instant.
            v
        }
    }
}

/// rsyslog secpath-replace: replace '/' and '.' with '_' (..' collapse is
/// implied since every '.' becomes '_').
pub fn secpath(v: Vec<u8>) -> Vec<u8> {
    v.into_iter()
        .map(|b| if b == b'/' || b == b'.' { b'_' } else { b })
        .collect()
}

/// Parse "%PROP[:FROM:TO[:OPT]...]%" — compile once.
pub fn compile(name: &str, s: &str) -> Result<Template, TemplateErr> {
    let b = s.as_bytes();
    let mut segs = Vec::new();
    let mut lit = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 1 < b.len() && b[i + 1] == b'%' {
                lit.push(b'%');
                i += 2;
                continue;
            }
            let end = s[i + 1..]
                .find('%')
                .map(|e| i + 1 + e)
                .ok_or(TemplateErr::Unterminated)?;
            if !lit.is_empty() {
                segs.push(Seg::Lit(std::mem::take(&mut lit)));
            }
            segs.push(compile_prop(&s[i + 1..end])?);
            i = end + 1;
        } else if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'n' => lit.push(b'\n'),
                b'r' => lit.push(b'\r'),
                b't' => lit.push(b'\t'),
                b'\\' => lit.push(b'\\'),
                b'7' => lit.push(7),
                c => {
                    lit.push(b'\\');
                    lit.push(c);
                }
            }
            i += 2;
        } else {
            lit.push(b[i]);
            i += 1;
        }
    }
    if !lit.is_empty() {
        segs.push(Seg::Lit(lit));
    }
    Ok(Template {
        name: name.to_string(),
        segs,
    })
}

fn compile_prop(spec: &str) -> Result<Seg, TemplateErr> {
    let parts: Vec<&str> = spec.split(':').collect();
    let prop = prop_by_name(parts[0])?;
    let (mut from, mut to, mut opts) = (None, None, Vec::new());
    // rsyslog syntax: %prop% or %prop:from:to% or %prop:from:to:opt% or %prop:::opt%
    if parts.len() >= 2 && !parts[1].is_empty() {
        from = Some(
            parts[1]
                .parse::<usize>()
                .map_err(|_| TemplateErr::BadSubstring(parts[1].into()))?,
        );
    }
    if parts.len() >= 3 && !parts[2].is_empty() {
        to = Some(
            parts[2]
                .parse::<usize>()
                .map_err(|_| TemplateErr::BadSubstring(parts[2].into()))?,
        );
    }
    for o in parts.iter().skip(3).filter(|s| !s.is_empty()) {
        opts.push(opt_by_name(o)?);
    }
    Ok(Seg::Prop {
        prop,
        from,
        to,
        opts,
    })
}

fn prop_by_name(n: &str) -> Result<Prop, TemplateErr> {
    let l = n.to_ascii_lowercase();
    Ok(match l.as_str() {
        "msg" => Prop::Msg,
        "rawmsg" => Prop::RawMsg,
        "hostname" | "source" | "fromhost" => Prop::Hostname,
        "fromhost-ip" => Prop::FromhostIp,
        "pri" => Prop::Pri,
        "pri-text" => Prop::PriText,
        "syslogtag" => Prop::Syslogtag,
        "syslogfacility" => Prop::Syslogfacility,
        "syslogfacility-text" => Prop::SyslogfacilityText,
        "syslogseverity" => Prop::Syslogseverity,
        "syslogseverity-text" => Prop::SyslogseverityText,
        "programname" => Prop::Programname,
        "app-name" => Prop::AppName,
        "procid" => Prop::Procid,
        "msgid" => Prop::Msgid,
        "structured-data" => Prop::StructuredData,
        "timereported" | "timestamp" => Prop::Timereported,
        "timegenerated" => Prop::Timegenerated,
        "inputname" => Prop::Inputname,
        "iut" => Prop::Iut,
        "now" => Prop::Now,
        "timegenerated:::date-unixtimestamp" => Prop::TimeNowUnixTimestamp,
        _ => return Err(TemplateErr::UnknownProp(n.into())),
    })
}

fn opt_by_name(n: &str) -> Result<Opt, TemplateErr> {
    Ok(match n.to_ascii_lowercase().as_str() {
        "sp-if-no-1st-sp" => Opt::SpIfNo1stSp,
        "drop-last-lf" => Opt::DropLastLf,
        "lowercase" => Opt::Lowercase,
        "uppercase" => Opt::Uppercase,
        "secpath-replace" => Opt::SecpathReplace,
        "date-rfc3339" => Opt::DateRfc3339,
        _ => return Err(TemplateErr::UnsupportedOpt(n.into())),
    })
}

/// Predefined RSYSLOG_* templates, byte-exact from
/// docs.rsyslog.com/doc/reference/templates/templates-reserved-names.html
pub fn builtins() -> HashMap<String, Template> {
    let mut m = HashMap::new();
    let defs: [(&str, &str); 10] = [
        (
            "RSYSLOG_TraditionalFileFormat",
            "%TIMESTAMP% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n",
        ),
        (
            "RSYSLOG_FileFormat",
            "%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n",
        ),
        (
            "RSYSLOG_TraditionalForwardFormat",
            "<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag:1:32%%msg:::sp-if-no-1st-sp%%msg%",
        ),
        (
            "RSYSLOG_SysklogdFileFormat",
            "%TIMESTAMP% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg%\n",
        ),
        (
            "RSYSLOG_ForwardFormat",
            "<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag:1:32%%msg:::sp-if-no-1st-sp%%msg%",
        ),
        (
            "RSYSLOG_SyslogProtocol23Format",
            "<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%\n",
        ),
        (
            "RSYSLOG_SyslogRFC5424Format",
            "<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%",
        ),
        (
            "RSYSLOG_DebugFormat",
            "Debug line with all properties:\nFROMHOST: '%fromhost%', fromhost-ip: '%fromhost-ip%', HOSTNAME: '%hostname%', PRI: %pri%,\nsyslogtag '%syslogtag%', programname: '%programname%', APP-NAME: '%app-name%', PROCID: '%procid%', MSGID: '%msgid%',\nTIMESTAMP: '%timereported%', STRUCTURED-DATA: '%structured-data%',\nmsg: '%msg%'\nescaped msg: '%msg%'\ninputname: %inputname% rawmsg: '%rawmsg%'\n$!:\n$.:\n$/:\n\n",
        ),
        (
            "RSYSLOG_WallFmt",
            "\r\n\x07Message from syslogd@%HOSTNAME% at %timegenerated% ...\r\n%syslogtag%%msg%\n\r",
        ),
        ("RSYSLOG_StdUsrMsgFmt", " %syslogtag%%msg%\n\r"),
    ];
    for (n, s) in defs {
        m.insert(n.to_string(), compile(n, s).expect("builtin"));
    }
    // FileFormat list == same output as the string form above.
    m
}

/// Byte props that must get secpath-replace in dynafile templates.
pub fn is_user_controlled(propname: &str) -> bool {
    matches!(
        propname.to_ascii_lowercase().as_str(),
        "hostname" | "programname" | "fromhost-ip" | "syslogtag" | "app-name" | "msg" | "rawmsg"
    )
}

impl Template {
    /// True when any user-controlled property in the template lacks
    /// secpath-replace (dynafile path-injection risk).
    pub fn missing_secpath(&self) -> bool {
        self.segs.iter().any(|seg| match seg {
            Seg::Prop { prop, opts, .. } => {
                user_controlled(prop) && !opts.contains(&Opt::SecpathReplace)
            }
            _ => false,
        })
    }
}

fn user_controlled(p: &Prop) -> bool {
    matches!(
        p,
        Prop::Hostname
            | Prop::Programname
            | Prop::FromhostIp
            | Prop::Syslogtag
            | Prop::AppName
            | Prop::Msg
            | Prop::RawMsg
    )
}

/// Render a timestamp with date-rfc3339 applied — used because
/// Opt::DateRfc3339 on a Vec<u8> can't reformat; we re-render at prop level.
pub fn render_date_rfc3339(t: &OffsetDateTime) -> Vec<u8> {
    fmt_rfc3339(t).into_bytes()
}

pub fn bytes_mut() -> BytesMut {
    BytesMut::with_capacity(256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse3164::parse_rfc3164;
    use time::macros::datetime;

    fn msg() -> Msg {
        parse_rfc3164(
            b"<13>Jun  1 12:00:00 host prog[9]: hello\n",
            datetime!(2024-06-01 12:00:00 UTC),
            time::UtcOffset::UTC,
        )
        .unwrap()
    }

    #[test]
    fn traditional_file_format() {
        let t = builtins()["RSYSLOG_TraditionalFileFormat"].clone();
        let tg = datetime!(2024-06-01 12:00:00 UTC);
        assert_eq!(
            String::from_utf8(t.render(&msg(), &tg)).unwrap(),
            "Jun  1 12:00:00 host prog[9]:  hello\nhello\n"
        );
    }

    #[test]
    fn forward_format() {
        let t = builtins()["RSYSLOG_ForwardFormat"].clone();
        let tg = datetime!(2024-06-01 12:00:00 UTC);
        assert_eq!(
            String::from_utf8(t.render(&msg(), &tg)).unwrap(),
            "<13>2024-06-01T12:00:00Z host prog[9]:  hello\nhello\n"
        );
    }

    #[test]
    fn substring_and_opts() {
        let t = compile("x", "%syslogtag:1:4%|%msg:::uppercase%").unwrap();
        let tg = datetime!(2024-06-01 12:00:00 UTC);
        assert_eq!(
            String::from_utf8(t.render(&msg(), &tg)).unwrap(),
            "prog|HELLO\n"
        );
    }

    #[test]
    fn file_format_golden() {
        let t = builtins()["RSYSLOG_FileFormat"].clone();
        let tg = datetime!(2024-06-01 12:00:00 UTC);
        assert_eq!(
            String::from_utf8(t.render(&msg(), &tg)).unwrap(),
            "2024-06-01T12:00:00Z host prog[9]:  hello
hello
"
        );
    }

    #[test]
    fn rfc5424_golden() {
        let t = builtins()["RSYSLOG_SyslogRFC5424Format"].clone();
        let tg = datetime!(2024-06-01 12:00:00 UTC);
        assert_eq!(
            String::from_utf8(t.render(&msg(), &tg)).unwrap(),
            "<13>1 2024-06-01T12:00:00Z host prog - - - hello\n"
        );
    }

    #[test]
    fn dynafile_secpath_detected() {
        let bad = compile("dyn", "%HOSTNAME%/%programname%").unwrap();
        let good = compile(
            "dyn",
            "%HOSTNAME:::secpath-replace%/%programname:::secpath-replace%",
        )
        .unwrap();
        assert!(bad.missing_secpath());
        assert!(!good.missing_secpath());
    }

    #[test]
    fn secpath_replace() {
        assert_eq!(&super::secpath(b"a/b.c".to_vec())[..], b"a_b_c");
    }
}
