use crate::msg::Msg;
use bytes::Bytes;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Error)]
pub enum ParseErr {
    #[error("bad PRI")]
    BadPri,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("bad timestamp")]
    BadTimestamp,
    #[error("non-ASCII header")]
    HeaderNonAscii,
    #[error("truncated header")]
    Truncated,
}

fn pri(input: &[u8]) -> Result<(u8, usize), ParseErr> {
    if input.first() != Some(&b'<') {
        return Err(ParseErr::BadPri);
    }
    let end = input
        .iter()
        .position(|&b| b == b'>')
        .ok_or(ParseErr::BadPri)?;
    if end < 2 || end > 4 {
        return Err(ParseErr::BadPri);
    }
    let digits = &input[1..end];
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(ParseErr::BadPri);
    }
    if digits.len() > 1 && digits[0] == b'0' {
        return Err(ParseErr::BadPri); // leading zero
    }
    let v: u32 = digits.iter().fold(0u32, |a, b| a * 10 + (b - b'0') as u32);
    if v > 191 {
        return Err(ParseErr::BadPri);
    }
    Ok((v as u8, end + 1))
}

/// Read one header token up to SP. Returns (token, next_idx).
fn token(input: &[u8], mut i: usize) -> Result<(&[u8], usize), ParseErr> {
    let start = i;
    while i < input.len() && input[i] != b' ' {
        if !input[i].is_ascii() {
            return Err(ParseErr::HeaderNonAscii);
        }
        i += 1;
    }
    if i == start {
        return Err(ParseErr::Truncated);
    }
    Ok((&input[start..i], i))
}

fn nil(tok: &[u8]) -> Option<String> {
    if tok == b"-" {
        None
    } else {
        Some(String::from_utf8_lossy(tok).into_owned())
    }
}

/// Validate RFC3339 per RFC5424: uppercase T/Z, <=6 frac digits, no leap seconds.
fn parse_ts(tok: &[u8]) -> Result<OffsetDateTime, ParseErr> {
    if tok == b"-" {
        return Ok(OffsetDateTime::UNIX_EPOCH); // caller treats as None
    }
    let s = std::str::from_utf8(tok).map_err(|_| ParseErr::BadTimestamp)?;
    // Reject lowercase t/z, leap second, >6 frac digits per RFC5424.
    let bytes = s.as_bytes();
    if bytes.len() < 20 || bytes[10] != b'T' {
        return Err(ParseErr::BadTimestamp);
    }
    if s.as_bytes()[17..19] == *b"60" {
        return Err(ParseErr::BadTimestamp);
    }
    let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(|_| ParseErr::BadTimestamp)?;
    // time crate accepts lowercase t/z? Rfc3339 is strict; also enforce frac <=6 digits
    if dt.nanosecond() % 1000 != 0 {
        return Err(ParseErr::BadTimestamp); // >6 digits precision
    }
    Ok(dt)
}

/// Locate end of STRUCTURED-DATA: first ']' that closes an element,
/// honoring backslash escapes inside quoted params. Returns index one
/// past SD (start of SP-or-end before MSG).
fn sd_end(sd: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut in_quote = false;
    let mut i = 0usize;
    while i < sd.len() {
        match sd[i] {
            b'\\' if in_quote => i += 1, // skip escaped char
            b'"' => in_quote = !in_quote,
            b'[' if !in_quote => depth += 1,
            b']' if !in_quote => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    sd.len()
}

/// Strict RFC5424 parse. On Err, caller should try RFC3164.
pub fn parse_rfc5424(input: &[u8]) -> Result<Msg, ParseErr> {
    let (pri_v, mut i) = pri(input)?;
    // VERSION
    let (ver, n) = token(input, i)?;
    if ver != b"1" {
        return Err(ParseErr::UnsupportedVersion);
    }
    i = n + 1;
    // TIMESTAMP
    let (ts_tok, n) = token(input, i)?;
    let timestamp = if ts_tok == b"-" {
        None
    } else {
        Some(parse_ts(ts_tok)?)
    };
    i = n + 1;
    let (hn, n) = token(input, i)?;
    let hostname = nil(hn);
    i = n + 1;
    let (an, n) = token(input, i)?;
    let app_name = nil(an);
    i = n + 1;
    let (pid, n) = token(input, i)?;
    let procid = nil(pid);
    i = n + 1;
    let (mid, n) = token(input, i)?;
    let msgid = nil(mid);
    i = n + 1;
    // STRUCTURED-DATA or NILVALUE, then SP, then MSG
    let (sd_raw, sd_invalid) = if i < input.len() && input[i] == b'-' {
        (None, false)
    } else {
        let end = sd_end(&input[i..]);
        let sd = &input[i..i + end];
        (Some(Bytes::copy_from_slice(sd)), false)
    };
    let mut msg_start = i + sd_raw.as_ref().map_or(1, |s| s.len());
    if msg_start < input.len() && input[msg_start] == b' ' {
        msg_start += 1;
    }
    let msg = Bytes::copy_from_slice(&input[msg_start.min(input.len())..]);
    let mut m = Msg::new(pri_v, msg, Bytes::copy_from_slice(input), "imtcp");
    m.timestamp = timestamp;
    m.hostname = hostname;
    m.app_name = app_name.clone();
    m.procid = procid;
    m.msgid = msgid;
    m.sd_raw = sd_raw;
    m.sd_invalid = sd_invalid;
    // rsyslog tag synthesis for 5424: APP-NAME[PROCID]: with trailing space
    if let Some(an) = &app_name {
        let mut t = an.clone();
        if let Some(p) = &m.procid {
            t.push('[');
            t.push_str(p);
            t.push(']');
        }
        t.push(':');
        t.push(' ');
        m.tag = t;
        m.programname = Some(an.clone());
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_5424() {
        let m = parse_rfc5424(
            b"<34>1 2024-06-01T12:00:00Z host app 1234 ID47 [exampleSDID@32473 iut=\"3\"] hi",
        )
        .unwrap();
        assert_eq!(m.facility, 4);
        assert_eq!(m.severity, 2); // 34 = 4*8+2
        assert_eq!(m.hostname.as_deref(), Some("host"));
        assert_eq!(m.app_name.as_deref(), Some("app"));
        assert_eq!(m.procid.as_deref(), Some("1234"));
        assert_eq!(m.msgid.as_deref(), Some("ID47"));
        assert_eq!(&m.msg[..], b"hi");
        assert_eq!(m.tag, "app[1234]: ");
    }

    #[test]
    fn nil_fields() {
        let m = parse_rfc5424(b"<13>1 - - - - - - msg").unwrap();
        assert!(m.timestamp.is_none() && m.hostname.is_none() && m.app_name.is_none());
        assert!(m.sd_raw.is_none());
        assert_eq!(&m.msg[..], b"msg");
    }

    #[test]
    fn sd_boundary_stops_at_first_close() {
        let m =
            parse_rfc5424(b"<34>1 2024-06-01T12:00:00Z h a - - [a i=\"1\"] [rest is msg").unwrap();
        assert_eq!(m.sd_raw.as_deref(), Some(&b"[a i=\"1\"]"[..]));
        assert_eq!(&m.msg[..], b"[rest is msg");
    }

    #[test]
    fn sd_quoted_bracket() {
        let m = parse_rfc5424(b"<34>1 2024-06-01T12:00:00Z h a - - [a i=\"x]y\"] msg").unwrap();
        assert_eq!(m.sd_raw.as_deref(), Some(&b"[a i=\"x]y\"]"[..]));
        assert_eq!(&m.msg[..], b"msg");
    }

    #[test]
    fn rejects_bad_pri_and_version() {
        assert!(matches!(
            parse_rfc5424(b"<00>1 - - - - - - x"),
            Err(ParseErr::BadPri)
        ));
        assert!(matches!(
            parse_rfc5424(b"<192>1 - - - - - - x"),
            Err(ParseErr::BadPri)
        ));
        assert!(matches!(
            parse_rfc5424(b"<34>2 - - - - - - x"),
            Err(ParseErr::UnsupportedVersion)
        ));
    }

    #[test]
    fn rejects_bad_ts() {
        // 9 frac digits
        assert!(matches!(
            parse_rfc5424(b"<34>1 2003-08-24T05:14:15.000000003-07:00 h a - - - x"),
            Err(ParseErr::BadTimestamp)
        ));
        // leap second
        assert!(matches!(
            parse_rfc5424(b"<34>1 2003-08-24T05:14:60Z h a - - - x"),
            Err(ParseErr::BadTimestamp)
        ));
    }

    #[test]
    fn accepts_6_frac_digits() {
        let m = parse_rfc5424(b"<34>1 2024-06-01T12:00:00.123456Z h a - - - x").unwrap();
        assert_eq!(m.timestamp.unwrap().nanosecond(), 123_456_000);
    }
}
