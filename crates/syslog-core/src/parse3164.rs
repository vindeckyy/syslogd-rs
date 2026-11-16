use crate::msg::Msg;
use crate::parse5424::ParseErr;
use bytes::Bytes;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

fn month(s: &[u8]) -> Option<Month> {
    Some(match s {
        b"Jan" => Month::January,
        b"Feb" => Month::February,
        b"Mar" => Month::March,
        b"Apr" => Month::April,
        b"May" => Month::May,
        b"Jun" => Month::June,
        b"Jul" => Month::July,
        b"Aug" => Month::August,
        b"Sep" => Month::September,
        b"Oct" => Month::October,
        b"Nov" => Month::November,
        b"Dec" => Month::December,
        _ => return None,
    })
}

/// Parse RFC3164-ish: "<pri>Mmm dd hh:mm:ss hostname tag: msg".
/// `now`/`local_tz` supply year + timezone (rsyslog uses receive time).
/// Valid PRI but missing/bad TIMESTAMP -> relay fix-up by caller (T4),
/// here it returns Truncated.
pub fn parse_rfc3164(
    input: &[u8],
    now: OffsetDateTime,
    local_tz: UtcOffset,
) -> Result<Msg, ParseErr> {
    let (pri_v, mut i) = match pri(input) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    // TIMESTAMP "Mmm dd hh:mm:ss" — 15 bytes, day may be ' d' or 'dd'
    if input.len() < i + 15 {
        return Err(ParseErr::Truncated);
    }
    let mon = month(&input[i..i + 3]).ok_or(ParseErr::BadTimestamp)?;
    if input[i + 3] != b' ' {
        return Err(ParseErr::BadTimestamp);
    }
    let d1 = input[i + 4];
    let d2 = input[i + 5];
    let day = if d1 == b' ' {
        (d2 - b'0') as u8
    } else {
        ((d1 - b'0') as u8) * 10 + (d2 - b'0') as u8
    };
    if input[i + 6] != b' ' {
        return Err(ParseErr::BadTimestamp);
    }
    let hh = two(&input[i + 7..i + 9])?;
    if input[i + 9] != b':' {
        return Err(ParseErr::BadTimestamp);
    }
    let mm = two(&input[i + 10..i + 12])?;
    if input[i + 12] != b':' {
        return Err(ParseErr::BadTimestamp);
    }
    let ss = two(&input[i + 13..i + 15])?;
    if input.get(i + 15) != Some(&b' ') {
        return Err(ParseErr::BadTimestamp);
    }
    i += 16;
    // HOSTNAME: up to next space
    let hs = i;
    while i < input.len() && input[i] != b' ' {
        i += 1;
    }
    let hostname = if i > hs {
        Some(String::from_utf8_lossy(&input[hs..i]).into_owned())
    } else {
        None
    };
    if i < input.len() {
        i += 1;
    }
    // TAG: "prog[pid]: " or "prog:" — scan for ':'
    let rest = &input[i..];
    let (tag, msg_start) = tag_and_msg(rest, i);
    let programname = tag
        .split(|c| c == '[' || c == ':')
        .next()
        .filter(|s| !s.is_empty())
        .map(String::from);
    let msg = Bytes::copy_from_slice(&input[msg_start..]);
    let dt = PrimitiveDateTime::new(
        Date::from_calendar_date(now.year(), mon, day).map_err(|_| ParseErr::BadTimestamp)?,
        Time::from_hms(hh, mm, ss).map_err(|_| ParseErr::BadTimestamp)?,
    )
    .assume_offset(local_tz);
    let mut m = Msg::new(pri_v, msg, Bytes::copy_from_slice(input), "imudp");
    m.timestamp = Some(dt);
    m.hostname = hostname;
    m.programname = programname.clone();
    m.tag = tag;
    if let Some(pn) = &programname {
        if m.app_name.is_none() {
            m.app_name = Some(pn.clone());
        }
    }
    Ok(m)
}

fn two(b: &[u8]) -> Result<u8, ParseErr> {
    if b.len() == 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() {
        Ok((b[0] - b'0') * 10 + (b[1] - b'0'))
    } else {
        Err(ParseErr::BadTimestamp)
    }
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
        return Err(ParseErr::BadPri);
    }
    let v: u32 = digits.iter().fold(0u32, |a, b| a * 10 + (b - b'0') as u32);
    if v > 191 {
        return Err(ParseErr::BadPri);
    }
    Ok((v as u8, end + 1))
}

/// Scan rest for tag terminator ':' then optional space. Returns
/// (tag incl "prog[pid]: ", absolute msg_start).
fn tag_and_msg(rest: &[u8], base: usize) -> (String, usize) {
    // tag is a printable token optionally ending with [pid] then ':'
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < rest.len() {
        let c = rest[i];
        match c {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b':' if depth == 0 => {
                let mut end = i + 1;
                if end < rest.len() && rest[end] == b' ' {
                    end += 1;
                }
                return (
                    String::from_utf8_lossy(&rest[..end]).into_owned(),
                    base + end,
                );
            }
            b' ' if depth == 0 && i > 0 => break, // space before ':' -> no tag
            _ => {}
        }
        i += 1;
        if i > 200 {
            break; // unreasonably long tag
        }
    }
    (String::new(), base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2024-06-01 12:00:00 UTC)
    }

    #[test]
    fn parses_3164() {
        let m = parse_rfc3164(
            b"<13>Jun  1 12:00:00 host prog[999]: hello",
            now(),
            UtcOffset::UTC,
        )
        .unwrap();
        assert_eq!(m.severity, 5);
        assert_eq!(m.hostname.as_deref(), Some("host"));
        assert_eq!(m.programname.as_deref(), Some("prog"));
        assert_eq!(m.tag, "prog[999]: ");
        assert_eq!(&m.msg[..], b"hello");
        let ts = m.timestamp.unwrap();
        assert_eq!((ts.month() as u8, ts.day(), ts.hour()), (6, 1, 12));
    }

    #[test]
    fn single_digit_day_two_spaces() {
        let m = parse_rfc3164(b"<13>Aug  7 12:00:00 h p: x", now(), UtcOffset::UTC).unwrap();
        assert_eq!(m.timestamp.unwrap().day(), 7);
    }

    #[test]
    fn no_tag() {
        let m = parse_rfc3164(
            b"<13>Jun  1 12:00:00 h just a message",
            now(),
            UtcOffset::UTC,
        )
        .unwrap();
        assert_eq!(m.tag, "");
        assert_eq!(&m.msg[..], b"just a message");
    }
}
