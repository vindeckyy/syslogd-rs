use bytes::{BufMut, Bytes, BytesMut};

/// `$EscapeControlCharactersOnReceive` (default ON):
/// every byte <0x20 or ==0x7F is replaced by `prefix` + 3-digit octal.
/// rsyslog escapes the tab too (no exceptions in v1).
pub fn escape_control_chars(msg: &mut Bytes, prefix: u8) {
    let needs = msg.iter().any(|&b| b < 0x20 || b == 0x7f);
    if !needs {
        return;
    }
    let mut out = BytesMut::with_capacity(msg.len() + 16);
    for &b in msg.iter() {
        if b < 0x20 || b == 0x7f {
            out.put_u8(prefix);
            out.put_u8(b'0' + (b >> 6));
            out.put_u8(b'0' + ((b >> 3) & 7));
            out.put_u8(b'0' + (b & 7));
        } else {
            out.put_u8(b);
        }
    }
    *msg = out.freeze();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_escapes() {
        let mut b = Bytes::from_static(b"a\nb\tc\x7fd");
        escape_control_chars(&mut b, b'\\');
        assert_eq!(&b[..], b"a\\012b\\011c\\177d");
    }

    #[test]
    fn clean_unchanged() {
        let mut b = Bytes::from_static(b"hello world");
        escape_control_chars(&mut b, b'\\');
        assert_eq!(&b[..], b"hello world");
    }
}
