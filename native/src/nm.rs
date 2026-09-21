//! Native messaging framing: each message is a 32-bit length in native byte order followed
//! by UTF-8 JSON. Chromium limits host->browser messages to 1 MB.

use std::io::{self, Read, Write};

/// Largest message we accept from the extension. Chromium allows 64 MiB, but no legitimate
/// command is close to this (imports are capped at 5 MiB of text).
pub const MAX_INBOUND: usize = 8 * 1024 * 1024;
/// Chromium's limit for messages sent by the host.
pub const MAX_OUTBOUND: usize = 1024 * 1024;

#[derive(Debug)]
pub enum ReadError {
    Eof,
    TooLarge(usize),
    Io(io::Error),
}

pub fn read_message<R: Read>(r: &mut R) -> Result<Vec<u8>, ReadError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ReadError::Eof),
        Err(e) => return Err(ReadError::Io(e)),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n > MAX_INBOUND {
        return Err(ReadError::TooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            ReadError::Eof
        } else {
            ReadError::Io(e)
        }
    })?;
    Ok(buf)
}

pub fn write_message<W: Write>(w: &mut W, json: &[u8]) -> io::Result<()> {
    if json.len() > MAX_OUTBOUND {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "outbound message exceeds 1 MB"));
    }
    w.write_all(&(json.len() as u32).to_ne_bytes())?;
    w.write_all(json)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        write_message(&mut buf, br#"{"a":1}"#).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_message(&mut r).unwrap(), br#"{"a":1}"#);
        assert!(matches!(read_message(&mut r), Err(ReadError::Eof)));
    }

    #[test]
    fn rejects_oversized() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_INBOUND as u32) + 1).to_ne_bytes());
        let mut r = &buf[..];
        assert!(matches!(read_message(&mut r), Err(ReadError::TooLarge(_))));
    }

    #[test]
    fn truncated_is_eof() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_ne_bytes());
        buf.extend_from_slice(b"abc");
        let mut r = &buf[..];
        assert!(matches!(read_message(&mut r), Err(ReadError::Eof)));
    }

    #[test]
    fn outbound_limit() {
        let big = vec![b'a'; MAX_OUTBOUND + 1];
        assert!(write_message(&mut Vec::new(), &big).is_err());
    }
}
