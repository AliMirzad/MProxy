//! Bounded, rotated diagnostics log with redaction.
//!
//! * `helper.log`, rotated at 512 KiB, 3 generations kept (max ~2 MiB on disk).
//! * Every line passes through [`redact`] (UUIDs, URL userinfo/paths/queries, long tokens).
//! * Callers log events and error codes, never credentials. Redaction is a second layer.
//! * Xray output goes to disk only when "debug logging" is enabled. Otherwise it is kept in
//!   a small in-memory ring buffer used to explain startup failures.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_BYTES: u64 = 512 * 1024;
const GENERATIONS: u32 = 3;

struct Logger {
    path: PathBuf,
    file: Option<File>,
    debug: bool,
}

static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub fn init(dir: &Path, debug: bool) {
    let _ = fs::create_dir_all(dir);
    crate::paths::harden_dir(dir);
    let path = dir.join("helper.log");
    let file = OpenOptions::new().create(true).append(true).open(&path).ok();
    crate::paths::harden_file(&path);
    *LOGGER.lock().unwrap_or_else(|e| e.into_inner()) = Some(Logger { path, file, debug });
}

pub fn set_debug(debug: bool) {
    if let Some(l) = LOGGER.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        l.debug = debug;
    }
}

pub fn debug_enabled() -> bool {
    LOGGER.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|l| l.debug)
}

pub fn log_path() -> Option<PathBuf> {
    LOGGER.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|l| l.path.clone())
}

fn rotate(l: &mut Logger) {
    l.file = None;
    for i in (1..GENERATIONS).rev() {
        let _ = fs::rename(l.path.with_extension(format!("log.{i}")), l.path.with_extension(format!("log.{}", i + 1)));
    }
    let _ = fs::rename(&l.path, l.path.with_extension("log.1"));
    l.file = OpenOptions::new().create(true).append(true).open(&l.path).ok();
    crate::paths::harden_file(&l.path);
}

fn write(level: &str, msg: &str) {
    let mut guard = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    let Some(l) = guard.as_mut() else { return };
    if level == "DEBUG" && !l.debug {
        return;
    }
    if l.file.as_ref().and_then(|f| f.metadata().ok()).is_some_and(|m| m.len() > MAX_BYTES) {
        rotate(l);
    }
    if let Some(f) = l.file.as_mut() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{ts} {level} [{}] {}", std::process::id(), redact(msg));
    }
}

pub fn info(msg: impl AsRef<str>) {
    write("INFO", msg.as_ref());
}
pub fn warn(msg: impl AsRef<str>) {
    write("WARN", msg.as_ref());
}
pub fn error(msg: impl AsRef<str>) {
    write("ERROR", msg.as_ref());
}
pub fn debug(msg: impl AsRef<str>) {
    write("DEBUG", msg.as_ref());
}

fn is_uuid_at(b: &[u8], i: usize) -> bool {
    if i + 36 > b.len() {
        return false;
    }
    b[i..i + 36].iter().enumerate().all(|(k, c)| {
        if matches!(k, 8 | 13 | 18 | 23) {
            *c == b'-'
        } else {
            c.is_ascii_hexdigit()
        }
    })
}

/// Removes likely secrets from a log line:
/// * UUIDs (VLESS/VMess ids) -> `<uuid>`
/// * `scheme://user@host/path?query` -> `scheme://host/…` (subscription tokens, link params)
/// * base64/hex runs of 32+ characters (keys, tokens) -> `<redacted>`
pub fn redact(input: &str) -> String {
    // Pass 1: URLs.
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("://") {
        let scheme_start = rest[..pos]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'))
            .map(|p| p + 1)
            .unwrap_or(0);
        out.push_str(&rest[..scheme_start]);
        let scheme = &rest[scheme_start..pos];
        let after = &rest[pos + 3..];
        let end = after.find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '>').unwrap_or(after.len());
        let url = &after[..end];
        let authority_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        let authority = &url[..authority_end];
        let host = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
        out.push_str(scheme);
        out.push_str("://");
        if scheme.eq_ignore_ascii_case("vless") || scheme.eq_ignore_ascii_case("vmess") {
            out.push_str("<redacted>");
        } else {
            out.push_str(host);
            if authority_end < url.len() {
                out.push_str("/…");
            }
        }
        rest = &after[end..];
    }
    out.push_str(rest);

    // Pass 2: UUIDs and long tokens.
    let b = out.as_bytes();
    let mut res = String::with_capacity(out.len());
    let mut i = 0;
    while i < b.len() {
        if is_uuid_at(b, i) {
            res.push_str("<uuid>");
            i += 36;
            continue;
        }
        let tok_len = b[i..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'_' | b'-'))
            .count();
        if tok_len >= 32 && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let tok = &out[i..i + tok_len];
            // Keep paths such as C:/Users/... or /Library/... readable.
            if tok.contains('/') && tok.chars().filter(|c| *c == '/').count() > 1 {
                res.push_str(tok);
            } else {
                res.push_str("<redacted>");
            }
            i += tok_len;
            continue;
        }
        let ch = out[i..].chars().next().unwrap();
        res.push(ch);
        i += ch.len_utf8();
    }
    res
}

/// Fixed-size ring buffer of recent Xray output lines (already redacted).
pub struct Tail {
    lines: std::collections::VecDeque<String>,
    cap: usize,
}

impl Tail {
    pub fn new(cap: usize) -> Self {
        Tail { lines: Default::default(), cap }
    }
    pub fn push(&mut self, line: &str) {
        if self.lines.len() == self.cap {
            self.lines.pop_front();
        }
        self.lines.push_back(redact(line).chars().take(400).collect());
    }
    pub fn lines(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets() {
        let s = redact("user b831381d-6324-4d53-ad4f-8cda48b30811 failed");
        assert_eq!(s, "user <uuid> failed");
        let s = redact("fetch https://sub.example.com/api/v1/client/subscribe?token=abcdef123 failed");
        assert_eq!(s, "fetch https://sub.example.com/… failed");
        let s = redact("link vless://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?pbk=x#n end");
        assert_eq!(s, "link vless://<redacted> end");
        let s = redact("key OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI here");
        assert_eq!(s, "key <redacted> here");
        let s = redact("path C:/Users/someone/AppData/Local/PrivateProxy/logs/helper.log ok");
        assert!(s.contains("helper.log"));
        assert_eq!(redact("plain message"), "plain message");
    }

    #[test]
    fn tail_is_bounded() {
        let mut t = Tail::new(2);
        t.push("a");
        t.push("b");
        t.push("c");
        assert_eq!(t.lines(), vec!["b", "c"]);
    }
}
