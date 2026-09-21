//! Persistent local storage.
//!
//! * `state.json`   – server metadata, subscriptions (without URLs), selection, settings.
//! * `secrets.bin`  – encrypted [`SecretsFile`] (server credentials, subscription URLs).
//! * `store.lock`   – advisory lock; several helpers (one per browser/profile) may run at once.
//!
//! Every operation re-reads from disk under the lock and writes atomically (temp + rename).

use crate::model::*;
use crate::secrets::{self, KeyProvider, SecretError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_SERVERS: usize = 5000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub jetbrains_enabled: bool,
    pub jetbrains_socks_port: u16,
    pub jetbrains_http_port: u16,
    pub passthrough_when_disconnected: bool,
    pub debug_logging: bool,
    /// Allow subscription URLs on private networks (company-internal servers). Off by default:
    /// see netpolicy.rs.
    pub allow_private_subscription_hosts: bool,
    /// Require a username/password on the IDE endpoint (HTTP and SOCKS). On by default: the
    /// loopback ports are otherwise usable by every local process, including other users'.
    pub ide_auth: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            jetbrains_enabled: true,
            jetbrains_socks_port: 10808,
            jetbrains_http_port: 10809,
            passthrough_when_disconnected: true,
            debug_logging: false,
            allow_private_subscription_hosts: false,
            ide_auth: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionMeta {
    pub id: String,
    pub name: String,
    /// Host of the subscription URL, for display only (the URL itself is a secret).
    pub host: String,
    #[serde(default)]
    pub last_updated: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct StateFile {
    pub version: u32,
    pub servers: Vec<ServerMeta>,
    pub subscriptions: Vec<SubscriptionMeta>,
    pub selected_server_id: Option<String>,
    pub settings: Settings,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SecretsFile {
    pub servers: HashMap<String, ServerSecrets>,
    pub subscriptions: HashMap<String, String>,
    /// Password of the IDE endpoint (generated on first use, stored encrypted).
    pub ide_password: Option<String>,
}

/// Fixed user name of the IDE endpoint; only the password is secret.
pub const IDE_USER: &str = "privateproxy";

fn new_password() -> String {
    random_token(24)
}

/// Random token from the OS CSPRNG (57-symbol alphabet: ~5.8 bits per character).
pub fn random_token(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    (0..len).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    Secret(#[from] SecretError),
    #[error("local data could not be read or written: {0}")]
    Io(String),
    #[error("{0}")]
    Invalid(String),
    #[error("not found")]
    NotFound,
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

pub struct Store {
    dir: PathBuf,
    keys: Box<dyn KeyProvider>,
}

#[derive(Debug, Default, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub server_ids: Vec<String>,
    /// Entries skipped because the same server appeared earlier in the batch.
    pub duplicates: usize,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    // Never write through a pre-existing temp file: it could be a link planted to redirect the
    // write. Remove it (removes the link itself, not its target) and create a fresh file.
    let _ = fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    crate::paths::harden_file(&tmp);
    fs::rename(&tmp, path)
}

impl Store {
    pub fn open(dir: PathBuf, keys: Box<dyn KeyProvider>) -> Result<Store, StoreError> {
        if crate::harden::is_link(&dir) {
            return Err(StoreError::Io(format!("{} is a link or junction; refusing to store credentials there", dir.display())));
        }
        fs::create_dir_all(&dir)?;
        crate::paths::harden_dir(&dir);
        Ok(Store { dir, keys })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn key_storage(&self) -> &'static str {
        self.keys.describe()
    }

    fn lock(&self) -> Result<File, StoreError> {
        let f = OpenOptions::new().create(true).truncate(false).write(true).open(self.dir.join("store.lock"))?;
        f.lock()?;
        Ok(f) // released on drop
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    fn secrets_path(&self) -> PathBuf {
        self.dir.join("secrets.bin")
    }

    fn read_state_unlocked(&self) -> Result<StateFile, StoreError> {
        match fs::read(self.state_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| StoreError::Io("state.json is corrupted".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StateFile { version: 1, ..Default::default() }),
            Err(e) => Err(e.into()),
        }
    }

    fn write_state_unlocked(&self, s: &StateFile) -> Result<(), StoreError> {
        let b = serde_json::to_vec_pretty(s).map_err(|e| StoreError::Io(e.to_string()))?;
        atomic_write(&self.state_path(), &b)?;
        Ok(())
    }

    fn key(&self, create: bool) -> Result<Option<[u8; 32]>, StoreError> {
        if let Some(k) = self.keys.load()? {
            return Ok(Some(k));
        }
        if self.secrets_path().exists() {
            return Err(SecretError::KeyMissing.into());
        }
        if !create {
            return Ok(None);
        }
        let k = secrets::new_key();
        self.keys.store(&k)?;
        Ok(Some(k))
    }

    fn read_secrets_unlocked(&self, create_key: bool) -> Result<(SecretsFile, Option<[u8; 32]>), StoreError> {
        let key = self.key(create_key)?;
        let blob = match fs::read(self.secrets_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((SecretsFile::default(), key)),
            Err(e) => return Err(e.into()),
        };
        let key = key.ok_or(SecretError::KeyMissing)?;
        let plain = secrets::decrypt(&key, &blob)?;
        let sf = serde_json::from_slice(&plain).map_err(|_| SecretError::Corrupt)?;
        Ok((sf, Some(key)))
    }

    fn write_secrets_unlocked(&self, s: &SecretsFile, key: &[u8; 32]) -> Result<(), StoreError> {
        let plain = serde_json::to_vec(s).map_err(|e| StoreError::Io(e.to_string()))?;
        atomic_write(&self.secrets_path(), &secrets::encrypt(key, &plain))?;
        Ok(())
    }

    /// Read-only snapshot of the metadata.
    pub fn state(&self) -> Result<StateFile, StoreError> {
        let _l = self.lock()?;
        self.read_state_unlocked()
    }

    /// Mutate metadata only.
    pub fn update_state<T>(&self, f: impl FnOnce(&mut StateFile) -> Result<T, StoreError>) -> Result<T, StoreError> {
        let _l = self.lock()?;
        let mut s = self.read_state_unlocked()?;
        let r = f(&mut s)?;
        self.write_state_unlocked(&s)?;
        Ok(r)
    }

    /// Mutate metadata and secrets together.
    pub fn update_all<T>(
        &self,
        f: impl FnOnce(&mut StateFile, &mut SecretsFile) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let _l = self.lock()?;
        let mut s = self.read_state_unlocked()?;
        let (mut sec, key) = self.read_secrets_unlocked(true)?;
        let key = key.ok_or(SecretError::KeyMissing)?;
        let r = f(&mut s, &mut sec)?;
        // Drop secrets whose server/subscription no longer exists.
        sec.servers.retain(|id, _| s.servers.iter().any(|m| &m.id == id));
        sec.subscriptions.retain(|id, _| s.subscriptions.iter().any(|m| &m.id == id));
        self.write_secrets_unlocked(&sec, &key)?;
        self.write_state_unlocked(&s)?;
        Ok(r)
    }

    pub fn server_with_secrets(&self, id: &str) -> Result<(ServerMeta, ServerSecrets), StoreError> {
        let _l = self.lock()?;
        let s = self.read_state_unlocked()?;
        let meta = s.servers.into_iter().find(|m| m.id == id).ok_or(StoreError::NotFound)?;
        let (sec, _) = self.read_secrets_unlocked(false)?;
        let secrets = sec.servers.get(id).cloned().ok_or_else(|| {
            StoreError::Invalid("Credentials for this server are missing; please import it again".into())
        })?;
        Ok((meta, secrets))
    }

    /// Password of the IDE endpoint, created (and stored encrypted) on first use.
    pub fn ide_password(&self) -> Result<String, StoreError> {
        let _l = self.lock()?;
        let (mut sec, key) = self.read_secrets_unlocked(true)?;
        if let Some(p) = &sec.ide_password {
            return Ok(p.clone());
        }
        let key = key.ok_or(SecretError::KeyMissing)?;
        let p = new_password();
        sec.ide_password = Some(p.clone());
        self.write_secrets_unlocked(&sec, &key)?;
        Ok(p)
    }

    /// Replaces the IDE endpoint password.
    pub fn regenerate_ide_password(&self) -> Result<String, StoreError> {
        let _l = self.lock()?;
        let (mut sec, key) = self.read_secrets_unlocked(true)?;
        let key = key.ok_or(SecretError::KeyMissing)?;
        let p = new_password();
        sec.ide_password = Some(p.clone());
        self.write_secrets_unlocked(&sec, &key)?;
        Ok(p)
    }

    pub fn subscription_url(&self, id: &str) -> Result<String, StoreError> {
        let _l = self.lock()?;
        let (sec, _) = self.read_secrets_unlocked(false)?;
        sec.subscriptions.get(id).cloned().ok_or(StoreError::NotFound)
    }

    /// Removes all product data including the data key.
    pub fn reset(&self) -> Result<(), StoreError> {
        let _l = self.lock()?;
        let settings = self.read_state_unlocked().map(|s| s.settings).unwrap_or_default();
        let _ = fs::remove_file(self.secrets_path());
        self.keys.delete()?;
        self.write_state_unlocked(&StateFile { version: 1, settings, ..Default::default() })
    }
}

/// Merge parsed servers into the store.
///
/// * Manual import (`subscription_id == None`): a server with the same identity as an
///   existing manually imported one updates it in place (keeps its id); others are added.
/// * Subscription refresh: entries matching an existing server of that subscription update it
///   in place; new ones are added; servers no longer listed are removed.
pub fn merge(
    state: &mut StateFile,
    secrets: &mut SecretsFile,
    parsed: Vec<ParsedServer>,
    subscription_id: Option<&str>,
) -> Result<MergeReport, StoreError> {
    let mut report = MergeReport::default();
    let mut seen: Vec<String> = Vec::new();
    let mut batch_idents: Vec<String> = Vec::new();
    for mut p in parsed {
        let ident = p.identity();
        // The same server twice in one batch (same protocol, endpoint, credentials, transport):
        // keep the first, so a subscription can never multiply entries.
        if batch_idents.contains(&ident) {
            report.duplicates += 1;
            continue;
        }
        batch_idents.push(ident.clone());
        let existing = state.servers.iter().position(|m| {
            m.subscription_id.as_deref() == subscription_id
                && !seen.contains(&m.id)
                && secrets.servers.get(&m.id).is_some_and(|s| identity_of(m, s) == ident)
        });
        match existing {
            Some(i) => {
                let old = &state.servers[i];
                p.meta.id = old.id.clone();
                p.meta.created_at = old.created_at;
                if subscription_id.is_none() && old.name != p.meta.name && p.meta.name == format!("{}:{}", p.meta.address, p.meta.port) {
                    p.meta.name = old.name.clone(); // don't clobber a user rename with a fallback name
                }
                p.meta.subscription_id = subscription_id.map(String::from);
                if p.meta.subscription_id.is_some() {
                    p.meta.source = Source::Subscription;
                }
                secrets.servers.insert(p.meta.id.clone(), p.secrets);
                seen.push(p.meta.id.clone());
                report.server_ids.push(p.meta.id.clone());
                state.servers[i] = p.meta;
                report.updated += 1;
            }
            None => {
                if state.servers.len() >= MAX_SERVERS {
                    return Err(StoreError::Invalid(format!("Too many servers (limit {MAX_SERVERS})")));
                }
                p.meta.id = uuid::Uuid::new_v4().to_string();
                p.meta.created_at = now();
                p.meta.subscription_id = subscription_id.map(String::from);
                if subscription_id.is_some() {
                    p.meta.source = Source::Subscription;
                }
                secrets.servers.insert(p.meta.id.clone(), p.secrets);
                seen.push(p.meta.id.clone());
                report.server_ids.push(p.meta.id.clone());
                state.servers.push(p.meta);
                report.added += 1;
            }
        }
    }
    if let Some(sid) = subscription_id {
        let before = state.servers.len();
        state.servers.retain(|m| m.subscription_id.as_deref() != Some(sid) || seen.contains(&m.id));
        report.removed = before - state.servers.len();
        if let Some(sel) = &state.selected_server_id {
            if !state.servers.iter().any(|m| &m.id == sel) {
                state.selected_server_id = None;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_link;
    use crate::secrets::FileKeyProvider;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path().join("data"), Box::new(FileKeyProvider { path: d.path().join("k") })).unwrap();
        (d, s)
    }

    const L1: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?security=tls&type=ws&path=%2Fws#One";
    const L2: &str = "vless://c831381d-6324-4d53-ad4f-8cda48b30811@b.example.com:443?security=tls#Two";

    #[test]
    fn secrets_not_in_plaintext_files() {
        let (_d, s) = store();
        s.update_all(|st, sec| merge(st, sec, vec![parse_link(L1).unwrap()], None)).unwrap();
        let state = fs::read_to_string(s.dir().join("state.json")).unwrap();
        assert!(state.contains("a.example.com"));
        assert!(!state.contains("b831381d"));
        let blob = fs::read(s.dir().join("secrets.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("b831381d"));
        let id = s.state().unwrap().servers[0].id.clone();
        let (_m, sec) = s.server_with_secrets(&id).unwrap();
        assert_eq!(sec.user_id, "b831381d-6324-4d53-ad4f-8cda48b30811");
    }

    #[test]
    fn manual_reimport_updates_in_place() {
        let (_d, s) = store();
        let r1 = s.update_all(|st, sec| merge(st, sec, vec![parse_link(L1).unwrap()], None)).unwrap();
        let r2 = s.update_all(|st, sec| merge(st, sec, vec![parse_link(L1).unwrap(), parse_link(L2).unwrap()], None)).unwrap();
        assert_eq!((r1.added, r2.added, r2.updated), (1, 1, 1));
        assert_eq!(r1.server_ids[0], r2.server_ids[0]);
        assert_eq!(s.state().unwrap().servers.len(), 2);
    }

    #[test]
    fn subscription_refresh_adds_updates_removes() {
        let (_d, s) = store();
        let sub = "sub1";
        s.update_all(|st, sec| {
            st.subscriptions.push(SubscriptionMeta { id: sub.into(), name: "S".into(), host: "h".into(), last_updated: None, last_error: None });
            sec.subscriptions.insert(sub.into(), "https://h/x".into());
            merge(st, sec, vec![parse_link(L1).unwrap(), parse_link(L2).unwrap()], Some(sub))
        })
        .unwrap();
        let id1 = s.state().unwrap().servers[0].id.clone();
        let id2 = s.state().unwrap().servers[1].id.clone();
        s.update_state(|st| {
            st.selected_server_id = Some(id2.clone());
            Ok(())
        })
        .unwrap();
        let r = s.update_all(|st, sec| merge(st, sec, vec![parse_link(L1).unwrap()], Some(sub))).unwrap();
        assert_eq!((r.added, r.updated, r.removed), (0, 1, 1));
        let st = s.state().unwrap();
        assert_eq!(st.servers.len(), 1);
        assert_eq!(st.servers[0].id, id1);
        assert_eq!(st.servers[0].source, Source::Subscription);
        assert_eq!(st.selected_server_id, None, "selection of a removed server is cleared");
        assert_eq!(s.subscription_url(sub).unwrap(), "https://h/x");
    }

    #[test]
    fn missing_key_is_reported() {
        let d = tempfile::tempdir().unwrap();
        let kp = d.path().join("k");
        let s = Store::open(d.path().join("data"), Box::new(FileKeyProvider { path: kp.clone() })).unwrap();
        s.update_all(|st, sec| merge(st, sec, vec![parse_link(L1).unwrap()], None)).unwrap();
        fs::remove_file(&kp).unwrap();
        let id = s.state().unwrap().servers[0].id.clone();
        let e = s.server_with_secrets(&id).unwrap_err();
        assert!(matches!(e, StoreError::Secret(SecretError::KeyMissing)));
        // reset recovers
        s.reset().unwrap();
        assert!(s.state().unwrap().servers.is_empty());
        s.update_all(|st, sec| merge(st, sec, vec![parse_link(L1).unwrap()], None)).unwrap();
    }

    fn parsed(link: &str) -> ParsedServer {
        crate::parse::parse_link(link).unwrap()
    }

    #[test]
    fn duplicates_in_one_batch_are_collapsed_but_cdn_fronted_servers_are_not() {
        let (_d, st) = store();
        let a = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?security=tls&sni=de.example.com&type=ws&host=de.example.com&path=%2Fws#DE";
        let a_again = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?security=tls&sni=de.example.com&type=ws&host=de.example.com&path=%2Fws#DE%20copy";
        let fi = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?security=tls&sni=fi.example.com&type=ws&host=fi.example.com&path=%2Fws#FI";
        let r = st.update_all(|s, sec| merge(s, sec, vec![parsed(a), parsed(a_again), parsed(fi)], Some("sub1"))).unwrap();
        assert_eq!((r.added, r.duplicates), (2, 1));
        assert_eq!(st.state().unwrap().servers.len(), 2);
        // Re-running the same subscription never multiplies entries.
        for _ in 0..3 {
            let r = st.update_all(|s, sec| merge(s, sec, vec![parsed(a), parsed(a_again), parsed(fi)], Some("sub1"))).unwrap();
            assert_eq!((r.added, r.updated, r.removed), (0, 2, 0));
        }
        assert_eq!(st.state().unwrap().servers.len(), 2);
    }

    #[test]
    fn update_shrinks_a_bloated_subscription() {
        // A list imported by the old per-outbound behaviour (many alternatives per server) is
        // reconciled by the next update: extra entries are removed.
        let (_d, st) = store();
        let many: Vec<ParsedServer> = (0..12)
            .map(|i| parsed(&format!("vless://b831381d-6324-4d53-ad4f-8cda48b30811@front{i}.example.com:443?security=tls&sni=de.example.com#DE")))
            .collect();
        st.update_all(|s, sec| merge(s, sec, many, Some("sub1"))).unwrap();
        assert_eq!(st.state().unwrap().servers.len(), 12);
        let one = vec![parsed("vless://b831381d-6324-4d53-ad4f-8cda48b30811@front0.example.com:443?security=tls&sni=de.example.com#DE")];
        let r = st.update_all(|s, sec| merge(s, sec, one, Some("sub1"))).unwrap();
        assert_eq!((r.updated, r.removed), (1, 11));
        assert_eq!(st.state().unwrap().servers.len(), 1);
    }

}
