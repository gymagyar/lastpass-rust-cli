use crate::{
    crypto,
    model::{Session, Vault},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone)]
pub struct Metadata {
    pub username: String,
    pub iterations: u32,
    pub timeout: u64,
    pub refresh: u64,
    pub agent_token: String,
    pub trusted_id: Option<String>,
}
pub struct Store {
    pub dir: PathBuf,
}
impl Store {
    pub fn new(dir: PathBuf) -> Result<Self> {
        if !dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut b = fs::DirBuilder::new();
                b.recursive(true).mode(0o700);
                b.create(&dir)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(&dir)?;
        }
        let md = fs::symlink_metadata(&dir)?;
        ensure!(
            md.is_dir() && !md.file_type().is_symlink(),
            "State directory must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                md.permissions().mode() & 0o077 == 0,
                "State directory must be private (chmod 700)"
            );
        }
        Ok(Self { dir })
    }
    pub fn default_dir() -> PathBuf {
        std::env::var_os("LPASS_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("lpass-rs")
            })
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    pub fn atomic_write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(name);
        check_regular(&path)?;
        let temporary = self.path(&format!(
            ".{name}.{}",
            hex::encode(crypto::random_bytes::<8>())
        ));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&temporary)?;
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.path(name);
        check_regular(&path)?;
        ensure!(
            fs::metadata(&path)?.len() <= 64 * 1024 * 1024,
            "Local state file too large"
        );
        fs::read(path).with_context(|| format!("Missing local {name}; log in first"))
    }
    pub fn save_meta(&self, m: &Metadata) -> Result<()> {
        self.atomic_write("metadata.json", &serde_json::to_vec(m)?)
    }
    pub fn metadata(&self) -> Result<Metadata> {
        serde_json::from_slice(&self.read("metadata.json")?).context("Invalid local metadata")
    }
    pub fn save_session(&self, s: &Session, key: &[u8; 32]) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(s)?);
        self.atomic_write("session.enc", &crypto::seal(&bytes, key, b"session")?)
    }
    pub fn session(&self, key: &[u8; 32]) -> Result<Session> {
        serde_json::from_slice(&crypto::unseal(
            &self.read("session.enc")?,
            key,
            b"session",
        )?)
        .context("Invalid encrypted session")
    }
    pub fn save_vault(&self, v: &Vault, key: &[u8; 32]) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(v)?);
        self.atomic_write("vault.enc", &crypto::seal(&bytes, key, b"vault")?)
    }
    pub fn vault(&self, key: &[u8; 32]) -> Result<Vault> {
        serde_json::from_slice(&crypto::unseal(&self.read("vault.enc")?, key, b"vault")?)
            .context("No cached vault; run sync")
    }
    pub fn cache_fresh(&self, seconds: u64) -> bool {
        fs::metadata(self.path("vault.enc"))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age < Duration::from_secs(seconds))
    }
    pub fn clear(&self) -> Result<()> {
        for name in ["metadata.json", "session.enc", "vault.enc", "pending.enc"] {
            let path = self.path(name);
            check_regular(&path)?;
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
    pub fn save_pending(&self, bytes: &[u8], key: &[u8; 32]) -> Result<()> {
        self.atomic_write("pending.enc", &crypto::seal(bytes, key, b"pending")?)
    }
    pub fn pending(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        if !self.path("pending.enc").exists() {
            return Ok(Zeroizing::new(b"[]".to_vec()));
        }
        crypto::unseal(&self.read("pending.enc")?, key, b"pending")
    }
}
fn check_regular(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) => ensure!(
            m.is_file() && !m.file_type().is_symlink(),
            "Refusing symlink or non-regular state file"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
