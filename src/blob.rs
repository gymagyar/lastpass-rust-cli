//! Bounds-checked port of blob.c's chunked LPAV/ACCT/SHAR format.
use crate::{
    crypto,
    model::{Account, Attachment, Field, Share, Vault},
};
use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

struct Cursor<'a> {
    rest: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(count <= self.rest.len(), "Truncated vault record");
        let (value, rest) = self.rest.split_at(count);
        self.rest = rest;
        Ok(value)
    }
    fn item(&mut self) -> Result<&'a [u8]> {
        let bytes: [u8; 4] = self.take(4)?.try_into()?;
        self.take(u32::from_be_bytes(bytes) as usize)
    }
}
fn items(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut cursor = Cursor { rest: bytes };
    let mut result = Vec::new();
    while !cursor.rest.is_empty() {
        result.push(cursor.item()?);
    }
    Ok(result)
}
fn plain(v: &[u8]) -> String {
    crypto::text(v)
}
fn crypt(v: &[u8], key: &[u8; 32], errors: &mut usize) -> String {
    match crypto::decrypt_raw(v, key) {
        Ok(bytes) => crypto::text(&bytes),
        Err(_) => {
            *errors += 1;
            String::new()
        }
    }
}
fn url(v: &[u8], key: &[u8; 32], errors: &mut usize) -> Result<String> {
    if v.first() == Some(&b'!') {
        Ok(crypt(v, key, errors))
    } else {
        Ok(crypto::text(
            &hex::decode(v).context("Invalid URL hex in vault")?,
        ))
    }
}
pub fn encrypted_field(kind: &str) -> bool {
    matches!(kind, "email" | "tel" | "text" | "password" | "textarea")
}

pub fn parse(bytes: &[u8], key: &[u8; 32], private_key: &[u8]) -> Result<Vault> {
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "Vault exceeds 64 MiB limit"
    );
    let mut cursor = Cursor { rest: bytes };
    let mut vault = Vault::default();
    let mut has_version = false;
    let mut share_idx: Option<usize> = None;
    let mut unavailable_share = false;
    let mut account_idx: Option<usize> = None;
    let mut app_idx: Option<usize> = None;
    while !cursor.rest.is_empty() {
        let tag = cursor.take(4)?;
        let chunk = cursor.item()?;
        match tag {
            b"LPAV" => {
                vault.version = plain(chunk).parse().context("Invalid vault version")?;
                has_version = true;
            }
            b"ACCT" => {
                if unavailable_share {
                    vault.unavailable_accounts += 1;
                    account_idx = None;
                    continue;
                }
                let v = items(chunk)?;
                ensure!(v.len() >= 10, "Incomplete account record");
                let account_key = share_idx.map(|i| &vault.shares[i].key).unwrap_or(key);
                let errors = &mut vault.decryption_errors;
                let mut account = Account::default();
                account.id = plain(v[0]);
                account.name = crypt(v[1], account_key, errors);
                account.group = crypt(v[2], account_key, errors);
                account.url = url(v[3], account_key, errors)?;
                account.note = crypt(v[4], account_key, errors);
                account.favorite = v[5] == b"1";
                account.username = crypt(v[7], account_key, errors);
                account.password = crypt(v[8], account_key, errors);
                account.pwprotect = v[9] == b"1";
                account.last_touch = v.get(12).map(|v| plain(v)).unwrap_or_default();
                account.last_modified_gmt = v.get(31).map(|v| plain(v)).unwrap_or_default();
                account.attachpresent = v.get(27).is_some_and(|v| *v == b"1");
                if let Some(value) = v.get(26).filter(|v| !v.is_empty()) {
                    let enc = plain(value);
                    match crypto::decrypt_base64(&enc, account_key) {
                        Ok(p) => account.attachkey = crypto::text(&p),
                        Err(_) => vault.decryption_errors += 1,
                    }
                }
                if account.name.starts_with('\u{10}') {
                    account.name.clear();
                }
                if account.group.starts_with('\u{10}') {
                    account.group.clear();
                }
                if let Some(i) = share_idx {
                    account.share_id = vault.shares[i].id.clone();
                    account.share_name = vault.shares[i].name.clone();
                }
                vault.accounts.push(account);
                account_idx = Some(vault.accounts.len() - 1);
            }
            b"ACFL" | b"ACOF" | b"AACF" => {
                if unavailable_share {
                    continue;
                }
                let v = items(chunk)?;
                let is_app = tag == b"AACF";
                ensure!(
                    v.len() >= if is_app { 3 } else { 4 },
                    "Incomplete custom field record"
                );
                let i = if is_app { app_idx } else { account_idx }
                    .context("Field without parent account")?;
                let account_key = share_idx.map(|i| &vault.shares[i].key).unwrap_or(key);
                let kind = plain(v[if is_app { 2 } else { 1 }]);
                let data = v[if is_app { 1 } else { 2 }];
                let value = if is_app || encrypted_field(&kind) {
                    crypt(data, account_key, &mut vault.decryption_errors)
                } else {
                    plain(data)
                };
                vault.accounts[i].fields.push(Field {
                    name: plain(v[0]),
                    kind,
                    value,
                    checked: !is_app && v[3] == b"1",
                });
            }
            b"SHAR" => {
                let v = items(chunk)?;
                ensure!(v.len() >= 4, "Incomplete shared-folder record");
                ensure!(
                    !private_key.is_empty(),
                    "Shared folders require the account sharing private key"
                );
                let encrypted = hex::decode(v[1]).context("Invalid RSA shared-folder key hex")?;
                let key_hex = crypto::rsa_decrypt(&encrypted, private_key)?;
                let share_key = Zeroizing::new(
                    hex::decode(&*key_hex).context("Invalid decrypted shared-folder key hex")?,
                );
                if share_key.len() != 32 {
                    // share_parse() in the supplied C client returns NULL for
                    // an invalid-length key. Preserve that compatibility, but
                    // explicitly count skipped folders/items instead of trying
                    // their ciphertext with the personal vault key.
                    vault.unavailable_shares += 1;
                    share_idx = None;
                    unavailable_share = true;
                    continue;
                }
                unavailable_share = false;
                let mut share = Share::default();
                share.id = plain(v[0]);
                share.readonly = v[3] == b"1";
                share.chunk = chunk.to_vec();
                share.key.copy_from_slice(&share_key);
                share.name = crypto::text(&crypto::decrypt_base64(&plain(v[2]), &share.key)?);
                vault.shares.push(share);
                share_idx = Some(vault.shares.len() - 1);
            }
            b"AACT" => {
                if unavailable_share {
                    vault.unavailable_accounts += 1;
                    app_idx = None;
                    continue;
                }
                let v = items(chunk)?;
                ensure!(v.len() >= 15, "Incomplete application record");
                let account_key = share_idx.map(|i| &vault.shares[i].key).unwrap_or(key);
                let errors = &mut vault.decryption_errors;
                let mut account = Account::default();
                account.id = plain(v[0]);
                account.appname = crypto::text(&hex::decode(v[1])?);
                account.app_extra = crypt(v[2], account_key, errors);
                account.name = crypt(v[3], account_key, errors);
                account.group = crypt(v[4], account_key, errors);
                account.last_touch = plain(v[5]);
                account.pwprotect = v[7] == b"1";
                account.favorite = v[8] == b"1";
                account.is_app = true;
                if let Some(i) = share_idx {
                    account.share_id = vault.shares[i].id.clone();
                    account.share_name = vault.shares[i].name.clone();
                }
                vault.accounts.push(account);
                app_idx = Some(vault.accounts.len() - 1);
            }
            b"ATTA" => {
                let v = items(chunk)?;
                ensure!(v.len() >= 6, "Incomplete attachment record");
                let attach = Attachment {
                    id: plain(v[0]),
                    parent: plain(v[1]),
                    mimetype: plain(v[2]),
                    storagekey: plain(v[3]),
                    size: plain(v[4]),
                    filename: plain(v[5]),
                };
                if let Some(a) = vault.accounts.iter_mut().find(|a| a.id == attach.parent) {
                    a.attachments.push(attach);
                }
            }
            b"LOCL" => {}
            b"ENDM" => ensure!(chunk == b"OK", "Invalid vault end marker"),
            _ => {} // Forward-compatible with non-account chunks in the C client.
        }
    }
    ensure!(has_version, "Server did not return an LPAV vault blob");
    Ok(vault)
}
pub fn item(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}
pub fn chunk(output: &mut Vec<u8>, tag: &[u8; 4], bytes: &[u8]) {
    output.extend_from_slice(tag);
    item(output, bytes);
}
fn write_account(output: &mut Vec<u8>, a: &Account, key: &[u8; 32], encrypted_url: bool) {
    let mut v = Vec::<Vec<u8>>::new();
    if a.is_app {
        v = vec![
            a.id.as_bytes().to_vec(),
            hex::encode(&a.appname).into_bytes(),
            crypto::encrypt_raw(a.app_extra.as_bytes(), key),
            crypto::encrypt_raw(a.name.as_bytes(), key),
            crypto::encrypt_raw(a.group.as_bytes(), key),
            a.last_touch.as_bytes().to_vec(),
            vec![],
            if a.pwprotect {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            },
            if a.favorite {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            },
        ];
        v.resize(15, Vec::new());
    } else {
        v.resize(36, Vec::new());
        v[0] = a.id.as_bytes().to_vec();
        for (i, value) in [
            (1, &a.name),
            (2, &a.group),
            (4, &a.note),
            (7, &a.username),
            (8, &a.password),
        ] {
            v[i] = crypto::encrypt_raw(value.as_bytes(), key);
        }
        v[3] = if encrypted_url && !a.is_note() && !a.is_group() {
            crypto::encrypt_raw(a.url.as_bytes(), key)
        } else {
            hex::encode(&a.url).into_bytes()
        };
        v[5] = if a.favorite {
            b"1".to_vec()
        } else {
            b"0".to_vec()
        };
        v[9] = if a.pwprotect {
            b"1".to_vec()
        } else {
            b"0".to_vec()
        };
        v[12] = a.last_touch.as_bytes().to_vec();
        v[31] = a.last_modified_gmt.as_bytes().to_vec();
        if !a.attachkey.is_empty() {
            v[26] = crypto::encrypt_base64(&a.attachkey, key).into_bytes();
        }
        v[27] = if a.attachpresent {
            b"1".to_vec()
        } else {
            b"0".to_vec()
        };
    }
    let mut record = Vec::new();
    for value in v {
        item(&mut record, &value);
    }
    chunk(output, if a.is_app { b"AACT" } else { b"ACCT" }, &record);
    for f in &a.fields {
        let mut record = Vec::new();
        item(&mut record, f.name.as_bytes());
        let value = if a.is_app || encrypted_field(&f.kind) {
            crypto::encrypt_raw(f.value.as_bytes(), key)
        } else {
            f.value.as_bytes().to_vec()
        };
        if a.is_app {
            item(&mut record, &value);
            item(&mut record, f.kind.as_bytes());
        } else {
            item(&mut record, f.kind.as_bytes());
            item(&mut record, &value);
            item(&mut record, if f.checked { b"1" } else { b"0" });
        }
        chunk(output, if a.is_app { b"AACF" } else { b"ACFL" }, &record);
    }
    for at in &a.attachments {
        let mut record = Vec::new();
        for value in [
            &at.id,
            &at.parent,
            &at.mimetype,
            &at.storagekey,
            &at.size,
            &at.filename,
        ] {
            item(&mut record, value.as_bytes());
        }
        chunk(output, b"ATTA", &record);
    }
}
pub fn write(vault: &Vault, key: &[u8; 32], encrypted_url: bool) -> Result<Vec<u8>> {
    ensure!(
        vault.unavailable_shares == 0 && vault.decryption_errors == 0,
        "Cannot serialize an incomplete vault to the server wire format"
    );
    let mut result = Vec::new();
    chunk(&mut result, b"LPAV", vault.version.to_string().as_bytes());
    for a in vault.accounts.iter().filter(|a| a.share_id.is_empty()) {
        write_account(&mut result, a, key, encrypted_url);
    }
    for s in &vault.shares {
        if s.chunk.is_empty() {
            bail!("Missing original shared-folder wire record");
        }
        chunk(&mut result, b"SHAR", &s.chunk);
        for a in vault.accounts.iter().filter(|a| a.share_id == s.id) {
            write_account(&mut result, a, &s.key, encrypted_url);
        }
    }
    chunk(&mut result, b"ENDM", b"OK");
    Ok(result)
}
