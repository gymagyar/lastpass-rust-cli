//! Rust equivalents of endpoints.c / endpoints-login.c. No C client is invoked.
use crate::{
    blob,
    crypto::{self, Key},
    model::{Account, Session, Vault},
    transport::{Params, Transport, params},
    xml,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

pub struct LoginOptions {
    pub server: String,
    pub otp: Option<Zeroizing<String>>,
    pub trusted_id: Option<String>,
    pub trust_label: Option<String>,
    pub wait_for_approval: bool,
}
impl Default for LoginOptions {
    fn default() -> Self {
        Self {
            server: "lastpass.com".into(),
            otp: None,
            trusted_id: None,
            trust_label: None,
            wait_for_approval: false,
        }
    }
}
pub struct LastPass<T: Transport> {
    pub transport: T,
    pub session: Session,
    pub key: Key,
}
impl<T: Transport> LastPass<T> {
    pub fn login(
        transport: T,
        username: &str,
        password: &str,
        options: LoginOptions,
    ) -> Result<Self> {
        let username = username.to_lowercase();
        ensure!(!username.is_empty(), "Username must not be empty");
        let mut server = options.server.clone();
        let response = transport.post(
            &server,
            "iterations.php",
            None,
            &params(&[("email", &username)]),
        )?;
        let mut iterations = std::str::from_utf8(&response)?
            .trim()
            .parse::<u32>()
            .context("LastPass did not return an iteration count")?;
        let mut key = crypto::derive_key(&username, password, iterations)?;
        let mut p = Zeroizing::new(params(&[
            ("xml", "2"),
            ("username", &username),
            ("hash", &crypto::login_hash(&key, password)),
            ("iterations", &iterations.to_string()),
            ("includeprivatekeyenc", "1"),
            ("method", "cli"),
            ("outofbandsupported", "1"),
        ]));
        if let Some(uuid) = &options.trusted_id {
            p.push(("uuid".into(), uuid.clone()));
        }
        if let Some(label) = &options.trust_label {
            p.push(("trustlabel".into(), label.clone()));
        }
        if let Some(otp) = &options.otp {
            p.push(("otp".into(), otp.to_string()));
        }
        let mut redirects = 0;
        let mut iteration_changes = 0;
        for _ in 0..120 {
            let reply = Zeroizing::new(transport.post(&server, "login.php", None, &p)?);
            let root = xml::parse(&reply).context("LastPass returned an invalid login response")?;
            if let Some(ok) = root.find("ok") {
                let mut session = Session::default();
                session.username = username.clone();
                session.uid = ok.attr("uid");
                session.sessionid = ok.attr("sessionid");
                session.token = ok.attr("token");
                session.server = server.clone();
                session.iterations = iterations;
                session.url_encryption = ok.attr("url_encryption") == "1";
                session.url_logging = ok.attr("url_logging") == "1";
                ensure!(
                    !session.uid.is_empty()
                        && !session.sessionid.is_empty()
                        && !session.token.is_empty(),
                    "Incomplete LastPass login session"
                );
                session.private_key =
                    crypto::decrypt_private_key(&ok.attr("privatekeyenc"), &key)?.to_vec();
                let client = Self {
                    transport,
                    session,
                    key,
                };
                if let (Some(uuid), Some(label)) = (&options.trusted_id, &options.trust_label) {
                    let reply = client.post(
                        "trust.php",
                        &params(&[
                            ("token", &client.session.token),
                            ("uuid", uuid),
                            ("trustlabel", label),
                        ]),
                    )?;
                    if !reply.is_empty() {
                        xml::check_reply(&reply)?;
                    }
                }
                return Ok(client);
            }
            let error = root
                .find("error")
                .context("Missing login success/error element")?;
            let next = error.attr("server");
            if !next.is_empty() {
                ensure!(
                    next == "lastpass.eu" && redirects < 2,
                    "Unsupported login server redirect"
                );
                server = next;
                redirects += 1;
                continue;
            }
            let changed = error.attr("iterations");
            if !changed.is_empty() && changed.parse::<u32>().ok() != Some(iterations) {
                ensure!(iteration_changes < 2, "Too many iteration-count changes");
                iterations = changed.parse().context("Invalid updated iteration count")?;
                key = crypto::derive_key(&username, password, iterations)?;
                set_param(
                    &mut p,
                    "hash",
                    crypto::login_hash(&key, password).to_string(),
                );
                set_param(&mut p, "iterations", iterations.to_string());
                iteration_changes += 1;
                continue;
            }
            let cause = error.attr("cause");
            if cause == "outofbandrequired" && options.wait_for_approval {
                set_param(&mut p, "outofbandrequest", "1".into());
                let retry = error.attr("retryid");
                if !retry.is_empty() {
                    set_param(&mut p, "outofbandretry", "1".into());
                    set_param(&mut p, "outofbandretryid", retry);
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            if matches!(
                cause.as_str(),
                "googleauthrequired"
                    | "otprequired"
                    | "sesameotprequired"
                    | "microsoftauthrequired"
                    | "outofbandrequired"
            ) {
                bail!(
                    "MFA required ({cause}); supply --otp or --out-of-band and approve the request"
                );
            }
            bail!(
                "Login failed: {}",
                xml::error_message(&root).unwrap_or_else(|| "Unknown LastPass error".into())
            );
        }
        bail!("MFA approval timed out")
    }
    pub fn post(&self, page: &str, p: &Params) -> Result<Vec<u8>> {
        self.transport
            .post(&self.session.server, page, Some(&self.session.sessionid), p)
    }
    pub fn load_vault(&self) -> Result<Vault> {
        let bytes = Zeroizing::new(self.post(
            "getaccts.php",
            &params(&[
                ("mobile", "1"),
                ("requestsrc", "cli"),
                ("hasplugin", "1.6.1"),
            ]),
        )?);
        blob::parse(&bytes, &self.key, &self.session.private_key)
    }
    pub fn check_session(&mut self) -> Result<u64> {
        let bytes = Zeroizing::new(self.post("login_check.php", &params(&[("method", "cli")]))?);
        let root = xml::parse(&bytes)?;
        if let Some(error) = xml::error_message(&root) {
            bail!("Session invalid: {error}");
        }
        let ok = root
            .find("ok")
            .context("LastPass session has expired; log in again")?;
        for name in ["uid", "token", "sessionid"] {
            let value = ok.attr(name);
            if value.is_empty() {
                continue;
            }
            match name {
                "uid" => self.session.uid = value,
                "token" => self.session.token = value,
                _ => self.session.sessionid = value,
            }
        }
        if ok.attrs.contains_key("url_encryption") {
            self.session.url_encryption = ok.attr("url_encryption") == "1";
        }
        if ok.attrs.contains_key("url_logging") {
            self.session.url_logging = ok.attr("url_logging") == "1";
        }
        ok.attr("accts_version")
            .parse()
            .context("Missing account version in session check")
    }
    pub fn logout(&self) -> Result<()> {
        let reply = self.post(
            "logout.php",
            &params(&[
                ("method", "cli"),
                ("noredirect", "1"),
                ("token", &self.session.token),
            ]),
        )?;
        if !reply.is_empty() {
            xml::check_reply(&reply)?;
        }
        Ok(())
    }
    pub fn account_key<'a>(&'a self, a: &Account, vault: &'a Vault) -> Result<&'a [u8; 32]> {
        if a.share_id.is_empty() {
            return Ok(&self.key);
        }
        let s = vault
            .shares
            .iter()
            .find(|s| s.id == a.share_id)
            .context("Missing shared-folder key")?;
        Ok(&s.key)
    }
    pub fn ensure_writable(&self, a: &Account, vault: &Vault) -> Result<()> {
        ensure!(
            !vault
                .shares
                .iter()
                .any(|s| s.id == a.share_id && s.readonly),
            "Shared folder is read-only"
        );
        Ok(())
    }
    pub fn account_params(&self, a: &Account, vault: &Vault) -> Result<Params> {
        self.ensure_writable(a, vault)?;
        let key = self.account_key(a, vault)?;
        let mut p = params(&[
            ("extjs", "1"),
            ("token", &self.session.token),
            ("method", "cli"),
            ("name", &crypto::encrypt_base64(&a.name, key)),
            ("grouping", &crypto::encrypt_base64(&a.group, key)),
            ("pwprotect", if a.pwprotect { "on" } else { "off" }),
            ("fav", if a.favorite { "1" } else { "0" }),
        ]);
        if !a.share_id.is_empty() {
            p.push(("sharedfolderid".into(), a.share_id.clone()));
        }
        if a.is_app {
            p.extend(params(&[
                ("ajax", "1"),
                ("cmd", "updatelpaa"),
                ("appname", &a.appname),
            ]));
            if a.id != "0" {
                p.push(("appaid".into(), a.id.clone()));
            }
            for (i, f) in a.fields.iter().enumerate() {
                p.push((format!("fieldid{i}"), f.name.clone()));
                p.push((format!("fieldtype{i}"), f.kind.clone()));
                p.push((
                    format!("fieldvalue{i}"),
                    crypto::encrypt_base64(&f.value, key),
                ));
            }
            return Ok(p);
        }
        p.extend(params(&[
            ("aid", &a.id),
            ("username", &crypto::encrypt_base64(&a.username, key)),
            ("password", &crypto::encrypt_base64(&a.password, key)),
            ("extra", &crypto::encrypt_base64(&a.note, key)),
        ]));
        p.push((
            "url".into(),
            if self.session.url_encryption && !a.is_note() && !a.is_group() {
                crypto::encrypt_base64(&a.url, key)
            } else {
                hex::encode(&a.url)
            },
        ));
        if self.session.url_logging {
            p.push(("recordUrl".into(), hex::encode(&a.url)));
        }
        if !a.fields.is_empty() {
            let mut fields = String::new();
            for f in &a.fields {
                let value = if blob::encrypted_field(&f.kind) {
                    crypto::encrypt_base64(&f.value, key)
                } else if matches!(f.kind.as_str(), "checkbox" | "radio") {
                    format!("{}-{}", f.value, if f.checked { 1 } else { 0 })
                } else {
                    f.value.clone()
                };
                fields.push_str(&format!(
                    "0\t{}\t{}\t{}\n",
                    escape(&f.name),
                    escape(&value),
                    escape(&f.kind)
                ));
            }
            fields.push_str("0\taction\t\taction\n0\tmethod\t\tmethod\n");
            p.push(("save_all".into(), "1".into()));
            p.push(("data".into(), hex::encode(fields)));
        }
        Ok(p)
    }
    pub fn update_account(&self, a: &Account, vault: &Vault) -> Result<()> {
        let p = Zeroizing::new(self.account_params(a, vault)?);
        let reply = Zeroizing::new(self.post(
            if a.is_app {
                "addapp.php"
            } else {
                "show_website.php"
            },
            &p,
        )?);
        xml::check_reply(&reply)
    }
    pub fn remove_account(&self, a: &Account, vault: &Vault) -> Result<()> {
        self.ensure_writable(a, vault)?;
        let mut p = params(&[
            ("extjs", "1"),
            ("token", &self.session.token),
            ("delete", "1"),
            ("aid", &a.id),
        ]);
        if !a.share_id.is_empty() {
            p.push(("sharedfolderid".into(), a.share_id.clone()));
        }
        if self.session.url_logging {
            p.push(("recordUrl".into(), hex::encode(&a.url)));
        }
        xml::check_reply(&self.post("show_website.php", &p)?)
    }
    pub fn log_access(&self, a: &Account) -> Result<()> {
        let mut p = params(&[("id", &a.id), ("method", "cli")]);
        if !a.share_id.is_empty() {
            p.push(("sharedfolderid".into(), a.share_id.clone()));
        }
        if self.session.url_logging {
            p.push(("recordUrl".into(), hex::encode(&a.url)));
        }
        let reply = self.post("loglogin.php", &p)?;
        if !reply.is_empty() {
            xml::check_reply(&reply)?;
        }
        Ok(())
    }
    pub fn load_attachment(&self, a: &Account, attach_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let attach = a
            .attachments
            .iter()
            .find(|at| at.id == attach_id || format!("att-{}", at.id) == attach_id)
            .context("Attachment not found")?;
        let key = Zeroizing::new(hex::decode(&a.attachkey).context("Invalid attachment key")?);
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .context("Missing attachment AES key")?;
        let mut p = params(&[
            ("token", &self.session.token),
            ("getattach", &attach.storagekey),
        ]);
        if !a.share_id.is_empty() {
            p.push(("sharedfolderid".into(), a.share_id.clone()));
        }
        let reply = Zeroizing::new(self.post("getattach.php", &p)?);
        let value = std::str::from_utf8(&reply)?.trim();
        let ciphertext = if value.starts_with('"') {
            serde_json::from_str::<String>(value)?
        } else {
            value.into()
        };
        let base64 = crypto::decrypt_base64(&ciphertext, key)?;
        Ok(Zeroizing::new(
            STANDARD
                .decode(&*base64)
                .context("Invalid attachment payload base64")?,
        ))
    }
    pub fn upload_accounts(&self, accounts: &[Account], vault: &Vault) -> Result<()> {
        if accounts.is_empty() {
            return Ok(());
        }
        let mut p = params(&[("token", &self.session.token), ("cmd", "uploadaccounts")]);
        for (i, a) in accounts.iter().enumerate() {
            ensure!(
                a.share_id.is_empty(),
                "Bulk import into shared folders is not supported; use add"
            );
            let key = self.account_key(a, vault)?;
            for (name, value) in [
                ("name", &a.name),
                ("grouping", &a.group),
                ("username", &a.username),
                ("password", &a.password),
                ("extra", &a.note),
            ] {
                p.push((format!("{name}{i}"), crypto::encrypt_base64(value, key)));
            }
            p.push((
                format!("url{i}"),
                if self.session.url_encryption && !a.is_note() {
                    crypto::encrypt_base64(&a.url, key)
                } else {
                    hex::encode(&a.url)
                },
            ));
            p.push((
                format!("fav{i}"),
                if a.favorite { "1".into() } else { "0".into() },
            ));
            if self.session.url_logging {
                p.push((format!("recordUrl{i}"), hex::encode(&a.url)));
            }
        }
        let p = Zeroizing::new(p);
        let reply = Zeroizing::new(self.post("lastpass/api.php", &p)?);
        xml::check_reply(&reply)
    }
    pub fn move_shared(&self, a: &Account, original_share_id: &str, vault: &Vault) -> Result<()> {
        let normal = self.account_params(a, vault)?;
        let mut p = params(&[
            ("token", &self.session.token),
            ("cmd", "uploadaccounts"),
            ("todelete", &a.id),
        ]);
        for (k, v) in &normal {
            if matches!(
                k.as_str(),
                "aid"
                    | "name"
                    | "grouping"
                    | "url"
                    | "username"
                    | "password"
                    | "extra"
                    | "pwprotect"
            ) {
                p.push((format!("{k}0"), v.clone()));
            }
        }
        if !a.share_id.is_empty() {
            p.push(("sharedfolderid".into(), a.share_id.clone()));
        }
        if !original_share_id.is_empty() {
            p.push(("origsharedfolderid".into(), original_share_id.into()));
        }
        if self.session.url_logging {
            p.push(("recordUrl".into(), hex::encode(&a.url)));
        }
        let p = Zeroizing::new(p);
        xml::check_reply(&self.post("lastpass/api.php", &p)?)
    }
}
fn set_param(p: &mut Params, name: &str, value: String) {
    if let Some((_, v)) = p.iter_mut().find(|(k, _)| k == name) {
        *v = value;
    } else {
        p.push((name.into(), value));
    }
}
fn escape(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}
