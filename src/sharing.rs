//! Shared folder administration, matching endpoints-share.c.
use crate::{
    client::LastPass,
    crypto,
    model::Share,
    transport::{Params, Transport, params},
    xml,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ShareUser {
    pub uid: String,
    pub username: String,
    pub realname: String,
    pub cgid: String,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub admin: bool,
    pub is_group: bool,
    pub outside_enterprise: bool,
    pub accepted: bool,
    #[serde(skip)]
    pub public_key: Vec<u8>,
}
impl ShareUser {
    pub fn id(&self) -> String {
        if self.is_group {
            format!("group:{}", self.uid)
        } else {
            self.uid.clone()
        }
    }
}
impl<T: Transport> LastPass<T> {
    pub fn share_users(&self, share: &Share) -> Result<Vec<ShareUser>> {
        let reply = self.post(
            "share.php",
            &params(&[
                ("sharejs", "1"),
                ("getinfo", "1"),
                ("id", &share.id),
                ("xmlr", "1"),
            ]),
        )?;
        let root = xml::parse(&reply)?;
        if let Some(error) = xml::error_message(&root) {
            anyhow::bail!("{error}");
        }
        let users = root.find("users").context("Missing shared-folder users")?;
        let mut result = Vec::new();
        for n in &users.children {
            if n.name != "item" {
                continue;
            }
            let permissions = n.find("permissions");
            let p = |name: &str| permissions.map(|p| p.value(name) == "1").unwrap_or(false);
            result.push(ShareUser {
                uid: n.value("uid"),
                username: n.value("username"),
                realname: n.value("realname"),
                is_group: n.value("group") == "1",
                outside_enterprise: n.value("outsideenterprise") == "1",
                accepted: n.value("accepted") == "1",
                read_only: p("readonly"),
                hide_passwords: !p("give"),
                admin: p("canadminister"),
                ..ShareUser::default()
            });
        }
        Ok(result)
    }
    fn share_public_keys(&self, user: &str) -> Result<Vec<ShareUser>> {
        let uid = serde_json::json!({user:{}}).to_string();
        let reply = self.post(
            "share.php",
            &params(&[
                ("token", &self.session.token),
                ("getpubkey", "1"),
                ("uid", &uid),
                ("xmlr", "1"),
            ]),
        )?;
        let root = xml::parse(&reply)?;
        if let Some(error) = xml::error_message(&root) {
            anyhow::bail!("{error}");
        }
        let mut result = Vec::new();
        for i in 0..1000 {
            let uid = root.value(&format!("uid{i}"));
            if uid.is_empty() {
                break;
            }
            result.push(ShareUser {
                uid,
                username: root.value(&format!("username{i}")),
                cgid: root.value(&format!("cgid{i}")),
                public_key: hex::decode(root.value(&format!("pubkey{i}")))
                    .context("Invalid share public key")?,
                ..ShareUser::default()
            });
        }
        ensure!(!result.is_empty(), "No sharing identity found");
        Ok(result)
    }
    fn share_post(&self, p: &Params) -> Result<()> {
        let reply = self.post("share.php", p)?;
        xml::check_reply(&reply)
    }
    pub fn share_add_user(&self, share: &Share, user: &ShareUser) -> Result<()> {
        for identity in self.share_public_keys(&user.username)? {
            let mut p = params(&[
                ("token", &self.session.token),
                ("id", &share.id),
                ("update", "1"),
                ("add", "1"),
                ("notify", "1"),
                (
                    "sharename",
                    &crypto::encrypt_base64(&share.name, &share.key),
                ),
                ("name", &share.name),
                ("readonly", bool_text(user.read_only)),
                ("give", bool_text(!user.hide_passwords)),
                ("canadminister", bool_text(user.admin)),
                ("xmlr", "1"),
            ]);
            if identity.public_key.is_empty() {
                p.extend(params(&[
                    ("msfusername0", &identity.username),
                    ("msfcgid0", &identity.cgid),
                    ("msfreadonly0", bool_text(user.read_only)),
                    ("msfgive0", bool_text(!user.hide_passwords)),
                    ("msfcanadminister0", bool_text(user.admin)),
                ]));
            } else {
                let key_hex = Zeroizing::new(hex::encode(share.key));
                let encrypted = crypto::rsa_encrypt(key_hex.as_bytes(), &identity.public_key)?;
                p.extend(params(&[
                    ("username0", &identity.username),
                    ("cgid0", &identity.cgid),
                    ("sharekey0", &hex::encode(encrypted)),
                ]));
            }
            self.share_post(&p)?;
        }
        Ok(())
    }
    pub fn share_modify_user(&self, share: &Share, user: &ShareUser) -> Result<()> {
        self.share_post(&params(&[
            ("token", &self.session.token),
            ("id", &share.id),
            ("up", "1"),
            ("edituser", "1"),
            ("uid", &user.id()),
            ("readonly", if user.read_only { "on" } else { "" }),
            ("give", if !user.hide_passwords { "on" } else { "" }),
            ("canadminister", if user.admin { "on" } else { "" }),
            ("xmlr", "1"),
        ]))
    }
    pub fn share_remove_user(&self, share: &Share, user: &ShareUser) -> Result<()> {
        self.share_post(&params(&[
            ("token", &self.session.token),
            ("id", &share.id),
            ("update", "1"),
            ("delete", "1"),
            ("uid", &user.id()),
            ("xmlr", "1"),
        ]))
    }
    pub fn share_create(&self, name: &str) -> Result<()> {
        let name = format!("Shared-{}", name.strip_prefix("Shared-").unwrap_or(name));
        let me = self
            .share_public_keys(&self.session.uid)?
            .into_iter()
            .next()
            .context("Missing own sharing public key")?;
        let username = format!("{}-{name}", me.username).replace(' ', "_");
        let key = Zeroizing::new(crypto::random_bytes::<32>());
        let key_hex = Zeroizing::new(hex::encode(*key));
        let first = crypto::sha256_hex(
            format!("{}{}", username.to_lowercase(), key_hex.as_str()).as_bytes(),
        );
        let hash = crypto::sha256_hex(format!("{first}{}", key_hex.as_str()).as_bytes());
        self.share_post(&params(&[
            ("token", &self.session.token),
            ("id", "0"),
            ("update", "1"),
            ("newusername", &username),
            ("newhash", &hash),
            (
                "sharekey",
                &hex::encode(crypto::rsa_encrypt(key_hex.as_bytes(), &me.public_key)?),
            ),
            ("name", &name),
            ("sharename", &crypto::encrypt_base64(&name, &key)),
            ("xmlr", "1"),
        ]))
    }
    pub fn share_delete(&self, share: &Share) -> Result<()> {
        self.share_post(&params(&[
            ("token", &self.session.token),
            ("id", &share.id),
            ("delete", "1"),
            ("xmlr", "1"),
        ]))
    }
    pub fn share_limits(&self, share: &Share, user: &ShareUser) -> Result<(bool, Vec<String>)> {
        let root = xml::parse(&self.post(
            "share.php",
            &params(&[
                ("token", &self.session.token),
                ("id", &share.id),
                ("limit", "1"),
                ("uid", &user.uid),
                ("xmlr", "1"),
            ]),
        )?)?;
        if let Some(error) = xml::error_message(&root) {
            anyhow::bail!("{error}");
        }
        let aids = root
            .find("aids")
            .map(|n| {
                n.children
                    .iter()
                    .filter(|n| n.name.starts_with("aid"))
                    .map(|n| n.text.clone())
                    .collect()
            })
            .unwrap_or_default();
        Ok((root.value("hidebydefault") == "1", aids))
    }
    pub fn share_set_limits(
        &self,
        share: &Share,
        user: &ShareUser,
        whitelist: bool,
        aids: &[String],
    ) -> Result<()> {
        self.share_post(&params(&[
            ("token", &self.session.token),
            ("id", &share.id),
            ("limit", "1"),
            ("edit", "1"),
            ("uid", &user.uid),
            ("numaids", &aids.len().to_string()),
            ("hidebydefault", bool_text(whitelist)),
            ("aids", &aids.join(",")),
            ("xmlr", "1"),
        ]))
    }
}
fn bool_text(v: bool) -> &'static str {
    if v { "1" } else { "0" }
}
