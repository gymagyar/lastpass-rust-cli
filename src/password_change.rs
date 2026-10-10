//! Master-password rotation protocol. Tested on mocks only, never by the live test.
use crate::{
    client::LastPass,
    crypto,
    transport::{Params, Transport, params},
    xml,
};
use anyhow::{Context, Result, ensure};
use zeroize::Zeroizing;
pub struct PasswordChange {
    pub parameters: Zeroizing<Params>,
}
impl<T: Transport> LastPass<T> {
    pub fn prepare_password_change(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<PasswordChange> {
        ensure!(new_password.len() >= 8, "New master password is too short");
        let derived = crypto::derive_key(
            &self.session.username,
            old_password,
            self.session.iterations,
        )?;
        ensure!(
            *derived == *self.key,
            "Current master password is incorrect"
        );
        let old_hash = crypto::login_hash(&self.key, old_password);
        let new_key = crypto::derive_key(
            &self.session.username,
            new_password,
            self.session.iterations,
        )?;
        let new_hash = crypto::login_hash(&new_key, new_password);
        let p = Zeroizing::new(params(&[
            ("cmd", "getacctschangepw"),
            ("username", &self.session.username),
            ("hash", &old_hash),
            ("changepw", "1"),
            ("changepw2", "1"),
            ("includersaprivatekeyenc", "1"),
            ("changeun", ""),
            ("resetrsakeys", "0"),
            ("includeendmarker", "1"),
        ]));
        let reply = Zeroizing::new(self.post("lastpass/api.php", &p)?);
        xml::check_reply(&reply)?;
        let root = xml::parse(&reply)?;
        let data = root.find("data").context("Missing password-change data")?;
        let xml = data.attr("xml");
        let mut lines = xml.lines();
        let reencrypt_id = lines.next().context("Missing re-encryption ID")?;
        let private_enc = lines
            .next()
            .context("Missing sharing-key re-encryption data")?;
        let private = crypto::decrypt_private_key(private_enc, &self.key)?;
        ensure!(
            *private == self.session.private_key,
            "Server and session sharing keys do not match; sync first"
        );
        let new_private = crypto::encrypt_private_key(&private, &new_key);
        let mut replacements = Zeroizing::new(format!("{reencrypt_id}\n"));
        let mut endmarker = false;
        for line in lines {
            if line.starts_with("endmarker") {
                endmarker = true;
                break;
            }
            if line.is_empty() {
                continue;
            }
            let (encrypted, optional) = line
                .split_once('\t')
                .map(|(v, flag)| (v, flag == "0"))
                .unwrap_or((line, false));
            let plain = match crypto::decrypt_base64(encrypted, &self.key) {
                Ok(p) => p,
                Err(e) if !optional => {
                    return Err(e.context(
                        "Required vault field could not be decrypted; password unchanged",
                    ));
                }
                Err(_) => Zeroizing::new(b" ".to_vec()),
            };
            let plain = Zeroizing::new(crypto::text(&plain));
            replacements.push_str(encrypted);
            replacements.push(':');
            replacements.push_str(&crypto::encrypt_base64(&plain, &new_key));
            replacements.push('\n');
        }
        ensure!(
            endmarker,
            "Incomplete password-change response; password unchanged"
        );
        let mut p = Zeroizing::new(params(&[
            ("cmd", "updatepassword"),
            ("pwupdate", "1"),
            ("email", &self.session.username),
            ("token", &data.attr("token")),
            ("reencrypt", &replacements),
            ("newprivatekeyenc", &new_private),
            ("newuserkeyhexhash", &crypto::sha256_hex(&*new_key)),
            (
                "newprivatekeyenchexhash",
                &crypto::sha256_hex(new_private.as_bytes()),
            ),
            ("newpasswordhash", &new_hash),
            ("key_iterations", &self.session.iterations.to_string()),
            (
                "encrypted_username",
                &crypto::encrypt_base64(&self.session.username, &new_key),
            ),
            ("origusername", &self.session.username),
            ("wxhash", &old_hash),
        ]));
        let mut count = 0;
        loop {
            let uid = data.attr(&format!("suuid{count}"));
            let key = data.attr(&format!("sukey{count}"));
            if uid.is_empty() && key.is_empty() {
                break;
            }
            let public = hex::decode(key).context("Invalid recovery public key")?;
            ensure!(
                !uid.is_empty() && !public.is_empty(),
                "Invalid recovery-key record"
            );
            p.push((format!("suuid{count}"), uid));
            p.push((
                format!("sukey{count}"),
                hex::encode(crypto::rsa_encrypt(&*new_key, &public)?),
            ));
            count += 1;
        }
        ensure!(
            !data.attr("token").is_empty(),
            "Missing password-change token"
        );
        p.push(("sukeycnt".into(), count.to_string()));
        Ok(PasswordChange { parameters: p })
    }
    pub fn commit_password_change(&self, change: PasswordChange) -> Result<()> {
        let reply = Zeroizing::new(self.post("lastpass/api.php", &change.parameters)?);
        ensure!(
            std::str::from_utf8(&reply)?.contains("pwchangeok"),
            "LastPass did not confirm the password change"
        );
        Ok(())
    }
}
