use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use lastpass_cli::{
    blob,
    client::{LastPass, LoginOptions},
    commands::{self, EditChoice, Search},
    crypto,
    model::{Account, Field, Session, Vault},
    store::Store,
    transport::{Params, Transport, valid_server},
    xml,
};
use std::{cell::RefCell, rc::Rc};

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/vectors.json")).unwrap()
}
fn key() -> crypto::Key {
    crypto::derive_key("user@example.com", "123456", 1000).unwrap()
}
fn vault() -> Vault {
    blob::parse(include_bytes!("fixtures/legacy_vault.bin"), &key(), &[]).unwrap()
}
#[derive(Clone)]
struct Mock {
    state: Rc<RefCell<MockState>>,
}
struct MockState {
    posts: Vec<(String, String, Params)>,
    vault: Vec<u8>,
    login_error: Option<String>,
    redirect: bool,
    otp: bool,
    private: String,
    version: u64,
    reply: Option<Vec<u8>>,
}
impl Mock {
    fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(MockState {
                posts: Vec::new(),
                vault: include_bytes!("fixtures/legacy_vault.bin").to_vec(),
                login_error: None,
                redirect: false,
                otp: false,
                private: String::new(),
                version: 1,
                reply: None,
            })),
        }
    }
    fn client(&self) -> LastPass<Self> {
        LastPass::login(
            self.clone(),
            "USER@EXAMPLE.COM",
            "123456",
            LoginOptions::default(),
        )
        .unwrap()
    }
}
fn param<'a>(p: &'a Params, name: &str) -> &'a str {
    p.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}
impl Transport for Mock {
    fn post(
        &self,
        server: &str,
        page: &str,
        session_id: Option<&str>,
        p: &Params,
    ) -> Result<Vec<u8>> {
        let mut s = self.state.borrow_mut();
        s.posts.push((server.into(), page.into(), p.clone()));
        if let Some(reply) = s.reply.take() {
            return Ok(reply);
        }
        match page {
            "iterations.php"=>{ensure!(param(p,"email")=="user@example.com","Email must be normalized");Ok(b"1000".to_vec())}
            "login.php"=>{
                if s.redirect&&server=="lastpass.com" {return Ok(b"<response><error server=\"lastpass.eu\"/></response>".to_vec());}
                if let Some(message)=&s.login_error {return Ok(format!("<response><error cause=\"unknownemail\" message=\"{message}\"/></response>").into_bytes());}
                if s.otp&&param(p,"otp")!="123456" {return Ok(b"<response><error cause=\"googleauthrequired\"/></response>".to_vec());}
                if param(p,"hash")!=vectors()["login_hash"].as_str().unwrap() {return Ok(b"<response><error message=\"invalid password\"/></response>".to_vec());}
                ensure!(param(p,"iterations")=="1000"&&param(p,"method")=="cli","Login protocol mismatch");
                Ok(format!("<response><ok uid=\"57747756\" sessionid=\"1234\" token=\"abcd\" privatekeyenc=\"{}\"/></response>",s.private).into_bytes())
            }
            "getaccts.php"=>{ensure!(session_id==Some("1234"),"Missing session cookie");ensure!(param(p,"mobile")=="1","Wrong vault request");Ok(s.vault.clone())}
            "login_check.php"=>Ok(format!("<response><ok uid=\"57747756\" sessionid=\"1234\" token=\"newtoken\" accts_version=\"{}\" url_encryption=\"1\"/></response>",s.version).into_bytes()),
            "getattach.php"=>{
                let base64=STANDARD.encode(b"synthetic attachment bytes\0\xff");
                Ok(serde_json::to_vec(&crypto::encrypt_base64(&base64,&[7;32]))?)
            }
            "show_website.php"|"addapp.php"|"logout.php"|"loglogin.php"|"trust.php"=>Ok(b"<response><ok/></response>".to_vec()),
            "share.php"=>{
                if param(p,"getinfo")=="1" {return Ok(b"<xmlresponse><users><item><uid>u1</uid><username>member@example.com</username><realname>Member</realname><group>0</group><permissions><readonly>1</readonly><give>0</give><canadminister>0</canadminister></permissions><accepted>1</accepted></item></users></xmlresponse>".to_vec());}
                if param(p,"getpubkey")=="1" {return Ok(format!("<xmlresponse><uid0>57747756</uid0><username0>user@example.com</username0><pubkey0>{}</pubkey0></xmlresponse>",vectors()["public_key_der_hex"].as_str().unwrap()).into_bytes());}
                if param(p,"limit")=="1"&&param(p,"edit").is_empty(){return Ok(b"<xmlresponse><hidebydefault>1</hidebydefault><aids><aid0>0001</aid0></aids></xmlresponse>".to_vec());}
                Ok(b"<xmlresponse><success>1</success></xmlresponse>".to_vec())
            }
            "lastpass/api.php"=>{
                if param(p,"cmd")=="getacctschangepw" {
                    let data=format!("id-1\n\n{}\t1\nendmarker\n",crypto::encrypt_base64("synthetic field",&key()));
                    let data=quick_xml::escape::escape(&data);
                    return Ok(format!("<lastpass rc=\"OK\"><data token=\"change-token\" xml=\"{data}\"/></lastpass>").into_bytes());
                }
                if param(p,"cmd")=="updatepassword" {return Ok(b"<lastpass rc=\"OK\"><pwchangeok/></lastpass>".to_vec());}
                Ok(b"<lastpass rc=\"OK\"><result/></lastpass>".to_vec())
            }
            _=>bail!("Unhandled mock endpoint"),
        }
    }
}
#[test]
fn kdf_matches_independent_python_vector() {
    assert_eq!(hex::encode(*key()), vectors()["key_hex"].as_str().unwrap());
    assert_eq!(
        crypto::login_hash(&key(), "123456").as_str(),
        vectors()["login_hash"].as_str().unwrap()
    );
    assert_eq!(
        *crypto::derive_key("USER@example.COM", "123456", 1000).unwrap(),
        *key()
    );
}
#[test]
fn invalid_iteration_counts_are_rejected() {
    for n in [0, 1, 10_000_001, u32::MAX] {
        assert!(crypto::derive_key("u", "p", n).is_err());
    }
}
#[test]
fn decrypts_independent_cbc_and_ecb_vectors() {
    for name in ["cbc", "ecb"] {
        let plain = crypto::decrypt_base64(vectors()[name].as_str().unwrap(), &key()).unwrap();
        assert_eq!(plain.as_slice(), b"synthetic cipher vector");
    }
}
#[test]
fn wire_base64_and_aes_interoperability() {
    let raw = crypto::encrypt_raw(b"test with unicode: \xc3\xb6", &key());
    let encoded = crypto::wire_base64(&raw);
    assert_eq!(raw, crypto::wire_unbase64(&encoded).unwrap());
    assert_eq!(
        crypto::decrypt_base64(&encoded, &key()).unwrap().as_slice(),
        b"test with unicode: \xc3\xb6"
    );
    assert_ne!(
        encoded,
        crypto::encrypt_base64("test with unicode: ö", &key())
    );
}
#[test]
fn invalid_ciphertext_is_rejected() {
    for value in [
        "!abc|def",
        "!AAAAAAAAAAAAAAAAAAAAAA==|bad",
        "invalid base64%%",
    ] {
        assert!(crypto::decrypt_base64(value, &key()).is_err());
    }
    assert!(crypto::decrypt_raw(&[0; 15], &key()).is_err());
}
#[test]
fn private_key_v1_and_v2_match_independent_fixtures() {
    for name in ["private_key_v1", "private_key_v2"] {
        let der = crypto::decrypt_private_key(vectors()[name].as_str().unwrap(), &key()).unwrap();
        assert_eq!(
            hex::encode(&*der),
            vectors()["private_key_der_hex"].as_str().unwrap()
        );
    }
}
#[test]
fn rsa_oaep_matches_independent_shared_folder_fixture() {
    let der = hex::decode(vectors()["private_key_der_hex"].as_str().unwrap()).unwrap();
    let vault = blob::parse(include_bytes!("fixtures/shared_vault.bin"), &key(), &der).unwrap();
    assert_eq!(vault.shares.len(), 1);
    assert_eq!(vault.shares[0].name, "Shared-Team");
    assert_eq!(
        hex::encode(vault.shares[0].key),
        vectors()["share_key_hex"].as_str().unwrap()
    );
    let a = vault.accounts.iter().find(|a| a.id == "0005").unwrap();
    assert_eq!(a.fullname(), "Shared-Team/test-group/shared-account");
    assert_eq!(a.password, "test-account-password");
    assert_eq!(a.fields[0].value, "custom-value");
    assert_eq!(vault.decryption_errors, 0);
}
#[test]
fn legacy_vault_decrypts_all_four_c_reference_accounts() {
    let v = vault();
    assert_eq!(v.version, 1);
    assert_eq!(v.accounts.len(), 4);
    assert_eq!(v.decryption_errors, 0);
    assert_eq!(v.accounts[0].password, "test-account-password");
    assert!(v.accounts[2].pwprotect);
}
#[test]
fn truncated_blobs_never_panic() {
    let bytes = include_bytes!("fixtures/legacy_vault.bin");
    let test_key = key();
    for n in 0..bytes.len() {
        let result = std::panic::catch_unwind(|| blob::parse(&bytes[..n], &test_key, &[]));
        assert!(result.is_ok());
    }
    assert!(blob::parse(b"ACCT\xff\xff\xff\xff", &key(), &[]).is_err());
}
#[test]
fn unknown_chunks_are_forward_compatible() {
    let mut bytes = include_bytes!("fixtures/legacy_vault.bin").to_vec();
    blob::chunk(&mut bytes, b"ZZZZ", b"future extension");
    assert_eq!(blob::parse(&bytes, &key(), &[]).unwrap().accounts.len(), 4);
}
#[test]
fn wrong_vault_key_is_reported_instead_of_silently_succeeding() {
    let v = blob::parse(include_bytes!("fixtures/legacy_vault.bin"), &[0; 32], &[]).unwrap();
    assert!(v.decryption_errors > 0);
}
#[test]
fn blob_writer_preserves_accounts_fields_and_attachments() {
    let mut v = vault();
    v.accounts[0].fields.push(Field {
        name: "field".into(),
        kind: "text".into(),
        value: "synthetic value".into(),
        checked: false,
    });
    for encrypted_url in [false, true] {
        let encoded = blob::write(&v, &key(), encrypted_url).unwrap();
        let decoded = blob::parse(&encoded, &key(), &[]).unwrap();
        assert_eq!(decoded.accounts[0].password, v.accounts[0].password);
        assert_eq!(decoded.accounts[0].fields[0].value, "synthetic value");
        assert_eq!(decoded.accounts[0].url, v.accounts[0].url);
        assert_eq!(decoded.decryption_errors, 0);
    }
}
#[test]
fn shared_blob_writer_preserves_sharing_keys() {
    let der = hex::decode(vectors()["private_key_der_hex"].as_str().unwrap()).unwrap();
    let v = blob::parse(include_bytes!("fixtures/shared_vault.bin"), &key(), &der).unwrap();
    let bytes = blob::write(&v, &key(), true).unwrap();
    let again = blob::parse(&bytes, &key(), &der).unwrap();
    assert_eq!(again.shares[0].key, v.shares[0].key);
    assert_eq!(again.accounts[1].password, v.accounts[1].password);
}
#[test]
fn login_and_load_follow_the_c_http_protocol() {
    let mock = Mock::new();
    let c = mock.client();
    assert_eq!(c.session.username, "user@example.com");
    assert_eq!(c.load_vault().unwrap().accounts.len(), 4);
}
#[test]
fn wrong_password_login_is_rejected() {
    let mock = Mock::new();
    assert!(LastPass::login(mock, "user@example.com", "wrong", LoginOptions::default()).is_err());
}
#[test]
fn login_follows_eu_redirect_and_keeps_the_server() {
    let mock = Mock::new();
    mock.state.borrow_mut().redirect = true;
    let c = mock.client();
    assert_eq!(c.session.server, "lastpass.eu");
    assert_eq!(c.load_vault().unwrap().accounts.len(), 4);
}
#[test]
fn mfa_error_and_otp_login() {
    let mock = Mock::new();
    mock.state.borrow_mut().otp = true;
    assert!(
        LastPass::login(
            mock.clone(),
            "user@example.com",
            "123456",
            LoginOptions::default()
        )
        .is_err()
    );
    let options = LoginOptions {
        otp: Some(zeroize::Zeroizing::new("123456".into())),
        ..Default::default()
    };
    assert!(LastPass::login(mock, "user@example.com", "123456", options).is_ok());
}
#[test]
fn login_decrypts_account_private_key() {
    let mock = Mock::new();
    mock.state.borrow_mut().private = vectors()["private_key_v2"].as_str().unwrap().into();
    let c = mock.client();
    assert_eq!(
        hex::encode(&c.session.private_key),
        vectors()["private_key_der_hex"].as_str().unwrap()
    );
}
#[test]
fn session_check_updates_token_and_feature_flags() {
    let mock = Mock::new();
    let mut c = mock.client();
    assert_eq!(c.check_session().unwrap(), 1);
    assert_eq!(c.session.token, "newtoken");
    assert!(c.session.url_encryption);
}
#[test]
fn show_matches_c_account_output() {
    let v = vault();
    let output = commands::display_account(&v.accounts[0], "%aN [id: %ai]", "%fn: %fv");
    assert_eq!(
        output,
        "test-group/test-account [id: 0001]\nUsername: xyz@example.com\nPassword: test-account-password\nURL: https://test-url.example.com/\n"
    );
}
#[test]
fn show_json_has_c_reference_fields() {
    let v = vault();
    let json = v.accounts[0].json_value();
    assert_eq!(json["password"], "test-account-password");
    assert_eq!(json["fullname"], "test-group/test-account");
    assert_eq!(json["last_touch"], "skipped");
}
#[test]
fn searches_exact_id_substring_and_regex() {
    let v = vault();
    assert_eq!(
        commands::matches(&v, "0001", &Search::Exact).unwrap().len(),
        1
    );
    assert_eq!(
        commands::matches(&v, "test-group/test-account", &Search::Exact)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        commands::matches(&v, "reprompt", &Search::Substring)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        commands::matches(&v, "^test-note$", &Search::Regex)
            .unwrap()
            .len(),
        1
    );
    assert!(commands::matches(&v, "[", &Search::Regex).is_err());
}
#[test]
fn duplicate_names_need_unique_ids() {
    let mut v = vault();
    let mut a = v.accounts[0].clone();
    a.id = "new".into();
    v.accounts.push(a);
    assert!(commands::unique_index(&v, "test-account").is_err());
    assert_eq!(commands::unique_index(&v, "0001").unwrap(), 0);
}
#[test]
fn edit_regular_account_fields() {
    let v = vault();
    let mut a = v.accounts[0].clone();
    commands::edit_value(&mut a,&EditChoice::Any,"Name: changed\nUsername: new-user\nURL: example.com\nReprompt: Yes\nNotes:\nline one\nline two\n",&v).unwrap();
    assert_eq!(a.name, "changed");
    assert_eq!(a.username, "new-user");
    assert_eq!(a.url, "http://example.com");
    assert!(a.pwprotect);
    assert_eq!(a.note, "line one\nline two");
}
#[test]
fn secure_note_expansion_and_editing() {
    let v = vault();
    let mut a = v.accounts[1].clone();
    assert_eq!(a.expanded().username, "test-note-user");
    commands::edit_value(
        &mut a,
        &EditChoice::Field("Hostname".into()),
        "changed.example.com\n",
        &v,
    )
    .unwrap();
    assert_eq!(a.field_value("Hostname").unwrap(), "changed.example.com");
}
#[test]
fn secure_note_name_is_distinct_from_item_name() {
    let v = Vault::default();
    let mut a = Account::default();
    a.url = "http://sn".into();
    a.note = "NoteType:Social Security".into();
    commands::edit_value(
        &mut a,
        &EditChoice::Any,
        "Name: item-name\nName: Person Name\nNumber: 000-00-0000\n",
        &v,
    )
    .unwrap();
    assert_eq!(a.name, "item-name");
    assert_eq!(a.field_value("Name").unwrap(), "Person Name");
}
#[test]
fn ssh_private_key_headers_and_multiline_notes_are_preserved() {
    let mut a = Account::default();
    a.url = "http://sn".into();
    a.note="NoteType:SSH Key\nPrivate Key:-----BEGIN KEY-----\nProc-Type:4,ENCRYPTED\n\nabc\n-----END KEY-----\nPublic Key:ssh-test key\nNotes:line one\ntext: still notes".into();
    assert_eq!(
        a.field_value("Private Key").unwrap(),
        "-----BEGIN KEY-----\nProc-Type:4,ENCRYPTED\n\nabc\n-----END KEY-----"
    );
    assert_eq!(
        a.field_value("Notes").unwrap(),
        "line one\ntext: still notes"
    );
}
#[test]
fn password_generator_checks_lengths_and_character_classes() {
    assert!(commands::generate_password(0, true).is_err());
    for symbols in [false, true] {
        for _ in 0..20 {
            let p = commands::generate_password(30, symbols).unwrap();
            assert_eq!(p.len(), 30);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert_eq!(p.chars().any(|c| !c.is_ascii_alphanumeric()), symbols);
        }
    }
}
#[test]
fn csv_round_trip_quotes_multiline_notes() {
    let v = vault();
    let fields = "url,username,password,extra,name,grouping,fav"
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let bytes = commands::export_csv(&v, &fields).unwrap();
    let imported = commands::import_csv(&bytes, &Vault::default(), true).unwrap();
    assert_eq!(imported.len(), 4);
    assert_eq!(imported[1].note, v.accounts[1].note);
    assert_eq!(imported[0].password, v.accounts[0].password);
    assert_eq!(commands::import_csv(&bytes, &v, false).unwrap().len(), 0);
}
#[test]
fn mutations_encrypt_all_sensitive_fields() {
    let mock = Mock::new();
    let c = mock.client();
    let v = vault();
    let mut a = v.accounts[0].clone();
    a.fields.push(Field {
        name: "custom".into(),
        kind: "text".into(),
        value: "custom secret".into(),
        checked: false,
    });
    c.update_account(&a, &v).unwrap();
    let state = mock.state.borrow();
    let (_, page, p) = state.posts.last().unwrap();
    assert_eq!(page, "show_website.php");
    assert_eq!(
        crypto::text(&crypto::decrypt_base64(param(p, "password"), &key()).unwrap()),
        a.password
    );
    assert_eq!(param(p, "url"), hex::encode(&a.url));
    assert_eq!(param(p, "aid"), a.id);
    assert!(!serde_json::to_string(p).unwrap().contains("custom secret"));
}
#[test]
fn url_feature_flag_encrypts_urls() {
    let mock = Mock::new();
    let mut c = mock.client();
    c.session.url_encryption = true;
    let v = vault();
    let p = c.account_params(&v.accounts[0], &v).unwrap();
    assert_eq!(
        crypto::text(&crypto::decrypt_base64(param(&p, "url"), &key()).unwrap()),
        v.accounts[0].url
    );
}
#[test]
fn remove_upload_and_logout_use_reference_endpoints() {
    let mock = Mock::new();
    let c = mock.client();
    let v = vault();
    c.remove_account(&v.accounts[0], &v).unwrap();
    c.upload_accounts(&v.accounts, &v).unwrap();
    c.logout().unwrap();
    let s = mock.state.borrow();
    assert!(
        s.posts
            .iter()
            .any(|(_, p, v)| p == "show_website.php" && param(v, "delete") == "1")
    );
    assert!(
        s.posts
            .iter()
            .any(|(_, p, v)| p == "lastpass/api.php" && param(v, "cmd") == "uploadaccounts")
    );
    assert_eq!(s.posts.last().unwrap().1, "logout.php");
}
#[test]
fn read_only_shared_folder_updates_are_rejected() {
    let der = hex::decode(vectors()["private_key_der_hex"].as_str().unwrap()).unwrap();
    let mut v = blob::parse(include_bytes!("fixtures/shared_vault.bin"), &key(), &der).unwrap();
    v.shares[0].readonly = true;
    assert!(
        Mock::new()
            .client()
            .update_account(&v.accounts[1], &v)
            .is_err()
    );
}
#[test]
fn attachment_download_and_decryption() {
    let mut a = Account::default();
    a.attachkey = hex::encode([7; 32]);
    a.attachments.push(lastpass_cli::model::Attachment {
        id: "a1".into(),
        parent: "0001".into(),
        mimetype: "application/octet-stream".into(),
        storagekey: "storage".into(),
        size: "32".into(),
        filename: String::new(),
    });
    let value = Mock::new().client().load_attachment(&a, "att-a1").unwrap();
    assert_eq!(value.as_slice(), b"synthetic attachment bytes\0\xff");
}
#[test]
fn authenticated_cache_detects_tampering_and_wrong_labels() {
    let sealed = crypto::seal(b"synthetic secret", &key(), b"vault").unwrap();
    assert!(!sealed.windows(16).any(|b| b == b"synthetic secret"));
    assert!(crypto::unseal(&sealed, &key(), b"session").is_err());
    let mut corrupt = sealed;
    let n = corrupt.len() - 1;
    corrupt[n] ^= 1;
    assert!(crypto::unseal(&corrupt, &key(), b"vault").is_err());
}
#[test]
fn encrypted_store_round_trip_and_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let s = Store::new(dir.path().to_path_buf()).unwrap();
    s.save_vault(&vault(), &key()).unwrap();
    s.save_session(&Session::default(), &key()).unwrap();
    assert_eq!(s.vault(&key()).unwrap().accounts.len(), 4);
    assert!(s.vault(&[9; 32]).is_err());
    let bytes = std::fs::read(s.path("vault.enc")).unwrap();
    assert!(!bytes.windows(21).any(|v| v == b"test-account-password"));
}
#[cfg(unix)]
#[test]
fn state_symlinks_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let s = Store::new(dir.path().to_path_buf()).unwrap();
    let other = dir.path().join("other");
    std::fs::write(&other, b"keep").unwrap();
    symlink(&other, s.path("vault.enc")).unwrap();
    assert!(s.save_vault(&vault(), &key()).is_err());
    assert_eq!(std::fs::read(&other).unwrap(), b"keep");
}
#[test]
fn xml_entities_empty_elements_and_dtd_rejection() {
    let root =
        xml::parse(b"<response><ok token=\"a&amp;b\"/><value>A &lt; B&#10;C</value></response>")
            .unwrap();
    assert_eq!(root.find("ok").unwrap().attr("token"), "a&b");
    assert_eq!(root.find("value").unwrap().text, "A < B\nC");
    assert!(xml::parse(b"<!DOCTYPE response><response/>").is_err());
}
#[test]
fn server_errors_are_not_acknowledged_as_success() {
    for value in [
        b"<lastpass rc=\"FAIL\"><result/></lastpass>".as_slice(),
        b"<response><error message=\"denied\"/></response>",
        b"<html><body>login</body></html>",
        b"",
        b"not an acknowledgement",
    ] {
        assert!(xml::check_reply(value).is_err());
    }
}
#[test]
fn credential_destinations_are_allowlisted() {
    for s in ["lastpass.com", "lastpass.eu", "http://127.0.0.1:12345"] {
        assert!(valid_server(s));
    }
    for s in [
        "evil.example",
        "lastpass.com.evil.example",
        "https://evil.example",
        "http://127.0.0.1@evil.example",
        "http://localhost/else",
    ] {
        assert!(!valid_server(s));
    }
}
#[test]
fn sharing_admin_and_limits_follow_c_protocol() {
    let mock = Mock::new();
    let c = mock.client();
    let mut share = lastpass_cli::model::Share::default();
    share.id = "s1".into();
    share.name = "Shared-Team".into();
    share.key = [8; 32];
    let users = c.share_users(&share).unwrap();
    assert!(users[0].read_only && users[0].hide_passwords);
    let (w, a) = c.share_limits(&share, &users[0]).unwrap();
    assert!(w);
    assert_eq!(a, vec!["0001"]);
    c.share_set_limits(&share, &users[0], false, &[]).unwrap();
    c.share_modify_user(&share, &users[0]).unwrap();
    c.share_remove_user(&share, &users[0]).unwrap();
    c.share_create("New Team").unwrap();
    c.share_delete(&share).unwrap();
}
#[test]
fn password_change_prepares_reencryption_and_commits_only_explicitly() {
    let mock = Mock::new();
    let c = mock.client();
    let change = c
        .prepare_password_change("123456", "new synthetic password")
        .unwrap();
    let p = &change.parameters;
    assert_eq!(param(p, "cmd"), "updatepassword");
    assert_eq!(param(p, "token"), "change-token");
    let newkey = crypto::derive_key("user@example.com", "new synthetic password", 1000).unwrap();
    assert_eq!(param(p, "newuserkeyhexhash"), crypto::sha256_hex(&*newkey));
    let line = param(p, "reencrypt").lines().nth(1).unwrap();
    let (_, encrypted) = line.split_once(':').unwrap();
    assert_eq!(
        crypto::text(&crypto::decrypt_base64(encrypted, &newkey).unwrap()),
        "synthetic field"
    );
    c.commit_password_change(change).unwrap();
}

#[test]
fn invalid_shared_keys_are_counted_and_never_misdecrypt_items() {
    let private = hex::decode(vectors()["private_key_der_hex"].as_str().unwrap()).unwrap();
    let public = hex::decode(vectors()["public_key_der_hex"].as_str().unwrap()).unwrap();
    for length in [16, 22] {
        let mut record = Vec::new();
        let invalid_key = hex::encode(vec![7; length]);
        let encrypted = crypto::rsa_encrypt(invalid_key.as_bytes(), &public).unwrap();
        for field in [
            "invalid-folder".to_string(),
            hex::encode(encrypted),
            String::new(),
            "0".into(),
        ] {
            blob::item(&mut record, field.as_bytes());
        }
        let mut wire = Vec::new();
        blob::chunk(&mut wire, b"LPAV", b"1");
        blob::chunk(&mut wire, b"SHAR", &record);
        // Four accounts following a rejected share are not decrypted with the
        // unrelated personal key, even if that would happen to succeed.
        wire.extend_from_slice(include_bytes!("fixtures/legacy_vault.bin"));
        // A valid share resets the rejection state and can still be loaded.
        wire.extend_from_slice(include_bytes!("fixtures/shared_vault.bin"));
        let result = blob::parse(&wire, &key(), &private).unwrap();
        assert_eq!(result.unavailable_shares, 1);
        assert_eq!(result.unavailable_accounts, 5);
        assert_eq!(result.accounts.len(), 1);
        assert_eq!(result.accounts[0].name, "shared-account");
        assert_eq!(result.decryption_errors, 0);
        assert!(blob::write(&result, &key(), true).is_err());
    }
}

#[test]
fn logout_redirect_is_accepted_without_forwarding_credentials() {
    use lastpass_cli::transport::HttpTransport;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0; 4096];
            let _ = stream.read(&mut bytes).unwrap();
            stream.write_all(b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://127.0.0.1:9/untrusted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        }
    });
    let transport = HttpTransport::new().unwrap();
    assert!(
        transport
            .post(&address, "logout.php", Some("synthetic-session"), &vec![])
            .unwrap()
            .is_empty()
    );
    assert!(
        transport
            .post(&address, "login.php", None, &vec![])
            .is_err()
    );
    server.join().unwrap();
}
