//! End-to-end binary tests, with an isolated synthetic vault and loopback server.
use lastpass_cli::{
    blob, crypto,
    model::Session,
    store::{Metadata, Store},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct Fixture {
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        let key = crypto::derive_key("user@example.com", "123456", 1000).unwrap();
        let mut session = Session::default();
        session.username = "user@example.com".into();
        session.iterations = 1000;
        session.uid = "57747756".into();
        session.sessionid = "1234".into();
        session.token = "abcd".into();
        session.server = "lastpass.com".into();
        let metadata = Metadata {
            username: session.username.clone(),
            iterations: 1000,
            timeout: 900,
            refresh: 300,
            agent_token: hex::encode([0; 32]),
            trusted_id: None,
        };
        store.save_meta(&metadata).unwrap();
        store.save_session(&session, &key).unwrap();
        let vault = blob::parse(include_bytes!("fixtures/legacy_vault.bin"), &key, &[]).unwrap();
        store.save_vault(&vault, &key).unwrap();
        Self { dir }
    }
    fn run(&self, args: &[&str], input: &str) -> Output {
        self.run_env(args, input, Some("123456"))
    }
    fn run_env(&self, args: &[&str], input: &str, password: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lpass-rs"));
        command
            .arg("--data-dir")
            .arg(self.dir.path())
            .args(args)
            .env_remove("LPASS_PASSWORD")
            .env_remove("LPASS_TEST_PASSWORD")
            .env_remove("LPASS_TEST_USERNAME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(password) = password {
            command.env("LPASS_PASSWORD", password);
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
    fn ok(&self, args: &[&str], input: &str) -> String {
        let output = self.run(args, input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.run_env(&["logout", "--force"], "", None);
    }
}

#[test]
fn cli_lists_c_reference_fixture() {
    let f = Fixture::new();
    assert_eq!(
        f.ok(&["ls", "--sync=no"], ""),
        "test-group/test-account [id: 0001]\ntest-group/test-note [id: 0002]\ntest-group/test-reprompt-account [id: 0003]\ntest-group/test-reprompt-note [id: 0004]\n"
    );
}
#[test]
fn cli_shows_fields_and_json() {
    let f = Fixture::new();
    assert_eq!(
        f.ok(&["show", "--sync=no", "--username", "0001"], ""),
        "xyz@example.com\n"
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "0001"], ""),
        "test-account-password\n"
    );
    let value: serde_json::Value =
        serde_json::from_str(&f.ok(&["show", "--sync=no", "--json", "0001"], "")).unwrap();
    assert_eq!(value[0]["id"], "0001");
}
#[test]
fn cli_reprompt_requires_the_correct_master_password() {
    let f = Fixture::new();
    assert!(
        f.run_env(
            &["show", "--sync=no", "--password", "0003"],
            "",
            Some("wrong")
        )
        .status
        .code()
            == Some(1)
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "0003"], ""),
        "test-account-password\n"
    );
}
#[test]
fn cli_add_and_edit_regular_item_offline() {
    let f = Fixture::new();
    f.ok(&["add","--sync=no","--non-interactive","new-item"],"Name: new-item\nURL: example.com\nUsername: new-user\nPassword: new-pass\nNotes:\nfirst\nsecond\n");
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "new-item"], ""),
        "new-pass\n"
    );
    f.ok(
        &[
            "edit",
            "--sync=no",
            "--username",
            "--non-interactive",
            "new-item",
        ],
        "changed-user\n",
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--username", "new-item"], ""),
        "changed-user\n"
    );
}
#[test]
fn cli_add_social_security_note_and_field() {
    let f = Fixture::new();
    f.ok(
        &[
            "add",
            "--sync=no",
            "--note-type=ssn",
            "--non-interactive",
            "note",
        ],
        "Name: note\nName: Person Name\nNumber: 000-00-0000\n",
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--field=Number", "note"], ""),
        "000-00-0000\n"
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--field=Name", "note"], ""),
        "Person Name\n"
    );
}
#[test]
fn cli_ssh_multiline_private_key_add_and_edit() {
    let f = Fixture::new();
    let key = "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,1234\n\nabc\n-----END EC PRIVATE KEY-----";
    let input =
        format!("Name: ssh\nHostname: server\nPrivate Key: {key}\nPublic Key: ssh-test key\n");
    f.ok(
        &[
            "add",
            "--sync=no",
            "--note-type=ssh-key",
            "--non-interactive",
            "ssh",
        ],
        &input,
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--field=Private Key", "ssh"], ""),
        format!("{key}\n")
    );
    f.ok(
        &[
            "edit",
            "--sync=no",
            "--field=Private Key",
            "--non-interactive",
            "ssh",
        ],
        &format!("{key}\n"),
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--field=Private Key", "ssh"], ""),
        format!("{key}\n")
    );
}
#[test]
fn cli_duplicate_generate_move_and_remove_offline() {
    let f = Fixture::new();
    f.ok(&["duplicate", "--sync=no", "0001"], "");
    assert_eq!(f.ok(&["ls", "--sync=no"], "").lines().count(), 5);
    f.ok(&["generate", "--sync=no", "generated", "30"], "");
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "generated"], "")
            .trim()
            .len(),
        30
    );
    f.ok(&["mv", "--sync=no", "generated", "new-group"], "");
    assert!(
        f.ok(&["ls", "--sync=no"], "")
            .contains("new-group/generated")
    );
    f.ok(&["rm", "--sync=no", "generated"], "");
    assert!(!f.ok(&["ls", "--sync=no"], "").contains("generated"));
}
#[test]
fn cli_edit_reprompt_and_secure_note_field() {
    let f = Fixture::new();
    f.ok(
        &["edit", "--sync=no", "--non-interactive", "0003"],
        "Reprompt: No\n",
    );
    assert!(
        !f.ok(&["show", "--sync=no", "0003"], "")
            .contains("Reprompt:")
    );
    f.ok(
        &[
            "edit",
            "--sync=no",
            "--field=Hostname",
            "--non-interactive",
            "0002",
        ],
        "changed.example.com\n",
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--field=Hostname", "0002"], ""),
        "changed.example.com\n"
    );
}
#[test]
fn cli_export_contains_all_items_and_multiline_notes() {
    let f = Fixture::new();
    let csv = f.ok(&["export", "--sync=no"], "");
    let mut r = csv::Reader::from_reader(csv.as_bytes());
    assert_eq!(r.records().count(), 4);
    assert!(csv.contains("NoteType: Server\nHostname:"));
}
#[test]
fn cli_lock_unlock_agent_and_expiration() {
    let f = Fixture::new();
    f.ok(&["unlock"], "");
    let status = f.run_env(&["status", "--quiet"], "", None);
    assert!(status.status.success());
    assert!(
        f.run_env(&["show", "--sync=no", "--password", "0001"], "", None)
            .status
            .success()
    );
    f.ok(&["lock"], "");
    assert!(
        !f.run_env(&["show", "--sync=no", "--password", "0001"], "", None)
            .status
            .success()
    );
    f.ok(&["unlock"], "");
    f.ok(&["settings", "--timeout=1"], "");
    std::thread::sleep(Duration::from_millis(1300));
    assert!(!f.run_env(&["status", "--quiet"], "", None).status.success());
}
#[test]
fn cli_unknown_item_and_bad_regex_are_errors() {
    let f = Fixture::new();
    assert!(
        !f.run(&["show", "--sync=no", "missing"], "")
            .status
            .success()
    );
    assert!(
        !f.run(&["show", "--sync=no", "-G", "["], "")
            .status
            .success()
    );
}
#[test]
fn cli_output_file_is_private_and_cannot_overwrite() {
    let f = Fixture::new();
    let path = f.dir.path().join("exported-item.txt");
    let p = path.to_str().unwrap();
    f.ok(
        &[
            "show",
            "--sync=no",
            "--password",
            "--output-file",
            p,
            "0001",
        ],
        "",
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "test-account-password\n"
    );
    assert!(
        !f.run(
            &[
                "show",
                "--sync=no",
                "--password",
                "--output-file",
                p,
                "0001"
            ],
            ""
        )
        .status
        .success()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

struct Server {
    address: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let key = crypto::derive_key("user@example.com", "123456", 1000).unwrap();
            let mut vault =
                blob::parse(include_bytes!("fixtures/legacy_vault.bin"), &key, &[]).unwrap();
            let mut next_id = 1000;
            while !flag.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                let (head_end, length) = loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break (0, 0),
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    };
                    if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..i]);
                        let length = headers
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        break (i + 4, length);
                    }
                };
                if head_end == 0 {
                    continue;
                }
                while request.len() < head_end + length {
                    let n = stream.read(&mut buffer).unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..n]);
                }
                let headers = String::from_utf8_lossy(&request[..head_end]);
                let page = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .trim_start_matches('/');
                let values: std::collections::HashMap<String, String> =
                    url::form_urlencoded::parse(&request[head_end..])
                        .into_owned()
                        .collect();
                let get = |n: &str| values.get(n).map(String::as_str).unwrap_or("");
                let reply = match page {
                    "iterations.php" => b"1000".to_vec(),
                    "login.php" => {
                        if get("hash") == crypto::login_hash(&key, "123456").as_str() {
                            b"<response><ok uid=\"57747756\" sessionid=\"1234\" token=\"abcd\"/></response>".to_vec()
                        } else {
                            b"<response><error message=\"invalid password\"/></response>".to_vec()
                        }
                    }
                    "getaccts.php" => blob::write(&vault, &key, false).unwrap(),
                    "login_check.php" => format!(
                        "<response><ok accts_version=\"{}\"/></response>",
                        vault.version
                    )
                    .into_bytes(),
                    "show_website.php" => {
                        if get("delete") == "1" {
                            vault.accounts.retain(|a| a.id != get("aid"));
                        } else {
                            let mut a = if let Some(a) =
                                vault.accounts.iter().find(|a| a.id == get("aid"))
                            {
                                a.clone()
                            } else {
                                lastpass_cli::model::Account::default()
                            };
                            if get("aid") == "0" {
                                next_id += 1;
                                a.id = next_id.to_string();
                            } else {
                                a.id = get("aid").into();
                            }
                            for (name, target) in [
                                ("name", &mut a.name),
                                ("grouping", &mut a.group),
                                ("username", &mut a.username),
                                ("password", &mut a.password),
                                ("extra", &mut a.note),
                            ] {
                                *target =
                                    crypto::text(&crypto::decrypt_base64(get(name), &key).unwrap());
                            }
                            a.url = crypto::text(&hex::decode(get("url")).unwrap());
                            a.pwprotect = get("pwprotect") == "on";
                            if let Some(i) = vault.accounts.iter().position(|b| b.id == a.id) {
                                vault.accounts[i] = a;
                            } else {
                                vault.accounts.push(a);
                            }
                        }
                        vault.version += 1;
                        b"<response><ok/></response>".to_vec()
                    }
                    "logout.php" => b"<response><ok/></response>".to_vec(),
                    _ => b"<response><error message=\"unimplemented\"/></response>".to_vec(),
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&reply);
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
#[test]
fn cli_mock_server_login_sync_list_edit_add_delete_and_logout() {
    let server = Server::new();
    let f = Fixture::new();
    f.ok(
        &["--server", &server.address, "login", "user@example.com"],
        "",
    );
    assert!(f.run_env(&["status", "--quiet"], "", None).status.success());
    f.ok(&["sync"], "");
    assert_eq!(f.ok(&["ls", "--sync=no"], "").lines().count(), 4);
    f.ok(
        &[
            "edit",
            "--sync=now",
            "--non-interactive",
            "--username",
            "0001",
        ],
        "online-user\n",
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--username", "0001"], ""),
        "online-user\n"
    );
    f.ok(
        &["add", "--sync=now", "--non-interactive", "online-new"],
        "Name: online-new\nPassword: online-pass\n",
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "online-new"], ""),
        "online-pass\n"
    );
    f.ok(&["rm", "--sync=now", "online-new"], "");
    assert_eq!(f.ok(&["ls", "--sync=no"], "").lines().count(), 4);
    f.ok(&["logout"], "");
    assert!(!f.dir.path().join("session.enc").exists());
}
#[test]
fn cli_offline_queue_replays_create_edit_delete_without_duplicate_creation() {
    let server = Server::new();
    let f = Fixture::new();
    f.ok(
        &["--server", &server.address, "login", "user@example.com"],
        "",
    );
    f.ok(&["sync"], "");
    f.ok(
        &["add", "--sync=no", "--non-interactive", "queued"],
        "Name: queued\nPassword: first-pass\n",
    );
    f.ok(
        &[
            "edit",
            "--sync=no",
            "--non-interactive",
            "--password",
            "queued",
        ],
        "second-pass\n",
    );
    f.ok(&["sync"], "");
    assert_eq!(f.ok(&["ls", "--sync=no"], "").lines().count(), 5);
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "queued"], ""),
        "second-pass\n"
    );
    f.ok(&["rm", "--sync=no", "queued"], "");
    f.ok(&["sync"], "");
    assert_eq!(f.ok(&["ls", "--sync=no"], "").lines().count(), 4);
}

#[test]
fn cli_generate_updates_the_password_inside_secure_notes() {
    let f = Fixture::new();
    let password = f.ok(
        &[
            "generate",
            "--sync=no",
            "--username=new-note-user",
            "--url=note.example.com",
            "test-note",
            "24",
        ],
        "",
    );
    assert_eq!(password.trim().len(), 24);
    assert_eq!(
        f.ok(&["show", "--sync=no", "--password", "test-note"], ""),
        password
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--username", "test-note"], ""),
        "new-note-user\n"
    );
    assert_eq!(
        f.ok(&["show", "--sync=no", "--url", "test-note"], ""),
        "http://note.example.com\n"
    );
    let note = f.ok(&["show", "--sync=no", "--note", "test-note"], "");
    assert_eq!(
        note.lines()
            .next()
            .unwrap()
            .split_once(':')
            .unwrap()
            .1
            .trim(),
        "Server"
    );
    let item: serde_json::Value =
        serde_json::from_str(&f.ok(&["show", "--sync=no", "--json", "test-note"], "")).unwrap();
    assert_eq!(item[0]["url"], "http://sn");
}
