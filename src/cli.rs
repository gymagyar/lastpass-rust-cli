use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use lastpass_cli::{
    agent,
    client::{LastPass, LoginOptions},
    commands::{self, EditChoice, Search},
    crypto::{self, Key},
    model::{Account, Vault},
    store::{Metadata, Store},
    transport::{HttpTransport, Params},
    xml,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "lpass-rs",
    version,
    about = "Rust LastPass CLI: authentication, vault access, and item management"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true, default_value = "lastpass.com")]
    server: String,
    #[arg(long,global=true,default_value="never",value_parser=["auto","never","always"])]
    color: String,
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    /// Authenticate; password is read from a hidden prompt, stdin, or LPASS_PASSWORD.
    Login {
        username: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        out_of_band: bool,
        #[arg(long)]
        trust: bool,
        #[arg(long, default_value_t = 900, env = "LPASS_AGENT_TIMEOUT")]
        timeout: u64,
        #[arg(long, default_value_t = 300)]
        refresh: u64,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Revoke the remote session and erase local encrypted state.
    Logout {
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Forget the in-memory decryption key but keep the encrypted vault.
    Lock,
    /// Unlock cached state without performing another remote login.
    Unlock {
        #[arg(long)]
        password_stdin: bool,
    },
    Status {
        #[arg(short = 'q', long)]
        quiet: bool,
        #[arg(long)]
        check: bool,
    },
    Sync {
        #[arg(short = 'b', long)]
        background: bool,
    },
    Ls(ListArgs),
    Show(ShowArgs),
    Add(EditArgs),
    Edit(EditArgs),
    Mv {
        name: String,
        group: String,
        #[arg(long, value_enum, default_value = "auto")]
        sync: SyncMode,
    },
    Duplicate {
        name: String,
        #[arg(long, value_enum, default_value = "auto")]
        sync: SyncMode,
        #[arg(long)]
        new_name: Option<String>,
    },
    Rm {
        name: String,
        #[arg(long, value_enum, default_value = "auto")]
        sync: SyncMode,
    },
    Generate {
        name: String,
        length: usize,
        #[arg(long, value_enum, default_value = "auto")]
        sync: SyncMode,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        no_symbols: bool,
        #[arg(short = 'c', long)]
        clip: bool,
    },
    Export {
        #[arg(long, value_enum, default_value = "auto")]
        sync: SyncMode,
        #[arg(long, default_value = "url,username,password,extra,name,grouping,fav")]
        fields: String,
    },
    Import {
        file: Option<PathBuf>,
        #[arg(long)]
        keep_dupes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Share {
        #[command(subcommand)]
        operation: ShareCmd,
    },
    /// Change the remote master password and invalidate the current local session.
    Passwd,
    Settings {
        #[arg(long)]
        timeout: Option<u64>,
        #[arg(long)]
        refresh: Option<u64>,
    },
    #[command(name = "__agent", hide = true)]
    Agent {
        timeout: u64,
    },
}
#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum SyncMode {
    Auto,
    Now,
    No,
}
#[derive(Args)]
struct ListArgs {
    group: Option<String>,
    #[arg(long, value_enum, default_value = "auto")]
    sync: SyncMode,
    #[arg(short = 'l', long)]
    long: bool,
    #[arg(short = 'm')]
    modified: bool,
    #[arg(short = 'u')]
    used: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    format: Option<String>,
}
#[derive(Args)]
struct ShowArgs {
    #[arg(required = true)]
    names: Vec<String>,
    #[arg(long, value_enum, default_value = "auto")]
    sync: SyncMode,
    #[arg(long, group = "selection")]
    username: bool,
    #[arg(long, group = "selection")]
    password: bool,
    #[arg(long, group = "selection")]
    url: bool,
    #[arg(long, group = "selection")]
    id: bool,
    #[arg(long, group = "selection")]
    name: bool,
    #[arg(long, alias = "notes", group = "selection")]
    note: bool,
    #[arg(long, group = "selection")]
    field: Option<String>,
    #[arg(long = "attach", alias = "attachment", group = "selection")]
    attach: Option<String>,
    #[arg(long)]
    all: bool,
    #[arg(short = 'j', long)]
    json: bool,
    #[arg(short = 'x', long)]
    expand_multi: bool,
    #[arg(
        short = 'G',
        long = "basic-regexp",
        alias = "basic-regex",
        conflicts_with = "fixed_strings"
    )]
    regex: bool,
    #[arg(short = 'F', long = "fixed-strings")]
    fixed_strings: bool,
    #[arg(short = 'c', long)]
    clip: bool,
    #[arg(short = 'q', long)]
    quiet: bool,
    #[arg(long)]
    log_access: bool,
    #[arg(long)]
    output_file: Option<PathBuf>,
    #[arg(long, default_value = "%aN [id: %ai]")]
    title_format: String,
    #[arg(long, default_value = "%fn: %fv")]
    format: String,
}
#[derive(Args)]
struct EditArgs {
    name: String,
    #[arg(long, value_enum, default_value = "auto")]
    sync: SyncMode,
    #[arg(long)]
    non_interactive: bool,
    #[arg(long, group = "edit_choice")]
    username: bool,
    #[arg(long, group = "edit_choice")]
    password: bool,
    #[arg(long, group = "edit_choice")]
    url: bool,
    #[arg(long = "name", group = "edit_choice")]
    edit_name: bool,
    #[arg(long, alias = "note", group = "edit_choice")]
    notes: bool,
    #[arg(long, group = "edit_choice")]
    field: Option<String>,
    #[arg(long)]
    note_type: Option<String>,
    #[arg(long)]
    app: bool,
}
#[derive(Subcommand)]
enum ShareCmd {
    Ls,
    Userls {
        share: String,
    },
    Create {
        share: String,
    },
    #[command(alias = "rm")]
    Delete {
        share: String,
    },
    Useradd {
        share: String,
        username: String,
        #[arg(long,num_args=0..=1,default_missing_value="true",default_value="true",action=clap::ArgAction::Set)]
        read_only: bool,
        #[arg(long="hidden",alias="hide-passwords",num_args=0..=1,default_missing_value="true",default_value="true",action=clap::ArgAction::Set)]
        hide_passwords: bool,
        #[arg(long,num_args=0..=1,default_missing_value="true",default_value="false",action=clap::ArgAction::Set)]
        admin: bool,
    },
    Usermod {
        share: String,
        username: String,
        #[arg(long,num_args=0..=1,default_missing_value="true")]
        read_only: Option<bool>,
        #[arg(long="hidden",alias="hide-passwords",num_args=0..=1,default_missing_value="true")]
        hide_passwords: Option<bool>,
        #[arg(long,num_args=0..=1,default_missing_value="true")]
        admin: Option<bool>,
    },
    Userdel {
        share: String,
        username: String,
    },
    Limit {
        share: String,
        username: String,
        #[arg(long)]
        whitelist: Option<bool>,
        #[arg(long, value_delimiter = ',')]
        aids: Option<Vec<String>>,
        #[arg(long, conflicts_with = "allow")]
        deny: bool,
        #[arg(long)]
        allow: bool,
        #[arg(long, conflicts_with = "remove")]
        add: bool,
        #[arg(long = "rm")]
        remove: bool,
        #[arg(long)]
        clear: bool,
        sites: Vec<String>,
    },
}
#[derive(Serialize, Deserialize)]
struct Pending {
    page: String,
    parameters: Params,
}
impl Drop for Pending {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.parameters.zeroize();
    }
}
type Client = LastPass<HttpTransport>;

pub fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}
fn password(stdin: bool, label: &str) -> Result<Zeroizing<String>> {
    if let Ok(value) = std::env::var("LPASS_PASSWORD") {
        return Ok(Zeroizing::new(value));
    }
    if stdin {
        let mut value = String::new();
        io::stdin().read_line(&mut value)?;
        while value.ends_with(['\n', '\r']) {
            value.pop();
        }
        return Ok(Zeroizing::new(value));
    }
    ensure!(
        io::stdin().is_terminal(),
        "No interactive terminal; use --password-stdin or LPASS_PASSWORD"
    );
    Ok(Zeroizing::new(rpassword::prompt_password(label)?))
}
fn unlock_key(store: &Store) -> Result<Key> {
    let metadata = store.metadata()?;
    if let Ok(Some(key)) = agent::request(store, &metadata.agent_token, b'K') {
        return Ok(key);
    }
    let password = password(false, "Master password: ")?;
    let key = crypto::derive_key(&metadata.username, &password, metadata.iterations)?;
    let _session = store.session(&key)?;
    Ok(key)
}
fn client(store: &Store) -> Result<Client> {
    let key = unlock_key(store)?;
    let session = store.session(&key)?;
    Ok(Client {
        transport: HttpTransport::new()?,
        session,
        key,
    })
}
fn verify_reprompt(c: &Client, a: &Account) -> Result<()> {
    if !a.pwprotect {
        return Ok(());
    }
    let password = password(false, "Reprompt — master password: ")?;
    let key = crypto::derive_key(&c.session.username, &password, c.session.iterations)?;
    let diff = key
        .iter()
        .zip(c.key.iter())
        .fold(0u8, |d, (a, b)| d | (a ^ b));
    ensure!(diff == 0, "Master password verification failed");
    Ok(())
}
fn flush(store: &Store, c: &Client) -> Result<()> {
    let mut pending: Vec<Pending> = serde_json::from_slice(&store.pending(&c.key)?)?;
    while !pending.is_empty() {
        let mut wire = Zeroizing::new(pending[0].parameters.clone());
        wire.retain(|(k, _)| k != "__local_id");
        for (k, v) in &mut *wire {
            if k == "token" {
                *v = c.session.token.clone();
            }
        }
        xml::check_reply(&c.post(&pending[0].page, &wire)?)?;
        pending.remove(0);
        let bytes = Zeroizing::new(serde_json::to_vec(&pending)?);
        store.save_pending(&bytes, &c.key)?;
    }
    Ok(())
}
fn load(store: &Store, c: &mut Client, sync: SyncMode) -> Result<Vault> {
    if sync == SyncMode::No {
        let vault = store.vault(&c.key)?;
        warn_unavailable(&vault);
        return Ok(vault);
    }
    let metadata = store.metadata()?;
    if sync == SyncMode::Auto && store.cache_fresh(metadata.refresh) {
        let vault = store.vault(&c.key)?;
        warn_unavailable(&vault);
        return Ok(vault);
    }
    flush(store, c)?;
    let vault = c.load_vault()?;
    ensure!(
        vault.decryption_errors == 0,
        "Vault has {} failed field decryptions; refusing partial results",
        vault.decryption_errors
    );
    warn_unavailable(&vault);
    store.save_vault(&vault, &c.key)?;
    store.save_session(&c.session, &c.key)?;
    Ok(vault)
}
fn warn_unavailable(vault: &Vault) {
    if vault.unavailable_shares > 0 {
        eprintln!(
            "Warning: {} shared folders have invalid keys; {} items are unavailable. Results cover the decryptable portion of the vault.",
            vault.unavailable_shares, vault.unavailable_accounts
        );
    }
}
fn save_change(
    store: &Store,
    c: &Client,
    vault: &mut Vault,
    account: &Account,
    sync: SyncMode,
    original_share: Option<&str>,
) -> Result<()> {
    c.ensure_writable(account, vault)?;
    ensure!(
        vault.decryption_errors == 0,
        "Cannot modify a partially decrypted vault"
    );
    if sync == SyncMode::No {
        ensure!(
            original_share.is_none(),
            "Moving between shared folders requires --sync=now"
        );
        let mut wire = account.clone();
        if wire.id.starts_with("local-") {
            wire.id = "0".into();
        }
        let mut parameters = c.account_params(&wire, vault)?;
        let mut pending: Vec<Pending> = serde_json::from_slice(&store.pending(&c.key)?)?;
        let marker = account.id.clone();
        parameters.push(("__local_id".into(), marker.clone()));
        if let Some(p) = pending.iter_mut().find(|p| {
            p.parameters
                .iter()
                .any(|(k, v)| k == "__local_id" && v == &marker)
        }) {
            p.parameters = parameters;
        } else {
            pending.push(Pending {
                page: if account.is_app {
                    "addapp.php"
                } else {
                    "show_website.php"
                }
                .into(),
                parameters,
            });
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&pending)?);
        store.save_pending(&bytes, &c.key)?;
        vault.pending_updates = true;
    } else {
        flush(store, c)?;
        if let Some(old) = original_share {
            c.move_shared(account, old, vault)?;
        } else {
            c.update_account(account, vault)?;
        }
    }
    if let Some(i) = vault
        .accounts
        .iter()
        .position(|a| a.id == account.id && a.id != "0")
    {
        vault.accounts[i] = account.clone();
    } else {
        vault.accounts.push(account.clone());
    }
    vault.version += 1;
    if sync != SyncMode::No {
        *vault = c.load_vault()?;
        ensure!(
            vault.decryption_errors == 0,
            "Updated vault has failed field decryptions"
        );
    }
    store.save_vault(vault, &c.key)?;
    Ok(())
}
fn editor(initial: &str) -> Result<Zeroizing<String>> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or("vi".into());
    let mut args = editor.split_whitespace();
    let executable = args.next().context("Empty editor setting")?;
    let dir = std::env::temp_dir().join(format!(
        "lpass-rs-edit-{}",
        hex::encode(crypto::random_bytes::<12>())
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir)?;
    let result = (|| -> Result<Zeroizing<String>> {
        let store = Store::new(dir.clone())?;
        store.atomic_write("item.txt", initial.as_bytes())?;
        let status = Command::new(executable)
            .args(args)
            .arg(store.path("item.txt"))
            .status()?;
        ensure!(status.success(), "Editor failed");
        Ok(Zeroizing::new(std::fs::read_to_string(
            store.path("item.txt"),
        )?))
    })();
    let _ = std::fs::remove_dir_all(dir);
    result
}
fn input_for_edit(args: &EditArgs, initial: &str) -> Result<Zeroizing<String>> {
    if args.non_interactive {
        let mut input = Zeroizing::new(String::new());
        io::stdin()
            .take(8 * 1024 * 1024)
            .read_to_string(&mut input)?;
        Ok(input)
    } else {
        editor(initial)
    }
}
fn edit_choice(args: &EditArgs) -> EditChoice {
    if args.username {
        EditChoice::Username
    } else if args.password {
        EditChoice::Password
    } else if args.url {
        EditChoice::Url
    } else if args.edit_name {
        EditChoice::Name
    } else if args.notes {
        EditChoice::Notes
    } else if let Some(field) = &args.field {
        EditChoice::Field(field.clone())
    } else {
        EditChoice::Any
    }
}
fn copy_clipboard(value: &[u8]) -> Result<()> {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    };
    for (exe, args) in candidates {
        match Command::new(exe)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                child
                    .stdin
                    .take()
                    .context("Clipboard input unavailable")?
                    .write_all(value)?;
                ensure!(child.wait()?.success(), "Clipboard command failed");
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("Install wl-copy, xclip, or xsel for clipboard support")
}
fn emit(value: &[u8], clip: bool, file: Option<&PathBuf>) -> Result<()> {
    ensure!(
        !(clip && file.is_some()),
        "Choose either clipboard or output file"
    );
    if clip {
        copy_clipboard(value)
    } else if let Some(path) = file {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(path)
            .context("Output file must not already exist")?;
        output.write_all(value)?;
        Ok(())
    } else {
        io::stdout().lock().write_all(value).map_err(Into::into)
    }
}
fn run(cli: Cli) -> Result<()> {
    let store = Store::new(cli.data_dir.unwrap_or_else(Store::default_dir))?;
    match cli.command {
        Cmd::Agent { timeout } => agent::serve(&store, timeout),
        Cmd::Login {
            username,
            password_stdin,
            otp,
            out_of_band,
            trust,
            timeout,
            refresh,
            force: _,
        } => {
            let password = password(password_stdin, "Master password: ")?;
            let trusted_id = if trust {
                store
                    .metadata()
                    .ok()
                    .and_then(|m| m.trusted_id)
                    .or_else(|| Some(hex::encode(crypto::random_bytes::<16>())))
            } else {
                None
            };
            let options = LoginOptions {
                server: cli.server,
                otp: otp.map(Zeroizing::new),
                wait_for_approval: out_of_band,
                trust_label: trust.then(|| "LastPass CLI Rust".into()),
                trusted_id: trusted_id.clone(),
            };
            let c = LastPass::login(HttpTransport::new()?, &username, &password, options)?;
            store.save_session(&c.session, &c.key)?;
            for name in ["vault.enc", "pending.enc"] {
                if store.path(name).is_file() {
                    std::fs::remove_file(store.path(name))?;
                }
            }
            let token = agent::start(&store, &c.key, timeout)?;
            let m = Metadata {
                username: c.session.username.clone(),
                iterations: c.session.iterations,
                timeout,
                refresh,
                agent_token: token,
                trusted_id,
            };
            store.save_meta(&m)?;
            println!("Success: Logged in as {}.", c.session.username);
            Ok(())
        }
        Cmd::Unlock { password_stdin } => {
            let mut m = store.metadata()?;
            let password = password(password_stdin, "Master password: ")?;
            let key = crypto::derive_key(&m.username, &password, m.iterations)?;
            let _session = store.session(&key)?;
            m.agent_token = agent::start(&store, &key, m.timeout)?;
            store.save_meta(&m)?;
            println!("Vault unlocked.");
            Ok(())
        }
        Cmd::Lock => {
            if let Ok(m) = store.metadata() {
                let _ = agent::request(&store, &m.agent_token, b'L');
            }
            println!("Vault locked.");
            Ok(())
        }
        Cmd::Logout { force } => {
            if !force {
                let c = client(&store)?;
                c.logout()?;
            }
            if let Ok(m) = store.metadata() {
                let _ = agent::request(&store, &m.agent_token, b'L');
            }
            store.clear()?;
            println!("Logged out.");
            Ok(())
        }
        Cmd::Status { quiet, check } => {
            let m = store.metadata()?;
            let unlocked = agent::request(&store, &m.agent_token, b'P').is_ok();
            if check {
                let mut c = client(&store)?;
                let version = c.check_session()?;
                store.save_session(&c.session, &c.key)?;
                if !quiet {
                    println!("Session valid; vault version {version}.");
                }
                return Ok(());
            }
            if !quiet {
                println!(
                    "{} as {}.",
                    if unlocked { "Logged in" } else { "Locked" },
                    m.username
                );
            }
            ensure!(unlocked, "Vault is locked");
            Ok(())
        }
        Cmd::Settings { timeout, refresh } => {
            let mut m = store.metadata()?;
            if let Some(timeout) = timeout {
                let key = unlock_key(&store)?;
                m.agent_token = agent::start(&store, &key, timeout)?;
                m.timeout = timeout;
            }
            if let Some(refresh) = refresh {
                m.refresh = refresh;
            }
            store.save_meta(&m)?;
            println!(
                "Agent timeout: {} seconds; refresh interval: {} seconds.",
                m.timeout, m.refresh
            );
            Ok(())
        }
        Cmd::Sync { background: true } => {
            Command::new(std::env::current_exe()?)
                .arg("--data-dir")
                .arg(&store.dir)
                .arg("sync")
                .env_remove("LPASS_PASSWORD")
                .env_remove("LPASS_TEST_PASSWORD")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            println!("Sync started in background.");
            Ok(())
        }
        command => run_vault_command(&store, command),
    }
}
fn run_vault_command(store: &Store, command: Cmd) -> Result<()> {
    let mut c = client(store)?;
    match command {
        Cmd::Sync { background: false } => {
            let vault = load(store, &mut c, SyncMode::Now)?;
            println!(
                "Synchronized {} items (version {}).",
                vault.accounts.len(),
                vault.version
            );
        }
        Cmd::Ls(args) => {
            let vault = load(store, &mut c, args.sync)?;
            let mut accounts: Vec<_> = vault
                .accounts
                .iter()
                .filter(|a| !a.is_group())
                .filter(|a| {
                    args.group
                        .as_ref()
                        .is_none_or(|g| a.fullname().starts_with(g))
                })
                .collect();
            accounts.sort_by_key(|a| a.fullname().to_lowercase());
            if args.json {
                let values:Vec<_>=accounts.iter().map(|a|serde_json::json!({"id":a.id,"name":a.name,"fullname":a.fullname(),"url":a.url,"group":a.group,"favorite":a.favorite})).collect();
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else {
                for a in accounts {
                    if let Some(fmt) = &args.format {
                        println!("{}", commands::format_account(fmt, a, None));
                    } else if args.long {
                        println!(
                            "{} {} [id: {}]",
                            if args.used {
                                &a.last_touch
                            } else {
                                &a.last_modified_gmt
                            },
                            a.fullname(),
                            a.id
                        );
                    } else {
                        println!("{} [id: {}]", a.fullname(), a.id);
                    }
                }
            }
        }
        Cmd::Show(args) => {
            let vault = load(store, &mut c, args.sync)?;
            let mode = if args.regex {
                Search::Regex
            } else if args.fixed_strings {
                Search::Substring
            } else {
                Search::Exact
            };
            let mut found = Vec::new();
            for pattern in &args.names {
                for a in commands::matches(&vault, pattern, &mode)? {
                    if !found.iter().any(|b: &&Account| b.id == a.id) {
                        found.push(a);
                    }
                }
            }
            ensure!(!found.is_empty(), "No matching vault item");
            ensure!(
                found.len() == 1 || args.expand_multi || args.names.len() > 1,
                "Multiple matches; use --expand-multi or a unique ID"
            );
            for a in &found {
                verify_reprompt(&c, a)?;
                if args.log_access {
                    c.log_access(a)?;
                }
            }
            let mut bytes = Zeroizing::new(Vec::new());
            if args.json {
                let values: Vec<_> = found.iter().map(|a| a.json_value()).collect();
                bytes.extend(serde_json::to_vec_pretty(&values)?);
                bytes.push(b'\n');
            } else if let Some(attach_id) = &args.attach {
                ensure!(found.len() == 1, "Choose one item for attachment download");
                bytes = c.load_attachment(found[0], attach_id)?;
            } else {
                for a in found {
                    let expanded = a.expanded();
                    let value = if args.username {
                        Some(expanded.username.clone())
                    } else if args.password {
                        Some(expanded.password.clone())
                    } else if args.url {
                        Some(expanded.url.clone())
                    } else if args.id {
                        Some(a.id.clone())
                    } else if args.name {
                        Some(a.name.clone())
                    } else if args.note {
                        Some(a.note.clone())
                    } else if let Some(field) = &args.field {
                        Some(a.field_value(field).context("Field not found")?)
                    } else {
                        None
                    };
                    if let Some(value) = value {
                        bytes.extend_from_slice(value.as_bytes());
                        if !args.clip {
                            bytes.push(b'\n');
                        }
                    } else {
                        let value = Zeroizing::new(commands::display_account(
                            a,
                            &args.title_format,
                            &args.format,
                        ));
                        bytes.extend_from_slice(value.as_bytes());
                    }
                }
            }
            emit(&bytes, args.clip, args.output_file.as_ref())?;
        }
        Cmd::Add(args) => edit_command(store, &c, args, true)?,
        Cmd::Edit(args) => edit_command(store, &c, args, false)?,
        Cmd::Duplicate {
            name,
            sync,
            new_name,
        } => {
            let mut vault = load(store, &mut c, sync)?;
            let mut account = vault.accounts[commands::unique_index(&vault, &name)?].clone();
            verify_reprompt(&c, &account)?;
            account.id = if sync == SyncMode::No {
                format!("local-{}", hex::encode(crypto::random_bytes::<12>()))
            } else {
                "0".into()
            };
            account.attachments.clear();
            account.attachkey.clear();
            account.attachpresent = false;
            if let Some(name) = new_name {
                commands::set_fullname(&mut account, &name, &vault)?;
            }
            save_change(store, &c, &mut vault, &account, sync, None)?;
            println!("Item duplicated.");
        }
        Cmd::Mv { name, group, sync } => {
            let mut vault = load(store, &mut c, sync)?;
            let mut account = vault.accounts[commands::unique_index(&vault, &name)?].clone();
            verify_reprompt(&c, &account)?;
            let original = account.share_id.clone();
            let fullname = if group.is_empty() {
                account.name.clone()
            } else {
                format!("{group}/{}", account.name)
            };
            commands::set_fullname(&mut account, &fullname, &vault)?;
            let transition = (original != account.share_id).then_some(original.as_str());
            save_change(store, &c, &mut vault, &account, sync, transition)?;
            println!("Item moved.");
        }
        Cmd::Rm { name, sync } => {
            let mut vault = load(store, &mut c, sync)?;
            let i = commands::unique_index(&vault, &name)?;
            let a = &vault.accounts[i];
            verify_reprompt(&c, a)?;
            c.ensure_writable(a, &vault)?;
            if sync == SyncMode::No {
                let mut pending: Vec<Pending> = serde_json::from_slice(&store.pending(&c.key)?)?;
                pending.retain(|p| {
                    !p.parameters
                        .iter()
                        .any(|(k, v)| k == "__local_id" && v == &a.id)
                });
                if !a.id.starts_with("local-") {
                    let mut parameters = lastpass_cli::transport::params(&[
                        ("extjs", "1"),
                        ("token", &c.session.token),
                        ("delete", "1"),
                        ("aid", &a.id),
                    ]);
                    if !a.share_id.is_empty() {
                        parameters.push(("sharedfolderid".into(), a.share_id.clone()));
                    }
                    pending.push(Pending {
                        page: "show_website.php".into(),
                        parameters,
                    });
                }
                store.save_pending(&Zeroizing::new(serde_json::to_vec(&pending)?), &c.key)?;
                vault.pending_updates = !pending.is_empty();
            } else {
                flush(store, &c)?;
                c.remove_account(a, &vault)?;
            }
            vault.accounts.remove(i);
            vault.version += 1;
            store.save_vault(&vault, &c.key)?;
            println!("Item removed.");
        }
        Cmd::Generate {
            name,
            length,
            sync,
            username,
            url,
            no_symbols,
            clip,
        } => {
            let mut vault = load(store, &mut c, sync)?;
            let mut account = if commands::matches(&vault, &name, &Search::Exact)?.is_empty() {
                let mut a = Account::default();
                a.id = if sync == SyncMode::No {
                    format!("local-{}", hex::encode(crypto::random_bytes::<12>()))
                } else {
                    "0".into()
                };
                commands::set_fullname(&mut a, &name, &vault)?;
                a
            } else {
                vault.accounts[commands::unique_index(&vault, &name)?].clone()
            };
            verify_reprompt(&c, &account)?;
            let generated = Zeroizing::new(commands::generate_password(length, !no_symbols)?);
            commands::edit_value(&mut account, &EditChoice::Password, &generated, &vault)?;
            if let Some(username) = username {
                commands::edit_value(&mut account, &EditChoice::Username, &username, &vault)?;
            }
            if let Some(url) = url {
                commands::edit_value(&mut account, &EditChoice::Url, &url, &vault)?;
            }
            save_change(store, &c, &mut vault, &account, sync, None)?;
            emit(generated.as_bytes(), clip, None)?;
            if !clip {
                println!();
            }
        }
        Cmd::Export { sync, fields } => {
            let vault = load(store, &mut c, sync)?;
            for a in &vault.accounts {
                verify_reprompt(&c, a)?;
            }
            let fields: Vec<_> = fields.split(',').map(str::to_owned).collect();
            let bytes = Zeroizing::new(commands::export_csv(&vault, &fields)?);
            emit(&bytes, false, None)?;
        }
        Cmd::Import {
            file,
            keep_dupes,
            dry_run,
        } => {
            let vault = load(store, &mut c, SyncMode::Now)?;
            let bytes = Zeroizing::new(if let Some(file) = file {
                std::fs::read(file)?
            } else {
                let mut b = Vec::new();
                io::stdin().take(64 * 1024 * 1024).read_to_end(&mut b)?;
                b
            });
            let accounts = commands::import_csv(&bytes, &vault, keep_dupes)?;
            if dry_run {
                println!("{} items would be imported.", accounts.len());
            } else {
                c.upload_accounts(&accounts, &vault)?;
                let refreshed = c.load_vault()?;
                store.save_vault(&refreshed, &c.key)?;
                println!("Imported {} items.", accounts.len());
            }
        }
        Cmd::Share { operation } => share_command(store, &mut c, operation)?,
        Cmd::Passwd => {
            let vault = load(store, &mut c, SyncMode::Now)?;
            ensure!(
                vault.unavailable_shares == 0,
                "Cannot change the master password while shared folders are unavailable"
            );
            let old = password(false, "Current master password: ")?;
            let new = Zeroizing::new(rpassword::prompt_password("New master password: ")?);
            let repeat =
                Zeroizing::new(rpassword::prompt_password("Confirm new master password: ")?);
            ensure!(*new == *repeat, "New passwords do not match");
            let change = c.prepare_password_change(&old, &new)?;
            c.commit_password_change(change)?;
            if let Ok(m) = store.metadata() {
                let _ = agent::request(store, &m.agent_token, b'L');
            }
            store.clear()?;
            println!("Master password changed; logged out.");
        }
        _ => bail!("Invalid vault command"),
    }
    Ok(())
}
fn edit_command(store: &Store, c: &Client, args: EditArgs, is_add: bool) -> Result<()> {
    // Loading only reads the session and never rotates it, so share this client.
    let mut reader = Client {
        transport: HttpTransport::new()?,
        session: c.session.clone(),
        key: c.key.clone(),
    };
    let mut vault = load(store, &mut reader, args.sync)?;
    let mut account = if is_add {
        let mut a = Account::default();
        a.id = format!("local-{}", hex::encode(crypto::random_bytes::<12>()));
        commands::set_fullname(&mut a, &args.name, &vault)?;
        a
    } else {
        vault.accounts[commands::unique_index(&vault, &args.name)?].clone()
    };
    let original_share = account.share_id.clone();
    if !is_add {
        verify_reprompt(c, &account)?;
    }
    if let Some(kind) = &args.note_type {
        let (name, _) = commands::note_type(kind).context("Unknown secure-note type")?;
        account.url = "http://sn".into();
        account.note = format!("NoteType:{name}");
    }
    if args.app {
        account.is_app = true;
    }
    let choice = edit_choice(&args);
    let expanded = account.expanded();
    let initial = Zeroizing::new(match &choice {
        EditChoice::Any => commands::display_account(&account, "Name: %aN", "%fn: %fv"),
        EditChoice::Username => expanded.username.clone(),
        EditChoice::Password => expanded.password.clone(),
        EditChoice::Url => expanded.url.clone(),
        EditChoice::Name => account.fullname(),
        EditChoice::Notes => expanded.note.clone(),
        EditChoice::Field(f) => account.field_value(f).unwrap_or_default(),
    });
    let input = input_for_edit(&args, &initial)?;
    commands::edit_value(&mut account, &choice, &input, &vault)?;
    let transition =
        (!is_add && original_share != account.share_id).then_some(original_share.as_str());
    if args.sync != SyncMode::No && is_add {
        account.id = "0".into();
    }
    save_change(store, c, &mut vault, &account, args.sync, transition)?;
    println!("Item saved.");
    Ok(())
}
fn share_command(store: &Store, c: &mut Client, operation: ShareCmd) -> Result<()> {
    let vault = load(store, c, SyncMode::Now)?;
    let find_share = |name: &str| {
        vault
            .shares
            .iter()
            .find(|s| {
                s.id == name
                    || s.name.eq_ignore_ascii_case(name)
                    || s.name.eq_ignore_ascii_case(&format!("Shared-{name}"))
            })
            .context("Shared folder not found")
    };
    let find_user = |share: &lastpass_cli::model::Share,
                     username: &str|
     -> Result<lastpass_cli::sharing::ShareUser> {
        c.share_users(share)?
            .into_iter()
            .find(|u| u.username.eq_ignore_ascii_case(username) || u.uid == username)
            .context("Shared-folder user not found")
    };
    let mut changed = true;
    match operation {
        ShareCmd::Ls => {
            for s in &vault.shares {
                println!(
                    "{} [id: {}]{}",
                    s.name,
                    s.id,
                    if s.readonly { " (read-only)" } else { "" }
                );
            }
            changed = false;
        }
        ShareCmd::Userls { share } => {
            let users = c.share_users(find_share(&share)?)?;
            println!("{}", serde_json::to_string_pretty(&users)?);
            changed = false;
        }
        ShareCmd::Create { share } => c.share_create(&share)?,
        ShareCmd::Delete { share } => c.share_delete(find_share(&share)?)?,
        ShareCmd::Useradd {
            share,
            username,
            read_only,
            hide_passwords,
            admin,
        } => {
            let user = lastpass_cli::sharing::ShareUser {
                username,
                read_only,
                hide_passwords,
                admin,
                ..Default::default()
            };
            c.share_add_user(find_share(&share)?, &user)?;
        }
        ShareCmd::Usermod {
            share,
            username,
            read_only,
            hide_passwords,
            admin,
        } => {
            let share = find_share(&share)?;
            let mut user = find_user(share, &username)?;
            if let Some(v) = read_only {
                user.read_only = v;
            }
            if let Some(v) = hide_passwords {
                user.hide_passwords = v;
            }
            if let Some(v) = admin {
                user.admin = v;
            }
            c.share_modify_user(share, &user)?;
        }
        ShareCmd::Userdel { share, username } => {
            let share = find_share(&share)?;
            let user = find_user(share, &username)?;
            c.share_remove_user(share, &user)?;
        }
        ShareCmd::Limit {
            share,
            username,
            whitelist,
            aids,
            deny,
            allow,
            add: _,
            remove,
            clear,
            sites,
        } => {
            let share = find_share(&share)?;
            let user = find_user(share, &username)?;
            let (old_mode, old_aids) = c.share_limits(share, &user)?;
            if whitelist.is_none()
                && aids.is_none()
                && !deny
                && !allow
                && !clear
                && sites.is_empty()
            {
                println!(
                    "{}",
                    serde_json::json!({"whitelist":old_mode,"aids":old_aids})
                );
                changed = false;
            } else {
                let mode = whitelist.unwrap_or(if deny {
                    true
                } else if allow {
                    false
                } else {
                    old_mode
                });
                let mut list = aids.unwrap_or(if clear { Vec::new() } else { old_aids });
                for site in sites {
                    let matches = commands::matches(&vault, &site, &Search::Exact)?;
                    ensure!(
                        !matches.is_empty(),
                        "No matching site for shared-folder limit"
                    );
                    for a in matches {
                        ensure!(
                            a.share_id == share.id,
                            "Site does not belong to the selected shared folder"
                        );
                        if remove {
                            list.retain(|id| id != &a.id);
                        } else if !list.contains(&a.id) {
                            list.push(a.id.clone());
                        }
                    }
                }
                c.share_set_limits(share, &user, mode, &list)?;
            }
        }
    }
    if changed {
        let refreshed = c.load_vault()?;
        store.save_vault(&refreshed, &c.key)?;
        println!("Shared folder updated.");
    }
    Ok(())
}
