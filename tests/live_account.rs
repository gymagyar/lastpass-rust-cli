//! Opt-in, read-only live test. Supply credentials through environment variables.
//! No credentials, tokens, names, item IDs, or item values are printed.
use anyhow::{Context, Result, ensure};
use lastpass_cli::{
    client::{LastPass, LoginOptions},
    commands::{self, Search},
    store::Store,
    transport::HttpTransport,
};
use zeroize::Zeroizing;

#[test]
#[ignore = "Requires explicitly supplied LastPass test credentials and network access"]
fn live_login_load_list_show_sync_and_logout() -> Result<()> {
    let username = std::env::var("LPASS_TEST_USERNAME").context("Set LPASS_TEST_USERNAME")?;
    let password =
        Zeroizing::new(std::env::var("LPASS_TEST_PASSWORD").context("Set LPASS_TEST_PASSWORD")?);
    let options = LoginOptions {
        server: std::env::var("LPASS_TEST_SERVER").unwrap_or("lastpass.com".into()),
        ..LoginOptions::default()
    };
    let mut client = LastPass::login(HttpTransport::new()?, &username, &password, options)?;
    eprintln!(
        "LIVE login: PASS (iterations={})",
        client.session.iterations
    );
    let result = (|| -> Result<()> {
        let vault = client.load_vault()?;
        ensure!(
            vault.decryption_errors == 0,
            "Live vault contained {} failed field decryptions",
            vault.decryption_errors
        );
        eprintln!(
            "LIVE shared-folder key validation: valid_folders={}, invalid_folders={}, unavailable_items={}",
            vault.shares.len(),
            vault.unavailable_shares,
            vault.unavailable_accounts
        );
        if std::env::var("LPASS_TEST_REQUIRE_COMPLETE").ok().as_deref() == Some("1") {
            ensure!(
                vault.unavailable_accounts == 0,
                "{} items belong to folders with invalid shared keys",
                vault.unavailable_accounts
            );
        }
        eprintln!(
            "LIVE load/decrypt: PASS (items={}, shared_folders={}, version={})",
            vault.accounts.len(),
            vault.shares.len(),
            vault.version
        );
        let mut listing: Vec<_> = vault.accounts.iter().filter(|a| !a.is_group()).collect();
        listing.sort_by_key(|a| a.fullname());
        ensure!(listing.len() <= vault.accounts.len(), "Invalid listing");
        eprintln!("LIVE list: PASS (listed_items={})", listing.len());
        for item in &listing {
            let matches = commands::matches(&vault, &item.id, &Search::Exact)?;
            ensure!(
                matches.iter().any(|a| a.id == item.id),
                "Loaded item could not be found by ID"
            );
            let formatted =
                Zeroizing::new(commands::display_account(item, "%aN [id: %ai]", "%fn: %fv"));
            ensure!(!formatted.is_empty(), "Empty show output");
            let json = Zeroizing::new(serde_json::to_string(&item.json_value())?);
            let _: serde_json::Value = serde_json::from_str(&json)?;
        }
        eprintln!("LIVE show/search/JSON for all listed items: PASS");
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::new(dir.path().to_path_buf())?;
        store.save_session(&client.session, &client.key)?;
        store.save_vault(&vault, &client.key)?;
        let restored = store.vault(&client.key)?;
        ensure!(
            restored.accounts.len() == vault.accounts.len(),
            "Cached vault item count differs"
        );
        for (a, b) in vault.accounts.iter().zip(&restored.accounts) {
            ensure!(
                a.id == b.id
                    && a.name == b.name
                    && a.username == b.username
                    && a.password == b.password
                    && a.note == b.note,
                "Encrypted cache round-trip changed an item"
            );
        }
        eprintln!("LIVE encrypted cache save/load: PASS");
        let server_version = client.check_session()?;
        ensure!(
            server_version >= vault.version,
            "Server vault version went backwards"
        );
        let refreshed = client.load_vault()?;
        ensure!(
            refreshed.decryption_errors == 0,
            "Refreshed vault has decryption errors"
        );
        ensure!(
            refreshed.accounts.len() == vault.accounts.len(),
            "Live vault item count changed during test"
        );
        ensure!(
            refreshed.unavailable_accounts == vault.unavailable_accounts
                && refreshed.unavailable_shares == vault.unavailable_shares,
            "Unavailable folder/item count changed during test"
        );
        eprintln!("LIVE session check and sync: PASS");
        if std::env::var("LPASS_TEST_ATTACHMENTS").ok().as_deref() == Some("1") {
            let mut count = 0;
            for a in &vault.accounts {
                for at in &a.attachments {
                    let _bytes = client.load_attachment(a, &at.id)?;
                    count += 1;
                }
            }
            eprintln!("LIVE attachment download/decrypt: PASS (attachments={count})");
        }
        Ok(())
    })();
    let logout = client.logout();
    if logout.is_ok() {
        eprintln!("LIVE logout: PASS");
    } else if let Err(error) = &logout {
        eprintln!("LIVE logout failed: {error:#}");
    }
    result?;
    logout?;
    Ok(())
}
