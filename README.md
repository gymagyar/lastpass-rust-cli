# LastPass CLI in Rust

A Rust implementation of the protocol and command families in the supplied
`lastpass-cli-master(1).zip`. The executable is `lpass-rs`; it does not invoke the
C client or require OpenSSL. This is a source-level port with a new local cache
and agent, rather than a byte-for-byte replacement of every C option and output.

Actual-account verification and its vault-data limitation are recorded in
[TEST_RESULTS.md](TEST_RESULTS.md). Implementation mapping and compatibility
changes are in [PORTING_NOTES.md](PORTING_NOTES.md).

## Build and run

Rust 1.85.0 is pinned in `rust-toolchain.toml`. Cargo and rustc come from the same
Rust toolchain. A system C linker is needed to build dependencies. See
[BUILDING.md](BUILDING.md) for setup, build, test, and installation instructions.

```sh
git clone https://github.com/gymagyar/lastpass-rust-cli.git
cd lastpass-rust-cli
cargo build --release --locked -j1
./target/release/lpass-rs --help
```

The implementation was compiled and tested on Ubuntu 24.04.3 x86_64.
Build from source on your own platform. macOS and Windows builds have not been
verified. The repository contains source and synthetic test fixtures.

```sh
./target/release/lpass-rs login your-email@example.com
./target/release/lpass-rs sync
./target/release/lpass-rs ls --sync=no
./target/release/lpass-rs show --sync=no --username ITEM_ID
./target/release/lpass-rs show --sync=no --password ITEM_ID
./target/release/lpass-rs lock
./target/release/lpass-rs unlock
./target/release/lpass-rs logout
```

`login` and `unlock` use a hidden password prompt. `--password-stdin` reads one
line from stdin; `LPASS_PASSWORD` is also supported for automation and reprompt.
No password argument is accepted. For MFA, pass `login --otp CODE` or
`login --out-of-band` and approve the request. Trusted-device registration is
explicit through `--trust`.

State defaults to the platform's local data directory under `lpass-rs`.
`--data-dir /absolute/private/directory` or `LPASS_HOME` selects another directory.
Use a separate directory from the C client's state. On Unix the directory must
have mode 700; state files have mode 600.

## Commands

| Command | Behavior |
|---|---|
| `login`, `logout`, `status` | Authenticate, revoke/clear a session, inspect/check session state |
| `sync` | Download the vault and replay queued changes; `--background` starts a child process |
| `ls` | List items, filter by folder prefix, format output, or emit JSON |
| `show` | Show an item, selected fields, JSON, notes, custom fields, or an attachment |
| `add`, `edit` | Edit regular accounts, application entries, and secure-note templates |
| `mv`, `duplicate`, `rm` | Move, duplicate, or remove an item |
| `generate` | Generate a random password and save it in an account or secure note |
| `export`, `import` | LastPass CSV output/input; `import --dry-run` previews the count |
| `share` | List/administer shared folders, membership, permissions, and item limits |
| `passwd` | Prepare and commit master-password re-encryption |
| `lock`, `unlock`, `settings` | Rust-specific key-agent and cache controls |

Run `lpass-rs COMMAND --help` for exact supported options. Item IDs avoid
ambiguous duplicate names. Search supports exact matching, fixed substrings,
and Rust regular expressions. Clipboard output uses installed platform helpers
such as `wl-copy`, `xclip`, `pbcopy`, or `clip.exe`.

For vault commands, `--sync=now` refreshes before the operation and sends changes
immediately. `--sync=no` uses the encrypted cache and queues local changes for
later `sync`. `--sync=auto` uses a fresh cache for up to 300 seconds by default
and sends mutations immediately. Cross-share moves require a network sync.

`show --json`, `show --password`, and `export` intentionally output secrets.
`ls --json` contains listing metadata only. `show --output-file FILE` creates a
private file and refuses to overwrite an existing file. Access logging is an
explicit `show --log-access` option.

## Tests

```sh
cargo test --locked -j1
cargo fmt --all -- --check
cargo clippy --all-targets --locked -j1 -- -D warnings
```

The ordinary suite uses synthetic fixtures and loopback mock HTTP servers. It
covers cryptographic interoperability, vault parsing, malformed data, sessions,
item commands, encrypted persistence, agent behavior, shared-folder operations,
attachments, offline replay, and password-change request preparation/commit.
Checked-in fixtures were independently generated with Python cryptography.
Regeneration, if needed, is `python3 scripts/generate_test_fixtures.py`.

The live test is ignored by default. From a Bash shell, supply credentials only
in the environment:

```bash
read -r -p 'LastPass email: ' LPASS_TEST_USERNAME
read -r -s -p 'Master password: ' LPASS_TEST_PASSWORD
printf '\n'
export LPASS_TEST_USERNAME LPASS_TEST_PASSWORD
cargo test --locked -j1 --test live_account -- --ignored --nocapture
python3 scripts/live_cli_test.py ./target/release/lpass-rs
unset LPASS_TEST_USERNAME LPASS_TEST_PASSWORD
```

Both live tests are read-only for vault contents. They print statuses and counts,
not vault contents. The CLI test uses a temporary private cache, tests lock/unlock,
and logs out before removing it. `LPASS_TEST_REQUIRE_COMPLETE=1` makes the library
live test fail if any item belongs to an invalid shared folder.
`LPASS_TEST_ATTACHMENTS=1` additionally tests attachment downloads in the library
test; that option was not used during the recorded account verification.

The port preserves LastPass's wire cryptography: PBKDF2/SHA-256, AES-256 CBC/ECB,
and RSA-OAEP/SHA-1 sharing. Local session, vault, and queue files use authenticated
AES-256-GCM. The key agent holds the vault key in memory and expires after 900
seconds of idle key access by default. `lock` stops it; `unlock` derives the key
again without another server login. Metadata and its agent authentication token
are restricted to the owner. The master password is not saved.

Invalid shared-folder keys are counted and their items are excluded with a
warning instead of silently returning empty decrypted fields. Failed decryption
of an otherwise accessible field makes CLI vault loading fail. The cache retains
these counters; incomplete vaults cannot be serialized to the wire format, and
`passwd` refuses to run when shared folders are unavailable.

## License

GPL-2.0-or-later, following the supplied source. See `COPYING`, `NOTICE.md`, and
the retained upstream `LICENSE.OpenSSL`. The Rust implementation uses rustls
rather than linking OpenSSL.
