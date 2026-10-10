# Build instructions

The project pins Rust **1.85.0** in `rust-toolchain.toml` and uses edition 2024.
Use rustc and Cargo from the same toolchain. Dependency versions are recorded in
`Cargo.lock`. The source has been built and tested on Ubuntu 24.04.3 x86_64.

## Prerequisites

Install Rust using [rustup](https://rustup.rs/). With rustup installed:

```sh
rustup toolchain install 1.85.0 --profile minimal
rustup component add --toolchain 1.85.0 rustfmt clippy
```

A native C linker is required for dependencies. On Ubuntu or Debian:

```sh
sudo apt-get update
sudo apt-get install build-essential ca-certificates
```

On macOS, install the Apple command-line development tools with
`xcode-select --install`. The macOS build has not been tested. Clipboard output
uses an installed OS helper such as `pbcopy`, `wl-copy`, or `xclip`; this is not
needed for ordinary terminal output.

## Clone and compile

```sh
git clone https://github.com/gymagyar/lastpass-rust-cli.git
cd lastpass-rust-cli
cargo build --release --locked -j1
./target/release/lpass-rs --version
./target/release/lpass-rs --help
```

The first build downloads the locked dependency sources. OpenSSL development
packages are not required: networking uses rustls. Single-job builds and one
codegen unit are configured for reliable compilation in the original container.

## Test and check

```sh
cargo test --locked -j1
cargo fmt --all -- --check
cargo clippy --all-targets --locked -j1 -- -D warnings
```

The normal suite runs 59 synthetic/mock tests and skips the live account test.
It does not require LastPass credentials. Checked-in binary and JSON fixtures
contain generated test material only. Python is not required to build or run
these Rust tests.

To regenerate fixtures, install Python's `cryptography` package in a virtual
environment and run `scripts/generate_test_fixtures.py`. Regeneration makes a
new synthetic RSA key pair; it is optional.

## Install locally

```sh
cargo install --path . --locked -j1
lpass-rs --help
```

Cargo installs the executable into its user bin directory, normally
`~/.cargo/bin`. Ensure that directory is in your shell's PATH. You can also run
`target/release/lpass-rs` directly without installing it.

## Authenticate and read the vault

```sh
lpass-rs login your-email@example.com
lpass-rs sync
lpass-rs ls --sync=no
lpass-rs show --sync=no --username ITEM_ID
lpass-rs show --sync=no --password ITEM_ID
lpass-rs logout
```

The password is read through a hidden prompt. `--password-stdin` reads a single
line from stdin for automation. Credentials do not belong in source files,
commits, or command-line arguments. Live read-only test instructions are in
README.md; TEST_RESULTS.md records the original validation and the unavailable
shared-folder records.

## Optional offline dependency copy

The repository uses Cargo's normal registry dependencies. To create an offline
source copy while connected:

```sh
mkdir -p .cargo
cargo vendor --locked --versioned-dirs vendor > .cargo/config.toml
cargo build --release --locked --offline -j1
```

Keep the generated `vendor/` and `.cargo/config.toml` together. Rust and the native
linker must already be installed; `--offline` does not install the toolchain.
These generated dependency copies are ignored by Git.
