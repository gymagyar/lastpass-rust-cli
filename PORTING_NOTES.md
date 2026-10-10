# Porting notes

## Source and module mapping

The source supplied by the user is `lastpass-cli-master(1).zip`.
Its SHA-256 is
`ef60ab7ec7a2a1d1b7aee24b50fff8cbeca6150711caf9e754d70e459ddc00d5`.
The port was made from that extracted source, not from a downloaded replacement.
The C code is a reference for protocol behavior and fixture expectations; no C
LastPass library or executable is used at runtime.

| Supplied C source | Rust implementation |
|---|---|
| `kdf.c`, `cipher.c` | `src/crypto.rs` |
| `blob.c`, `blob.h` | `src/blob.rs`, `src/model.rs` |
| `http.c` | `src/transport.rs` |
| `xml.c`, endpoint response parsing | `src/xml.rs` |
| `endpoints-login.c`, `endpoints.c` | `src/client.rs` |
| `agent.c`, `config.c` | `src/agent.rs`, `src/store.rs` |
| `notes.c`, `format.c`, shared command helpers | `src/commands.rs`, `src/model.rs`, `assets/note_templates.json` |
| `cmd-*.c`, `lpass.c` | `src/cli.rs` |
| `cmd-share.c` | `src/sharing.rs`, CLI share subcommands |
| `cmd-passwd.c` | `src/password_change.rs`, CLI `passwd` |

Vault records handled include LPAV, ACCT, ACFL, ACOF, SHAR, AACT, AACF, ATTA,
LOCL, and ENDM. Unknown chunks are skipped for forward compatibility. Bounds
are checked before reading lengths. Shared-folder wire chunks are retained when
serializing valid folders. CBC and legacy ECB field encryption, encrypted URLs,
private-key envelopes v1/v2, secure-note fields, application fields, and
attachment keys are implemented.

## Deliberate implementation changes

- The executable is named `lpass-rs`. CLI command families are ported; every C
  switch, alias, output layout, or filesystem convention is not a drop-in match.
- Local encrypted state has a separate AES-GCM format. C cache files, aliases,
  pinentry integration, configuration scripts, and `--plaintext-key` are not
  imported. C Unix-socket agent compatibility is not provided.
- The key agent uses an authenticated IPv4 loopback TCP connection and a random
  32-byte owner-private token. This container rejects Unix-domain socket binding.
  The key is sent to the child over stdin, never through argv or a persistent key
  file. The implementation uses zeroizing secret containers; it does not call
  `mlock` or make a general guarantee that no copy can ever enter swap.
- Plain listing output is flat rather than the C tree rendering. `--color` is
  accepted, but output is plain. Some output compatibility switches (`show
  --quiet`, `show --all`) are accepted without changing the basic field display.
  Long listing timestamps retain the server's string representation.
- Regex matching follows the Rust regex engine, not POSIX basic-regex syntax.
- Password generation accepts lengths 4 through 4096 and guarantees a member of
  each enabled character class, rather than the C generator's unrestricted
  length and independent character selection.
- The default refresh age is 300 seconds. Auto-mode mutations send immediately;
  explicit no-sync mutations are encrypted and queued. Cross-share moves require
  immediate synchronization. Queued requests are retried on a later sync but
  have no server-side idempotency token; a lost acknowledgement can make a retry
  duplicate a newly created item.
- Missing/invalid field ciphertext is reported rather than silently becoming an
  empty value. Invalid-length shared keys are counted separately, with affected
  items omitted and an explicit CLI warning. This follows C rejection of the
  folder key while avoiding C fallback decryption using the unrelated master key.
- HTTPS certificate validation remains enabled. Production destinations are
  restricted to `lastpass.com` and `lastpass.eu`; an explicit loopback HTTP server
  is allowed for tests. Redirects are not followed. A logout 3xx is accepted,
  matching the supplied libcurl behavior, without forwarding credentials to a
  redirect destination.
- Master-password change is staged through `PasswordChange` before explicit
  commit. The CLI requires matching new-password prompts and refuses rotation
  when the loaded vault contains unavailable shared folders.

The C source's requested minimum PBKDF2 iteration count of 2 is retained. The
Rust port also caps it at 10 million to bound untrusted-server computation.
The recorded live account uses 1 million iterations.

## Verification boundaries

Live verification covers authentication and read-only access to the supplied
account. Mutations, share administration, attachment handling, and password
rotation have synthetic/mock coverage. They were not exercised by changing the
user's real vault, sending invitations, or replacing the master password.
MFA and EU redirection have protocol-level mock coverage; the real account login
did not require those paths. Platform testing was on Linux x86_64 only.

This is an initial implementation, not a statement of complete option/output
parity or an independent security audit. Dependencies are fixed by Cargo.lock.
