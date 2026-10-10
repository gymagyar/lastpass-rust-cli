# Source attribution

This Rust port derives protocol behavior, command behavior, note templates, and
synthetic test expectations from the user-supplied LastPass CLI C source.

Upstream notices identify LastPass as copyright holder, including:

- encrypted vault parsing: Copyright (C) 2014-2025 LastPass
- cryptographic helpers: Copyright (C) 2014-2024 LastPass
- key derivation, login endpoints, and secure-note routines:
  Copyright (C) 2014-2018 LastPass

The original source is distributed under GNU GPL version 2 or, at your option,
any later version. This modified Rust version uses the same GPL-2.0-or-later
license. `COPYING` is retained. `LICENSE.OpenSSL` is retained for upstream
provenance; the Rust program uses Rust cryptographic crates and rustls and does
not link OpenSSL.

The original program's OpenSSL exception text is in the supplied source and
LICENSE.OpenSSL. This Rust port does not extend that special linking exception
for the modified implementation. The corresponding Rust source is included
in this repository.

Synthetic fixture credentials and RSA keys in tests/fixtures are generated test
material. They do not belong to the live test account. No live password, session
token, decrypted vault item, or attachment is included in this distribution.
