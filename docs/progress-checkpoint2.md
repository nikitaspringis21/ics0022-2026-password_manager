# Progress Note — Checkpoint 2 (Week 9)

**Status:** all Checkpoint 2 core requirements are implemented, tested
(49 automated tests, all passing) and documented. Build/run steps are in
the [README](../README.md#build--run-clean-machine).

## Requirement checklist

| Requirement | Status | Where / how |
|---|---|---|
| Basic vault storage working | Done | `storage/file_storage.py`: single JSON envelope, atomic write (temp file → `fsync` → `os.replace`), `0600` permissions; warns if the file becomes group/world-readable. Commands: `init`, `add`, `get`, `show`, `list`, `delete`. |
| Credentials encrypted at rest with the chosen scheme | Done | Argon2id (64 MiB, t=3, p=4, 128-bit salt) → 256-bit key → AES-256-GCM over the whole entry list, fresh 96-bit nonce per save, `{version, kdf}` header bound as AAD. Test `test_envelope_contains_no_plaintext` checks titles/usernames/passwords never appear in the file. |
| Master password authentication; vault unlocks only on successful verification | Done | `vault/session.py::unlock`. Verification is trial decryption: a `Session` is only constructed after the GCM tag verifies, so a wrong password can never yield vault contents. 3 attempts per command, then a generic error. No password hash is stored. |
| Usable interface that never prints passwords in cleartext | Done | `cli.py`. `get --show` was removed; `get` copies to the clipboard and auto-clears it after 20 s; `show` masks the password; `add --generate` creates one that is never displayed; all secret input is via non-echoing `getpass`. Test `test_no_command_prints_the_password` checks stdout/stderr of every command. |
| Build/run instructions for a clean machine; incremental commits | Done | README rewritten and verified in a fresh virtualenv. Work for this checkpoint is split into separate commits (auth hardening → interface → tests → docs). |

## What changed since Checkpoint 1

**Authentication and vault loading**
- The vault is returned only after successful GCM verification; retry loop (3 attempts) with a generic failure message.
- Envelope structure is validated *before* any crypto runs. Missing, corrupted or non-JSON files give a clear error instead of a Python traceback.
- **New finding, fixed:** the header is authenticated only *after* key derivation, so an attacker who could edit `vault.json` could set `memory_cost` to many GB and exhaust memory before the tag check. Argon2id parameters are now bounds-checked (19 MiB–4 GiB, t 1–20, p 1–16, exact salt length).
- **Bug fixed:** `zero(bytearray(password))` wiped a *copy*, not the secret. The master password is now held in a `bytearray` from the prompt onward and the original buffer is zeroed. The derived key is also wiped after `init`, and `Session.lock()` clears the decrypted entries.
- Minimum master-password policy at `init` (≥ 12 characters, not trivially repetitive), covering threat M2.
- `init` refuses to overwrite an existing vault.

**Interface**
- Removed `get --show` (it printed the password to stdout).
- Clipboard auto-clear (threat I2): cleared after `--clear-after` seconds (default 20) or immediately on Ctrl+C. The clipboard is only cleared if it still holds our password. The key is dropped *before* the wait.
- If no clipboard backend exists, `get` fails with installation guidance and never falls back to printing.
- New `show` (masked), `add --generate` (CSPRNG via `secrets`), entry-password confirmation, delete confirmation.
- Text from the vault is sanitised before printing, so a title or note containing ANSI escape sequences can't manipulate the terminal.
- Clean handling of Ctrl+C / EOF (exit 130, no traceback).

**Tests**
- Added the `tests/` suite (it was referenced in the Checkpoint 1 README but not committed): 49 tests across KDF, cipher, vault, session/auth, storage and CLI.

## Known limitations (accepted for now)

- Python `str` objects (from `getpass`, and decrypted entries) cannot be reliably wiped from memory (threat V1). Documented, not solved.
- `--notes`, `--username` and `--url` are CLI arguments and therefore visible in shell history and `ps`. They are documented as non-secret fields.
- Argon2id parameters are the OWASP baseline. On the development VM one derivation takes about 0.1 s, so the cost can likely be raised. Final tuning is planned for Checkpoint 3.
- The clipboard wait blocks the terminal for the timeout. A background clearer was rejected for now because handing the password to a child process safely (not via argv) adds complexity.

## Plan for Checkpoint 3

- `change-master` (re-encrypt with a new salt and key) and `edit` commands.
- Argon2id benchmark and tuning to about 0.5–1 s unlock on target hardware.
- Stronger master-password estimator (zxcvbn) and an optional strength check for stored entries.
- Hardening: disable core dumps / `mlock` where available (V2), and a security review of the code with a static analyser (bandit) and dependency audit (pip-audit).