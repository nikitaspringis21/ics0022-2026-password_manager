# Threat Model — Checkpoint 1

Scope: a single-user, offline, local CLI password manager. Out of scope
for this checkpoint: multi-device sync, network attacks, and malicious
insiders with root/kernel-level access (a fully compromised OS can always
defeat a userspace application — this is documented as an accepted
limitation, not mitigated).

Method: assets and trust boundaries first, then threats grouped by the
four areas requested (master password, vault at rest, vault in memory,
interface), each with an intended mitigation and residual risk.

## Assets

- The **master password** (never stored).
- The **derived encryption key** (exists only in memory during a session).
- The **vault file** (`vault.json`) containing all secrets, encrypted.
- The **plaintext entries** while displayed or copied to clipboard.

## Trust boundaries

- Disk (multi-user machine, backups, other processes) — untrusted.
- RAM (other processes, swap, core dumps) — semi-trusted; assumed the OS
  itself is not compromised, but other unprivileged processes might be.
- Terminal / clipboard — semi-trusted; shoulder-surfing, screen recording,
  and other clipboard-reading apps are realistic threats for a password
  manager specifically.

## 1. Master password threats

| # | Threat | Mitigation |
|---|--------|------------|
| M1 | Offline brute-force / dictionary attack against a stolen vault file | Argon2id KDF with high memory/time cost (tunable, see design-decisions.md) makes each guess expensive; salted per-vault so no rainbow tables |
| M2 | Weak master password chosen by user | Minimum length/entropy check at `init` time with a strength estimator (zxcvbn or equivalent); warn, don't silently accept |
| M3 | Shoulder-surfing / terminal echo while typing | Input via `getpass.getpass()` — never echoed to terminal, never logged |
| M4 | Master password ends up in shell history, environment variables, or CLI args | CLI never accepts the password as an argument or flag; interactive prompt only |
| M5 | Online guessing (repeated unlock attempts) | Not applicable in v1 (no network service), but noted as future work if a daemon/API is ever added: attempt throttling / exponential backoff |

## 2. Vault-at-rest threats

| # | Threat | Mitigation |
|---|--------|------------|
| S1 | Attacker reads `vault.json` from disk or a backup | Content is AES-256-GCM encrypted; ciphertext is useless without the master password |
| S2 | Attacker tampers with the vault file (bit-flip, truncation, swapping ciphertext) | GCM provides authenticated encryption — decryption fails closed on any modification (auth tag check), including tampering with associated header data (version/KDF params bound as AAD) |
| S3 | Nonce reuse under the same key, which breaks AES-GCM confidentiality | Fresh random 96-bit nonce generated per encryption operation via CSPRNG (`os.urandom`); the whole vault is re-encrypted as one blob per save so a nonce is only ever used once per key |
| S4 | Other local users / processes reading the file | File created with `0600` permissions (owner read/write only) at rest |
| S5 | Crash or power loss during save corrupts the vault | Atomic write: write to temp file, `fsync`, then `os.replace()` over the original |
| S6 | Salt or KDF parameters tampered with to weaken future key derivation | KDF parameters and salt are covered by the GCM authentication tag (AAD), so tampering is detected on next unlock |

## 3. Vault-in-memory threats

| # | Threat | Mitigation | Residual risk |
|---|--------|------------|----------------|
| V1 | Decrypted secrets lingering in memory and swapped to disk | Sensitive buffers held as mutable `bytearray`s and explicitly zeroed after use; session key is dropped and overwritten on lock | Python's garbage collector and immutable `str`/`bytes` objects can leave copies in memory that cannot be reliably zeroed — this is a documented limitation of pure-Python, not a solved problem |
| V2 | Process memory dump / debugger attached to a running session exposes the key or plaintext | Minimize the time secrets are held decrypted (decrypt on demand, re-lock after idle timeout); avoid passing secrets through more layers/variables than necessary | Full mitigation needs OS-level protections (mlock, no-core-dump) — planned as a stretch goal, not v1 |
| V3 | Secrets left decrypted after the CLI command finishes | Vault auto-locks (key discarded) at the end of every CLI invocation, since each command is a fresh process; no long-running unlocked daemon in v1 | N/A for v1's process-per-command model |

## 4. Interface threats

| # | Threat | Mitigation |
|---|--------|------------|
| I1 | Password printed to stdout and captured by terminal scrollback/logging/screen-recorders | `get` copies the password to the clipboard instead of printing it by default; printing requires an explicit `--show` flag |
| I2 | Password left on the clipboard indefinitely, readable by other apps | Clipboard is cleared automatically after a short timeout (e.g. 20s) after a `get` |
| I3 | Sensitive data written to application logs or error/debug output | No plaintext secret is ever passed to a logging call; exceptions are caught and re-raised with generic messages before any logging layer |
| I4 | Command-line arguments containing secrets visible via `ps`/process list | No command accepts a password or secret value as a CLI argument; all secret input goes through interactive prompts |
| I5 | Malicious/careless entry data (e.g. a "note" containing shell metacharacters) causing injection if ever templated into a shell command | Entries are only ever passed to `subprocess` clipboard calls as argument lists (no `shell=True`), never interpolated into a shell string |

## Explicitly out of scope / accepted risk for Checkpoint 1

- A fully compromised OS/kernel (keyloggers with root, malicious kernel
  modules) — cannot be defended from userspace.
- Multi-device sync and any associated transport security — no such
  feature exists yet.
- Physical attacks with unlimited time and forensic tooling against
  memory (cold boot attacks) — noted, not mitigated in v1.
