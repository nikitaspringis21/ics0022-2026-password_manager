# Secure Password Manager

A local-first, offline CLI password manager, built as coursework for
*Secure Programming* (ICS0022). This repository is at **Checkpoint 2**:
core requirements implemented. See
[`docs/progress-checkpoint2.md`](docs/progress-checkpoint2.md) for the
progress note.

## Scope

In scope:
- A single-user, single-vault, local CLI tool (no network, no sync).
- Master-password-derived encryption of a vault file on disk
  (Argon2id → AES-256-GCM).
- Basic CRUD on password entries (add / get / show / list / delete).

Explicitly out of scope (see `docs/threat-model.md`):
- Multi-device sync.
- Protection against a fully compromised OS/kernel.
- Browser integration / autofill.

Full design detail:
- [`docs/architecture.md`](docs/architecture.md) — module breakdown and data flow.
- [`docs/threat-model.md`](docs/threat-model.md) — threats, mitigations and implementation status.
- [`docs/design-decisions.md`](docs/design-decisions.md) — vault format and crypto scheme.

## Commands

| Command | Status | Description |
|---|---|---|
| `pwmanager init` | working | Create a new, empty vault, prompting for a master password (min. 12 chars) |
| `pwmanager add <title>` | working | Add an entry; its password is prompted (twice), never passed as an argument |
| `pwmanager add <title> --generate` | working | Add an entry with a random password (`--length N`, default 20) |
| `pwmanager get <title>` | working | Copy the password to the clipboard; cleared after 20 s (`--clear-after N`) |
| `pwmanager show <title>` | working | Show username/URL/notes/timestamps — password is masked |
| `pwmanager list` | working | List entry titles |
| `pwmanager delete <title>` | working | Remove an entry (asks for confirmation; `-y` to skip) |
| change master password | planned | Checkpoint 3 |
| edit entry | planned | Checkpoint 3 |

**Passwords are never printed to the terminal.** There is deliberately
no `--show`/`--reveal` option. Every command that reads the vault asks
for the master password; the vault is decrypted only if it is correct
(3 attempts per command).

## Build & run (clean machine)

Requires **Python 3.10+** and `git`. No other system packages are
needed to build, run and test.

```bash
git clone <this-repo-url> password-manager
cd password-manager

python3 -m venv .venv
source .venv/bin/activate            # Windows (PowerShell): .venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -e .                     # installs the `pwmanager` command

pwmanager --version
```

### Example session

```bash
pwmanager init                                   # choose a master password
pwmanager add "GitHub" --username alice --url https://github.com
pwmanager add "Email" --username alice@example.com --generate
pwmanager list
pwmanager show "GitHub"                          # password shown as ********
pwmanager get "GitHub"                           # copied, cleared after 20 s
pwmanager delete "GitHub"
```

By default the vault is `./vault.json` (git-ignored). Pass
`--vault /path/to/file.json` **before** the command to use another file,
e.g. `pwmanager --vault ~/secrets.json list`.

### Clipboard support

`get` needs a clipboard backend (via `pyperclip`):

- **Windows / macOS:** works out of the box.
- **Linux:** install one of `xclip`, `xsel` (X11) or `wl-clipboard`
  (Wayland), e.g. `sudo apt install xclip`.
- **Headless / SSH without X:** `get` exits with an error instead of
  printing the password. All other commands work normally.

## Running the tests

```bash
pytest            # from the repository root, inside the venv
```

49 tests cover the crypto core (Argon2id determinism and parameter
bounds, AES-GCM round-trip, wrong key / tamper / AAD detection, nonce
uniqueness), vault seal/unseal and malformed-file handling, master
password authentication (correct, wrong ×3, retry, weak password,
key wiping on lock), storage (0600 permissions, atomic writes), and the
CLI — including a check that no command ever outputs a stored password.

## Project layout

See the "Repository layout" section of
[`docs/architecture.md`](docs/architecture.md).

## Status

Checkpoint 2: core requirements implemented and tested. Not yet
independently audited; not recommended for real secrets.