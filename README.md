# Secure Password Manager

A local-first, offline CLI password manager, built as coursework for
*Secure Programming*. This repository currently covers **Checkpoint 1**:
threat model, architecture, and an initial, working crypto core.

## Scope (Checkpoint 1)

In scope:
- A single-user, single-vault, local CLI tool (no network, no sync).
- Master-password-derived encryption of a vault file on disk.
- Basic CRUD on password entries (add / get / list / delete).

Explicitly out of scope for now (see `docs/threat-model.md`):
- Multi-device sync.
- Protection against a fully compromised OS/kernel.
- Browser integration / autofill.

Full design detail:
- [`docs/architecture.md`](docs/architecture.md) — module breakdown and data flow.
- [`docs/threat-model.md`](docs/threat-model.md) — threats and mitigations.
- [`docs/design-decisions.md`](docs/design-decisions.md) — vault format and crypto scheme.

## Planned commands

| Command | Status | Description |
|---|---|---|
| `pwmanager init` | working | Create a new, empty vault, prompting for a master password |
| `pwmanager add <title>` | working | Add an entry (prompts for its password) |
| `pwmanager get <title>` | working | Copy an entry's password to the clipboard (`--show` to print instead) |
| `pwmanager list` | working | List entry titles |
| `pwmanager delete <title>` | working | Remove an entry |
| auto-lock timeout | planned | Not yet implemented — see design-decisions.md open questions |
| password generator | planned | `pwmanager generate` — not yet implemented |

## Build & run

Requires Python 3.10+.

```bash
# from the repository root
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -e .                # installs the `pwmanager` command

# use it
pwmanager init
pwmanager add "GitHub" --username alice --url https://github.com
pwmanager list
pwmanager get "GitHub"          # copies to clipboard
pwmanager get "GitHub" --show   # prints instead
pwmanager delete "GitHub"
```

By default the vault is created at `./vault.json`; pass `--vault
/path/to/file.json` to any command to use a different location.

## Running the tests

```bash
pytest
```

Tests cover the crypto core (KDF determinism, AEAD seal/unseal
round-trips, tamper and wrong-key detection) and a full vault
seal/unseal round-trip. See `tests/`.

## Project layout

See the "Repository layout" section of
[`docs/architecture.md`](docs/architecture.md).

## Status

Checkpoint 1: architecture, threat model, vault format decided, and a
working (tested) crypto core + minimal CLI. Not yet audited; not yet
recommended for real secrets.
