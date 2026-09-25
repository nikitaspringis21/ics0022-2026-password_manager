# Initial Design Decisions — Checkpoint 1

These are starting points for Checkpoint 1, chosen for being
well-vetted, boring, and easy to justify — not novel. They can be
revisited once encryption/decryption is implemented and reviewed.

## 1. Cryptographic scheme

| Choice | Value | Why |
|--------|-------|-----|
| Key derivation function | **Argon2id** (`argon2-cffi`) | Winner of the Password Hashing Competition; the `id` variant resists both GPU/ASIC cracking and side-channel attacks; recommended by OWASP over PBKDF2/bcrypt/scrypt for new designs |
| KDF parameters (starting point) | time_cost=3, memory_cost=65536 KiB (64 MB), parallelism=4 | OWASP baseline recommendation; will be benchmarked on target hardware in a later checkpoint and tuned so unlock takes roughly 0.5–1s |
| Symmetric cipher | **AES-256-GCM** (`cryptography` library, `AESGCM`) | Authenticated encryption (confidentiality + integrity) in one primitive; hardware-accelerated (AES-NI) so it's fast even with large vaults; avoids the classic "encrypt-then-forget-to-MAC" mistake |
| Nonce | 96-bit, `os.urandom(12)`, generated fresh every encryption | Standard GCM nonce size; the whole vault is encrypted as a single blob per save, so a (key, nonce) pair is used exactly once |
| Salt | 128-bit, `os.urandom(16)`, generated once at vault creation, stored alongside the vault | Per-vault salt defeats precomputed/rainbow-table attacks; does not need to be secret |
| Associated data (AAD) | Serialized `{version, kdf params}` header | Binds the header to the ciphertext so an attacker can't swap in weaker KDF parameters or a different version without the tag check failing |
| Master password storage | **Not stored at all**, not even hashed | The correctness of the derived key is implicitly verified by successful GCM decryption (the auth tag check). Storing a separate password hash would be redundant and would add another artifact to protect |

Libraries deliberately avoided: hand-rolled crypto, MD5/SHA1 for
anything security-relevant, ECB mode, and any home-grown "obfuscation".

## 2. Vault file format (v1)

A single JSON file, `vault.json`, containing one opaque envelope. Binary
fields are base64-encoded so the file stays plain JSON:

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt": "base64(16 random bytes)",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4
  },
  "cipher": {
    "algorithm": "AES-256-GCM",
    "nonce": "base64(12 random bytes)"
  },
  "ciphertext": "base64(AES-GCM output, tag included)"
}
```

The **plaintext** that gets encrypted (never written to disk on its own)
is itself JSON:

```json
{
  "entries": [
    {
      "id": "uuid4",
      "title": "GitHub",
      "username": "alice",
      "password": "correct horse battery staple",
      "url": "https://github.com",
      "notes": "",
      "created_at": "2026-09-25T12:00:00Z",
      "updated_at": "2026-09-25T12:00:00Z"
    }
  ]
}
```

**Why one encrypted blob for the whole vault, rather than per-entry
encryption:** simpler to reason about for Checkpoint 1 (one nonce per
save, one auth tag to check, atomic write of one file), and vault sizes
for a personal password manager are small enough that decrypting
everything on unlock is not a performance concern. Per-entry encryption
(so a search doesn't require decrypting everything) is listed as a
possible future iteration once the basic scheme is reviewed.

## 3. Open questions for the next checkpoint

- Exact Argon2id parameter tuning on real target hardware.
- Auto-lock timeout value and whether to support a short-lived unlocked
  daemon (would reopen the "long-lived key in memory" tradeoffs in the
  threat model).
- Whether to add an optional password-strength check for stored entries
  themselves, not just the master password.
- Backup/export format (would need its own threat model).
