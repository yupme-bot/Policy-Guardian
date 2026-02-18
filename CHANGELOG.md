# Changelog

## v1.0.0 — Initial release

- Go monorepo with shared deterministic infrastructure
- Mode A: `policyguardian.exe` with `policylock` and `consent` subcommands
- Mode B: wrapper binaries `policylock.exe` and `consentguardian.exe`
- PolicyLock:
  - Snapshot from file / URL / stdin
  - Deterministic ZIP packs (STORE, fixed timestamps, sorted paths)
  - Zip-slip protection
  - Verification + show
- Consent Guardian:
  - Deterministic consent JSON + sha2-256 `hashes` field
  - Subject hashing (sha2-256) with salt + pepper
  - Snapshot binding and optional store resolution
  - Optional Ed25519 signing + verification
  - Warning on unsigned consent
- Schemas, fixtures, reference verifier, and demo scripts included
