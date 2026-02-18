# Architecture (Policy Guardian v1.0)

Policy Guardian is intentionally small and deterministic.

## Packages

- `internal/shared/`
  - `cliapp/` — CLI routing and exit codes
  - `jcs/` — RFC 8785 canonicalization
  - `hashing/` — sha2-256 helpers
  - `zipdet/` — deterministic ZIP writer + entry validation
  - `timefmt/` — strict UTC timestamp parsing/formatting

- `internal/policylock/`
  - snapshot creation (file/url/stdin)
  - verification (zip-slip protection + hash checks)
  - show (human-readable summary)

- `internal/consentguardian/`
  - consent creation (deterministic JSON)
  - verification (hash/signature enforcement + optional snapshot resolution)

## Binaries

- Mode A: `cmd/policyguardian` → `policyguardian.exe`
- Mode B wrappers:
  - `cmd/policylock` → `policylock.exe` (prepends `policylock`)
  - `cmd/consentguardian` → `consentguardian.exe` (prepends `consent`)

All binaries call the same internal packages (no drift).

## Determinism rules

- PolicyLock packs: deterministic ZIP writing (STORE, fixed timestamps, sorted paths)
- Consent events: deterministic signing bytes via RFC 8785 JCS (omit absent fields; never null)

See `SPEC_POLICY_GUARDIAN_V0_1_FROZEN.md` for the v1.0 contract.
