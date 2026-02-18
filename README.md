# Policy Guardian v1.0

Policy Guardian is a **Windows-first**, **deterministic** CLI monorepo that ships two tools:

- **PolicyLock** — capture an exact policy snapshot (raw bytes) into a deterministic ZIP “snapshot pack”
- **Consent Guardian** — record a consent event that binds a subject to a specific policy snapshot, with optional Ed25519 signing

This repo supports two build modes (same shared code, no drift):

- **Mode A (default / preferred):** one binary with subcommands  
  `policyguardian.exe policylock ...` and `policyguardian.exe consent ...`
- **Mode B (optional wrappers):** two small wrapper binaries built from the same repo  
  `policylock.exe` and `consentguardian.exe` (they call the same internal packages)

## Design goals

- **Deterministic outputs** (same input → same bytes)
- **RFC 8785 (JCS) canonical JSON** for all signing payloads (UTF‑8 bytes, no trailing newline)
- **Raw bytes only** for PolicyLock snapshots (no parsing, no “canonicalization” of policy content)
- **Deterministic ZIP writer** (STORE, fixed timestamps, sorted paths) with zip-slip protection
- No UI. No CANON modes. No revocation model. No feature creep.

## Repo layout

```
policyguardian/
  cmd/
    policyguardian/      (main CLI with subcommands)
    policylock/          (wrapper binary)
    consentguardian/     (wrapper binary)

  internal/
    policylock/
    consentguardian/
    shared/
      cliapp/
      jcs/
      hashing/
      zipdet/
      timefmt/

  schemas/
  fixtures/
    policylock/
    consentguardian/

  tools/
    ref_verify/
    scripts/
```

## Quickstart (fresh unzip)

Start here: `FRESH_UNZIP_QUICKSTART.md`

## Build (Windows / PowerShell)

```powershell
mkdir dist -ErrorAction SilentlyContinue

go build -trimpath -buildvcs=false -o dist\policyguardian.exe .\cmd\policyguardian
go build -trimpath -buildvcs=false -o dist\policylock.exe .\cmd\policylock
go build -trimpath -buildvcs=false -o dist\consentguardian.exe .\cmd\consentguardian

.\dist\policyguardian.exe --version
```

### Important CLI rule (flags come first)

These CLIs use Go `flag`. **Flags must come before positional args.**

✅ Good:
```powershell
.\dist\policyguardian.exe policylock snapshot --out out\snap.zip fixtures\policylock\policy1.txt
```

❌ Bad:
```powershell
.\dist\policyguardian.exe policylock snapshot fixtures\policylock\policy1.txt --out out\snap.zip
```

## CLI overview

### PolicyLock

- Snapshot (file):
  ```powershell
  .\dist\policyguardian.exe policylock snapshot --out policy_snapshot.zip fixtures\policylock\policy1.txt
  ```

- Verify:
  ```powershell
  .\dist\policyguardian.exe policylock verify policy_snapshot.zip
  ```

  For URL snapshots, `verify` prints a `policy_sha256` line. If two URL snapshots differ, compare `policy_sha256`:

  - If `policy_sha256` differs, the remote bytes changed between fetches (common on dynamic websites).
  - If `policy_sha256` matches and you also pinned `--created-at`, the snapshot ZIP should be byte-identical.

- Show:
  ```powershell
  .\dist\policyguardian.exe policylock show policy_snapshot.zip
  ```

### Consent Guardian

- Record (unsigned):
  ```powershell
  .\dist\policyguardian.exe consent record --subject "Alice Example" --tenant-salt 0011 --pepper aabb --out consent.json demo_snapshot.zip
  ```

- Record (signed, Ed25519):
  ```powershell
  .\dist\policyguardian.exe consent record --subject "Alice Example" --tenant-salt 0011 --pepper aabb --sign-privkey <64-byte-privkey-hex> --out consent_signed.json demo_snapshot.zip
  ```

- Verify:
  ```powershell
  .\dist\policyguardian.exe consent verify consent.json
  ```

- Verify + resolve snapshot:
  ```powershell
  .\dist\policyguardian.exe consent verify --resolve-snapshot consent.json
  ```

## Exit codes

- `0` — VALID
- `1` — PARTIAL
- `2` — INVALID
- `3` — UNSUPPORTED
- `4` — INPUT ERROR
- `5` — NETWORK ERROR

## Schemas, fixtures, verifier, demo

- Schemas: `schemas/`
- Fixtures: `fixtures/`
- Reference verifier: `tools/ref_verify/`
- Demo scripts: `tools/scripts/`

Run the demo:

```powershell
.\tools\scripts\demo.ps1
```

Full release checklist: `RELEASE_TESTS.md`

## Security & privacy

See `SECURITY.md`.

## URL snapshots, determinism, and dynamic websites

PolicyLock snapshots URLs as **RAW bytes**. Many modern websites are dynamic (cookies, rotating IDs, injected banners), so two fetches can legitimately return different bytes.

When you verify a URL snapshot, PolicyLock prints:

- `policy_sha256` — the SHA-256 of the captured policy bytes
- URL fetch context (status, content type, final URL, etc.)
- A note: if two URL snapshots differ, compare `policy_sha256` to confirm whether the remote bytes changed

**Tip:** Quickly compare the key fields:

```powershell
.\dist\policyguardian.exe policylock show <snapshot.zip> | Select-String "policy_sha256|retrieved_at_utc|final_url|content_type|http_status"
```

If you need byte-identical URL snapshots for testing, pin time using `--created-at` (it pins `retrieved_at_utc` for URL snapshots), and ensure the remote bytes are stable (PDFs usually are).

Note: the release ZIP includes an `out/` folder so you can run demos/tests immediately.
