# Security & Privacy (Policy Guardian v0.1)

Policy Guardian produces tamper-evident artifacts:

- **PolicyLock snapshot packs** (deterministic ZIP) containing raw policy bytes and metadata + hashes
- **Consent events** binding a subject hash to a specific policy snapshot pack and policy hash, with optional Ed25519 signing

## What is captured

### PolicyLock
- Raw bytes from file / stdin / HTTP response (`--url`)
- Deterministic ZIP output (STORE, fixed timestamps, sorted paths)
- Metadata fields as defined in `SPEC_POLICY_GUARDIAN_V0_1_FROZEN.md`

### Consent Guardian
- `subject.subject_id_hash` (sha2-256), derived from subject identifier + tenant salt + pepper
- Snapshot binding: `policy.snapshot_id`, `policy.snapshot_pack_sha256`, `policy.policy_sha256`
- Optional Ed25519 signature envelope (when enabled)

## What is NOT captured
- No UI
- No revocation model
- No “canonicalization” of policy bytes
- No background network calls (except explicit `policylock snapshot --url`)
- No telemetry upload

## Crypto / formats
- Canonical JSON: RFC 8785 (JCS)
- Hash format: `"hashes": { "sha2-256": "<hex>" }`
- Signing bytes: JCS UTF-8 bytes (no trailing newline)
- Optional signing: Ed25519

## ZIP safety
- Zip-slip protection during verification (entry validation)
- Deterministic ZIP writing reduces “same content, different bytes” ambiguity

## Operational guidance
- Treat `--pepper` as secret material. Avoid logging it.
- If you use `--resolve-snapshot`, preserve `.policyguardian_store/` (or set `POLICYGUARDIAN_STORE`).

## Reporting security issues
If this is shared publicly, add a security contact and disclosure policy here.
