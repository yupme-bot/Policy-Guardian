# POLICY GUARDIAN v1.0 — FROZEN SPEC (Schema v0.1)

Status: Frozen  
Tool release: v1.0.0  
Schemas: `policylock.policy_snapshot.v0.1`, `consentguardian.consent_event.v0.1`

Components:
1. PolicyLock — policy snapshot tool
2. Consent Guardian — consent recording tool
3. Shared canonical JSON + rules

Design goals:
- Deterministic (same inputs → same bytes)
- Privacy-minimized
- Offline-verifiable
- CLI-first
- Guardian-family compatible
- No dashboards / no inference / no feature creep

## Trust chain

PolicyLock snapshot  
↓  
Consent Guardian record  
↓  
(Optional) external sealing / evidence packaging  
↓  
Verifier / Proof Lab

This proves:
- What policy bytes existed
- Which policy snapshot a user agreed to
- When that agreement record was created

## 1. Shared rules (both tools)

### 1.1 Canonical JSON standard

Policy Guardian canonical JSON = RFC 8785 (JCS).

All signing payloads use:
- UTF-8
- Unicode NFC normalization
- Lexicographic key ordering
- Optional fields omitted (never `null`)

**Numbers:** signing payloads MUST NOT use floats.

This guarantees cross-language determinism.

### 1.2 Timestamp format

All timestamps MUST be:

`YYYY-MM-DDTHH:MM:SSZ`

- UTC only
- No sub-seconds
- Leap seconds clamped to `:59`

### 1.3 Hash and signature format

Hashes use explicit algorithm identifiers:

```json
"hashes": { "sha2-256": "hex..." }
```

Signatures specify:

```json
"algorithm": "ed25519"
```

### 1.4 Snapshot resolution model

Consent Guardian resolves a PolicyLock snapshot by:
1. Local content-addressable store keyed by `snapshot_id`
2. Optional override path (CLI)

If the snapshot is not found → `PARTIAL` when verification is requested with resolution.

Snapshot packs are immutable artifacts.

### 1.5 Optional fields rule

Absent fields are omitted, never `null`.

## 2. PolicyLock (schema v0.1)

### 2.1 Purpose

Freeze policy bytes into a deterministic snapshot pack.

Proves:
- Exact policy bytes
- Provenance metadata
- Tamper-evident hashing and (optional) signature support

### 2.2 Snapshot pack contents

Required:
- `policy_snapshot.json`
- `policy_body.bin`

Optional:
- `signature_envelope.json` (Ed25519 envelope) and referenced signature files (if used)

### 2.3 Deterministic ZIP rules

- Compression: STORE
- Path separator: `/`
- File order: lexicographic byte order
- Fixed entry timestamps
- No OS metadata

ZIP output must be reproducible byte-for-byte for the same inputs.

### 2.4 RAW mode only

`policy_body.bin` is the **exact bytes** captured.

No newline normalization. No charset decoding. No HTML/PDF parsing.

### 2.5 URL metadata stored

For URL snapshots, metadata MAY include (as implemented):
- requested_url, final_url
- redirect_count (tri-state)
- http_status, content_type
- retrieved_at_utc, resolved_ip
- cross_domain_redirect (tri-state)
- minimal request headers (nested under `policy.fetch.request_headers`)

### 2.6 Signing payload

Includes (conceptually):
- `created_at_utc`
- `policy.input`
- `policy.fetch`
- `policy.bytes.hashes`
- minimal request headers

Excludes:
- signing block
- snapshot_id

Compute:
- `sign_payload_bytes = RFC8785(sign_payload)`
- `snapshot_id = SHA256(sign_payload_bytes)`

Signature is optional but recommended for audit use.

### 2.7 Exit codes

- 0 — VALID
- 1 — PARTIAL
- 2 — INVALID
- 3 — UNSUPPORTED
- 4 — INPUT ERROR
- 5 — NETWORK ERROR

## 3. Consent Guardian (schema v0.1)

### 3.1 Purpose

Record deterministic consent events referencing a PolicyLock snapshot.

Proves:
- A consent record was created
- It binds a subject hash to specific policy bytes (via snapshot hashes)
- It was not tampered with (and optionally signed)

### 3.2 `consent_event.json` structure (high-level)

```json
{
  "schema": "consentguardian.consent_event.v0.1",
  "spec_url": "...",
  "tool_version": "...",
  "created_at_utc": "...",
  "policy": {
    "policy_sha256": "hex...",
    "snapshot_id": "hex...",
    "snapshot_pack_sha256": "hex..."
  },
  "subject": {
    "subject_id_hash": "hex...",
    "hash_algorithm": "sha2-256"
  },
  "signing": {
    "mode": "none|ed25519",
    "algorithm": "ed25519",
    "public_key": "...",
    "signature_file": "..."
  }
}
```

Unsigned records are integrity-only (tamper-evident but not attributable to a signer).

### 3.3 `subject_id_hash` definition

```
normalized_identifier = NFC(lowercase(identifier_utf8))
subject_id_hash = SHA256(environment_pepper || tenant_salt || normalized_identifier)
```

Notes:
- Pepper is secret material (do not log it)
- Tenant salt is per-tenant
- Consent records are pseudonymous personal data under many regimes

### 3.4 Signing payload

Includes:
- `created_at_utc`
- `policy`
- `subject`
- optional context/evidence fields (if present)

Excludes:
- signing block

Compute:
- `consent_event_id = SHA256(RFC8785(sign_payload))`

Signing recommended for audit use.

### 3.5 Replay protection

Systems consuming consent records should deduplicate by `consent_event_id`.

### 3.6 Known v1.0 gaps (intentionally out of scope)

- Consent revocation
- Policy validity windows
- Batch consent records
- Identity verification
- UI capture proof

## 4. Security notes

Policy Guardian proves:
- Policy snapshot bytes existed as captured
- Consent record integrity (and optional signer attribution)

It does NOT prove:
- Real-world user identity
- UI displayed correctly
- Policy is legally valid

## 5. Interoperability requirements (release)

Release should ship:
- JSON Schemas
- Golden fixtures (snapshot + consent pair)
- Reference verifier
- Example snapshot + consent pair

Verifiers should ignore unknown fields for forward compatibility.
