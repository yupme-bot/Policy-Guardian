POLICY GUARDIAN v0.1 — FINAL FREEZE SPEC

Status: Frozen
Components:

1️⃣ PolicyLock — policy snapshot tool
2️⃣ Consent Guardian — consent recording tool
3️⃣ Shared Canonical JSON + Rules

Design goals:

• deterministic
• privacy-minimized
• offline-verifiable
• CLI-first
• Guardian-Kernel compatible
• no dashboards / no inference

0️⃣ Trust Chain
PolicyLock snapshot
      ↓
Consent Guardian record
      ↓
Guardian Kernel sealing (optional)
      ↓
Verifier / Proof Lab


This proves:

👉 what policy existed
👉 which policy user agreed to
👉 when agreement was recorded

1️⃣ Shared Rules (Both Tools)
1.1 Canonical JSON Standard

Policy Guardian canonical JSON = RFC 8785 (JCS).

All signing payloads use:

• UTF-8
• Unicode NFC normalization
• lexicographic key ordering
• integers only (no floats)
• omit optional fields (never null)

This guarantees cross-language determinism.

1.2 Timestamp Format

All timestamps MUST be:

YYYY-MM-DDTHH:MM:SSZ


• UTC only
• no sub-seconds
• leap seconds clamped to :59

1.3 Hash Format

All hashes use explicit algorithm identifiers:

"hashes": {
  "sha2-256": "hex..."
}


All signatures specify:

"algorithm": "ed25519"

1.4 Snapshot Resolution Model

Consent Guardian resolves PolicyLock snapshot by:

1️⃣ local content-addressable store keyed by snapshot_id
2️⃣ optional object-store backend
3️⃣ CLI override path

If snapshot not found → PARTIAL.

Snapshot packs are immutable artifacts.

1.5 Optional Fields Rule

Absent fields are omitted, never null.

This rule is identical across both tools.

2️⃣ PolicyLock v0.1
2.1 Purpose

Freeze policy bytes into a deterministic snapshot pack.

Proves:

👉 exact policy text
👉 provenance metadata
👉 optional existence-at-time-T

2.2 Snapshot Pack Contents

Required:

policy_snapshot.json
policy_body.bin


Optional:

signature.ed25519.json
anchor/*

2.3 Deterministic ZIP Rules

• Compression: STORE
• Path separator: /
• File order: lexicographic byte order
• Fixed entry timestamp
• No OS metadata

ZIP must be reproducible byte-for-byte.

2.4 RAW Mode Only

policy_body.bin = exact bytes.

No newline normalization.
No charset decoding.
No HTML/PDF parsing.

2.5 URL Metadata Stored

• requested_url
• final_url
• redirect_count
• http_status
• content_type
• etag
• last_modified
• retrieved_at_utc
• resolved_ip
• tls_version
• tls_leaf_cert_sha256
• tls_subject_cn_san
• cross_domain_redirect

Minimal request headers stored.

2.6 Signing Payload

Includes:

• created_at_utc
• policy.input
• policy.fetch
• policy.bytes.hashes
• minimal request headers

Excludes:

• signing block
• anchoring
• snapshot_id

Compute:

sign_payload_bytes = RFC8785(sign_payload)
snapshot_id = SHA256(sign_payload_bytes)


Signature optional but recommended.

2.7 Anchoring

Optional anchor types:

• RFC 3161 TSA
• Transparency log
• OpenTimestamps

Earliest verified anchor is authoritative.

Warn if anchors differ >1 hour.

2.8 Exit Codes
0 success
2 integrity failure
3 unsupported
4 input error
5 network error
6 anchors unavailable
7 anchor invalid

3️⃣ Consent Guardian v0.1
3.1 Purpose

Record deterministic consent events referencing PolicyLock snapshot.

Proves:

👉 user agreed
👉 to specific policy text
👉 at a specific time

3.2 consent_event.json Schema
{
  "schema": "consentguardian.consent_event.v0.1",
  "spec_url": "...",

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

  "context": {
    "purpose": "...",
    "app_id": "...",
    "app_version": "...",
    "language": "...",
    "affirmation_type": "...",
    "jurisdiction": "...",
    "version_label": "...",
    "version_identifier": "..."
  },

  "evidence": {
    "presentation_mode": "...",
    "session_token_hash": "optional"
  },

  "signing": {
    "mode": "none|ed25519",
    "algorithm": "ed25519",
    "public_key": "...",
    "key_description": "...",
    "legal_entity_name": "...",
    "signature_file": "..."
  }
}


Unsigned records labeled INTEGRITY-ONLY.

3.3 subject_id_hash Definition
normalized_identifier =
NFC(lowercase(identifier_UTF8))

subject_id_hash =
SHA256(environment_pepper || tenant_salt || normalized_identifier)


Notes:

• pepper stored in secrets manager
• tenant_salt stored per tenant
• loss of salt → cannot correlate users
• records are pseudonymous personal data

3.4 Signing Payload

Includes:

• created_at_utc
• policy section
• subject section
• context section
• evidence section

Excludes:

• signing block

Compute:

consent_event_id = SHA256(RFC8785(sign_payload))


Signing recommended for audit use.

3.5 Replay Protection

Guardian Kernel must deduplicate consent_event_id.

Optional session_token_hash strengthens replay resistance.

3.6 Known v0.1 Gaps

Out-of-scope:

• consent revocation
• policy validity windows
• batch consent records
• identity verification
• UI capture proof

These will be v0.2 items.

4️⃣ Security Notes

Policy Guardian proves:

✔ policy version existed
✔ consent recorded

It does NOT prove:

✖ user identity
✖ UI displayed correctly
✖ policy legally valid

Supply-chain trust required:

• open source
• reproducible builds
• signed releases

5️⃣ Interoperability Requirements

Before release MUST ship:

• JSON Schemas
• Golden test vectors
• Reference verifier
• Example snapshot + consent pair

Verifiers must ignore unknown fields for forward compatibility.