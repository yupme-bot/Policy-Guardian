# Security & Privacy (Policy Guardian v0.1)

Policy Guardian produces **tamper-evident evidence artifacts**:

• PolicyLock snapshot packs — deterministic ZIP archives containing raw policy bytes and metadata + hashes
• Consent Guardian records — deterministic JSON events binding a subject hash to a specific policy snapshot, optionally signed with Ed25519


======================================================================
1. WHAT IS CAPTURED
======================================================================

Policy Guardian captures only the minimum evidence needed for verification.

### PolicyLock
• Raw policy bytes from file / stdin / HTTP response (`--url`)
• Deterministic ZIP output (STORE compression, fixed timestamps, sorted paths)
• Snapshot metadata fields defined in `SPEC_POLICY_GUARDIAN_V0_1_FROZEN.md`
• Cryptographic hashes of captured bytes

No parsing or rewriting of policy text occurs.


### Consent Guardian
• `subject.subject_id_hash` (sha2-256), derived from identifier + tenant salt + pepper
• Snapshot binding:
    - `policy.snapshot_id`
    - `policy.snapshot_pack_sha256`
    - `policy.policy_sha256`
• Optional Ed25519 signature envelope

Consent records are deterministic JSON evidence.


======================================================================
2. WHAT IS NOT CAPTURED
======================================================================

Policy Guardian intentionally does NOT capture:

• UI screenshots or recordings
• Identity verification evidence
• Consent revocation tracking
• Policy canonicalization or rewriting
• Background network calls (except explicit `policylock snapshot --url`)
• Telemetry upload or analytics

Policy Guardian is an evidence generator, not an observability system.


======================================================================
3. CRYPTOGRAPHY & FORMATS
======================================================================

Canonical JSON
--------------
RFC 8785 (JCS) canonical JSON is used for all signing payloads.

• UTF-8 encoding
• Unicode NFC normalization
• Deterministic key ordering
• Optional fields omitted

Hash Format
-----------
All hashes use explicit algorithm identifiers:

    "hashes": { "sha2-256": "<hex>" }

Signing
-------
Optional Ed25519 signatures.

Signing payload = canonical JSON bytes (no trailing newline).

Signature verifies integrity and origin of the consent record,
not identity of the user.


======================================================================
4. ZIP SAFETY
======================================================================

• Zip-slip protection during verification (entry path validation)
• Deterministic ZIP writing removes ambiguity between equivalent archives
• Snapshot packs are immutable artifacts


======================================================================
5. PRIVACY MODEL
======================================================================

Policy Guardian is privacy-minimized.

• Subject identifiers are hashed with tenant salt + environment pepper
• No raw identifiers are stored
• No tracking or analytics

Important notes:

• Pepper MUST be treated as secret material
• Loss of tenant salt prevents cross-record correlation
• Consent records are still pseudonymous personal data under many laws


======================================================================
6. THREAT MODEL
======================================================================

Policy Guardian is designed to detect:

• Modification of policy snapshot bytes
• Modification of consent records
• Substitution of policy snapshot packs
• Reordering or tampering with signed consent artifacts

It is NOT designed to detect:

• Compromised endpoints before snapshot capture
• Fraudulent identity claims
• UI misrepresentation
• Legal invalidity of policy text


======================================================================
7. REPRODUCIBLE BUILDS
======================================================================

For strong supply-chain trust:

• Source code is open
• Builds should be reproducible
• Release artifacts should be signed

Users should verify checksums of release ZIP files.


======================================================================
8. OPERATIONAL GUIDANCE
======================================================================

• Keep `--pepper` secret and out of logs
• Back up snapshot packs and consent records
• Preserve `.policyguardian_store/` when using `--resolve-snapshot`
• Store release SHA-256 hashes with artifacts


======================================================================
9. SECURITY REPORTING
======================================================================

To report a security issue:

1. Do not open a public GitHub issue.
2. Contact the project maintainer directly.
3. Provide reproduction steps and affected version.

A public disclosure policy may be added in future releases.
