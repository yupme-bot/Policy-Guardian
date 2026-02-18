# Changelog

## v1.0.0 — Policy Guardian v1.0 Release (Freeze + Build Fixes)

This release is the **v1.0.0 tagged** baseline for Policy Guardian (PolicyLock + Consent Guardian).

### Freeze fixes (audit-grade determinism)
- **tool_version required** (no omitempty; verified in tests)
- **request_headers moved under policy.fetch** (not top-level)
- **redirect_count is tri-state** (`*int`) to distinguish “not tracked” vs `0`
- **cross_domain_redirect is tri-state** (`*bool`) to distinguish “not tracked” vs `false`
- **snapshot_id excluded from signing payload** (explicit boundary clarified)
- **mode invariants enforced** (file/url/stdin correctness)

### Release notes
- Windows-first CLI binaries in `dist/`
- Deterministic fixtures + JSON schemas in `fixtures/` + `schemas/`
- Reference verifier in `tools/ref_verify/`

