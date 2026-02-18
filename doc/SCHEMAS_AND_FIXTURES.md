# Schemas & Fixtures (Policy Guardian v0.1)

## Schemas

Located in `schemas/`:

- `policy_snapshot_v0_1.schema.json`
- `consent_event_v0_1.schema.json`
- `signature_envelope_v0_1.schema.json`

## Fixtures

Located in `fixtures/`:

- `fixtures/policylock/` — raw policy inputs + golden snapshot ZIPs
- `fixtures/consentguardian/` — golden consent events covering VALID/INVALID/PARTIAL and unsigned/signed

## Reference verifier

`tools/ref_verify/` is a minimal verifier intended to validate fixtures deterministically.
