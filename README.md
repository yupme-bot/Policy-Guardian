# Policy Guardian

Policy Guardian creates cryptographically verifiable evidence of policy history and user consent.

It lets you prove:

• what policy text existed
• when it was captured
• which policy version a user agreed to
• that records were never tampered with

Windows-first packaging, fully cross-platform Go implementation.

---

## Overview

Policy Guardian is a deterministic CLI monorepo that ships two tools.

### PolicyLock

Capture an exact policy snapshot (raw bytes) into a deterministic ZIP “snapshot pack”.

### Consent Guardian

Record a consent event that binds a subject to a specific policy snapshot, with optional Ed25519 signing.

Both tools share the same internal code and are built together.

---

## Build Modes

Two build modes are supported (same shared code, no drift).

**Mode A (default / preferred)**
One binary with subcommands:

policyguardian.exe policylock ...
policyguardian.exe consent ...

**Mode B (optional wrappers)**
Two small wrapper binaries:

policylock.exe
consentguardian.exe

These call the same internal packages.

---

## Design Goals

• Deterministic outputs (same input → same bytes)
• RFC 8785 (JCS) canonical JSON for signing payloads
• Raw bytes only for PolicyLock snapshots (no parsing or rewriting policy text)
• Deterministic ZIP writer (STORE, fixed timestamps, sorted paths)
• Zip-slip protection
• Offline verification
• No UI. No CANON modes. No revocation model. No feature creep.

---

## When to Use Policy Guardian

Use Policy Guardian when a policy affects:

• money (procurement, contracts)
• rights (privacy policies, terms of service)
• health (clinical protocols, safety rules)
• compliance (regulatory approvals)

Do not use it for drafts or informal notes.

---

## Example Use Case

Before updating an Ontario procurement policy:

1. Run PolicyLock snapshot.
2. Record approvals or consent with Consent Guardian.
3. Later, verify exactly which policy version was used.

This provides verifiable evidence for audits, compliance, or disputes.

---

## Quickstart

Start here: `doc/FRESH_UNZIP_QUICKSTART.md`

---

## Building

Windows / PowerShell:

mkdir dist -ErrorAction SilentlyContinue

go build -trimpath -buildvcs=false -o dist\policyguardian.exe .\cmd\policyguardian
go build -trimpath -buildvcs=false -o dist\policylock.exe .\cmd\policylock
go build -trimpath -buildvcs=false -o dist\consentguardian.exe .\cmd\consentguardian

Builds on Windows, Linux, and macOS using Go 1.22+.

---

## Outputs

PolicyLock creates:

• snapshot_pack.zip

Consent Guardian creates:

• consent_event.json

These files are deterministic and verifiable offline.

### What is inside `snapshot_pack.zip`?

• exact policy bytes
• capture metadata
• integrity hashes
• optional signature/timestamp anchors

A sealed evidence bundle you can verify years later.

---

## Supported Formats

### PolicyLock Input

Any file or URL as raw bytes.

Examples:

• .pdf .docx .txt .html .md .json
• images (.png, .jpg)
• zipped bundles

No parsing. Always exact bytes.

---

### Consent Guardian Input

• PolicyLock snapshot ZIP
• Subject identifier (salted + peppered hash)
• Optional Ed25519 private key

Output:

• consent_event.json

---

## Verification

Both tools verify:

• snapshot ZIPs
• consent_event.json

Works offline.

Reference verifier: `tools/ref_verify/`

---

## Not Supported (v1.0)

• Revocation tracking
• Policy diffing
• Database storage
• UI dashboards
• Automatic parsing

Intentionally out of scope.

---

## CLI Overview

### PolicyLock

Snapshot:

policyguardian.exe policylock snapshot --out policy_snapshot.zip fixtures\policylock\policy1.txt

Verify:

policyguardian.exe policylock verify policy_snapshot.zip

Show:

policyguardian.exe policylock show policy_snapshot.zip

---

### Consent Guardian

Record:

policyguardian.exe consent record --subject "Alice" --tenant-salt 0011 --pepper aabb --out consent.json demo_snapshot.zip

Signed:

policyguardian.exe consent record --subject "Alice" --tenant-salt 0011 --pepper aabb --sign-privkey <hex> --out consent_signed.json demo_snapshot.zip

Verify:

policyguardian.exe consent verify consent.json

Verify + resolve snapshot:

policyguardian.exe consent verify --resolve-snapshot consent.json

---

## Exit Codes

0 VALID
1 PARTIAL
2 INVALID
3 UNSUPPORTED
4 INPUT ERROR
5 NETWORK ERROR

---

## Repo Layout

Schemas: `schemas/`
Fixtures: `fixtures/`
Docs: `doc/`
Verifier: `tools/ref_verify/`

Run demo:

tools/scripts/demo.ps1

---

## Security & Privacy

See `doc/SECURITY.md`.

No raw PII stored. Consent uses salted hashes.

## Commercial Licensing / Pilots

If you're evaluating this project for commercial use, pilots, or enterprise licensing,
please contact:

Ben
yupme112@gmail.com

---

## License

Apache License 2.0
Copyright © 2026 Ben Slater

---

## Project Philosophy

Part of the Guardian tool family:

• deterministic
• verifier-first
• local-first
• audit-ready

No dashboards. No SaaS. Just evidence you can verify.
