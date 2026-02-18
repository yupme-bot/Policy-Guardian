# Policy Guardian

<<<<<<< HEAD
Docs are in `doc/`.

Start here: `doc/README.md`.
=======
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

Start here: FRESH_UNZIP_QUICKSTART.md

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

In simple terms, it contains:

• the exact policy file bytes you captured  
• metadata describing when and where it was captured  
• hashes that prove the content hasn’t changed  
• optional signature or timestamp anchors  

It is a sealed evidence bundle you can store, send, or verify years later.

---

## Supported Formats

### PolicyLock Input

PolicyLock snapshots **any file or URL as raw bytes**.

Common examples:

• .pdf  
• .docx  
• .txt  
• .html  
• .md  
• .json  
• images (.png, .jpg)  
• zipped policy bundles  

There is **no parsing or rewriting**. The snapshot always captures exact bytes.

URL snapshots are also supported (HTTP/HTTPS). Dynamic websites may produce different snapshots over time.

---

### Consent Guardian Input

Consent Guardian records consent tied to a PolicyLock snapshot.

Inputs:

• PolicyLock snapshot ZIP  
• Subject identifier (hashed with tenant salt + pepper)  
• Optional Ed25519 private key for signing  

Outputs:

• consent_event.json (deterministic JSON evidence)

---

### Verification

Both tools verify:

• snapshot ZIPs  
• consent_event.json files  

Verification works offline and cross-platform.

Reference verifier is included in tools/ref_verify/.

---

### Not Supported (v1.0)

• Revocation tracking  
• Policy diffing  
• Database storage  
• UI or dashboards  
• Automatic policy parsing  

These are intentionally out of scope for v1.0.

---

## CLI Overview

### PolicyLock

Snapshot (file):

policyguardian.exe policylock snapshot --out policy_snapshot.zip fixtures\policylock\policy1.txt

Verify:

policyguardian.exe policylock verify policy_snapshot.zip

Show:

policyguardian.exe policylock show policy_snapshot.zip

---

### Consent Guardian

Record (unsigned):

policyguardian.exe consent record --subject "Alice Example" --tenant-salt 0011 --pepper aabb --out consent.json demo_snapshot.zip

Record (signed, Ed25519):

policyguardian.exe consent record --subject "Alice Example" --tenant-salt 0011 --pepper aabb --sign-privkey <64-byte-privkey-hex> --out consent_signed.json demo_snapshot.zip

Verify:

policyguardian.exe consent verify consent.json

Verify + resolve snapshot:

policyguardian.exe consent verify --resolve-snapshot consent.json

---

## Exit Codes

0 — VALID  
1 — PARTIAL (integrity OK but snapshot or anchors unavailable)  
2 — INVALID  
3 — UNSUPPORTED  
4 — INPUT ERROR  
5 — NETWORK ERROR

---

## Schemas, Fixtures, Verifier, Demo

Schemas: schemas/  
Fixtures: fixtures/  
Reference verifier: tools/ref_verify/  
Demo scripts: tools/scripts/  

Run the demo:

tools/scripts/demo.ps1  

Full release checklist: RELEASE_TESTS.md

---

## Security & Privacy

See SECURITY.md.

Policy Guardian stores no raw PII. Consent records use salted hashes and deterministic evidence formats.

---

## Notes on URL Snapshots

PolicyLock snapshots URLs as raw bytes. Many modern websites are dynamic (cookies, rotating IDs, injected banners), so two snapshots may legitimately differ.

When you verify a URL snapshot, PolicyLock prints:

• policy_sha256 — SHA-256 of captured policy bytes  
• URL fetch context (status, content type, final URL, retrieved time, etc.)

If two URL snapshots differ, compare policy_sha256.

If you need byte-identical URL snapshots for testing, ensure the remote bytes are stable (PDFs usually are). If supported, pin time using --created-at.

---

## License

See LICENSE file.

---

## Project Philosophy

Policy Guardian is part of the Guardian tool family:

• deterministic  
• verifier-first  
• local-first  
• audit-ready  

No dashboards. No SaaS. Just evidence you can verify.

Note: the release ZIP includes an out/ folder so you can run demos/tests immediately.


## License

Policy Guardian is licensed under the Apache License 2.0.
Copyright © 2026 Ben Slater

>>>>>>> 9200a4bf5894e38408fa0224ae6871fcf72226a6
