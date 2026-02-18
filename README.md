# Policy Guardian

Policy Guardian creates cryptographically verifiable evidence of policy
history and user consent.

It lets you prove:

• what policy text existed\
• when it was captured\
• which policy version a user agreed to\
• that records were never tampered with

Windows-first packaging, fully cross-platform Go implementation.

------------------------------------------------------------------------

## Overview

Policy Guardian is a deterministic CLI monorepo that ships two tools.

### PolicyLock

Capture an exact policy snapshot (raw bytes) into a deterministic ZIP
"snapshot pack".

### Consent Guardian

Record a consent event that binds a subject to a specific policy
snapshot, with optional Ed25519 signing.

Both tools share the same internal code and are built together.

------------------------------------------------------------------------

## Build Modes

Two build modes are supported (same shared code, no drift).

**Mode A (default / preferred)**\
One binary with subcommands:

policyguardian.exe policylock ...\
policyguardian.exe consent ...

**Mode B (optional wrappers)**\
Two small wrapper binaries:

policylock.exe\
consentguardian.exe

These call the same internal packages.

------------------------------------------------------------------------

## Design Goals

• Deterministic outputs (same input → same bytes)\
• RFC 8785 (JCS) canonical JSON for signing payloads\
• Raw bytes only for PolicyLock snapshots\
• Deterministic ZIP writer (STORE, fixed timestamps, sorted paths)\
• Zip-slip protection\
• Offline verification\
• No UI. No revocation model. No feature creep.

------------------------------------------------------------------------

## Quickstart

Start here: doc/FRESH_UNZIP_QUICKSTART.md

------------------------------------------------------------------------

## Building

Windows / PowerShell:

mkdir dist -ErrorAction SilentlyContinue go build -trimpath
-buildvcs=false -o dist`\policyguardian`{=tex}.exe
.`\cmd`{=tex}`\policyguardian`{=tex} go build -trimpath -buildvcs=false
-o dist`\policylock`{=tex}.exe .`\cmd`{=tex}`\policylock`{=tex} go build
-trimpath -buildvcs=false -o dist`\consentguardian`{=tex}.exe
.`\cmd`{=tex}`\consentguardian`{=tex}

Builds on Windows, Linux, and macOS using Go 1.22+.

------------------------------------------------------------------------

## Outputs

PolicyLock creates snapshot_pack.zip\
Consent Guardian creates consent_event.json

Deterministic and verifiable offline.

------------------------------------------------------------------------

## Verification

Reference verifier: tools/ref_verify/

------------------------------------------------------------------------

## Not Supported (v1.0)

Revocation tracking\
Policy diffing\
Database storage\
UI dashboards\
Automatic parsing

Intentionally out of scope.

------------------------------------------------------------------------

## License

Apache License 2.0\
Copyright © 2026 Ben Slater

------------------------------------------------------------------------

## Project Philosophy

Part of the Guardian tool family:

deterministic\
verifier-first\
local-first\
audit-ready

No dashboards. No SaaS. Just evidence you can verify.
