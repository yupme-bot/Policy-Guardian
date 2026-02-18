# Policy Guardian v0.1 — Fresh Unzip Quickstart (Ben)

This is the “I just unzipped it and want it working” guide for Windows.

## 0) Prereqs

- Windows
- Go installed (`go version` works)

Open **PowerShell** in the repo root (you should see `cmd\`, `internal\`, `go.mod`).

## 1) Build (Mode A + Mode B wrappers)

```powershell
mkdir dist -ErrorAction SilentlyContinue

go build -trimpath -buildvcs=false -o dist\policyguardian.exe .\cmd\policyguardian
go build -trimpath -buildvcs=false -o dist\policylock.exe .\cmd\policylock
go build -trimpath -buildvcs=false -o dist\consentguardian.exe .\cmd\consentguardian
```

Sanity:

```powershell
.\dist\policyguardian.exe --version
dir dist
```

## 2) Important CLI rule (don’t get tripped)

This CLI uses Go `flag`. That means:

✅ flags must come before positional args

Example:
```powershell
.\dist\policyguardian.exe policylock snapshot --out out\snap.zip fixtures\policylock\policy1.txt
```

Not:
```powershell
.\dist\policyguardian.exe policylock snapshot fixtures\policylock\policy1.txt --out out\snap.zip
```

## 3) Run the demo (fastest validation)

```powershell
.\tools\scripts\demo.ps1
```

Expected:
- `OK` for snapshot
- `OK` for consent record
- `VALID` (policylock verify)
- `VALID` (consent verify)
- plus `WARNING: unsigned_consent` (expected for unsigned demo)

## 4) Where outputs go

- `demo_snapshot.zip`
- `demo_consent.json`
- local snapshot store:
  - `.policyguardian_store\snapshots\<snapshot_id>.zip`

## 5) If something fails

- Confirm you’re in the repo root (`dir` shows `cmd`, `internal`, `go.mod`)
- Confirm `dist\policyguardian.exe` exists
- Re-run using correct flag ordering (flags first)
