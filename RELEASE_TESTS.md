# Policy Guardian v1.0 — Release Test Checklist (Windows)

Goal: prove determinism + tamper detection + correct exit codes, with tests that are **hard to fake** and easy to re-run.

All commands run from repo root in **PowerShell**.

---

## 0) Build

```powershell
mkdir dist -ErrorAction SilentlyContinue

go build -trimpath -buildvcs=false -o dist\policyguardian.exe .\cmd\policyguardian
go build -trimpath -buildvcs=false -o dist\policylock.exe .\cmd\policylock
go build -trimpath -buildvcs=false -o dist\consentguardian.exe .\cmd\consentguardian

.\dist\policyguardian.exe --version
```

Expected:
- prints `policyguardian v0.1.0`

---

## 1) Happy path demo

```powershell
.\tools\scripts\demo.ps1
```

Expected:
- Snapshot prints `OK`
- Consent record prints `OK`
- Then `VALID` and `VALID`
- `WARNING: unsigned_consent` may appear (expected for unsigned)

---

## 2) PolicyLock determinism (local file): same input => identical ZIP

```powershell
mkdir out -ErrorAction SilentlyContinue

.\dist\policyguardian.exe policylock snapshot --out .\out\snap1.zip .\fixtures\policylock\policy1.txt
.\dist\policyguardian.exe policylock snapshot --out .\out\snap2.zip .\fixtures\policylock\policy1.txt

certutil -hashfile .\out\snap1.zip SHA256
certutil -hashfile .\out\snap2.zip SHA256
```

Expected:
- ZIP SHA256 hashes match exactly.

**Golden check (content hash):** confirm the snapshot’s `policy_sha256` equals the SHA-256 of the source file bytes.

```powershell
.\dist\policyguardian.exe policylock verify .\out\snap1.zip
certutil -hashfile .\fixtures\policylock\policy1.txt SHA256
```

Expected:
- `policy_sha256:` printed by verify matches the SHA256 from `certutil -hashfile policy1.txt`.

---

## 2b) PolicyLock determinism (URL pinning): stable URL + pinned time => identical ZIP


Note:
- This test uses a live external URL. Skip in air-gapped environments.
- For CI, substitute a locally-served stable file (e.g., a tiny local HTTP server hosting a fixed PDF).

This proves the “URL snapshots can be byte-identical when content is identical” behavior.

Use a **stable PDF** URL:

```powershell
mkdir out -ErrorAction SilentlyContinue

.\dist\policyguardian.exe policylock snapshot --created-at 2026-02-18T02:00:00Z --url "https://budget.ontario.ca/2025/pdf/2025-ontario-budget-en.pdf" --max-bytes 104857600 --out .\out\url_fixed1.zip
.\dist\policyguardian.exe policylock snapshot --created-at 2026-02-18T02:00:00Z --url "https://budget.ontario.ca/2025/pdf/2025-ontario-budget-en.pdf" --max-bytes 104857600 --out .\out\url_fixed2.zip

certutil -hashfile .\out\url_fixed1.zip SHA256
certutil -hashfile .\out\url_fixed2.zip SHA256
```

Expected:
- ZIP SHA256 hashes match exactly.

Note:
- If the **remote bytes** change between fetches (dynamic site / CDN variance / A/B), the ZIPs should differ. In that case compare `policy_sha256` printed by `policylock verify` to confirm whether the bytes changed.

---

## 3) PolicyLock tamper: flip a byte in policy_body.bin => INVALID (exit 2)

Avoid `Compress-Archive` (it rebuilds ZIP structure). Use a tiny one-off Go helper to tamper **only** the policy body bytes and keep the test non-ambiguous.

### 3a) Generate a tampered ZIP by flipping 1 byte in `policy_body.bin`

```powershell
@'
package main

import (
  "archive/zip"
  "bytes"
  "fmt"
  "io"
  "os"
  "time"
)

// Writes a new zip with the same entries, but flips 1 byte in policy_body.bin.
// For release testing only.
func main() {
  if len(os.Args) != 3 {
    fmt.Fprintln(os.Stderr, "usage: go run .\\tmp_zip_tamper.go <in.zip> <out.zip>")
    os.Exit(4)
  }
  inPath := os.Args[1]
  outPath := os.Args[2]

  inBytes, err := os.ReadFile(inPath)
  if err != nil { fmt.Fprintln(os.Stderr, "read:", err); os.Exit(4) }

  zr, err := zip.NewReader(bytes.NewReader(inBytes), int64(len(inBytes)))
  if err != nil { fmt.Fprintln(os.Stderr, "zip read:", err); os.Exit(4) }

  outF, err := os.Create(outPath)
  if err != nil { fmt.Fprintln(os.Stderr, "create:", err); os.Exit(4) }
  defer outF.Close()

  zw := zip.NewWriter(outF)
  defer zw.Close()

  for _, f := range zr.File {
    rc, err := f.Open()
    if err != nil { fmt.Fprintln(os.Stderr, "open entry:", err); os.Exit(4) }
    b, err := io.ReadAll(rc)
    rc.Close()
    if err != nil { fmt.Fprintln(os.Stderr, "read entry:", err); os.Exit(4) }

    if f.Name == "policy_body.bin" {
      if len(b) == 0 { fmt.Fprintln(os.Stderr, "policy_body.bin empty"); os.Exit(4) }
      b[len(b)-1] ^= 0x01 // flip last byte
    }

    hdr := f.FileHeader
    hdr.Modified = time.Unix(0, 0).UTC()
    w, err := zw.CreateHeader(&hdr)
    if err != nil { fmt.Fprintln(os.Stderr, "create hdr:", err); os.Exit(4) }
    if _, err := w.Write(b); err != nil { fmt.Fprintln(os.Stderr, "write:", err); os.Exit(4) }
  }

  if err := zw.Close(); err != nil { fmt.Fprintln(os.Stderr, "zip close:", err); os.Exit(4) }
  if err := outF.Close(); err != nil { fmt.Fprintln(os.Stderr, "file close:", err); os.Exit(4) }

  fmt.Println("OK tampered:", outPath)
}
'@ | Set-Content -Encoding UTF8 .\tmp_zip_tamper.go

go run .\tmp_zip_tamper.go .\out\snap1.zip .\out\snap1_tampered.zip
```

### 3b) Verify tampered ZIP

```powershell
.\dist\policyguardian.exe policylock verify .\out\snap1_tampered.zip
echo Exit:$LASTEXITCODE
```

Expected:
- `INVALID`
- `reason: policy_body_hash_mismatch`
- `Exit:2`

Cleanup helper:

```powershell
Remove-Item .\tmp_zip_tamper.go
```

Optional cleanup (keeps workspace predictable):

```powershell
Remove-Item .\out\snap1_tampered.zip -ErrorAction SilentlyContinue
```

---

## 4) Consent unsigned happy path: VALID + warning (exit 0)

```powershell
.\dist\policyguardian.exe consent record --subject "Alice Example" --tenant-salt 0011 --pepper aabb --out demo_consent.json demo_snapshot.zip
.\dist\policyguardian.exe consent verify demo_consent.json
echo Exit:$LASTEXITCODE
```

Expected:
- `VALID`
- `Exit:0`
- warning may appear: `WARNING: unsigned_consent`

---

## 5) Consent tamper (unsigned): edit a covered field => INVALID (exit 2)

Patch `snapshot_pack_sha256` and **confirm the replacement actually happened** before verifying.

```powershell
(Get-Content demo_consent.json -Raw) `
  -replace '"snapshot_pack_sha256":"[0-9a-f]{64}"','"snapshot_pack_sha256":"0000000000000000000000000000000000000000000000000000000000000000"' `
  | Set-Content demo_consent_tampered.json -NoNewline

# Prove the tamper write happened (non-vacuous test)
Select-String -Path demo_consent_tampered.json -Pattern "0000000000000000000000000000000000000000000000000000000000000000" -Quiet
echo TamperApplied:$LASTEXITCODE

.\dist\policyguardian.exe consent verify demo_consent_tampered.json
echo Exit:$LASTEXITCODE
```

Expected:
- `TamperApplied:0`
- `INVALID`
- `reason: hash_mismatch`
- `Exit:2`

---

## 6) Snapshot missing => PARTIAL (exit 1) (stateless: isolated store)

Do **not** mutate your real `.policyguardian_store`. Point the resolver at an empty temp store for this test.

```powershell
mkdir .\out\empty_store\snapshots -ErrorAction SilentlyContinue
$env:POLICYGUARDIAN_STORE = (Join-Path $PWD "out\empty_store")

.\dist\policyguardian.exe consent verify --resolve-snapshot demo_consent.json
echo Exit:$LASTEXITCODE
```

Expected:
- `PARTIAL`
- `reason: snapshot_missing`
- `Exit:1`

Cleanup env var:

```powershell
Remove-Item env:POLICYGUARDIAN_STORE -ErrorAction SilentlyContinue
```

---

## 7) Signed consent path: VALID (exit 0) and tamper fails (multiple fields)


Defensive reset (in case a prior run aborted mid-test):

```powershell
Remove-Item env:POLICYGUARDIAN_STORE -ErrorAction SilentlyContinue
```

### 7a) Generate a one-off keypair

```powershell
@'
package main
import ("crypto/ed25519"; "crypto/rand"; "encoding/hex"; "fmt")
func main(){ pub, priv, _ := ed25519.GenerateKey(rand.Reader)
fmt.Println("privkey_hex:", hex.EncodeToString(priv))
fmt.Println("pubkey_hex:",  hex.EncodeToString(pub))
}
'@ | Set-Content -Encoding UTF8 .\tmp_keygen.go

go run .\tmp_keygen.go
```

Copy `privkey_hex` into this command:

```powershell
.\dist\policyguardian.exe consent record --subject "Alice Example" --tenant-salt 0011 --pepper aabb --sign-privkey <PRIVKEY_HEX> --out demo_consent_signed.json demo_snapshot.zip
.\dist\policyguardian.exe consent verify demo_consent_signed.json
echo Exit:$LASTEXITCODE
```

Expected:
- `VALID`
- `Exit:0`
- no unsigned warning

### 7b) Tamper tests (each should fail)

**Tamper policy_sha256:**

```powershell
(Get-Content demo_consent_signed.json -Raw) `
  -replace '"policy_sha256":"[0-9a-f]{64}"','"policy_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' `
  | Set-Content demo_consent_signed_tampered_policyhash.json -NoNewline

Select-String -Path demo_consent_signed_tampered_policyhash.json -Pattern "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" -Quiet
echo TamperApplied:$LASTEXITCODE

.\dist\policyguardian.exe consent verify demo_consent_signed_tampered_policyhash.json
echo Exit:$LASTEXITCODE
```

Expected:
- `TamperApplied:0`
- `INVALID`
- `reason: hash_mismatch`
- `Exit:2`

**Tamper created_at_utc:**

```powershell
(Get-Content demo_consent_signed.json -Raw) `
  -replace '"created_at_utc":"[^"]+"','"created_at_utc":"2026-01-01T00:00:00Z"' `
  | Set-Content demo_consent_signed_tampered_time.json -NoNewline

Select-String -Path demo_consent_signed_tampered_time.json -Pattern '"created_at_utc":"2026-01-01T00:00:00Z"' -Quiet
echo TamperApplied:$LASTEXITCODE

.\dist\policyguardian.exe consent verify demo_consent_signed_tampered_time.json
echo Exit:$LASTEXITCODE
```

Expected:
- `TamperApplied:0`
- `INVALID`
- `reason: hash_mismatch`
- `Exit:2`

**Tamper subject_id_hash:**

```powershell
(Get-Content demo_consent_signed.json -Raw) `
  -replace '"subject_id_hash":"[0-9a-f]{64}"','"subject_id_hash":"0000000000000000000000000000000000000000000000000000000000000000"' `
  | Set-Content demo_consent_signed_tampered_subject.json -NoNewline

Select-String -Path demo_consent_signed_tampered_subject.json -Pattern '"subject_id_hash":"0000000000000000000000000000000000000000000000000000000000000000"' -Quiet
echo TamperApplied:$LASTEXITCODE

.\dist\policyguardian.exe consent verify demo_consent_signed_tampered_subject.json
echo Exit:$LASTEXITCODE
```

Expected:
- `TamperApplied:0`
- `INVALID`
- `reason: hash_mismatch`
- `Exit:2`

Cleanup:

```powershell
Remove-Item .\tmp_keygen.go
```

---

## Optional Appendix A) Cross-platform determinism (Windows vs Linux/macOS)

Do this if you plan to distribute non-Windows builds **or** you want to claim cross-platform determinism. If you are Windows-first for v1.0, you may treat this as optional, but be explicit about that scope in README/marketing.

Idea:
1) On Windows: produce `snap_win.zip` from `fixtures/policylock/policy1.txt`
2) On Linux/macOS: build the tool, produce `snap_nix.zip` from the same fixture bytes
3) Compare ZIP SHA256 hashes

If they match, you have strong cross-platform determinism. If they don’t, compare `policy_sha256` first to check whether the policy bytes are identical and the difference is only packaging/metadata.
