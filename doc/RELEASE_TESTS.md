# Policy Guardian v0.1 — Release Test Checklist (Windows)

Goal: prove determinism + tamper detection + correct exit codes.

All commands run from repo root in **PowerShell**.

## 0) Build

```powershell
mkdir dist -ErrorAction SilentlyContinue

go build -trimpath -buildvcs=false -o dist\policyguardian.exe .\cmd\policyguardian
go build -trimpath -buildvcs=false -o dist\policylock.exe .\cmd\policylock
go build -trimpath -buildvcs=false -o dist\consentguardian.exe .\cmd\consentguardian

.\dist\policyguardian.exe --version
```

## 1) Happy path demo

```powershell
.\tools\scripts\demo.ps1
```

Expected:
- Snapshot prints `OK`
- Consent record prints `OK`
- Then `VALID` and `VALID`
- `WARNING: unsigned_consent` may appear (expected for unsigned)

## 2) PolicyLock determinism: same input => identical ZIP

```powershell
mkdir out -ErrorAction SilentlyContinue

.\dist\policyguardian.exe policylock snapshot --out .\out\snap1.zip .\fixtures\policylock\policy1.txt
.\dist\policyguardian.exe policylock snapshot --out .\out\snap2.zip .\fixtures\policylock\policy1.txt

certutil -hashfile .\out\snap1.zip SHA256
certutil -hashfile .\out\snap2.zip SHA256
```

Expected: hashes match exactly.

Note: For URL snapshots, the tool records `retrieved_at_utc`. When you pass
`--created-at` for a URL snapshot, PolicyLock pins `retrieved_at_utc` to the
same value (unless you explicitly set `--retrieved-at` in the future). This
makes repeated URL snapshots byte-identical across runs *when the fetched
content is identical*.

## 3) PolicyLock tamper: modify policy_body.bin => INVALID (exit 2)

```powershell
mkdir out\tamper -ErrorAction SilentlyContinue
Expand-Archive -Force .\out\snap1.zip .\out\tamper
Add-Content -Path .\out\tamper\policy_body.bin -Value "X" -NoNewline
Compress-Archive -Force .\out\tamper\* .\out\snap1_tampered.zip

.\dist\policyguardian.exe policylock verify .\out\snap1_tampered.zip
echo Exit:$LASTEXITCODE
```

Expected:
- `INVALID`
- `reason: policy_body_hash_mismatch`
- `Exit:2`

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

## 5) Consent tamper: edit a covered field => INVALID (exit 2)

```powershell
(Get-Content demo_consent.json -Raw) `
  -replace '"snapshot_pack_sha256":"[0-9a-f]{64}"','"snapshot_pack_sha256":"0000000000000000000000000000000000000000000000000000000000000000"' `
  | Set-Content demo_consent_tampered.json -NoNewline

.\dist\policyguardian.exe consent verify demo_consent_tampered.json
echo Exit:$LASTEXITCODE
```

Expected:
- `INVALID`
- `reason: hash_mismatch`
- `Exit:2`

## 6) Snapshot missing => PARTIAL (exit 1)

Move the stored snapshot aside:

```powershell
mkdir out -ErrorAction SilentlyContinue
Move-Item .\.policyguardian_store\snapshots\*.zip .\out\
```

Verify with snapshot resolution enabled:

```powershell
.\dist\policyguardian.exe consent verify --resolve-snapshot demo_consent.json
echo Exit:$LASTEXITCODE
```

Expected:
- `PARTIAL`
- `reason: snapshot_missing`
- `Exit:1`

Restore store:

```powershell
Move-Item .\out\*.zip .\.policyguardian_store\snapshots\
```

## 7) Signed consent path: VALID (exit 0) and tamper fails

Generate a one-off keypair:

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

Tamper the signed consent (should fail):

```powershell
(Get-Content demo_consent_signed.json -Raw) `
  -replace '"policy_sha256":"[0-9a-f]{64}"','"policy_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' `
  | Set-Content demo_consent_signed_tampered.json -NoNewline

.\dist\policyguardian.exe consent verify demo_consent_signed_tampered.json
echo Exit:$LASTEXITCODE
```

Expected:
- `INVALID`
- `reason: hash_mismatch`
- `Exit:2`

Cleanup:

```powershell
Remove-Item .\tmp_keygen.go
```
