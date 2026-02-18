package consentguardian

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"policyguardian/internal/policylock"
	"policyguardian/internal/shared/hashing"
	"policyguardian/internal/shared/jcs"
	"policyguardian/internal/shared/timefmt"
)

const (
	SchemaConsentEvent = "consentguardian.consent_event.v0.1"
	SpecURLPolicyGuardian = "SPEC_POLICY_GUARDIAN_V0_1_FROZEN.md"
)

type RecordOptions struct {
	CreatedAtUTC       string
	SubjectIdentifier  string
	TenantSaltHex      string
	PepperHex          string
	Context            map[string]string
	Evidence           map[string]string

	SignPrivKeyHex     string
	KeyDescription     string
	LegalEntityName    string
}

func normalizeIdentifier(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty identifier")
	}
	s = strings.Map(func(r rune) rune { return unicode.ToLower(r) }, s)
	return s, nil
}

func SubjectIDHash(identifier, pepperHex, saltHex string) (string, error) {
	n, err := normalizeIdentifier(identifier)
	if err != nil {
		return "", err
	}
	pepper, err := hex.DecodeString(strings.TrimSpace(pepperHex))
	if err != nil {
		return "", errors.New("invalid pepper hex")
	}
	salt, err := hex.DecodeString(strings.TrimSpace(saltHex))
	if err != nil {
		return "", errors.New("invalid tenant_salt hex")
	}
	// For hashing we use raw UTF-8 bytes of the normalized identifier.
	msg := append(append([]byte{}, pepper...), salt...)
	msg = append(msg, []byte(n)...)
	return hashing.SHA256Hex(msg), nil
}

func BuildConsentSignPayload(ev ConsentEvent) map[string]any {
	m := map[string]any{
		"created_at_utc": ev.CreatedAtUTC,
		"policy": map[string]any{
			"policy_sha256": ev.Policy.PolicySHA256,
			"snapshot_id": ev.Policy.SnapshotID,
			"snapshot_pack_sha256": ev.Policy.SnapshotPackSHA256,
		},
		"subject": map[string]any{
			"subject_id_hash": ev.Subject.SubjectIDHash,
			"hash_algorithm": ev.Subject.HashAlgorithm,
		},
	}
	if len(ev.Context) > 0 {
		ctx := map[string]any{}
		for k, v := range ev.Context {
			if v != "" {
				ctx[k] = v
			}
		}
		if len(ctx) > 0 {
			m["context"] = ctx
		}
	}
	if len(ev.Evidence) > 0 {
		e := map[string]any{}
		for k, v := range ev.Evidence {
			if v != "" {
				e[k] = v
			}
		}
		if len(e) > 0 {
			m["evidence"] = e
		}
	}
	return m
}

func resolveSnapshot(arg string) ([]byte, string, string, error) {
	if st, err := os.Stat(arg); err == nil && !st.IsDir() {
		b, err := os.ReadFile(arg)
		if err != nil { return nil,"","",err }
		status, reason, err := policylock.VerifySnapshotZip(b)
		if err != nil { return nil,"","",err }
		if status != "VALID" { return nil,"","",fmt.Errorf("snapshot invalid: %s", reason) }
		snap, bodyHash, err := policylock.ReadSnapshotInfo(b)
		if err != nil { return nil,"","",err }
		return b, snap.SnapshotID, bodyHash, nil
	}
	store := os.Getenv("POLICYGUARDIAN_STORE")
	if store == "" { store = ".policyguardian_store" }
	path := filepath.Join(store, "snapshots", arg+".zip")
	b, err := os.ReadFile(path)
	if err != nil { return nil,"","",fmt.Errorf("snapshot not found: %s", arg) }
	status, reason, err := policylock.VerifySnapshotZip(b)
	if err != nil { return nil,"","",err }
	if status != "VALID" { return nil,"","",fmt.Errorf("snapshot invalid: %s", reason) }
	snap, bodyHash, err := policylock.ReadSnapshotInfo(b)
	if err != nil { return nil,"","",err }
	return b, snap.SnapshotID, bodyHash, nil
}

func RecordConsent(snapshotZipPathOrID string, outPath string, opts RecordOptions) (*ConsentEvent, []byte, []byte, error) {
	created := opts.CreatedAtUTC
	if created == "" { created = timefmt.Format(timefmt.NowUTC()) }

	snapZipBytes, snapID, policySHA, err := resolveSnapshot(snapshotZipPathOrID)
	if err != nil { return nil,nil,nil,err }

	packSHA := hashing.SHA256Hex(snapZipBytes)
	subHash, err := SubjectIDHash(opts.SubjectIdentifier, opts.PepperHex, opts.TenantSaltHex)
	if err != nil { return nil,nil,nil,err }

	ev := &ConsentEvent{
		Schema: SchemaConsentEvent,
		SpecURL: SpecURLPolicyGuardian,
		CreatedAtUTC: created,
		Policy: PolicyRef{
			PolicySHA256: policySHA,
			SnapshotID: snapID,
			SnapshotPackSHA256: packSHA,
		},
		Subject: SubjectRef{
			SubjectIDHash: subHash,
			HashAlgorithm: "sha2-256",
		},
	}
	if len(opts.Context)>0 { ev.Context = opts.Context }
	if len(opts.Evidence)>0 { ev.Evidence = opts.Evidence }

	signPayload := BuildConsentSignPayload(*ev)
	signBytes, err := jcs.CanonicalizeValue(signPayload)
	if err != nil { return nil,nil,nil,err }
	expHash := hashing.SHA256Hex(signBytes)
	ev.Hashes = map[string]string{"sha2-256": expHash}
	ev.ConsentEventID = expHash

	var sigBytes []byte
	if opts.SignPrivKeyHex != "" {
		priv, err := hex.DecodeString(strings.TrimSpace(opts.SignPrivKeyHex))
		if err != nil { return nil,nil,nil,errors.New("invalid ed25519 private key hex") }
		if len(priv)!=ed25519.PrivateKeySize { return nil,nil,nil,fmt.Errorf("invalid ed25519 private key length: %d", len(priv)) }
		pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
		sig := ed25519.Sign(ed25519.PrivateKey(priv), signBytes)
		env := map[string]any{
			"schema": "policyguardian.signature_envelope.v0.1",
			"algorithm": "ed25519",
			"public_key": hex.EncodeToString(pub),
			"signature": hex.EncodeToString(sig),
			"payload_hashes": map[string]any{
				"sha2-256": expHash,
			},
		}
		sigBytes, err = jcs.CanonicalizeValue(env)
		if err != nil { return nil,nil,nil,err }
		if ev.Signing == nil { ev.Signing = &SigningInfo{} }
		ev.Signing.Mode = "ed25519"
		ev.Signing.Algorithm = "ed25519"
		ev.Signing.PublicKey = hex.EncodeToString(pub)
		ev.Signing.KeyDescription = opts.KeyDescription
		ev.Signing.LegalEntityName = opts.LegalEntityName
		ev.Signing.SignatureFile = filepath.Base(outPath)+".sig.ed25519.json"
	} else {
		ev.Signing = &SigningInfo{Mode:"none"}
	}

	evRaw, err := json.Marshal(ev)
	if err != nil { return nil,nil,nil,err }
	evCanonical, err := jcs.CanonicalizeJSON(evRaw)
	if err != nil { return nil,nil,nil,err }

	if outPath != "" {
		if err := os.WriteFile(outPath, evCanonical, 0644); err != nil { return nil,nil,nil,err }
		if sigBytes != nil {
			if err := os.WriteFile(outPath+".sig.ed25519.json", sigBytes, 0644); err != nil { return nil,nil,nil,err }
		}
	}

	return ev, evCanonical, sigBytes, nil
}

// VerifyConsent verifies a consent event from raw JSON bytes.
// It checks canonical signing payload hashing (hashes["sha2-256"]) and, when present,
// validates the signature envelope if provided by the caller (see VerifyConsentFile).
func VerifyConsent(consentJSON []byte, resolveSnapshotStore bool) (string, string, error) {
	dec := json.NewDecoder(bytes.NewReader(consentJSON))
	dec.UseNumber()
	var ev ConsentEvent
	if err := dec.Decode(&ev); err != nil {
		return "INVALID","invalid_json",nil
	}
	if ev.Schema != SchemaConsentEvent {
		return "INVALID","wrong_schema",nil
	}
	signPayload := BuildConsentSignPayload(ev)
	signBytes, err := jcs.CanonicalizeValue(signPayload)
	if err != nil { return "INVALID","jcs_error",nil }
	expHash := hashing.SHA256Hex(signBytes)
	if ev.Hashes == nil {
		return "INVALID","missing_hashes",nil
	}
	claimed, ok := ev.Hashes["sha2-256"]
	if !ok || claimed == "" {
		return "INVALID","missing_sha2_256",nil
	}
	if claimed != expHash {
		return "INVALID","hash_mismatch",nil
	}
	if ev.ConsentEventID != "" && ev.ConsentEventID != expHash {
		return "INVALID","consent_event_id_mismatch",nil
	}
	if resolveSnapshotStore {
		_,_,_, err := resolveSnapshot(ev.Policy.SnapshotID)
		if err != nil {
			return "PARTIAL","snapshot_missing",nil
		}
	}
	return "VALID","",nil
}

type signatureEnvelope struct {
	Schema       string            `json:"schema"`
	Algorithm    string            `json:"algorithm"`
	PublicKey    string            `json:"public_key"`
	Signature    string            `json:"signature"`
	PayloadHashes map[string]string `json:"payload_hashes"`
}

// VerifyConsentFile verifies a consent.json file and (if signing.mode==ed25519)
// verifies the companion signature envelope file in the same directory.
// It returns (status, reason, unsignedWarning, error).
func VerifyConsentFile(consentPath string, resolveSnapshotStore bool) (string, string, bool, error) {
	b, err := os.ReadFile(consentPath)
	if err != nil { return "","",false, err }
	// First verify hashes and optional snapshot resolution.
	st, reason, err := VerifyConsent(b, resolveSnapshotStore)
	if err != nil { return "","",false, err }
	if st != "VALID" {
		return st, reason, false, nil
	}
	// Parse event to inspect signing.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var ev ConsentEvent
	if err := dec.Decode(&ev); err != nil {
		return "INVALID","invalid_json",false,nil
	}
	unsigned := false
	if ev.Signing == nil || ev.Signing.Mode == "none" {
		unsigned = true
		return "VALID","",unsigned,nil
	}
	if ev.Signing.Mode != "ed25519" {
		return "INVALID","unsupported_signing_mode",false,nil
	}
	// Rebuild payload bytes.
	signPayload := BuildConsentSignPayload(ev)
	signBytes, err := jcs.CanonicalizeValue(signPayload)
	if err != nil { return "INVALID","jcs_error",false,nil }
	expHash := hashing.SHA256Hex(signBytes)

	// Determine signature file path.
	sigName := ev.Signing.SignatureFile
	if sigName == "" {
		sigName = filepath.Base(consentPath) + ".sig.ed25519.json"
	}
	sigPath := filepath.Join(filepath.Dir(consentPath), sigName)
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return "INVALID","signature_missing",false,nil
	}
	var env signatureEnvelope
	dec2 := json.NewDecoder(bytes.NewReader(sigRaw))
	dec2.UseNumber()
	if err := dec2.Decode(&env); err != nil {
		return "INVALID","invalid_signature_json",false,nil
	}
	if env.Schema != "policyguardian.signature_envelope.v0.1" {
		return "INVALID","wrong_signature_schema",false,nil
	}
	if env.Algorithm != "ed25519" {
		return "INVALID","wrong_signature_algorithm",false,nil
	}
	ph, ok := env.PayloadHashes["sha2-256"]
	if !ok || ph == "" {
		return "INVALID","missing_signature_payload_hash",false,nil
	}
	if ph != expHash {
		return "INVALID","signature_payload_hash_mismatch",false,nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(env.PublicKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "INVALID","invalid_public_key",false,nil
	}
	sig, err := hex.DecodeString(strings.TrimSpace(env.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "INVALID","invalid_signature",false,nil
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), signBytes, sig) {
		return "INVALID","signature_verify_failed",false,nil
	}
	// Also ensure event hashes match expected, defensively.
	if ev.Hashes == nil || ev.Hashes["sha2-256"] != expHash {
		return "INVALID","hash_mismatch",false,nil
	}
	// consent_event_id is allowed to be empty, but if present must match.
	if ev.ConsentEventID != "" && ev.ConsentEventID != expHash {
		return "INVALID","consent_event_id_mismatch",false,nil
	}
	return "VALID","",false,nil
}
