package consentguardian

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"policyguardian/internal/policylock"
	"policyguardian/internal/shared/hashing"
	"policyguardian/internal/shared/jcs"
)

func TestSubjectNormalization(t *testing.T) {
	h1, err := SubjectIDHash("Alice@Example.com", "aa", "bb")
	if err != nil { t.Fatal(err) }
	h2, err := SubjectIDHash(" alice@example.com ", "aa", "bb")
	if err != nil { t.Fatal(err) }
	if h1 != h2 {
		t.Fatalf("expected same hash")
	}
}

func TestSnapshotMissingPartial(t *testing.T) {
	// Build consent referencing a fake snapshot id
	ev := ConsentEvent{
		Schema: SchemaConsentEvent,
		SpecURL: SpecURLPolicyGuardian,
		CreatedAtUTC: "2026-01-01T00:00:01Z",
		Policy: PolicyRef{PolicySHA256: "" + strings.Repeat("0",64), SnapshotID: "" + strings.Repeat("1",64), SnapshotPackSHA256: "" + strings.Repeat("2",64)},
		Subject: SubjectRef{SubjectIDHash: "" + strings.Repeat("3",64), HashAlgorithm: "sha2-256"},
	}
	// Add required hashes over signing payload.
	sp := BuildConsentSignPayload(ev)
	spb, err := jcs.CanonicalizeValue(sp)
	if err != nil { t.Fatal(err) }
	ev.Hashes = map[string]string{"sha2-256": hashing.SHA256Hex(spb)}
	ev.ConsentEventID = ev.Hashes["sha2-256"]
	raw, _ := json.Marshal(ev)
	canon, err := jcs.CanonicalizeJSON(raw)
	if err != nil { t.Fatal(err) }
	st, _, _ := VerifyConsent(canon, true)
	if st != "PARTIAL" { t.Fatalf("expected PARTIAL, got %s", st) }
}

func TestConsentTamperFails(t *testing.T) {
	opts := policylock.SnapshotOptions{CreatedAtUTC: "2026-01-01T00:00:00Z", UserAgent: "test"}
	zipb, _, err := policylock.SnapshotFromFile("../../fixtures/policylock/policy1.txt", opts)
	if err != nil { t.Fatal(err) }
	tmp := t.TempDir() + "/snap.zip"
	if err := os.WriteFile(tmp, zipb, 0644); err != nil { t.Fatal(err) }

	_, evBytes, _, err := RecordConsent(tmp, "", RecordOptions{
		CreatedAtUTC: "2026-01-01T00:00:01Z",
		SubjectIdentifier: "alice@example.com",
		TenantSaltHex: "bb",
		PepperHex: "aa",
	})
	if err != nil { t.Fatal(err) }

	tampered := append([]byte{}, evBytes...)
	for i := range tampered {
		if tampered[i] == 'a' { tampered[i] = 'b'; break }
	}
	st, _, _ := VerifyConsent(tampered, false)
	if st != "INVALID" {
		t.Fatalf("expected INVALID, got %s", st)
	}
}
