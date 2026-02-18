package policylock

import (
	"bytes"
	"testing"
)

func TestDeterministicZipSameInput(t *testing.T) {
	opts := SnapshotOptions{CreatedAtUTC: "2026-01-01T00:00:00Z", UserAgent: "test"}
	z1, _, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", opts)
	if err != nil { t.Fatal(err) }
	z2, _, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", opts)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(z1, z2) {
		t.Fatalf("zip differs")
	}
}

func TestVerifyFailsOnTamper(t *testing.T) {
	opts := SnapshotOptions{CreatedAtUTC: "2026-01-01T00:00:00Z", UserAgent: "test"}
	z, _, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", opts)
	if err != nil { t.Fatal(err) }
	z2 := append([]byte{}, z...)
	z2[len(z2)-1] ^= 0x01
	st, _, _ := VerifySnapshotZip(z2)
	if st == "VALID" {
		t.Fatalf("expected invalid")
	}
}
