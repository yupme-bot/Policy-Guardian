package policylock

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"policyguardian/internal/shared/hashing"
	"policyguardian/internal/shared/jcs"
)

func TestSnapshotDeterminism(t *testing.T) {
	b1, _, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", SnapshotOptions{
		CreatedAtUTC: "2026-01-01T00:00:00Z",
		ToolVersion:  "policyguardian/v0.1.0-test",
		UserAgent:    "policyguardian/v0.1.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	b2, _, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", SnapshotOptions{
		CreatedAtUTC: "2026-01-01T00:00:00Z",
		ToolVersion:  "policyguardian/v0.1.0-test",
		UserAgent:    "policyguardian/v0.1.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	h1 := hashing.SHA256Hex(b1)
	h2 := hashing.SHA256Hex(b2)
	if h1 != h2 {
		t.Fatalf("zip hash mismatch:\n%s\n%s", h1, h2)
	}
}

func TestToolVersionRequired(t *testing.T) {
	_, _, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", SnapshotOptions{
		CreatedAtUTC: "2026-01-01T00:00:00Z",
		ToolVersion:  "",
		UserAgent:    "policyguardian/test",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestURLSnapshotTriStatePreserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	zipBytes, _, err := SnapshotFromURL(srv.URL, SnapshotOptions{
		CreatedAtUTC:   "2026-01-01T00:00:00Z",
		RetrievedAtUTC: "2026-01-01T00:00:00Z",
		ToolVersion:    "policyguardian/v0.1.0-test",
		UserAgent:      "policyguardian/v0.1.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatal(err)
	}

	var snapJSON string
	for _, f := range zr.File {
		if f.Name == "policy_snapshot.json" {
			rc, _ := f.Open()
			b := new(bytes.Buffer)
			_, _ = b.ReadFrom(rc)
			_ = rc.Close()
			snapJSON = b.String()
			break
		}
	}
	if snapJSON == "" {
		t.Fatalf("policy_snapshot.json missing")
	}

	// Parse JSON to avoid brittle whitespace assumptions.
	var root map[string]any
	if err := json.Unmarshal([]byte(snapJSON), &root); err != nil {
		t.Fatalf("failed to parse policy_snapshot.json: %v", err)
	}

	// request_headers must NOT be top-level.
	if _, ok := root["request_headers"]; ok {
		t.Fatalf("request_headers must be nested under policy.fetch")
	}

	policy, ok := root["policy"].(map[string]any)
	if !ok {
		t.Fatalf("missing policy")
	}
	fetch, ok := policy["fetch"].(map[string]any)
	if !ok {
		t.Fatalf("missing policy.fetch")
	}

	// Tri-state fields must preserve checked false / zero.
	if v, ok := fetch["redirect_count"]; !ok {
		t.Fatalf("expected redirect_count present")
	} else {
		// encoding/json uses float64 for numbers.
		fv, ok := v.(float64)
		if !ok || fv != 0 {
			t.Fatalf("expected redirect_count=0, got %v", v)
		}
	}
	if v, ok := fetch["cross_domain_redirect"]; !ok {
		t.Fatalf("expected cross_domain_redirect present")
	} else {
		bv, ok := v.(bool)
		if !ok || bv != false {
			t.Fatalf("expected cross_domain_redirect=false, got %v", v)
		}
	}

	// request_headers must be nested under policy.fetch.
	if _, ok := fetch["request_headers"].(map[string]any); !ok {
		t.Fatalf("expected policy.fetch.request_headers present")
	}
}

func TestModeInvariants(t *testing.T) {
	// mode=file forbids URL and fetch
	_, _, err := buildSnapshot([]byte("x"), PolicyInput{Mode: "file", Path: "a.txt", URL: "http://x"}, &PolicyFetch{}, SnapshotOptions{
		CreatedAtUTC: "2026-01-01T00:00:00Z",
		ToolVersion:  "policyguardian/test",
		UserAgent:    "policyguardian/test",
	})
	if err == nil {
		t.Fatalf("expected error for invalid invariants")
	}
}

func TestSnapshotIDMatchesSigningPayloadHash(t *testing.T) {
	_, snap, err := SnapshotFromFile("../../fixtures/policylock/policy1.txt", SnapshotOptions{
		CreatedAtUTC: "2026-01-01T00:00:00Z",
		ToolVersion:  "policyguardian/v0.1.0-test",
		UserAgent:    "policyguardian/v0.1.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildSignPayload(*snap)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := jcs.CanonicalizeValue(payload)
	if err != nil {
		t.Fatal(err)
	}
	exp := hashing.SHA256Hex(sb)
	if snap.SnapshotID != exp {
		t.Fatalf("snapshot_id mismatch\nexp=%s\ngot=%s", exp, snap.SnapshotID)
	}
}
