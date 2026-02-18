package cliapp

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"policyguardian/internal/consentguardian"
	"policyguardian/internal/policylock"
	"policyguardian/internal/shared/version"
)

func Run(argv []string) int {
	if len(argv) == 0 {
		usage()
		return 4
	}
	if argv[0] == "--version" || argv[0] == "version" {
		fmt.Println("policyguardian " + version.Version)
		return 0
	}
	switch argv[0] {
	case "policylock":
		return runPolicyLock(argv[1:])
	case "consent":
		return runConsent(argv[1:])
	default:
		usage()
		return 4
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  policyguardian --version")
	fmt.Fprintln(os.Stderr, "  policyguardian policylock snapshot <file>|--url <url>|--stdin [--out <zip>] [--created-at <ts>]")
	fmt.Fprintln(os.Stderr, "  policyguardian policylock verify <snapshot.zip>")
	fmt.Fprintln(os.Stderr, "  policyguardian policylock show <snapshot.zip>")
	fmt.Fprintln(os.Stderr, "  policyguardian consent record <snapshot.zip|snapshot_id> --subject <id> --tenant-salt <hex> --pepper <hex> [--out <consent.json>] [--created-at <ts>] [--sign-privkey <hex>]")
	fmt.Fprintln(os.Stderr, "  policyguardian consent verify <consent.json> [--resolve-snapshot]")
}

func runPolicyLock(argv []string) int {
	if len(argv) == 0 {
		usage()
		return 4
	}
	switch argv[0] {
	case "snapshot":
		return cmdPolicySnapshot(argv[1:])
	case "verify":
		return cmdPolicyVerify(argv[1:])
	case "show":
		return cmdPolicyShow(argv[1:])
	default:
		usage()
		return 4
	}
}

func cmdPolicySnapshot(argv []string) int {
	fs := flag.NewFlagSet("policylock snapshot", flag.ContinueOnError)
	var urlStr string
	var useStdin bool
	var outPath string
	var createdAt string
	var maxBytes int64
	fs.StringVar(&urlStr, "url", "", "URL to fetch")
	fs.BoolVar(&useStdin, "stdin", false, "Read policy bytes from stdin")
	fs.StringVar(&outPath, "out", "policy_snapshot.zip", "Output snapshot zip")
	fs.StringVar(&createdAt, "created-at", "", "Created timestamp")
	fs.Int64Var(&maxBytes, "max-bytes", 0, "Max bytes for URL fetch")
	if err := fs.Parse(argv); err != nil {
		return 4
	}
	opts := policylock.SnapshotOptions{
		CreatedAtUTC: createdAt,
		ToolVersion:  version.ToolVersion,
		UserAgent:    version.ToolVersion + " (PolicyLock)",
		MaxBytes:     maxBytes,
	}

	var zipBytes []byte
	var snap *policylock.PolicySnapshot
	var err error
	if useStdin {
		zipBytes, snap, err = policylock.SnapshotFromStdin(os.Stdin, opts)
	} else if urlStr != "" {
		zipBytes, snap, err = policylock.SnapshotFromURL(urlStr, opts)
	} else {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "missing <file>")
			return 4
		}
		zipBytes, snap, err = policylock.SnapshotFromFile(fs.Arg(0), opts)
	}
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "unsupported") {
			fmt.Fprintln(os.Stderr, "UNSUPPORTED:", msg)
			return 3
		}
		if strings.Contains(msg, "truncated_http") || strings.Contains(msg, "response exceeds") {
			fmt.Fprintln(os.Stderr, "NETWORK ERROR:", msg)
			return 5
		}
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", msg)
		return 4
	}
	if err := os.WriteFile(outPath, zipBytes, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", err)
		return 4
	}
	// Save into store
	store := os.Getenv("POLICYGUARDIAN_STORE")
	if store == "" {
		store = ".policyguardian_store"
	}
	_ = os.MkdirAll(filepath.Join(store, "snapshots"), 0755)
	_ = os.WriteFile(filepath.Join(store, "snapshots", snap.SnapshotID+".zip"), zipBytes, 0644)

	fmt.Println("OK")
	fmt.Println("snapshot_id:", snap.SnapshotID)
	fmt.Println("out:", outPath)
	return 0
}

func cmdPolicyVerify(argv []string) int {
	if len(argv) != 1 {
		fmt.Fprintln(os.Stderr, "missing <snapshot.zip>")
		return 4
	}
	b, err := os.ReadFile(argv[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", err)
		return 4
	}
	status, reason, err := policylock.VerifySnapshotZip(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", err)
		return 4
	}
	fmt.Println(status)
	if reason != "" {
		fmt.Println("reason:", reason)
	}
	if status != "VALID" {
		return 2
	}

	// Helpful, deterministic context for humans.
	// This explains why two URL snapshots might legitimately differ:
	// if policy_sha256 differs, the remote bytes changed between fetches.
	snap, bodyHash, err := policylock.ReadSnapshotInfo(b)
	if err == nil {
		fmt.Println("policy_sha256:", bodyHash)
		if snap.Policy.Input.Mode == "url" && snap.Policy.Fetch != nil {
			if snap.Policy.Fetch.RetrievedAtUTC != "" {
				fmt.Println("retrieved_at_utc:", snap.Policy.Fetch.RetrievedAtUTC)
			}
			if snap.Policy.Fetch.FinalURL != "" {
				fmt.Println("final_url:", snap.Policy.Fetch.FinalURL)
			}
			if snap.Policy.Fetch.HTTPStatus != 0 {
				fmt.Println("http_status:", snap.Policy.Fetch.HTTPStatus)
			}
			if snap.Policy.Fetch.ContentType != "" {
				fmt.Println("content_type:", snap.Policy.Fetch.ContentType)
			}
			if snap.Policy.Fetch.ETag != "" {
				fmt.Println("etag:", snap.Policy.Fetch.ETag)
			}
			if snap.Policy.Fetch.LastModified != "" {
				fmt.Println("last_modified:", snap.Policy.Fetch.LastModified)
			}
			if snap.Policy.Fetch.ResolvedIP != "" {
				fmt.Println("resolved_ip:", snap.Policy.Fetch.ResolvedIP)
			}
			if snap.Policy.Fetch.RedirectCount != nil && *snap.Policy.Fetch.RedirectCount != 0 {
				fmt.Println("redirect_count:", *snap.Policy.Fetch.RedirectCount)
			}
			if snap.Policy.Fetch.CrossDomainRedirect != nil && *snap.Policy.Fetch.CrossDomainRedirect {
				fmt.Println("cross_domain_redirect:", "true")
			}
			fmt.Println("note:", "If two URL snapshots differ, compare policy_sha256. If it differs, the remote bytes changed between fetches.")
		}
	}
	return 0
}

func cmdPolicyShow(argv []string) int {
	if len(argv) != 1 {
		fmt.Fprintln(os.Stderr, "missing <snapshot.zip>")
		return 4
	}
	out, err := policylock.ShowSnapshot(argv[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", err)
		return 4
	}
	fmt.Print(out)
	return 0
}

func runConsent(argv []string) int {
	if len(argv) == 0 {
		usage()
		return 4
	}
	switch argv[0] {
	case "record":
		return cmdConsentRecord(argv[1:])
	case "verify":
		return cmdConsentVerify(argv[1:])
	default:
		usage()
		return 4
	}
}

func cmdConsentRecord(argv []string) int {
	fs := flag.NewFlagSet("consent record", flag.ContinueOnError)
	var outPath string
	var createdAt string
	var subject string
	var tenantSalt string
	var pepper string
	var signPriv string
	fs.StringVar(&outPath, "out", "consent_event.json", "Output consent json")
	fs.StringVar(&createdAt, "created-at", "", "Created timestamp")
	fs.StringVar(&subject, "subject", "", "Subject identifier")
	fs.StringVar(&tenantSalt, "tenant-salt", "", "Tenant salt hex")
	fs.StringVar(&pepper, "pepper", "", "Pepper hex")
	fs.StringVar(&signPriv, "sign-privkey", "", "Ed25519 private key hex")
	if err := fs.Parse(argv); err != nil {
		return 4
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "missing <snapshot.zip|snapshot_id>")
		return 4
	}
	if subject == "" || tenantSalt == "" || pepper == "" {
		fmt.Fprintln(os.Stderr, "missing --subject/--tenant-salt/--pepper")
		return 4
	}
	_, _, _, err := consentguardian.RecordConsent(fs.Arg(0), outPath, consentguardian.RecordOptions{
		CreatedAtUTC:      createdAt,
		SubjectIdentifier: subject,
		TenantSaltHex:     tenantSalt,
		PepperHex:         pepper,
		SignPrivKeyHex:    signPriv,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", err)
		return 4
	}
	fmt.Println("OK")
	fmt.Println("out:", outPath)
	return 0
}

func cmdConsentVerify(argv []string) int {
	fs := flag.NewFlagSet("consent verify", flag.ContinueOnError)
	var resolveSnap bool
	fs.BoolVar(&resolveSnap, "resolve-snapshot", false, "Resolve snapshot from local store")
	if err := fs.Parse(argv); err != nil {
		return 4
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "missing <consent.json>")
		return 4
	}
	status, reason, unsigned, err := consentguardian.VerifyConsentFile(fs.Arg(0), resolveSnap)
	if err != nil {
		fmt.Fprintln(os.Stderr, "INPUT ERROR:", err)
		return 4
	}
	fmt.Println(status)
	if reason != "" {
		fmt.Println("reason:", reason)
	}
	if unsigned {
		fmt.Fprintln(os.Stderr, "WARNING: unsigned_consent")
	}
	if status == "INVALID" {
		return 2
	}
	if status == "PARTIAL" {
		return 1
	}
	return 0
}
