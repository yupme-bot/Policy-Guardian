package policylock

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"policyguardian/internal/shared/hashing"
	"policyguardian/internal/shared/jcs"
	"policyguardian/internal/shared/timefmt"
	"policyguardian/internal/shared/zipdet"
)

const (
	SchemaPolicySnapshot = "policylock.policy_snapshot.v0.1"
	SpecURLPolicyGuardian = "SPEC_POLICY_GUARDIAN_V0_1_FROZEN.md"
)

type SnapshotOptions struct {
	CreatedAtUTC   string
	RetrievedAtUTC string
	UserAgent      string
	MaxBytes       int64
}

func (o SnapshotOptions) ua() string {
	if o.UserAgent != "" {
		return o.UserAgent
	}
	return "policyguardian/0.1 (PolicyLock)"
}

func SnapshotFromFile(path string, opts SnapshotOptions) ([]byte, *PolicySnapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	in := PolicyInput{Mode: "file", Path: path}
	return buildSnapshot(b, in, nil, opts)
}

func SnapshotFromStdin(r io.Reader, opts SnapshotOptions) ([]byte, *PolicySnapshot, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	in := PolicyInput{Mode: "stdin"}
	return buildSnapshot(b, in, nil, opts)
}

func SnapshotFromURL(rawurl string, opts SnapshotOptions) ([]byte, *PolicySnapshot, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, errors.New("unsupported URL scheme")
	}

	firstHost := u.Hostname()
	finalURL := rawurl
	redirCount := 0
	var tlsInfo *tls.ConnectionState

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirCount = len(via)
			finalURL = req.URL.String()
			return nil
		},
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", opts.ua())

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		tmp := *resp.TLS
		tlsInfo = &tmp
	}

	var r io.Reader = resp.Body
	if opts.MaxBytes > 0 {
		r = io.LimitReader(resp.Body, opts.MaxBytes+1)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	if opts.MaxBytes > 0 && int64(len(body)) > opts.MaxBytes {
		return nil, nil, fmt.Errorf("response exceeds max bytes limit (%d)", opts.MaxBytes)
	}

	cl := resp.Header.Get("Content-Length")
	if cl != "" {
		var expected int
		_, _ = fmt.Sscanf(cl, "%d", &expected)
		if expected > 0 && expected != len(body) {
			return nil, nil, fmt.Errorf("truncated_http: content-length=%d read=%d", expected, len(body))
		}
	}

	fetch := &PolicyFetch{
		RequestedURL: rawurl,
		FinalURL: finalURL,
		RedirectCount: redirCount,
		HTTPStatus: resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		ETag: resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		RetrievedAtUTC: opts.RetrievedAtUTC,
	}
	// Note: retrieved_at_utc is finalized in buildSnapshot.
	// If the caller pins --created-at (and does not set --retrieved-at), we
	// intentionally pin retrieved_at_utc to created_at_utc to make URL snapshots
	// byte-identical across runs for the same content.
	if ip, _ := resolveIP(firstHost); ip != "" {
		fetch.ResolvedIP = ip
	}
	if strings.ToLower(firstHost) != strings.ToLower(parseHost(finalURL)) {
		fetch.CrossDomainRedirect = true
	}
	if tlsInfo != nil {
		fetch.TLSVersion = tlsVersionString(tlsInfo.Version)
		if len(tlsInfo.PeerCertificates) > 0 {
			leaf := tlsInfo.PeerCertificates[0]
			fetch.TLSLeafCertSHA256 = sha256Hex(leaf.Raw)
			fetch.TLSSubjectCNSAN = subjectCNSAN(leaf)
		}
	}
	in := PolicyInput{Mode: "url", URL: rawurl}
	return buildSnapshot(body, in, fetch, opts)
}

func buildSnapshot(policyBytes []byte, input PolicyInput, fetch *PolicyFetch, opts SnapshotOptions) ([]byte, *PolicySnapshot, error) {
	created := opts.CreatedAtUTC
	if created == "" {
		created = timefmt.Format(timefmt.NowUTC())
	}
	if fetch != nil {
		// Finalize retrieved_at_utc deterministically.
		// Default behavior: retrieved_at_utc == created_at_utc.
		// Override behavior: --retrieved-at pins it explicitly.
		if fetch.RetrievedAtUTC == "" {
			fetch.RetrievedAtUTC = created
		}
	}
	pHash := hashing.SHA256Hex(policyBytes)
	snap := &PolicySnapshot{
		Schema: SchemaPolicySnapshot,
		SpecURL: SpecURLPolicyGuardian,
		CreatedAtUTC: created,
		Policy: PolicySection{
			Input: input,
			Fetch: fetch,
			Bytes: PolicyBytes{
				Length: len(policyBytes),
				Hashes: map[string]string{"sha2-256": pHash},
			},
		},
		SnapshotID: "",
	}
	if input.Mode == "url" {
		snap.RequestHeaders = map[string]string{"user-agent": opts.ua()}
	}

	payload, err := BuildSignPayload(*snap)
	if err != nil {
		return nil, nil, err
	}
	signBytes, err := jcs.CanonicalizeValue(payload)
	if err != nil {
		return nil, nil, err
	}
	snap.SnapshotID = hashing.SHA256Hex(signBytes)

	snapJSON, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	entries := []zipdet.Entry{
		{Name:"policy_body.bin", Data: policyBytes},
		{Name:"policy_snapshot.json", Data: snapJSON},
	}
	zipBytes, err := zipdet.WriteDeterministicZip(entries)
	if err != nil {
		return nil, nil, err
	}
	return zipBytes, snap, nil
}

func BuildSignPayload(s PolicySnapshot) (map[string]any, error) {
	p := map[string]any{
		"created_at_utc": s.CreatedAtUTC,
		"policy": map[string]any{
			"input": map[string]any{
				"mode": s.Policy.Input.Mode,
			},
			"bytes": map[string]any{
				"hashes": map[string]any{
					"sha2-256": s.Policy.Bytes.Hashes["sha2-256"],
				},
			},
		},
	}
	inm := p["policy"].(map[string]any)["input"].(map[string]any)
	if s.Policy.Input.Mode == "file" && s.Policy.Input.Path != "" {
		inm["path"] = s.Policy.Input.Path
	}
	if s.Policy.Input.Mode == "url" && s.Policy.Input.URL != "" {
		inm["url"] = s.Policy.Input.URL
	}
	if s.Policy.Fetch != nil {
		f := map[string]any{}
		addStr := func(k, v string){ if v!="" { f[k]=v } }
		addStr("requested_url", s.Policy.Fetch.RequestedURL)
		addStr("final_url", s.Policy.Fetch.FinalURL)
		if s.Policy.Fetch.RedirectCount!=0 { f["redirect_count"]=s.Policy.Fetch.RedirectCount }
		if s.Policy.Fetch.HTTPStatus!=0 { f["http_status"]=s.Policy.Fetch.HTTPStatus }
		addStr("content_type", s.Policy.Fetch.ContentType)
		addStr("etag", s.Policy.Fetch.ETag)
		addStr("last_modified", s.Policy.Fetch.LastModified)
		addStr("retrieved_at_utc", s.Policy.Fetch.RetrievedAtUTC)
		addStr("resolved_ip", s.Policy.Fetch.ResolvedIP)
		addStr("tls_version", s.Policy.Fetch.TLSVersion)
		addStr("tls_leaf_cert_sha256", s.Policy.Fetch.TLSLeafCertSHA256)
		addStr("tls_subject_cn_san", s.Policy.Fetch.TLSSubjectCNSAN)
		if s.Policy.Fetch.CrossDomainRedirect { f["cross_domain_redirect"]=true }
		p["policy"].(map[string]any)["fetch"]=f
	}
	if len(s.RequestHeaders)>0 {
		rh := map[string]any{}
		// stable: include in sorted order by key
		keys := make([]string,0,len(s.RequestHeaders))
		for k := range s.RequestHeaders { keys = append(keys, strings.ToLower(k)) }
		sort.Strings(keys)
		for _, k := range keys {
			v := s.RequestHeaders[k]
			if v!="" { rh[k]=v }
		}
		if len(rh)>0 { p["request_headers"]=rh }
	}
	return p,nil
}

func VerifySnapshotZip(zipBytes []byte) (string, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return "", "", err
	}
	var snapJSON []byte
	var body []byte
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, `\`) {
			return "INVALID", "zip_slip_path", nil
		}
		switch f.Name {
		case "policy_snapshot.json":
			rc,_ := f.Open(); snapJSON,_ = io.ReadAll(rc); rc.Close()
		case "policy_body.bin":
			rc,_ := f.Open(); body,_ = io.ReadAll(rc); rc.Close()
		}
	}
	if snapJSON==nil || body==nil {
		return "INVALID","missing_required_files",nil
	}
	var snap PolicySnapshot
	if err := json.Unmarshal(snapJSON,&snap); err!=nil {
		return "INVALID","invalid_policy_snapshot_json",nil
	}
	bodyHash := hashing.SHA256Hex(body)
	if snap.Policy.Bytes.Hashes==nil || snap.Policy.Bytes.Hashes["sha2-256"]!=bodyHash {
		return "INVALID","policy_body_hash_mismatch",nil
	}
	payload, err := BuildSignPayload(snap)
	if err!=nil { return "INVALID","cannot_build_sign_payload",nil }
	signBytes, err := jcs.CanonicalizeValue(payload)
	if err!=nil { return "INVALID","jcs_error",nil }
	exp := hashing.SHA256Hex(signBytes)
	if snap.SnapshotID!=exp {
		return "INVALID","snapshot_id_mismatch",nil
	}
	return "VALID","",nil
}

func ReadSnapshotInfo(zipBytes []byte) (*PolicySnapshot, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, "", err
	}
	var snapJSON []byte
	var body []byte
	for _, f := range zr.File {
		switch f.Name {
		case "policy_snapshot.json":
			rc,_ := f.Open(); snapJSON,_ = io.ReadAll(rc); rc.Close()
		case "policy_body.bin":
			rc,_ := f.Open(); body,_ = io.ReadAll(rc); rc.Close()
		}
	}
	if snapJSON==nil || body==nil {
		return nil,"",fmt.Errorf("missing required files")
	}
	var snap PolicySnapshot
	if err := json.Unmarshal(snapJSON,&snap); err!=nil { return nil,"",err }
	return &snap, hashing.SHA256Hex(body), nil
}

func ShowSnapshot(zipPath string) (string, error) {
	b, err := os.ReadFile(zipPath)
	if err != nil { return "", err }
	snap, bodyHash, err := ReadSnapshotInfo(b)
	if err != nil { return "", err }
	var sb strings.Builder
	fmt.Fprintf(&sb,"schema: %s\n", snap.Schema)
	fmt.Fprintf(&sb,"created_at_utc: %s\n", snap.CreatedAtUTC)
	fmt.Fprintf(&sb,"snapshot_id: %s\n", snap.SnapshotID)
	fmt.Fprintf(&sb,"policy_sha256: %s\n", bodyHash)
	if snap.Policy.Input.Mode=="file" { fmt.Fprintf(&sb,"input_file: %s\n", snap.Policy.Input.Path) }
	if snap.Policy.Input.Mode=="url" { fmt.Fprintf(&sb,"input_url: %s\n", snap.Policy.Input.URL) }
	return sb.String(), nil
}

func resolveIP(host string) (string, error) {
	if host=="" { return "", nil }
	ips, err := net.LookupIP(host)
	if err!=nil || len(ips)==0 { return "", err }
	for _, ip := range ips {
		if ip.To4()!=nil { return ip.String(), nil }
	}
	return ips[0].String(), nil
}

func parseHost(u string) string {
	pu, err := url.Parse(u)
	if err!=nil { return "" }
	return pu.Hostname()
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10: return "TLS1.0"
	case tls.VersionTLS11: return "TLS1.1"
	case tls.VersionTLS12: return "TLS1.2"
	case tls.VersionTLS13: return "TLS1.3"
	default: return fmt.Sprintf("0x%x", v)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func subjectCNSAN(cert *x509.Certificate) string {
	parts := []string{}
	if cert.Subject.CommonName!="" { parts = append(parts,"CN="+cert.Subject.CommonName) }
	if len(cert.DNSNames)>0 { parts = append(parts,"SAN="+strings.Join(cert.DNSNames,",")) }
	return strings.Join(parts,";")
}
