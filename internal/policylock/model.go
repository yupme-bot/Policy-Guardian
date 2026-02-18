package policylock

type PolicySnapshot struct {
	Schema       string        `json:"schema"`
	SpecURL      string        `json:"spec_url"`
	ToolVersion  string        `json:"tool_version"`
	CreatedAtUTC string        `json:"created_at_utc"`
	Policy       PolicySection `json:"policy"`
	// SnapshotID is derived from sha2-256(JCS(sign_payload_bytes)).
	// It MUST NOT be included in the signing payload.
	SnapshotID string `json:"snapshot_id"`
}

type PolicySection struct {
	Input PolicyInput  `json:"input"`
	Fetch *PolicyFetch `json:"fetch,omitempty"`
	Bytes PolicyBytes  `json:"bytes"`
}

type PolicyInput struct {
	Mode string `json:"mode"` // file|url|stdin
	Path string `json:"path,omitempty"`
	URL  string `json:"url,omitempty"`
}

type PolicyFetch struct {
	RequestedURL        string            `json:"requested_url,omitempty"`
	FinalURL            string            `json:"final_url,omitempty"`
	RequestHeaders      map[string]string `json:"request_headers,omitempty"`
	RedirectCount       *int              `json:"redirect_count,omitempty"`
	HTTPStatus          int               `json:"http_status,omitempty"`
	ContentType         string            `json:"content_type,omitempty"`
	ETag                string            `json:"etag,omitempty"`
	LastModified        string            `json:"last_modified,omitempty"`
	RetrievedAtUTC      string            `json:"retrieved_at_utc,omitempty"`
	ResolvedIP          string            `json:"resolved_ip,omitempty"`
	TLSVersion          string            `json:"tls_version,omitempty"`
	TLSLeafCertSHA256   string            `json:"tls_leaf_cert_sha256,omitempty"`
	TLSSubjectCNSAN     string            `json:"tls_subject_cn_san,omitempty"`
	CrossDomainRedirect *bool             `json:"cross_domain_redirect,omitempty"`
}

type PolicyBytes struct {
	Length int               `json:"length"`
	Hashes map[string]string `json:"hashes"`
}
