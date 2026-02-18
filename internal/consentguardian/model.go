package consentguardian

type ConsentEvent struct {
	Schema        string            `json:"schema"`
	SpecURL       string            `json:"spec_url"`
	CreatedAtUTC  string            `json:"created_at_utc"`
	Hashes        map[string]string `json:"hashes"`
	ConsentEventID string           `json:"consent_event_id,omitempty"`

	Policy  PolicyRef          `json:"policy"`
	Subject SubjectRef         `json:"subject"`
	Context map[string]string  `json:"context,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`

	Signing *SigningInfo `json:"signing,omitempty"`
}

type PolicyRef struct {
	PolicySHA256        string `json:"policy_sha256"`
	SnapshotID          string `json:"snapshot_id"`
	SnapshotPackSHA256  string `json:"snapshot_pack_sha256"`
}

type SubjectRef struct {
	SubjectIDHash string `json:"subject_id_hash"`
	HashAlgorithm string `json:"hash_algorithm"`
}

type SigningInfo struct {
	Mode            string `json:"mode"` // none|ed25519
	Algorithm        string `json:"algorithm,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
	KeyDescription   string `json:"key_description,omitempty"`
	LegalEntityName  string `json:"legal_entity_name,omitempty"`
	SignatureFile    string `json:"signature_file,omitempty"`
}
