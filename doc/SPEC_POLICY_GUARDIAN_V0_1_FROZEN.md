POLICY GUARDIAN v0.1 — FINAL FROZEN SPEC

Status: Frozen



Components

----------

1\. PolicyLock — policy snapshot tool

2\. Consent Guardian — consent recording tool

3\. Shared canonical JSON rules



Design Goals

------------

• Deterministic outputs  

• Privacy-minimized evidence  

• Offline verifiable artifacts  

• CLI-first workflow  

• Guardian Kernel compatible  

• No dashboards, no inference, no feature creep  





Trust Chain

-----------

PolicyLock snapshot

&nbsp;   ↓

Consent Guardian record

&nbsp;   ↓

Guardian Kernel sealing (optional)

&nbsp;   ↓

Verifier / Proof Lab



This chain proves:



• what policy existed  

• which policy a user agreed to  

• when the agreement was recorded  





======================================================================

1\. SHARED RULES (Both Tools)

======================================================================



1.1 Canonical JSON

------------------

All signing payloads use RFC 8785 (JCS):



• UTF-8 encoding  

• Unicode NFC normalization  

• Lexicographic key ordering  

• Integers only (no floats)  

• Optional fields omitted (never null)



This guarantees cross-language determinism.





1.2 Timestamp Format

--------------------

All timestamps MUST be:



YYYY-MM-DDTHH:MM:SSZ



• UTC only  

• No sub-seconds  

• Leap seconds clamped to :59  





1.3 Hash Format

---------------

All hashes are explicitly labeled:



&nbsp;   "hashes": { "sha2-256": "hex..." }



All signatures specify:



&nbsp;   "algorithm": "ed25519"





1.4 Snapshot Resolution Model

-----------------------------

Consent Guardian resolves snapshots using:



1\. Local content-addressable store keyed by snapshot\_id  

2\. CLI override path  



If snapshot not found → verification result PARTIAL.



Snapshot packs are immutable artifacts.





1.5 Optional Fields Rule

------------------------

Optional fields are omitted when absent.  

Never use null.





======================================================================

2\. POLICYLOCK v0.1

======================================================================



2.1 Purpose

-----------

Freeze policy bytes into a deterministic snapshot pack.



Proves:



• exact policy text  

• provenance metadata  

• optional existence-at-time evidence  





2.2 Snapshot Pack Contents

--------------------------

Required:



• policy\_snapshot.json  

• policy\_body.bin  



Optional:



• signature.ed25519.json  

• anchor/\*  





2.3 Deterministic ZIP Rules

---------------------------

ZIP archives MUST be reproducible byte-for-byte:



• Compression: STORE  

• Path separator: /  

• File order: lexicographic byte order  

• Fixed entry timestamps  

• No OS metadata  





2.4 RAW Mode Only

-----------------

policy\_body.bin contains exact bytes.



No newline normalization.  

No charset decoding.  

No HTML/PDF parsing.  





2.5 URL Metadata Stored

-----------------------

If snapshot from URL, metadata may include:



• requested\_url  

• final\_url  

• redirect\_count  

• http\_status  

• content\_type  

• etag  

• last\_modified  

• retrieved\_at\_utc  

• resolved\_ip  

• tls\_version  

• tls\_leaf\_cert\_sha256  

• tls\_subject\_cn\_san  

• cross\_domain\_redirect  



Minimal request headers may be stored.





2.6 Signing Payload

-------------------

Signing payload includes:



• created\_at\_utc  

• policy.input  

• policy.fetch  

• policy.bytes.hashes  



Excludes:



• signing block  

• anchors  

• snapshot\_id  



Compute:



sign\_payload\_bytes = RFC8785(sign\_payload)  

snapshot\_id = SHA256(sign\_payload\_bytes)



Signature optional but recommended.





2.7 Anchoring

-------------

Optional anchor types:



• RFC 3161 TSA  

• Transparency log  

• OpenTimestamps  



Earliest verified anchor is authoritative.





2.8 Exit Codes

--------------

0 — VALID / success  

1 — PARTIAL  

2 — INVALID / integrity failure  

3 — UNSUPPORTED  

4 — INPUT ERROR  

5 — NETWORK ERROR  





======================================================================

3\. CONSENT GUARDIAN v0.1

======================================================================



3.1 Purpose

-----------

Record deterministic consent events referencing a PolicyLock snapshot.



Proves:



• user agreed  

• to a specific policy text  

• at a specific time  





3.2 consent\_event.json Schema (Core Fields)

-------------------------------------------

{

&nbsp; "schema": "consentguardian.consent\_event.v0.1",

&nbsp; "spec\_url": "...",

&nbsp; "created\_at\_utc": "...",



&nbsp; "policy": {

&nbsp;   "policy\_sha256": "...",

&nbsp;   "snapshot\_id": "...",

&nbsp;   "snapshot\_pack\_sha256": "..."

&nbsp; },



&nbsp; "subject": {

&nbsp;   "subject\_id\_hash": "...",

&nbsp;   "hash\_algorithm": "sha2-256"

&nbsp; },



&nbsp; "context": { ... optional ... },

&nbsp; "evidence": { ... optional ... },



&nbsp; "signing": {

&nbsp;   "mode": "none|ed25519",

&nbsp;   "algorithm": "ed25519",

&nbsp;   "public\_key": "...",

&nbsp;   "signature\_file": "..."

&nbsp; }

}



Unsigned records are integrity-only.





3.3 subject\_id\_hash Definition

------------------------------

normalized\_identifier =

NFC(lowercase(identifier\_UTF8))



subject\_id\_hash =

SHA256(environment\_pepper || tenant\_salt || normalized\_identifier)



Notes:



• Pepper stored in secrets manager  

• Tenant salt stored per tenant  

• Records are pseudonymous personal data  





3.4 Signing Payload

-------------------

Includes:



• created\_at\_utc  

• policy section  

• subject section  

• context section  

• evidence section  



Excludes:



• signing block  



Compute:



consent\_event\_id = SHA256(RFC8785(sign\_payload))



Signing recommended for audit use.





3.5 Replay Protection

---------------------

Guardian Kernel SHOULD deduplicate consent\_event\_id.





3.6 Known v0.1 Out-of-Scope

----------------------------

• Consent revocation  

• Policy validity windows  

• Batch consent records  

• Identity verification  

• UI capture proof  





======================================================================

4\. SECURITY NOTES

======================================================================



Policy Guardian proves:



• policy version existed  

• consent was recorded  



It does NOT prove:



• user identity  

• UI display correctness  

• legal validity of policy  



Supply-chain trust required:



• Open source builds  

• Reproducible binaries  

• Signed releases  





======================================================================

5\. INTEROPERABILITY REQUIREMENTS

======================================================================



A compliant release MUST ship:



• JSON schemas  

• Golden test vectors  

• Reference verifier  

• Example snapshot + consent pair  



Verifiers MUST ignore unknown fields for forward compatibility.



END OF FROZEN SPEC



