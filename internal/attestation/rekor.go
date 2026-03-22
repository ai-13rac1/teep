package attestation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// RekorAPIBase is the base URL for the Rekor transparency log API.
//
//nolint:gochecknoglobals // var instead of const to allow test overrides
var RekorAPIBase = "https://rekor.sigstore.dev"

// Fulcio OIDC extension OID prefix: 1.3.6.1.4.1.57264.1.
var (
	fulcioOIDPrefix  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1}
	oidOIDCIssuer    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidTrigger       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}
	oidSourceCommit  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}
	oidSourceRepo    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}
	oidSourceRef     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}
	oidRunnerEnv     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidSourceRepoURL = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidRunURL        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}
)

// RekorProvenance holds the build provenance metadata extracted from a Rekor
// transparency log entry's Fulcio certificate.
type RekorProvenance struct {
	Digest        string
	HasCert       bool   // false = raw public key, no Fulcio provenance
	OIDCIssuer    string // 1.3.6.1.4.1.57264.1.1
	Trigger       string // 1.3.6.1.4.1.57264.1.2
	SourceCommit  string // 1.3.6.1.4.1.57264.1.3
	SourceRepo    string // 1.3.6.1.4.1.57264.1.5
	SourceRef     string // 1.3.6.1.4.1.57264.1.6
	SourceRepoURL string // 1.3.6.1.4.1.57264.1.12
	RunnerEnv     string // 1.3.6.1.4.1.57264.1.11
	RunURL        string // 1.3.6.1.4.1.57264.1.21
	Err           error  // non-fatal: provenance unavailable but digest exists
}

// FetchRekorProvenance queries the Rekor API for a digest's log entry and
// parses Fulcio certificate provenance if present.
func FetchRekorProvenance(ctx context.Context, digest string, client *http.Client) RekorProvenance {
	uuids, err := fetchRekorUUIDs(ctx, digest, client)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("search Rekor: %w", err)}
	}
	if len(uuids) == 0 {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("no Rekor entries for sha256:%s", digest)}
	}

	body, err := fetchRekorEntry(ctx, uuids[0], client)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("fetch Rekor entry: %w", err)}
	}

	verifierPEM, err := extractVerifierPEM(body)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("extract verifier: %w", err)}
	}

	block, _ := pem.Decode(verifierPEM)
	if block == nil {
		return RekorProvenance{Digest: digest, Err: errors.New("invalid PEM in verifier")}
	}

	if block.Type == "PUBLIC KEY" {
		// Raw public key — no Fulcio provenance available (e.g. datadog/agent).
		return RekorProvenance{Digest: digest, HasCert: false}
	}

	if block.Type != "CERTIFICATE" {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("unexpected PEM type: %s", block.Type)}
	}

	prov, err := parseFulcioProvenance(verifierPEM)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("parse Fulcio cert: %w", err)}
	}
	prov.Digest = digest
	return *prov
}

// fetchRekorUUIDs calls POST /api/v1/index/retrieve to search for log entries
// matching a digest.
func fetchRekorUUIDs(ctx context.Context, digest string, client *http.Client) ([]string, error) {
	payload, err := json.Marshal(map[string]string{"hash": "sha256:" + digest})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RekorAPIBase+"/api/v1/index/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 256))
	}

	var uuids []string
	if err := json.Unmarshal(body, &uuids); err != nil {
		return nil, fmt.Errorf("decode UUIDs: %w", err)
	}
	return uuids, nil
}

// fetchRekorEntry calls POST /api/v1/log/entries/retrieve to fetch a log entry
// by UUID and returns the decoded entry body.
func fetchRekorEntry(ctx context.Context, uuid string, client *http.Client) ([]byte, error) {
	payload, err := json.Marshal(map[string][]string{"entryUUIDs": {uuid}})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, RekorAPIBase+"/api/v1/log/entries/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody), 256))
	}

	// Response is an array of maps: [{"<uuid>": {"body": "<base64>", ...}}]
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &entries); err != nil {
		return nil, fmt.Errorf("decode entries array: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("empty entries response")
	}

	// Get the first entry's value (the map has one key: the UUID).
	var entryValue json.RawMessage
	for _, v := range entries[0] {
		entryValue = v
		break
	}

	var entryObj struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(entryValue, &entryObj); err != nil {
		return nil, fmt.Errorf("decode entry object: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(entryObj.Body)
	if err != nil {
		return nil, fmt.Errorf("base64 decode body: %w", err)
	}
	return decoded, nil
}

// extractVerifierPEM extracts the verifier PEM from a decoded Rekor entry body
// (DSSE envelope). The verifier is at spec.signatures[0].verifier and is itself
// base64-encoded.
func extractVerifierPEM(entryBody []byte) ([]byte, error) {
	var entry struct {
		Spec struct {
			Signatures []struct {
				Verifier string `json:"verifier"`
			} `json:"signatures"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(entryBody, &entry); err != nil {
		return nil, fmt.Errorf("decode DSSE entry: %w", err)
	}
	if len(entry.Spec.Signatures) == 0 {
		return nil, errors.New("no signatures in DSSE entry")
	}

	verifierB64 := entry.Spec.Signatures[0].Verifier
	if verifierB64 == "" {
		return nil, errors.New("empty verifier in DSSE signature")
	}

	verifierPEM, err := base64.StdEncoding.DecodeString(verifierB64)
	if err != nil {
		// Some entries have the PEM directly (not base64-wrapped).
		if _, rest := pem.Decode([]byte(verifierB64)); rest != nil {
			return []byte(verifierB64), nil
		}
		return nil, fmt.Errorf("decode verifier base64: %w", err)
	}
	return verifierPEM, nil
}

// parseFulcioProvenance parses a Fulcio certificate PEM and extracts the
// Sigstore OIDC extension OIDs containing build provenance metadata.
func parseFulcioProvenance(certPEM []byte) (*RekorProvenance, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse X.509: %w", err)
	}

	prov := &RekorProvenance{HasCert: true}

	for _, ext := range cert.Extensions {
		if !hasFulcioPrefix(ext.Id) {
			continue
		}
		val := decodeExtensionValue(ext.Value)

		switch {
		case ext.Id.Equal(oidOIDCIssuer):
			prov.OIDCIssuer = val
		case ext.Id.Equal(oidTrigger):
			prov.Trigger = val
		case ext.Id.Equal(oidSourceCommit):
			prov.SourceCommit = val
		case ext.Id.Equal(oidSourceRepo):
			prov.SourceRepo = val
		case ext.Id.Equal(oidSourceRef):
			prov.SourceRef = val
		case ext.Id.Equal(oidRunnerEnv):
			prov.RunnerEnv = val
		case ext.Id.Equal(oidSourceRepoURL):
			prov.SourceRepoURL = val
		case ext.Id.Equal(oidRunURL):
			prov.RunURL = val
		}
	}

	return prov, nil
}

// hasFulcioPrefix checks whether oid starts with 1.3.6.1.4.1.57264.1.
func hasFulcioPrefix(oid asn1.ObjectIdentifier) bool {
	if len(oid) < len(fulcioOIDPrefix) {
		return false
	}
	for i, v := range fulcioOIDPrefix {
		if oid[i] != v {
			return false
		}
	}
	return true
}

// decodeExtensionValue decodes a Fulcio extension value. These are ASN.1
// UTF8String encoded (tag 0x0C). Some older entries may use raw bytes.
func decodeExtensionValue(raw []byte) string {
	var s string
	if _, err := asn1.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Fallback: treat as raw UTF-8 bytes (some Rekor entries pre-date
	// the ASN.1 encoding convention).
	return string(raw)
}

// truncateStr truncates s to maxLen characters, appending "..." if truncated.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
