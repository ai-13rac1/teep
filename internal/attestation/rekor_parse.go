package attestation

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// maxRekorUUIDs bounds the entry UUIDs that teep accepts from one Rekor index
// search. A search result with more UUIDs fails for that digest. The largest
// search result in the test captures has 508 UUIDs.
const maxRekorUUIDs = 1024

// rekorDSSEKind and rekorDSSEAPIVersion name the only Rekor entry type that
// teep accepts.
const (
	rekorDSSEKind       = "dsse"
	rekorDSSEAPIVersion = "0.0.1"
)

// rekorDSSEBody holds the parts of a Rekor dsse 0.0.1 entry body that teep
// uses. Rekor stores the canonical form: the two hashes and one signature
// with its verifier, without the DSSE payload.
type rekorDSSEBody struct {
	EnvelopeHash string     // SHA-256 hex of the DSSE envelope
	PayloadHash  string     // SHA-256 hex of the DSSE payload
	Signature    []byte     // DSSE signature
	VerifierPEM  []byte     // PEM-encoded verifier
	Verifier     *pem.Block // decoded verifier: CERTIFICATE or PUBLIC KEY
}

// decodeRekorArray decodes one JSON array into target, a pointer to a slice.
// It rejects invalid JSON, more than one JSON value and duplicate object
// members at any depth. jsonstrict decodes only objects, so the array is put
// into an object with one "value" member; because data is one JSON value,
// that object has no other member.
func decodeRekorArray(data []byte, target any) error {
	if err := jsonstrict.ValidateUniqueFields(data); err != nil {
		return err
	}
	wrapped := struct {
		Value any `json:"value"`
	}{Value: target}
	doc := make([]byte, 0, len(data)+10)
	doc = append(doc, `{"value":`...)
	doc = append(doc, data...)
	doc = append(doc, '}')
	unknown, missing, err := jsonstrict.Unmarshal(doc, &wrapped)
	if err != nil {
		return err
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return errors.New("not one JSON array")
	}
	return nil
}

// parseRekorUUIDs decodes the response of POST /api/v1/index/retrieve: a JSON
// array of at most maxRekorUUIDs entry UUIDs. An array has no field names, so
// the function returns no unknown fields.
func parseRekorUUIDs(data []byte) ([]string, error) {
	var uuids []string
	if err := decodeRekorArray(data, &uuids); err != nil {
		return nil, fmt.Errorf("decode UUIDs: %w", err)
	}
	if len(uuids) > maxRekorUUIDs {
		return nil, fmt.Errorf("search returned %d UUIDs, more than the limit of %d", len(uuids), maxRekorUUIDs)
	}
	if slices.Contains(uuids, "") {
		return nil, errors.New("search returned an empty UUID")
	}
	return uuids, nil
}

// rekorEntryObject is one log entry in the response of POST
// /api/v1/log/entries/retrieve.
type rekorEntryObject struct {
	Body           string          `json:"body"`
	IntegratedTime int64           `json:"integratedTime"`
	LogID          string          `json:"logID"`
	LogIndex       int64           `json:"logIndex"`
	Verification   json.RawMessage `json:"verification"`
	// Attestation holds the attestation that Rekor stores beside intoto
	// entries. Teep does not use it.
	Attestation json.RawMessage `json:"attestation,omitempty"`
}

type rekorVerificationObject struct {
	SignedEntryTimestamp string          `json:"signedEntryTimestamp"`
	InclusionProof       json.RawMessage `json:"inclusionProof"`
}

type rekorInclusionProofObject struct {
	Checkpoint string   `json:"checkpoint"`
	Hashes     []string `json:"hashes"`
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
}

// parseRekorEntryResponse decodes the response of POST
// /api/v1/log/entries/retrieve for one requested UUID. The response must hold
// exactly one entry, keyed by that UUID. It returns unknown field names, with
// their paths, to the caller.
func parseRekorEntryResponse(data []byte, uuid string) (*rekorEntry, []string, error) {
	var entries []map[string]json.RawMessage
	if err := decodeRekorArray(data, &entries); err != nil {
		return nil, nil, fmt.Errorf("decode entries: %w", err)
	}
	if len(entries) != 1 || len(entries[0]) != 1 {
		return nil, nil, fmt.Errorf("entries response holds %d entries, want one", countRekorEntries(entries))
	}
	var key string
	var value json.RawMessage
	for k, v := range entries[0] {
		key, value = k, v
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(uuid)) != 1 {
		return nil, nil, errors.New("entries response is for a different UUID")
	}
	return parseRekorEntryObject(value)
}

func countRekorEntries(maps []map[string]json.RawMessage) int {
	n := 0
	for _, m := range maps {
		n += len(m)
	}
	return n
}

func parseRekorEntryObject(data []byte) (*rekorEntry, []string, error) {
	var obj rekorEntryObject
	unknown, err := jsonstrict.UnmarshalObject(data, &obj, "entry")
	if err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	switch {
	case obj.Body == "":
		return nil, nil, errors.New("entry.body is empty")
	case obj.IntegratedTime <= 0:
		return nil, nil, fmt.Errorf("entry.integratedTime is not positive: %d", obj.IntegratedTime)
	case obj.LogIndex < 0:
		return nil, nil, fmt.Errorf("entry.logIndex is negative: %d", obj.LogIndex)
	case obj.LogID == "":
		return nil, nil, errors.New("entry.logID is empty")
	}
	var ver rekorVerificationObject
	unknown, err = jsonstrict.UnmarshalObject(obj.Verification, &ver, "entry.verification")
	if err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	var ip rekorInclusionProofObject
	unknown, err = jsonstrict.UnmarshalObject(ver.InclusionProof, &ip, "entry.verification.inclusionProof")
	if err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	return &rekorEntry{
		Body:           obj.Body,
		IntegratedTime: obj.IntegratedTime,
		LogID:          obj.LogID,
		LogIndex:       obj.LogIndex,
		Verification: &rekorVerification{
			SignedEntryTimestamp: ver.SignedEntryTimestamp,
			InclusionProof: &rekorInclusionProof{
				Checkpoint: ip.Checkpoint,
				Hashes:     ip.Hashes,
				LogIndex:   ip.LogIndex,
				RootHash:   ip.RootHash,
				TreeSize:   ip.TreeSize,
			},
		},
	}, nil, nil
}

type rekorBodyHeader struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       json.RawMessage `json:"spec"`
}

type rekorDSSESpec struct {
	EnvelopeHash json.RawMessage   `json:"envelopeHash"`
	PayloadHash  json.RawMessage   `json:"payloadHash"`
	Signatures   []json.RawMessage `json:"signatures"`
}

type rekorHashObject struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type rekorDSSESignature struct {
	Signature string `json:"signature"`
	Verifier  string `json:"verifier"`
}

// parseRekorBody decodes a base64-decoded Rekor entry body. It accepts only a
// dsse 0.0.1 body whose envelopeHash and payloadHash are SHA-256 hex values
// and whose signatures list holds exactly one signature with a certificate or
// public key verifier. It returns unknown field names, with their paths, to
// the caller.
func parseRekorBody(data []byte) (*rekorDSSEBody, []string, error) {
	var header rekorBodyHeader
	unknown, err := jsonstrict.UnmarshalObject(data, &header, "body")
	if err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	if header.Kind != rekorDSSEKind {
		return nil, nil, fmt.Errorf("entry kind %q is not supported, want %q", truncate(header.Kind, 32), rekorDSSEKind)
	}
	if header.APIVersion != rekorDSSEAPIVersion {
		return nil, nil, fmt.Errorf("dsse apiVersion %q is not supported, want %q", truncate(header.APIVersion, 32), rekorDSSEAPIVersion)
	}
	var spec rekorDSSESpec
	unknown, err = jsonstrict.UnmarshalObject(header.Spec, &spec, "body.spec")
	if err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	body := &rekorDSSEBody{}
	if body.EnvelopeHash, unknown, err = parseRekorSHA256(spec.EnvelopeHash, "body.spec.envelopeHash"); err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	if body.PayloadHash, unknown, err = parseRekorSHA256(spec.PayloadHash, "body.spec.payloadHash"); err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	if len(spec.Signatures) != 1 {
		return nil, nil, fmt.Errorf("dsse entry has %d signatures, want one", len(spec.Signatures))
	}
	var sig rekorDSSESignature
	unknown, err = jsonstrict.UnmarshalObject(spec.Signatures[0], &sig, "body.spec.signatures[0]")
	if err != nil || len(unknown) > 0 {
		return nil, unknown, err
	}
	if body.Signature, err = base64.StdEncoding.DecodeString(sig.Signature); err != nil || len(body.Signature) == 0 {
		return nil, nil, errors.New("dsse signature is empty or not base64")
	}
	if body.VerifierPEM, body.Verifier, err = parseRekorVerifier(sig.Verifier); err != nil {
		return nil, nil, err
	}
	return body, nil, nil
}

// parseRekorSHA256 decodes a Rekor hash object and requires the sha256
// algorithm with a 64-character lowercase hex value.
func parseRekorSHA256(data json.RawMessage, path string) (value string, unknown []string, err error) {
	var h rekorHashObject
	unknown, err = jsonstrict.UnmarshalObject(data, &h, path)
	if err != nil || len(unknown) > 0 {
		return "", unknown, err
	}
	if h.Algorithm != "sha256" {
		return "", nil, fmt.Errorf("%s.algorithm %q is not sha256", path, truncate(h.Algorithm, 32))
	}
	if !isLowerHex(h.Value, 64) {
		return "", nil, fmt.Errorf("%s.value is not 64 lowercase hex characters", path)
	}
	return h.Value, nil, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseRekorVerifier decodes a base64-encoded PEM verifier. It requires one
// PEM block of type CERTIFICATE or PUBLIC KEY and nothing after it.
func parseRekorVerifier(verifierB64 string) (verifierPEM []byte, block *pem.Block, err error) {
	if verifierB64 == "" {
		return nil, nil, errors.New("dsse verifier is empty")
	}
	verifierPEM, err = base64.StdEncoding.DecodeString(verifierB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode verifier base64: %w", err)
	}
	block, rest := pem.Decode(verifierPEM)
	if block == nil {
		return nil, nil, errors.New("verifier holds no PEM block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("verifier holds data after the PEM block")
	}
	if block.Type != "CERTIFICATE" && block.Type != "PUBLIC KEY" {
		return nil, nil, fmt.Errorf("verifier PEM type %q is neither CERTIFICATE nor PUBLIC KEY", truncate(block.Type, 32))
	}
	return verifierPEM, block, nil
}

// formatUnknownFields formats unknown field names from a Rekor response for
// a diagnostic. The names come from untrusted input, so it quotes and
// shortens them and shows at most three.
func formatUnknownFields(unknown []string) string {
	const shown = 3
	parts := make([]string, 0, shown)
	for i, name := range unknown {
		if i == shown {
			break
		}
		parts = append(parts, fmt.Sprintf("%q", truncate(name, 64)))
	}
	s := strings.Join(parts, ", ")
	if len(unknown) > shown {
		s += fmt.Sprintf(" and %d more", len(unknown)-shown)
	}
	return s
}
