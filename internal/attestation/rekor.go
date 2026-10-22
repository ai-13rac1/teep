package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// defaultRekorBase is the production Rekor transparency log API URL.
const defaultRekorBase = "https://rekor.sigstore.dev"

// rekorLogPublicKeyPEM is the production Rekor transparency log's signing key.
// This key signs the Signed Entry Timestamp (SET) and checkpoints.
// Source: https://rekor.sigstore.dev/api/v1/log/publicKey
const rekorLogPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`

// rekorEntry holds the full data returned by the Rekor API for a single log
// entry. The Verification fields are used for SET and inclusion proof checks.
type rekorEntry struct {
	Body           string // base64-encoded entry body
	IntegratedTime int64
	LogID          string
	LogIndex       int64
	Verification   *rekorVerification
}

// rekorVerification holds the cryptographic verification data from a Rekor entry.
type rekorVerification struct {
	SignedEntryTimestamp string // base64-encoded SET
	InclusionProof       *rekorInclusionProof
}

// rekorInclusionProof holds the Merkle tree inclusion proof for a Rekor entry.
type rekorInclusionProof struct {
	Checkpoint string   // signed checkpoint (note format)
	Hashes     []string // hex-encoded sibling hashes
	LogIndex   int64
	RootHash   string // hex-encoded root hash
	TreeSize   int64
}

// RekorClient is an HTTP client for the Rekor transparency log API.
// The base URL is set at construction time and cannot be changed,
// preventing runtime redirection of Rekor lookups.
type RekorClient struct {
	baseURL      string
	httpClient   *http.Client
	publicKeyPEM string            // overrides rekorLogPublicKeyPEM when non-empty (tests)
	roots        TrustedRootSource // Sigstore trusted root for Fulcio certificate checks
}

// NewRekorClient returns a RekorClient pointing at the production Rekor API.
// roots supplies the Sigstore trusted root that Fulcio certificates must
// chain to. It panics when httpClient or roots is nil.
func NewRekorClient(httpClient *http.Client, roots TrustedRootSource) *RekorClient {
	return newRekorClient(defaultRekorBase, "", httpClient, roots)
}

// NewRekorClientWithBase returns a RekorClient with a custom base URL.
// Intended for tests and environments with a private Rekor instance.
func NewRekorClientWithBase(baseURL string, httpClient *http.Client, roots TrustedRootSource) *RekorClient {
	return newRekorClient(baseURL, "", httpClient, roots)
}

// NewRekorClientWithKey returns a RekorClient with a custom base URL and
// signing public key PEM. Intended for tests that need to verify entries
// against a known key without hitting the production Rekor log.
func NewRekorClientWithKey(baseURL, publicKeyPEM string, httpClient *http.Client, roots TrustedRootSource) *RekorClient {
	return newRekorClient(baseURL, publicKeyPEM, httpClient, roots)
}

func newRekorClient(baseURL, publicKeyPEM string, httpClient *http.Client, roots TrustedRootSource) *RekorClient {
	if httpClient == nil {
		panic("attestation.NewRekorClient: nil HTTP client")
	}
	if roots == nil {
		panic("attestation.NewRekorClient: nil Sigstore trusted root source")
	}
	return &RekorClient{baseURL: baseURL, publicKeyPEM: publicKeyPEM, httpClient: httpClient, roots: roots}
}

// RekorProvenance holds the result of the Rekor entry that teep selected for
// a digest. The identity fields are set only when FulcioVerified is true.
type RekorProvenance struct {
	Digest string
	// FulcioVerified is true when the entry verifier is a certificate, the
	// entry SET verified, and the certificate chains to a Fulcio CA in the
	// Sigstore trusted root, with a valid SCT, at the integrated time.
	FulcioVerified bool
	// FulcioErr is set when the verifier is a certificate that is not
	// verified as a Fulcio certificate. It is nil for a raw public key.
	FulcioErr      error
	KeyFingerprint string // SHA-256 hex of the PKIX public key bytes
	SubjectURI     string // certificate SAN (OIDC identity)
	OIDCIssuer     string // 1.3.6.1.4.1.57264.1.8, or 1.3.6.1.4.1.57264.1.1
	Trigger        string // 1.3.6.1.4.1.57264.1.2
	SourceCommit   string // 1.3.6.1.4.1.57264.1.3
	SourceRepo     string // 1.3.6.1.4.1.57264.1.5
	SourceRef      string // 1.3.6.1.4.1.57264.1.6
	SourceRepoURL  string // 1.3.6.1.4.1.57264.1.12
	RunnerEnv      string // 1.3.6.1.4.1.57264.1.11
	RunURL         string // 1.3.6.1.4.1.57264.1.21
	Err            error  // non-fatal: provenance unavailable but digest exists

	// SETVerified is true when the Rekor Signed Entry Timestamp was
	// successfully verified against the Rekor log's public key.
	SETVerified bool

	// SETErr is set when SET verification was attempted but failed.
	SETErr error

	// InclusionVerified is true when the Merkle tree inclusion proof was
	// successfully verified.
	InclusionVerified bool

	// InclusionErr is set when inclusion proof verification was attempted but failed.
	InclusionErr error

	// IntegratedTime is the Unix timestamp when Rekor integrated the entry.
	IntegratedTime int64
}

// FetchRekorProvenance queries the Rekor API for a digest's log entry and
// verifies its Fulcio certificate provenance if present.
//
// All returned UUIDs are tried in order. The function prefers an entry backed
// by a verified Fulcio certificate (which carries OIDC build-provenance
// metadata) over a raw-public-key entry or a certificate that does not
// verify, so that an entry logged before the legitimate entry does not
// replace it.
func (rc *RekorClient) FetchRekorProvenance(ctx context.Context, digest string) RekorProvenance {
	return rc.fetchWithTrustedRoot(ctx, digest, nil)
}

// FetchRekorProvenanceForImage queries Rekor for a digest and, when img has a
// component-specific signature policy, prefers an entry that satisfies it. This
// avoids accepting unrelated downstream attestations that merely reference the
// same digest.
func (rc *RekorClient) FetchRekorProvenanceForImage(ctx context.Context, digest string, img *ImageProvenance) RekorProvenance {
	return rc.fetchWithTrustedRoot(ctx, digest, rekorImageMatcher(img))
}

// FetchRekorProvenanceForPolicy queries Rekor for a digest and prefers entries
// matching either the recognized component policy for repo or, when repo is not
// yet recognized, any provider-wide component signature policy.
func (rc *RekorClient) FetchRekorProvenanceForPolicy(
	ctx context.Context,
	digest string,
	repo string,
	policy *SupplyChainPolicy,
) RekorProvenance {
	return rc.fetchWithTrustedRoot(ctx, digest, policyMatcher(policy, repo))
}

// FetchRekorProvenancesForPolicy fetches provenance for each digest
// concurrently, preferring entries that match the component-specific policy for
// that digest when one is available. It gets the Sigstore trusted root once
// and gives the same read-only material to every digest. When the root is
// not available, every result has Err set.
func (rc *RekorClient) FetchRekorProvenancesForPolicy(
	ctx context.Context,
	digests []string,
	digestToRepo map[string]string,
	policy *SupplyChainPolicy,
) []RekorProvenance {
	results := make([]RekorProvenance, len(digests))
	if len(digests) == 0 {
		return results
	}
	material, err := rc.trustedRoot(ctx)
	if err != nil {
		for i, d := range digests {
			results[i] = RekorProvenance{Digest: d, Err: err}
		}
		return results
	}
	var wg sync.WaitGroup
	for i, d := range digests {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			results[i] = rc.fetchRekorProvenance(ctx, d, policyMatcher(policy, digestToRepo[d]), material)
		}(i, d)
	}
	wg.Wait()
	return results
}

func policyMatcher(policy *SupplyChainPolicy, repo string) rekorMatcher {
	if policy == nil {
		return nil
	}
	return rekorPolicyMatcherForRepo(policy, repo)
}

func (rc *RekorClient) fetchWithTrustedRoot(ctx context.Context, digest string, matcher rekorMatcher) RekorProvenance {
	material, err := rc.trustedRoot(ctx)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: err}
	}
	return rc.fetchRekorProvenance(ctx, digest, matcher, material)
}

type rekorMatch int

const (
	rekorNoMatch rekorMatch = iota
	rekorFallbackMatch
	rekorPreferredMatch
)

type rekorMatcher func(*RekorProvenance) rekorMatch

func (rc *RekorClient) fetchRekorProvenance(ctx context.Context, digest string, matcher rekorMatcher, material root.TrustedMaterial) RekorProvenance {
	uuids, err := rc.fetchRekorUUIDs(ctx, digest)
	if err != nil {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("search Rekor: %w", err)}
	}
	if len(uuids) == 0 {
		return RekorProvenance{Digest: digest, Err: fmt.Errorf("no Rekor entries for sha256:%s", digest)}
	}

	preferPolicyMatch := matcher != nil
	// Try each UUID; prefer one whose verifier is a verified Fulcio
	// certificate. An entry with a raw key or a certificate that does not
	// verify is kept only as a fallback, so that an entry logged first by
	// another party does not replace the build-provenance entry.
	var rawKeyFallback *RekorProvenance
	var fulcioFallback *RekorProvenance
	var policyFallback *RekorProvenance
	var lastErr error
	// A public digest can have many entries from other parties. Warn once
	// for the digest, not once for each entry whose certificate fails.
	var fulcioFailures int
	var lastFulcioErr error
	defer func() {
		if fulcioFailures > 0 {
			slog.WarnContext(ctx, "Rekor entry certificates not verified as Fulcio certificates",
				"digest", digest, "entries", fulcioFailures, "last_reason", lastFulcioErr.Error())
		}
	}()
	for _, uuid := range uuids {
		p, err := rc.fetchEntryProvenance(ctx, digest, uuid, material)
		if p.FulcioErr != nil {
			fulcioFailures++
			lastFulcioErr = p.FulcioErr
		}
		if err != nil {
			if _, rejected := errors.AsType[rekorEntryRejectedError](err); rejected {
				slog.WarnContext(ctx, "Rekor entry rejected",
					"digest", digest, "uuid", truncate(uuid, 100), "reason", err.Error())
			}
			lastErr = fmt.Errorf("entry %s: %w", truncate(uuid, 100), err)
			continue
		}

		if !p.FulcioVerified {
			if preferPolicyMatch && rekorPolicyMatched(matcher, &p, &policyFallback) {
				return p
			}
			if rawKeyFallback == nil {
				rawKeyFallback = &p
			}
			continue
		}

		if preferPolicyMatch {
			if rekorPolicyMatched(matcher, &p, &policyFallback) {
				return p
			}
			if fulcioFallback == nil {
				fulcioFallback = &p
			}
			continue
		}

		return p
	}

	if policyFallback != nil {
		return *policyFallback
	}

	if fulcioFallback != nil {
		return *fulcioFallback
	}

	// No verified Fulcio entry found; return the first other entry.
	if rawKeyFallback != nil {
		return *rawKeyFallback
	}

	if lastErr != nil {
		return RekorProvenance{Digest: digest, Err: lastErr}
	}
	return RekorProvenance{Digest: digest, Err: fmt.Errorf("no usable Rekor entry for sha256:%s", digest)}
}

// fetchEntryProvenance fetches and parses the entry for uuid and builds its
// provenance.
func (rc *RekorClient) fetchEntryProvenance(ctx context.Context, digest, uuid string, material root.TrustedMaterial) (RekorProvenance, error) {
	entry, body, err := rc.fetchRekorEntryBody(ctx, uuid)
	if err != nil {
		return RekorProvenance{}, err
	}
	return rc.rekorEntryProvenance(ctx, digest, uuid, entry, body, material)
}

func rekorPolicyMatched(matcher rekorMatcher, prov *RekorProvenance, fallback **RekorProvenance) bool {
	switch matcher(prov) {
	case rekorPreferredMatch:
		return true
	case rekorFallbackMatch:
		if *fallback == nil {
			p := *prov
			*fallback = &p
		}
	case rekorNoMatch:
	}
	return false
}

func hasComponentSignaturePolicy(img *ImageProvenance) bool {
	if img == nil {
		return false
	}
	switch img.Provenance {
	case FulcioSigned:
		return img.OIDCIssuer != "" && (img.OIDCIdentity != "" || len(img.OIDCIdentities) > 0) && len(img.SourceRepos) > 0
	case SigstorePresent:
		return img.KeyFingerprint != ""
	default:
		return false
	}
}

func rekorImageMatcher(img *ImageProvenance) rekorMatcher {
	if !hasComponentSignaturePolicy(img) {
		return nil
	}
	return func(prov *RekorProvenance) rekorMatch {
		if rekorMatchesImagePolicy(prov, img) {
			return rekorPreferredMatch
		}
		return rekorNoMatch
	}
}

func rekorPolicyMatcher(policy *SupplyChainPolicy) rekorMatcher {
	if policy == nil || !policy.HasSignedComponents() {
		return nil
	}
	return func(prov *RekorProvenance) rekorMatch {
		if policy.LookupBySignature(prov) != nil {
			return rekorPreferredMatch
		}
		return rekorNoMatch
	}
}

func rekorPolicyMatcherForRepo(policy *SupplyChainPolicy, repo string) rekorMatcher {
	img := policy.Lookup(repo)
	componentMatcher := rekorImageMatcher(img)
	providerMatcher := rekorPolicyMatcher(policy)
	if componentMatcher == nil {
		return providerMatcher
	}
	return func(prov *RekorProvenance) rekorMatch {
		if componentMatcher(prov) == rekorPreferredMatch {
			return rekorPreferredMatch
		}
		if providerMatcher != nil && providerMatcher(prov) != rekorNoMatch {
			return rekorFallbackMatch
		}
		return rekorNoMatch
	}
}

func rekorMatchesImagePolicy(prov *RekorProvenance, img *ImageProvenance) bool {
	if prov == nil || img == nil {
		return false
	}
	_, failed := verifyComponentSignature(prov, img, img.Repo, false)
	return !failed
}

// fetchRekorUUIDs calls POST /api/v1/index/retrieve to search for log entries
// matching a digest.
func (rc *RekorClient) fetchRekorUUIDs(ctx context.Context, digest string) ([]string, error) {
	payload, err := json.Marshal(map[string]string{"hash": "sha256:" + digest})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.baseURL+"/api/v1/index/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	tlsct.SetUserAgent(req)

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRekorResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	return parseRekorUUIDs(body)
}

// fetchRekorEntry calls POST /api/v1/log/entries/retrieve to fetch a log entry
// by UUID and returns the response body.
func (rc *RekorClient) fetchRekorEntry(ctx context.Context, uuid string) ([]byte, error) {
	payload, err := json.Marshal(map[string][]string{"entryUUIDs": {uuid}})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.baseURL+"/api/v1/log/entries/retrieve", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	tlsct.SetUserAgent(req)

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRekorResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	return respBody, nil
}

// rekorEntryRejectedError marks an entry that teep fetched and then rejected
// because it is malformed or is not a dsse 0.0.1 entry.
type rekorEntryRejectedError struct{ err error }

func (r rekorEntryRejectedError) Error() string { return r.err.Error() }
func (r rekorEntryRejectedError) Unwrap() error { return r.err }

// fetchRekorEntryBody fetches the entry for uuid and parses the response and
// the entry body. A fetch failure returns the transport or HTTP error. Any
// response that is not a well-formed dsse 0.0.1 entry, including one with
// unknown fields, returns a rekorEntryRejectedError.
func (rc *RekorClient) fetchRekorEntryBody(ctx context.Context, uuid string) (*rekorEntry, *rekorDSSEBody, error) {
	respBody, err := rc.fetchRekorEntry(ctx, uuid)
	if err != nil {
		return nil, nil, err
	}
	entry, body, err := parseRekorEntryAndBody(respBody, uuid)
	if err != nil {
		return nil, nil, rekorEntryRejectedError{err: err}
	}
	return entry, body, nil
}

func parseRekorEntryAndBody(respBody []byte, uuid string) (*rekorEntry, *rekorDSSEBody, error) {
	entry, unknown, err := parseRekorEntryResponse(respBody, uuid)
	if err != nil {
		return nil, nil, err
	}
	if len(unknown) > 0 {
		return nil, nil, fmt.Errorf("entry response has unknown fields: %s", formatUnknownFields(unknown))
	}
	raw, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("decode body base64: %w", err)
	}
	body, unknown, err := parseRekorBody(raw)
	if err != nil {
		return nil, nil, err
	}
	if len(unknown) > 0 {
		return nil, nil, fmt.Errorf("body has unknown fields: %s", formatUnknownFields(unknown))
	}
	return entry, body, nil
}

// verifyRekorEntry verifies the Signed Entry Timestamp (SET) and Merkle tree
// inclusion proof for a Rekor entry. Results are stored on the provided
// RekorProvenance. Verification failures are non-fatal — the provenance is
// still usable, but the report will reflect the verification status.
func (rc *RekorClient) verifyRekorEntry(entry *rekorEntry, prov *RekorProvenance) {
	// SET verification requires the Rekor public key; inclusion proof does not.
	// Verify them independently so a key parse failure doesn't mask a working
	// inclusion proof (or vice versa).
	rekorKey, err := rc.parseRekorPublicKey()
	if err != nil {
		prov.SETErr = fmt.Errorf("parse Rekor public key: %w", err)
	} else {
		if err := verifySET(entry, rekorKey); err != nil {
			prov.SETErr = fmt.Errorf("SET verification: %w", err)
		} else {
			prov.SETVerified = true
		}
	}

	// Verify the Merkle tree inclusion proof independently of SET.
	if err := verifyInclusionProof(entry); err != nil {
		prov.InclusionErr = fmt.Errorf("inclusion proof: %w", err)
	} else {
		prov.InclusionVerified = true
	}
}

// verifySET verifies the Rekor Signed Entry Timestamp (SET). The SET is an
// ECDSA signature over the JSON-canonicalized bundle {body, integratedTime,
// logIndex, logID}. This proves Rekor's log server acknowledged the entry.
func verifySET(entry *rekorEntry, rekorKey *ecdsa.PublicKey) error {
	if entry.Verification == nil || entry.Verification.SignedEntryTimestamp == "" {
		return errors.New("no signed entry timestamp in Rekor response")
	}

	setBytes, err := base64.StdEncoding.DecodeString(entry.Verification.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("decode SET: %w", err)
	}

	// The SET signs over {body, integratedTime, logIndex, logID}.
	// body is the base64-encoded entry body (kept as-is, not decoded).
	type setBundle struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	}
	bundle := setBundle{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogIndex:       entry.LogIndex,
		LogID:          entry.LogID,
	}
	contents, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return fmt.Errorf("canonicalize bundle: %w", err)
	}

	h := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(rekorKey, h[:], setBytes) {
		return errors.New("SET signature does not match Rekor public key")
	}
	return nil
}

// verifyInclusionProof verifies a Rekor entry's Merkle tree inclusion proof.
// The leaf hash is SHA-256(0x00 || entryBytes) per RFC 6962 §2.1.
// This proves the entry is actually present in the append-only log at the
// claimed position, preventing a MITM from fabricating entries.
func verifyInclusionProof(entry *rekorEntry) error {
	if entry.Verification == nil || entry.Verification.InclusionProof == nil {
		return errors.New("no inclusion proof in Rekor response")
	}

	ip := entry.Verification.InclusionProof

	// Validate bounds before casting int64 → uint64. A malicious or garbled
	// Rekor response could produce negative values that wrap to huge uint64s.
	if ip.LogIndex < 0 {
		return fmt.Errorf("inclusion proof logIndex is negative: %d", ip.LogIndex)
	}
	if ip.TreeSize <= 0 {
		return fmt.Errorf("inclusion proof treeSize is non-positive: %d", ip.TreeSize)
	}
	if ip.LogIndex >= ip.TreeSize {
		return fmt.Errorf("inclusion proof logIndex (%d) >= treeSize (%d)", ip.LogIndex, ip.TreeSize)
	}
	// A Merkle tree of depth D has at most D sibling hashes. For a SHA-256
	// tree, D ≤ 64 covers well beyond any realistic log size (~2^64 entries).
	const maxProofHashes = 64
	if len(ip.Hashes) > maxProofHashes {
		return fmt.Errorf("inclusion proof has %d hashes, exceeds maximum %d", len(ip.Hashes), maxProofHashes)
	}

	entryBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return fmt.Errorf("decode entry body: %w", err)
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(entryBytes)

	rootHash, err := hex.DecodeString(ip.RootHash)
	if err != nil {
		return fmt.Errorf("decode root hash: %w", err)
	}

	var hashes [][]byte
	for _, h := range ip.Hashes {
		hb, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("decode proof hash: %w", err)
		}
		hashes = append(hashes, hb)
	}

	if err := proof.VerifyInclusion(rfc6962.DefaultHasher,
		uint64(ip.LogIndex), uint64(ip.TreeSize), leafHash, hashes, rootHash); err != nil {
		return fmt.Errorf("merkle inclusion proof invalid: %w", err)
	}
	return nil
}

// parseRekorPublicKey parses the Rekor transparency log public key.
// Uses rc.publicKeyPEM if set, otherwise the embedded production key.
func (rc *RekorClient) parseRekorPublicKey() (*ecdsa.PublicKey, error) {
	keyPEM := rekorLogPublicKeyPEM
	if rc.publicKeyPEM != "" {
		keyPEM = rc.publicKeyPEM
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("no PEM block in Rekor public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rekor public key is %T, expected *ecdsa.PublicKey", pub)
	}
	return ecKey, nil
}
