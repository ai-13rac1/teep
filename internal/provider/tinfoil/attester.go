package tinfoil

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

const attestationPath = "/.well-known/tinfoil-attestation"

// Attester fetches attestation data from the Tinfoil attestation endpoint.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Tinfoil Attester configured with the given base URL
// and API key.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	client := config.NewAttestationClient(len(offline) > 0 && offline[0])
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// SetClient replaces the HTTP client used for attestation fetches.
func (a *Attester) SetClient(c *http.Client) { a.client = c }

// FetchAttestation fetches a V3 attestation document from the static base URL.
func (a *Attester) FetchAttestation(ctx context.Context, _ string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	return fetchAndVerifyAttestation(ctx, a.client, a.baseURL, a.apiKey, nonce)
}

// DirectAttester fetches attestation from per-model inference enclaves,
// resolving each model to its dedicated domain via the DirectResolver.
type DirectAttester struct {
	resolver *DirectResolver
	apiKey   string
	client   *http.Client
}

// NewDirectAttester returns an attester that resolves per-model domains via
// the DirectResolver and fetches attestation from the resolved enclave.
func NewDirectAttester(resolver *DirectResolver, apiKey string, offline ...bool) *DirectAttester {
	return &DirectAttester{
		resolver: resolver,
		apiKey:   apiKey,
		client:   config.NewAttestationClient(len(offline) > 0 && offline[0]),
	}
}

// SetClient replaces the HTTP client used for attestation fetches and
// propagates it to the resolver for model discovery.
func (a *DirectAttester) SetClient(c *http.Client) {
	a.client = c
	a.resolver.SetClient(c)
}

// FetchAttestation resolves the model to a per-model domain and fetches
// attestation from that enclave's well-known endpoint. When a
// prompt_cache_key is present in the context, the resolver uses
// hash-based sticky routing for cache-aware backend selection.
func (a *DirectAttester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	m, err := a.resolver.ResolveMapping(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("tinfoil direct: resolve model %q: %w", model, err)
	}
	promptCacheKey := PromptCacheKeyFromContext(ctx)
	domain := m.SelectDomain(promptCacheKey)
	baseURL := "https://" + domain
	slog.DebugContext(ctx, "tinfoil direct: resolved model domain", "model", model, "domain", domain, "repo", m.Repo)
	raw, err := fetchAndVerifyAttestation(ctx, a.client, baseURL, a.apiKey, nonce)
	if err != nil {
		return nil, err
	}
	raw.TinfoilRepo = m.Repo
	return raw, nil
}

// fetchAndVerifyAttestation fetches a v3 attestation document from the given
// base URL, parses it, and checks the nonce and the TLS channel binding.
//
// The document carries no signature of its own. Its only authentication is the
// CPU quote over REPORT_DATA, which VerifyReportData checks later. The checks
// here reject a document that cannot possibly verify, before teep spends the
// work; they do not authenticate it.
func fetchAndVerifyAttestation(ctx context.Context, client *http.Client, baseURL, apiKey string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	u, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: parse attestation URL: %w", err)
	}
	q := u.Query()
	q.Set("nonce", nonce.Hex())
	u.RawQuery = q.Encode()

	// Log host+path only; the query string carries the client nonce and must
	// not be written to logs (matches tlsct.WrapLogging nonce-safety policy).
	slog.DebugContext(ctx, "tinfoil: fetching attestation", "host", u.Host, "path", u.Path)
	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, client, u.String(), apiKey, maxBodySize)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: fetch attestation: %w", err)
	}

	raw, err := parseV3Document(body)
	if err != nil {
		return nil, err
	}

	// Verify nonce matches (constant-time, decoded bytes per spec).
	responseNonce, err := hex.DecodeString(raw.Nonce)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: decode response nonce hex: %w", err)
	}
	if subtle.ConstantTimeCompare(responseNonce, nonce[:]) != 1 {
		return nil, fmt.Errorf("tinfoil: nonce mismatch: response nonce %q does not match client nonce",
			attestation.NoncePrefix(raw.Nonce))
	}

	// TLS channel binding: the live TLS peer must present the key the enclave
	// endorsed. parseV3Document requires the tls item, so an absent
	// fingerprint here is an internal invariant violation, not provider input.
	if peerSPKI == "" {
		return nil, errors.New("tinfoil: TLS channel binding failed: no TLS peer state (plain HTTP is not allowed for attestation endpoints)")
	}
	if subtle.ConstantTimeCompare([]byte(peerSPKI), []byte(raw.TinfoilTLSKeyFP)) != 1 {
		return nil, fmt.Errorf("tinfoil: TLS channel binding failed: live peer SPKI %s != endorsed tls key %s",
			provider.Truncate(peerSPKI, 16), provider.Truncate(raw.TinfoilTLSKeyFP, 16))
	}

	return raw, nil
}
