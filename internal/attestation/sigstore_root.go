package attestation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// trustedRootTimeout bounds one HTTP request of the TUF trusted root fetch.
const trustedRootTimeout = 30 * time.Second

// TrustedRootSource supplies the Sigstore trusted root: the Fulcio
// certificate authorities, the certificate transparency logs, the Rekor
// logs and the timestamp authorities, each with its validity window.
// Implementations must be safe for concurrent use. The returned material is
// read-only; callers must not change it.
type TrustedRootSource interface {
	TrustedRoot(ctx context.Context) (root.TrustedMaterial, error)
}

// tufTrustedRootSource fetches the public-good Sigstore trusted root through
// TUF, starting from the root metadata that sigstore-go embeds.
type tufTrustedRootSource struct{}

// NewTUFTrustedRootSource returns the production trusted root source. Each
// call to TrustedRoot updates the TUF metadata from tuf-repo-cdn.sigstore.dev
// with a new CT-enforcing HTTP client and makes one attempt for each file.
// The TUF client keeps the metadata in memory only and writes no files: a
// local cache gives nothing to a source that fetches on every call.
func NewTUFTrustedRootSource() TrustedRootSource {
	return tufTrustedRootSource{}
}

func (tufTrustedRootSource) TrustedRoot(ctx context.Context) (root.TrustedMaterial, error) {
	client := tlsct.NewHTTPClient(trustedRootTimeout)
	defer client.CloseIdleConnections()
	return fetchTUFTrustedRoot(newTrustedRootFetcher(ctx, client))
}

// fetchTUFTrustedRoot runs one TUF update with the local cache disabled.
func fetchTUFTrustedRoot(f fetcher.Fetcher) (root.TrustedMaterial, error) {
	opts := tuf.DefaultOptions().WithDisableLocalCache().WithFetcher(f)
	trustedRoot, err := root.FetchTrustedRootWithOptions(opts)
	if err != nil {
		return nil, err
	}
	return trustedRoot, nil
}

// staticTrustedRootSource returns one trusted root parsed at construction.
type staticTrustedRootSource struct {
	root *root.TrustedRoot
}

// NewStaticTrustedRootSource parses a Sigstore trusted root JSON document
// (media type application/vnd.dev.sigstore.trustedroot+json) and returns a
// source that always returns it. It sends no network requests. Tests use it
// with the checked-in testdata/sigstore_trusted_root.json; it must not read
// a root from untrusted input such as a capture directory.
func NewStaticTrustedRootSource(rootJSON []byte) (TrustedRootSource, error) {
	if len(rootJSON) == 0 {
		return nil, errors.New("empty Sigstore trusted root JSON")
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("parse Sigstore trusted root: %w", err)
	}
	switch {
	case len(trustedRoot.FulcioCertificateAuthorities()) == 0:
		return nil, errors.New("no Fulcio certificate authority in Sigstore trusted root")
	case len(trustedRoot.CTLogs()) == 0:
		return nil, errors.New("no certificate transparency log in Sigstore trusted root")
	case len(trustedRoot.RekorLogs()) == 0:
		return nil, errors.New("no Rekor log in Sigstore trusted root")
	}
	return staticTrustedRootSource{root: trustedRoot}, nil
}

func (s staticTrustedRootSource) TrustedRoot(_ context.Context) (root.TrustedMaterial, error) {
	return s.root, nil
}

// newTrustedRootFetcher retains the dependency's one-attempt download policy.
func newTrustedRootFetcher(ctx context.Context, client *http.Client) *fetcher.DefaultFetcher {
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(trustedRootDo(func(req *http.Request) (*http.Response, error) {
		return client.Do(req.WithContext(ctx))
	}))
	return f
}

// trustedRootDo attaches the verification context before http.Client applies
// its download timeout, including while the fetcher reads the response body.
type trustedRootDo func(*http.Request) (*http.Response, error)

func (do trustedRootDo) Do(req *http.Request) (*http.Response, error) { return do(req) }
