package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/attestation/sigstoretest"
	"github.com/13rac1/teep/internal/capture"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// countingRoots counts TrustedRoot calls and returns err when it is set.
type countingRoots struct {
	next  attestation.TrustedRootSource
	err   error
	calls atomic.Int32
}

func (c *countingRoots) TrustedRoot(ctx context.Context) (root.TrustedMaterial, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return c.next.TrustedRoot(ctx)
}

func TestNewSigstoreVerifierRejectsNil(t *testing.T) {
	roots := sigstoretest.TrustedRoot(attestation.NewStaticTrustedRootSource)
	for name, build := range map[string]func(){
		"client": func() { NewSigstoreVerifier(nil, roots) },
		"roots":  func() { NewSigstoreVerifier(http.DefaultClient, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("NewSigstoreVerifier accepted a nil %s", name)
				}
			}()
			build()
		})
	}
}

func replayFixtureClient(t *testing.T, fixture string) *http.Client {
	t.Helper()
	_, entries, err := capture.Load("../../integration/testdata/" + fixture)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return &http.Client{Transport: capture.NewReplayTransport(entries)}
}

// TestFetchAndVerifyUsesInjectedTrustedRoot replays a captured Tinfoil
// bundle with the static trusted root. The verifier gets the root from the
// injected source once and writes no TUF cache, so it sends no TUF request.
func TestFetchAndVerifyUsesInjectedTrustedRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	roots := &countingRoots{next: sigstoretest.TrustedRoot(attestation.NewStaticTrustedRootSource)}
	sv := NewSigstoreVerifier(replayFixtureClient(t, "tinfoil_v3_cloud_glm-5-2_20260817_003424"), roots)

	_, predicateType, signer, err := sv.FetchAndVerify(t.Context(), RouterRepo)
	if err != nil {
		t.Fatalf("FetchAndVerify: %v", err)
	}
	if predicateType != PredicateMultiPlatform {
		t.Errorf("predicate type = %q, want %q", predicateType, PredicateMultiPlatform)
	}
	if signer.OIDCIssuer != GithubActionsOIDCIssuer {
		t.Errorf("OIDC issuer = %q, want %q", signer.OIDCIssuer, GithubActionsOIDCIssuer)
	}
	if got := roots.calls.Load(); got != 1 {
		t.Errorf("trusted root source called %d times, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".sigstore")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("verification wrote a TUF cache under HOME: %v", err)
	}
}

func TestFetchAndVerifyTrustedRootError(t *testing.T) {
	roots := &countingRoots{err: errors.New("root unavailable")}
	sv := NewSigstoreVerifier(replayFixtureClient(t, "tinfoil_v3_cloud_glm-5-2_20260817_003424"), roots)

	_, _, signer, err := sv.FetchAndVerify(t.Context(), RouterRepo)
	if err == nil {
		t.Fatal("FetchAndVerify succeeded without a trusted root")
	}
	if !strings.Contains(err.Error(), "fetch Sigstore trusted root: root unavailable") {
		t.Errorf("error = %v, want the trusted root error", err)
	}
	if signer != (SignerIdentity{}) {
		t.Errorf("signer = %+v, want zero value", signer)
	}
}
