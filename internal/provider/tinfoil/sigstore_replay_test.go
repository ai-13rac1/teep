package tinfoil

import (
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/attestation/sigstoretest"
	"github.com/13rac1/teep/internal/capture"
)

const routerFixture = "tinfoil_v3_cloud_glm-5-2_20260817_003424"

// mutatedFixtureClient replays the router fixture after mutate changes its
// recorded GitHub proxy responses.
func mutatedFixtureClient(t *testing.T, mutate func(*capture.RecordedEntry)) *http.Client {
	t.Helper()
	_, entries, err := capture.Load("../../integration/testdata/" + routerFixture)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	for i := range entries {
		if strings.Contains(entries[i].URL, "github-proxy.tinfoil.sh") {
			mutate(&entries[i])
		}
	}
	return &http.Client{Transport: capture.NewReplayTransport(entries)}
}

func fixtureReleaseDigest(t *testing.T) string {
	t.Helper()
	_, entries, err := capture.Load("../../integration/testdata/" + routerFixture)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	for i := range entries {
		if strings.HasSuffix(entries[i].URL, "/tinfoil.hash") {
			return strings.TrimSpace(string(entries[i].Body))
		}
	}
	t.Fatal("fixture has no tinfoil.hash response")
	return ""
}

// TestFetchAndVerifyRejectsAlteredGitHubData changes one recorded GitHub
// proxy response at a time. Each change must fail the verification with no
// signer identity.
func TestFetchAndVerifyRejectsAlteredGitHubData(t *testing.T) {
	digest := fixtureReleaseDigest(t)
	otherDigest := strings.Repeat("ab", 32)
	isRelease := func(e *capture.RecordedEntry) bool { return strings.HasSuffix(e.URL, "/releases/latest") }
	isHash := func(e *capture.RecordedEntry) bool { return strings.HasSuffix(e.URL, "/tinfoil.hash") }
	isAttestation := func(e *capture.RecordedEntry) bool { return strings.Contains(e.URL, "/attestations/sha256:") }

	tests := []struct {
		name   string
		mutate func(*capture.RecordedEntry)
		want   string
	}{
		{"release request fails", func(e *capture.RecordedEntry) {
			if isRelease(e) {
				e.Method = "NONE"
			}
		}, "fetch latest release tag: GET"},
		{"release HTTP status", func(e *capture.RecordedEntry) {
			if isRelease(e) {
				e.Status = http.StatusNotFound
			}
		}, "returned HTTP 404"},
		{"release JSON", func(e *capture.RecordedEntry) {
			if isRelease(e) {
				e.Body = []byte("not json")
			}
		}, "unmarshal release response"},
		{"empty release tag", func(e *capture.RecordedEntry) {
			if isRelease(e) {
				e.Body = []byte(`{"tag_name":""}`)
			}
		}, "release has empty tag_name"},
		{"hash missing", func(e *capture.RecordedEntry) {
			if isHash(e) {
				e.Status = http.StatusNotFound
			}
		}, "fetch tinfoil.hash"},
		{"hash malformed", func(e *capture.RecordedEntry) {
			if isHash(e) {
				e.Body = []byte("zz")
			}
		}, "tinfoil.hash must be 64 hex chars"},
		{"attestation HTTP status", func(e *capture.RecordedEntry) {
			if isAttestation(e) {
				e.Status = http.StatusInternalServerError
			}
		}, "fetch attestation"},
		{"attestation oversized", func(e *capture.RecordedEntry) {
			if isAttestation(e) {
				e.Body = make([]byte, maxAttestationResponseSize+1)
			}
		}, "exceeds size limit"},
		{"attestation JSON", func(e *capture.RecordedEntry) {
			if isAttestation(e) {
				e.Body = []byte("not json")
			}
		}, "unmarshal attestation response"},
		{"no attestations", func(e *capture.RecordedEntry) {
			if isAttestation(e) {
				e.Body = []byte(`{"attestations":[]}`)
			}
		}, "no attestations found"},
		{"bundle malformed", func(e *capture.RecordedEntry) {
			if isAttestation(e) {
				e.Body = []byte(`{"attestations":[{"bundle":{"mediaType":"unknown"}}]}`)
			}
		}, "parse DSSE bundle"},
		{"artifact digest", func(e *capture.RecordedEntry) {
			switch {
			case isHash(e):
				e.Body = []byte(otherDigest + "\n")
			case isAttestation(e):
				e.URL = strings.Replace(e.URL, digest, otherDigest, 1)
			}
		}, "DSSE bundle verification failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sv := NewSigstoreVerifier(mutatedFixtureClient(t, tc.mutate), sigstoretest.TrustedRoot(attestation.NewStaticTrustedRootSource))
			predicate, _, signer, err := sv.FetchAndVerify(t.Context(), RouterRepo)
			if err == nil {
				t.Fatal("FetchAndVerify accepted altered GitHub data")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			if predicate != nil || signer != (SignerIdentity{}) {
				t.Fatalf("failed verification returned predicate %d bytes and signer %+v", len(predicate), signer)
			}
		})
	}
}
