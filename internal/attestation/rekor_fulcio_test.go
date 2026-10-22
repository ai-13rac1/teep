package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation/sigstoretest"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/merkle/rfc6962"
)

// mockIntegratedTime is 2026-03-04T14:15:00Z, inside the ten-minute validity
// of realFulcioCertPEM.
const mockIntegratedTime = 1772633700

const (
	composeManagerSAN  = "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
	githubActionsOIDC  = "https://token.actions.githubusercontent.com"
	composeManagerRepo = "nearai/compose-manager"
	composeManagerURL  = "https://github.com/nearai/compose-manager"
	composeManagerImg  = "nearaidev/compose-manager"
)

// testRekorKey is the test Rekor log key. It signs the SET of every mock
// entry that buildMockEntryResponse builds.
var testRekorKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
})

func testRekorKeyPEM() string {
	der, err := x509.MarshalPKIXPublicKey(&testRekorKey().PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// newTestRekorClient returns a client for ts that verifies SETs with the
// test Rekor key and certificates with the checked-in trusted root.
func newTestRekorClient(ts *httptest.Server) *RekorClient {
	return NewRekorClientWithKey(ts.URL, testRekorKeyPEM(), ts.Client(), sigstoretest.TrustedRoot(NewStaticTrustedRootSource))
}

// testRekorEntryResponse builds an entries response for uuid with a SET
// signed by the test Rekor key and a one-leaf inclusion proof.
func testRekorEntryResponse(uuid, bodyB64 string, integratedTime int64) []byte {
	body, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		// A test that sends a malformed body gets a SET over the text.
		body = []byte(bodyB64)
	}
	logID := strings.Repeat("c", 64)
	sig, err := signSETWithKey(&rekorEntry{Body: bodyB64, IntegratedTime: integratedTime, LogID: logID}, testRekorKey())
	if err != nil {
		panic(err)
	}
	raw, err := json.Marshal([]map[string]any{{uuid: map[string]any{
		"body":           bodyB64,
		"integratedTime": integratedTime,
		"logID":          logID,
		"logIndex":       0,
		"verification": map[string]any{
			"signedEntryTimestamp": sig,
			"inclusionProof": map[string]any{
				"checkpoint": "checkpoint",
				"hashes":     []string{},
				"logIndex":   0,
				"rootHash":   hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(body)),
				"treeSize":   1,
			},
		},
	}}})
	if err != nil {
		panic(err)
	}
	return raw
}

// signSETWithKey signs the canonical SET bundle of entry with key.
func signSETWithKey(entry *rekorEntry, key *ecdsa.PrivateKey) (string, error) {
	data, err := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	}{entry.Body, entry.IntegratedTime, entry.LogIndex, entry.LogID})
	if err != nil {
		return "", err
	}
	canon, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func realFulcioLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(realFulcioCertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func checkedInMaterial(t *testing.T) root.TrustedMaterial {
	t.Helper()
	material, err := sigstoretest.TrustedRoot(NewStaticTrustedRootSource).TrustedRoot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return material
}

// testTrustedMaterial is trusted material with chosen Fulcio CAs and CT logs.
// It counts calls to FulcioCertificateAuthorities.
type testTrustedMaterial struct {
	root.BaseTrustedMaterial
	cas     []root.CertificateAuthority
	ctlogs  map[string]*root.TransparencyLog
	caCalls atomic.Int32
}

func (m *testTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	m.caCalls.Add(1)
	return m.cas
}

func (m *testTrustedMaterial) CTLogs() map[string]*root.TransparencyLog { return m.ctlogs }

// materialSource is a TrustedRootSource that returns fixed material or an
// error and counts calls.
type materialSource struct {
	material root.TrustedMaterial
	err      error
	calls    atomic.Int32
}

func (s *materialSource) TrustedRoot(context.Context) (root.TrustedMaterial, error) {
	s.calls.Add(1)
	return s.material, s.err
}

// testCA is a certificate authority that teep does not trust.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"sigstore.dev"}, CommonName: "sigstore-intermediate"},
		NotBefore:             time.Unix(mockIntegratedTime, 0).Add(-365 * 24 * time.Hour),
		NotAfter:              time.Unix(mockIntegratedTime, 0).Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

// fulcioExtensions returns the Fulcio extensions of a GitHub Actions
// certificate for nearai/compose-manager.
func fulcioExtensions(t *testing.T) []pkix.Extension {
	t.Helper()
	der := func(s string) []byte {
		b, err := asn1.MarshalWithParams(s, "utf8")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	oid := func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, n} }
	return []pkix.Extension{
		{Id: oid(1), Value: []byte(githubActionsOIDC)},
		{Id: oid(2), Value: []byte("push")},
		{Id: oid(3), Value: []byte("406bddd95a7fa73858377f078d88272d7e8878ab")},
		{Id: oid(5), Value: []byte(composeManagerRepo)},
		{Id: oid(6), Value: []byte("refs/heads/master")},
		{Id: oid(8), Value: der(githubActionsOIDC)},
		{Id: oid(11), Value: der("github-hosted")},
		{Id: oid(12), Value: der(composeManagerURL)},
	}
}

// fulcioLikeLeaf returns a code-signing leaf with the Fulcio extensions and
// the compose-manager SAN. A nil parent makes it self-signed.
func fulcioLikeLeaf(t *testing.T, parent *testCA, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	san, err := url.Parse(composeManagerSAN)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:            []*url.URL{san},
		ExtraExtensions: fulcioExtensions(t),
	}
	issuer, signer := tmpl, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func certPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// testRootWithCA returns trusted material with ca as the only Fulcio CA,
// valid in [start, end], and the CT logs of the checked-in root.
func testRootWithCA(t *testing.T, ca testCA, start, end time.Time) *testTrustedMaterial {
	t.Helper()
	return &testTrustedMaterial{
		cas:    []root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: ca.cert, ValidityPeriodStart: start, ValidityPeriodEnd: end}},
		ctlogs: checkedInMaterial(t).CTLogs(),
	}
}

// composeManagerPolicy is the FulcioSigned policy of NEAR compose-manager.
func composeManagerPolicy() *SupplyChainPolicy {
	return &SupplyChainPolicy{Images: []ImageProvenance{{
		Repo:           composeManagerImg,
		ModelTier:      true,
		Provenance:     FulcioSigned,
		OIDCIssuer:     githubActionsOIDC,
		OIDCIdentities: []string{composeManagerSAN},
		SourceRepos:    []string{composeManagerRepo, composeManagerURL},
	}}}
}

// signedFactorResults evaluates the three signed-component factors for one
// compose-manager digest.
func signedFactorResults(prov *RekorProvenance) []FactorResult {
	in := &ReportInput{
		Rekor:             []RekorProvenance{*prov},
		DigestToRepo:      map[string]string{prov.Digest: composeManagerImg},
		ImageRepos:        []string{composeManagerImg},
		SupplyChainPolicy: composeManagerPolicy(),
	}
	out := make([]FactorResult, 0, 3)
	out = append(out, evalBuildTransparencyLog(in)...)
	out = append(out, evalComponentSignatureRecognition(in)...)
	out = append(out, evalProviderSignerRecognition(in)...)
	return out
}

func requireFactors(t *testing.T, prov *RekorProvenance, want Status, detail string) {
	t.Helper()
	results := signedFactorResults(prov)
	if len(results) != 3 {
		t.Fatalf("got %d factor results, want 3", len(results))
	}
	for _, f := range results {
		if f.Status != want || !strings.Contains(f.Detail, detail) {
			t.Errorf("%s: %s %q, want %s with %q", f.Name, f.Status, f.Detail, want, detail)
		}
	}
}

// entryServer serves the given entries, in order, for every digest.
func entryServer(t *testing.T, entries ...[]byte) *httptest.Server {
	t.Helper()
	uuids := make([]string, len(entries))
	byUUID := make(map[string][]byte, len(entries))
	for i, e := range entries {
		var m []map[string]json.RawMessage
		if err := json.Unmarshal(e, &m); err != nil {
			t.Fatal(err)
		}
		for k := range m[0] {
			uuids[i] = k
		}
		byUUID[uuids[i]] = e
	}
	var requests atomic.Int32
	return rekorParseServer(t, uuids, byUUID, &requests)
}

func certEntry(uuid string, cert *x509.Certificate) []byte {
	return testRekorEntryResponse(uuid, buildMockDSSEBody(certPEM(cert)), mockIntegratedTime)
}

// TestFulcioSelfSignedCertificateRejected logs a self-signed certificate with
// the Fulcio extensions, the GitHub Actions issuer and the compose-manager
// SAN, in an entry with a valid SET and inclusion proof. The certificate
// does not chain to the trusted root, so teep sets no identity and all three
// factors fail. It runs against the checked-in root and a test root.
func TestFulcioSelfSignedCertificateRejected(t *testing.T) {
	at := time.Unix(mockIntegratedTime, 0)
	forged := fulcioLikeLeaf(t, nil, at.Add(-time.Minute), at.Add(9*time.Minute))
	roots := map[string]TrustedRootSource{
		"checked-in root": sigstoretest.TrustedRoot(NewStaticTrustedRootSource),
		"test root":       &materialSource{material: testRootWithCA(t, newTestCA(t), at.Add(-time.Hour), at.Add(time.Hour))},
	}
	for name, roots := range roots {
		t.Run(name, func(t *testing.T) {
			ts := entryServer(t, certEntry("forged", forged))
			rc := NewRekorClientWithKey(ts.URL, testRekorKeyPEM(), ts.Client(), roots)
			prov := rc.FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy())
			if prov.Err != nil || !prov.SETVerified || !prov.InclusionVerified {
				t.Fatalf("Err=%v SET=%v inclusion=%v, want a logged entry", prov.Err, prov.SETVerified, prov.InclusionVerified)
			}
			if prov.FulcioVerified || prov.FulcioErr == nil || !strings.Contains(prov.FulcioErr.Error(), "does not chain to a Fulcio CA") {
				t.Fatalf("FulcioVerified=%v FulcioErr=%v, want a chain failure", prov.FulcioVerified, prov.FulcioErr)
			}
			if prov.OIDCIssuer != "" || prov.SubjectURI != "" || prov.SourceRepo != "" || prov.SourceRepoURL != "" {
				t.Fatalf("forged certificate gave identity %+v", prov)
			}
			requireFactors(t, &prov, Fail, "the entry certificate does not chain to the Sigstore trusted root")
		})
	}
}

// TestFulcioAttackerEntryBeforeLegitimateEntry lists the forged entry
// before an entry with a real Fulcio leaf. The selected entry does not
// change, and the factors pass on it.
func TestFulcioAttackerEntryBeforeLegitimateEntry(t *testing.T) {
	at := time.Unix(mockIntegratedTime, 0)
	forged := fulcioLikeLeaf(t, nil, at.Add(-time.Minute), at.Add(9*time.Minute))
	ts := entryServer(t,
		certEntry("forged", forged),
		buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM)))
	rc := newTestRekorClient(ts)
	for name, prov := range map[string]RekorProvenance{
		"policy":    rc.FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy()),
		"no policy": rc.FetchRekorProvenance(t.Context(), testDigest),
	} {
		t.Run(name, func(t *testing.T) {
			if !prov.FulcioVerified || prov.FulcioErr != nil || prov.SubjectURI != composeManagerSAN {
				t.Fatalf("FulcioVerified=%v FulcioErr=%v SAN=%q, want the real entry", prov.FulcioVerified, prov.FulcioErr, prov.SubjectURI)
			}
			if prov.KeyFingerprint == "" || prov.KeyFingerprint == keyFingerprint(forged) {
				t.Fatal("selected the forged entry")
			}
			requireFactors(t, &prov, Pass, "")
		})
	}
}

func keyFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

// TestFulcioCertificateChecks covers the chain, the validity windows and
// the SCT with verifyFulcioCertificate.
func TestFulcioCertificateChecks(t *testing.T) {
	at := time.Unix(mockIntegratedTime, 0)
	realLeaf := realFulcioLeaf(t)
	checkedIn := checkedInMaterial(t)
	ca := newTestCA(t)
	caLeaf := fulcioLikeLeaf(t, &ca, at.Add(-time.Minute), at.Add(9*time.Minute))
	otherCTLog := func() map[string]*root.TransparencyLog {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]*root.TransparencyLog{strings.Repeat("ab", 32): {PublicKey: &key.PublicKey}}
	}
	for _, tc := range []struct {
		name     string
		leaf     *x509.Certificate
		at       time.Time
		material root.TrustedMaterial
		err      string
	}{
		{name: "real leaf at integrated time", leaf: realLeaf, at: at, material: checkedIn},
		{name: "real leaf before validity", leaf: realLeaf, at: realLeaf.NotBefore.Add(-time.Second), material: checkedIn, err: "does not chain"},
		{name: "real leaf after validity", leaf: realLeaf, at: realLeaf.NotAfter.Add(time.Second), material: checkedIn, err: "does not chain"},
		{name: "CA not in trusted root", leaf: caLeaf, at: at, material: checkedIn, err: "does not chain"},
		{name: "test CA leaf without SCT", leaf: caLeaf, at: at,
			material: testRootWithCA(t, ca, at.Add(-time.Hour), at.Add(time.Hour)), err: "SCT not verified"},
		{name: "integrated time outside leaf validity", leaf: caLeaf, at: at.Add(time.Hour),
			material: testRootWithCA(t, ca, at.Add(-24*time.Hour), at.Add(24*time.Hour)), err: "does not chain"},
		{name: "integrated time after CA window", leaf: caLeaf, at: at,
			material: testRootWithCA(t, ca, at.Add(-time.Hour), at.Add(-time.Minute)), err: "does not chain"},
		{name: "integrated time before CA window", leaf: caLeaf, at: at,
			material: testRootWithCA(t, ca, at.Add(time.Minute), at.Add(time.Hour)), err: "does not chain"},
		{name: "SCT from a log not in the root", leaf: realLeaf, at: at,
			material: &testTrustedMaterial{cas: checkedIn.FulcioCertificateAuthorities(), ctlogs: otherCTLog()}, err: "SCT not verified"},
		{name: "no CT logs", leaf: realLeaf, at: at,
			material: &testTrustedMaterial{cas: checkedIn.FulcioCertificateAuthorities()}, err: "SCT not verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary, err := verifyFulcioCertificate(tc.leaf, tc.at, tc.material)
			if tc.err == "" {
				if err != nil || summary.SubjectAlternativeName != composeManagerSAN {
					t.Fatalf("err=%v SAN=%q", err, summary.SubjectAlternativeName)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
			if summary.SubjectAlternativeName != "" || summary.Issuer != "" {
				t.Fatalf("failed check returned identity %+v", summary)
			}
		})
	}
}

// TestFulcioCertificateWithoutSAN covers the identity step: a leaf that
// passes the chain and SCT checks but has no SAN does not verify. The test
// removes the parsed SAN from a copy of the real leaf; the chain and SCT
// checks use the unchanged DER.
func TestFulcioCertificateWithoutSAN(t *testing.T) {
	leaf := *realFulcioLeaf(t)
	leaf.URIs = nil
	_, err := verifyFulcioCertificate(&leaf, time.Unix(mockIntegratedTime, 0), checkedInMaterial(t))
	if err == nil || !strings.Contains(err.Error(), "certificate identity") {
		t.Fatalf("err = %v, want an identity failure", err)
	}
}

// TestFulcioLeafExpiredNowPasses fetches an entry for a real Fulcio leaf
// that expired before the test runs. The integrated time is inside the leaf
// validity, so the entry verifies.
func TestFulcioLeafExpiredNowPasses(t *testing.T) {
	ts := entryServer(t, buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM)))
	prov := newTestRekorClient(ts).FetchRekorProvenance(t.Context(), testDigest)
	if !prov.FulcioVerified || prov.FulcioErr != nil || prov.IntegratedTime != mockIntegratedTime {
		t.Fatalf("FulcioVerified=%v FulcioErr=%v IntegratedTime=%d", prov.FulcioVerified, prov.FulcioErr, prov.IntegratedTime)
	}

	expired := realFulcioLeaf(t).NotAfter.Add(time.Minute).Unix()
	ts = entryServer(t, testRekorEntryResponse("late", buildMockDSSEBody(realFulcioCertPEM), expired))
	prov = newTestRekorClient(ts).FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy())
	if prov.FulcioVerified || prov.FulcioErr == nil || prov.SubjectURI != "" {
		t.Fatalf("entry integrated after the leaf expired: FulcioVerified=%v FulcioErr=%v", prov.FulcioVerified, prov.FulcioErr)
	}
	requireFactors(t, &prov, Fail, "the entry certificate does not chain to the Sigstore trusted root")
}

// TestFulcioInvalidSETSkipsChainCheck sends a real Fulcio leaf with a SET
// signed by another key. teep does not check the chain and sets no identity.
func TestFulcioInvalidSETSkipsChainCheck(t *testing.T) {
	ts := entryServer(t, buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM)))
	material := &testTrustedMaterial{cas: checkedInMaterial(t).FulcioCertificateAuthorities(), ctlogs: checkedInMaterial(t).CTLogs()}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	rc := NewRekorClientWithKey(ts.URL, otherPEM, ts.Client(), &materialSource{material: material})
	prov := rc.FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy())
	if prov.SETVerified || prov.FulcioVerified || prov.FulcioErr == nil || !strings.Contains(prov.FulcioErr.Error(), "certificate chain not checked") {
		t.Fatalf("SET=%v FulcioVerified=%v FulcioErr=%v", prov.SETVerified, prov.FulcioVerified, prov.FulcioErr)
	}
	if got := material.caCalls.Load(); got != 0 {
		t.Fatalf("chain check ran %d times without a verified SET", got)
	}
	if prov.SubjectURI != "" || prov.OIDCIssuer != "" {
		t.Fatalf("unverified entry has identity %+v", prov)
	}
	requireFactors(t, &prov, Fail, "")
}

// TestFulcioTrustedRootSourceError fails every digest, and all three factors,
// when the trusted root source fails. No Rekor request is sent.
func TestFulcioTrustedRootSourceError(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer ts.Close()
	for name, source := range map[string]*materialSource{
		"error":       {err: errors.New("TUF metadata expired")},
		"no material": {},
	} {
		t.Run(name, func(t *testing.T) {
			rc := NewRekorClientWithBase(ts.URL, ts.Client(), source)
			results := rc.FetchRekorProvenancesForPolicy(t.Context(), []string{testDigest, strings.Repeat("b", 64)},
				map[string]string{testDigest: composeManagerImg}, composeManagerPolicy())
			if source.calls.Load() != 1 {
				t.Fatalf("trusted root fetched %d times, want once", source.calls.Load())
			}
			for _, r := range results {
				if r.Err == nil || !strings.Contains(r.Err.Error(), "Sigstore trusted root") {
					t.Fatalf("Err = %v, want a trusted root failure", r.Err)
				}
			}
			requireFactors(t, &results[0], Fail, "Rekor provenance unavailable: get Sigstore trusted root")
			single := rc.FetchRekorProvenance(t.Context(), testDigest)
			if single.Err == nil || !strings.Contains(single.Err.Error(), "Sigstore trusted root") {
				t.Fatalf("single digest Err = %v", single.Err)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("sent %d Rekor requests without a trusted root", requests.Load())
	}
	if got := NewRekorClientWithBase(ts.URL, ts.Client(), &materialSource{}).FetchRekorProvenancesForPolicy(t.Context(), nil, nil, nil); len(got) != 0 {
		t.Fatalf("no digests gave %d results", len(got))
	}
}

// TestFulcioConcurrentFetches runs FetchRekorProvenancesForPolicy from many
// goroutines under -race. Each call gets the trusted root once, and every
// call selects the same verified entry.
func TestFulcioConcurrentFetches(t *testing.T) {
	ts := entryServer(t, buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM)))
	source := &materialSource{material: checkedInMaterial(t)}
	rc := NewRekorClientWithKey(ts.URL, testRekorKeyPEM(), ts.Client(), source)
	digests := []string{testDigest, strings.Repeat("1", 64), strings.Repeat("2", 64)}
	digestToRepo := map[string]string{}
	for _, d := range digests {
		digestToRepo[d] = composeManagerImg
	}
	const calls = 8
	var wg sync.WaitGroup
	results := make([][]RekorProvenance, calls)
	for i := range calls {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = rc.FetchRekorProvenancesForPolicy(context.Background(), digests, digestToRepo, composeManagerPolicy())
		}(i)
	}
	wg.Wait()
	if got := source.calls.Load(); got != calls {
		t.Fatalf("trusted root fetched %d times for %d calls", got, calls)
	}
	for _, rs := range results {
		for i, r := range rs {
			if r.Digest != digests[i] || !r.FulcioVerified || r.SubjectURI != composeManagerSAN || r.SourceCommit != "406bddd95a7fa73858377f078d88272d7e8878ab" {
				t.Fatalf("result %d = %+v", i, r)
			}
		}
	}
}

// TestFulcioManySearchResults serves a search result with 2048 UUIDs, more
// than other parties could easily add before, with the real entry among
// them. The digest still verifies: the UUID count alone does not fail it.
func TestFulcioManySearchResults(t *testing.T) {
	uuids := make([]string, 2048)
	for i := range uuids {
		uuids[i] = fmt.Sprintf("%080x", i)
	}
	uuids[3] = "real"
	entries := map[string][]byte{"real": buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM))}
	var requests atomic.Int32
	ts := rekorParseServer(t, uuids, entries, &requests)
	prov := newTestRekorClient(ts).FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy())
	if prov.Err != nil || !prov.FulcioVerified {
		t.Fatalf("Err=%v FulcioVerified=%v FulcioErr=%v", prov.Err, prov.FulcioVerified, prov.FulcioErr)
	}
	if got := requests.Load(); got != 4 {
		t.Fatalf("entry requests = %d, want 4", got)
	}
}

// TestFulcioUnparsableCertificateRejected rejects an entry whose verifier is
// a CERTIFICATE block that does not parse, and keeps searching.
func TestFulcioUnparsableCertificateRejected(t *testing.T) {
	bad := "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n"
	ts := entryServer(t,
		buildMockEntryResponse("bad", buildMockDSSEBody(bad)),
		buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM)))
	prov := newTestRekorClient(ts).FetchRekorProvenance(t.Context(), testDigest)
	if !prov.FulcioVerified {
		t.Fatalf("FulcioVerified=false, FulcioErr=%v Err=%v", prov.FulcioErr, prov.Err)
	}
	ts = entryServer(t, buildMockEntryResponse("bad", buildMockDSSEBody(bad)))
	prov = newTestRekorClient(ts).FetchRekorProvenance(t.Context(), testDigest)
	if prov.Err == nil || !strings.Contains(prov.Err.Error(), "parse verifier certificate") {
		t.Fatalf("Err = %v", prov.Err)
	}
}

func TestNewRekorClientPanicsOnNilArguments(t *testing.T) {
	roots := sigstoretest.TrustedRoot(NewStaticTrustedRootSource)
	for name, build := range map[string]func(){
		"nil client": func() { NewRekorClient(nil, roots) },
		"nil roots":  func() { NewRekorClient(http.DefaultClient, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			build()
		})
	}
}

// TestVerifyFulcioEntryRequiresChainVerification checks the order of the
// FulcioSigned checks on hand-built results: a certificate error, a raw
// key, and a result with identity fields but no chain verification.
func TestVerifyFulcioEntryRequiresChainVerification(t *testing.T) {
	img := &composeManagerPolicy().Images[0]
	identity := RekorProvenance{
		OIDCIssuer: githubActionsOIDC, SubjectURI: composeManagerSAN,
		SourceRepo: composeManagerRepo, SourceRepoURL: composeManagerURL,
	}
	for _, tc := range []struct {
		name string
		prov RekorProvenance
		want string
	}{
		{name: "certificate error", prov: RekorProvenance{FulcioErr: errors.New("chain"), KeyFingerprint: "ab"},
			want: "the entry certificate does not chain to the Sigstore trusted root: chain"},
		{name: "raw key", prov: RekorProvenance{KeyFingerprint: "ab"}, want: "expected Fulcio certificate but entry has raw key"},
		{name: "identity without chain", prov: identity, want: "Fulcio certificate chain not verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail, failed := verifyFulcioEntry(&tc.prov, img, img.Repo)
			if !failed || !strings.Contains(detail, tc.want) {
				t.Fatalf("detail=%q failed=%v, want %q", detail, failed, tc.want)
			}
		})
	}
	verified := identity
	verified.FulcioVerified = true
	if detail, failed := verifyFulcioEntry(&verified, img, img.Repo); failed {
		t.Fatalf("verified identity failed: %s", detail)
	}
}

// TestFulcioFailuresWarnOncePerDigest lists three entries whose
// certificates do not chain before the real entry. Teep logs one warning for
// the digest, with the count and the last reason, and one DEBUG line for
// each entry.
func TestFulcioFailuresWarnOncePerDigest(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	at := time.Unix(mockIntegratedTime, 0)
	forged := fulcioLikeLeaf(t, nil, at.Add(-time.Minute), at.Add(9*time.Minute))
	ts := entryServer(t,
		certEntry("forged-1", forged),
		certEntry("forged-2", forged),
		certEntry("forged-3", forged),
		buildMockEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM)))
	prov := newTestRekorClient(ts).FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy())
	if !prov.FulcioVerified {
		t.Fatalf("FulcioVerified=false FulcioErr=%v, want the real entry", prov.FulcioErr)
	}
	out := logs.String()
	warnings := 0
	debugLines := 0
	for line := range strings.Lines(out) {
		switch {
		case strings.Contains(line, "level=WARN"):
			warnings++
			if !strings.Contains(line, "entries=3") || !strings.Contains(line, "does not chain to a Fulcio CA") {
				t.Errorf("warning = %q, want the count and the last reason", line)
			}
		case strings.Contains(line, "level=DEBUG") && strings.Contains(line, "Rekor entry certificate not verified"):
			debugLines++
		}
	}
	if warnings != 1 || debugLines != 3 {
		t.Fatalf("got %d warnings and %d per-entry DEBUG lines, want 1 and 3; logs:\n%s", warnings, debugLines, out)
	}
}

// TestFulcioSETVerifiedInclusionFails sends a real Fulcio leaf with a valid
// SET and an inclusion proof whose root hash does not match. The SET
// authenticates the integrated time, so the certificate chain verifies and
// the identity is set. The inclusion failure is reported separately:
// build_transparency_log fails on it, and the two recognition factors pass
// on the chain-verified identity.
func TestFulcioSETVerifiedInclusionFails(t *testing.T) {
	var resp []map[string]map[string]any
	if err := json.Unmarshal(testRekorEntryResponse("real", buildMockDSSEBody(realFulcioCertPEM), mockIntegratedTime), &resp); err != nil {
		t.Fatal(err)
	}
	verification, ok := resp[0]["real"]["verification"].(map[string]any)
	if !ok {
		t.Fatal("test entry has no verification")
	}
	proof, ok := verification["inclusionProof"].(map[string]any)
	if !ok {
		t.Fatal("test entry has no inclusion proof")
	}
	proof["rootHash"] = strings.Repeat("00", 32)
	ts := entryServer(t, mustJSON(t, resp))
	prov := newTestRekorClient(ts).FetchRekorProvenanceForPolicy(t.Context(), testDigest, composeManagerImg, composeManagerPolicy())
	if prov.Err != nil || !prov.SETVerified || prov.SETErr != nil {
		t.Fatalf("Err=%v SET=%v SETErr=%v, want a verified SET", prov.Err, prov.SETVerified, prov.SETErr)
	}
	if prov.InclusionVerified || prov.InclusionErr == nil {
		t.Fatalf("InclusionVerified=%v InclusionErr=%v, want an inclusion failure", prov.InclusionVerified, prov.InclusionErr)
	}
	if !prov.FulcioVerified || prov.FulcioErr != nil || prov.SubjectURI != composeManagerSAN {
		t.Fatalf("FulcioVerified=%v FulcioErr=%v SAN=%q, want a verified chain", prov.FulcioVerified, prov.FulcioErr, prov.SubjectURI)
	}
	// The recognition factors depend on the chain-verified identity, which
	// needs the SET only; build_transparency_log also requires inclusion.
	for _, f := range signedFactorResults(&prov) {
		want, detail := Pass, ""
		if f.Name == FactorBuildTransparency {
			want, detail = Fail, "Rekor inclusion proof verification failed"
		}
		if f.Status != want || !strings.Contains(f.Detail, detail) {
			t.Errorf("%s: %s %q, want %s with %q", f.Name, f.Status, f.Detail, want, detail)
		}
	}
}
