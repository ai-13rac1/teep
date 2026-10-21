package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/attestation/sigstoretest"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// ctfe2022LogID is the key ID of the ctfe.sigstore.dev/2022 CT log that signs
// the SCTs in current Fulcio leaf certificates.
const ctfe2022LogID = "dd3d306ac6c7113263191e1c99673702a24a5eb8de3cadff878a72802f29ee8e"

func TestStaticTrustedRootSourceRejectsInvalidJSON(t *testing.T) {
	valid := sigstoretest.TrustedRootJSON()
	unknownField := strings.Replace(string(valid), `"mediaType"`, `"unexpected": true, "mediaType"`, 1)
	for name, input := range map[string]string{
		"empty":         "",
		"not JSON":      "not json",
		"truncated":     string(valid[:len(valid)/2]),
		"array":         "[]",
		"unknown field": unknownField,
		"no CA":         `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			roots, err := NewStaticTrustedRootSource([]byte(input))
			if err == nil {
				t.Fatal("static trusted root source accepted invalid JSON")
			}
			if roots != nil {
				t.Fatalf("got source %v with error %v", roots, err)
			}
			t.Logf("rejected: %v", err)
		})
	}
}

func TestCheckedInTrustedRootContents(t *testing.T) {
	material, err := sigstoretest.TrustedRoot(NewStaticTrustedRootSource).TrustedRoot(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	var intermediate bool
	for _, ca := range material.FulcioCertificateAuthorities() {
		fulcio, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			t.Fatalf("certificate authority has type %T", ca)
		}
		for _, cert := range fulcio.Intermediates {
			if cert.Subject.CommonName == "sigstore-intermediate" && len(cert.Subject.Organization) == 1 &&
				cert.Subject.Organization[0] == "sigstore.dev" && fulcio.ValidityPeriodEnd.IsZero() {
				intermediate = true
			}
		}
	}
	if !intermediate {
		t.Error("trusted root has no current Fulcio CA with the sigstore-intermediate certificate")
	}

	ctLog, ok := material.CTLogs()[ctfe2022LogID]
	if !ok {
		t.Fatalf("trusted root has no ctfe.sigstore.dev/2022 log %s", ctfe2022LogID)
	}
	if ctLog.BaseURL != "https://ctfe.sigstore.dev/2022" {
		t.Errorf("CT log %s base URL = %q", ctfe2022LogID, ctLog.BaseURL)
	}

	block, _ := pem.Decode([]byte(rekorLogPublicKeyPEM))
	if block == nil {
		t.Fatal("decode pinned Rekor key")
	}
	sum := sha256.Sum256(block.Bytes)
	rekorLogID := hex.EncodeToString(sum[:])
	if !strings.HasPrefix(rekorLogID, "c0d23d6a") {
		t.Fatalf("pinned Rekor log ID = %s, want prefix c0d23d6a", rekorLogID)
	}
	rekorLog, ok := material.RekorLogs()[rekorLogID]
	if !ok {
		t.Fatalf("trusted root has no Rekor log with the pinned key ID %s", rekorLogID)
	}
	if rekorLog.BaseURL != defaultRekorBase {
		t.Errorf("Rekor log base URL = %q, want %q", rekorLog.BaseURL, defaultRekorBase)
	}
}

// TestCheckedInTrustedRootHash records the SHA-256 of the TUF target that the
// provenance note names. Change both together.
func TestCheckedInTrustedRootHash(t *testing.T) {
	data := sigstoretest.TrustedRootJSON()
	sum := sha256.Sum256(data)
	const want = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("trusted root SHA-256 = %s, want %s (update testdata/sigstore_trusted_root.md)", got, want)
	}
	note, err := os.ReadFile("testdata/sigstore_trusted_root.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(note), want) {
		t.Fatal("provenance note does not name the trusted root SHA-256")
	}
}

func TestStaticTrustedRootSourceConcurrentUse(t *testing.T) {
	roots := sigstoretest.TrustedRoot(NewStaticTrustedRootSource)
	first, err := roots.TrustedRoot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			material, err := roots.TrustedRoot(t.Context())
			if err != nil {
				errs <- err
				return
			}
			if material != first || len(material.CTLogs()) == 0 {
				errs <- errors.New("source returned different or empty material")
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent TrustedRoot: %v", err)
	}
}
