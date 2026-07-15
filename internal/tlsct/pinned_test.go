package tlsct

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSPKIPinnedClientRejectsBeforeSendingRequest(t *testing.T) {
	var requests atomic.Int64
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)

	base := ts.Client().Transport.(*http.Transport).Clone()
	wrong := sha256.Sum256([]byte("wrong SPKI"))
	client, err := NewSPKIPinnedHTTPClientWithTransport(0, base, hexFingerprint(wrong), false)
	if err != nil {
		t.Fatalf("NewSPKIPinnedHTTPClientWithTransport: %v", err)
	}

	body := &countingReader{}
	req, err := http.NewRequest(http.MethodPost, ts.URL, io.NopCloser(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrSPKIMismatch) {
		t.Fatalf("Do error = %v, want ErrSPKIMismatch", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server received %d requests, want 0", got)
	}
	if got := body.reads.Load(); got != 0 {
		t.Fatalf("request body was read %d times before pin rejection, want 0", got)
	}
}

func TestSPKIPinnedClientRetainsCTWrapperAndReusesConnection(t *testing.T) {
	var requests atomic.Int64
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)

	base := ts.Client().Transport.(*http.Transport).Clone()
	fingerprint := certificateSPKI(t, ts)
	client, err := NewSPKIPinnedHTTPClientWithTransport(0, base, fingerprint, true)
	if err != nil {
		t.Fatalf("NewSPKIPinnedHTTPClientWithTransport: %v", err)
	}
	if _, ok := client.Transport.(*ctRoundTripper); !ok {
		t.Fatalf("Transport = %T, want *ctRoundTripper", client.Transport)
	}

	for range 2 {
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("server received %d requests, want 2", got)
	}
}

func TestSPKIFingerprintsEqual(t *testing.T) {
	one := sha256.Sum256([]byte("one"))
	two := sha256.Sum256([]byte("two"))
	if !SPKIFingerprintsEqual(hexFingerprint(one), hexFingerprint(one)) {
		t.Fatal("matching fingerprints did not compare equal")
	}
	if SPKIFingerprintsEqual(hexFingerprint(one), hexFingerprint(two)) {
		t.Fatal("different fingerprints compared equal")
	}
	if SPKIFingerprintsEqual("malformed", hexFingerprint(one)) {
		t.Fatal("malformed fingerprint compared equal")
	}
}

type countingReader struct{ reads atomic.Int64 }

func (r *countingReader) Read(_ []byte) (int, error) {
	r.reads.Add(1)
	return 0, io.EOF
}

func hexFingerprint(sum [sha256.Size]byte) string {
	const hexDigits = "0123456789abcdef"
	encoded := make([]byte, len(sum)*2)
	for i, b := range sum {
		encoded[i*2] = hexDigits[b>>4]
		encoded[i*2+1] = hexDigits[b&0x0f]
	}
	return string(encoded)
}

func certificateSPKI(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	if ts.Certificate() == nil {
		t.Fatal("test server has no certificate")
	}
	sum := sha256.Sum256(ts.Certificate().RawSubjectPublicKeyInfo)
	return hexFingerprint(sum)
}
