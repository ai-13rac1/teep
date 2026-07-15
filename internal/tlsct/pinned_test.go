package tlsct

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestSPKIPinnedClientRejectsBeforeSendingRequest(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var requests atomic.Int64
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))

		wrong := sha256.Sum256([]byte("wrong SPKI"))
		client, err := NewSPKIPinnedHTTPClientWithTransport(0, &http.Transport{Proxy: nil}, hexFingerprint(wrong), false)
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
	})
}

func TestSPKIPinnedClientRetainsCTWrapperAndReusesConnection(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var mu sync.Mutex
		connections := make(map[string]struct{})
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			connections[r.RemoteAddr] = struct{}{}
			mu.Unlock()
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusNoContent)
		}))

		fingerprint := certificateSPKI(t, ts)
		client, err := NewSPKIPinnedHTTPClientWithTransport(0, &http.Transport{Proxy: nil}, fingerprint, true)
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
		mu.Lock()
		got := len(connections)
		mu.Unlock()
		if got != 1 {
			t.Fatalf("unique TLS connections = %d, want 1", got)
		}
	})
}

func TestSPKIPinnedClientRejectsModifiedTrust(t *testing.T) {
	customRoots := x509.NewCertPool()
	tests := map[string]*http.Transport{
		"InsecureSkipVerify": {TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		"custom roots":       {TLSClientConfig: &tls.Config{RootCAs: customRoots}},
		"VerifyPeerCertificate": {TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
		}},
		"VerifyConnection": {TLSClientConfig: &tls.Config{
			VerifyConnection: func(_ tls.ConnectionState) error { return nil },
		}},
		"ServerName": {TLSClientConfig: &tls.Config{ServerName: "example.com"}},
		"other TLS customization": {TLSClientConfig: &tls.Config{
			Time: time.Now,
		}},
		"custom TLS dialer": {DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}},
	}
	fingerprint := hexFingerprint(sha256.Sum256([]byte("fingerprint")))
	for name, transport := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := NewSPKIPinnedHTTPClientWithTransport(0, transport, fingerprint, false)
			if err == nil || client != nil {
				t.Fatalf("client, error = %v, %v; want nil, non-nil", client, err)
			}
		})
	}
}

func TestSPKIFingerprintsEqual(t *testing.T) {
	one := sha256.Sum256([]byte("one"))
	two := sha256.Sum256([]byte("two"))
	if !SPKIFingerprintsEqual(hexFingerprint(one), hexFingerprint(one)) {
		t.Fatal("matching fingerprints did not compare equal")
	}
	if !SPKIFingerprintsEqual(strings.ToUpper(hexFingerprint(one)), hexFingerprint(one)) {
		t.Fatal("equivalent uppercase fingerprint did not compare equal")
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
