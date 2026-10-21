package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/13rac1/teep/internal/attestation/sigstoretest"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestTrustedRootFetcherSingleAttempt runs in the test process, with the
// test server's own client, so the coverage profile records the fetcher. The
// system-WebPKI variants run in child processes (SEE:
// TestTrustedRootFetcherRejectsRedirectWithoutRetry).
func TestTrustedRootFetcherSingleAttempt(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/ok" {
			_, _ = w.Write([]byte("metadata"))
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	f := newTrustedRootFetcher(t.Context(), ts.Client())
	if _, err := f.DownloadFile(ts.URL+"/fail", 1024, time.Second); err == nil {
		t.Fatal("trusted root fetcher accepted HTTP 503")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("got %d requests after one failure, want one", got)
	}
	data, err := f.DownloadFile(ts.URL+"/ok", 1024, time.Second)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(data) != "metadata" {
		t.Fatalf("download = %q", data)
	}
}

// TestTUFTrustedRootSourceCanceledContext checks that the production source
// fails when the verification context ends, sends no request, and returns
// no material. HOME is a temporary directory, so a cache write cannot reach
// the real home directory.
func TestTUFTrustedRootSourceCanceledContext(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	material, err := NewTUFTrustedRootSource().TrustedRoot(ctx)
	if err == nil {
		t.Fatal("TUF trusted root fetch succeeded with a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if material != nil {
		t.Fatalf("got material %v with error", material)
	}
}

// failingTUFFetcher counts download requests and fails each one.
type failingTUFFetcher struct{ requests atomic.Int32 }

func (f *failingTUFFetcher) DownloadFile(string, int64, time.Duration) ([]byte, error) {
	f.requests.Add(1)
	return nil, errors.New("fetch disabled in test")
}

// TestTUFTrustedRootFetchWritesNoCache checks that a TUF update writes no
// file below the home directory. Without a disabled local cache, the TUF
// client writes root.json there before its first request.
func TestTUFTrustedRootFetchWritesNoCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := &failingTUFFetcher{}
	material, err := fetchTUFTrustedRoot(f)
	if err == nil || material != nil {
		t.Fatalf("TUF fetch succeeded with a failing fetcher: %v", material)
	}
	if f.requests.Load() == 0 {
		t.Fatal("TUF fetch sent no request through the fetcher")
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("TUF fetch wrote %d entries below HOME, first %q", len(entries), entries[0].Name())
	}
}

func TestStaticTrustedRootSourceRejectsIncompleteRoot(t *testing.T) {
	data := sigstoretest.TrustedRootJSON()
	for _, tc := range []struct {
		remove []string
		want   string
	}{
		{[]string{"certificateAuthorities"}, "no Fulcio certificate authority"},
		{[]string{"ctlogs"}, "no certificate transparency log"},
		{[]string{"tlogs"}, "no Rekor log"},
	} {
		t.Run(strings.Join(tc.remove, ","), func(t *testing.T) {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			for _, key := range tc.remove {
				delete(doc, key)
			}
			incomplete, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			roots, err := NewStaticTrustedRootSource(incomplete)
			if err == nil || roots != nil {
				t.Fatalf("static source accepted a root without %v", tc.remove)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
