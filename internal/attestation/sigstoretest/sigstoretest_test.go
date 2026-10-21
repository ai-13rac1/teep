package sigstoretest

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestTrustedRootPassesFileToConstructor(t *testing.T) {
	got := TrustedRoot(func(data []byte) ([]byte, error) { return data, nil })
	if !bytes.Contains(got, []byte("application/vnd.dev.sigstore.trustedroot+json")) {
		t.Fatalf("constructor got %d bytes without the trusted root media type", len(got))
	}
}

func TestTrustedRootPanicsOnConstructorError(t *testing.T) {
	defer func() {
		r := recover()
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "load Sigstore trusted root: bad root") {
			t.Fatalf("recover() = %v, want a load panic", r)
		}
	}()
	TrustedRoot(func([]byte) (int, error) { return 0, errors.New("bad root") })
	t.Fatal("TrustedRoot returned after a constructor error")
}
