// Package sigstoretest loads the checked-in Sigstore trusted root,
// internal/attestation/testdata/sigstore_trusted_root.json, for tests. Tests
// that use it send no TUF requests.
package sigstoretest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// TrustedRoot reads the checked-in trusted root and gives it to newSource,
// normally attestation.NewStaticTrustedRootSource. The attestation package
// tests use this function too, so this package does not import attestation.
// It panics when the file does not read or newSource returns an error.
func TrustedRoot[S any](newSource func([]byte) (S, error)) S {
	source, err := newSource(TrustedRootJSON())
	if err != nil {
		panic(fmt.Sprintf("sigstoretest: load Sigstore trusted root: %v", err))
	}
	return source
}

// TrustedRootJSON returns the bytes of the checked-in trusted root. It
// panics when the file does not read.
func TrustedRootJSON() []byte {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "testdata", "sigstore_trusted_root.json")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		panic(fmt.Sprintf("sigstoretest: read Sigstore trusted root: %v", err))
	}
	return data
}
