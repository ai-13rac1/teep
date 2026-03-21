package proxy

import (
	"io"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// ProviderByName returns the named provider from the server's provider map.
// Exported for use in external tests only.
func (s *Server) ProviderByName(name string) *provider.Provider {
	return s.providers[name]
}

// ReassembleNonStream exposes reassembleNonStream for external tests.
func ReassembleNonStream(body io.Reader, session *attestation.Session) ([]byte, error) {
	return reassembleNonStream(body, session)
}

// DecryptSSEChunk exposes decryptSSEChunk for external tests.
func DecryptSSEChunk(data string, session *attestation.Session) (string, error) {
	return decryptSSEChunk(data, session)
}

// DecryptNonStreamResponse exposes decryptNonStreamResponse for external tests.
func DecryptNonStreamResponse(body []byte, session *attestation.Session) ([]byte, error) {
	return decryptNonStreamResponse(body, session)
}

// SafePrefix exposes safePrefix for external tests.
func SafePrefix(s string, n int) string {
	return safePrefix(s, n)
}

// PrepareUpstreamHeaders exposes prepareUpstreamHeaders for external tests.
func PrepareUpstreamHeaders(req *http.Request, prov *provider.Provider, session *attestation.Session) error {
	return prepareUpstreamHeaders(req, prov, session)
}

// RelayStream exposes relayStream for external tests.
func (s *Server) RelayStream(w http.ResponseWriter, body io.Reader, session *attestation.Session) {
	s.relayStream(w, body, session)
}

// RelayNonStream exposes relayNonStream for external tests.
func (s *Server) RelayNonStream(w http.ResponseWriter, body io.Reader, session *attestation.Session) {
	s.relayNonStream(w, body, session)
}

// RelayReassembledNonStream exposes relayReassembledNonStream for external tests.
func (s *Server) RelayReassembledNonStream(w http.ResponseWriter, body io.Reader, session *attestation.Session) {
	s.relayReassembledNonStream(w, body, session)
}
