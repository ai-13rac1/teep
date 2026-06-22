package tlsct

import "net/http"

// UserAgent is the User-Agent header sent on outbound requests to external
// APIs. It identifies teep and points to the project repository.
//
// Many upstream APIs (GitHub, Rekor, AMD KDS, NVIDIA NRAS, Intel PCS) require
// a User-Agent header and may return 403/blocked responses without one,
// causing confusing rate-limit-style failures. Centralizing the value here
// keeps every outbound fetch consistent and avoids import cycles: the tlsct
// package depends only on the standard library and certificate-transparency,
// so it can be imported by low-level packages (internal/attestation) that
// cannot depend on internal/provider.
//
// For example, GitHub requires user agents:
// https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2026-03-10#user-agent
const UserAgent = "teep/1.0 (+https://github.com/13rac1/teep)"

// SetUserAgent sets the User-Agent header on req to UserAgent. Centralized so
// every outbound HTTP fetch to external services is consistent.
func SetUserAgent(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
}
