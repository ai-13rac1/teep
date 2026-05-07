package tlsct

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// loggingTransport logs every outgoing HTTP request at DEBUG level.
// When timeout is set, it is included in error messages so operators can see
// the configured limit without reading source code.
type loggingTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

// WrapLogging wraps a transport with DEBUG-level request/response logging.
// Logs method, host, path, status, content-type, content-length, and elapsed
// time. Query parameters are omitted for nonce safety.
func WrapLogging(base http.RoundTripper, timeout ...time.Duration) http.RoundTripper {
	var t time.Duration
	if len(timeout) > 0 {
		t = timeout[0]
	}
	return &loggingTransport{base: base, timeout: t}
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start)

	host := req.URL.Host
	path := req.URL.Path

	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		attrs := []any{
			"method", req.Method,
			"host", host,
			"path", path,
			"elapsed", elapsed,
			"err", err,
		}
		if t.timeout > 0 {
			attrs = append(attrs, "timeout", t.timeout)
		}
		slog.DebugContext(req.Context(), "http request failed", attrs...)
		if t.timeout > 0 {
			return nil, fmt.Errorf("%s %s%s (timeout %v): %w", req.Method, host, path, t.timeout, err)
		}
		return nil, err
	}

	slog.DebugContext(req.Context(), "http request",
		"method", req.Method,
		"host", host,
		"path", path,
		"status", resp.StatusCode,
		"content_type", resp.Header.Get("Content-Type"),
		"content_length", resp.ContentLength,
		"elapsed", elapsed,
	)
	return resp, nil
}

// countingTransport wraps a transport to count requests and errors.
type countingTransport struct {
	base      http.RoundTripper
	onRequest func()
	onError   func()
}

// WrapCounting wraps a transport to call onRequest before each request and
// onError on transport failures. Nil callbacks are no-ops.
func WrapCounting(base http.RoundTripper, onRequest, onError func()) http.RoundTripper {
	return &countingTransport{base: base, onRequest: onRequest, onError: onError}
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.onRequest != nil {
		t.onRequest()
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if t.onError != nil {
			t.onError()
		}
		return nil, err
	}
	return resp, nil
}
