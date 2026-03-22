package nearai

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const ctCacheTTL = time.Hour

var sctOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type ctCacheEntry struct {
	checkedAt time.Time
}

// CTChecker verifies that public-host certificates contain SCT evidence and
// caches successful checks for a short TTL.
type CTChecker struct {
	mu      sync.Mutex
	entries map[string]ctCacheEntry
}

// NewCTChecker returns a CT checker with an empty in-memory cache.
func NewCTChecker() *CTChecker {
	return &CTChecker{entries: make(map[string]ctCacheEntry)}
}

// CheckTLSState validates CT evidence for the peer leaf certificate in state.
func (c *CTChecker) CheckTLSState(host string, state *tls.ConnectionState) error {
	if isPrivateHost(host) {
		return nil
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("missing peer certificate")
	}
	return c.CheckLeafCert(host, state.PeerCertificates[0])
}

// CheckLeafCert validates CT evidence for cert and caches successful checks.
func (c *CTChecker) CheckLeafCert(host string, cert *x509.Certificate) error {
	if isPrivateHost(host) {
		return nil
	}
	if cert == nil {
		return errors.New("missing leaf certificate")
	}

	h := sha256.Sum256(cert.Raw)
	key := strings.ToLower(host) + "\x00" + hex.EncodeToString(h[:])

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[key]; ok && time.Since(e.checkedAt) <= ctCacheTTL {
		return nil
	}

	if !hasSCTExtension(cert) {
		return fmt.Errorf("leaf certificate for %s is missing SCT extension", host)
	}

	if len(c.entries) > 1024 {
		now := time.Now()
		for k, e := range c.entries {
			if now.Sub(e.checkedAt) > ctCacheTTL {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = ctCacheEntry{checkedAt: time.Now()}
	return nil
}

func hasSCTExtension(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sctOID) {
			return true
		}
	}
	for _, ext := range cert.ExtraExtensions {
		if ext.Id.Equal(sctOID) {
			return true
		}
	}
	return false
}

func isPrivateHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return true
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
	}
	return false
}
