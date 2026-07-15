package testtls

import (
	"slices"
	"strings"
	"testing"
)

func TestChildEnvironmentRemovesProxyConfiguration(t *testing.T) {
	proxyKeys := []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"no_proxy",
		"all_proxy",
	}
	for _, key := range proxyKeys {
		t.Setenv(key, "http://proxy.invalid")
	}
	t.Setenv("TEEP_TESTTLS_PRESERVED", "preserved")

	env := childEnvironment()
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if isProxyEnvironmentKey(key) {
			t.Fatalf("child environment retained proxy variable %q", key)
		}
	}
	if !slices.Contains(env, "TEEP_TESTTLS_PRESERVED=preserved") {
		t.Fatal("child environment dropped unrelated variable")
	}
}
