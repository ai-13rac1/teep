package provider_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func TestProvider_MapModel_Hit(t *testing.T) {
	p := &provider.Provider{
		ModelMap: map[string]string{
			"gpt-4": "e2ee-qwen3-5-122b-a10b",
		},
	}
	got := p.MapModel("gpt-4")
	if got != "e2ee-qwen3-5-122b-a10b" {
		t.Errorf("MapModel(%q) = %q, want %q", "gpt-4", got, "e2ee-qwen3-5-122b-a10b")
	}
}

func TestProvider_MapModel_Miss(t *testing.T) {
	p := &provider.Provider{
		ModelMap: map[string]string{
			"gpt-4": "e2ee-qwen3-5-122b-a10b",
		},
	}
	got := p.MapModel("gpt-3.5-turbo")
	if got != "gpt-3.5-turbo" {
		t.Errorf("MapModel(%q) = %q, want passthrough %q", "gpt-3.5-turbo", got, "gpt-3.5-turbo")
	}
}

func TestProvider_MapModel_EmptyMap(t *testing.T) {
	p := &provider.Provider{
		ModelMap: make(map[string]string),
	}
	got := p.MapModel("claude-3")
	if got != "claude-3" {
		t.Errorf("MapModel(%q) = %q, want passthrough %q", "claude-3", got, "claude-3")
	}
}

func TestProvider_MapModel_NilMap(t *testing.T) {
	p := &provider.Provider{}
	got := p.MapModel("some-model")
	if got != "some-model" {
		t.Errorf("MapModel(%q) = %q, want passthrough %q", "some-model", got, "some-model")
	}
}

func TestProvider_Fields(t *testing.T) {
	p := &provider.Provider{
		Name:    "venice",
		BaseURL: "https://api.venice.ai",
		APIKey:  "secret",
		E2EE:    true,
		ModelMap: map[string]string{
			"gpt-4": "e2ee-qwen3-5-122b-a10b",
		},
	}

	if p.Name != "venice" {
		t.Errorf("Name = %q, want %q", p.Name, "venice")
	}
	if p.BaseURL != "https://api.venice.ai" {
		t.Errorf("BaseURL = %q, want %q", p.BaseURL, "https://api.venice.ai")
	}
	if !p.E2EE {
		t.Error("E2EE = false, want true")
	}
	// Attester and Preparer are nil when not set — zero value is acceptable.
	if p.Attester != nil {
		t.Error("Attester should be nil by default")
	}
	if p.Preparer != nil {
		t.Error("Preparer should be nil by default")
	}
}
