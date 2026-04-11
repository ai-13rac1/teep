// Package verify implements attestation verification orchestration, extracted
// from cmd/teep for testability. Run is the primary entry point.
package verify

import (
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/provider/venice"
)

// ProviderEnvVars maps provider names to their API key environment variables.
var ProviderEnvVars = map[string]string{
	"venice":     "VENICE_API_KEY",
	"neardirect": "NEARAI_API_KEY",
	"nearcloud":  "NEARAI_API_KEY",
	"nanogpt":    "NANOGPT_API_KEY",
	"phalacloud": "PHALA_API_KEY",
	"chutes":     "CHUTES_API_KEY",
}

func newAttester(name string, cp *config.Provider, offline bool) (provider.Attester, error) {
	switch name {
	case "venice":
		return venice.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "neardirect":
		return neardirect.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "nearcloud":
		return nearcloud.NewAttester(cp.APIKey, offline), nil
	case "nanogpt":
		return nanogpt.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "phalacloud":
		return phalacloud.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "chutes":
		return chutes.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, neardirect, nearcloud, nanogpt, phalacloud, chutes)", name)
	}
}

func newReportDataVerifier(name string) provider.ReportDataVerifier {
	switch name {
	case "venice":
		return venice.ReportDataVerifier{}
	case "neardirect", "nearcloud":
		return neardirect.ReportDataVerifier{}
	case "nanogpt":
		// NanoGPT uses the same dstack REPORTDATA binding as Venice.
		return venice.ReportDataVerifier{}
	case "phalacloud":
		return multi.Verifier{
			Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
				attestation.FormatDstack: venice.ReportDataVerifier{},
			},
		}
	case "chutes":
		return chutes.ReportDataVerifier{}
	default:
		return nil
	}
}

func supplyChainPolicy(name string) *attestation.SupplyChainPolicy {
	switch name {
	case "venice":
		return venice.SupplyChainPolicy()
	case "neardirect":
		return neardirect.SupplyChainPolicy()
	case "nearcloud":
		return nearcloud.SupplyChainPolicy()
	case "nanogpt":
		return nanogpt.SupplyChainPolicy()
	case "phalacloud":
		return nil // no supply chain policy yet
	case "chutes":
		return nil // cosign+IMA model, no docker-compose
	default:
		return nil
	}
}

// e2eeEnabledByDefault reports whether the named provider has E2EE enabled
// by default in config.go's applyAPIKeyEnv.
func e2eeEnabledByDefault(name string) bool {
	switch name {
	case "venice", "nearcloud", "neardirect", "chutes":
		return true
	default:
		return false
	}
}

// chatPathForProvider returns the upstream chat completions path for the named provider.
func chatPathForProvider(name string) string {
	switch name {
	case "venice":
		return "/api/v1/chat/completions"
	case "nearcloud", "neardirect", "nanogpt":
		return "/v1/chat/completions"
	case "chutes":
		return "/v1/chat/completions"
	default:
		return ""
	}
}
