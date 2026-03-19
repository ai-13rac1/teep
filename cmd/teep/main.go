// Command teep is the CLI entrypoint for the TEE proxy and attestation verifier.
//
// Usage:
//
//	teep serve                              Start the proxy server.
//	teep verify --provider NAME --model M  Fetch and verify attestation, print report.
//
// Configuration is loaded from $TEEP_CONFIG (TOML) and environment variables.
// See the config package for full documentation.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/nearai"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/proxy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "teep: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// usage prints a brief help message to stderr.
func usage() {
	fmt.Fprintf(os.Stderr, `teep — TEE proxy and attestation verifier

Usage:
  teep serve                              Start the HTTP proxy server.
  teep verify --provider NAME --model M  Fetch and print attestation report.

Environment variables:
  TEEP_CONFIG       Path to TOML config file.
  TEEP_LISTEN_ADDR  Override listen address (default 127.0.0.1:8080).
  VENICE_API_KEY    Venice AI API key.
  NEARAI_API_KEY    NEAR AI API key.
`)
}

// runServe loads config, creates the proxy, and starts listening.
// It calls log.Fatal on any startup error.
func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: teep serve\n\nStart the proxy HTTP server.\n")
	}
	fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("teep serve: load config: %v", err)
	}

	srv := proxy.New(cfg)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("teep serve: %v", err)
	}
}

// runVerify parses flags, fetches attestation from the named provider, builds
// the 20-factor report, prints it to stdout, and exits with code 1 if any
// enforced factor failed.
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: teep verify --provider NAME --model MODEL\n\nFetch and print an attestation verification report.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	providerName := fs.String("provider", "", "provider name (required, e.g. venice, nearai)")
	modelName := fs.String("model", "", "model name as known to the provider (required)")

	fs.Parse(args)

	if *providerName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: --provider is required\n")
		fs.Usage()
		os.Exit(1)
	}
	if *modelName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: --model is required\n")
		fs.Usage()
		os.Exit(1)
	}

	report := runVerification(*providerName, *modelName)
	fmt.Print(formatReport(report))

	if report.Blocked() {
		os.Exit(1)
	}
}

// runVerification loads config, builds the appropriate attester, fetches
// attestation, runs TDX and NVIDIA verification, and returns the report.
// It calls log.Fatal on unrecoverable errors.
func runVerification(providerName, modelName string) *attestation.VerificationReport {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("teep verify: load config: %v", err)
	}

	cp, ok := cfg.Providers[providerName]
	if !ok {
		log.Fatalf("teep verify: provider %q not found in config (known: %s)",
			providerName, knownProviders(cfg))
	}

	attester := newAttester(providerName, cp)
	client := config.NewAttestationClient()

	nonce := attestation.NewNonce()
	ctx := context.Background()

	raw, err := attester.FetchAttestation(ctx, modelName, nonce)
	if err != nil {
		log.Fatalf("teep verify: fetch attestation for %s/%s: %v", providerName, modelName, err)
	}

	var tdxResult *attestation.TDXVerifyResult
	if raw.IntelQuote != "" {
		tdxResult = attestation.VerifyTDXQuote(raw.IntelQuote, raw.SigningKey, nonce)
	}

	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = attestation.VerifyNVIDIAJWT(ctx, raw.NvidiaPayload, client)
	}

	return attestation.BuildReport(providerName, modelName, raw, nonce, cfg.Enforced, tdxResult, nvidiaResult)
}

// attesterInterface is a local alias so we can call FetchAttestation without
// importing the provider package (which would be a circular path for nearai/venice).
type attesterInterface interface {
	FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error)
}

// newAttester returns the appropriate Attester for the named provider.
// Calls log.Fatal for unknown provider names.
func newAttester(name string, cp *config.Provider) attesterInterface {
	switch name {
	case "venice":
		return venice.NewAttester(cp.BaseURL, cp.APIKey)
	case "nearai":
		return nearai.NewAttester(cp.BaseURL, cp.APIKey)
	default:
		log.Fatalf("teep verify: provider %q has no registered attester; supported: venice, nearai", name)
		return nil // unreachable
	}
}

// knownProviders returns the comma-separated list of provider names from cfg.
func knownProviders(cfg *config.Config) string {
	names := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// tier groups the 20 factors into human-readable sections.
type tier struct {
	name    string
	factors []attestation.FactorResult
}

// tierBoundaries defines the exclusive upper index (0-based) for each tier.
// Factors 0-6 = Tier 1, 7-14 = Tier 2, 15-19 = Tier 3.
var tierBoundaries = [3]struct {
	name string
	end  int
}{
	{"Tier 1: Core Attestation", 7},
	{"Tier 2: Binding & Crypto", 15},
	{"Tier 3: Supply Chain & Channel Integrity", 20},
}

// formatReport renders a VerificationReport as a human-readable string,
// matching the output format documented in the plan.
func formatReport(r *attestation.VerificationReport) string {
	var b strings.Builder

	header := fmt.Sprintf("Attestation Report: %s / %s", r.Provider, r.Model)
	separator := strings.Repeat("\u2550", len(header)) // U+2550 BOX DRAWINGS DOUBLE HORIZONTAL

	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(separator)
	b.WriteString("\n\n")

	start := 0
	for _, tb := range tierBoundaries {
		end := tb.end
		if end > len(r.Factors) {
			end = len(r.Factors)
		}
		if start >= len(r.Factors) {
			break
		}

		b.WriteString(tb.name)
		b.WriteString("\n")

		for _, f := range r.Factors[start:end] {
			icon := statusIcon(f.Status)
			line := fmt.Sprintf("  %s %-30s %s", icon, f.Name, f.Detail)
			if f.Enforced {
				line += "  [ENFORCED]"
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")

		start = end
	}

	fmt.Fprintf(&b, "Score: %d/%d passed, %d skipped, %d failed\n",
		r.Passed, r.Passed+r.Failed+r.Skipped, r.Skipped, r.Failed)

	return b.String()
}

// statusIcon returns the display character for a factor's status.
func statusIcon(s attestation.Status) string {
	switch s {
	case attestation.Pass:
		return "\u2713" // ✓
	case attestation.Fail:
		return "\u2717" // ✗
	default:
		return "?"
	}
}
