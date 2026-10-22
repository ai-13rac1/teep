package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// trustedRoot gets the Sigstore trusted root for one verification.
func (rc *RekorClient) trustedRoot(ctx context.Context) (root.TrustedMaterial, error) {
	material, err := rc.roots.TrustedRoot(ctx)
	if err != nil {
		return nil, fmt.Errorf("get Sigstore trusted root: %w", err)
	}
	if material == nil {
		return nil, errors.New("get Sigstore trusted root: source returned no material")
	}
	return material, nil
}

// rekorEntryProvenance builds the provenance of one parsed Rekor entry. It
// verifies the SET and the inclusion proof. For a certificate verifier whose
// SET verifies, it then verifies the certificate as a Fulcio certificate at
// the integrated time and copies the Fulcio identity. A certificate that
// does not verify has FulcioErr set and no identity. An error means the
// verifier certificate does not parse, and the caller rejects the entry.
func (rc *RekorClient) rekorEntryProvenance(
	ctx context.Context,
	digest, uuid string,
	entry *rekorEntry,
	body *rekorDSSEBody,
	material root.TrustedMaterial,
) (RekorProvenance, error) {
	p := RekorProvenance{Digest: digest, IntegratedTime: entry.IntegratedTime}
	if body.Verifier.Type == "PUBLIC KEY" {
		h := sha256.Sum256(body.Verifier.Bytes)
		p.KeyFingerprint = hex.EncodeToString(h[:])
		rc.verifyRekorEntry(entry, &p)
		return p, nil
	}
	cert, err := x509.ParseCertificate(body.Verifier.Bytes)
	if err != nil {
		return RekorProvenance{}, rekorEntryRejectedError{err: fmt.Errorf("parse verifier certificate: %w", err)}
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	p.KeyFingerprint = hex.EncodeToString(h[:])
	rc.verifyRekorEntry(entry, &p)
	if !p.SETVerified {
		// Without a verified SET the integrated time is not authenticated.
		p.FulcioErr = errors.New("entry SET not verified; certificate chain not checked")
	} else if summary, err := verifyFulcioCertificate(cert, time.Unix(entry.IntegratedTime, 0), material); err != nil {
		p.FulcioErr = err
	} else {
		p.FulcioVerified = true
		setFulcioIdentity(&p, &summary)
	}
	if p.FulcioErr != nil {
		// The caller warns once per digest; see fetchRekorProvenance.
		slog.DebugContext(ctx, "Rekor entry certificate not verified as a Fulcio certificate",
			"digest", digest, "uuid", truncate(uuid, 100), "reason", p.FulcioErr.Error())
	}
	return p, nil
}

// verifyFulcioCertificate checks that leaf chains to a Fulcio certificate
// authority in the Sigstore trusted root at the integrated time, with the
// CA validity window, the leaf validity and the code-signing key usage
// checked at that time; that it holds one valid SCT from a CT log in the
// trusted root; and it returns the certificate identity.
func verifyFulcioCertificate(leaf *x509.Certificate, integrated time.Time, material root.TrustedMaterial) (certificate.Summary, error) {
	chains, err := sigstoreverify.VerifyLeafCertificate(integrated, leaf, material)
	if err != nil {
		return certificate.Summary{}, fmt.Errorf("certificate does not chain to a Fulcio CA in the Sigstore trusted root at integrated time %s: %w",
			integrated.UTC().Format(time.RFC3339), err)
	}
	if err := sigstoreverify.VerifySignedCertificateTimestamp(chains, 1, material); err != nil {
		return certificate.Summary{}, fmt.Errorf("certificate SCT not verified: %w", err)
	}
	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return certificate.Summary{}, fmt.Errorf("certificate identity: %w", err)
	}
	return summary, nil
}

// setFulcioIdentity copies the chain-verified certificate identity to p.
func setFulcioIdentity(p *RekorProvenance, s *certificate.Summary) {
	p.SubjectURI = s.SubjectAlternativeName
	p.OIDCIssuer = s.Issuer
	p.Trigger = s.GithubWorkflowTrigger
	p.SourceCommit = s.GithubWorkflowSHA
	p.SourceRepo = s.GithubWorkflowRepository
	p.SourceRef = s.GithubWorkflowRef
	p.RunnerEnv = s.RunnerEnvironment
	p.SourceRepoURL = s.SourceRepositoryURI
	p.RunURL = s.RunInvocationURI
}
