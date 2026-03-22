package attestation

import "github.com/google/go-tdx-guest/verify/trust"

func overrideSigstoreBase(base string) { sigstoreSearchBase = base }
func restoreSigstoreBase(base string)  { sigstoreSearchBase = base }

func overrideNRASURL(url string) { nrasAttestURL = url }
func restoreNRASURL(url string)  { nrasAttestURL = url }

func overrideJWKSURL(url string) { nvidiaJWKSURL = url }
func restoreJWKSURL(url string)  { nvidiaJWKSURL = url }

func overrideRekorBase(base string) { rekorAPIBase = base }
func restoreRekorBase(base string)  { rekorAPIBase = base }

func overrideTDXGetter(g trust.HTTPSGetter) { tdxCollateralGetter = g }
func restoreTDXGetter()                     { tdxCollateralGetter = nil }
