package attestation

import "maps"

// InapplicableFactors is a map from factor name to the reason it does not
// apply. Factors absent from the map are assumed applicable.
type InapplicableFactors map[string]string

// defaultInapplicable contains factors that are N/A for most providers
// (venice, nearcloud, neardirect, nanogpt, phalacloud). Provider-specific
// implementations (tinfoil, chutes) supply their own maps. Unexported to
// prevent accidental mutation by importers; use DefaultInapplicableFactors
// to obtain a defensive copy.
var defaultInapplicable = InapplicableFactors{
	"sigstore_code_verified": "Sigstore code verification is Tinfoil-specific",
	"nvswitch_binding":       "NVSwitch fabric verification is Tinfoil-specific",
}

// DefaultInapplicableFactors returns a defensive copy of the default
// inapplicable factors map. Callers cannot mutate the underlying package-level
// map, satisfying the repo's "no exported mutable package-level vars" guidance.
func DefaultInapplicableFactors() InapplicableFactors {
	out := make(InapplicableFactors, len(defaultInapplicable))
	maps.Copy(out, defaultInapplicable)
	return out
}
