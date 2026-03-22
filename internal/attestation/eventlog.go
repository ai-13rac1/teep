package attestation

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// ReplayEventLog replays event log entries to recompute the four RTMR values.
// Each entry extends the RTMR at its IMR index: RTMR_new = SHA384(RTMR_old || digest).
// RTMRs start as 48 zero bytes.
//
// Based on github.com/Dstack-TEE/dstack/sdk/go/dstack (Apache-2.0).
func ReplayEventLog(entries []EventLogEntry) ([4][48]byte, error) {
	var rtmrs [4][48]byte // zero-initialized

	for i, e := range entries {
		if e.IMR < 0 || e.IMR > 3 {
			return rtmrs, fmt.Errorf("event %d: IMR index %d out of range [0,3]", i, e.IMR)
		}

		digest, err := hex.DecodeString(e.Digest)
		if err != nil {
			return rtmrs, fmt.Errorf("event %d: invalid hex digest: %w", i, err)
		}

		if len(digest) < 48 {
			padded := make([]byte, 48)
			copy(padded, digest)
			digest = padded
		}

		h := sha512.New384()
		h.Write(rtmrs[e.IMR][:])
		h.Write(digest)
		copy(rtmrs[e.IMR][:], h.Sum(nil))
	}

	return rtmrs, nil
}
