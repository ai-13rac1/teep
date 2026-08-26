package attestation

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

func TestReplayEventLog_Empty(t *testing.T) {
	rtmrs, err := ReplayEventLog(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, r := range rtmrs {
		for _, b := range r {
			if b != 0 {
				t.Errorf("RTMR[%d] should be all zeros, got %s", i, hex.EncodeToString(r[:]))
				break
			}
		}
	}
}

func TestReplayEventLog_SingleExtend(t *testing.T) {
	digest := make([]byte, 48)
	digest[0] = 0x42
	digestHex := hex.EncodeToString(digest)

	entries := []EventLogEntry{
		{IMR: 0, Digest: digestHex},
	}

	rtmrs, err := ReplayEventLog(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: SHA384(48 zero bytes || digest)
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(digest)
	expected := h.Sum(nil)

	if hex.EncodeToString(rtmrs[0][:]) != hex.EncodeToString(expected) {
		t.Errorf("RTMR[0] mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(rtmrs[0][:]), hex.EncodeToString(expected))
	}

	// Other RTMRs should still be zero.
	for i := 1; i <= 3; i++ {
		for _, b := range rtmrs[i] {
			if b != 0 {
				t.Errorf("RTMR[%d] should be all zeros", i)
				break
			}
		}
	}
}

func TestReplayEventLog_MultipleExtends(t *testing.T) {
	d1 := make([]byte, 48)
	d1[0] = 0x01
	d2 := make([]byte, 48)
	d2[0] = 0x02

	entries := []EventLogEntry{
		{IMR: 1, Digest: hex.EncodeToString(d1)},
		{IMR: 1, Digest: hex.EncodeToString(d2)},
	}

	rtmrs, err := ReplayEventLog(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First extend: SHA384(zeros || d1)
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(d1)
	after1 := h.Sum(nil)

	// Second extend: SHA384(after1 || d2)
	h = sha512.New384()
	h.Write(after1)
	h.Write(d2)
	expected := h.Sum(nil)

	if hex.EncodeToString(rtmrs[1][:]) != hex.EncodeToString(expected) {
		t.Errorf("RTMR[1] mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(rtmrs[1][:]), hex.EncodeToString(expected))
	}
}

func TestReplayEventLog_InvalidIMR(t *testing.T) {
	entries := []EventLogEntry{
		{IMR: 5, Digest: hex.EncodeToString(make([]byte, 48))},
	}
	_, err := ReplayEventLog(entries)
	if err == nil {
		t.Fatal("expected error for IMR=5")
	}
	t.Logf("got expected error: %v", err)
}

func TestReplayEventLog_InvalidHex(t *testing.T) {
	entries := []EventLogEntry{
		{IMR: 0, Digest: "not-hex"},
	}
	_, err := ReplayEventLog(entries)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	t.Logf("got expected error: %v", err)
}

func TestReplayEventLog_ShortDigestPadded(t *testing.T) {
	// A 32-byte digest should be zero-padded to 48 bytes.
	short := make([]byte, 32)
	short[0] = 0xFF

	entries := []EventLogEntry{
		{IMR: 2, Digest: hex.EncodeToString(short)},
	}

	rtmrs, err := ReplayEventLog(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	padded := make([]byte, 48)
	copy(padded, short)

	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(padded)
	expected := h.Sum(nil)

	if hex.EncodeToString(rtmrs[2][:]) != hex.EncodeToString(expected) {
		t.Errorf("RTMR[2] mismatch with short digest:\n  got  %s\n  want %s",
			hex.EncodeToString(rtmrs[2][:]), hex.EncodeToString(expected))
	}
}

// TestReplayEventLog_RuntimeEventDigestRecomputed: a dstack runtime event's
// declared digest is not trusted — the replay recomputes it from
// (event_type, event, event_payload), so tampering with those fields fails
// the replay even though the declared digest is unchanged. This is what
// authenticates the app-id an ACI/1 custody chain reads from the log.
func TestReplayEventLog_RuntimeEventDigestRecomputed(t *testing.T) {
	// A genuine runtime event: digest = SHA384(u32le(type) ":" event ":" payload).
	typeBytes := []byte{0x01, 0x00, 0x00, 0x08} // 0x08000001 little-endian
	h := sha512.New384()
	h.Write(typeBytes)
	h.Write([]byte(":app-id:"))
	h.Write([]byte{0x11, 0x22, 0x33})
	good := EventLogEntry{
		IMR:          3,
		EventType:    0x08000001,
		Event:        "app-id",
		EventPayload: "112233",
		Digest:       hex.EncodeToString(h.Sum(nil)),
	}
	if _, err := ReplayEventLog([]EventLogEntry{good}); err != nil {
		t.Fatalf("genuine runtime event should replay: %v", err)
	}

	// Same declared digest, attacker-changed payload → mismatch, replay fails.
	tampered := good
	tampered.EventPayload = "445566"
	if _, err := ReplayEventLog([]EventLogEntry{tampered}); err == nil {
		t.Error("tampered runtime event_payload with an unchanged digest replayed without error")
	}

	// A non-runtime event keeps trusting its declared digest.
	nonRuntime := EventLogEntry{IMR: 0, EventType: 0x00000001, Digest: "aabb"}
	if _, err := ReplayEventLog([]EventLogEntry{nonRuntime}); err != nil {
		t.Errorf("non-runtime event should use its declared digest: %v", err)
	}
}
