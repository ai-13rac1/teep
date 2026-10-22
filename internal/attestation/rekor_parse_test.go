package attestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const parseTestUUID = "108e9186e8c5677a4de13a2a87d95ef994976acbf59a16ec2ffd616b66ddbab6477bafc7a6317ddf"

// mockEntryObject returns a well-formed entry object for an entries response.
func mockEntryObject(bodyB64 string) map[string]any {
	return map[string]any{
		"body":           bodyB64,
		"integratedTime": 1700000000,
		"logID":          "c0d23d6ad406973f9559f3ba2d1ca5f0e0c7f5e8b0c5a2e6d3b1e4f7a8b9c0d1",
		"logIndex":       42,
		"verification": map[string]any{
			"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("sig")),
			"inclusionProof": map[string]any{
				"checkpoint": "checkpoint",
				"hashes":     []string{"abcd"},
				"logIndex":   42,
				"rootHash":   "abcd",
				"treeSize":   100,
			},
		},
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseRekorUUIDs(t *testing.T) {
	limit := make([]string, maxRekorUUIDs)
	for i := range limit {
		limit[i] = fmt.Sprintf("%080x", i)
	}
	over := append(append([]string{}, limit...), "extra")
	for _, tc := range []struct {
		name string
		data string
		want int
		err  string
	}{
		{name: "two", data: `["a","b"]`, want: 2},
		{name: "empty", data: `[]`, want: 0},
		{name: "null", data: `null`, want: 0},
		{name: "limit", data: string(mustJSON(t, limit)), want: maxRekorUUIDs},
		{name: "over limit", data: string(mustJSON(t, over)), err: "more than the limit"},
		{name: "empty UUID", data: `["a",""]`, err: "empty UUID"},
		{name: "object", data: `{"uuid":"a"}`, err: "decode UUIDs"},
		{name: "numbers", data: `[1]`, err: "decode UUIDs"},
		{name: "not JSON", data: `not json`, err: "decode UUIDs"},
		{name: "trailing member", data: `["a"],"extra":1`, err: "decode UUIDs"},
		{name: "second value member", data: `["a"],"value":["b"]`, err: "decode UUIDs"},
		{name: "no value", data: ``, err: "decode UUIDs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uuids, err := parseRekorUUIDs([]byte(tc.data))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				if uuids != nil {
					t.Fatalf("got UUIDs %v with error", uuids)
				}
				return
			}
			if err != nil || len(uuids) != tc.want {
				t.Fatalf("uuids=%d err=%v, want %d UUIDs", len(uuids), err, tc.want)
			}
		})
	}
}

func TestParseRekorEntryResponse(t *testing.T) {
	body := buildMockDSSEBody(realPublicKeyPEM)
	valid := mockEntryObject(body)
	entry, unknown, err := parseRekorEntryResponse(mustJSON(t, []map[string]any{{parseTestUUID: valid}}), parseTestUUID)
	if err != nil || len(unknown) != 0 {
		t.Fatalf("valid response: unknown=%v err=%v", unknown, err)
	}
	if entry.Body != body || entry.IntegratedTime != 1700000000 || entry.LogIndex != 42 ||
		entry.Verification.InclusionProof.TreeSize != 100 || len(entry.Verification.InclusionProof.Hashes) != 1 {
		t.Fatalf("entry = %+v", entry)
	}

	withAttestation := mockEntryObject(body)
	withAttestation["attestation"] = map[string]any{"data": "e30="}
	if _, unknown, err := parseRekorEntryResponse(mustJSON(t, []map[string]any{{parseTestUUID: withAttestation}}), parseTestUUID); err != nil || len(unknown) != 0 {
		t.Fatalf("entry with attestation: unknown=%v err=%v", unknown, err)
	}

	change := func(f func(map[string]any)) []byte {
		e := mockEntryObject(body)
		f(e)
		return mustJSON(t, []map[string]any{{parseTestUUID: e}})
	}
	verification := func(e map[string]any) map[string]any { return e["verification"].(map[string]any) }
	proof := func(e map[string]any) map[string]any { return verification(e)["inclusionProof"].(map[string]any) }

	for _, tc := range []struct {
		name    string
		data    []byte
		unknown string
		err     string
	}{
		{name: "unknown entry field", data: change(func(e map[string]any) { e["extra"] = 1 }), unknown: "entry.extra"},
		{name: "unknown verification field", data: change(func(e map[string]any) { verification(e)["extra"] = 1 }), unknown: "entry.verification.extra"},
		{name: "unknown proof field", data: change(func(e map[string]any) { proof(e)["extra"] = 1 }), unknown: "entry.verification.inclusionProof.extra"},
		{name: "differently cased field", data: change(func(e map[string]any) { e["Body"] = "x" }), unknown: "entry.Body"},
		{name: "missing verification", data: change(func(e map[string]any) { delete(e, "verification") }), err: "missing required fields: verification"},
		{name: "missing integrated time", data: change(func(e map[string]any) { delete(e, "integratedTime") }), err: "missing required fields: integratedTime"},
		{name: "missing proof", data: change(func(e map[string]any) { delete(verification(e), "inclusionProof") }), err: "missing required fields: inclusionProof"},
		{name: "missing tree size", data: change(func(e map[string]any) { delete(proof(e), "treeSize") }), err: "missing required fields: treeSize"},
		{name: "null verification", data: change(func(e map[string]any) { e["verification"] = nil }), err: "null is not permitted"},
		{name: "string log index", data: change(func(e map[string]any) { e["logIndex"] = "42" }), err: "entry"},
		{name: "empty body", data: change(func(e map[string]any) { e["body"] = "" }), err: "entry.body is empty"},
		{name: "zero integrated time", data: change(func(e map[string]any) { e["integratedTime"] = 0 }), err: "integratedTime is not positive"},
		{name: "negative log index", data: change(func(e map[string]any) { e["logIndex"] = -1 }), err: "logIndex is negative"},
		{name: "empty log ID", data: change(func(e map[string]any) { e["logID"] = "" }), err: "logID is empty"},
		{name: "no entries", data: []byte(`[]`), err: "holds 0 entries"},
		{name: "two entries", data: mustJSON(t, []map[string]any{{parseTestUUID: valid}, {parseTestUUID + "0": valid}}), err: "holds 2 entries"},
		{name: "two keys", data: mustJSON(t, []map[string]any{{parseTestUUID: valid, "other": valid}}), err: "holds 2 entries"},
		{name: "other UUID", data: mustJSON(t, []map[string]any{{"other": valid}}), err: "different UUID"},
		{name: "duplicate field", data: []byte(`[{"` + parseTestUUID + `":{"body":"a","body":"b"}}]`), err: "duplicate"},
		{name: "object", data: []byte(`{}`), err: "decode entries"},
		{name: "trailing member", data: []byte(`[],"extra":1`), err: "decode entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, unknown, err := parseRekorEntryResponse(tc.data, parseTestUUID)
			if entry != nil {
				t.Fatalf("parser returned entry %+v", entry)
			}
			if tc.unknown != "" {
				if err != nil || len(unknown) != 1 || unknown[0] != tc.unknown {
					t.Fatalf("unknown=%v err=%v, want unknown %q", unknown, err, tc.unknown)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

// mockBody returns a well-formed dsse body as a map for changes.
func mockBody(verifierPEM string) map[string]any {
	return map[string]any{"apiVersion": "0.0.1", "kind": "dsse", "spec": mockDSSESpec(verifierPEM)}
}

func mockBodyJSON(t *testing.T, change func(body, spec, sig map[string]any)) []byte {
	t.Helper()
	body := mockBody(realFulcioCertPEM)
	spec := body["spec"].(map[string]any)
	sig := spec["signatures"].([]map[string]any)[0]
	if change != nil {
		change(body, spec, sig)
	}
	return mustJSON(t, body)
}

func TestParseRekorBodyAccepts(t *testing.T) {
	for name, verifier := range map[string]string{"certificate": realFulcioCertPEM, "public key": realPublicKeyPEM} {
		t.Run(name, func(t *testing.T) {
			raw := mustJSON(t, mockBody(verifier))
			body, unknown, err := parseRekorBody(raw)
			if err != nil || len(unknown) != 0 {
				t.Fatalf("unknown=%v err=%v", unknown, err)
			}
			if body.EnvelopeHash != mockEnvelopeHash || body.PayloadHash != mockPayloadHash ||
				string(body.Signature) != "mock-signature" || string(body.VerifierPEM) != verifier {
				t.Fatalf("body = %+v", body)
			}
			if (name == "certificate") != (body.Verifier.Type == "CERTIFICATE") {
				t.Fatalf("verifier type = %q", body.Verifier.Type)
			}
		})
	}
}

func TestParseRekorBodyRejects(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	privateKeyPEM := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"
	for _, tc := range []struct {
		name    string
		change  func(body, spec, sig map[string]any)
		unknown string
		err     string
	}{
		{name: "unknown body field", change: func(b, _, _ map[string]any) { b["extra"] = 1 }, unknown: "body.extra"},
		{name: "unknown spec field", change: func(_, s, _ map[string]any) { s["content"] = map[string]any{} }, unknown: "body.spec.content"},
		{name: "unknown signature field", change: func(_, _, g map[string]any) { g["keyid"] = "k" }, unknown: "body.spec.signatures[0].keyid"},
		{name: "unknown hash field", change: func(_, s, _ map[string]any) { s["payloadHash"].(map[string]any)["extra"] = 1 }, unknown: "body.spec.payloadHash.extra"},
		{name: "intoto kind", change: func(b, _, _ map[string]any) { b["kind"] = "intoto" }, err: `entry kind "intoto" is not supported, want "dsse"`},
		{name: "hashedrekord kind", change: func(b, _, _ map[string]any) { b["kind"] = "hashedrekord" }, err: `entry kind "hashedrekord"`},
		{name: "API version", change: func(b, _, _ map[string]any) { b["apiVersion"] = "0.0.2" }, err: `dsse apiVersion "0.0.2"`},
		{name: "missing kind", change: func(b, _, _ map[string]any) { delete(b, "kind") }, err: "missing required fields: kind"},
		{name: "null spec", change: func(b, _, _ map[string]any) { b["spec"] = nil }, err: "null is not permitted"},
		{name: "zero signatures", change: func(_, s, _ map[string]any) { s["signatures"] = []any{} }, err: "0 signatures, want one"},
		{name: "two signatures", change: func(_, s, g map[string]any) { s["signatures"] = []any{g, g} }, err: "2 signatures, want one"},
		{name: "missing envelope hash", change: func(_, s, _ map[string]any) { delete(s, "envelopeHash") }, err: "missing required fields: envelopeHash"},
		{name: "missing payload hash", change: func(_, s, _ map[string]any) { delete(s, "payloadHash") }, err: "missing required fields: payloadHash"},
		{name: "hash algorithm", change: func(_, s, _ map[string]any) { s["envelopeHash"].(map[string]any)["algorithm"] = "sha512" }, err: "envelopeHash.algorithm"},
		{name: "short hash", change: func(_, s, _ map[string]any) { s["payloadHash"].(map[string]any)["value"] = "abcd" }, err: "payloadHash.value"},
		{name: "uppercase hash", change: func(_, s, _ map[string]any) {
			s["payloadHash"].(map[string]any)["value"] = strings.ToUpper(strings.Repeat("ab", 32))
		}, err: "payloadHash.value"},
		{name: "non-hex hash", change: func(_, s, _ map[string]any) { s["envelopeHash"].(map[string]any)["value"] = strings.Repeat("zz", 32) }, err: "envelopeHash.value"},
		{name: "hash missing value", change: func(_, s, _ map[string]any) { delete(s["envelopeHash"].(map[string]any), "value") }, err: "missing required fields: value"},
		{name: "empty signature", change: func(_, _, g map[string]any) { g["signature"] = "" }, err: "signature is empty or not base64"},
		{name: "signature not base64", change: func(_, _, g map[string]any) { g["signature"] = "!!" }, err: "signature is empty or not base64"},
		{name: "empty verifier", change: func(_, _, g map[string]any) { g["verifier"] = "" }, err: "verifier is empty"},
		{name: "verifier not base64", change: func(_, _, g map[string]any) { g["verifier"] = realPublicKeyPEM }, err: "decode verifier base64"},
		{name: "verifier not PEM", change: func(_, _, g map[string]any) { g["verifier"] = b64("not a PEM block") }, err: "no PEM block"},
		{name: "verifier private key", change: func(_, _, g map[string]any) { g["verifier"] = b64(privateKeyPEM) }, err: "neither CERTIFICATE nor PUBLIC KEY"},
		{name: "verifier trailing data", change: func(_, _, g map[string]any) { g["verifier"] = b64(realPublicKeyPEM + "\n" + realFulcioCertPEM) }, err: "data after the PEM block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, unknown, err := parseRekorBody(mockBodyJSON(t, tc.change))
			if body != nil {
				t.Fatalf("parser returned body %+v", body)
			}
			if tc.unknown != "" {
				if err != nil || len(unknown) != 1 || unknown[0] != tc.unknown {
					t.Fatalf("unknown=%v err=%v, want unknown %q", unknown, err, tc.unknown)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
	if _, _, err := parseRekorBody([]byte(`{"kind":"dsse","kind":"dsse","apiVersion":"0.0.1","spec":{}}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate kind: err = %v", err)
	}
	if _, _, err := parseRekorBody([]byte(`[]`)); err == nil {
		t.Fatal("parser accepted a JSON array")
	}
}

func TestFormatUnknownFields(t *testing.T) {
	long := strings.Repeat("x", 100)
	got := formatUnknownFields([]string{"a\nb", long, "c", "d", "e"})
	want := fmt.Sprintf(`"a\nb", %q, "c" and 2 more`, strings.Repeat("x", 64)+"...")
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if got := formatUnknownFields([]string{"one"}); got != `"one"` {
		t.Fatalf("got %s", got)
	}
}

// rekorParseServer serves one index search result and the given entry
// responses by UUID over TLS. It counts entry requests.
func rekorParseServer(t *testing.T, uuids []string, entries map[string][]byte, entryRequests *atomic.Int32) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			_ = json.NewEncoder(w).Encode(uuids)
		case "/api/v1/log/entries/retrieve":
			entryRequests.Add(1)
			var req struct {
				EntryUUIDs []string `json:"entryUUIDs"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.EntryUUIDs) != 1 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			entry, ok := entries[req.EntryUUIDs[0]]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(entry)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestFetchRekorProvenanceSkipsRejectedEntries puts malformed entries before
// a well-formed one. The search rejects each malformed entry, continues, and
// selects the well-formed entry.
func TestFetchRekorProvenanceSkipsRejectedEntries(t *testing.T) {
	good := mockEntryObject(buildMockDSSEBody(realFulcioCertPEM))
	unknownField := mockEntryObject(buildMockDSSEBody(realFulcioCertPEM))
	unknownField["extra"] = true
	intoto := mockEntryObject(mockBodyB64(map[string]any{"apiVersion": "0.0.1", "kind": "intoto", "spec": map[string]any{}}))
	spec := mockDSSESpec(realFulcioCertPEM)
	spec["signatures"] = []any{spec["signatures"].([]map[string]any)[0], spec["signatures"].([]map[string]any)[0]}
	twoSigs := mockEntryObject(mockBodyB64(map[string]any{"apiVersion": "0.0.1", "kind": "dsse", "spec": spec}))
	entries := map[string][]byte{
		"u1": mustJSON(t, []map[string]any{{"u1": unknownField}}),
		"u2": mustJSON(t, []map[string]any{{"u2": intoto}}),
		"u3": mustJSON(t, []map[string]any{{"u3": twoSigs}}),
		"u4": mustJSON(t, []map[string]any{{"u4": good}}),
	}
	var requests atomic.Int32
	ts := rekorParseServer(t, []string{"u1", "u2", "u3", "u4"}, entries, &requests)
	prov := NewRekorClientWithBase(ts.URL, ts.Client()).FetchRekorProvenance(context.Background(), testDigest)
	if prov.Err != nil {
		t.Fatalf("Err = %v", prov.Err)
	}
	if !prov.HasCert || prov.SourceRepo != "nearai/compose-manager" {
		t.Fatalf("selected entry: HasCert=%v SourceRepo=%q", prov.HasCert, prov.SourceRepo)
	}
	if got := requests.Load(); got != 4 {
		t.Fatalf("entry requests = %d, want 4", got)
	}
}

// TestFetchRekorProvenanceAllEntriesRejected reports the last rejection
// reason when no entry passes the parser.
func TestFetchRekorProvenanceAllEntriesRejected(t *testing.T) {
	unknownField := mockEntryObject(buildMockDSSEBody(realFulcioCertPEM))
	unknownField["extra"] = true
	intoto := mockEntryObject(mockBodyB64(map[string]any{"apiVersion": "0.0.1", "kind": "intoto", "spec": map[string]any{}}))
	entries := map[string][]byte{
		"u1": mustJSON(t, []map[string]any{{"u1": unknownField}}),
		"u2": mustJSON(t, []map[string]any{{"u2": intoto}}),
	}
	var requests atomic.Int32
	ts := rekorParseServer(t, []string{"u1", "u2"}, entries, &requests)
	prov := NewRekorClientWithBase(ts.URL, ts.Client()).FetchRekorProvenance(context.Background(), testDigest)
	if prov.Err == nil || !strings.Contains(prov.Err.Error(), `entry u2: entry kind "intoto" is not supported`) {
		t.Fatalf("Err = %v, want the intoto rejection", prov.Err)
	}
	if prov.HasCert || prov.KeyFingerprint != "" {
		t.Fatalf("rejected entries gave provenance %+v", prov)
	}

	ts = rekorParseServer(t, []string{"u1"}, entries, &requests)
	prov = NewRekorClientWithBase(ts.URL, ts.Client()).FetchRekorProvenance(context.Background(), testDigest)
	if prov.Err == nil || !strings.Contains(prov.Err.Error(), `entry response has unknown fields: "entry.extra"`) {
		t.Fatalf("Err = %v, want the unknown field rejection", prov.Err)
	}
}

// TestRekorSearchRejectsOversizedAndMalformedResults covers the UUID list
// bound and a search response with a second JSON value, for both callers of
// the search.
func TestRekorSearchRejectsOversizedAndMalformedResults(t *testing.T) {
	over := make([]string, maxRekorUUIDs+1)
	for i := range over {
		over[i] = fmt.Sprintf("%080x", i)
	}
	for name, body := range map[string][]byte{
		"oversized":  mustJSON(t, over),
		"two values": []byte(`["a"],"extra":1`),
	} {
		t.Run(name, func(t *testing.T) {
			var entryRequests atomic.Int32
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/index/retrieve" {
					entryRequests.Add(1)
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(body)
			}))
			defer ts.Close()
			rc := NewRekorClientWithBase(ts.URL, ts.Client())
			prov := rc.FetchRekorProvenance(context.Background(), testDigest)
			if prov.Err == nil || !strings.Contains(prov.Err.Error(), "search Rekor") {
				t.Fatalf("Err = %v, want a search failure", prov.Err)
			}
			results := rc.CheckSigstoreDigests(context.Background(), []string{testDigest})
			if results[0].OK || results[0].Err == nil {
				t.Fatalf("CheckSigstoreDigests = %+v, want a failure", results[0])
			}
			if got := entryRequests.Load(); got != 0 {
				t.Fatalf("entry requests = %d, want 0", got)
			}
		})
	}
}

// TestFetchRekorProvenanceWarnsOnRejectedEntry checks the warn-level
// diagnostic: a rejected entry logs its UUID and reason; an entry fetch that
// fails with an HTTP error is not a rejection and logs no warning.
func TestFetchRekorProvenanceWarnsOnRejectedEntry(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })

	unknownField := mockEntryObject(buildMockDSSEBody(realFulcioCertPEM))
	unknownField["extra"] = true
	entries := map[string][]byte{"rejected-uuid": mustJSON(t, []map[string]any{{"rejected-uuid": unknownField}})}
	var requests atomic.Int32
	ts := rekorParseServer(t, []string{"rejected-uuid", "missing-uuid"}, entries, &requests)
	prov := NewRekorClientWithBase(ts.URL, ts.Client()).FetchRekorProvenance(context.Background(), testDigest)
	if prov.Err == nil || !strings.Contains(prov.Err.Error(), "entry missing-uuid") {
		t.Fatalf("Err = %v, want the last fetch failure", prov.Err)
	}
	out := logs.String()
	if strings.Count(out, "Rekor entry rejected") != 1 {
		t.Fatalf("logs = %q, want one rejection", out)
	}
	if !strings.Contains(out, "uuid=rejected-uuid") || !strings.Contains(out, `entry.extra`) {
		t.Fatalf("logs = %q, want the UUID and reason", out)
	}
}
