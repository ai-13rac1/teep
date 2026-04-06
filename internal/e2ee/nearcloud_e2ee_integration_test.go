package e2ee_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

const nearcloudBaseURL = "https://cloud-api.near.ai"

func skipNearCloudE2EEIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("NEARAI_API_KEY") == "" {
		t.Skip("NEARAI_API_KEY not set")
	}
}

// fetchSigningKey fetches a TEE attestation report from the nearcloud gateway
// and returns the model's Ed25519 signing key (64 hex chars).
func fetchSigningKey(t *testing.T, model string) string {
	t.Helper()
	apiKey := os.Getenv("NEARAI_API_KEY")

	attester := nearcloud.NewAttester(apiKey)
	nonce := attestation.NewNonce()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	raw, err := attester.FetchAttestation(ctx, model, nonce)
	if err != nil {
		t.Fatalf("fetch attestation for %s: %v", model, err)
	}
	if raw.SigningKey == "" {
		t.Fatalf("no signing key in attestation for %s", model)
	}
	t.Logf("signing key for %s: %s...", model, raw.SigningKey[:16])
	return raw.SigningKey
}

// nearcloudE2EERequest sends a POST request to the nearcloud API with E2EE
// headers. Returns the raw response. The caller must close resp.Body.
func nearcloudE2EERequest(t *testing.T, path string, body []byte, contentType string, session *e2ee.NearCloudSession) *http.Response {
	t.Helper()
	apiKey := os.Getenv("NEARAI_API_KEY")

	req, err := http.NewRequest(http.MethodPost, nearcloudBaseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connection", "close")

	// E2EE headers.
	req.Header.Set("X-Signing-Algo", "ed25519")
	req.Header.Set("X-Client-Pub-Key", session.ClientEd25519PubHex())
	req.Header.Set("X-Encryption-Version", "2")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// nearcloudPlaintextRequest sends a POST request to the nearcloud API without
// E2EE headers. Returns the raw response. The caller must close resp.Body.
func nearcloudPlaintextRequest(t *testing.T, path string, body []byte, contentType string) *http.Response {
	t.Helper()
	apiKey := os.Getenv("NEARAI_API_KEY")

	req, err := http.NewRequest(http.MethodPost, nearcloudBaseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connection", "close")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// readBody reads and returns the response body, bounded to 1 MiB.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return body
}

// createE2EESession creates a NearCloud E2EE session initialized with the
// model's signing key.
func createE2EESession(t *testing.T, signingKey string) *e2ee.NearCloudSession {
	t.Helper()
	session, err := e2ee.NewNearCloudSession()
	if err != nil {
		t.Fatalf("create NearCloud session: %v", err)
	}
	if err := session.SetModelKeyEd25519(signingKey); err != nil {
		session.Zero()
		t.Fatalf("set model key: %v", err)
	}
	return session
}

// makeMinimalWAV returns a minimal WAV file (PCM 16-bit 16kHz, ~0.1s silence).
func makeMinimalWAV() []byte {
	sampleRate := 16000
	numSamples := sampleRate / 10
	dataSize := numSamples * 2
	fileSize := 36 + dataSize

	buf := make([]byte, 44+dataSize)
	copy(buf[0:4], "RIFF")
	putLE32(buf[4:], uint32(fileSize))
	copy(buf[8:12], "WAVE")
	copy(buf[12:16], "fmt ")
	putLE32(buf[16:], 16)
	putLE16(buf[20:], 1)
	putLE16(buf[22:], 1)
	putLE32(buf[24:], uint32(sampleRate))
	putLE32(buf[28:], uint32(sampleRate*2))
	putLE16(buf[32:], 2)
	putLE16(buf[34:], 16)
	copy(buf[36:40], "data")
	putLE32(buf[40:], uint32(dataSize))
	return buf
}

func putLE16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func putLE32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// --------------------------------------------------------------------------
// Embeddings E2EE test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Embeddings_E2EE tests whether the nearcloud gateway
// supports E2EE for the /v1/embeddings endpoint. The EncryptChatMessagesNearCloud
// function only encrypts the "messages" array in chat requests. Embeddings use
// an "input" field instead. This test verifies the server-side behavior when
// E2EE headers are sent with an embeddings request.
func TestIntegration_NearCloud_Embeddings_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Embedding-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// First: verify plaintext embeddings work (baseline).
	plaintextBody := fmt.Sprintf(`{"model":%q,"input":"The quick brown fox"}`, model)
	ptResp := nearcloudPlaintextRequest(t, "/v1/embeddings", []byte(plaintextBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext embeddings: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	if ptResp.StatusCode != http.StatusOK {
		t.Fatalf("plaintext embeddings failed: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))
	}

	// Verify we got real embedding data in plaintext.
	var ptResult struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(ptBody, &ptResult); err != nil {
		t.Fatalf("unmarshal plaintext response: %v", err)
	}
	if len(ptResult.Data) == 0 || len(ptResult.Data[0].Embedding) == 0 {
		t.Fatalf("plaintext response has no embedding data")
	}
	t.Logf("plaintext embeddings: dimensions=%d", len(ptResult.Data[0].Embedding))

	// Now: send the same request WITH E2EE headers.
	// The input field is NOT encrypted (EncryptChatMessagesNearCloud only
	// handles messages[].content). This tests what the server does when it
	// sees E2EE headers on a non-chat endpoint.
	e2eeBody := fmt.Sprintf(`{"model":%q,"input":"The quick brown fox"}`, model)
	e2eeResp := nearcloudE2EERequest(t, "/v1/embeddings", []byte(e2eeBody), "application/json", session)
	e2eeRespBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE embeddings: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeRespBody))
	t.Logf("E2EE embeddings response (first 500 chars): %s", truncate(e2eeRespBody, 500))

	// Document the server behavior. The critical security question is:
	// does the server encrypt the response when it sees E2EE headers on embeddings?
	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// Server accepted. Check if response is encrypted or plaintext.
		var embResult struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(e2eeRespBody, &embResult); err == nil && len(embResult.Data) > 0 {
			// Response parsed as normal JSON — server returned plaintext embeddings
			// despite E2EE headers. This means the request "input" was sent in
			// plaintext AND the response was returned in plaintext, even though
			// the user's client believes E2EE is active.
			t.Log("FINDING: Server returned PLAINTEXT embeddings despite E2EE headers")
			t.Log("CONCLUSION: NearCloud does NOT encrypt embeddings responses when E2EE headers are present")
			t.Log("This confirms the E2EE gate is correct: nearcloud non-chat endpoints MUST NOT be wired with E2EE")
		} else {
			// Response is not standard JSON — might be encrypted.
			bodyStr := string(e2eeRespBody)
			if e2ee.IsEncryptedChunkXChaCha20(bodyStr) {
				t.Log("FINDING: Server returned ENCRYPTED embeddings response")
				t.Log("CONCLUSION: NearCloud MAY support E2EE for embeddings — further verification needed")
			} else {
				t.Logf("FINDING: Server returned non-JSON, non-encrypted response: %s", truncate(e2eeRespBody, 200))
			}
		}
	default:
		t.Logf("FINDING: Server rejected E2EE embeddings request: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeRespBody, 500))
	}
}

// --------------------------------------------------------------------------
// Audio transcription E2EE test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Audio_E2EE tests whether the nearcloud gateway
// supports E2EE for the /v1/audio/transcriptions endpoint. Audio requests use
// multipart/form-data which is fundamentally incompatible with the NearCloud
// E2EE message encryption scheme.
func TestIntegration_NearCloud_Audio_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "openai/whisper-large-v3"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	wavData := makeMinimalWAV()

	// Build multipart form.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", model); err != nil {
		t.Fatalf("write model field: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(wavData); err != nil {
		t.Fatalf("write wav data: %v", err)
	}
	mw.Close()
	multipartBody := buf.Bytes()
	contentType := mw.FormDataContentType()

	// First: verify plaintext audio transcription works (baseline).
	ptResp := nearcloudPlaintextRequest(t, "/v1/audio/transcriptions", multipartBody, contentType)
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext audio: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))

	if ptResp.StatusCode != http.StatusOK {
		t.Logf("plaintext audio transcription not available: status=%d (may not be supported on nearcloud)", ptResp.StatusCode)
		// Continue with E2EE test anyway to document behavior.
	}

	// Now: send audio with E2EE headers. Multipart body cannot be encrypted
	// with EncryptChatMessagesNearCloud (which only handles messages[].content).
	e2eeResp := nearcloudE2EERequest(t, "/v1/audio/transcriptions", multipartBody, contentType, session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE audio: status=%d body=%s", e2eeResp.StatusCode, truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		t.Log("FINDING: Server accepted audio request with E2EE headers")
		t.Log("Audio data was sent in PLAINTEXT (multipart cannot be encrypted by EncryptChatMessagesNearCloud)")
		// Check if response is encrypted.
		bodyStr := string(e2eeBody)
		if e2ee.IsEncryptedChunkXChaCha20(bodyStr) {
			t.Log("FINDING: Server returned ENCRYPTED audio response")
		} else {
			t.Log("FINDING: Server returned PLAINTEXT audio response despite E2EE headers")
			t.Log("CONCLUSION: Audio transcription is NOT E2EE-protected on nearcloud")
		}
	default:
		t.Logf("FINDING: Server rejected E2EE audio request: status=%d", e2eeResp.StatusCode)
		t.Log("This is consistent with the E2EE gate — audio is not supported with nearcloud E2EE")
	}
}

// --------------------------------------------------------------------------
// Rerank E2EE test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Rerank_E2EE tests whether the nearcloud gateway
// supports the /v1/rerank endpoint and whether E2EE works with it. Rerank
// requests use "query" and "documents" fields, not "messages", so
// EncryptChatMessagesNearCloud cannot encrypt them.
func TestIntegration_NearCloud_Rerank_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Reranker-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	rerankBody := fmt.Sprintf(`{
		"model": %q,
		"query": "What is deep learning?",
		"documents": [
			"Deep learning is a subset of machine learning.",
			"The weather today is sunny.",
			"Neural networks have multiple layers."
		],
		"top_n": 2
	}`, model)

	// First: verify plaintext rerank works (baseline).
	ptResp := nearcloudPlaintextRequest(t, "/v1/rerank", []byte(rerankBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext rerank: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))
	t.Logf("plaintext rerank response: %s", truncate(ptBody, 500))

	if ptResp.StatusCode != http.StatusOK {
		t.Logf("plaintext rerank not available at /v1/rerank: status=%d", ptResp.StatusCode)
		// Try /rerank as an alternative path.
		ptResp2 := nearcloudPlaintextRequest(t, "/rerank", []byte(rerankBody), "application/json")
		ptBody2 := readBody(t, ptResp2)
		ptResp2.Body.Close()
		t.Logf("plaintext /rerank (alt path): status=%d body=%s", ptResp2.StatusCode, truncate(ptBody2, 500))
	} else {
		// Plaintext rerank works. Parse and log.
		var result struct {
			Results []struct {
				Index          int     `json:"index"`
				RelevanceScore float64 `json:"relevance_score"`
			} `json:"results"`
		}
		if err := json.Unmarshal(ptBody, &result); err == nil {
			for _, r := range result.Results {
				t.Logf("  rank: doc[%d] score=%.4f", r.Index, r.RelevanceScore)
			}
		}
	}

	// Now: send rerank with E2EE headers.
	e2eeResp := nearcloudE2EERequest(t, "/v1/rerank", []byte(rerankBody), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE rerank: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("E2EE rerank response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// Check if response is encrypted or plaintext.
		var result struct {
			Results []struct {
				Index int `json:"index"`
			} `json:"results"`
		}
		if err := json.Unmarshal(e2eeBody, &result); err == nil && len(result.Results) > 0 {
			t.Log("FINDING: Server returned PLAINTEXT rerank results despite E2EE headers")
			t.Log("CONCLUSION: NearCloud does NOT encrypt rerank responses when E2EE headers are present")
			t.Log("The query and documents were sent in PLAINTEXT — E2EE gate is correct")
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(bodyStr) {
				t.Log("FINDING: Server returned ENCRYPTED rerank response")
				t.Log("CONCLUSION: NearCloud MAY support E2EE for rerank — further verification needed")
			} else {
				t.Logf("FINDING: Non-JSON, non-encrypted response: %s", truncate(e2eeBody, 200))
			}
		}
	default:
		t.Logf("FINDING: Server rejected E2EE rerank request: status=%d", e2eeResp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// Encrypted embeddings input test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Embeddings_EncryptedInput tests what happens when
// we actually encrypt the "input" field of an embeddings request using the
// NearCloud E2EE protocol, mimicking what the proxy would need to do if it
// supported E2EE for embeddings.
func TestIntegration_NearCloud_Embeddings_EncryptedInput(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Embedding-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// Encrypt the input text using the same E2EE protocol as chat messages.
	plaintext := "The quick brown fox"
	encInput, err := e2ee.EncryptXChaCha20([]byte(plaintext), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt input: %v", err)
	}
	t.Logf("encrypted input length: %d hex chars", len(encInput))

	body := fmt.Sprintf(`{"model":%q,"input":%q}`, model, encInput)

	e2eeResp := nearcloudE2EERequest(t, "/v1/embeddings", []byte(body), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("encrypted input embeddings: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("encrypted input response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// If server returns 200, check whether it processed the encrypted input
		// as an embedding or returned an error in the body.
		var result struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(e2eeBody, &result); err == nil && len(result.Data) > 0 {
			t.Log("FINDING: Server embedded the CIPHERTEXT as if it were plaintext")
			t.Log("The model computed an embedding of the hex-encoded ciphertext, not the original input")
			t.Log("CONCLUSION: Server does NOT decrypt the input field — E2EE is NOT end-to-end for embeddings")
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(strings.TrimSpace(bodyStr)) {
				t.Log("FINDING: Server returned encrypted response for encrypted input")
				t.Log("CONCLUSION: Server MAY support true E2EE for embeddings")
			} else {
				t.Logf("FINDING: Unexpected response format: %s", truncate(e2eeBody, 200))
			}
		}
	default:
		t.Logf("FINDING: Server rejected encrypted input: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeBody, 500))
	}
}

// truncate returns s[:maxLen] or s if shorter, as a string.
func truncate(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "..."
}
