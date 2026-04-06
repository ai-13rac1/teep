package proxy_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// NearDirect VL (vision-language) integration
// --------------------------------------------------------------------------

func nearDirectVLModel() string {
	if m := os.Getenv("NEARAI_VL_MODEL"); m != "" {
		return m
	}
	return "Qwen/Qwen3-VL-30B-A3B-Instruct"
}

// tinyPNG is a minimal 1x1 red PNG (67 bytes) used as a test image.
var tinyPNG = func() string {
	// Minimal valid PNG: 1x1 pixel, red.
	raw := []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xde,
		0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
		0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, 0x33,
		0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND
		0xae, 0x42, 0x60, 0x82,
	}
	return base64.StdEncoding.EncodeToString(raw)
}()

func TestIntegration_NearDirect_VL(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectVLModel()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": false,
		"max_tokens": 50
	}`, model, tinyPNG)

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat (VL): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	content := extractMessageContent(t, respBody)
	if !isPrintableUTF8(content) {
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("VL response: %q", content)
}

// --------------------------------------------------------------------------
// Chutes VL integration
// --------------------------------------------------------------------------

func chutesVLModel() string {
	if m := os.Getenv("CHUTES_VL_MODEL"); m != "" {
		return m
	}
	return "Qwen/Qwen3.5-397B-A17B-TEE"
}

func TestIntegration_Chutes_VL(t *testing.T) {
	skipChutesIntegration(t)

	proxySrv := newProxyServer(t, integrationChutesPlaintextConfig(t))
	defer proxySrv.Close()

	model := chutesVLModel()
	// Simple chat prompt (not VL image) to verify model name resolution.
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"Say hello"}],"stream":false,"max_tokens":50}`, model)

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	content := extractMessageContent(t, respBody)
	if !isPrintableUTF8(content) {
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("chutes VL model response: %q", content)
}

// --------------------------------------------------------------------------
// NearDirect Images integration (FLUX)
// --------------------------------------------------------------------------

func nearDirectImagesModel() string {
	if m := os.Getenv("NEARAI_IMAGES_MODEL"); m != "" {
		return m
	}
	return "black-forest-labs/FLUX.2-klein-4B"
}

func TestIntegration_NearDirect_Images(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectImagesModel()
	body := fmt.Sprintf(`{"model":%q,"prompt":"a solid red square","n":1,"size":"256x256"}`, model)

	resp, err := integrationClient.Post(proxySrv.URL+"/v1/images/generations", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertImagesResponse(t, respBody)
}

// --------------------------------------------------------------------------
// NearDirect Audio integration (Whisper)
// --------------------------------------------------------------------------

func nearDirectAudioModel() string {
	if m := os.Getenv("NEARAI_AUDIO_MODEL"); m != "" {
		return m
	}
	return "openai/whisper-large-v3"
}

func TestIntegration_NearDirect_Audio(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectAudioModel()

	// Create a minimal WAV file (PCM, 16-bit, 16kHz, 0.1s of silence).
	wavData := makeMinimalWAV()

	// Build multipart form.
	boundary := "teep-test-boundary"
	var buf strings.Builder
	fmt.Fprintf(&buf, "--%s\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n%s\r\n", boundary, model)
	fmt.Fprintf(&buf, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\n", boundary)
	buf.Write(wavData)
	fmt.Fprintf(&buf, "\r\n--%s--\r\n", boundary)

	resp, err := integrationClient.Post(
		proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary="+boundary,
		strings.NewReader(buf.String()))
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	t.Logf("audio transcription response: %s", respBody)
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// assertImagesResponse validates the response body matches OpenAI images spec.
func assertImagesResponse(t *testing.T, body []byte) {
	t.Helper()

	var resp struct {
		Created int64 `json:"created"`
		Data    []struct {
			URL     string `json:"url,omitempty"`
			B64JSON string `json:"b64_json,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode images response: %v\nraw: %s", err, body[:min(500, len(body))])
	}

	if len(resp.Data) == 0 {
		t.Fatal("no image data in response")
	}
	if resp.Data[0].URL == "" && resp.Data[0].B64JSON == "" {
		t.Error("image data[0] has neither url nor b64_json")
	}
	t.Logf("images: created=%d count=%d has_url=%v has_b64=%v",
		resp.Created, len(resp.Data), resp.Data[0].URL != "", resp.Data[0].B64JSON != "")
}

// makeMinimalWAV returns a minimal WAV file (PCM 16-bit 16kHz, ~0.1s silence).
func makeMinimalWAV() []byte {
	sampleRate := 16000
	numSamples := sampleRate / 10 // 0.1 seconds
	dataSize := numSamples * 2    // 16-bit = 2 bytes per sample
	fileSize := 36 + dataSize

	buf := make([]byte, 44+dataSize)
	copy(buf[0:4], "RIFF")
	putLE32(buf[4:], uint32(fileSize))
	copy(buf[8:12], "WAVE")
	copy(buf[12:16], "fmt ")
	putLE32(buf[16:], 16) // chunk size
	putLE16(buf[20:], 1)  // PCM
	putLE16(buf[22:], 1)  // mono
	putLE32(buf[24:], uint32(sampleRate))
	putLE32(buf[28:], uint32(sampleRate*2)) // byte rate
	putLE16(buf[32:], 2)                    // block align
	putLE16(buf[34:], 16)                   // bits per sample
	copy(buf[36:40], "data")
	putLE32(buf[40:], uint32(dataSize))
	// samples are all zero (silence)
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
