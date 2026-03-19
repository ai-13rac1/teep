package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
)

// sseChunk is a minimal parse of an SSE data event from an OpenAI-compatible
// streaming response. Only the first choice's delta content is inspected.
type sseChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

// decryptSSEChunk parses one SSE data JSON payload, decrypts the delta content
// field if it is an encrypted chunk, and returns the JSON with the plaintext
// content substituted in. Returns an error if the chunk contains non-empty
// content that is not a valid encrypted chunk, or if decryption fails.
// Callers must not fall through to plaintext on error.
func decryptSSEChunk(data string, session *attestation.Session) (string, error) {
	var chunk sseChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return "", fmt.Errorf("parse SSE chunk JSON: %w", err)
	}

	if len(chunk.Choices) == 0 {
		// No choices (e.g. usage-only chunk); pass through unchanged.
		return data, nil
	}

	content := chunk.Choices[0].Delta.Content
	if content == "" {
		// Empty delta (role announcement or finish_reason chunk); pass through.
		return data, nil
	}

	if !attestation.IsEncryptedChunk(content) {
		return "", fmt.Errorf("expected encrypted chunk but content does not look encrypted (len=%d prefix=%q)", len(content), safePrefix(content, 8))
	}

	plaintext, err := attestation.Decrypt(content, session.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decrypt chunk: %w", err)
	}

	// Re-parse as a generic map so all fields (id, object, model, etc.) are
	// preserved exactly; only the delta.content is swapped out.
	var full map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &full); err != nil {
		return "", fmt.Errorf("re-parse chunk for rewrite: %w", err)
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(full["choices"], &choices); err != nil {
		return "", fmt.Errorf("parse choices array: %w", err)
	}

	var delta map[string]json.RawMessage
	if err := json.Unmarshal(choices[0]["delta"], &delta); err != nil {
		return "", fmt.Errorf("parse delta object: %w", err)
	}

	plaintextJSON, err := json.Marshal(string(plaintext))
	if err != nil {
		return "", fmt.Errorf("marshal plaintext: %w", err)
	}
	delta["content"] = plaintextJSON

	deltaOut, err := json.Marshal(delta)
	if err != nil {
		return "", fmt.Errorf("marshal rewritten delta: %w", err)
	}
	choices[0]["delta"] = deltaOut

	choicesOut, err := json.Marshal(choices)
	if err != nil {
		return "", fmt.Errorf("marshal rewritten choices: %w", err)
	}
	full["choices"] = choicesOut

	out, err := json.Marshal(full)
	if err != nil {
		return "", fmt.Errorf("marshal rewritten chunk: %w", err)
	}
	return string(out), nil
}

// decryptNonStreamResponse decrypts the content field in each choice's message
// of an OpenAI-format non-streaming response body. Returns an error if any
// non-empty content field is not a recognised encrypted chunk or fails to
// decrypt. Callers must not fall through to plaintext on error.
func decryptNonStreamResponse(body []byte, session *attestation.Session) ([]byte, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		return nil, fmt.Errorf("parse response JSON: %w", err)
	}

	choicesRaw, ok := full["choices"]
	if !ok {
		return body, nil
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return nil, fmt.Errorf("parse choices: %w", err)
	}

	for i, choice := range choices {
		msgRaw, ok := choice["message"]
		if !ok {
			continue
		}
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(msgRaw, &msg); err != nil {
			return nil, fmt.Errorf("parse choice[%d].message: %w", i, err)
		}

		contentRaw, ok := msg["content"]
		if !ok {
			continue
		}
		var content string
		if err := json.Unmarshal(contentRaw, &content); err != nil {
			return nil, fmt.Errorf("parse choice[%d].message.content: %w", i, err)
		}

		if content == "" {
			continue
		}

		if !attestation.IsEncryptedChunk(content) {
			return nil, fmt.Errorf("choice[%d]: expected encrypted content but not recognised as encrypted (len=%d)", i, len(content))
		}

		plaintext, err := attestation.Decrypt(content, session.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("choice[%d]: decrypt: %w", i, err)
		}

		plaintextJSON, err := json.Marshal(string(plaintext))
		if err != nil {
			return nil, fmt.Errorf("choice[%d]: marshal plaintext: %w", i, err)
		}
		msg["content"] = plaintextJSON

		msgOut, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("choice[%d]: marshal rewritten message: %w", i, err)
		}
		choices[i]["message"] = msgOut
	}

	choicesOut, err := json.Marshal(choices)
	if err != nil {
		return nil, fmt.Errorf("marshal rewritten choices: %w", err)
	}
	full["choices"] = choicesOut

	return json.Marshal(full)
}

// safePrefix returns up to n characters of s for safe use in log messages.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
