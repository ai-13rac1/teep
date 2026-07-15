package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func runReasoningResponseTests(t *testing.T, plainURL, e2eeURL, model string) {
	t.Helper()
	t.Run("NonStream", func(t *testing.T) {
		resp := postReasoningChat(t, plainURL, model, false)
		defer resp.Body.Close()
		assertReasoningResponse(t, resp, false)
	})
	t.Run("E2EEStreaming", func(t *testing.T) {
		resp := postReasoningChat(t, e2eeURL, model, true)
		defer resp.Body.Close()
		assertReasoningResponse(t, resp, true)
	})
}

func postReasoningChat(t *testing.T, proxyURL, model string, stream bool) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v,"max_tokens":512,"reasoning_effort":"low"}`,
		model, integrationPrompt, stream)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST reasoning chat: %v", err)
	}
	return resp
}

func runGLMReasoningRepairTests(t *testing.T, proxyURL, model string) {
	t.Helper()
	t.Run("PriorTurn", func(t *testing.T) {
		body := fmt.Sprintf(`{
			"model": %q,
			"messages": [
				{"role":"user","content":"What is one plus one?"},
				{"role":"assistant","reasoning_content":"I should add one and one.","content":"Two."},
				{"role":"user","content":"Repeat that answer in one word."}
			],
			"max_tokens": 512
		}`, model)
		resp := postRawReasoningChat(t, proxyURL, body)
		defer resp.Body.Close()
		assertReasoningResponse(t, resp, false)
	})
	t.Run("TrailingUserAfterTool", func(t *testing.T) {
		body := fmt.Sprintf(`{
			"model": %q,
			"messages": [
				{"role":"user","content":"What is the weather in San Francisco?"},
				{"role":"assistant","reasoning_content":"I should call the weather tool.","content":null,"tool_calls":[{"id":"call_weather","type":"function","function":{"name":"get_weather","arguments":"{\"location\":\"San Francisco\"}"}}]},
				{"role":"tool","tool_call_id":"call_weather","content":"sunny"},
				{"role":"user","content":"Answer with the weather in one word."}
			],
			"max_tokens": 512
		}`, model)
		resp := postRawReasoningChat(t, proxyURL, body)
		defer resp.Body.Close()
		assertReasoningResponse(t, resp, false)
	})
}

func postRawReasoningChat(t *testing.T, proxyURL, body string) *http.Response {
	t.Helper()
	resp, err := integrationPostJSON(t, proxyURL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST reasoning repair chat: %v", err)
	}
	return resp
}

func assertReasoningResponse(t *testing.T, resp *http.Response, stream bool) {
	t.Helper()
	if stream {
		assertReasoningStreamResponse(t, resp)
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, diagnosticBodySnippet(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reasoning chat body: %v", err)
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content          json.RawMessage `json:"content"`
				Reasoning        string          `json:"reasoning"`
				ReasoningContent string          `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode reasoning chat body: %v; body=%s", err, diagnosticBodySnippet(body))
	}
	if len(parsed.Choices) == 0 {
		t.Fatalf("reasoning chat response has no choices: %s", diagnosticBodySnippet(body))
	}
	message := parsed.Choices[0].Message
	reasoning := message.Reasoning
	if reasoning == "" {
		reasoning = message.ReasoningContent
	}
	content, _, err := decodeMultimodalContentText(message.Content)
	if err != nil {
		t.Fatalf("decode reasoning chat content: %v", err)
	}
	assertReasoningAndContent(t, reasoning, content)
}

func assertReasoningStreamResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, diagnosticBodySnippet(body))
	}
	chunks := readSSEChunks(t, resp.Body)
	if len(chunks) == 0 {
		t.Fatal("no reasoning chat SSE chunks received")
	}
	var reasoning, content strings.Builder
	for _, chunk := range chunks {
		var parsed struct {
			Choices []struct {
				Delta struct {
					Content          json.RawMessage `json:"content"`
					Reasoning        string          `json:"reasoning"`
					ReasoningContent string          `json:"reasoning_content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(chunk), &parsed); err != nil {
			t.Fatalf("decode reasoning chat SSE chunk: %v; chunk=%s", err, diagnosticBodySnippet([]byte(chunk)))
		}
		if len(parsed.Choices) == 0 {
			continue
		}
		delta := parsed.Choices[0].Delta
		reasoning.WriteString(delta.Reasoning)
		reasoning.WriteString(delta.ReasoningContent)
		text, _, err := decodeMultimodalContentText(delta.Content)
		if err != nil {
			t.Fatalf("decode reasoning chat SSE content: %v", err)
		}
		content.WriteString(text)
	}
	assertReasoningAndContent(t, reasoning.String(), content.String())
}

func assertReasoningAndContent(t *testing.T, reasoning, content string) {
	t.Helper()
	if !isUsableReasoningText(reasoning) {
		t.Fatalf("reasoning is empty or not valid printable UTF-8: length=%d", len(reasoning))
	}
	if !isUsableReasoningText(content) {
		t.Fatalf("content is empty or not valid printable UTF-8: length=%d", len(content))
	}
	t.Logf("reasoning chat response: reasoning_bytes=%d content_bytes=%d", len(reasoning), len(content))
}

func isUsableReasoningText(text string) bool {
	return strings.TrimSpace(text) != "" && isPrintableUTF8(text)
}

func TestIsUsableReasoningText(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		text string
		want bool
	}{
		{name: "empty", text: "", want: false},
		{name: "spaces", text: " \t\n", want: false},
		{name: "unicode whitespace", text: "\u2003", want: false},
		{name: "printable", text: "reasoning", want: true},
		{name: "invalid UTF-8", text: string([]byte{0xff}), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isUsableReasoningText(tc.text); got != tc.want {
				t.Fatalf("isUsableReasoningText(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}
