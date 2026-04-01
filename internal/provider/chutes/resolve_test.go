package chutes_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/provider/chutes"
)

func modelsServer(t *testing.T, models []map[string]string) *httptest.Server {
	t.Helper()
	data := make([]map[string]any, len(models))
	for i, m := range models {
		data[i] = map[string]any{
			"id":       m["id"],
			"chute_id": m["chute_id"],
			"object":   "model",
		}
	}
	body, err := json.Marshal(map[string]any{"object": "list", "data": data})
	if err != nil {
		t.Fatalf("marshal models: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

func TestModelResolver_UUID_Passthrough(t *testing.T) {
	// A UUID should pass through without any HTTP call.
	r := chutes.NewModelResolver("http://should-not-be-called", "key", http.DefaultClient)
	got, err := r.Resolve(context.Background(), "0df3133d-c477-56d2-b4db-f2093bb150a1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "0df3133d-c477-56d2-b4db-f2093bb150a1" {
		t.Errorf("got %q, want UUID unchanged", got)
	}
}

func TestModelResolver_ResolvesName(t *testing.T) {
	srv := modelsServer(t, []map[string]string{
		{"id": "deepseek-ai/DeepSeek-V3-0324-TEE", "chute_id": "0df3133d-c477-56d2-b4db-f2093bb150a1"},
		{"id": "Qwen/Qwen3-32B-TEE", "chute_id": "ac059e33-eb27-541c-b9a9-24b214036475"},
	})
	defer srv.Close()

	r := chutes.NewModelResolver(srv.URL, "test-key", http.DefaultClient)
	got, err := r.Resolve(context.Background(), "deepseek-ai/DeepSeek-V3-0324-TEE")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "0df3133d-c477-56d2-b4db-f2093bb150a1" {
		t.Errorf("got %q, want 0df3133d-c477-56d2-b4db-f2093bb150a1", got)
	}

	// Second model
	got, err = r.Resolve(context.Background(), "Qwen/Qwen3-32B-TEE")
	if err != nil {
		t.Fatalf("Resolve Qwen: %v", err)
	}
	if got != "ac059e33-eb27-541c-b9a9-24b214036475" {
		t.Errorf("got %q, want ac059e33-eb27-541c-b9a9-24b214036475", got)
	}
}

func TestModelResolver_UnknownModel(t *testing.T) {
	srv := modelsServer(t, []map[string]string{
		{"id": "deepseek-ai/DeepSeek-V3-0324-TEE", "chute_id": "0df3133d-c477-56d2-b4db-f2093bb150a1"},
	})
	defer srv.Close()

	r := chutes.NewModelResolver(srv.URL, "test-key", http.DefaultClient)
	_, err := r.Resolve(context.Background(), "nonexistent/model")
	if err == nil {
		t.Fatal("expected error for unknown model")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found, got: %v", err)
	}
}

func TestModelResolver_CachesResults(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "model-a", "chute_id": "uuid-a"},
			},
		})
	}))
	defer srv.Close()

	r := chutes.NewModelResolver(srv.URL, "test-key", http.DefaultClient)

	// First call should fetch.
	_, err := r.Resolve(context.Background(), "model-a")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Second call should use cache.
	_, err = r.Resolve(context.Background(), "model-a")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount.Load())
	}
}

func TestModelResolver_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := chutes.NewModelResolver(srv.URL, "test-key", http.DefaultClient)
	_, err := r.Resolve(context.Background(), "some-model")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention HTTP 500, got: %v", err)
	}
}

func TestModelResolver_SendsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "m", "chute_id": "u"},
			},
		})
	}))
	defer srv.Close()

	r := chutes.NewModelResolver(srv.URL, "sk-secret-key", http.DefaultClient)
	_, _ = r.Resolve(context.Background(), "m")

	if gotAuth != "Bearer sk-secret-key" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer sk-secret-key")
	}
}

func TestLooksLikeUUID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0df3133d-c477-56d2-b4db-f2093bb150a1", true},
		{"ac059e33-eb27-541c-b9a9-24b214036475", true},
		{"AC059E33-EB27-541C-B9A9-24B214036475", true}, // uppercase
		{"deepseek-ai/DeepSeek-V3-0324-TEE", false},
		{"Qwen/Qwen3-32B-TEE", false},
		{"default", false},
		{"", false},
		{"not-a-uuid-at-all", false},
		{"0df3133d-c477-56d2-b4db-f2093bb150a", false},   // too short
		{"0df3133d-c477-56d2-b4db-f2093bb150a1x", false}, // too long
	}

	for _, tt := range tests {
		got := chutes.LooksLikeUUID(tt.input)
		if got != tt.want {
			t.Errorf("LooksLikeUUID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
