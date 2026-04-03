# Plan: Multi-Endpoint Support (Embeddings, VL, Audio, Image Gen)

**TL;DR** — Phase 1 adds three new proxy endpoint families: embeddings (`POST /v1/embeddings`), audio transcriptions (`POST /v1/audio/transcriptions`), and image generations (`POST /v1/images/generations`). VL support continues via the existing `POST /v1/chat/completions` route. Rerank support is follow-on/conditional work rather than a guaranteed new endpoint. All endpoints require TEE attestation + body E2EE per policy; providers that can't meet this will fail-closed, which is intentional.

---

## Design Principle: Standard OpenAI Endpoints Only

The teep proxy exposes **only standard OpenAI-compatible endpoints** to clients. Provider-specific upstream path formats (e.g., phalacloud's `/embeddings` without `/v1/` prefix, or phalacloud's `/chat/completions`) are internal routing details — the proxy always accepts `/v1/embeddings`, `/v1/chat/completions`, etc. from the client.

The per-provider `EmbeddingsPath`, `AudioPath`, `ImagesPath` fields (like the existing `ChatPath`) specify the **upstream** path sent to the provider backend, not the client-facing route. For example, phalacloud's `ChatPath = "/chat/completions"` is already an upstream path; the proxy route is always `/v1/chat/completions`.

Each new endpoint's integration tests must verify that the upstream provider response schema matches the OpenAI spec (correct fields, types, status codes). If a provider returns a non-standard response, that is a provider compliance issue, not something the proxy should silently transform.

---

## Target Models

Integration tests and reports should always use **model names** (not chute UUIDs) to exercise the full model name → chute ID → instance ID resolution path via `llm.chutes.ai`. This resolution code is shared across all endpoint types (chat, embeddings, vision, images) and must be tested end-to-end.

| Model | Provider | Endpoint |
|---|---|---|
| Qwen/Qwen3-Embedding-0.6B | near.ai (neardirect/nearcloud) | POST /v1/embeddings |
| Qwen/Qwen3-Reranker-0.6B | near.ai (neardirect/nearcloud) | POST /v1/rerank (TBD) |
| qwen/qwen3-embedding-8b | phalacloud | POST /v1/embeddings (upstream: `/embeddings`) |
| Qwen/Qwen3-Embedding-8B | chutes (chute `fd636cb1`) | POST /v1/embeddings |
| openai/whisper-large-v3 | near.ai (neardirect/nearcloud) | POST /v1/audio/transcriptions |
| Qwen/Qwen3-VL-30B-A3B-Instruct | near.ai (neardirect/nearcloud) | POST /v1/chat/completions (existing) |
| Qwen/Qwen3.5-397B-A17B-TEE | chutes (chute `51a4284a`) | POST /v1/chat/completions (existing) |
| black-forest-labs/FLUX.2-klein-4B | near.ai (neardirect/nearcloud) | POST /v1/images/generations |

---

## E2EE Status by Provider

All endpoints require TEE attestation + body E2EE per policy. Providers that cannot meet this requirement must fail-closed — this is correct behavior, not a bug.

| Provider | E2EE mechanism | New endpoint viability |
|---|---|---|
| **neardirect** | TLS-level (SPKI pinned to model TEE cert) | ✓ all types |
| **nearcloud** | XChaCha20-Poly1305 app-layer (chat only today) | ⚠️ see nearcloud gate below |
| **chutes** | ML-KEM-768 via `/e2e/invoke` + `X-E2E-Path` | ✓ all types |
| **phalacloud** | None | ✗ fail-closed per policy (expected) |

neardirect TLS E2EE: SPKI cert is generated inside the model TEE and verified by attestation; TLS terminates at the model TEE, so the TLS channel provides end-to-end encryption to the TEE directly. No additional application-layer E2EE is needed.

**GATE: nearcloud non-chat E2EE** — nearcloud's `EncryptChatMessagesNearCloud` only encrypts the `messages` array in chat requests. For embeddings the secret data is in `input`; for images, in `prompt`. **nearcloud MUST NOT be wired for non-chat endpoints until the E2EE protocol is verified to cover those content fields.** If implementation proceeds without this gate, an embeddings request through nearcloud could send the `input` field in plaintext through a channel the user believes is E2EE. Until verified, non-chat nearcloud paths must either not be wired or must fail-closed with an explicit error.

---

## Phase 1 — Provider & Proxy Infrastructure

No dependencies. All other phases depend on this.

1. Add `EmbeddingsPath`, `AudioPath`, `ImagesPath` string fields to `Provider` in `internal/provider/provider.go`. Follow the same pattern as `ChatPath`.

2. Register new routes in `fromConfig` / `NewServer` in `internal/proxy/proxy.go`:
   - `POST /v1/embeddings` → `handleEmbeddings`
   - `POST /v1/audio/transcriptions` → `handleAudioTranscriptions`
   - `POST /v1/images/generations` → `handleImagesGenerations`

3. In `fromConfig`, assign new paths per provider:
   - **neardirect** + **nearcloud**: `EmbeddingsPath = "/v1/embeddings"`, `AudioPath = "/v1/audio/transcriptions"`, `ImagesPath = "/v1/images/generations"`
   - **phalacloud**: `EmbeddingsPath = "/embeddings"` (no `/v1/` prefix, consistent with `ChatPath = "/chat/completions"`)
   - **chutes**: `EmbeddingsPath = "/v1/embeddings"` (for `X-E2E-Path` threading)

4. **Do not** raise the existing `handleChatCompletions` body limit to 100 MiB while the handler still reads the entire body into memory via `io.ReadAll`. The current 10 MiB cap stays until the implementation is changed to avoid full-buffering. The path forward:

   - **neardirect VL (TLS-level E2EE):** The pinned handler already has a raw `tls.Conn` to the model TEE. Refactor to stream the request body via `io.Copy` directly to the TLS connection without buffering. This eliminates the body limit constraint for neardirect VL entirely. This is significant refactoring that warrants its own sub-plan or early phase.
   - **Chutes/nearcloud VL (app-layer E2EE):** ML-KEM and XChaCha20-Poly1305 operate on the complete body as a unit (no chunked encryption protocol exists). These providers must keep full-body buffering. Raise limit modestly only for these providers if needed, after measuring real VL request sizes, rather than a blanket 100 MiB.
   - **All non-VL endpoints:** Current limits are sufficient (embeddings 10 MiB, audio 25 MiB, images 10 MiB).

5. Parameterize `doUpstreamRoundtrip` to accept the endpoint path as an argument instead of reading `prov.ChatPath`. Today `proxy.go:1468` hardcodes `prov.BaseURL + prov.ChatPath` as the upstream URL. Each new handler must pass its endpoint-specific path (e.g., `prov.EmbeddingsPath`). Same for `PinnedRequest` construction — all `handlePinned*` functions pass the correct path field rather than hardcoding `prov.ChatPath`.

6. Add unit tests for new route dispatch and 404 for unregistered paths.

---

## Phase 2 — Chutes E2EE Multi-Path Support

Depends on Phase 1.

The Chutes `/e2e/invoke` tunnel requires an `X-E2E-Path` header naming the TEE-internal endpoint. Today the Chutes Preparer at `chutes.go` uses `p.chatPath` (a struct field set once at construction time), which does not vary per-request. This must be made dynamic.

7. Add `TargetPath string` to the `e2ee.ChutesE2EE` struct (in `internal/e2ee/chutes.go` or wherever `ChutesE2EE` is defined).

8. **Bind `TargetPath` at encryption time, not as an afterthought.** Add `targetPath string` as a required parameter to `RequestEncryptor.EncryptRequest` (or to a Chutes-specific variant) so that the path is bound when the body is encrypted. This ensures correctly-encrypted data cannot be misrouted to the wrong TEE-internal endpoint by a handler that forgets to set the path later. For non-Chutes encryptors (Venice, NearCloud), the parameter is unused.

9. In **every** Chutes relay path (existing chat handler AND new handlers), set `meta.TargetPath` unconditionally before calling `prov.Preparer.PrepareRequest`:
   - chat completions: `meta.TargetPath = prov.ChatPath`
   - embeddings: `meta.TargetPath = prov.EmbeddingsPath`
   - audio transcriptions: `meta.TargetPath = prov.AudioPath`
   - image generations: `meta.TargetPath = prov.ImagesPath`

10. In `internal/provider/chutes/chutes.go` `PrepareRequest`: **require** `meta.TargetPath` to be non-empty and use it for `X-E2E-Path`. Return an error if `TargetPath` is missing. Do **not** fall back to configured `chatPath` — missing routing metadata must fail-closed so non-chat requests cannot be silently misrouted to the chat endpoint.

11. Unit tests for the chutes preparer must cover both explicit `TargetPath` routing for each endpoint type AND rejection when `TargetPath` is empty.

---

## Phase 3 — Embeddings

Depends on Phases 1–2.

12. Implement `handleEmbeddings` in `internal/proxy/proxy.go`:
    - Parse JSON body; require `model` field (`{"model": "...", "input": ...}`).
    - `resolveModel` → check `prov.EmbeddingsPath != ""`, else 400.
    - Same attestation path as chat: `attestAndCache` for standard providers; `handlePinnedEmbeddings` (parallel to `handlePinnedChat`) for pinned providers — passes `Path: prov.EmbeddingsPath` to `PinnedHandler.HandlePinned`.
    - Non-streaming relay only (embeddings have no SSE stream).
    - Pass `prov.EmbeddingsPath` to `doUpstreamRoundtrip` (not `prov.ChatPath`).
    - E2EE required: for chutes, `TargetPath` is bound at encryption time per Phase 2 step 8; for neardirect, TLS-level; nearcloud is gated per the nearcloud non-chat E2EE gate (not wired until verified).
    - Verify upstream response matches OpenAI embeddings spec: `{"object": "list", "data": [{"object": "embedding", "embedding": [...], "index": 0}], "model": "...", "usage": {...}}`.

13. Integration tests (use **model names**, not chute UUIDs, to exercise full resolution path):
    - `internal/integration/embeddings_neardirect_test.go` — `Qwen/Qwen3-Embedding-0.6B`
    - `internal/integration/embeddings_chutes_test.go` — `Qwen/Qwen3-Embedding-8B` (exercises model name → chute ID resolution via `llm.chutes.ai`)
    - `internal/integration/embeddings_phalacloud_test.go` — `qwen/qwen3-embedding-8b` (expected fail-closed; documents current state)
    - Each test validates response schema against OpenAI embeddings spec.

---

## Phase 4 — VL / Vision-Language

Depends on Phase 1 body limit only.

VL models use `/v1/chat/completions` verbatim — no new handler needed.

14. Both neardirect `Qwen/Qwen3-VL-30B-A3B-Instruct` and chutes `Qwen/Qwen3.5-397B-A17B-TEE` route through the existing handler. The chutes model name is resolved via `llm.chutes.ai` like any other model. Verify the chutes Preparer does not mis-classify a VL (chat) request as requiring a non-chat path.

15. Integration tests (use **model names** to exercise full resolution):
    - `internal/integration/vl_neardirect_test.go` — `Qwen/Qwen3-VL-30B-A3B-Instruct`
    - `internal/integration/vl_chutes_test.go` — `Qwen/Qwen3.5-397B-A17B-TEE` (exercises model name → chute ID resolution)
    - Use a small inline base64 PNG test image (< 1 MiB) in the test body.

---

## Phase 5 — Audio / ASR (Whisper)

Depends on Phase 1.

16. Implement `handleAudioTranscriptions` in `internal/proxy/proxy.go`:
    - Body is `multipart/form-data` (audio file + `model` field). Extract `model` from the form; do NOT parse as JSON.
    - 25 MiB body limit.
    - Pinned handler path for neardirect: `Path: prov.AudioPath`.
    - No chutes audio in scope (Whisper not listed on chutes).
    - **Multipart E2EE guard (fail-closed):** Non-pinned E2EE providers (Chutes, nearcloud) require body encryption, which does not support multipart. The handler must explicitly reject these with an error:
      ```go
      // Non-pinned E2EE providers (Chutes, nearcloud) require body encryption,
      // which doesn't support multipart. Fail closed.
      if prov.E2EE && prov.PinnedHandler == nil {
          http.Error(w, "audio transcription requires TLS-level E2EE (pinned provider)", 400)
          return
      }
      ```
      Without this, adding Chutes audio later would silently try to JSON-unmarshal multipart data.
    - E2EE: neardirect provides TLS-level. nearcloud E2EE over multipart requires investigation (flag as ⚠️ further research — encrypting raw multipart form data at app layer is non-trivial).

17. Integration test: `internal/integration/audio_neardirect_test.go` — `openai/whisper-large-v3`.

---

## Phase 6 — Image Generation (FLUX)

Depends on Phase 1.

18. Implement `handleImagesGenerations` in `internal/proxy/proxy.go`:
    - JSON body: `{"model": "...", "prompt": "...", "n": 1, ...}`.
    - Non-streaming JSON relay.
    - Pass `prov.ImagesPath` to `doUpstreamRoundtrip` and `PinnedRequest`.
    - Verify upstream response matches OpenAI images spec.

19. Integration test: `internal/integration/images_neardirect_test.go` — `black-forest-labs/FLUX.2-klein-4B`.

---

## Phase 7 — Reranking

Depends on Phase 1; research required first.

20. **Research step**: Determine what HTTP path near.ai uses for `Qwen/Qwen3-Reranker-0.6B` (likely `/v1/rerank` Cohere-style, or may route through `/v1/embeddings`). Check live API or near.ai docs.

21. If `/v1/rerank`: add `RerankPath` to Provider, register `POST /v1/rerank`, implement `handleRerank` following the same pattern as `handleEmbeddings`.

22. If near.ai routes reranking through `/v1/embeddings`: no new proxy endpoint; configure `EmbeddingsPath` and route through `handleEmbeddings`.

23. Integration test: neardirect `Qwen/Qwen3-Reranker-0.6B`.

---

## Relevant Files

- `internal/provider/provider.go` — add `EmbeddingsPath`, `AudioPath`, `ImagesPath` to `Provider`
- `internal/proxy/proxy.go` — new handlers, routes, `fromConfig` path wiring, body limit
- `internal/e2ee/chutes.go` — add `TargetPath` to `ChutesE2EE` struct
- `internal/provider/chutes/chutes.go` — Preparer uses `meta.TargetPath`
- `internal/provider/chutes/resolve.go` — verify UUID pass-through handles VL chute
- `internal/provider/neardirect/pinned.go` — verify `PinnedRequest.Path` is already forwarded unchanged (no change expected)
- `internal/provider/nearcloud/pinned.go` — same
- `internal/integration/*` — new integration test files per phase

---

## Verification

1. `make check` passes after each phase (fmt + vet + lint + unit tests).
2. `make integration` at plan completion.
3. `make reports` to verify attestation factors still pass for existing chat models after refactors.
4. Phalacloud embeddings test should produce a **blocked** result (fail-closed on `e2ee_usable`) — expected correct behavior.

---

## Open Questions

1. **nearcloud non-chat E2EE**: Does near.ai's `X-Client-Pub-Key` / `X-Encryption-Version` protocol extend to `/v1/embeddings`, `/v1/audio/transcriptions`, `/v1/images/generations`? This is gated — nearcloud must not be wired for non-chat endpoints until answered (see E2EE Status section above). If verified, wire nearcloud in Phases 3/5/6. If not, only neardirect handles new endpoint types from near.ai.

2. **Audio over Chutes / NearCloud**: Encrypting `multipart/form-data` at app layer is non-trivial. Needs resolution once nearcloud non-chat E2EE status is known. Phase 5 includes a fail-closed guard that blocks multipart requests for non-pinned E2EE providers.

3. **Chutes embeddings base URL**: Chutes uses `llm.chutes.ai` for LLM models and `api.chutes.ai` for E2EE invoke. Verify whether the embeddings base URL differs (e.g. `embedding.chutes.ai`). Check the `/v1/models` response for embedding chute type metadata.

4. **VL body limit for buffered E2EE providers**: Current 10 MiB limit may be too small for some VL use cases with Chutes/nearcloud (which require full-body buffering for encryption). Measure real VL request sizes before choosing a raised limit. neardirect can stream, so no limit constraint there.
