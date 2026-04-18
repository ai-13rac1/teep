# Compatibility test: vendor and containerize

## Context

OpenAI's gpt-oss repo contains a `compatibility-test/` harness that tests
whether a provider correctly exposes tool calling and reasoning output. We want
to vendor just that subdirectory into teep, containerize it with Podman (to
isolate npm from the host), and wire it into the teep Makefile so it's easy
to run against all providers in both direct and teep-proxy modes.

Upstream source: `https://github.com/openai/gpt-oss` — `compatibility-test/`

---

## Step 1: Move files

```
gpt-oss/compatibility-test/  →  vendored/gpt-oss-compat-test/
gpt-oss/                     →  delete (temporary clone, untracked)
```

Commit `vendored/gpt-oss-compat-test/` as-is with a message noting the
upstream source URL and commit hash.

---

## Step 2: Add `Containerfile`

**`vendored/gpt-oss-compat-test/Containerfile`**

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p results
ENTRYPOINT ["node_modules/.bin/tsx", "index.ts"]
```

`npm ci` pins to the lockfile exactly. `mkdir -p results` ensures the output
directory exists so the host volume mount is never empty.

---

## Step 3: Modify `index.ts` — two small changes only

### 3a. Write outputs into `./results/`

`index.ts` currently writes `rollout_*.jsonl` and `analysis_*.json` to
`process.cwd()` (i.e. `/app` in the container). The volume mount is at
`/app/results`, so outputs disappear on container exit. Fix: write into
`./results/`:

```typescript
const outputFile  = path.join(process.cwd(), "results", `rollout_${provider}_${timestamp}.jsonl`);
const analysisFile = path.join(process.cwd(), "results", `analysis_${provider}_${timestamp}.json`);
```

### 3b. Validate model name at startup

`providers.ts` will ship with placeholder model names. Passing a placeholder
to the API produces a cryptic error. Add a guard before any requests go out:

```typescript
const config = PROVIDERS[provider];
if (!config) { /* existing error */ }
if (config.modelName === "<SET_MODEL_NAME>") {
  console.error(`Provider "${provider}" has no model name set. Edit providers.ts.`);
  process.exitCode = 1;
  return;
}
```

No other changes to `index.ts`. `--provider all` and `--via-teep` are
handled at the Makefile level instead (see Step 5).

---

## Step 4: Modify `providers.ts`

Add all six real providers. API keys from env vars. Model names as
`"<SET_MODEL_NAME>"` (descriptive, clearly invalid at runtime, caught by
the Step 3b guard). Export a `ProviderConfig` type.

When `TEEP_BASE_URL` is set, each provider routes through the teep proxy
automatically — no flag needed in `index.ts`:

```typescript
import process from "node:process";

export type ProviderConfig = {
  apiBaseUrl: string;
  apiKey: string;
  apiType: string[];
  modelName: string;
  providerDetails: Record<string, any>;
};

export const PROVIDERS: Record<string, ProviderConfig> = {
  vllm: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "http://localhost:8000/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : "vllm",
    apiType: ["responses", "chat"],
    modelName: "openai/gpt-oss-120b",
    providerDetails: {},
  },
  venice: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "https://api.venice.ai/api/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : (process.env.VENICE_API_KEY ?? ""),
    apiType: ["chat"],
    modelName: "<SET_MODEL_NAME>",
    providerDetails: {},
  },
  chutes: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "https://api.chutes.ai/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : (process.env.CHUTES_API_KEY ?? ""),
    apiType: ["chat"],
    modelName: "<SET_MODEL_NAME>",
    providerDetails: {},
  },
  neardirect: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "https://completions.near.ai/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : (process.env.NEARAI_API_KEY ?? ""),
    apiType: ["chat"],
    modelName: "<SET_MODEL_NAME>",
    providerDetails: {},
  },
  nearcloud: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "https://cloud-api.near.ai/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : (process.env.NEARAI_API_KEY ?? ""),
    apiType: ["chat"],
    modelName: "<SET_MODEL_NAME>",
    providerDetails: {},
  },
  nanogpt: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "https://nano-gpt.com/api/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : (process.env.NANOGPT_API_KEY ?? ""),
    apiType: ["chat"],
    modelName: "<SET_MODEL_NAME>",
    providerDetails: {},
  },
  phalacloud: {
    apiBaseUrl: process.env.TEEP_BASE_URL ?? "https://api.redpill.ai/v1",
    apiKey: process.env.TEEP_BASE_URL ? "teep" : (process.env.PHALA_API_KEY ?? ""),
    apiType: ["chat"],
    modelName: "<SET_MODEL_NAME>",
    providerDetails: {},
  },
};
```

---

## Step 5: Add Makefile targets to teep root `Makefile`

`compat-build` is **not** a prerequisite of `compat-test` — Podman builds
are slow. Run `make compat-build` once; rebuild manually when deps change.

```makefile
COMPAT_DIR     := vendored/gpt-oss-compat-test
COMPAT_IMAGE   := teep-compat-test
COMPAT_RESULTS := $(COMPAT_DIR)/results
TEEP_BASE_URL  ?= http://127.0.0.1:8337/v1

.PHONY: compat-build compat-test compat-test-teep compat-test-all

## Build the compatibility test container image
compat-build:
	podman build -t $(COMPAT_IMAGE) $(COMPAT_DIR)

## Run compatibility test directly against one provider (no teep).
## Usage: make compat-test PROVIDER=venice [CASES=1] [TRIES=1]
compat-test:
	mkdir -p $(COMPAT_RESULTS)
	podman run --rm \
	  -e VENICE_API_KEY \
	  -e CHUTES_API_KEY \
	  -e NEARAI_API_KEY \
	  -e NANOGPT_API_KEY \
	  -e PHALA_API_KEY \
	  -v $(CURDIR)/$(COMPAT_RESULTS):/app/results \
	  $(COMPAT_IMAGE) \
	  --provider $(or $(PROVIDER),vllm) \
	  -n $(or $(CASES),1) \
	  -k $(or $(TRIES),1)

## Run compatibility test against all providers sequentially (direct mode).
compat-test-all:
	@for p in venice chutes neardirect nearcloud nanogpt phalacloud; do \
	  $(MAKE) compat-test PROVIDER=$$p CASES=$(or $(CASES),1) TRIES=$(or $(TRIES),1); \
	done

## Run compatibility test through the teep proxy.
## Requires: teep serve <provider> already running on $(TEEP_BASE_URL).
## On macOS: make compat-test-teep TEEP_BASE_URL=http://host.containers.internal:8337/v1
compat-test-teep:
	mkdir -p $(COMPAT_RESULTS)
	podman run --rm \
	  --network host \
	  -e TEEP_BASE_URL=$(TEEP_BASE_URL) \
	  -v $(CURDIR)/$(COMPAT_RESULTS):/app/results \
	  $(COMPAT_IMAGE) \
	  --provider $(or $(PROVIDER),vllm) \
	  -n $(or $(CASES),1) \
	  -k $(or $(TRIES),1)
```

`--network host` gives the container access to `127.0.0.1:8337`. On macOS,
Podman routes through a VM — override `TEEP_BASE_URL` to use
`host.containers.internal` instead.

---

## Step 6: Update `.gitignore`

```
vendored/gpt-oss-compat-test/results/
```

---

## Verification

```bash
# Build container (once)
make compat-build

# Smoke test — direct, single provider, 1 case
make compat-test PROVIDER=venice CASES=1

# All providers, direct
make compat-test-all CASES=1

# Through teep (start 'teep serve venice' first)
make compat-test-teep PROVIDER=venice CASES=1
```
