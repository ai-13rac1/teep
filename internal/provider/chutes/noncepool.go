package chutes

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// modelResolver abstracts model name → chute UUID resolution for testing.
type modelResolver interface {
	Resolve(ctx context.Context, model string) (string, error)
}

// NoncePool caches the /e2e/instances/ response and serves nonces from
// the pool without re-fetching. When all nonces are consumed or expired,
// a fresh batch is fetched automatically.
//
// This mirrors the nonce caching strategy in chutesai/e2ee-proxy's
// e2ee_discovery.lua and eliminates the per-request /e2e/instances +
// /chutes/{id}/evidence roundtrips that made E2EE requests slow.
type NoncePool struct {
	baseURL  string
	apiKey   string
	client   *http.Client
	resolver modelResolver

	mu        sync.Mutex
	refreshMu sync.Mutex            // serializes refresh calls to prevent thundering herd
	pools     map[string]*chutePool // keyed by chute UUID
}

// chutePool holds cached instances and their remaining nonces for one chute.
type chutePool struct {
	instances []poolInstance
	expiresAt time.Time
}

// poolInstance is one instance with remaining nonces.
type poolInstance struct {
	instanceID string
	e2ePubKey  string
	nonces     []string
	failures   int // consecutive failures on this instance; prefer others
}

// NewNoncePool creates a NoncePool that fetches from the given base URL.
func NewNoncePool(baseURL, apiKey string, resolver modelResolver, client *http.Client) *NoncePool {
	return &NoncePool{
		baseURL:  baseURL,
		apiKey:   apiKey,
		client:   client,
		resolver: resolver,
		pools:    make(map[string]*chutePool),
	}
}

// Take returns E2EE material for one request: a live instance with its
// ML-KEM pubkey and a single-use nonce. The nonce is consumed (removed
// from the pool) atomically. If the pool is empty or expired, a fresh
// batch is fetched from /e2e/instances/{chute}.
func (p *NoncePool) Take(ctx context.Context, model string) (*provider.E2EEMaterial, error) {
	chuteID, err := p.resolver.Resolve(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("nonce pool: resolve model: %w", err)
	}

	// Fast path: try to take from cache.
	if m := p.take(chuteID); m != nil {
		return m, nil
	}

	// Slow path: serialize refreshes to prevent thundering herd.
	// Multiple goroutines may reach here concurrently when the pool is empty;
	// only the first should call the API — the rest wait and retry take().
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	// Double-check after acquiring refresh lock.
	if m := p.take(chuteID); m != nil {
		return m, nil
	}

	if err := p.refresh(ctx, chuteID); err != nil {
		return nil, err
	}

	if m := p.take(chuteID); m != nil {
		return m, nil
	}
	return nil, fmt.Errorf("nonce pool: no nonces available for chute %s after refresh", chuteID)
}

// MarkFailed records that an instance failed, so future Take calls prefer
// other instances. Does not remove the instance — it may recover.
func (p *NoncePool) MarkFailed(chuteID, instanceID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pool, ok := p.pools[chuteID]
	if !ok {
		return
	}
	for i := range pool.instances {
		if pool.instances[i].instanceID == instanceID {
			pool.instances[i].failures++
			return
		}
	}
}

// Invalidate discards cached nonces for a chute, forcing a refresh on next Take.
func (p *NoncePool) Invalidate(chuteID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pools, chuteID)
}

// FetchE2EEMaterial implements provider.E2EEMaterialFetcher.
func (p *NoncePool) FetchE2EEMaterial(ctx context.Context, model string) (*provider.E2EEMaterial, error) {
	return p.Take(ctx, model)
}

// take attempts to consume one nonce from the pool. Returns nil if no nonces
// are available or the pool is expired. Prefers instances with fewer failures.
func (p *NoncePool) take(chuteID string) *provider.E2EEMaterial {
	p.mu.Lock()
	defer p.mu.Unlock()

	pool, ok := p.pools[chuteID]
	if !ok || time.Now().After(pool.expiresAt) {
		delete(p.pools, chuteID)
		return nil
	}

	// Find the instance with the fewest failures that has nonces.
	bestIdx := -1
	for i := range pool.instances {
		if len(pool.instances[i].nonces) == 0 {
			continue
		}
		if bestIdx == -1 || pool.instances[i].failures < pool.instances[bestIdx].failures {
			bestIdx = i
		}
	}
	if bestIdx == -1 {
		// All nonces consumed.
		delete(p.pools, chuteID)
		return nil
	}

	inst := &pool.instances[bestIdx]
	nonce := inst.nonces[0]
	inst.nonces = inst.nonces[1:]

	slog.Debug("nonce pool: took nonce",
		"chute_id", chuteID,
		"instance_id", inst.instanceID,
		"remaining", len(inst.nonces),
		"failures", inst.failures,
	)

	return &provider.E2EEMaterial{
		InstanceID: inst.instanceID,
		E2EPubKey:  inst.e2ePubKey,
		E2ENonce:   nonce,
		ChuteID:    chuteID,
	}
}

// refresh fetches /e2e/instances/{chute} and populates the pool.
func (p *NoncePool) refresh(ctx context.Context, chuteID string) error {
	instancesURL, err := url.Parse(p.baseURL + instancesPath + url.PathEscape(chuteID))
	if err != nil {
		return fmt.Errorf("nonce pool: parse instances URL: %w", err)
	}

	slog.DebugContext(ctx, "nonce pool: fetching fresh instances", "chute_id", chuteID)
	body, err := provider.FetchAttestationJSON(ctx, p.client, instancesURL.String(), p.apiKey, maxBodySize)
	if err != nil {
		return fmt.Errorf("nonce pool: fetch instances: %w", err)
	}

	var resp e2eInstancesResponse
	if err := jsonstrict.UnmarshalWarn(body, &resp, "nonce pool e2e instances"); err != nil {
		return fmt.Errorf("nonce pool: unmarshal instances: %w", err)
	}
	if len(resp.Instances) == 0 {
		return fmt.Errorf("nonce pool: no instances available for chute %s", chuteID)
	}
	if len(resp.Instances) > maxInstances {
		return fmt.Errorf("nonce pool: too many instances (%d, max %d)", len(resp.Instances), maxInstances)
	}

	ttl := resp.NonceExpIn
	if ttl <= 0 {
		ttl = 55 // default from Chutes reference proxy
	}
	// Subtract a safety margin to avoid using near-expired nonces.
	margin := 5
	if ttl > margin*2 {
		ttl -= margin
	}

	pool := &chutePool{
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}

	// Carry over failure counts from previous pool.
	// Build the map while holding p.mu to avoid racing with MarkFailed().
	p.mu.Lock()
	oldFailures := make(map[string]int)
	if oldPool, ok := p.pools[chuteID]; ok {
		for _, inst := range oldPool.instances {
			if inst.failures > 0 {
				oldFailures[inst.instanceID] = inst.failures
			}
		}
	}
	p.mu.Unlock()

	totalNonces := 0
	for _, inst := range resp.Instances {
		if inst.E2EPubKey == "" || len(inst.Nonces) == 0 {
			continue
		}
		pi := poolInstance{
			instanceID: inst.InstanceID,
			e2ePubKey:  inst.E2EPubKey,
			nonces:     inst.Nonces,
			failures:   oldFailures[inst.InstanceID],
		}
		pool.instances = append(pool.instances, pi)
		totalNonces += len(inst.Nonces)
	}

	if len(pool.instances) == 0 {
		return fmt.Errorf("nonce pool: no E2EE-capable instances for chute %s", chuteID)
	}

	slog.InfoContext(ctx, "nonce pool: refreshed",
		"chute_id", chuteID,
		"instances", len(pool.instances),
		"nonces", totalNonces,
		"ttl_seconds", ttl,
	)

	p.mu.Lock()
	p.pools[chuteID] = pool
	p.mu.Unlock()

	return nil
}
