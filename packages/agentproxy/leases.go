package agentproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

const (
	// serve a cached lease only while this much validity remains, so a value isn't injected right as it expires
	leaseExpirySkew = 5 * time.Second
	// re-mint backoff bounds while the old lease is still valid
	minMintBackoff = 5 * time.Second
	maxMintBackoff = 60 * time.Second
)

// refreshBuffer is how far before expiry the proxy re-mints. Proportional to the TTL so very short
// leases (e.g. ~30s TOTP) don't get a buffer larger than their own lifetime.
func refreshBuffer(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return time.Minute
	}
	buf := ttl / 5
	if buf > time.Minute {
		return time.Minute
	}
	return buf
}

// leaseKey identifies a per-agent lease. jwt+scope scope it to a single agent session (matching the agent
// cache key), so each session gets its own ephemeral credentials; secretName+configHash separate leases for
// the same dynamic secret minted with different per-lease config.
type leaseKey struct {
	jwt        string
	scope      agentScope
	secretName string
	configHash string
}

func (k leaseKey) string() string {
	return strings.Join([]string{k.jwt, k.scope.projectID, k.scope.environment, k.scope.secretPath, k.secretName, k.configHash}, "\x00")
}

type leaseSpec struct {
	projectSlug string
	config      map[string]interface{}
}

type leaseEntry struct {
	key             leaseKey
	spec            leaseSpec
	leaseID         string
	expireAt        time.Time
	ttl             time.Duration
	data            map[string]string
	lastUsed        time.Time
	mintFailures    int
	nextMintAttempt time.Time
}

type leaseMintArgs struct {
	secretName  string
	projectSlug string
	environment string
	path        string
	config      map[string]interface{}
}

type leaseMintResult struct {
	leaseID  string
	expireAt time.Time
	data     map[string]interface{}
}

type leaseMinter func(args leaseMintArgs) (leaseMintResult, error)
type leaseRevoker func(leaseID, projectSlug, environment, path string) error

type leaseStore struct {
	mint   leaseMinter
	revoke leaseRevoker

	mu      sync.Mutex
	entries map[leaseKey]*leaseEntry
	group   singleflight.Group
	wake    chan struct{}
}

func newLeaseStore(proxyToken func() string) *leaseStore {
	return &leaseStore{
		mint:    defaultLeaseMinter(proxyToken),
		revoke:  defaultLeaseRevoker(proxyToken),
		entries: make(map[leaseKey]*leaseEntry),
		wake:    make(chan struct{}, 1),
	}
}

func defaultLeaseMinter(proxyToken func() string) leaseMinter {
	return func(args leaseMintArgs) (leaseMintResult, error) {
		client := resty.New().SetAuthToken(proxyToken())
		resp, err := api.CallCreateDynamicSecretLeaseV1(client, api.CreateDynamicSecretLeaseV1Request{
			ProjectSlug:       args.projectSlug,
			Environment:       args.environment,
			SecretPath:        args.path,
			DynamicSecretName: args.secretName,
			// empty TTL: the server applies the dynamic secret's configured defaultTTL
			Config: args.config,
		})
		if err != nil {
			return leaseMintResult{}, err
		}
		return leaseMintResult{leaseID: resp.Lease.Id, expireAt: resp.Lease.ExpireAt, data: resp.Data}, nil
	}
}

func defaultLeaseRevoker(proxyToken func() string) leaseRevoker {
	return func(leaseID, projectSlug, environment, path string) error {
		client := resty.New().SetAuthToken(proxyToken())
		_, err := api.CallRevokeDynamicSecretLeaseV1(client, api.RevokeDynamicSecretLeaseV1Request{
			LeaseID:     leaseID,
			ProjectSlug: projectSlug,
			Environment: environment,
			SecretPath:  path,
		})
		return err
	}
}

// canonicalConfigHash produces a stable hash of the per-lease config so two credentials with the same
// config share a lease and differing configs get separate leases. json.Marshal sorts map keys recursively;
// nil and empty both normalize to "".
func canonicalConfigHash(config map[string]interface{}) string {
	if len(config) == 0 {
		return ""
	}
	b, err := json.Marshal(config)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// register records (or refreshes) the spec for a lease key without minting. Called from resolve() on every
// discovery/refresh, so an existing live lease is preserved across agent-cache rebuilds.
func (s *leaseStore) register(key leaseKey, spec leaseSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[key]; ok {
		e.spec = spec
		return
	}
	s.entries[key] = &leaseEntry{key: key, spec: spec}
}

func stringifyData(data map[string]interface{}) map[string]string {
	out := make(map[string]string, len(data))
	for k, v := range data {
		switch val := v.(type) {
		case string:
			out[k] = val
		default:
			b, err := json.Marshal(v)
			if err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}

// value returns the current lease value for a field, minting lazily on first use. Returns ok=false when the
// lease can't be minted or the field is absent, so the caller skips the credential (fail-open, like a missing
// static secret).
func (s *leaseStore) value(key leaseKey, field string) (string, bool) {
	s.mu.Lock()
	e, ok := s.entries[key]
	if ok && e.leaseID != "" && time.Until(e.expireAt) > leaseExpirySkew {
		e.lastUsed = time.Now()
		v, has := e.data[field]
		s.mu.Unlock()
		return v, has
	}
	// respect the re-mint backoff so a request storm against a failing provider doesn't hammer the mint endpoint
	inBackoff := ok && !e.nextMintAttempt.IsZero() && time.Now().Before(e.nextMintAttempt)
	s.mu.Unlock()
	if !ok || inBackoff {
		return "", false
	}

	entry, err := s.mintLease(key)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	entry.lastUsed = time.Now()
	v, has := entry.data[field]
	s.mu.Unlock()
	return v, has
}

// mintLease mints (or re-mints) a fresh lease for the key, singleflighted so concurrent callers share one
// network mint. Make-before-break: the new lease swaps in atomically and the old lease is left for the
// server's scheduled revocation to reap (never proactively revoked here).
func (s *leaseStore) mintLease(key leaseKey) (*leaseEntry, error) {
	v, err, _ := s.group.Do(key.string(), func() (interface{}, error) {
		s.mu.Lock()
		e, ok := s.entries[key]
		if !ok {
			s.mu.Unlock()
			return nil, fmt.Errorf("lease entry no longer registered")
		}
		// another flight may have already minted a still-valid lease
		if e.leaseID != "" && time.Until(e.expireAt) > leaseExpirySkew {
			s.mu.Unlock()
			return e, nil
		}
		spec := e.spec
		s.mu.Unlock()

		res, mintErr := s.mint(leaseMintArgs{
			secretName:  key.secretName,
			projectSlug: spec.projectSlug,
			environment: key.scope.environment,
			path:        key.scope.secretPath,
			config:      spec.config,
		})

		s.mu.Lock()
		defer s.mu.Unlock()
		if mintErr != nil {
			e.mintFailures++
			e.nextMintAttempt = time.Now().Add(mintBackoff(e.mintFailures))
			// once the old lease has expired, drop stale data so requests fail open instead of injecting a dead value
			if !e.expireAt.IsZero() && e.expireAt.Before(time.Now()) {
				e.data = nil
				e.leaseID = ""
			}
			return nil, mintErr
		}

		now := time.Now()
		e.leaseID = res.leaseID
		e.expireAt = res.expireAt
		e.ttl = res.expireAt.Sub(now)
		e.data = stringifyData(res.data)
		// deliberately do NOT touch lastUsed here: the request path (value) owns it. If a proactive re-mint
		// bumped lastUsed, the "unused for a full TTL" prune could never fire and orphaned leases (e.g. after
		// a config change made a new leaseKey) would be re-minted forever.
		e.mintFailures = 0
		e.nextMintAttempt = time.Time{}
		return e, nil
	})
	if err != nil {
		return nil, err
	}
	s.signalWake()
	return v.(*leaseEntry), nil
}

func mintBackoff(failures int) time.Duration {
	d := minMintBackoff
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= maxMintBackoff {
			return maxMintBackoff
		}
	}
	return d
}

// refreshPass re-mints leases nearing expiry and prunes dead ones. liveKeys is the set of agent-cache keys
// (cacheKey(jwt, scope)) for still-active sessions; leases whose session is gone are left to expire (no
// revoke). Returns the earliest future deadline the loop should wake for, or the zero time if none.
func (s *leaseStore) refreshPass(liveKeys map[string]struct{}) time.Time {
	now := time.Now()

	s.mu.Lock()
	var due []leaseKey
	for k, e := range s.entries {
		agentKey := cacheKey(k.jwt, k.scope)
		_, live := liveKeys[agentKey]

		if !live {
			// session gone: drop once the lease has expired; otherwise let it lapse
			if e.leaseID == "" || !e.expireAt.After(now) {
				delete(s.entries, k)
			}
			continue
		}
		if e.leaseID == "" {
			continue // not yet minted; minted lazily on first request
		}
		// unused for a full TTL: drop after it expires so the next use re-mints on demand
		if e.ttl > 0 && now.Sub(e.lastUsed) > e.ttl {
			if !e.expireAt.After(now) {
				delete(s.entries, k)
			}
			continue
		}
		deadline := e.expireAt.Add(-refreshBuffer(e.ttl))
		if !e.nextMintAttempt.IsZero() && e.nextMintAttempt.After(deadline) {
			deadline = e.nextMintAttempt
		}
		if !now.Before(deadline) {
			due = append(due, k)
		}
	}
	s.mu.Unlock()

	for _, k := range due {
		if _, err := s.mintLease(k); err != nil {
			log.Warn().Err(err).Msgf("failed to re-mint lease for dynamic secret %q", k.secretName)
		}
	}

	return s.nextDeadline(liveKeys)
}

func (s *leaseStore) nextDeadline(liveKeys map[string]struct{}) time.Time {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var next time.Time
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	for k, e := range s.entries {
		if _, live := liveKeys[cacheKey(k.jwt, k.scope)]; !live {
			continue
		}
		// never-minted entries (leaseID == "") are minted lazily on the next request, not proactively.
		// refreshPass skips them, so scheduling on their nextMintAttempt here would busy-spin the loop.
		if e.leaseID == "" {
			continue
		}
		// unused for a full TTL: refreshPass won't re-mint it, only delete it once expired. Schedule the
		// wake for expiry, not the (already-past) re-mint deadline, else the loop spins at its 1s floor.
		if e.ttl > 0 && now.Sub(e.lastUsed) > e.ttl {
			consider(e.expireAt)
			continue
		}
		consider(e.expireAt.Add(-refreshBuffer(e.ttl)))
		if !e.nextMintAttempt.IsZero() {
			consider(e.nextMintAttempt)
		}
	}
	return next
}

// refreshLoop drives lease re-minting on a timer that wakes at the earliest lease deadline (bounded by
// pollInterval), plus an out-of-band wake whenever a fresh short-TTL lease is minted.
func (s *leaseStore) refreshLoop(stop <-chan struct{}, pollInterval time.Duration, liveKeys func() map[string]struct{}) {
	if pollInterval <= 0 {
		pollInterval = 60 * time.Second
	}
	timer := time.NewTimer(pollInterval)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-s.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			next := s.refreshPass(liveKeys())
			timer.Reset(clampDuration(time.Until(next), time.Second, pollInterval, next.IsZero()))
			continue
		}
		// woken out-of-band: recompute the deadline without a full pass
		next := s.nextDeadline(liveKeys())
		timer.Reset(clampDuration(time.Until(next), time.Second, pollInterval, next.IsZero()))
	}
}

func clampDuration(d, min, max time.Duration, useMax bool) time.Duration {
	if useMax {
		return max
	}
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

func (s *leaseStore) signalWake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// revokeAll best-effort revokes every live lease on shutdown, bounded by ctx. Failures are logged; the
// server's per-lease scheduled revocation is the backstop.
func (s *leaseStore) revokeAll(ctx context.Context) {
	type target struct {
		leaseID     string
		projectSlug string
		environment string
		path        string
		secretName  string
	}
	s.mu.Lock()
	var targets []target
	for k, e := range s.entries {
		if e.leaseID == "" {
			continue
		}
		targets = append(targets, target{
			leaseID:     e.leaseID,
			projectSlug: e.spec.projectSlug,
			environment: k.scope.environment,
			path:        k.scope.secretPath,
			secretName:  k.secretName,
		})
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			if err := s.revoke(t.leaseID, t.projectSlug, t.environment, t.path); err != nil {
				log.Warn().Err(err).Msgf("failed to revoke lease for dynamic secret %q on shutdown", t.secretName)
			}
		}(t)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		log.Warn().Msg("timed out revoking leases on shutdown; relying on server-side lease expiry")
	}
}
