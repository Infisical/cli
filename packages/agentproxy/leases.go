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
	leaseExpirySkew = 5 * time.Second
	minMintBackoff  = 5 * time.Second
	maxMintBackoff  = 60 * time.Second
)

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
			Config:            args.config,
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

func (s *leaseStore) value(key leaseKey, field string) (string, bool) {
	s.mu.Lock()
	e, ok := s.entries[key]
	if ok && e.leaseID != "" && time.Until(e.expireAt) > leaseExpirySkew {
		e.lastUsed = time.Now()
		v, has := e.data[field]
		s.mu.Unlock()
		return v, has
	}
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

func (s *leaseStore) mintLease(key leaseKey) (*leaseEntry, error) {
	v, err, _ := s.group.Do(key.string(), func() (interface{}, error) {
		s.mu.Lock()
		e, ok := s.entries[key]
		if !ok {
			s.mu.Unlock()
			return nil, fmt.Errorf("lease entry no longer registered")
		}
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
		// don't touch lastUsed here (the request path owns it); bumping it would break the unused-TTL prune
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

func (s *leaseStore) refreshPass(liveKeys map[string]struct{}) time.Time {
	now := time.Now()

	s.mu.Lock()
	var due []leaseKey
	for k, e := range s.entries {
		agentKey := cacheKey(k.jwt, k.scope)
		_, live := liveKeys[agentKey]

		if !live {
			if e.leaseID == "" || !e.expireAt.After(now) {
				delete(s.entries, k)
			}
			continue
		}
		if e.leaseID == "" {
			continue
		}
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
		// never-minted entries mint lazily; scheduling on their nextMintAttempt would busy-spin the loop
		if e.leaseID == "" {
			continue
		}
		// unused-TTL entries: wake for expiry, not the already-past re-mint deadline, else the loop spins
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
