package agentvault

import (
	"context"
	"errors"
	"sync"
	"time"
)

// A database or SSH connection the proxy is serving. It is tracked under the session cache's lock, so the cache can
// close it the moment the session really ends or the service it reaches changes, and keep its session polled while
// it is open however long it sits idle.
type nativeConn struct {
	key       string
	serviceID string
	target    nativeTarget
	kind      string
	ctx       context.Context
	cancel    context.CancelFunc
	release   sync.Once
}

var errNativeServiceChanged = errors.New("the service changed while the connection was being opened, try again")

// registerNative admits a connection for svc only if the session's cache entry still holds that service as it was
// looked up, so a revoke or an edit that landed in between can't leave a connection nothing will close.
func (c *sessionCache) registerNative(sessionToken string, svc *resolvedService) (*nativeConn, error) {
	key := sessionKey(sessionToken)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok || (entry.expiresAt != nil && time.Now().After(*entry.expiresAt)) {
		return nil, errSessionGone
	}
	current := findServiceByID(entry.services, svc.id)
	if current == nil || current.native == nil || svc.native == nil || current.kind != svc.kind || !current.native.equal(*svc.native) {
		return nil, errNativeServiceChanged
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := &nativeConn{
		key:       key,
		serviceID: svc.id,
		target:    *svc.native,
		kind:      svc.kind,
		ctx:       ctx,
		cancel:    cancel,
	}
	if c.native == nil {
		c.native = make(map[string]map[*nativeConn]struct{})
	}
	if c.native[key] == nil {
		c.native[key] = make(map[*nativeConn]struct{})
	}
	c.native[key][conn] = struct{}{}
	// The token stays known while the connection is open, so the poll loop keeps asking about the session.
	c.tokens[key] = sessionToken
	c.nativeOpen.Add(1)
	return conn, nil
}

func (c *sessionCache) releaseNative(conn *nativeConn) {
	conn.release.Do(func() {
		conn.cancel()
		c.mu.Lock()
		if conns := c.native[conn.key]; conns != nil {
			delete(conns, conn)
			if len(conns) == 0 {
				delete(c.native, conn.key)
				// Nothing pins the session any more; an entry that went away while it was pinned leaves its token.
				if _, ok := c.entries[conn.key]; !ok {
					delete(c.tokens, conn.key)
				}
			}
		}
		c.mu.Unlock()
		c.nativeOpen.Done()
	})
}

func (c *sessionCache) pinnedLocked(key string) bool {
	return len(c.native[key]) > 0
}

// The session really ended, so every connection it opened closes. Cancelling never blocks: each connection closes
// itself on its own goroutine.
func (c *sessionCache) endNativeLocked(key string) {
	for conn := range c.native[key] {
		conn.cancel()
	}
}

// A connection survives a new resolve only if its service is still there and still points at the same server.
// A rotated password or a member clearing their personal values leaves it open: the login is already made, and new
// connections use the new values or are refused.
func (c *sessionCache) applyNativeLocked(key string, services []*resolvedService) {
	for conn := range c.native[key] {
		current := findServiceByID(services, conn.serviceID)
		if current == nil || current.native == nil || current.kind != conn.kind || !current.native.equal(conn.target) {
			conn.cancel()
		}
	}
}

// forgetLocked drops a session from the cache. A pinned session keeps its token so the poll loop still asks about
// it; only a real ending, which also cancels its connections, drops the token of a pinned session.
func (c *sessionCache) forgetLocked(key string, ended bool) {
	delete(c.entries, key)
	if ended {
		c.endNativeLocked(key)
		delete(c.tokens, key)
		return
	}
	if !c.pinnedLocked(key) {
		delete(c.tokens, key)
	}
}

// closeNative cancels every connection and waits up to timeout for them to finish, so their last session log rows
// are recorded before the session logs close.
func (c *sessionCache) closeNative(timeout time.Duration) {
	c.mu.Lock()
	for key := range c.native {
		c.endNativeLocked(key)
	}
	c.mu.Unlock()

	done := make(chan struct{})
	go func() {
		c.nativeOpen.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func findServiceByID(services []*resolvedService, id string) *resolvedService {
	for _, svc := range services {
		if svc.id == id {
			return svc
		}
	}
	return nil
}
