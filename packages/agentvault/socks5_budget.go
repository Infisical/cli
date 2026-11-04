package agentvault

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Infisical allows a proxy about 70 resolves a second, shared by every machine running it and by the refreshes
// of sessions it already knows. The SOCKS5 port faces the internet, where anyone can send a password shaped
// like a session token, so lookups of tokens the proxy hasn't seen get a budget well under that.
const (
	socks5MissesPerSecond        = 20
	socks5MissBurst              = 40
	socks5SuspectRefusals        = 10
	socks5SuspectWindow          = time.Minute
	socks5SuspectMissesPerSecond = 1
	socks5MaxTrackedIPs          = 4096
)

var errResolveBudget = errors.New("too many logins with unknown session tokens; try again shortly")

// missBudget throttles lookups of unknown tokens. An address whose recent logins all failed gets a small share
// rather than a block, because E2B's egress addresses are shared by many customers' sandboxes.
type missBudget struct {
	global *rate.Limiter

	mu  sync.Mutex
	ips map[string]*ipRecord
}

type ipRecord struct {
	windowStart time.Time
	refusals    int
	lastSuccess time.Time
	limiter     *rate.Limiter
}

func newMissBudget(perSecond float64, burst int) *missBudget {
	return &missBudget{global: rate.NewLimiter(rate.Limit(perSecond), burst), ips: make(map[string]*ipRecord)}
}

func (r *ipRecord) suspect(now time.Time) bool {
	return now.Sub(r.windowStart) < socks5SuspectWindow &&
		r.refusals >= socks5SuspectRefusals &&
		now.Sub(r.lastSuccess) >= socks5SuspectWindow
}

// admit reports whether a lookup of an unknown token from ip may go to Infisical now.
func (b *missBudget) admit(ip string) bool {
	b.mu.Lock()
	var limiter *rate.Limiter
	if rec := b.ips[ip]; rec != nil && rec.suspect(time.Now()) {
		if rec.limiter == nil {
			rec.limiter = rate.NewLimiter(socks5SuspectMissesPerSecond, 1)
		}
		limiter = rec.limiter
	}
	b.mu.Unlock()
	if limiter != nil && !limiter.Allow() {
		return false
	}
	return b.global.Allow()
}

// record notes how a login from ip went. Only a session Infisical says is gone counts against the address:
// an unreachable Infisical or a spent budget says nothing about the client.
func (b *missBudget) record(ip string, err error) {
	success := err == nil
	if !success && !isSessionGone(err) {
		return
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	rec := b.ips[ip]
	if rec == nil {
		if len(b.ips) >= socks5MaxTrackedIPs {
			b.evictStaleLocked(now)
			if len(b.ips) >= socks5MaxTrackedIPs {
				return
			}
		}
		rec = &ipRecord{windowStart: now}
		b.ips[ip] = rec
	}
	if success {
		rec.lastSuccess = now
		return
	}
	if now.Sub(rec.windowStart) >= socks5SuspectWindow {
		rec.windowStart, rec.refusals, rec.limiter = now, 0, nil
	}
	rec.refusals++
}

func (b *missBudget) evictStaleLocked(now time.Time) {
	for ip, rec := range b.ips {
		if now.Sub(rec.windowStart) >= socks5SuspectWindow && now.Sub(rec.lastSuccess) >= socks5SuspectWindow {
			delete(b.ips, ip)
		}
	}
}
