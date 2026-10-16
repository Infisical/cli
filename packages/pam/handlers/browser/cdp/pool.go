package cdp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/browser"
	"github.com/rs/zerolog/log"
)

var (
	ErrAtCapacity = browser.ErrAtCapacity
	ErrPoolClosed = errors.New("browser pool is closed")
)

const (
	defaultMaxInstances = 10
	defaultWarmIdle     = 10 * time.Minute
)

type PoolConfig struct {
	MaxInstances  int // warm browsers included
	Warm          int
	WarmIdle      time.Duration
	LaunchOptions LaunchOptions
}

// A browser is never reused across sessions.
type Pool struct {
	launcher Launcher
	config   PoolConfig
	ctx      context.Context
	cancel   context.CancelFunc

	mu        sync.Mutex
	warm      []*warmInstance
	active    int // handed out and not yet stopped
	launching int // warm launches in flight
	closed    bool
}

type warmInstance struct {
	instance *Instance
	taken    chan struct{}
}

func NewPool(launcher Launcher, config PoolConfig) *Pool {
	if config.MaxInstances <= 0 {
		config.MaxInstances = defaultMaxInstances
	}
	if config.WarmIdle <= 0 {
		config.WarmIdle = defaultWarmIdle
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{launcher: launcher, config: config, ctx: ctx, cancel: cancel}
	go p.refill()
	return p
}

// The caller must Stop the browser, which frees its slot.
func (p *Pool) Acquire(ctx context.Context) (*Instance, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	for len(p.warm) > 0 {
		w := p.warm[0]
		p.warm = p.warm[1:]
		close(w.taken)
		select {
		case <-w.instance.Done():
			// Crashed while idle, before its watcher dropped it.
			go w.instance.Stop()
			continue
		default:
		}
		p.active++
		p.mu.Unlock()
		go p.refill()
		return p.handOut(w.instance), nil
	}
	if p.active+len(p.warm)+p.launching >= p.config.MaxInstances {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w (%d)", ErrAtCapacity, p.config.MaxInstances)
	}
	p.active++
	p.mu.Unlock()

	instance, err := p.launcher.Launch(ctx, p.config.LaunchOptions)
	if err != nil {
		p.release()
		return nil, err
	}
	go p.refill()
	return p.handOut(instance), nil
}

// Browsers already handed out are stopped by their sessions.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	warm := p.warm
	p.warm = nil
	p.mu.Unlock()

	p.cancel()
	for _, w := range warm {
		close(w.taken)
		w.instance.Stop()
	}
}

func (p *Pool) handOut(instance *Instance) *Instance {
	return &Instance{
		CDPURL: instance.CDPURL,
		done:   instance.done,
		stop: func() {
			instance.Stop()
			p.release()
		},
	}
}

func (p *Pool) release() {
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	go p.refill()
}

func (p *Pool) refill() {
	for {
		p.mu.Lock()
		if p.closed ||
			len(p.warm)+p.launching >= p.config.Warm ||
			p.active+len(p.warm)+p.launching >= p.config.MaxInstances {
			p.mu.Unlock()
			return
		}
		p.launching++
		p.mu.Unlock()

		instance, err := p.launcher.Launch(p.ctx, p.config.LaunchOptions)

		p.mu.Lock()
		p.launching--
		if err != nil {
			p.mu.Unlock()
			if p.ctx.Err() == nil {
				log.Warn().Err(err).Msg("Failed to pre-warm browser")
			}
			return
		}
		if p.closed {
			p.mu.Unlock()
			instance.Stop()
			return
		}
		w := &warmInstance{instance: instance, taken: make(chan struct{})}
		p.warm = append(p.warm, w)
		p.mu.Unlock()
		go p.watchWarm(w)
	}
}

func (p *Pool) watchWarm(w *warmInstance) {
	timer := time.NewTimer(p.config.WarmIdle)
	defer timer.Stop()
	select {
	case <-w.taken:
		return
	case <-timer.C:
	case <-w.instance.Done():
	}

	p.mu.Lock()
	removed := false
	for i, candidate := range p.warm {
		if candidate == w {
			p.warm = append(p.warm[:i], p.warm[i+1:]...)
			removed = true
			break
		}
	}
	p.mu.Unlock()
	if removed {
		w.instance.Stop()
	}
}
