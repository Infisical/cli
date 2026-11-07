package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type cdpMessage struct {
	receivedAt  time.Time
	queuedBytes int64
	ID          uint64          `json:"id,omitzero"`
	Method      string          `json:"method,omitempty"`
	SessionID   string          `json:"sessionId,omitempty"`
	Params      json.RawMessage `json:"params,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       *struct {
		Code    int
		Message string
	} `json:"error,omitempty"`
}

type cdpClient struct {
	queuedBytes atomic.Int64
	mux         *Mux
	next        atomic.Uint64
	mu          sync.Mutex
	pending     map[uint64]chan cdpMessage
	events      chan cdpMessage
	controls    chan json.RawMessage
	done        chan struct{}
	err         error
}

func newCDP(mux *Mux) *cdpClient {
	c := &cdpClient{mux: mux, pending: map[uint64]chan cdpMessage{}, events: make(chan cdpMessage, 512), controls: make(chan json.RawMessage, 256), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			ch, b, err := mux.Read()
			if err != nil {
				c.mu.Lock()
				c.err = err
				c.mu.Unlock()
				return
			}
			if ch == MuxControl {
				select {
				case c.controls <- b:
				default:
					c.mu.Lock()
					c.err = errors.New("worker control overflow")
					c.mu.Unlock()
					return
				}
				continue
			}
			var msg cdpMessage
			if err := json.Unmarshal(b, &msg); err != nil {
				c.mu.Lock()
				c.err = err
				c.mu.Unlock()
				return
			}
			msg.receivedAt = time.Now()
			if msg.ID != 0 {
				c.mu.Lock()
				pending := c.pending[msg.ID]
				c.mu.Unlock()
				if pending != nil {
					select {
					case pending <- msg:
					default:
						c.mu.Lock()
						c.err = errors.New("duplicate CDP response")
						c.mu.Unlock()
						return
					}
				}
				continue
			}
			switch msg.Method {
			case "Target.attachedToTarget", "Target.detachedFromTarget", "Target.targetInfoChanged", "Page.screencastFrame", "Fetch.requestPaused", "Fetch.authRequired", "Page.frameNavigated", "Page.javascriptDialogOpening":
			default:
				continue
			}
			msg.queuedBytes = int64(len(b))
			if c.queuedBytes.Add(msg.queuedBytes) > 32<<20 {
				c.mu.Lock()
				c.err = errors.New("CDP event byte budget exceeded")
				c.mu.Unlock()
				return
			}
			select {
			case c.events <- msg:
			default:
				c.mu.Lock()
				c.err = errors.New("CDP event overflow")
				c.mu.Unlock()
				return
			}
		}
	}()
	return c
}

func (c *cdpClient) begin(ctx context.Context, session, method string, params any) (func(any) error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := c.next.Add(1)
	ch := make(chan cdpMessage, 1)
	cleanup := func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	stop := context.AfterFunc(ctx, cleanup)
	fail := func(err error) (func(any) error, error) { stop(); cleanup(); return nil, err }
	p, err := json.Marshal(params)
	if err != nil {
		return fail(err)
	}
	b, err := json.Marshal(cdpMessage{ID: id, SessionID: session, Method: method, Params: p})
	if err != nil {
		return fail(err)
	}
	written := make(chan error, 1)
	go func() { written <- c.mux.Write(MuxCDP, b) }()
	select {
	case err := <-written:
		if err != nil {
			return fail(err)
		}
	case <-ctx.Done():
		return fail(ctx.Err())
	case <-c.done:
		return fail(errors.New("CDP closed"))
	}
	return func(result any) error {
		defer stop()
		defer cleanup()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			c.mu.Lock()
			defer c.mu.Unlock()
			return fmt.Errorf("CDP closed: %w", c.err)
		case msg := <-ch:
			if msg.Error != nil {
				return fmt.Errorf("CDP %s: %s", method, msg.Error.Message)
			}
			if result != nil {
				return json.Unmarshal(msg.Result, result)
			}
			return nil
		}
	}, nil
}

func (c *cdpClient) call(ctx context.Context, session, method string, params, result any) error {
	wait, err := c.begin(ctx, session, method, params)
	if err != nil {
		return err
	}
	return wait(result)
}
