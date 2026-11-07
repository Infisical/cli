package webapp

import (
	"encoding/json"
	"errors"
	"github.com/rs/zerolog/log"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type liveStream struct {
	closeErr        error
	quiesced        atomic.Bool
	conn            net.Conn
	reader          io.Reader
	gen             uint32
	seq             uint32
	mu              sync.Mutex
	controls        [][]byte
	frames          [][]byte
	frameBytes      int
	dropped         uint64
	notify          chan struct{}
	done            chan struct{}
	closeOnce       sync.Once
	closeAfterWrite bool
}

func newStream(conn net.Conn, reader io.Reader, gen uint32) *liveStream {
	v := &liveStream{conn: conn, reader: reader, gen: gen, notify: make(chan struct{}, 1), done: make(chan struct{})}
	go v.writeLoop()
	return v
}

func (v *liveStream) close() {
	v.quiesced.Store(true)
	v.closeOnce.Do(func() { close(v.done); v.conn.Close() })
}
func (v *liveStream) send(message any) { v.enqueue(ControlFrame(message), false) }

func (v *liveStream) flushClose() {
	v.mu.Lock()
	v.frames = nil
	v.frameBytes = 0
	v.closeAfterWrite = true
	queued := len(v.controls) > 0
	v.mu.Unlock()
	if !queued {
		v.close()
		return
	}
	select {
	case v.notify <- struct{}{}:
	default:
	}
	select {
	case <-v.done:
	case <-time.After(time.Second):
		v.close()
	}
}

func (v *liveStream) droppedFrames() uint64 { v.mu.Lock(); defer v.mu.Unlock(); return v.dropped }
func (v *liveStream) enqueue(b []byte, frame bool) {
	v.mu.Lock()
	select {
	case <-v.done:
		v.mu.Unlock()
		return
	default:
	}
	if frame {
		for len(v.frames) > 0 && (len(v.frames) >= 6 || v.frameBytes+len(b) > 4<<20) {
			v.frameBytes -= len(v.frames[0])
			v.frames = v.frames[1:]
			v.dropped++
		}
		v.frames = append(v.frames, b)
		v.frameBytes += len(b)
	} else if len(v.controls) >= 256 {
		v.controls = [][]byte{ControlFrame(map[string]string{"t": "error", "code": "slow-reader", "message": "control queue exceeded"})}
		v.frames = nil
		v.frameBytes = 0
		v.closeAfterWrite = true
	} else {
		v.controls = append(v.controls, b)
	}
	v.mu.Unlock()
	select {
	case v.notify <- struct{}{}:
	default:
	}
}

func (v *liveStream) writeLoop() {
	defer v.close()
	for {
		select {
		case <-v.done:
			return
		case <-v.notify:
		}
		for {
			v.mu.Lock()
			var b []byte
			if len(v.controls) > 0 {
				b = v.controls[0]
				v.controls = v.controls[1:]
			} else if len(v.frames) > 0 {
				b = v.frames[0]
				v.frames = v.frames[1:]
				v.frameBytes -= len(b)
			}
			end := v.closeAfterWrite && len(v.controls) == 0 && len(v.frames) == 0
			v.mu.Unlock()
			if b == nil {
				break
			}
			_ = v.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if v.writeFrame(b, 30*time.Second) != nil {
				return
			}
			if b[0] == Control {
				var control struct {
					T          string `json:"t"`
					DialogSeq  uint32 `json:"dialogSeq"`
					SurfaceSeq uint32 `json:"surfaceSeq"`
				}
				if json.Unmarshal(b[1:], &control) == nil && control.T == "dialog" {
					log.Debug().Uint32("controllerGen", v.gen).Uint32("dialogSeq", control.DialogSeq).Uint32("surfaceSeq", control.SurfaceSeq).Msg("PAM browser dialog delivered")
				}
			}
			if end {
				return
			}
		}
	}
}

func (v *liveStream) writeFrame(frame []byte, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() { result <- WriteFrame(v.conn, frame) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		err := errors.New("slow-reader")
		v.mu.Lock()
		v.closeErr = err
		v.mu.Unlock()
		log.Warn().Str("code", "slow-reader").Uint32("controllerGen", v.gen).Msg("PAM browser stream closed")
		v.close()
		return err
	case <-v.done:
		return errors.New("stream closed")
	}
}

func (v *liveStream) readError(err error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closeErr != nil {
		return v.closeErr
	}
	return err
}
