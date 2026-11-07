package webapp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestMuxConcurrentWritesAndBounds(t *testing.T) {
	var buf bytes.Buffer
	mux := NewMux(nil, &buf)
	var wg sync.WaitGroup
	for n := range 100 {
		wg.Go(func() {
			if err := mux.Control(map[string]any{"c": "test", "n": n}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	reader := NewMux(&buf, io.Discard)
	for range 100 {
		channel, payload, err := reader.Read()
		if err != nil || channel != MuxControl || len(payload) == 0 {
			t.Fatalf("corrupt serialized message: %d %q %v", channel, payload, err)
		}
	}
	for _, channel := range []byte{MuxCDP, MuxControl, 9} {
		t.Run(fmt.Sprint(channel), func(t *testing.T) {
			var h [5]byte
			h[0] = channel
			binary.BigEndian.PutUint32(h[1:], uint32(muxLimit(channel)+1))
			if _, _, err := NewMux(bytes.NewReader(h[:]), io.Discard).Read(); err == nil {
				t.Fatal("oversized mux header accepted")
			}
		})
	}
}

func TestMuxSplitReads(t *testing.T) {
	var buf bytes.Buffer
	writer := NewMux(nil, &buf)
	if err := writer.Write(MuxCDP, []byte(`{"id":1}`)); err != nil {
		t.Fatal(err)
	}
	reader := NewMux(&oneByteReader{Reader: &buf}, io.Discard)
	_, b, err := reader.Read()
	if err != nil || string(b) != `{"id":1}` {
		t.Fatalf("%s %v", b, err)
	}
}

type oneByteReader struct{ io.Reader }

func (r *oneByteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), 1)]) }
