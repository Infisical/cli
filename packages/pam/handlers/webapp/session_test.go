package webapp

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func startReader(t *testing.T) (net.Conn, chan clientMessage, *atomic.Int32, chan error) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	var activity atomic.Int32
	s := &browserSession{sessionID: "s", conn: server, onActivity: func() { activity.Add(1) }}
	inputs := make(chan clientMessage, 1024)
	done := make(chan error, 1)
	go func() { done <- s.readInput(context.Background(), inputs) }()
	return client, inputs, &activity, done
}

func waitErr(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not stop")
		return nil
	}
}

func TestReadInputRateLimitsAndCountsActivity(t *testing.T) {
	client, inputs, activity, done := startReader(t)
	var burst []byte
	for range 500 {
		burst = append(burst, clientFrame(frameTypeJSON, `{"type":"mouse","action":"move","x":1,"y":1}`)...)
	}
	if _, err := client.Write(burst); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := waitErr(t, done); !errors.Is(err, errViewerClosed) {
		t.Fatalf("err = %v, want viewer closed", err)
	}
	if n := activity.Load(); n != 500 {
		t.Errorf("activity = %d, want 500", n)
	}
	if n := len(inputs); n < inputRate || n > inputRate+50 {
		t.Errorf("accepted %d of 500 messages, want about %d", n, inputRate)
	}
}

func TestReadInputDropsUnreadableJSON(t *testing.T) {
	client, inputs, _, done := startReader(t)
	stream := append(clientFrame(frameTypeJSON, `{not json`), clientFrame(frameTypeJSON, `{"type":"whatever"}`)...)
	if _, err := client.Write(stream); err != nil {
		t.Fatal(err)
	}
	client.Close()
	waitErr(t, done)
	if len(inputs) != 1 || (<-inputs).Type != "whatever" {
		t.Error("unreadable JSON was not dropped, or a later message was lost")
	}
}

func TestReadInputEndsOnInvalidFrame(t *testing.T) {
	client, _, _, done := startReader(t)
	go client.Write(clientFrame(frameTypeJPEG, "x"))
	if err := waitErr(t, done); !errors.Is(err, errInvalidFrame) {
		t.Fatalf("err = %v, want invalid frame", err)
	}
}
