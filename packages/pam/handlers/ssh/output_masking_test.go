package ssh

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type lockedBuffer struct {
	mutex sync.Mutex
	buf   bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buf.String()
}

func newOutputMaskingProxy() *SSHProxy {
	return NewSSHProxy(SSHProxyConfig{
		SessionID:     "sid",
		SessionLogger: &recordingLogger{},
		OutputMaskingPatterns: []*regexp.Regexp{
			regexp.MustCompile(`token=\w+`),
			regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
		},
	})
}

func TestMaskedOutputMatchesAValueSplitAcrossReads(t *testing.T) {
	src, w := io.Pipe()
	out := &lockedBuffer{}
	go func() {
		_, _ = w.Write([]byte("value token=ab"))
		time.Sleep(maskedOutputQuietPeriod / 5)
		_, _ = w.Write([]byte("cd123 end\nprompt$ "))
		_ = w.Close()
	}()

	if err := newOutputMaskingProxy().proxyData(src, out, "server→client", "sid", false, newChannelState()); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "value [MASKED] end\nprompt$ " {
		t.Fatalf("client saw %q", got)
	}
}

func TestMaskedOutputSendsAPartialLineOnceQuiet(t *testing.T) {
	src, w := io.Pipe()
	out := &lockedBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- newOutputMaskingProxy().proxyData(src, out, "server→client", "sid", false, newChannelState())
	}()

	_, _ = w.Write([]byte("prompt$ "))
	time.Sleep(4 * maskedOutputQuietPeriod)
	if got := out.String(); got != "prompt$ " {
		t.Fatalf("client saw %q before closing, want the prompt", got)
	}
	_ = w.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMaskedOutputMatchesThroughColorCodes(t *testing.T) {
	line := "1,Jane,jane\x1b[01;31m\x1b[K@\x1b[m\x1b[Kacme.com,123\n"
	src, w := io.Pipe()
	out := &lockedBuffer{}
	go func() {
		_, _ = w.Write([]byte(line))
		_ = w.Close()
	}()

	if err := newOutputMaskingProxy().proxyData(src, out, "server→client", "sid", false, newChannelState()); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "1,Jane,[MASKED]\x1b[01;31m\x1b[K\x1b[m\x1b[K,123\n"; got != want {
		t.Fatalf("client saw %q, want %q", got, want)
	}
}

func TestMaskedOutputDoesNotRecordAHeldEchoTwice(t *testing.T) {
	logger := &recordingLogger{}
	proxy := NewSSHProxy(SSHProxyConfig{
		SessionID:             "sid",
		SessionLogger:         logger,
		OutputMaskingPatterns: []*regexp.Regexp{regexp.MustCompile(`token=\w+`)},
	})
	chState := newChannelState()
	chState.channelType = session.SessionChannelShell
	chState.inputChannelType = session.SessionChannelShell

	src, w := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- proxy.proxyData(src, io.Discard, "server→client", "sid", false, chState) }()

	_, _ = w.Write([]byte("$ "))
	time.Sleep(4 * maskedOutputQuietPeriod)
	proxy.bufferInput([]byte("ls"), "sid", session.SessionChannelShell, chState)
	_, _ = w.Write([]byte("ls"))
	time.Sleep(maskedOutputQuietPeriod / 5)
	proxy.bufferInput([]byte{0x0D}, "sid", session.SessionChannelShell, chState)
	_, _ = w.Write([]byte("\r\nfile.txt\r\n$ "))
	_ = w.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	recorded := 0
	logger.mutex.Lock()
	for _, event := range logger.events {
		if strings.Contains(string(event.Data), "ls") {
			recorded++
		}
	}
	logger.mutex.Unlock()
	if recorded != 1 {
		t.Fatalf("command recorded %d times, want once: %+v", recorded, logger.events)
	}
}
