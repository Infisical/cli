package ssh

import (
	"bytes"
	"io"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
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
		OutputMaskingPatterns: []masking.Matcher{
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

func TestMaskedOutputMatchesInsideTerminalTitles(t *testing.T) {
	src, w := io.Pipe()
	out := &lockedBuffer{}
	go func() {
		_, _ = w.Write([]byte("\x1b]0;token=abcd123\x07\n"))
		_ = w.Close()
	}()

	if err := newOutputMaskingProxy().proxyData(src, out, "server→client", "sid", false, newChannelState()); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "\x1b]0;[MASKED]\x07\n"; got != want {
		t.Fatalf("client saw %q, want %q", got, want)
	}
}
