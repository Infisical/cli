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
		OutputMasker:  masking.New([]*regexp.Regexp{regexp.MustCompile(`token=\w+`)}, false, nil, "sid"),
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
