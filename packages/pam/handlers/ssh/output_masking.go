package ssh

import (
	"bytes"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
)

func (p *SSHProxy) masksOutput() bool {
	return len(p.config.OutputMaskingPatterns) > 0
}

const maskedOutputQuietPeriod = 25 * time.Millisecond

const maxHeldOutput = 64 * 1024

// Masks a line at a time so a value split across reads still matches; a partial line waits until output goes quiet.
func (p *SSHProxy) proxyMaskedOutput(src io.Reader, dst io.Writer, sessionID string, chState *channelState) error {
	defer p.flushOutputBuffer(sessionID, chState)

	type chunk struct {
		data []byte
		err  error
	}
	reads := make(chan chunk)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			buf := make([]byte, 32*1024)
			n, err := src.Read(buf)
			select {
			case reads <- chunk{buf[:n], err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	emit := func(data []byte) error {
		if len(data) == 0 {
			return nil
		}
		masked := maskTerminalOutput(p.config.OutputMaskingPatterns, data)
		chState.mutex.Lock()
		channelType := chState.channelType
		chState.mutex.Unlock()
		p.bufferOutput(masked, sessionID, channelType, chState)
		_, err := dst.Write(masked)
		return err
	}

	var pending []byte
	for {
		var quiet <-chan time.Time
		if len(pending) > 0 {
			quiet = time.After(maskedOutputQuietPeriod)
		}
		select {
		case c := <-reads:
			if len(c.data) > 0 && p.config.OnActivity != nil {
				p.config.OnActivity()
			}
			pending = append(pending, c.data...)
			cut := bytes.LastIndexAny(pending, "\r\n") + 1
			if c.err != nil || len(pending)-cut > maxHeldOutput {
				cut = len(pending)
			}
			if err := emit(pending[:cut]); err != nil {
				return err
			}
			pending = append(pending[:0], pending[cut:]...)
			chState.outputHeld.Store(int64(len(pending)))
			if c.err == io.EOF {
				return nil
			}
			if c.err != nil {
				return c.err
			}
		case <-quiet:
			if err := emit(pending); err != nil {
				return err
			}
			pending = pending[:0]
			chState.outputHeld.Store(0)
		}
	}
}

// Skips escape sequences when matching so color can't split a value, and keeps them after the placeholder.
func maskTerminalOutput(patterns []*regexp.Regexp, data []byte) []byte {
	plain := make([]byte, 0, len(data))
	offsets := make([]int, 0, len(data))
	for i := 0; i < len(data); {
		if data[i] == 0x1b {
			i += escapeLength(data, i)
			continue
		}
		plain = append(plain, data[i])
		offsets = append(offsets, i)
		i++
	}

	var spans [][2]int
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllIndex(plain, -1) {
			if match[1] > match[0] {
				spans = append(spans, [2]int{match[0], match[1]})
			}
		}
	}
	if len(spans) == 0 {
		return data
	}
	sort.Slice(spans, func(a, b int) bool { return spans[a][0] < spans[b][0] })

	out := make([]byte, 0, len(data))
	last := 0
	for i := 0; i < len(spans); {
		start, end := spans[i][0], spans[i][1]
		for i++; i < len(spans) && spans[i][0] <= end; i++ {
			end = max(end, spans[i][1])
		}
		from, to := offsets[start], offsets[end-1]+1
		out = append(out, data[last:from]...)
		out = append(out, masking.Placeholder...)
		for j := from; j < to; {
			if data[j] == 0x1b {
				n := escapeLength(data, j)
				out = append(out, data[j:j+n]...)
				j += n
				continue
			}
			j++
		}
		last = to
	}
	return append(out, data[last:]...)
}

func escapeLength(data []byte, i int) int {
	j := i + 1
	if j >= len(data) {
		return 1
	}
	switch data[j] {
	case '[':
		j++
		for j < len(data) && data[j] >= 0x20 && data[j] <= 0x3f {
			j++
		}
		if j < len(data) && data[j] >= 0x40 && data[j] <= 0x7e {
			j++
		}
		return j - i
	case ']', 'P', 'X', '^', '_':
		for j++; j < len(data); j++ {
			if data[j] == 0x07 {
				return j + 1 - i
			}
			if data[j] == 0x1b && j+1 < len(data) && data[j+1] == '\\' {
				return j + 2 - i
			}
		}
		return len(data) - i
	}
	return 2
}
