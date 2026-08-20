package ssh

import (
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

const (
	esc = "\x1b"
	bel = "\x07"
)

// Default bash PS1: an OSC title whose payload holds '@', ':', ' ' and '/'.
func prompt(cwd string) string {
	return esc + "]0;user@host: " + cwd + bel +
		esc + "[01;32muser@host" + esc + "[00m:" + esc + "[01;34m" + cwd + esc + "[00m$ "
}

func render(chunks ...string) []string {
	t := newTerminalTranscript()
	var got []string
	for _, c := range chunks {
		got = append(got, t.Feed([]byte(c))...)
	}
	return append(got, t.Flush()...)
}

func TestTerminalTranscript(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   []string
	}{
		{"osc title and coloured prompt", []string{prompt("~") + "ls\r\n"}, []string{"user@host:~$ ls"}},
		{"osc payload split across reads", []string{esc + "]0;user@ho", "st: ~" + bel + "$ id\n"}, []string{"$ id"}},
		{"csi split across reads", []string{"ab" + esc + "[", "1;32mcd\n"}, []string{"abcd"}},
		{"osc terminated by st", []string{esc + "]0;user@host: /var" + esc + "\\done\n"}, []string{"done"}},
		{"charset designator", []string{esc + "(B" + esc + "[m% ls\n"}, []string{"% ls"}},
		{"redraw overwrites", []string{prompt("~") + "\r" + prompt("~") + "ls\r\n"}, []string{"user@host:~$ ls"}},
		{"erase line after redraw", []string{"cat f\rls" + esc + "[K\n"}, []string{"ls"}},
		{"backspace echo", []string{"lsx\b \bs\n"}, []string{"lss"}},
		{"tabs and blank lines", []string{"a\tb\n\r\n\r\nc\n"}, []string{"a       b", "c"}},
		{"vertical move commits", []string{"one" + esc + "[2Btwo\n"}, []string{"one", "two"}},
		{"clear screen drops pending", []string{"stale" + esc + "[2Jfresh\n"}, []string{"fresh"}},
		{"multibyte rune split", []string{"caf\xc3", "\xa9 \xe2\x9c\x93\n"}, []string{"café ✓"}},
		{"cursor moves and edits", []string{"abcdef" + esc + "[3D" + esc + "[2P\n", "ab" + esc + "[4Ccd\n"}, []string{"abcf", "ab    cd"}},
		{"unterminated osc recovers", []string{esc + "]0;no terminator", esc + "[0mrecovered\n"}, []string{"recovered"}},
		{"overlong line wraps instead of dropping", []string{strings.Repeat("a", maxLineRunes) + "bb\n"},
			[]string{strings.Repeat("a", maxLineRunes), "bb"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := render(tt.chunks...); !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTranscriptBoundsPathologicalInput(t *testing.T) {
	tr := newTerminalTranscript()
	tr.Feed([]byte(strings.Repeat("x", 100_000)))
	tr.Feed([]byte(esc + "[999999999999C" + esc + "[999999999999@"))

	// Insert-character returned to column zero must not extend the line each time.
	tr.Feed([]byte(strings.Repeat("a", maxLineRunes)))
	for range 8 {
		tr.Feed([]byte("\r" + esc + "[8192@"))
	}

	if n := len(tr.line); n > maxLineRunes {
		t.Errorf("line grew to %d runes, want at most %d", n, maxLineRunes)
	}
}

type recordingLogger struct {
	mutex  sync.Mutex
	events []session.SessionEvent
}

func (l *recordingLogger) LogEntry(session.SessionLogEntry) error { return nil }
func (l *recordingLogger) LogHttpEvent(session.HttpEvent) error   { return nil }
func (l *recordingLogger) Close() error                           { return nil }

func (l *recordingLogger) LogSessionEvent(event session.SessionEvent) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.events = append(l.events, event)
	return nil
}

// typeLine models interactive typing: the shell echoes each keystroke before Enter.
func typeLine(p *SSHProxy, ch *channelState, channel session.SessionChannelType, text string) {
	p.bufferInput([]byte(text), "sid", channel, ch)
	if channel == session.SessionChannelShell {
		emit(p, ch, text)
	}
	p.bufferInput([]byte{0x0D}, "sid", channel, ch)
}

// typeSilently models a prompt with echo off: nothing comes back while typing.
func typeSilently(p *SSHProxy, ch *channelState, text string) {
	p.bufferInput([]byte(text), "sid", session.SessionChannelShell, ch)
	p.bufferInput([]byte{0x0D}, "sid", session.SessionChannelShell, ch)
}

func emit(p *SSHProxy, ch *channelState, text string) {
	p.bufferOutput([]byte(text), "sid", session.SessionChannelShell, ch)
}

func TestSessionRecording(t *testing.T) {
	shell := session.SessionChannelShell

	tests := []struct {
		name  string
		steps func(p *SSHProxy, ch *channelState)
		want  []string
	}{
		{
			name: "echo replaces the command event",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "ls")
				emit(p, ch, "\r\nLICENSE go\r\n"+prompt("~"))
			},
			want: []string{"output: user@host:~$ ls", "output: LICENSE go", "output: user@host:~$"},
		},
		{
			name: "tab completion counts as echoed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~/cli"))
				typeLine(p, ch, shell, "cd ..")
				emit(p, ch, "/\r\n")
			},
			want: []string{"output: user@host:~/cli$ cd ../"},
		},
		{
			name: "paste arriving with its newline counts as echoed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte("cd ../cli\r"), "sid", shell, ch)
				emit(p, ch, "cd ../cli\r\n")
			},
			want: []string{"output: user@host:~$ cd ../cli"},
		},
		{
			name: "unechoed input is recorded when it is typed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeSilently(p, ch, "whoami")
				emit(p, ch, "\r\nroot\r\n")
			},
			want: []string{"output: user@host:~$", "input: whoami", "output: root"},
		},
		{
			name: "multi-line paste counts as echoed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte("cd cli\nls\n"), "sid", shell, ch)
				emit(p, ch, "cd cli\r\n"+prompt("~/cli")+"ls\r\nLICENSE go\r\n")
			},
			want: []string{
				"output: user@host:~$ cd cli",
				"output: user@host:~/cli$ ls",
				"output: LICENSE go",
			},
		},
		{
			name: "input at a prompt that does not echo is recorded",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~")+"read -s -p \"Enter name: \" x\r\nEnter name: ")
				typeSilently(p, ch, "operator")
				emit(p, ch, "\r\nok\r\n")
			},
			want: []string{
				"output: user@host:~$ read -s -p \"Enter name: \" x",
				"output: Enter name:",
				"input: operator",
				"output: ok",
			},
		},
		{
			name:  "exec channel logs its command immediately",
			steps: func(p *SSHProxy, ch *channelState) { typeLine(p, ch, session.SessionChannelExec, "uname -a") },
			want:  []string{"input: uname -a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &recordingLogger{}
			p := NewSSHProxy(SSHProxyConfig{SessionLogger: logger})
			ch := newChannelState()

			tt.steps(p, ch)
			p.flushOutputBuffer("sid", ch)
			p.flushPendingEcho("sid", ch)

			got := make([]string, len(logger.events))
			for i, e := range logger.events {
				if !e.Rendered || e.Timestamp.IsZero() {
					t.Errorf("event %d (%q) lacks the rendered flag or a timestamp", i, e.Data)
				}
				got[i] = string(e.EventType) + ": " + string(e.Data)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConcurrentChannelsKeepSeparateTranscripts(t *testing.T) {
	p := NewSSHProxy(SSHProxyConfig{SessionLogger: &recordingLogger{}})

	var wg sync.WaitGroup
	for range 8 {
		ch := newChannelState()
		wg.Go(func() {
			for range 200 {
				typeLine(p, ch, session.SessionChannelShell, "ls -la")
			}
		})
		wg.Go(func() {
			for range 200 {
				emit(p, ch, prompt("~")+"ls -la\r\ntotal 0\r\n")
				p.flushOutputBuffer("sid", ch)
			}
		})
	}
	wg.Wait()
}

// Channel state must not be shared: input has to stay attributed to its own channel.
func TestChannelsRecordIndependently(t *testing.T) {
	logger := &recordingLogger{}
	p := NewSSHProxy(SSHProxyConfig{SessionLogger: logger})
	shellCh, execCh := newChannelState(), newChannelState()

	emit(p, shellCh, prompt("~"))
	p.bufferInput([]byte("whoami"), "sid", session.SessionChannelShell, shellCh)
	typeLine(p, execCh, session.SessionChannelExec, "id")
	p.bufferInput([]byte{0x0D}, "sid", session.SessionChannelShell, shellCh)
	emit(p, shellCh, "\r\n")
	p.flushOutputBuffer("sid", shellCh)
	p.flushPendingEcho("sid", shellCh)

	for _, e := range logger.events {
		if e.EventType != session.SessionEventInput {
			continue
		}
		want := map[string]session.SessionChannelType{
			"whoami": session.SessionChannelShell,
			"id":     session.SessionChannelExec,
		}[string(e.Data)]
		if want == "" {
			t.Fatalf("unexpected input event %q", e.Data)
		}
		if e.ChannelType != want {
			t.Errorf("input %q recorded on channel %q, want %q", e.Data, e.ChannelType, want)
		}
	}
}

// typedInput feeds keystrokes the way a client does, with the server's echo of
// each chunk arriving before the next one is read.
type typedInput struct {
	p      *SSHProxy
	ch     *channelState
	chunks []string
	i      int
}

func (r *typedInput) Read(b []byte) (int, error) {
	if r.i > 0 {
		emit(r.p, r.ch, r.chunks[r.i-1])
	}
	if r.i >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(b, r.chunks[r.i])
	r.i++
	return n, nil
}

// A blocked command is recorded once, by the echoed line, like any other.
func TestBlockedCommandIsNotDuplicated(t *testing.T) {
	logger := &recordingLogger{}
	p := NewSSHProxy(SSHProxyConfig{
		SessionLogger:          logger,
		BlockedCommandPatterns: []*regexp.Regexp{regexp.MustCompile(`sudo`)},
	})
	ch := newChannelState()
	ch.channelType = session.SessionChannelShell

	emit(p, ch, prompt("~"))
	src := &typedInput{p: p, ch: ch, chunks: []string{"sudo what", "\r"}}
	if err := p.proxyClientToServerWithBlocking(src, io.Discard, io.Discard, "sid", ch); err != nil {
		t.Fatalf("proxy returned %v", err)
	}
	p.flushOutputBuffer("sid", ch)
	p.flushPendingEcho("sid", ch)

	var got []string
	for _, e := range logger.events {
		got = append(got, string(e.EventType)+": "+string(e.Data))
	}
	want := []string{
		"output: user@host:~$ sudo what",
		"output: [BLOCKED] Command not permitted",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
