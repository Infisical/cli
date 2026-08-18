package ssh

import (
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

	if n := tr.PendingLen(); n > maxLineRunes {
		t.Errorf("pending line grew to %d runes, want at most %d", n, maxLineRunes)
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

func typeLine(p *SSHProxy, channel session.SessionChannelType, text string) {
	p.bufferInput([]byte(text), "sid", channel)
	p.bufferInput([]byte{0x0D}, "sid", channel)
}

func emit(p *SSHProxy, text string) {
	p.bufferOutput([]byte(text), "sid", session.SessionChannelShell)
}

func TestSessionRecording(t *testing.T) {
	shell := session.SessionChannelShell

	tests := []struct {
		name  string
		steps func(p *SSHProxy)
		want  []string
	}{
		{
			name: "echo replaces the command event",
			steps: func(p *SSHProxy) {
				emit(p, prompt("~"))
				typeLine(p, shell, "ls")
				emit(p, "ls\r\nLICENSE go\r\n"+prompt("~"))
			},
			want: []string{"output: user@host:~$ ls", "output: LICENSE go", "output: user@host:~$"},
		},
		{
			name: "tab completion counts as echoed",
			steps: func(p *SSHProxy) {
				emit(p, prompt("~/cli"))
				typeLine(p, shell, "cd ..\t")
				emit(p, "cd ../\r\n")
			},
			want: []string{"output: user@host:~/cli$ cd ../"},
		},
		{
			name: "paste arriving with its newline counts as echoed",
			steps: func(p *SSHProxy) {
				emit(p, prompt("~"))
				p.bufferInput([]byte("cd ../cli\r"), "sid", shell)
				emit(p, "cd ../cli\r\n")
			},
			want: []string{"output: user@host:~$ cd ../cli"},
		},
		{
			name: "unechoed input is recorded without its content",
			steps: func(p *SSHProxy) {
				emit(p, "[sudo] password for deploy: ")
				typeLine(p, shell, "s3cr3t!!")
				emit(p, "\r\nroot\r\n")
			},
			want: []string{
				"output: [sudo] password for deploy:",
				"input: [no echo] 8 characters submitted",
				"output: root",
			},
		},
		{
			name: "multi-line paste counts as echoed",
			steps: func(p *SSHProxy) {
				emit(p, prompt("~"))
				p.bufferInput([]byte("cd cli\nls\n"), "sid", shell)
				emit(p, "cd cli\r\n"+prompt("~/cli")+"ls\r\nLICENSE go\r\n")
			},
			want: []string{
				"output: user@host:~$ cd cli",
				"output: user@host:~/cli$ ls",
				"output: LICENSE go",
			},
		},
		{
			name:  "exec channel logs its command immediately",
			steps: func(p *SSHProxy) { typeLine(p, session.SessionChannelExec, "uname -a") },
			want:  []string{"input: uname -a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &recordingLogger{}
			p := NewSSHProxy(SSHProxyConfig{SessionLogger: logger})

			tt.steps(p)
			p.flushOutputBuffer("sid")
			p.flushPendingEcho("sid")

			got := make([]string, len(logger.events))
			for i, e := range logger.events {
				if !e.Rendered || e.Timestamp.IsZero() {
					t.Errorf("event %d (%q) lacks the rendered flag or a timestamp", i, e.Data)
				}
				if strings.Contains(string(e.Data), "s3cr3t") {
					t.Errorf("event %d recorded the typed secret", i)
				}
				got[i] = string(e.EventType) + ": " + string(e.Data)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
