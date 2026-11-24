package ssh

import (
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
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

func renderWide(width int, chunks ...string) []string {
	t := newTerminalTranscript()
	t.SetWidth(width)
	var got []string
	for _, c := range chunks {
		got = append(got, t.Feed([]byte(c))...)
	}
	return append(got, t.Flush()...)
}

// Shells wrap a line longer than the terminal by writing a space and a carriage return.
func TestTranscriptWrapsAtTerminalWidth(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   []string
	}{
		{"bash wrap", []string{"$ echo abcdefghijklm \rnopq\r\n"}, []string{"$ echo abcdefghijklmnopq"}},
		{"zsh wrap", []string{"% echo abcdefghijklm \r" + esc + "[Kn\rnopq\r\n"}, []string{"% echo abcdefghijklmnopq"}},
		{"zsh partial-line marker", []string{"%" + strings.Repeat(" ", 19) + "\r \r" + "% ls\r\n"}, []string{"% ls"}},
		{"edit a row above", []string{"$ echo abcdefghijklm \rnopq" + esc + "[A\r" + esc + "[7CX" + esc + "[B\r\n"}, []string{"$ echo Xbcdefghijklmnopq"}},
		{"newline moves down within the line", []string{"$ echo abcdefghijklm \rnopq" + esc + "[A\n\rNO\r\n"}, []string{"$ echo abcdefghijklmNOpq"}},
		{"erase a row keeps the rows after it", []string{"$ echo abcdefghijklm \rnopq" + esc + "[A\r" + esc + "[K\r\n"}, []string{strings.Repeat(" ", 20) + "nopq"}},
		{"short lines unchanged", []string{"ab\rc\n" + esc + "[2Jx\n"}, []string{"cb", "x"}},
		{"delete and insert stay within a row", []string{"$ echo abcdefghijklm \rnopq" + esc + "[A\r" + esc + "[7C" + esc + "[2P" + esc + "[1@" + esc + "[B\r\n"},
			[]string{"$ echo  cdefghijklm nopq"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderWide(20, tt.chunks...); !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// zsh redraws a wrapped command after an edit at its start with row-local deletes and moves.
func TestTranscriptFollowsZshRedrawOfWrappedCommand(t *testing.T) {
	typed := "e\becho " + strings.Repeat("klmnopqrst", 10) + "k \r" + esc + "[Kl\rlmnopqrst" + strings.Repeat("klmnopqrst", 2)
	edited := esc + "[A" + esc + "[15Dxecho " + esc + "[9P" + esc + "[91Clmnopqrstk" + esc + "[9P" + esc + "[19Cklmnopqrst" +
		esc + "[A" + esc + "[15D" + esc + "[1B" + esc + "[15C" + esc + "[?1l" + esc + ">" + esc + "[?2004l\r\r\nzsh: command not found: xecho\r\n"
	prompt := "host%" + strings.Repeat(" ", 9)
	want := []string{prompt + "xecho " + strings.Repeat("klmnopqrst", 13), "zsh: command not found: xecho"}
	if got := renderWide(120, prompt, typed, edited); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTranscriptMovesDownSeveralRows(t *testing.T) {
	got := renderWide(10, "0123456789abcdefghijABCDEFGHIJxyz"+esc+"[3A"+esc+"[2B#\r\n")
	if want := []string{"0123456789abcdefghijABC#EFGHIJxyz"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Widening the terminal while a wrap is pending must not move the cursor's row before the line.
func TestTranscriptSurvivesWideningMidWrap(t *testing.T) {
	for _, erase := range []string{"[1K", "[2K", "[3K", "[K", "[1P", "[1@", "[1X"} {
		tr := newTerminalTranscript()
		tr.SetWidth(10)
		tr.Feed([]byte(strings.Repeat("x", 10)))
		tr.SetWidth(50)
		tr.Feed([]byte(esc + erase + "y\r\n"))
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

	// Inserting on a row that runs past the line limit.
	huge := newTerminalTranscript()
	huge.SetWidth(5000)
	huge.Feed([]byte(strings.Repeat("z", maxLineRunes-1) + "\r" + esc + "[3000@"))
	if n := len(huge.line); n > maxLineRunes {
		t.Errorf("line grew to %d runes after inserts, want at most %d", n, maxLineRunes)
	}

	// A tab near the line limit on a terminal whose width is not a multiple of the tab width.
	wide := newTerminalTranscript()
	wide.SetWidth(30)
	wide.Feed([]byte(strings.Repeat("y", maxLineRunes-1) + "\t\t"))
	if n := len(wide.line); n > maxLineRunes {
		t.Errorf("wrapped line grew to %d runes, want at most %d", n, maxLineRunes)
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
			want: []string{"output: user@host:~$ ls [command: ls]", "output: LICENSE go", "output: user@host:~$"},
		},
		{
			name: "tab completion counts as echoed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~/cli"))
				typeLine(p, ch, shell, "cd ..")
				emit(p, ch, "/\r\n")
			},
			want: []string{"output: user@host:~/cli$ cd ../ [command: cd ../]"},
		},
		{
			name: "paste arriving with its newline counts as echoed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte("cd ../cli\r"), "sid", shell, ch)
				emit(p, ch, "cd ../cli\r\n")
			},
			want: []string{"output: user@host:~$ cd ../cli [command: cd ../cli]"},
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
			name: "unechoed typing on the alternate screen is kept as input",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~")+esc+"[?1049h")
				typeSilently(p, ch, "cat /etc/shadow > /tmp/x")
			},
			want: []string{"output: user@host:~$", "input: cat /etc/shadow > /tmp/x"},
		},
		{
			name: "unechoed commands held when the screen switches are kept as input",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeSilently(p, ch, "one")
				typeSilently(p, ch, "two")
				emit(p, ch, esc+"[?1049h")
			},
			want: []string{"output: user@host:~$", "input: one", "input: two"},
		},
		{
			name: "multi-line paste counts as echoed",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte("cd cli\nls\n"), "sid", shell, ch)
				emit(p, ch, "cd cli\r\n"+prompt("~/cli")+"ls\r\nLICENSE go\r\n")
			},
			want: []string{
				"output: user@host:~$ cd cli [command: cd cli]",
				"output: user@host:~/cli$ ls [command: ls]",
				"output: LICENSE go",
			},
		},
		{
			name: "multi-line paste the shell shows before running",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte(esc+"[200~ls\recho hi\r"+esc+"[201~"), "sid", shell, ch)
				emit(p, ch, "ls\r\necho hi")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r\nLICENSE go\r\nhi\r\n")
			},
			want: []string{
				"output: user@host:~$ ls [command: ls]",
				"output: echo hi [command: echo hi]",
				"output: LICENSE go",
				"output: hi",
			},
		},
		{
			name: "paste split across reads",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte("ls\r"), "sid", shell, ch)
				emit(p, ch, "ls")
				p.bufferInput([]byte("e"), "sid", shell, ch)
				emit(p, ch, "\r\nLICENSE go\r\n"+prompt("~")+"e")
				p.bufferInput([]byte("cho hi\r"), "sid", shell, ch)
				emit(p, ch, "cho hi\r\nhi\r\n")
			},
			want: []string{
				"output: user@host:~$ ls [command: ls]",
				"output: LICENSE go",
				"output: user@host:~$ echo hi [command: echo hi]",
				"output: hi",
			},
		},
		{
			name: "typing before the previous line ends",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "ls")
				p.bufferInput([]byte("p"), "sid", shell, ch)
				emit(p, ch, "\r\nLICENSE go\r\n"+prompt("~")+"p")
				typeLine(p, ch, shell, "wd")
				emit(p, ch, "\r\n/root\r\n")
			},
			want: []string{
				"output: user@host:~$ ls [command: ls]",
				"output: LICENSE go",
				"output: user@host:~$ pwd [command: pwd]",
				"output: /root",
			},
		},
		{
			name: "typing while a command runs",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "sleep 1")
				emit(p, ch, "\r\n")
				p.bufferInput([]byte("ls"), "sid", shell, ch)
				emit(p, ch, "ls"+prompt("~")+"ls")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r\nLICENSE go\r\n")
			},
			want: []string{
				"output: user@host:~$ sleep 1 [command: sleep 1]",
				"output: lsuser@host:~$ ls [command: ls]",
				"output: LICENSE go",
			},
		},
		{
			name: "history recall",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte(esc+"[A"), "sid", shell, ch)
				emit(p, ch, "ls -la")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r\ntotal 0\r\n")
			},
			want: []string{"output: user@host:~$ ls -la [command: ls -la]", "output: total 0"},
		},
		{
			name: "history recall extended by typing",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte(esc+"[A"), "sid", shell, ch)
				emit(p, ch, "ls -la")
				typeLine(p, ch, shell, " | wc -l")
				emit(p, ch, "\r\n1\r\n")
			},
			want: []string{"output: user@host:~$ ls -la | wc -l [command: ls -la | wc -l]", "output: 1"},
		},
		{
			name: "typed faster than the echo comes back",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeSilently(p, ch, "pwd")
				emit(p, ch, "pwd\r\n/root\r\n"+prompt("~"))
			},
			want: []string{"output: user@host:~$ pwd [command: pwd]", "output: /root", "output: user@host:~$"},
		},
		{
			name: "several commands typed faster than the echo comes back",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeSilently(p, ch, "pwd")
				typeSilently(p, ch, "whoami")
				emit(p, ch, "pwd\r\n/root\r\n"+prompt("~")+"whoami\r\nroot\r\n")
			},
			want: []string{
				"output: user@host:~$ pwd [command: pwd]",
				"output: /root",
				"output: user@host:~$ whoami [command: whoami]",
				"output: root",
			},
		},
		{
			name: "silent read that prints no newline",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "read -s x")
				emit(p, ch, "\r\n")
				typeSilently(p, ch, "hunter2")
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "id -u")
				emit(p, ch, "\r\n0\r\n")
			},
			want: []string{
				"output: user@host:~$ read -s x [command: read -s x]",
				"output: user@host:~$ id -u [command: id -u]",
				"input: hunter2",
				"output: 0",
			},
		},
		{
			name: "typed before the prompt is drawn, entered before the echo finishes",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "ls")
				emit(p, ch, "\r\nLICENSE\r\n")
				p.bufferInput([]byte("id -u"), "sid", shell, ch)
				emit(p, ch, prompt("~")+"id -")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "u\r\n0\r\n")
			},
			want: []string{
				"output: user@host:~$ ls [command: ls]",
				"output: LICENSE",
				"output: user@host:~$ id -u [command: id -u]",
				"output: 0",
			},
		},
		{
			name: "keys typed into a full-screen program stay out of the next command",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "less f")
				emit(p, ch, "\r\n"+esc+"[?1049hcontents\r\n")
				p.bufferInput([]byte("q"), "sid", shell, ch)
				emit(p, ch, esc+"[?1049l"+prompt("~"))
				typeLine(p, ch, shell, "pwd")
				emit(p, ch, "\r\n/root\r\n"+prompt("~"))
				p.bufferInput([]byte("q"), "sid", shell, ch)
				emit(p, ch, esc+"[?1049l")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r\n")
			},
			want: []string{
				"output: user@host:~$ less f [command: less f]",
				"output: contents",
				"input: q",
				"output: user@host:~$ pwd [command: pwd]",
				"output: /root",
				"output: user@host:~$",
				"input: q",
			},
		},
		{
			name: "command longer than the terminal",
			steps: func(p *SSHProxy, ch *channelState) {
				ch.setWidth(30)
				emit(p, ch, "$ ")
				typeSilently(p, ch, "echo "+strings.Repeat("ab", 20))
				emit(p, ch, "echo "+strings.Repeat("ab", 11)+"a \rb"+strings.Repeat("ab", 8)+"\r\nok\r\n")
			},
			want: []string{"output: $ echo " + strings.Repeat("ab", 20) + " [command: echo " + strings.Repeat("ab", 20) + "]", "output: ok"},
		},
		{
			name: "typing inside a full-screen program is not a command",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "vim .env")
				emit(p, ch, "\r\n"+esc+"[?1049h"+esc+"[H")
				typeLine(p, ch, shell, "DB_PASSWORD=hunter2")
				emit(p, ch, "\r\n")
				p.bufferInput([]byte(esc+"[B"), "sid", shell, ch)
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, esc+"[2;1Hapi_token=sk_live_abcdef\r\n")
				typeLine(p, ch, shell, ":wq")
				emit(p, ch, esc+"[?1049l"+prompt("~"))
				typeLine(p, ch, shell, "ls")
				emit(p, ch, "\r\n")
			},
			want: []string{
				"output: user@host:~$ vim .env [command: vim .env]",
				"input: DB_PASSWORD=hunter2",
				"output: DB_PASSWORD=hunter2",
				"output: api_token=sk_live_abcdef",
				"input: :wq",
				"output: :wq",
				"output: user@host:~$ ls [command: ls]",
			},
		},
		{
			name: "completion typed before the prompt is drawn",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "ls")
				emit(p, ch, "\r\nLICENSE\r\n")
				p.bufferInput([]byte("cd Doc\t"), "sid", shell, ch)
				emit(p, ch, prompt("~")+"cd Documents/")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r\n")
			},
			want: []string{
				"output: user@host:~$ ls [command: ls]",
				"output: LICENSE",
				"output: user@host:~$ cd Documents/ [command: cd Documents/]",
			},
		},
		{
			name: "password typed before its prompt appears",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "sudo ls")
				emit(p, ch, "\r\n")
				p.bufferInput([]byte("hunter2"), "sid", shell, ch)
				emit(p, ch, "[sudo] password for user: ")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r\nLICENSE\r\n")
			},
			want: []string{
				"output: user@host:~$ sudo ls [command: sudo ls]",
				"output: [sudo] password for user:",
				"output: LICENSE",
				"input: hunter2",
			},
		},
		{
			name: "history recalled right after Ctrl+C",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				typeLine(p, ch, shell, "npm start")
				emit(p, ch, "\r\nlistening")
				p.bufferInput([]byte{0x03}, "sid", shell, ch)
				p.bufferInput([]byte(esc+"[A"), "sid", shell, ch)
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "^C\r\n"+prompt("~")+"npm start\r\n")
			},
			want: []string{
				"output: user@host:~$ npm start [command: npm start]",
				"output: listening^C",
				"output: user@host:~$ npm start",
			},
		},
		{
			name: "pasted tab shown as spaces",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte("printf 'a\tb'\r"), "sid", shell, ch)
				emit(p, ch, "printf 'a\tb'\r\n")
			},
			want: []string{"output: user@host:~$ printf 'a  b' [command: printf 'a  b']"},
		},
		{
			name: "arrow keys in a full-screen program enter no command",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, "line one")
				p.bufferInput([]byte(esc+"[B"), "sid", shell, ch)
				emit(p, ch, esc+"[Bline two")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, esc+"[Bline three")
			},
			want: []string{"output: line one", "output: line two", "output: line three"},
		},
		{
			name: "history search",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, prompt("~"))
				p.bufferInput([]byte{0x12}, "sid", shell, ch)
				emit(p, ch, "\r(reverse-i-search)`': ")
				p.bufferInput([]byte("ls"), "sid", shell, ch)
				emit(p, ch, "\r(reverse-i-search)`ls': ls -la")
				p.bufferInput([]byte{0x0D}, "sid", shell, ch)
				emit(p, ch, "\r"+prompt("~")+"ls -la"+esc+"[K\r\ntotal 0\r\n")
			},
			want: []string{"output: user@host:~$ ls -la [command: ls -la]", "output: total 0"},
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
			name: "input at a prompt that does not echo is recorded even when the prompt ends with it",
			steps: func(p *SSHProxy, ch *channelState) {
				emit(p, ch, "[sudo] password for user: ")
				typeSilently(p, ch, "user:")
				emit(p, ch, "\r\nok\r\n")
			},
			want: []string{"output: [sudo] password for user:", "input: user:", "output: ok"},
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
				if e.Command != "" {
					got[i] += " [command: " + e.Command + "]"
				}
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
	echoes []string // What the server writes back for each chunk, when it is not the chunk itself
	i      int
}

func (r *typedInput) Read(b []byte) (int, error) {
	if r.i > 0 {
		echo := r.chunks[r.i-1]
		if r.echoes != nil {
			echo = r.echoes[r.i-1]
		}
		emit(r.p, r.ch, echo)
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
	if n := len(logger.events); n == 0 || !logger.events[n-1].Blocked {
		t.Error("the notice is not marked as written for a blocked command")
	}
}

// Command blocking checks each Enter on its own, which must not make a paste look typed.
func TestPasteThroughCommandBlocking(t *testing.T) {
	logger := &recordingLogger{}
	p := NewSSHProxy(SSHProxyConfig{
		SessionLogger:          logger,
		BlockedCommandPatterns: []*regexp.Regexp{regexp.MustCompile(`sudo`)},
	})
	ch := newChannelState()
	ch.channelType = session.SessionChannelShell

	emit(p, ch, prompt("~"))
	src := &typedInput{p: p, ch: ch,
		chunks: []string{"ls\recho hi\r"},
		echoes: []string{"ls\r\nLICENSE go\r\n" + prompt("~") + "echo hi\r\nhi\r\n"},
	}
	if err := p.proxyClientToServerWithBlocking(src, io.Discard, io.Discard, "sid", ch); err != nil {
		t.Fatalf("proxy returned %v", err)
	}
	p.flushOutputBuffer("sid", ch)

	var got []string
	for _, e := range logger.events {
		got = append(got, string(e.EventType)+": "+string(e.Data)+" ["+e.Command+"]")
	}
	want := []string{
		"output: user@host:~$ ls [ls]",
		"output: LICENSE go []",
		"output: user@host:~$ echo hi [echo hi]",
		"output: hi []",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestInputFilterRecognizesHistoryKeys(t *testing.T) {
	for keys, want := range map[string]bool{
		esc + "[A": true, esc + "OB": true, esc + "[1;5A": true,
		esc + "[D": false, esc + "OH": false, esc + "[200~": false, esc + "[<0;3;4M": false,
	} {
		f := newInputSequenceFilter()
		for _, b := range []byte(keys) {
			if !f.consumed(b) {
				t.Errorf("%q: kept %q", keys, b)
			}
		}
		if f.historyKey != want {
			t.Errorf("%q: history key %v, want %v", keys, f.historyKey, want)
		}
	}
}

// laggingInput delivers a command, then its Enter while the echo of the last key is still in
// flight from the server.
type laggingInput struct {
	p  *SSHProxy
	ch *channelState
	i  int
}

func (r *laggingInput) Read(b []byte) (int, error) {
	r.i++
	switch r.i {
	case 1:
		return copy(b, "sudo what"), nil
	case 2:
		emit(r.p, r.ch, "sudo wha")
		go func() {
			time.Sleep(50 * time.Millisecond)
			emit(r.p, r.ch, "t")
		}()
		return copy(b, "\r"), nil
	default:
		return 0, io.EOF
	}
}

// A command blocked before its echo arrives is still recorded whole.
func TestBlockedCommandWaitsForItsEcho(t *testing.T) {
	logger := &recordingLogger{}
	p := NewSSHProxy(SSHProxyConfig{
		SessionLogger:          logger,
		BlockedCommandPatterns: []*regexp.Regexp{regexp.MustCompile(`sudo`)},
	})
	ch := newChannelState()
	ch.channelType = session.SessionChannelShell

	emit(p, ch, prompt("~"))
	if err := p.proxyClientToServerWithBlocking(&laggingInput{p: p, ch: ch}, io.Discard, io.Discard, "sid", ch); err != nil {
		t.Fatalf("proxy returned %v", err)
	}

	var got []string
	for _, e := range logger.events {
		got = append(got, string(e.EventType)+": "+string(e.Data)+" ["+e.Command+"]")
	}
	want := []string{
		"output: user@host:~$ sudo what [sudo what]",
		"output: [BLOCKED] Command not permitted []",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTranscriptCountsFullScreenExits(t *testing.T) {
	tr := newTerminalTranscript()
	tr.Feed([]byte(esc + "[?1049h" + esc + "[?25l" + esc + "[?1049l" + esc + "[?47l" + esc + "[?1047l" + esc + "[?1l"))
	if got := tr.ScreenExits(); got != 3 {
		t.Errorf("counted %d exits, want 3", got)
	}
}

// A held command is never recorded with a value output masking hid in its echo.
func TestHeldCommandKeepsOutputMasking(t *testing.T) {
	logger := &recordingLogger{}
	patterns := []masking.Matcher{regexp.MustCompile(`token=\w+`)}
	p := NewSSHProxy(SSHProxyConfig{SessionLogger: logger, OutputMaskingPatterns: patterns})
	ch := newChannelState()
	shell := session.SessionChannelShell

	emit(p, ch, prompt("~"))
	p.bufferInput([]byte("echo token=abcd\r"), "sid", shell, ch)
	emit(p, ch, string(maskTerminalOutput(patterns, []byte("echo token=abcd")))+"\r\n"+prompt("~")+"read -s x\r\n")
	p.bufferInput([]byte("token=efgh\r"), "sid", shell, ch)
	emit(p, ch, "\r\n")
	p.flushOutputBuffer("sid", ch)
	p.flushPendingEcho("sid", ch)

	tagged := false
	for _, e := range logger.events {
		if strings.Contains(string(e.Data)+e.Command, "abcd") || strings.Contains(string(e.Data)+e.Command, "efgh") {
			t.Errorf("event %s %q [%q] holds a masked value", e.EventType, e.Data, e.Command)
		}
		tagged = tagged || strings.HasPrefix(e.Command, "echo ")
	}
	if !tagged {
		t.Error("the masked echo was not matched to its command")
	}
}

// Keys forwarded before a full-screen program's exit arrives still count toward command blocking.
func TestScreenExitKeepsKeysForBlocking(t *testing.T) {
	logger := &recordingLogger{}
	p := NewSSHProxy(SSHProxyConfig{
		SessionLogger:          logger,
		BlockedCommandPatterns: []*regexp.Regexp{regexp.MustCompile(`^rm -rf`)},
	})
	ch := newChannelState()
	ch.channelType = session.SessionChannelShell
	var server strings.Builder

	emit(p, ch, prompt("~"))
	src := &typedInput{p: p, ch: ch,
		chunks: []string{"rm -rf /tmp/x", " ", "\r"},
		echoes: []string{esc + "[?1049h" + esc + "[?1049l", " ", ""},
	}
	if err := p.proxyClientToServerWithBlocking(src, &server, io.Discard, "sid", ch); err != nil {
		t.Fatalf("proxy returned %v", err)
	}
	if strings.ContainsAny(server.String(), "\r\n") {
		t.Errorf("the server received the Enter of a blocked command: %q", server.String())
	}
}

// A line too long to keep whole can't be checked, so its Enter is refused.
func TestOverlongLineIsBlocked(t *testing.T) {
	p := NewSSHProxy(SSHProxyConfig{
		SessionLogger:          &recordingLogger{},
		BlockedCommandPatterns: []*regexp.Regexp{regexp.MustCompile(`^rm -rf`)},
	})
	ch := newChannelState()
	ch.channelType = session.SessionChannelShell
	var server strings.Builder

	emit(p, ch, prompt("~"))
	src := &typedInput{p: p, ch: ch, chunks: []string{strings.Repeat(" ", maxLineRunes-3) + "rm -rf /tmp/x", "\r"}}
	if err := p.proxyClientToServerWithBlocking(src, &server, io.Discard, "sid", ch); err != nil {
		t.Fatalf("proxy returned %v", err)
	}
	if strings.ContainsAny(server.String(), "\r\n") {
		t.Error("the server received the Enter of a line too long to check")
	}
}

// Ctrl+C makes the shell drop a line too long to check, but after Ctrl+A, Ctrl+U deletes nothing.
func TestCanceledOverlongLine(t *testing.T) {
	p := NewSSHProxy(SSHProxyConfig{
		SessionLogger:          &recordingLogger{},
		BlockedCommandPatterns: []*regexp.Regexp{regexp.MustCompile(`^rm -rf`)},
	})
	for _, tt := range []struct {
		cancel  string
		refused bool
	}{
		{cancel: "\x03", refused: false},
		{cancel: "\x01\x15", refused: true},
	} {
		ch := newChannelState()
		ch.channelType = session.SessionChannelShell
		var server strings.Builder

		emit(p, ch, prompt("~"))
		src := &typedInput{p: p, ch: ch, chunks: []string{strings.Repeat(" ", maxLineRunes) + "rm -rf /tmp/x", tt.cancel, "\r"}}
		if err := p.proxyClientToServerWithBlocking(src, &server, io.Discard, "sid", ch); err != nil {
			t.Fatalf("proxy returned %v", err)
		}
		if refused := !strings.HasSuffix(server.String(), "\r"); refused != tt.refused {
			t.Errorf("after %q the Enter was refused: %v, want %v", tt.cancel, refused, tt.refused)
		}
	}
}

// However many commands go unechoed, none is lost from the recording.
func TestUnechoedCommandsPastTheHoldLimitAreKept(t *testing.T) {
	logger := &recordingLogger{}
	p := NewSSHProxy(SSHProxyConfig{SessionLogger: logger})
	ch := newChannelState()

	emit(p, ch, prompt("~"))
	for i := range maxHeldCommands + 1 {
		typeSilently(p, ch, "cmd"+strconv.Itoa(i))
	}
	p.flushPendingEcho("sid", ch)

	inputs := 0
	for _, e := range logger.events {
		if e.EventType == session.SessionEventInput {
			inputs++
		}
	}
	if inputs != maxHeldCommands+1 {
		t.Errorf("recorded %d of %d unechoed commands", inputs, maxHeldCommands+1)
	}
}

// A string introducer in the keystroke stream must not swallow the command: that
// would hide it from command blocking and from the recording.
func TestInputFilterKeepsCommandAfterStringIntroducer(t *testing.T) {
	for _, introducer := range []string{"]", "P", "X", "^", "_"} {
		f := newInputSequenceFilter()
		var kept []byte
		for _, b := range []byte(esc + introducer + "rm -rf /\r") {
			if !f.consumed(b) {
				kept = append(kept, b)
			}
		}
		if string(kept) != "rm -rf /\r" {
			t.Errorf("ESC %s: kept %q, want %q", introducer, kept, "rm -rf /\r")
		}
	}
}
