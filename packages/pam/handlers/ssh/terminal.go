package ssh

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/ansi/parser"
)

const (
	maxLineRunes = 8192
	tabWidth     = 8
)

type terminalTranscript struct {
	parser *ansi.Parser
	line   []rune
	cursor int
}

func newTerminalTranscript() *terminalTranscript {
	return &terminalTranscript{parser: ansi.NewParser()}
}

func (t *terminalTranscript) Feed(data []byte) []string {
	var lines []string
	for _, b := range data {
		// An OSC payload can end in a byte that looks like a CSI final.
		fromCSI := isCSIState(t.parser.State())

		switch t.parser.Advance(b) {
		case parser.PrintAction:
			t.writeRune(t.parser.Rune())
		case parser.ExecuteAction:
			t.execute(t.parser.Control(), &lines)
		case parser.DispatchAction:
			if fromCSI {
				t.dispatchCSI(&lines)
			}
		}
	}
	return lines
}

func (t *terminalTranscript) Flush() []string {
	return appendLine(nil, t.commit())
}

func (t *terminalTranscript) PendingLen() int {
	n := len(t.line)
	for n > 0 && t.line[n-1] == ' ' {
		n--
	}
	return n
}

func isCSIState(state parser.State) bool {
	return state == parser.CsiEntryState || state == parser.CsiParamState ||
		state == parser.CsiIntermediateState
}

func (t *terminalTranscript) execute(control byte, lines *[]string) {
	switch control {
	case '\n', 0x0B, 0x0C:
		*lines = appendLine(*lines, t.commit())
	case '\r':
		t.cursor = 0
	case 0x08:
		t.cursor = max(t.cursor-1, 0)
	case '\t':
		for stop := (t.cursor/tabWidth + 1) * tabWidth; t.cursor < stop; {
			t.writeRune(' ')
		}
	}
}

func (t *terminalTranscript) dispatchCSI(lines *[]string) {
	switch t.parser.Command() {
	case 'K', 'J': // erase in line, erase in display
		switch t.param(0) {
		case 1:
			t.blank(0, t.cursor)
		case 2, 3:
			t.line, t.cursor = t.line[:0], 0
		default:
			t.line = t.line[:min(t.cursor, len(t.line))]
		}
	case 'C': // cursor forward
		t.cursor = clampColumn(t.cursor + t.param(1))
	case 'D': // cursor back
		t.cursor = clampColumn(t.cursor - t.param(1))
	case 'G', '`': // absolute column
		t.cursor = clampColumn(t.param(1) - 1)
	case 'P': // delete characters
		t.deleteChars(t.param(1))
	case '@': // insert blanks
		t.insertBlanks(t.param(1))
	case 'X': // erase characters
		t.blank(t.cursor, t.cursor+t.param(1))
	case 'A', 'B', 'E', 'F', 'H', 'f', 'd': // vertical and absolute moves; no rows to move between
		*lines = appendLine(*lines, t.commit())
	}
}

func (t *terminalTranscript) param(fallback int) int {
	n, _ := t.parser.Param(0, fallback)
	return min(max(n, 0), maxLineRunes)
}

func (t *terminalTranscript) commit() string {
	line := strings.TrimRight(string(t.line), " ")
	t.line, t.cursor = t.line[:0], 0
	return line
}

func (t *terminalTranscript) writeRune(r rune) {
	if t.cursor >= maxLineRunes {
		return
	}
	t.padTo(t.cursor)
	if t.cursor < len(t.line) {
		t.line[t.cursor] = r
	} else {
		t.line = append(t.line, r)
	}
	t.cursor++
}

func (t *terminalTranscript) padTo(col int) {
	for len(t.line) < col {
		t.line = append(t.line, ' ')
	}
}

func (t *terminalTranscript) blank(start, end int) {
	for i := start; i < min(end, len(t.line)); i++ {
		t.line[i] = ' '
	}
}

func (t *terminalTranscript) deleteChars(n int) {
	if n <= 0 || t.cursor >= len(t.line) {
		return
	}
	t.line = append(t.line[:t.cursor], t.line[min(t.cursor+n, len(t.line)):]...)
}

func (t *terminalTranscript) insertBlanks(n int) {
	if n = min(n, maxLineRunes-t.cursor); n <= 0 {
		return
	}
	t.padTo(t.cursor)
	t.line = append(t.line, make([]rune, n)...)
	copy(t.line[t.cursor+n:], t.line[t.cursor:])
	t.blank(t.cursor, t.cursor+n)
}

func clampColumn(col int) int {
	return min(max(col, 0), maxLineRunes)
}

func appendLine(lines []string, line string) []string {
	if line == "" {
		return lines
	}
	return append(lines, line)
}

// inputSequenceFilter drops escape sequences, which can straddle a read.
type inputSequenceFilter struct {
	parser *ansi.Parser
}

func newInputSequenceFilter() *inputSequenceFilter {
	return &inputSequenceFilter{parser: ansi.NewParser()}
}

func (f *inputSequenceFilter) consumed(b byte) bool {
	switch f.parser.Advance(b) {
	case parser.PrintAction, parser.ExecuteAction:
		return false
	default:
		return true
	}
}

// echoedCommand holds a command until the output shows whether the shell echoed
// it. The echoed line is the better record: it carries the prompt and reflects
// tab completion and history recall.
type echoedCommand struct {
	mutex     sync.Mutex
	text      string
	timestamp time.Time
	channel   session.SessionChannelType
	baseline  int
}

// hold takes a command with the length of the line on screen when typing began.
// A command displaced before any line committed is dropped: a multi-line paste
// delivers every command ahead of its echo, so claiming no echo would be wrong.
func (e *echoedCommand) hold(text string, channel session.SessionChannelType, baseline int) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.text, e.timestamp, e.channel, e.baseline = text, time.Now(), channel, baseline
}

// resolve settles a held command against the first line committed after it. A
// line longer than what was on screen when typing began was echoed, so the
// echoed line stands in for the command; otherwise echo was off.
func (e *echoedCommand) resolve(lineRunes int) (session.SessionEvent, bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.text == "" {
		return session.SessionEvent{}, false
	}
	if lineRunes > e.baseline {
		e.text = ""
		return session.SessionEvent{}, false
	}
	return e.takeUnsafe()
}

func (e *echoedCommand) take() (session.SessionEvent, bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.takeUnsafe()
}

func (e *echoedCommand) takeUnsafe() (session.SessionEvent, bool) {
	if e.text == "" {
		return session.SessionEvent{}, false
	}
	// Echo off means a secret prompt; recording the keystrokes would log the password.
	count := utf8.RuneCountInString(e.text)
	notice := fmt.Sprintf("[no echo] %d characters submitted", count)
	if count == 1 {
		notice = "[no echo] 1 character submitted"
	}

	event := session.SessionEvent{
		Timestamp:   e.timestamp,
		EventType:   session.SessionEventInput,
		ChannelType: e.channel,
		Data:        []byte(notice),
		Rendered:    true,
	}
	e.text = ""
	return event, true
}
