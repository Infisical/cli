package ssh

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/ansi/parser"
)

const (
	maxLineRunes    = 8192
	tabWidth        = 8
	promptTailRunes = 256
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
			t.writeRune(t.parser.Rune(), &lines)
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
	return t.FlushAt(-1)
}

// FlushAt cuts the pending line back to n runes before committing it, dropping a
// secret the shell echoed after the prompt. n < 0 keeps it whole.
func (t *terminalTranscript) FlushAt(n int) []string {
	if n >= 0 && n < len(t.line) {
		t.line = t.line[:n]
	}
	return appendLine(nil, t.commit())
}

// pendingLine returns the length of the line on screen and its tail, capped so a
// long line stays cheap to snapshot.
func (t *terminalTranscript) pendingLine() (int, string) {
	n := len(t.line)
	for n > 0 && t.line[n-1] == ' ' {
		n--
	}
	return n, string(t.line[max(n-promptTailRunes, 0):n])
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
			t.writeRune(' ', lines)
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

// A stream with no newline wraps at the line limit rather than dropping the rest.
func (t *terminalTranscript) writeRune(r rune, lines *[]string) {
	if t.cursor >= maxLineRunes {
		*lines = appendLine(*lines, t.commit())
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
	t.padTo(t.cursor)
	if n = min(n, maxLineRunes-len(t.line)); n <= 0 {
		return
	}
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

// settle applies a held command to the first line committed after it. A longer line
// means the shell echoed it, so that line is the record.
func (e *echoedCommand) settle(line string) (session.SessionEvent, bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.text == "" {
		return session.SessionEvent{}, false
	}
	if utf8.RuneCountInString(line) > e.baseline {
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
	event := session.SessionEvent{
		Timestamp:   e.timestamp,
		EventType:   session.SessionEventInput,
		ChannelType: e.channel,
		Data:        []byte(e.text),
		Rendered:    true,
	}
	e.text = ""
	return event, true
}

const redactedPromptInput = "[redacted] secret prompt input"

// Requiring a terminator right after the keyword keeps ordinary output that merely
// mentions one of these words from matching.
var secretPromptPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)pass(word|phrase|code)[^:]*:$`),
	regexp.MustCompile(`(?i)\bpin\b[^:]*:$`),
	regexp.MustCompile(`(?i)(verification|authentication|security|access) code[^:]*:$`),
	regexp.MustCompile(`(?i)\b(otp|2fa|mfa)\b[^:]*:$`),
	regexp.MustCompile(`(?i)(secret|token|credential)s?[^:]*:$`),
	regexp.MustCompile(`(?i)enter[^:]*\bkey\b[^:]*:$`),
}

// isSecretPrompt reports whether the line on screen is asking for a secret, which is
// what distinguishes a password from a command. Echo state does not.
func isSecretPrompt(line string) bool {
	line = strings.TrimRight(line, " ")
	for _, pattern := range secretPromptPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}
