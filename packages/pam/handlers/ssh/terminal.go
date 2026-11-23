package ssh

import (
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
	parser    *ansi.Parser
	line      []rune
	cursor    int
	committed int // Lines committed so far, which identifies the line still on screen
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
	return appendLine(nil, t.commit())
}

func (t *terminalTranscript) Pending() string {
	return strings.TrimRight(string(t.line), " ")
}

func (t *terminalTranscript) Committed() int {
	return t.committed
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
	t.committed++
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
	parser     *ansi.Parser
	ss3        bool // ESC O was read, so the next byte ends an application-mode key
	historyKey bool // The byte just consumed ended an up or down arrow
}

func newInputSequenceFilter() *inputSequenceFilter {
	return &inputSequenceFilter{parser: ansi.NewParser()}
}

func (f *inputSequenceFilter) consumed(b byte) bool {
	f.historyKey = false
	if f.ss3 {
		f.ss3 = false
		if b >= 0x40 && b <= 0x7E {
			f.historyKey = b == 'A' || b == 'B'
			return true
		}
	}
	if f.parser.State() == parser.EscapeState && isStringIntroducer(b) {
		f.parser.Reset()
		return true
	}
	if isStringState(f.parser.State()) {
		f.parser.Reset()
	}

	state := f.parser.State()
	switch f.parser.Advance(b) {
	case parser.PrintAction, parser.ExecuteAction:
		return false
	case parser.DispatchAction:
		command := f.parser.Command()
		f.ss3 = state == parser.EscapeState && command == 'O'
		f.historyKey = isCSIState(state) && (command == 'A' || command == 'B')
	}
	return true
}

func isStringIntroducer(b byte) bool {
	return b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_'
}

func isStringState(state parser.State) bool {
	switch state {
	case parser.OscStringState, parser.DcsStringState, parser.SosStringState,
		parser.PmStringState, parser.ApcStringState:
		return true
	default:
		return false
	}
}

// enteredCommand is a command line entered at a shell. line and baseline say where typing
// began: the line on screen then, by commit count, and its rendered length.
type enteredCommand struct {
	text      string
	recalled  bool // History keys were used, so the line can show more than was typed
	line      uint32
	baseline  int
	timestamp time.Time
	channel   session.SessionChannelType
}

// startOn returns where the command starts on a line that shows it. Typed text is found by
// its echo, which holds even when typing began before the prompt was drawn. Recalled history
// or a completion is found by where typing began, which holds only on the line on screen then.
func (e enteredCommand) startOn(line string, sameLine bool) (int, bool) {
	typed := strings.TrimSpace(e.text)
	at := len(line) - len(typed)
	grew := utf8.RuneCountInString(line) > e.baseline
	echoed := !e.recalled && typed != "" && (grew || !sameLine) &&
		strings.HasSuffix(line, typed) && (at == 0 || line[at-1] == ' ')

	switch {
	case echoed:
		return utf8.RuneCountInString(line[:at]), true
	case sameLine && grew:
		return e.baseline, true
	}
	return 0, false
}

// echoedCommand holds pasted commands until the output shows whether the shell echoed
// them. The echoed line is the better record: it carries the prompt and reflects tab
// completion and history recall.
type echoedCommand struct {
	mutex sync.Mutex
	held  []heldCommand
}

type heldCommand struct {
	enteredCommand
	next bool // Nothing else awaited a line, so the next committed line is the one it was entered on
}

// maxHeldCommands bounds a paste the shell never echoes; past it the oldest command is dropped.
const maxHeldCommands = 64

func (e *echoedCommand) hold(command enteredCommand, next bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if len(e.held) == maxHeldCommands {
		e.held = e.held[1:]
	}
	e.held = append(e.held, heldCommand{command, next && len(e.held) == 0})
}

// clear drops held commands once a later command is on screen: the shell shows input in
// order, so the ones it has not shown by then never appeared as typed.
func (e *echoedCommand) clear() {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.held = nil
}

// settle applies the oldest held command to a committed line. A line showing it is its echo,
// and echoedAt is where the command starts on it (-1 otherwise). A command that was next is
// settled by the first line either way: one that does not show it means the shell did not
// echo it, while later commands wait for their own line.
func (e *echoedCommand) settle(line string) (unechoed session.SessionEvent, ok bool, echoedAt int) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if len(e.held) == 0 {
		return session.SessionEvent{}, false, -1
	}
	head := e.held[0]
	if start, found := head.startOn(line, head.next); found {
		e.held = e.held[1:]
		return session.SessionEvent{}, false, start
	}
	if !head.next {
		return session.SessionEvent{}, false, -1
	}
	e.held = e.held[1:]
	unechoed, ok = head.inputEvent()
	return unechoed, ok, -1
}

// commandOnLine returns what was typed after the prompt on a committed line, or "" when
// the line no longer reaches where typing began (the shell redrew it shorter).
func commandOnLine(line string, start int) string {
	runes := []rune(line)
	if start >= len(runes) {
		return ""
	}
	return strings.TrimSpace(string(runes[start:]))
}

func (e *echoedCommand) takeAll() []session.SessionEvent {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	var events []session.SessionEvent
	for _, held := range e.held {
		if event, ok := held.inputEvent(); ok {
			events = append(events, event)
		}
	}
	e.held = nil
	return events
}

func (e enteredCommand) inputEvent() (session.SessionEvent, bool) {
	if e.text == "" {
		return session.SessionEvent{}, false
	}
	return session.SessionEvent{
		Timestamp:   e.timestamp,
		EventType:   session.SessionEventInput,
		ChannelType: e.channel,
		Data:        []byte(e.text),
		Rendered:    true,
	}, true
}
