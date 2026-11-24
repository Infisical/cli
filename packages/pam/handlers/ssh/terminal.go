package ssh

import (
	"cmp"
	"strings"
	"sync"
	"time"
	"unicode"
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
	parser      *ansi.Parser
	line        []rune
	cursor      int
	width       int  // Columns of the client's terminal (0 if unknown); longer lines wrap onto rows
	wrapPending bool // A row's last column was just written, so the cursor still belongs to that row
	committed   int  // Lines committed so far, which identifies the line still on screen
	screenExits int  // Times a full-screen program left the alternate screen
	alternate   bool // A full-screen program is on the alternate screen
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

func (t *terminalTranscript) ScreenExits() int {
	return t.screenExits
}

// SetWidth applies a new terminal width; a wrap pending at the old width no longer applies.
func (t *terminalTranscript) SetWidth(columns int) {
	t.width, t.wrapPending = min(max(columns, 0), maxLineRunes), false
}

func (t *terminalTranscript) Width() int {
	return t.width
}

func (t *terminalTranscript) Alternate() bool {
	return t.alternate
}

func (t *terminalTranscript) rowStart() int {
	switch {
	case t.width == 0:
		return 0
	case t.wrapPending:
		return max(t.cursor-t.width, 0)
	default:
		return t.cursor - t.cursor%t.width
	}
}

// column returns the cursor's position, which stays in a row's last column until the next character wraps.
func (t *terminalTranscript) column() int {
	if t.wrapPending {
		return t.cursor - 1
	}
	return t.cursor
}

// moveTo puts the cursor at pos and ends any pending wrap.
func (t *terminalTranscript) moveTo(pos int) {
	t.cursor, t.wrapPending = clampColumn(pos), false
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
		// Within a wrapped line a shell moves down to its next row this way.
		if t.width > 0 && t.rowStart()+t.width < len(t.line) {
			t.moveTo(t.column() + t.width)
			return
		}
		*lines = appendLine(*lines, t.commit())
	case '\r':
		t.moveTo(t.rowStart())
	case 0x08:
		t.moveTo(max(t.column()-1, t.rowStart()))
	case '\t':
		start := t.rowStart()
		stop := min(start+((t.column()-start)/tabWidth+1)*tabWidth, maxLineRunes)
		if t.width > 0 {
			stop = min(stop, start+t.width-1)
		}
		for t.cursor < stop {
			t.writeRune(' ', lines)
		}
	}
}

func (t *terminalTranscript) dispatchCSI(lines *[]string) {
	switch t.parser.Command() {
	case 'K', 'J': // erase in line, erase in display
		start := 0
		if t.parser.Command() == 'K' {
			start = t.rowStart()
		}
		// Erasing one row of a wrapped line leaves the rows after it.
		if end := start + t.width; t.parser.Command() == 'K' && t.width > 0 && end < len(t.line) {
			switch t.param(0) {
			case 1:
				t.blank(start, t.column()+1)
			case 2:
				t.blank(start, end)
			default:
				t.blank(t.column(), end)
			}
			break
		}
		switch t.param(0) {
		case 1:
			t.blank(start, t.cursor)
		case 2, 3:
			t.line = t.line[:min(start, len(t.line))]
			t.moveTo(start)
		default:
			t.line = t.line[:min(t.column(), len(t.line))]
		}
	case 'C': // cursor forward
		if t.width > 0 {
			t.moveTo(min(t.column()+t.param(1), t.rowStart()+t.width-1))
		} else {
			t.moveTo(t.cursor + t.param(1))
		}
	case 'D': // cursor back
		t.moveTo(max(t.column()-t.param(1), t.rowStart()))
	case 'G', '`': // absolute column
		if t.width > 0 {
			t.moveTo(t.rowStart() + min(max(t.param(1)-1, 0), t.width-1))
		} else {
			t.moveTo(t.param(1) - 1)
		}
	case 'P': // delete characters
		t.deleteChars(t.param(1))
	case '@': // insert blanks
		t.insertBlanks(t.param(1))
	case 'X': // erase characters
		t.blank(t.column(), min(t.column()+t.param(1), t.rowEnd()))
	case 'A': // cursor up, which stays within a wrapped line while it has rows above
		if start := t.rowStart(); t.width > 0 && start >= t.width {
			t.moveTo(t.column() - min(t.param(1), start/t.width)*t.width)
		} else {
			*lines = appendLine(*lines, t.commit())
		}
	case 'B': // cursor down, which stays within a wrapped line while it has rows below
		if start := t.rowStart(); t.width > 0 && start+t.width < len(t.line) {
			t.moveTo(t.column() + min(t.param(1), (len(t.line)-1-start)/t.width)*t.width)
		} else {
			*lines = appendLine(*lines, t.commit())
		}
	case 'E', 'F', 'H', 'f', 'd': // moves to other lines or absolute positions, which no row maps to
		*lines = appendLine(*lines, t.commit())
	case '?'<<8 | 'h': // private mode set; 47, 1047 and 1049 switch to the alternate screen
		if mode := t.param(0); mode == 47 || mode == 1047 || mode == 1049 {
			*lines = appendLine(*lines, t.commit())
			t.alternate = true
		}
	case '?'<<8 | 'l': // private mode reset; 47, 1047 and 1049 switch back, leaving what was drawn behind
		if mode := t.param(0); mode == 47 || mode == 1047 || mode == 1049 {
			*lines = appendLine(*lines, t.commit())
			t.alternate = false
			t.screenExits++
		}
	}
}

func (t *terminalTranscript) param(fallback int) int {
	n, _ := t.parser.Param(0, fallback)
	return min(max(n, 0), maxLineRunes)
}

func (t *terminalTranscript) commit() string {
	line := strings.TrimRight(string(t.line), " ")
	t.line, t.cursor, t.wrapPending = t.line[:0], 0, false
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
	t.wrapPending = t.width > 0 && t.cursor%t.width == 0
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

// rowEnd returns where the row holding the cursor ends, or the line limit when rows are unknown.
func (t *terminalTranscript) rowEnd() int {
	if t.width == 0 {
		return maxLineRunes
	}
	return t.rowStart() + t.width
}

// deleteChars removes n characters at the cursor, shifting only the cursor's row.
func (t *terminalTranscript) deleteChars(n int) {
	col := t.column()
	if n <= 0 || col >= len(t.line) {
		return
	}
	if end := t.rowEnd(); end < len(t.line) {
		n = min(n, end-col)
		copy(t.line[col:], t.line[col+n:end])
		t.blank(end-n, end)
		return
	}
	t.line = append(t.line[:col], t.line[min(col+n, len(t.line)):]...)
}

// insertBlanks opens n blanks at the cursor, losing what the shift pushes past the row's end.
func (t *terminalTranscript) insertBlanks(n int) {
	col := t.column()
	t.padTo(col)
	end := t.rowEnd()
	if n = min(n, end-col, maxLineRunes-col); n <= 0 {
		return
	}
	if grown := min(len(t.line)+n, end, maxLineRunes); grown > len(t.line) {
		t.line = append(t.line, make([]rune, grown-len(t.line))...)
	}
	last := min(end, len(t.line))
	copy(t.line[col+n:last], t.line[col:last-n])
	t.blank(col, col+n)
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

// enteredCommand is a command line entered at a shell; line and baseline say where typing began.
type enteredCommand struct {
	text      string
	masked    string // text as output masking shows it
	recalled  bool   // History keys were used, so the line can show more than was typed
	line      uint32
	baseline  int
	timestamp time.Time
	channel   session.SessionChannelType
}

// echoStart returns where typed text starts on a line ending with its echo; tabs show as spaces, so whitespace runs match.
func (e enteredCommand) echoStart(line string) (int, bool) {
	if e.recalled {
		return 0, false
	}
	if start, ok := echoStartOf(e.text, line); ok || e.masked == "" || e.masked == e.text {
		return start, ok
	}
	return echoStartOf(e.masked, line)
}

func echoStartOf(text, line string) (int, bool) {
	typed, shown := []rune(strings.TrimSpace(text)), []rune(line)
	if len(typed) == 0 {
		return 0, false
	}
	i, j := len(shown)-1, len(typed)-1
	for j >= 0 {
		if unicode.IsSpace(typed[j]) {
			for j >= 0 && unicode.IsSpace(typed[j]) {
				j--
			}
			if i < 0 || !unicode.IsSpace(shown[i]) {
				return 0, false
			}
			for i >= 0 && unicode.IsSpace(shown[i]) {
				i--
			}
			continue
		}
		if i < 0 || shown[i] != typed[j] {
			return 0, false
		}
		i, j = i-1, j-1
	}
	if i >= 0 && !unicode.IsSpace(shown[i]) {
		return 0, false
	}
	return i + 1, true
}

// completionStart finds text a completion extended by the part typed before the first tab.
func (e enteredCommand) completionStart(line string) (int, bool) {
	before, _, completed := strings.Cut(e.text, "\t")
	typed := strings.TrimSpace(before)
	if e.recalled || !completed || typed == "" {
		return 0, false
	}
	for at := len(line) - len(typed); at >= 0; at-- {
		if strings.HasPrefix(line[at:], typed) && (at == 0 || line[at-1] == ' ') {
			return utf8.RuneCountInString(line[:at]), true
		}
	}
	return 0, false
}

// startOn returns where the command starts on a line that shows it: by its echo, or with byPosition on the line
// typing began on, by where it began unless that line was still empty.
func (e enteredCommand) startOn(line string, sameLine, byPosition bool) (int, bool) {
	grew := utf8.RuneCountInString(line) > e.baseline
	if start, ok := e.echoStart(line); ok && (grew || !sameLine) {
		return start, true
	}
	if start, ok := e.completionStart(line); ok && (grew || !sameLine) {
		return start, true
	}
	if byPosition && sameLine && grew && e.baseline > 0 {
		return e.baseline, true
	}
	return 0, false
}

// echoedCommand holds commands until the output shows whether the shell echoed
// them. The echoed line is the better record: it carries the prompt and reflects
// tab completion and history recall.
type echoedCommand struct {
	mutex sync.Mutex
	held  []heldCommand
}

type heldCommand struct {
	enteredCommand
	next bool // Entered at an unchanged line with nothing ahead of it, so the next committed line settles it
}

// maxHeldCommands bounds what the shell never echoes; past it the oldest command is dropped.
const maxHeldCommands = 64

func (e *echoedCommand) hold(command enteredCommand, next bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if len(e.held) == maxHeldCommands {
		e.held = e.held[1:]
	}
	e.held = append(e.held, heldCommand{command, next && len(e.held) == 0})
}

func (e *echoedCommand) empty() bool {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return len(e.held) == 0
}

func (e *echoedCommand) clear() {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.held = nil
}

// settle matches a committed line to the held command it shows; those held before it were never echoed. A next
// command is settled by this line either way, so an unechoed secret never matches later output.
func (e *echoedCommand) settle(line string) (echoedAt int, unechoed []session.SessionEvent) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	for k, held := range e.held {
		sameLine := k == 0 && held.next
		if start, ok := held.startOn(line, sameLine, sameLine && (held.recalled || held.text == "")); ok {
			unechoed = inputEvents(e.held[:k])
			e.held = e.held[k+1:]
			return start, unechoed
		}
	}
	if len(e.held) > 0 && e.held[0].next {
		unechoed = inputEvents(e.held[:1])
		e.held = e.held[1:]
	}
	return -1, unechoed
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

	events := inputEvents(e.held)
	e.held = nil
	return events
}

func inputEvents(held []heldCommand) []session.SessionEvent {
	var events []session.SessionEvent
	for _, h := range held {
		if event, ok := h.inputEvent(); ok {
			events = append(events, event)
		}
	}
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
		Data:        []byte(cmp.Or(e.masked, e.text)),
		Rendered:    true,
	}, true
}
