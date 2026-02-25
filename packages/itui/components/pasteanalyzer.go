package components

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// PasteAnalysisMsg is emitted when the analyzer has a suggestion
type PasteAnalysisMsg struct {
	SuggestedCommand string
	Explanation      string
}

type errorPattern struct {
	Pattern   *regexp.Regexp
	Diagnosis string
	Command   string // empty if no auto-command
}

var errorPatterns = []errorPattern{
	{
		Pattern:   regexp.MustCompile(`(?i)(not logged in|login.*expired|unauthorized|401|auth.*fail)`),
		Diagnosis: "Authentication error — you may need to log in again",
		Command:   "infisical login",
	},
	{
		Pattern:   regexp.MustCompile(`(?i)(project not found|workspace.*not found|no \.infisical\.json|run infisical init)`),
		Diagnosis: "Project not linked — connect to a project first",
		Command:   "infisical init",
	},
	{
		Pattern:   regexp.MustCompile(`(?i)(secret.*not found|key.*not found|no secrets found)`),
		Diagnosis: "Secret not found — check the key name and environment",
		Command:   "",
	},
	{
		Pattern:   regexp.MustCompile(`(?i)(permission denied|forbidden|403|access denied)`),
		Diagnosis: "Permission denied — check your access level for this project/environment",
		Command:   "",
	},
	{
		Pattern:   regexp.MustCompile(`(?i)(ECONNREFUSED|connection refused|timeout|network|DNS|resolve)`),
		Diagnosis: "Network connectivity issue — check your internet connection or VPN",
		Command:   "",
	},
	{
		Pattern:   regexp.MustCompile(`(?i)(rate limit|too many requests|429)`),
		Diagnosis: "Rate limited — wait a moment and try again",
		Command:   "",
	},
	{
		Pattern:   regexp.MustCompile(`(?i)(command not found|not recognized|unknown command)`),
		Diagnosis: "Command not found — is the Infisical CLI installed?",
		Command:   "",
	},
}

var (
	pasteStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7C3AED")).
			Padding(1, 2).
			Width(60)

	pasteTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C3AED")).
			Bold(true)

	pasteDiagStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B")).
			Bold(true)

	pasteCmdStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981")).
			Italic(true)

	pasteHintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))
)

// PasteAnalyzerModel is the paste-and-analyze overlay
type PasteAnalyzerModel struct {
	Visible   bool
	textInput textinput.Model
	analysis  string
	command   string
	analyzed  bool
}

// NewPasteAnalyzer creates a new paste analyzer
func NewPasteAnalyzer() PasteAnalyzerModel {
	ti := textinput.New()
	ti.Placeholder = "Paste terminal output here..."
	ti.CharLimit = 2000
	ti.Prompt = "  "
	ti.Width = 50

	return PasteAnalyzerModel{
		textInput: ti,
	}
}

// Show opens the analyzer and focuses the text input
func (m *PasteAnalyzerModel) Show() {
	m.Visible = true
	m.textInput.SetValue("")
	m.textInput.Focus()
	m.analysis = ""
	m.command = ""
	m.analyzed = false
}

// Hide closes the analyzer
func (m *PasteAnalyzerModel) Hide() {
	m.Visible = false
	m.textInput.Blur()
}

// SetClipboardContent pre-fills the input with clipboard content
func (m *PasteAnalyzerModel) SetClipboardContent(content string) {
	// Truncate long content to first meaningful chunk
	if len(content) > 500 {
		content = content[:500]
	}
	m.textInput.SetValue(content)
}

func (m *PasteAnalyzerModel) analyze() {
	input := m.textInput.Value()
	if input == "" {
		m.analysis = "No input to analyze. Paste terminal output and press Enter."
		m.command = ""
		m.analyzed = true
		return
	}

	for _, ep := range errorPatterns {
		if ep.Pattern.MatchString(input) {
			m.analysis = ep.Diagnosis
			m.command = ep.Command
			m.analyzed = true
			return
		}
	}

	m.analysis = "No known error patterns detected. Try pasting the specific error message."
	m.command = ""
	m.analyzed = true
}

// Update handles input events
func (m PasteAnalyzerModel) Update(msg tea.Msg) (PasteAnalyzerModel, tea.Cmd) {
	if !m.Visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, key.NewBinding(key.WithKeys("esc"))):
			m.Visible = false
			m.textInput.Blur()
			return m, nil

		case key.Matches(msg, key.NewBinding(key.WithKeys("enter"))):
			if m.analyzed && m.command != "" {
				// Emit suggestion
				m.Visible = false
				m.textInput.Blur()
				cmd := m.command
				explanation := m.analysis
				return m, func() tea.Msg {
					return PasteAnalysisMsg{SuggestedCommand: cmd, Explanation: explanation}
				}
			}
			// First enter: analyze
			m.analyze()
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

// View renders the paste analyzer
func (m PasteAnalyzerModel) View() string {
	if !m.Visible {
		return ""
	}

	var b strings.Builder
	b.WriteString(pasteTitleStyle.Render("Paste & Analyze Terminal Output"))
	b.WriteString("  ")
	b.WriteString(pasteHintStyle.Render("Ctrl+V"))
	b.WriteString("\n\n")
	b.WriteString(pasteHintStyle.Render("Paste your error output below:"))
	b.WriteString("\n")
	b.WriteString(m.textInput.View())
	b.WriteString("\n")

	if m.analyzed {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#374151")).Render("─── Analysis ───"))
		b.WriteString("\n\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", pasteDiagStyle.Render("●"), m.analysis))

		if m.command != "" {
			b.WriteString(fmt.Sprintf("\n  %s %s\n", pasteCmdStyle.Render("Suggestion:"), pasteCmdStyle.Render(m.command)))
			b.WriteString("\n" + pasteHintStyle.Render("  Enter to execute suggestion, Esc to close"))
		} else {
			b.WriteString("\n" + pasteHintStyle.Render("  Esc to close"))
		}
	} else {
		b.WriteString("\n" + pasteHintStyle.Render("  Enter to analyze, Esc to close"))
	}

	return pasteStyle.Render(b.String())
}
