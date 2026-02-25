package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type PromptState int

const (
	PromptStateIdle PromptState = iota
	PromptStateInput
	PromptStateLoading
	PromptStatePreview
)

var (
	promptBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1)

	promptActiveBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#10B981")).
				Padding(0, 1)

	promptPrefix = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981")).
			Bold(true)

	cmdPreviewStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B")).
			Italic(true)

	explanationStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6B7280"))

	actionReadStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981"))

	actionWriteStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F59E0B"))

	actionDestructiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#EF4444")).
				Bold(true)
)

type PromptBarModel struct {
	textInput textinput.Model
	spinner   spinner.Model
	Active    bool
	State     PromptState
	Width     int

	// Preview state
	PreviewCommand   string
	PreviewExplanation string
	PreviewActionType  string
	PreviewConfirm     bool
}

func NewPromptBar() PromptBarModel {
	ti := textinput.New()
	ti.Placeholder = "Ask me anything about your secrets..."
	ti.CharLimit = 500
	ti.Prompt = ""

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED"))

	return PromptBarModel{
		textInput: ti,
		spinner:   s,
		State:     PromptStateIdle,
	}
}

func (m *PromptBarModel) Focus() {
	m.Active = true
	m.State = PromptStateInput
	m.textInput.Focus()
}

func (m *PromptBarModel) Blur() {
	m.Active = false
	m.State = PromptStateIdle
	m.textInput.Blur()
}

func (m *PromptBarModel) SetLoading() {
	m.State = PromptStateLoading
}

func (m *PromptBarModel) SetPreview(command, explanation, actionType string, requiresConfirm bool) {
	m.State = PromptStatePreview
	m.PreviewCommand = command
	m.PreviewExplanation = explanation
	m.PreviewActionType = actionType
	m.PreviewConfirm = requiresConfirm
}

func (m *PromptBarModel) Reset() {
	m.textInput.SetValue("")
	m.State = PromptStateInput
	m.PreviewCommand = ""
	m.PreviewExplanation = ""
	m.PreviewActionType = ""
	m.PreviewConfirm = false
}

func (m *PromptBarModel) Value() string {
	return m.textInput.Value()
}

func (m *PromptBarModel) SetWidth(width int) {
	m.Width = width
	m.textInput.Width = width - 10 // account for border, padding, prefix
}

func (m PromptBarModel) Update(msg tea.Msg) (PromptBarModel, tea.Cmd) {
	var cmds []tea.Cmd

	if m.State == PromptStateLoading {
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.Active && (m.State == PromptStateInput || m.State == PromptStateIdle) {
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m PromptBarModel) View() string {
	style := promptBorder
	if m.Active {
		style = promptActiveBorder
	}

	if m.Width > 0 {
		style = style.Width(m.Width - 2)
	}

	var content string

	switch m.State {
	case PromptStateIdle:
		content = fmt.Sprintf("%s %s", promptPrefix.Render("AI >"), m.textInput.View())
	case PromptStateInput:
		content = fmt.Sprintf("%s %s", promptPrefix.Render("AI >"), m.textInput.View())
	case PromptStateLoading:
		content = fmt.Sprintf("%s Thinking...", m.spinner.View())
	case PromptStatePreview:
		actionStyle := actionReadStyle
		switch m.PreviewActionType {
		case "write":
			actionStyle = actionWriteStyle
		case "destructive":
			actionStyle = actionDestructiveStyle
		}

		line1 := fmt.Sprintf("%s %s  %s",
			promptPrefix.Render("AI >"),
			explanationStyle.Render(m.PreviewExplanation),
			actionStyle.Render("["+m.PreviewActionType+"]"),
		)

		line2 := fmt.Sprintf("  %s %s",
			cmdPreviewStyle.Render("Will run:"),
			cmdPreviewStyle.Render(m.PreviewCommand),
		)

		confirmHint := "  Press Enter to execute, Esc to cancel"
		if m.PreviewConfirm {
			confirmHint = "  Press y to confirm, Esc to cancel"
		}

		content = line1 + "\n" + line2 + "\n" + explanationStyle.Render(confirmHint)
	}

	return style.Render(content)
}
