package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	confirmStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#F59E0B")).
			Padding(1, 2).
			Width(60)

	confirmDangerStyled = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(lipgloss.Color("#EF4444")).
				Padding(1, 2).
				Width(60)

	confirmTitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F59E0B")).
				Bold(true)

	confirmDangerTitle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#EF4444")).
				Bold(true)

	confirmCmdStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB")).
			Bold(true)

	confirmHintStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6B7280"))
)

// ConfirmYesMsg is sent when user confirms
type ConfirmYesMsg struct {
	Command string
}

// ConfirmNoMsg is sent when user cancels
type ConfirmNoMsg struct{}

type ConfirmModel struct {
	Visible     bool
	Command     string
	Explanation string
	IsDangerous bool
	IsProd      bool
}

func NewConfirm() ConfirmModel {
	return ConfirmModel{}
}

func (m *ConfirmModel) Show(command, explanation string, isDangerous, isProd bool) {
	m.Visible = true
	m.Command = command
	m.Explanation = explanation
	m.IsDangerous = isDangerous
	m.IsProd = isProd
}

func (m *ConfirmModel) Hide() {
	m.Visible = false
}

func (m ConfirmModel) Update(msg tea.Msg) (ConfirmModel, tea.Cmd) {
	if !m.Visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, key.NewBinding(key.WithKeys("y", "Y"))):
			m.Visible = false
			cmd := m.Command
			return m, func() tea.Msg { return ConfirmYesMsg{Command: cmd} }
		case key.Matches(msg, key.NewBinding(key.WithKeys("n", "N", "esc"))):
			m.Visible = false
			return m, func() tea.Msg { return ConfirmNoMsg{} }
		}
	}

	return m, nil
}

func (m ConfirmModel) View() string {
	if !m.Visible {
		return ""
	}

	style := confirmStyle
	title := confirmTitleStyle.Render("Confirm Action")

	if m.IsDangerous {
		style = confirmDangerStyled
		title = confirmDangerTitle.Render("!! DESTRUCTIVE ACTION !!")
	}

	prodWarning := ""
	if m.IsProd {
		prodWarning = "\n" + lipgloss.NewStyle().
			Background(lipgloss.Color("#EF4444")).
			Foreground(lipgloss.Color("#F9FAFB")).
			Bold(true).
			Padding(0, 1).
			Render(" WARNING: This targets PRODUCTION ") + "\n"
	}

	content := fmt.Sprintf("%s\n%s\n%s\n\n%s\n\n%s",
		title,
		prodWarning,
		m.Explanation,
		confirmCmdStyle.Render("$ "+m.Command),
		confirmHintStyle.Render("Press y to confirm, n/Esc to cancel"),
	)

	return style.Render(content)
}
