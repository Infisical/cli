package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	envPickerStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7C3AED")).
			Padding(1, 2).
			Width(40)

	envPickerTitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C3AED")).
			Bold(true)

	envItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB")).
			Padding(0, 1)

	envSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F9FAFB")).
				Background(lipgloss.Color("#8B5CF6")).
				Bold(true).
				Padding(0, 1)

	envCurrentStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981"))
)

// EnvSelectedMsg is sent when an environment is selected
type EnvSelectedMsg struct {
	Environment string
}

type EnvPickerModel struct {
	Visible      bool
	Environments []string
	Current      string
	cursor       int
}

func NewEnvPicker() EnvPickerModel {
	return EnvPickerModel{
		Environments: []string{"dev", "staging", "prod"},
	}
}

func (m *EnvPickerModel) Show(current string, envs []string) {
	m.Visible = true
	m.Current = current
	if len(envs) > 0 {
		m.Environments = envs
	}
	m.cursor = 0
	for i, e := range m.Environments {
		if e == current {
			m.cursor = i
			break
		}
	}
}

func (m *EnvPickerModel) Hide() {
	m.Visible = false
}

func (m EnvPickerModel) Update(msg tea.Msg) (EnvPickerModel, tea.Cmd) {
	if !m.Visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, key.NewBinding(key.WithKeys("up", "k"))):
			if m.cursor > 0 {
				m.cursor--
			}
		case key.Matches(msg, key.NewBinding(key.WithKeys("down", "j"))):
			if m.cursor < len(m.Environments)-1 {
				m.cursor++
			}
		case key.Matches(msg, key.NewBinding(key.WithKeys("enter"))):
			selected := m.Environments[m.cursor]
			m.Visible = false
			return m, func() tea.Msg { return EnvSelectedMsg{Environment: selected} }
		case key.Matches(msg, key.NewBinding(key.WithKeys("esc"))):
			m.Visible = false
		}
	}

	return m, nil
}

func (m EnvPickerModel) View() string {
	if !m.Visible {
		return ""
	}

	content := envPickerTitle.Render("Switch Environment") + "\n\n"

	for i, env := range m.Environments {
		marker := "  "
		if env == m.Current {
			marker = envCurrentStyle.Render("* ")
		}

		if i == m.cursor {
			content += fmt.Sprintf("%s%s\n", marker, envSelectedStyle.Render(env))
		} else {
			content += fmt.Sprintf("%s%s\n", marker, envItemStyle.Render(env))
		}
	}

	content += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Render("Enter to select, Esc to cancel")

	return envPickerStyle.Render(content)
}
