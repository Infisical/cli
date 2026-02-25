package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	formStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7C3AED")).
			Padding(1, 2).
			Width(60)

	formTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C3AED")).
			Bold(true)

	formLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981")).
			Bold(true).
			Width(10)

	formHintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))
)

// SecretCreatedMsg is sent when a secret form is submitted
type SecretCreatedMsg struct {
	Key   string
	Value string
}

type SecretFormModel struct {
	Visible    bool
	keyInput   textinput.Model
	valueInput textinput.Model
	focusIndex int // 0 = key, 1 = value
}

func NewSecretForm() SecretFormModel {
	ki := textinput.New()
	ki.Placeholder = "SECRET_KEY"
	ki.CharLimit = 256
	ki.Prompt = ""

	vi := textinput.New()
	vi.Placeholder = "secret_value"
	vi.CharLimit = 4096
	vi.Prompt = ""

	return SecretFormModel{
		keyInput:   ki,
		valueInput: vi,
	}
}

func (m *SecretFormModel) Show() {
	m.Visible = true
	m.focusIndex = 0
	m.keyInput.SetValue("")
	m.valueInput.SetValue("")
	m.keyInput.Focus()
	m.valueInput.Blur()
}

func (m *SecretFormModel) Hide() {
	m.Visible = false
	m.keyInput.Blur()
	m.valueInput.Blur()
}

func (m SecretFormModel) Update(msg tea.Msg) (SecretFormModel, tea.Cmd) {
	if !m.Visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, key.NewBinding(key.WithKeys("esc"))):
			m.Visible = false
			return m, nil
		case key.Matches(msg, key.NewBinding(key.WithKeys("tab"))):
			if m.focusIndex == 0 {
				m.focusIndex = 1
				m.keyInput.Blur()
				m.valueInput.Focus()
			} else {
				m.focusIndex = 0
				m.valueInput.Blur()
				m.keyInput.Focus()
			}
			return m, nil
		case key.Matches(msg, key.NewBinding(key.WithKeys("enter"))):
			if m.focusIndex == 0 {
				// Move to value field
				m.focusIndex = 1
				m.keyInput.Blur()
				m.valueInput.Focus()
				return m, nil
			}
			// Submit
			k := m.keyInput.Value()
			v := m.valueInput.Value()
			if k != "" && v != "" {
				m.Visible = false
				return m, func() tea.Msg {
					return SecretCreatedMsg{Key: k, Value: v}
				}
			}
			return m, nil
		}
	}

	var cmds []tea.Cmd
	var cmd tea.Cmd

	if m.focusIndex == 0 {
		m.keyInput, cmd = m.keyInput.Update(msg)
		cmds = append(cmds, cmd)
	} else {
		m.valueInput, cmd = m.valueInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m SecretFormModel) View() string {
	if !m.Visible {
		return ""
	}

	content := fmt.Sprintf("%s\n\n%s %s\n\n%s %s\n\n%s",
		formTitleStyle.Render("Create New Secret"),
		formLabelStyle.Render("Key:"),
		m.keyInput.View(),
		formLabelStyle.Render("Value:"),
		m.valueInput.View(),
		formHintStyle.Render("Tab to switch fields, Enter to submit, Esc to cancel"),
	)

	return formStyle.Render(content)
}
