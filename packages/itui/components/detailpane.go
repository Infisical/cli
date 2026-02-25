package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type DetailMode int

const (
	DetailModeSecret DetailMode = iota
	DetailModeOutput
	DetailModeWelcome
)

var (
	detailBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1)

	detailActiveBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#7C3AED")).
				Padding(0, 1)

	dLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280")).
			Width(12)

	dValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB"))

	dKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981")).
			Bold(true)

	dMaskedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B"))

	dErrorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444"))

	dSuccessStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981"))

	dTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C3AED")).
			Bold(true).
			Padding(0, 0, 1, 0)
)

type DetailPaneModel struct {
	viewport viewport.Model
	Active   bool
	Mode     DetailMode
	Width    int
	Height   int

	// Secret detail
	SecretKey     string
	SecretValue   string
	SecretType    string
	SecretPath    string
	SecretComment string
	ValueRevealed bool

	// Command output
	OutputTitle   string
	OutputContent string
	OutputIsError bool
}

func NewDetailPane() DetailPaneModel {
	vp := viewport.New(30, 10)
	return DetailPaneModel{
		viewport: vp,
		Mode:     DetailModeWelcome,
	}
}

func (m *DetailPaneModel) SetSize(width, height int) {
	m.Width = width
	m.Height = height
	m.viewport.Width = width - 4 // border + padding
	m.viewport.Height = height - 4
}

func (m *DetailPaneModel) SetSecret(key, value, secretType, path, comment string) {
	m.Mode = DetailModeSecret
	m.SecretKey = key
	m.SecretValue = value
	m.SecretType = secretType
	m.SecretPath = path
	m.SecretComment = comment
	m.ValueRevealed = false
	m.updateViewportContent()
}

func (m *DetailPaneModel) SetOutput(title, content string, isError bool) {
	m.Mode = DetailModeOutput
	m.OutputTitle = title
	m.OutputContent = content
	m.OutputIsError = isError
	m.updateViewportContent()
}

func (m *DetailPaneModel) ToggleReveal() {
	if m.Mode == DetailModeSecret {
		m.ValueRevealed = !m.ValueRevealed
		m.updateViewportContent()
	}
}

func (m *DetailPaneModel) updateViewportContent() {
	var content string

	switch m.Mode {
	case DetailModeSecret:
		content = m.renderSecretDetail()
	case DetailModeOutput:
		content = m.renderOutput()
	case DetailModeWelcome:
		content = m.renderWelcome()
	}

	m.viewport.SetContent(content)
}

func (m *DetailPaneModel) renderSecretDetail() string {
	var b strings.Builder

	b.WriteString(dTitleStyle.Render("Secret Detail"))
	b.WriteString("\n\n")

	b.WriteString(dLabelStyle.Render("Key:"))
	b.WriteString("  ")
	b.WriteString(dKeyStyle.Render(m.SecretKey))
	b.WriteString("\n\n")

	b.WriteString(dLabelStyle.Render("Value:"))
	b.WriteString("  ")
	if m.ValueRevealed {
		b.WriteString(dValueStyle.Render(m.SecretValue))
	} else {
		b.WriteString(dMaskedStyle.Render("••••••••  [press r to reveal]"))
	}
	b.WriteString("\n\n")

	b.WriteString(dLabelStyle.Render("Type:"))
	b.WriteString("  ")
	b.WriteString(dValueStyle.Render(m.SecretType))
	b.WriteString("\n\n")

	b.WriteString(dLabelStyle.Render("Path:"))
	b.WriteString("  ")
	b.WriteString(dValueStyle.Render(m.SecretPath))

	if m.SecretComment != "" {
		b.WriteString("\n\n")
		b.WriteString(dLabelStyle.Render("Comment:"))
		b.WriteString("  ")
		b.WriteString(dValueStyle.Render(m.SecretComment))
	}

	return b.String()
}

func (m *DetailPaneModel) renderOutput() string {
	var b strings.Builder

	title := dTitleStyle.Render(m.OutputTitle)
	b.WriteString(title)
	b.WriteString("\n\n")

	if m.OutputIsError {
		b.WriteString(dErrorStyle.Render(m.OutputContent))
	} else {
		b.WriteString(dValueStyle.Render(m.OutputContent))
	}

	return b.String()
}

func (m *DetailPaneModel) renderWelcome() string {
	var b strings.Builder

	b.WriteString(dTitleStyle.Render("Welcome to ITUI"))
	b.WriteString("\n\n")
	b.WriteString(dValueStyle.Render("Infisical Terminal UI"))
	b.WriteString("\n\n")
	b.WriteString(dLabelStyle.Render("Get started:"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n", dKeyStyle.Render("Ctrl+P"), "Focus AI prompt"))
	b.WriteString(fmt.Sprintf("  %s  %s\n", dKeyStyle.Render("Enter"), "View secret detail"))
	b.WriteString(fmt.Sprintf("  %s  %s\n", dKeyStyle.Render("e"), "Switch environment"))
	b.WriteString(fmt.Sprintf("  %s  %s\n", dKeyStyle.Render("n"), "Create new secret"))
	b.WriteString(fmt.Sprintf("  %s  %s\n", dKeyStyle.Render("?"), "Show all shortcuts"))

	return b.String()
}

func (m DetailPaneModel) Update(msg tea.Msg) (DetailPaneModel, tea.Cmd) {
	if !m.Active {
		return m, nil
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m DetailPaneModel) View() string {
	style := detailBorder
	if m.Active {
		style = detailActiveBorder
	}

	if m.Width > 0 {
		style = style.Width(m.Width - 2)
	}
	if m.Height > 0 {
		style = style.Height(m.Height - 2)
	}

	m.updateViewportContent()
	return style.Render(m.viewport.View())
}
