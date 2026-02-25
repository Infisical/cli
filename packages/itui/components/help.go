package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	helpModalStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7C3AED")).
			Padding(1, 2).
			Width(60)

	helpTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C3AED")).
			Bold(true)

	helpKeyBind = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981")).
			Bold(true).
			Width(16)

	helpDescBind = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB"))

	helpSectionStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F59E0B")).
				Bold(true).
				Padding(1, 0, 0, 0)
)

type HelpModel struct {
	Visible  bool
	viewport viewport.Model
}

func NewHelp() HelpModel {
	vp := viewport.New(56, 20)
	vp.SetContent(helpContent())
	return HelpModel{
		viewport: vp,
	}
}

func (m *HelpModel) Show() {
	m.Visible = true
}

func (m *HelpModel) Hide() {
	m.Visible = false
}

func (m HelpModel) Update(msg tea.Msg) (HelpModel, tea.Cmd) {
	if !m.Visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, key.NewBinding(key.WithKeys("esc", "?", "q"))):
			m.Visible = false
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m HelpModel) View() string {
	if !m.Visible {
		return ""
	}

	content := helpTitleStyle.Render("ITUI Keyboard Shortcuts") + "\n" + m.viewport.View() + "\n\n" +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Render("Press Esc or ? to close")

	return helpModalStyle.Render(content)
}

func helpContent() string {
	sections := []struct {
		title string
		binds []struct{ key, desc string }
	}{
		{
			title: "Navigation",
			binds: []struct{ key, desc string }{
				{"Tab / Shift+Tab", "Switch between panes"},
				{"Up / Down / j / k", "Navigate secret list"},
				{"Enter", "Select / expand secret"},
				{"Ctrl+P", "Focus AI prompt bar"},
			},
		},
		{
			title: "Secrets",
			binds: []struct{ key, desc string }{
				{"r", "Reveal / mask secret value"},
				{"n", "Create new secret"},
				{"d", "Delete selected secret"},
				{"e", "Switch environment"},
				{"/", "Search / filter secrets"},
				{"R", "Refresh secrets"},
			},
		},
		{
			title: "AI Prompt",
			binds: []struct{ key, desc string }{
				{"Ctrl+P", "Focus prompt bar"},
				{"Enter", "Send prompt / execute command"},
				{"Esc", "Cancel / clear prompt"},
			},
		},
		{
			title: "Clipboard & Tools",
			binds: []struct{ key, desc string }{
				{"Ctrl+K", "Command palette"},
				{"c", "Copy value / output"},
				{"Ctrl+L", "Copy CLI deep link"},
				{"Ctrl+V", "Paste & analyze output"},
			},
		},
		{
			title: "General",
			binds: []struct{ key, desc string }{
				{"?", "Toggle this help"},
				{"q / Ctrl+C", "Quit ITUI"},
			},
		},
	}

	var content string
	for _, section := range sections {
		content += helpSectionStyle.Render(section.title) + "\n"
		for _, b := range section.binds {
			content += fmt.Sprintf("  %s%s\n", helpKeyBind.Render(b.key), helpDescBind.Render(b.desc))
		}
	}

	content += "\n" + helpSectionStyle.Render("Example AI Prompts") + "\n"
	examples := []string{
		"show me all production secrets",
		"set DATABASE_URL to postgres://... in staging",
		"delete the old API key in dev",
		"compare staging and prod secrets",
		"export all dev secrets as .env",
	}
	for _, ex := range examples {
		content += fmt.Sprintf("  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#C4B5FD")).Italic(true).Render("\""+ex+"\""))
	}

	return content
}
