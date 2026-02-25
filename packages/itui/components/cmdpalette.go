package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// PaletteAction identifies what a command palette item does
type PaletteAction int

const (
	PaletteGoToSecret PaletteAction = iota
	PaletteGoToEnv
	PaletteCopyCLI
	PaletteOpenHelp
	PaletteCopyValue
)

// PaletteResultMsg is emitted when an item is selected in the command palette
type PaletteResultMsg struct {
	Action PaletteAction
	Data   string
}

// PaletteItem is a single entry in the command palette
type PaletteItem struct {
	Label    string
	Category string // "action", "pinned", "recent", "secret", "env"
	Action   PaletteAction
	Data     string
}

var (
	paletteStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7C3AED")).
			Padding(1, 2).
			Width(60)

	paletteTitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#7C3AED")).
				Bold(true)

	paletteCategoryStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F59E0B")).
				Bold(true).
				Padding(1, 0, 0, 0)

	paletteItemStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F9FAFB")).
				Padding(0, 1)

	paletteSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F9FAFB")).
				Background(lipgloss.Color("#8B5CF6")).
				Bold(true).
				Padding(0, 1)

	palettePinStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B"))
)

// CmdPaletteModel is the command palette overlay
type CmdPaletteModel struct {
	Visible     bool
	searchInput textinput.Model
	items       []PaletteItem
	filtered    []PaletteItem
	cursor      int
	maxVisible  int
}

// NewCmdPalette creates a new command palette
func NewCmdPalette() CmdPaletteModel {
	ti := textinput.New()
	ti.Placeholder = "Type to search..."
	ti.CharLimit = 100
	ti.Prompt = "  "
	ti.Width = 50

	return CmdPaletteModel{
		searchInput: ti,
		maxVisible:  15,
	}
}

// Show opens the palette and populates it with current data
func (m *CmdPaletteModel) Show(secretKeys []string, envs []string, recents []string, pins []string) {
	m.Visible = true
	m.searchInput.SetValue("")
	m.searchInput.Focus()
	m.cursor = 0

	// Build items list in priority order
	m.items = nil

	// Static actions
	m.items = append(m.items, PaletteItem{
		Label: "Copy CLI command for current view", Category: "action",
		Action: PaletteCopyCLI,
	})
	m.items = append(m.items, PaletteItem{
		Label: "Copy secret value", Category: "action",
		Action: PaletteCopyValue,
	})
	m.items = append(m.items, PaletteItem{
		Label: "Open Help", Category: "action",
		Action: PaletteOpenHelp,
	})

	// Pinned secrets
	for _, pin := range pins {
		m.items = append(m.items, PaletteItem{
			Label: "★ " + pin, Category: "pinned",
			Action: PaletteGoToSecret, Data: pin,
		})
	}

	// Recent secrets (max 5)
	shown := 0
	for _, key := range recents {
		if shown >= 5 {
			break
		}
		m.items = append(m.items, PaletteItem{
			Label: key, Category: "recent",
			Action: PaletteGoToSecret, Data: key,
		})
		shown++
	}

	// All secrets
	for _, key := range secretKeys {
		m.items = append(m.items, PaletteItem{
			Label: key, Category: "secret",
			Action: PaletteGoToSecret, Data: key,
		})
	}

	// Environments
	for _, env := range envs {
		m.items = append(m.items, PaletteItem{
			Label: env, Category: "env",
			Action: PaletteGoToEnv, Data: env,
		})
	}

	m.applyFilter()
}

// Hide closes the palette
func (m *CmdPaletteModel) Hide() {
	m.Visible = false
	m.searchInput.Blur()
}

func (m *CmdPaletteModel) applyFilter() {
	query := strings.ToLower(m.searchInput.Value())
	if query == "" {
		m.filtered = m.items
	} else {
		m.filtered = nil
		for _, item := range m.items {
			if strings.Contains(strings.ToLower(item.Label), query) ||
				strings.Contains(strings.ToLower(item.Category), query) {
				m.filtered = append(m.filtered, item)
			}
		}
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
}

// Update handles input events
func (m CmdPaletteModel) Update(msg tea.Msg) (CmdPaletteModel, tea.Cmd) {
	if !m.Visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, key.NewBinding(key.WithKeys("esc"))):
			m.Visible = false
			m.searchInput.Blur()
			return m, nil

		case key.Matches(msg, key.NewBinding(key.WithKeys("up"))):
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil

		case key.Matches(msg, key.NewBinding(key.WithKeys("down"))):
			if m.cursor < len(m.filtered)-1 {
				m.cursor++
			}
			return m, nil

		case key.Matches(msg, key.NewBinding(key.WithKeys("enter"))):
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				selected := m.filtered[m.cursor]
				m.Visible = false
				m.searchInput.Blur()
				return m, func() tea.Msg {
					return PaletteResultMsg{Action: selected.Action, Data: selected.Data}
				}
			}
			return m, nil
		}
	}

	// Update text input (for typing filter)
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	m.applyFilter()
	return m, cmd
}

// View renders the command palette
func (m CmdPaletteModel) View() string {
	if !m.Visible {
		return ""
	}

	var b strings.Builder
	b.WriteString(paletteTitleStyle.Render("Command Palette") + "  ")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Render("Ctrl+K"))
	b.WriteString("\n\n")
	b.WriteString(m.searchInput.View())
	b.WriteString("\n")

	// Group items by category for display
	lastCategory := ""
	visibleCount := 0

	for i, item := range m.filtered {
		if visibleCount >= m.maxVisible {
			remaining := len(m.filtered) - visibleCount
			b.WriteString(fmt.Sprintf("\n  ... and %d more", remaining))
			break
		}

		// Category header
		if item.Category != lastCategory {
			header := categoryDisplayName(item.Category)
			b.WriteString(paletteCategoryStyle.Render(header))
			b.WriteString("\n")
			lastCategory = item.Category
		}

		// Item
		label := item.Label
		if i == m.cursor {
			b.WriteString(fmt.Sprintf("  ▸ %s\n", paletteSelectedStyle.Render(label)))
		} else {
			b.WriteString(fmt.Sprintf("    %s\n", paletteItemStyle.Render(label)))
		}
		visibleCount++
	}

	if len(m.filtered) == 0 {
		b.WriteString("\n  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Italic(true).Render("No results"))
	}

	b.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Render("↑/↓ navigate, Enter select, Esc close"))

	return paletteStyle.Render(b.String())
}

func categoryDisplayName(cat string) string {
	switch cat {
	case "action":
		return "Actions"
	case "pinned":
		return "Pinned"
	case "recent":
		return "Recent"
	case "secret":
		return "Secrets"
	case "env":
		return "Environments"
	default:
		return cat
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
