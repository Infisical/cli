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
	PaletteCreateSecret
	PaletteCreateSecretInEnv
	PaletteNavigatePath
)

// PaletteResultMsg is emitted when an item is selected in the command palette
type PaletteResultMsg struct {
	Action PaletteAction
	Data   string
}

// PaletteContext provides all the data the command palette needs to build its items
type PaletteContext struct {
	SecretKeys   []string
	Environments []string
	Recents      []string
	Pins         []string
	CurrentEnv   string
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
func (m *CmdPaletteModel) Show(ctx PaletteContext) {
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

	// Create secret actions
	m.items = append(m.items, PaletteItem{
		Label: "Create new secret", Category: "action",
		Action: PaletteCreateSecret,
	})
	for _, env := range ctx.Environments {
		if env != ctx.CurrentEnv {
			m.items = append(m.items, PaletteItem{
				Label:    fmt.Sprintf("Create secret in %s", env),
				Category: "action",
				Action:   PaletteCreateSecretInEnv,
				Data:     env,
			})
		}
	}

	// Pinned secrets
	for _, pin := range ctx.Pins {
		m.items = append(m.items, PaletteItem{
			Label: "★ " + pin, Category: "pinned",
			Action: PaletteGoToSecret, Data: pin,
		})
	}

	// Recent secrets (max 5)
	shown := 0
	for _, key := range ctx.Recents {
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
	for _, key := range ctx.SecretKeys {
		m.items = append(m.items, PaletteItem{
			Label: key, Category: "secret",
			Action: PaletteGoToSecret, Data: key,
		})
	}

	// Environments with friendly labels
	for _, env := range ctx.Environments {
		label := "Switch to " + env
		if env == ctx.CurrentEnv {
			label = "Switch to " + env + " (current)"
		}
		m.items = append(m.items, PaletteItem{
			Label: label, Category: "env",
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
			if matchesQuery(item, query) {
				m.filtered = append(m.filtered, item)
			}
		}
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
}

// matchesQuery checks if an item matches the search query, including common aliases
func matchesQuery(item PaletteItem, query string) bool {
	label := strings.ToLower(item.Label)
	cat := strings.ToLower(item.Category)

	// Direct substring match on label or category
	if strings.Contains(label, query) || strings.Contains(cat, query) {
		return true
	}

	// Alias matching: expand query to check synonyms
	aliases := map[string][]string{
		"prod":       {"production"},
		"production": {"prod"},
		"stg":        {"staging"},
		"stage":      {"staging"},
		"staging":    {"stg", "stage"},
		"dev":        {"development"},
		"development": {"dev"},
		"create":     {"new", "add"},
		"new":        {"create", "add"},
		"add":        {"create", "new"},
		"switch":     {"env", "navigate"},
		"go to":      {"switch", "navigate"},
	}
	if synonyms, ok := aliases[query]; ok {
		for _, syn := range synonyms {
			if strings.Contains(label, syn) {
				return true
			}
		}
	}

	return false
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
	case "navigate":
		return "Navigation"
	case "project":
		return "Projects"
	case "path":
		return "Paths"
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
