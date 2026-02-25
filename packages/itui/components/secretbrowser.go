package components

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	browserBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1)

	browserActiveBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#7C3AED")).
				Padding(0, 1)

	selectedItemStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F9FAFB")).
				Background(lipgloss.Color("#8B5CF6")).
				Bold(true).
				Padding(0, 1)

	normalItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB")).
			Padding(0, 1)

	maskedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))
)

// SecretItem represents a secret in the list
type SecretItem struct {
	KeyName string
	Value   string
	Type    string
}

func (s SecretItem) FilterValue() string { return s.KeyName }

// SecretItemDelegate renders secret items in the list
type SecretItemDelegate struct{}

func (d SecretItemDelegate) Height() int                             { return 1 }
func (d SecretItemDelegate) Spacing() int                            { return 0 }
func (d SecretItemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

func (d SecretItemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	item, ok := listItem.(SecretItem)
	if !ok {
		return
	}

	masked := maskedStyle.Render("••••••••")
	line := fmt.Sprintf("%s  %s", item.KeyName, masked)

	if index == m.Index() {
		line = selectedItemStyle.Render(fmt.Sprintf("▸ %s  %s", item.KeyName, masked))
	} else {
		line = normalItemStyle.Render(fmt.Sprintf("  %s  %s", item.KeyName, masked))
	}

	fmt.Fprint(w, line)
}

// NavigationHintMsg is emitted when the user presses Enter during filtering
// and the filter text matches a navigation intent (e.g., an environment name).
type NavigationHintMsg struct {
	TargetEnv string
}

type SecretBrowserModel struct {
	list         list.Model
	Active       bool
	Width        int
	Height       int
	Selected     int
	Environments []string // available envs, populated by parent for smart hints
	CurrentEnv   string   // current env, populated by parent
}

func NewSecretBrowser() SecretBrowserModel {
	delegate := SecretItemDelegate{}
	l := list.New([]list.Item{}, delegate, 30, 10)
	l.Title = "Secrets"
	l.SetShowTitle(true)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(true)
	l.Styles.Title = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C3AED")).
		Bold(true).
		Padding(0, 0, 1, 0)

	l.KeyMap = list.KeyMap{
		CursorUp:   key.NewBinding(key.WithKeys("up", "k")),
		CursorDown: key.NewBinding(key.WithKeys("down", "j")),
		Filter:     key.NewBinding(key.WithKeys("/")),
		CancelWhileFiltering: key.NewBinding(key.WithKeys("esc")),
		AcceptWhileFiltering: key.NewBinding(key.WithKeys("enter")),
		ClearFilter:          key.NewBinding(key.WithKeys("esc")),
	}

	return SecretBrowserModel{
		list: l,
	}
}

func (m *SecretBrowserModel) SetSecrets(secrets []SecretItem) {
	items := make([]list.Item, len(secrets))
	for i, s := range secrets {
		items[i] = s
	}
	m.list.SetItems(items)
}

func (m *SecretBrowserModel) SetSize(width, height int) {
	m.Width = width
	m.Height = height
	// Account for border (2) and padding (2)
	m.list.SetSize(width-4, height-4)
}

func (m SecretBrowserModel) SelectedItem() (SecretItem, bool) {
	item := m.list.SelectedItem()
	if item == nil {
		return SecretItem{}, false
	}
	si, ok := item.(SecretItem)
	return si, ok
}

func (m SecretBrowserModel) SelectedIndex() int {
	return m.list.Index()
}

// SelectIndex programmatically selects a secret by index (used by command palette).
func (m *SecretBrowserModel) SelectIndex(idx int) {
	m.list.Select(idx)
}

func (m SecretBrowserModel) Update(msg tea.Msg) (SecretBrowserModel, tea.Cmd) {
	if !m.Active {
		return m, nil
	}

	// Intercept Enter during filtering with no visible results —
	// check if the filter text matches an environment name for smart navigation
	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "enter" {
		if m.list.FilterState() == list.Filtering && len(m.list.VisibleItems()) == 0 {
			if targetEnv := m.matchEnvFromFilter(); targetEnv != "" {
				m.list.ResetFilter()
				return m, func() tea.Msg {
					return NavigationHintMsg{TargetEnv: targetEnv}
				}
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// matchEnvFromFilter checks if the current filter text matches an environment name
func (m SecretBrowserModel) matchEnvFromFilter() string {
	query := strings.ToLower(m.list.FilterValue())
	if query == "" {
		return ""
	}

	// Map common aliases to canonical env slugs
	envAliases := map[string]string{
		"prod": "prod", "production": "prod",
		"stg": "staging", "stage": "staging", "staging": "staging",
		"dev": "dev", "development": "dev",
		"test": "test", "testing": "test",
	}

	// Check alias match first
	if slug, ok := envAliases[query]; ok {
		for _, env := range m.Environments {
			if strings.HasPrefix(strings.ToLower(env), slug) && env != m.CurrentEnv {
				return env
			}
		}
	}

	// Direct prefix match on environment names
	for _, env := range m.Environments {
		if strings.HasPrefix(strings.ToLower(env), query) && env != m.CurrentEnv {
			return env
		}
	}

	return ""
}

func (m SecretBrowserModel) View() string {
	style := browserBorder
	if m.Active {
		style = browserActiveBorder
	}

	if m.Width > 0 {
		style = style.Width(m.Width - 2) // account for border
	}
	if m.Height > 0 {
		style = style.Height(m.Height - 2)
	}

	content := m.list.View()

	// Show smart navigation hints when filtering yields no results
	if m.list.FilterState() == list.Filtering && len(m.list.VisibleItems()) == 0 {
		hints := m.buildFilterHints()
		if hints != "" {
			content += "\n" + hints
		}
	}

	if len(m.list.Items()) == 0 && m.list.FilterState() == list.Unfiltered {
		content = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280")).
			Italic(true).
			Render("No secrets found.\nPress 'n' to create one or use the AI prompt.")
	}

	return style.Render(content)
}

// buildFilterHints generates helpful suggestions when the filter has no matches
func (m SecretBrowserModel) buildFilterHints() string {
	query := strings.ToLower(m.list.FilterValue())
	if query == "" {
		return ""
	}

	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280")).Italic(true)
	actionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)

	var hints []string

	// Check if query matches an environment
	if targetEnv := m.matchEnvFromFilter(); targetEnv != "" {
		hints = append(hints, fmt.Sprintf("  %s Switch to %s  %s",
			actionStyle.Render("→"),
			targetEnv,
			hintStyle.Render("[press Enter]")))
	}

	// Check for create/new intent
	if strings.Contains(query, "create") || strings.Contains(query, "new") || strings.Contains(query, "add") {
		hints = append(hints, fmt.Sprintf("  %s Create new secret  %s",
			actionStyle.Render("→"),
			hintStyle.Render("[press n]")))
	}

	if len(hints) == 0 {
		return ""
	}

	header := hintStyle.Render("  Did you mean?")
	return header + "\n" + strings.Join(hints, "\n")
}
