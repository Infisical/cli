package components

import (
	"fmt"
	"io"

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

type SecretBrowserModel struct {
	list     list.Model
	Active   bool
	Width    int
	Height   int
	Selected int
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
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
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
	if len(m.list.Items()) == 0 {
		content = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280")).
			Italic(true).
			Render("No secrets found.\nPress 'n' to create one or use the AI prompt.")
	}

	return style.Render(content)
}
