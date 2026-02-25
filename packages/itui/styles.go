package itui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	primaryColor   = lipgloss.Color("#7C3AED") // purple
	accentColor    = lipgloss.Color("#10B981") // green
	warningColor   = lipgloss.Color("#F59E0B") // yellow
	dangerColor    = lipgloss.Color("#EF4444") // red
	mutedColor     = lipgloss.Color("#6B7280") // gray
	textColor      = lipgloss.Color("#F9FAFB") // white
	bgColor        = lipgloss.Color("#111827") // dark bg
	surfaceColor   = lipgloss.Color("#1F2937") // slightly lighter bg
	borderColor    = lipgloss.Color("#374151") // border gray
	highlightColor = lipgloss.Color("#8B5CF6") // lighter purple

	// Context bar
	contextBarStyle = lipgloss.NewStyle().
			Background(primaryColor).
			Foreground(textColor).
			Bold(true).
			Padding(0, 1)

	contextBarProdStyle = lipgloss.NewStyle().
				Background(dangerColor).
				Foreground(textColor).
				Bold(true).
				Padding(0, 1)

	contextLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#C4B5FD")).
				Bold(false)

	// Secret browser pane
	secretBrowserStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(borderColor).
				Padding(0, 1)

	secretBrowserActiveStyle = lipgloss.NewStyle().
					Border(lipgloss.RoundedBorder()).
					BorderForeground(primaryColor).
					Padding(0, 1)

	secretItemStyle = lipgloss.NewStyle().
			Foreground(textColor)

	secretItemSelectedStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Background(highlightColor).
				Bold(true)

	secretValueMasked = lipgloss.NewStyle().
				Foreground(mutedColor)

	// Detail / output pane
	detailPaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(0, 1)

	detailPaneActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(primaryColor).
				Padding(0, 1)

	detailKeyStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	detailLabelStyle = lipgloss.NewStyle().
				Foreground(mutedColor)

	detailValueStyle = lipgloss.NewStyle().
				Foreground(textColor)

	// Prompt bar
	promptBarStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(0, 1)

	promptBarActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(accentColor).
				Padding(0, 1)

	promptPrefixStyle = lipgloss.NewStyle().
				Foreground(accentColor).
				Bold(true)

	commandPreviewStyle = lipgloss.NewStyle().
				Foreground(warningColor).
				Italic(true)

	// Overlays / modals
	overlayStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			Background(surfaceColor)

	confirmDangerStyle = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(dangerColor).
				Padding(1, 2).
				Background(surfaceColor)

	// General
	titleStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(accentColor)

	spinnerStyle = lipgloss.NewStyle().
			Foreground(primaryColor)

	helpKeyStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	helpDescStyle = lipgloss.NewStyle().
			Foreground(mutedColor)
)
