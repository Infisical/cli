package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	ctxBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#7C3AED")).
			Foreground(lipgloss.Color("#F9FAFB")).
			Bold(true).
			Padding(0, 1)

	ctxBarProdStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#EF4444")).
			Foreground(lipgloss.Color("#F9FAFB")).
			Bold(true).
			Padding(0, 1)

	ctxLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#C4B5FD"))

	ctxValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB")).
			Bold(true)
)

type ContextBarModel struct {
	UserEmail   string
	ProjectName string
	Environment string
	Path        string
	Width       int
}

func NewContextBar() ContextBarModel {
	return ContextBarModel{
		UserEmail:   "not logged in",
		ProjectName: "none",
		Environment: "dev",
		Path:        "/",
	}
}

func (m ContextBarModel) View() string {
	isProd := strings.EqualFold(m.Environment, "prod") || strings.EqualFold(m.Environment, "production")

	logo := "  ITUI "
	user := fmt.Sprintf(" %s %s ", ctxLabelStyle.Render("User:"), ctxValueStyle.Render(m.UserEmail))
	project := fmt.Sprintf(" %s %s ", ctxLabelStyle.Render("Project:"), ctxValueStyle.Render(m.ProjectName))
	env := fmt.Sprintf(" %s %s ", ctxLabelStyle.Render("Env:"), ctxValueStyle.Render(m.Environment))
	path := fmt.Sprintf(" %s %s ", ctxLabelStyle.Render("Path:"), ctxValueStyle.Render(m.Path))

	separator := " | "
	content := logo + separator + user + separator + project + separator + env + separator + path

	style := ctxBarStyle
	if isProd {
		style = ctxBarProdStyle
	}

	if m.Width > 0 {
		style = style.Width(m.Width)
	}

	return style.Render(content)
}
