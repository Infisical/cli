package itui

import (
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/itui/components"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Messages
type secretsLoadedMsg struct {
	secrets []Secret
	err     error
}

type contextLoadedMsg struct {
	ctx SessionContext
	err error
}

type commandExecutedMsg struct {
	result CommandResult
}

type aiResponseMsg struct {
	response AIResponse
	err      error
}

// Model is the top-level Bubble Tea model
type Model struct {
	// Components
	contextBar    components.ContextBarModel
	secretBrowser components.SecretBrowserModel
	detailPane    components.DetailPaneModel
	promptBar     components.PromptBarModel
	envPicker     components.EnvPickerModel
	confirmDialog components.ConfirmModel
	secretForm    components.SecretFormModel
	helpModal     components.HelpModel

	// State
	ctx         SessionContext
	secrets     []Secret
	focusedPane FocusedPane
	mode        AppMode
	aiClient    *AIClient
	executor    *Executor
	auditLog    *AuditLogger
	valueCache  map[string]string // placeholder → real value, for sanitize/hydrate

	// Window
	windowWidth  int
	windowHeight int
	ready        bool
	err          error
}

// NewModel creates a new ITUI model
func NewModel() Model {
	executor := NewExecutor()

	var aiClient *AIClient
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey != "" {
		aiClient = NewAIClient(apiKey)
	}

	return Model{
		contextBar:    components.NewContextBar(),
		secretBrowser: components.NewSecretBrowser(),
		detailPane:    components.NewDetailPane(),
		promptBar:     components.NewPromptBar(),
		envPicker:     components.NewEnvPicker(),
		confirmDialog: components.NewConfirm(),
		secretForm:    components.NewSecretForm(),
		helpModal:     components.NewHelp(),
		focusedPane:   PaneSecretBrowser,
		mode:          ModeNormal,
		executor:      executor,
		aiClient:      aiClient,
		auditLog:      NewAuditLogger(),
		valueCache:    make(map[string]string),
		ctx: SessionContext{
			Environment: "dev",
			Path:        "/",
		},
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.loadContext,
	)
}

func (m Model) loadContext() tea.Msg {
	ctx := LoadSessionContext()
	return contextLoadedMsg{ctx: ctx}
}

func (m Model) loadSecrets() tea.Msg {
	secrets, err := m.executor.FetchSecrets(m.ctx.Environment, m.ctx.Path)
	return secretsLoadedMsg{secrets: secrets, err: err}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height
		m.ready = true
		m.updateLayout()
		return m, nil

	case tea.KeyMsg:
		// Global quit
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		// Handle overlays first
		if m.helpModal.Visible {
			var cmd tea.Cmd
			m.helpModal, cmd = m.helpModal.Update(msg)
			return m, cmd
		}
		if m.envPicker.Visible {
			var cmd tea.Cmd
			m.envPicker, cmd = m.envPicker.Update(msg)
			return m, cmd
		}
		if m.confirmDialog.Visible {
			var cmd tea.Cmd
			m.confirmDialog, cmd = m.confirmDialog.Update(msg)
			return m, cmd
		}
		if m.secretForm.Visible {
			var cmd tea.Cmd
			m.secretForm, cmd = m.secretForm.Update(msg)
			return m, cmd
		}

		// Handle prompt bar in preview mode
		if m.promptBar.State == components.PromptStatePreview {
			return m.handlePreviewKeys(msg)
		}

		// Handle prompt bar input mode
		if m.focusedPane == PanePrompt && m.promptBar.Active {
			return m.handlePromptKeys(msg)
		}

		// Global shortcuts (when not in prompt)
		return m.handleGlobalKeys(msg)

	case contextLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.detailPane.SetOutput("Error", msg.err.Error(), true)
		} else {
			m.ctx = msg.ctx
			m.updateContextBar()

			if !m.ctx.IsLoggedIn {
				m.detailPane.SetOutput("Not Logged In",
					"You are not logged in to Infisical.\n\n"+
						"Run 'infisical login' in another terminal,\n"+
						"then press R to refresh.", true)
				return m, nil
			}
			if m.ctx.ProjectID == "" {
				m.detailPane.SetOutput("No Project Linked",
					"No .infisical.json found in the current directory.\n\n"+
						"Run 'infisical init' in another terminal to link a project,\n"+
						"then press R to refresh.\n\n"+
						"You can still use the AI prompt (Ctrl+P) for general questions.", true)
				return m, nil
			}
		}
		return m, m.loadSecrets

	case secretsLoadedMsg:
		if msg.err != nil {
			m.detailPane.SetOutput("Error Loading Secrets", msg.err.Error(), true)
		} else {
			m.secrets = msg.secrets
			m.updateSecretBrowser()
		}
		return m, nil

	case aiResponseMsg:
		if msg.err != nil {
			m.promptBar.Reset()
			m.detailPane.SetOutput("AI Error", msg.err.Error(), true)
		} else {
			resp := msg.response
			if resp.Command == "" {
				// AI is asking a clarifying question
				m.promptBar.Reset()
				m.detailPane.SetOutput("AI Response", resp.Explanation, false)
			} else {
				m.promptBar.SetPreview(resp.Command, resp.Explanation, resp.ActionType, resp.RequiresConfirmation)
			}
		}
		return m, nil

	case commandExecutedMsg:
		result := msg.result
		if result.Error != nil {
			output := result.Stderr
			if output == "" {
				output = result.Error.Error()
			}
			m.detailPane.SetOutput("Command Failed", output, true)
		} else {
			m.detailPane.SetOutput("Command Output", result.Stdout, false)
		}
		m.promptBar.Reset()
		// Refresh secrets after any command
		return m, m.loadSecrets

	case components.EnvSelectedMsg:
		m.ctx.Environment = msg.Environment
		m.updateContextBar()
		return m, m.loadSecrets

	case components.ConfirmYesMsg:
		return m, m.executeCommand(msg.Command)

	case components.ConfirmNoMsg:
		m.promptBar.Reset()
		return m, nil

	case components.SecretCreatedMsg:
		// Use RunSecretSet directly — keeps KEY=VALUE as a single arg
		// so values with spaces/special chars aren't broken
		executor := m.executor
		auditLog := m.auditLog
		env := m.ctx.Environment
		path := m.ctx.Path
		key := msg.Key
		value := msg.Value
		return m, func() tea.Msg {
			kvPairs := []string{key + "=" + value}
			flags := []string{"--env=" + env}
			if path != "" && path != "/" {
				flags = append(flags, "--path="+path)
			}
			result := executor.RunSecretSet(kvPairs, flags)
			auditLog.Log(AuditEntry{
				Environment:      env,
				AICommand:        fmt.Sprintf("secrets set %s=[redacted] --env=%s", key, env),
				ValidationResult: "allowed",
				ExecutionResult:  "success",
			})
			return commandExecutedMsg{result: result}
		}
	}

	// Update active components
	switch m.focusedPane {
	case PaneSecretBrowser:
		var cmd tea.Cmd
		m.secretBrowser, cmd = m.secretBrowser.Update(msg)
		cmds = append(cmds, cmd)
	case PaneDetailOutput:
		var cmd tea.Cmd
		m.detailPane, cmd = m.detailPane.Update(msg)
		cmds = append(cmds, cmd)
	case PanePrompt:
		var cmd tea.Cmd
		m.promptBar, cmd = m.promptBar.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) handleGlobalKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		if m.focusedPane != PanePrompt {
			return m, tea.Quit
		}
	case "tab":
		m.cycleFocus(1)
	case "shift+tab":
		m.cycleFocus(-1)
	case "ctrl+p":
		m.setFocus(PanePrompt)
		m.promptBar.Focus()
	case "?":
		m.helpModal.Show()
	case "e":
		m.envPicker.Show(m.ctx.Environment, m.ctx.Environments)
	case "n":
		m.secretForm.Show()
	case "d":
		if item, ok := m.secretBrowser.SelectedItem(); ok {
			isProd := strings.EqualFold(m.ctx.Environment, "prod") || strings.EqualFold(m.ctx.Environment, "production")
			cmd := fmt.Sprintf("infisical secrets delete %s --env=%s --path=%s --type=shared", item.KeyName, m.ctx.Environment, m.ctx.Path)
			m.confirmDialog.Show(cmd, fmt.Sprintf("Delete secret '%s' from %s?", item.KeyName, m.ctx.Environment), true, isProd)
		}
	case "r":
		m.detailPane.ToggleReveal()
	case "R":
		return m, m.loadContext
	case "enter":
		if m.focusedPane == PaneSecretBrowser {
			if item, ok := m.secretBrowser.SelectedItem(); ok {
				// Find the full secret
				for _, s := range m.secrets {
					if s.Key == item.KeyName {
						m.detailPane.SetSecret(s.Key, s.Value, s.Type, s.SecretPath, s.Comment)
						break
					}
				}
			}
		}
	default:
		// Pass unhandled keys to the active component
		if m.focusedPane == PaneSecretBrowser {
			var cmd tea.Cmd
			m.secretBrowser, cmd = m.secretBrowser.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func (m *Model) handlePromptKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.promptBar.Blur()
		m.setFocus(PaneSecretBrowser)
		return m, nil
	case "enter":
		input := m.promptBar.Value()
		if input == "" {
			return m, nil
		}
		if m.aiClient == nil {
			m.detailPane.SetOutput("AI Unavailable", "Set GEMINI_API_KEY environment variable to enable AI features.", true)
			return m, nil
		}
		m.promptBar.SetLoading()
		cmd := m.translatePrompt(input)
		return m, cmd
	}

	// Let the text input handle the key
	var cmd tea.Cmd
	m.promptBar, cmd = m.promptBar.Update(msg)
	return m, cmd
}

func (m *Model) handlePreviewKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.promptBar.Reset()
		return m, nil
	case "enter":
		if !m.promptBar.PreviewConfirm {
			return m, m.executeCommand(m.promptBar.PreviewCommand)
		}
		// Needs confirmation
		isProd := strings.EqualFold(m.ctx.Environment, "prod") || strings.EqualFold(m.ctx.Environment, "production")
		m.confirmDialog.Show(
			m.promptBar.PreviewCommand,
			m.promptBar.PreviewExplanation,
			m.promptBar.PreviewActionType == "destructive",
			isProd,
		)
		return m, nil
	case "y", "Y":
		if m.promptBar.PreviewConfirm {
			return m, m.executeCommand(m.promptBar.PreviewCommand)
		}
	}
	return m, nil
}

func (m *Model) translatePrompt(input string) tea.Cmd {
	// Collect known secret values for redaction
	knownValues := make([]string, 0, len(m.secrets))
	for _, s := range m.secrets {
		if s.Value != "" {
			knownValues = append(knownValues, s.Value)
		}
	}

	// Sanitize: extract values, replace with placeholders
	sanitized, cache := SanitizePrompt(input, knownValues)
	m.valueCache = cache

	// Collect secret key names (safe to send to AI)
	secretKeys := make([]string, 0, len(m.secrets))
	for _, s := range m.secrets {
		secretKeys = append(secretKeys, s.Key)
	}

	return func() tea.Msg {
		resp, err := m.aiClient.Translate(sanitized, m.ctx, secretKeys)
		return aiResponseMsg{response: resp, err: err}
	}
}

func (m *Model) executeCommand(command string) tea.Cmd {
	// Step 1: Validate the AI command (with placeholders still in place).
	// Placeholders like [VALUE_1] are safe — no special chars to false-positive on.
	if err := ValidateCommand(command); err != nil {
		auditEntry := AuditEntry{
			UserEmail:        m.ctx.UserEmail,
			Environment:      m.ctx.Environment,
			AICommand:        command,
			ValidationResult: "rejected: " + err.Error(),
		}
		m.auditLog.Log(auditEntry)
		return func() tea.Msg {
			return commandExecutedMsg{result: CommandResult{
				Command: command,
				Error:   fmt.Errorf("security: %s", err.Error()),
				Stderr:  "Command rejected: " + err.Error(),
			}}
		}
	}

	// Step 2: Hydrate placeholders with cached real values
	hydrated := HydrateCommand(command, m.valueCache)

	auditEntry := AuditEntry{
		UserEmail:        m.ctx.UserEmail,
		Environment:      m.ctx.Environment,
		AICommand:        command,
		ValidationResult: "allowed",
	}
	if hydrated != command {
		auditEntry.HydratedCommand = "[hydrated — values redacted from log]"
	}

	executor := m.executor
	auditLog := m.auditLog

	// Step 3: Execute — use safe arg handling for `secrets set` to preserve
	// values with spaces/special chars as single arguments
	return func() tea.Msg {
		var result CommandResult

		if IsSecretsSetCommand(hydrated) {
			kvPairs, flags := ParseSetCommand(hydrated)
			result = executor.RunSecretSet(kvPairs, flags)
		} else {
			result = executor.RunRaw(hydrated)
		}

		// Log after execution
		if result.Error != nil {
			auditEntry.ExecutionError = result.Error.Error()
		} else {
			auditEntry.ExecutionResult = "success"
		}
		auditLog.Log(auditEntry)

		return commandExecutedMsg{result: result}
	}
}

func (m *Model) cycleFocus(dir int) {
	panes := []FocusedPane{PaneSecretBrowser, PaneDetailOutput, PanePrompt}
	current := 0
	for i, p := range panes {
		if p == m.focusedPane {
			current = i
			break
		}
	}
	next := (current + dir + len(panes)) % len(panes)
	m.setFocus(panes[next])
}

func (m *Model) setFocus(pane FocusedPane) {
	m.focusedPane = pane
	m.secretBrowser.Active = pane == PaneSecretBrowser
	m.detailPane.Active = pane == PaneDetailOutput
	m.promptBar.Active = pane == PanePrompt

	if pane == PanePrompt {
		m.promptBar.Focus()
	} else {
		m.promptBar.Blur()
	}
}

func (m *Model) updateContextBar() {
	m.contextBar.UserEmail = m.ctx.UserEmail
	m.contextBar.ProjectName = m.ctx.ProjectName
	m.contextBar.Environment = m.ctx.Environment
	m.contextBar.Path = m.ctx.Path

	if m.ctx.UserEmail == "" {
		m.contextBar.UserEmail = "not logged in"
	}
	if m.ctx.ProjectName == "" {
		m.contextBar.ProjectName = "none (run infisical init)"
	}
}

func (m *Model) updateSecretBrowser() {
	items := make([]components.SecretItem, len(m.secrets))
	for i, s := range m.secrets {
		items[i] = components.SecretItem{
			KeyName: s.Key,
			Value:   s.Value,
			Type:    s.Type,
		}
	}
	m.secretBrowser.SetSecrets(items)
}

func (m *Model) updateLayout() {
	if !m.ready {
		return
	}

	w := m.windowWidth
	h := m.windowHeight

	// Context bar: full width, 1 line + padding
	contextBarHeight := 1
	// Prompt bar: full width, 5 lines (input + preview + hint + borders)
	promptBarHeight := 5
	// Main content area: remaining height split between browser and detail
	mainHeight := h - contextBarHeight - promptBarHeight - 2 // 2 for spacing

	if mainHeight < 5 {
		mainHeight = 5
	}

	// Browser takes 40% width, detail takes 60%
	browserWidth := w * 2 / 5
	detailWidth := w - browserWidth

	m.contextBar.Width = w
	m.secretBrowser.SetSize(browserWidth, mainHeight)
	m.detailPane.SetSize(detailWidth, mainHeight)
	m.promptBar.SetWidth(w)
}

func (m Model) View() string {
	if !m.ready {
		return "Loading ITUI..."
	}

	// Check for overlays
	var overlay string
	if m.helpModal.Visible {
		overlay = m.helpModal.View()
	} else if m.envPicker.Visible {
		overlay = m.envPicker.View()
	} else if m.confirmDialog.Visible {
		overlay = m.confirmDialog.View()
	} else if m.secretForm.Visible {
		overlay = m.secretForm.View()
	}

	if overlay != "" {
		return m.renderWithOverlay(overlay)
	}

	return m.renderNormal()
}

func (m Model) renderNormal() string {
	contextBar := m.contextBar.View()

	mainContent := lipgloss.JoinHorizontal(
		lipgloss.Top,
		m.secretBrowser.View(),
		m.detailPane.View(),
	)

	promptBar := m.promptBar.View()

	return lipgloss.JoinVertical(
		lipgloss.Left,
		contextBar,
		mainContent,
		promptBar,
	)
}

func (m Model) renderWithOverlay(overlay string) string {
	base := m.renderNormal()

	// Center the overlay
	overlayWidth := lipgloss.Width(overlay)
	overlayHeight := lipgloss.Height(overlay)

	x := (m.windowWidth - overlayWidth) / 2
	y := (m.windowHeight - overlayHeight) / 2

	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	// Place overlay on top of base
	return placeOverlay(x, y, overlay, base)
}

// placeOverlay places an overlay string on top of a background string
func placeOverlay(x, y int, overlay, background string) string {
	bgLines := strings.Split(background, "\n")
	olLines := strings.Split(overlay, "\n")

	for i, olLine := range olLines {
		bgIdx := y + i
		if bgIdx >= len(bgLines) {
			break
		}

		bgLine := bgLines[bgIdx]
		bgRunes := []rune(bgLine)

		// Pad bg line if needed
		for len(bgRunes) < x+lipgloss.Width(olLine) {
			bgRunes = append(bgRunes, ' ')
		}

		// Replace section
		before := string(bgRunes[:x])
		after := ""
		afterStart := x + lipgloss.Width(olLine)
		if afterStart < len(bgRunes) {
			after = string(bgRunes[afterStart:])
		}

		bgLines[bgIdx] = before + olLine + after
	}

	return strings.Join(bgLines, "\n")
}

// Run starts the ITUI application
func Run() error {
	p := tea.NewProgram(
		NewModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	_, err := p.Run()
	return err
}
