package itui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Quit          key.Binding
	Tab           key.Binding
	ShiftTab      key.Binding
	Up            key.Binding
	Down          key.Binding
	Enter         key.Binding
	Escape        key.Binding
	Search        key.Binding
	EnvSwitch     key.Binding
	NewSecret     key.Binding
	DeleteSecret  key.Binding
	RevealValue   key.Binding
	FocusPrompt   key.Binding
	Help          key.Binding
	Refresh       key.Binding
	Confirm       key.Binding
	Deny          key.Binding
}

var keys = keyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q/ctrl+c", "quit"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next pane"),
	),
	ShiftTab: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "prev pane"),
	),
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("up/k", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("down/j", "move down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select/execute"),
	),
	Escape: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "cancel/back"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search secrets"),
	),
	EnvSwitch: key.NewBinding(
		key.WithKeys("e"),
		key.WithHelp("e", "switch environment"),
	),
	NewSecret: key.NewBinding(
		key.WithKeys("n"),
		key.WithHelp("n", "new secret"),
	),
	DeleteSecret: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "delete secret"),
	),
	RevealValue: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "reveal/mask value"),
	),
	FocusPrompt: key.NewBinding(
		key.WithKeys("ctrl+p"),
		key.WithHelp("ctrl+p", "focus AI prompt"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("R"),
		key.WithHelp("R", "refresh secrets"),
	),
	Confirm: key.NewBinding(
		key.WithKeys("y", "Y"),
		key.WithHelp("y", "confirm"),
	),
	Deny: key.NewBinding(
		key.WithKeys("n", "N"),
		key.WithHelp("n", "deny"),
	),
}
