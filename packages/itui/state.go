package itui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const maxRecents = 20

// PersistentState stores user preferences across sessions in ~/.itui/state.json
type PersistentState struct {
	Recents []RecentEntry `json:"recents"`
	Pins    []string      `json:"pins"`
}

// RecentEntry records a recently viewed secret
type RecentEntry struct {
	SecretKey   string `json:"secret_key"`
	Environment string `json:"environment"`
	ViewedAt    string `json:"viewed_at"`
}

// LoadState reads persistent state from ~/.itui/state.json.
// Returns empty state if file doesn't exist or can't be read.
func LoadState() PersistentState {
	path := statePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return PersistentState{}
	}

	var state PersistentState
	if err := json.Unmarshal(data, &state); err != nil {
		return PersistentState{}
	}
	return state
}

// SaveState writes persistent state to ~/.itui/state.json.
// Silently ignores errors to avoid disrupting the TUI.
func SaveState(s PersistentState) {
	path := statePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

// AddRecent adds a secret to the recents list, deduplicating by key+env.
// Newest entries appear first. Capped at maxRecents.
func (s *PersistentState) AddRecent(key, env string) {
	// Remove existing entry for same key+env
	filtered := make([]RecentEntry, 0, len(s.Recents))
	for _, r := range s.Recents {
		if !(r.SecretKey == key && r.Environment == env) {
			filtered = append(filtered, r)
		}
	}

	// Prepend new entry
	entry := RecentEntry{
		SecretKey:   key,
		Environment: env,
		ViewedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	s.Recents = append([]RecentEntry{entry}, filtered...)

	// Cap at maxRecents
	if len(s.Recents) > maxRecents {
		s.Recents = s.Recents[:maxRecents]
	}
}

// TogglePin adds or removes a secret key from the pinned list.
func (s *PersistentState) TogglePin(key string) {
	for i, p := range s.Pins {
		if p == key {
			s.Pins = append(s.Pins[:i], s.Pins[i+1:]...)
			return
		}
	}
	s.Pins = append(s.Pins, key)
}

// IsPinned returns true if the given key is in the pinned list.
func (s *PersistentState) IsPinned(key string) bool {
	for _, p := range s.Pins {
		if p == key {
			return true
		}
	}
	return false
}

func statePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".itui", "state.json")
}
