package agent

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	manifestVersion    = "1"
	defaultDuration    = "1h"
	maxInstructionsLen = 4000
	minPort            = 1024
	maxPort            = 65535
)

// Manifest describes the PAM accounts to expose to an agent and how to explain them to it.
type Manifest struct {
	Version  string         `yaml:"version"`
	Defaults Defaults       `yaml:"defaults"`
	Accounts []AccountEntry `yaml:"accounts"`
}

type Defaults struct {
	Duration string `yaml:"duration"`
	Reason   string `yaml:"reason"`
}

type AccountEntry struct {
	Account string `yaml:"account"`
	Port    int    `yaml:"port"`
	// TargetHost picks the host to connect to for accounts that front more than one, such as a
	// Windows AD account covering a whole domain. It matches `pam access --target`.
	TargetHost        string `yaml:"target_host"`
	Duration          string `yaml:"duration"`
	Reason            string `yaml:"reason"`
	AgentInstructions string `yaml:"agent_instructions"`
}

// EffectiveDuration returns the account's duration, falling back to the manifest default.
func (e AccountEntry) EffectiveDuration(defaults Defaults) time.Duration {
	value := e.Duration
	if value == "" {
		value = defaults.Duration
	}
	if value == "" {
		value = defaultDuration
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return time.Hour
	}
	return duration
}

// EffectiveReason returns the account's reason, falling back to the manifest default.
func (e AccountEntry) EffectiveReason(defaults Defaults) string {
	if e.Reason != "" {
		return e.Reason
	}
	return defaults.Reason
}

// Folder and Name split the account path, which is always "folder/account".
func (e AccountEntry) Folder() string {
	folder, _ := splitPath(e.Account)
	return folder
}

func (e AccountEntry) Name() string {
	_, name := splitPath(e.Account)
	return name
}

func splitPath(path string) (folder, name string) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) != 2 {
		return "", parts[0]
	}
	return parts[0], parts[1]
}

// LoadManifest reads and validates a manifest file. All problems are reported together so a
// user fixing a manifest sees the whole list rather than one error per run.
func LoadManifest(path string) (*Manifest, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest %s: %w", path, err)
	}

	var manifest Manifest
	decoder := yaml.NewDecoder(strings.NewReader(string(contents)))
	// Reject unknown keys so a typo like `agent_instruction` fails loudly instead of being
	// silently dropped, which would leave the agent with no guidance and no explanation.
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest %s: %w", path, err)
	}

	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (m *Manifest) Validate() error {
	var problems []string

	// Optional, so a short manifest doesn't need boilerplate. If it is set we still hold it to a
	// known value, otherwise the field would silently mean nothing.
	if m.Version != "" && m.Version != manifestVersion {
		problems = append(problems, fmt.Sprintf("unsupported version %q, expected %q", m.Version, manifestVersion))
	}

	if m.Defaults.Duration != "" {
		if err := validateDuration(m.Defaults.Duration); err != nil {
			problems = append(problems, fmt.Sprintf("defaults.duration: %v", err))
		}
	}

	if len(m.Accounts) == 0 {
		problems = append(problems, "manifest defines no accounts")
	}

	seenPorts := map[int]string{}
	seenAccounts := map[string]bool{}

	for i, entry := range m.Accounts {
		label := entry.Account
		if label == "" {
			label = fmt.Sprintf("accounts[%d]", i)
		}

		folder, name := splitPath(entry.Account)
		if folder == "" || name == "" {
			problems = append(problems, fmt.Sprintf("%s: account must be in folder/account form", label))
		}

		if seenAccounts[entry.Account] {
			problems = append(problems, fmt.Sprintf("%s: listed more than once", label))
		}
		seenAccounts[entry.Account] = true

		if entry.Port < minPort || entry.Port > maxPort {
			problems = append(problems, fmt.Sprintf("%s: port %d must be between %d and %d", label, entry.Port, minPort, maxPort))
		} else if other, taken := seenPorts[entry.Port]; taken {
			problems = append(problems, fmt.Sprintf("%s: port %d is already used by %s", label, entry.Port, other))
		} else {
			seenPorts[entry.Port] = label
		}

		if entry.Duration != "" {
			if err := validateDuration(entry.Duration); err != nil {
				problems = append(problems, fmt.Sprintf("%s: duration: %v", label, err))
			}
		}

		if len(entry.AgentInstructions) > maxInstructionsLen {
			problems = append(problems, fmt.Sprintf("%s: agent_instructions exceeds %d characters", label, maxInstructionsLen))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid manifest:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func validateDuration(value string) error {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q, use formats like '1h', '30m', '2h30m'", value)
	}
	if duration <= 0 {
		return fmt.Errorf("duration %q must be positive", value)
	}
	return nil
}
