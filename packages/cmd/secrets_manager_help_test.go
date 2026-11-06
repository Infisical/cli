package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// The legacy top-level copies keep working for existing scripts but leave `infisical --help`, so
// people find the `secrets-manager` paths. Both copies come from one builder and share their help.
func TestLegacyTopLevelCommandsAreHiddenButWork(t *testing.T) {
	pairs := map[string][]string{"export": {secretsManagerCommandName, "secrets", "export"}}
	for _, build := range secretsManagementCommands {
		pairs[build().Name()] = []string{secretsManagerCommandName, build().Name()}
	}
	for name, underPath := range pairs {
		top := findCommand(t, []string{name})
		under := findCommand(t, underPath)
		if !top.Hidden {
			t.Errorf("infisical %s is listed in infisical --help", name)
		}
		if under.Hidden {
			t.Errorf("infisical %s is hidden", strings.Join(underPath, " "))
		}
		if found, _, err := RootCmd.Find([]string{name}); err != nil || found != top {
			t.Errorf("infisical %s no longer resolves: %v", name, err)
		}
		if top.Short != under.Short || top.Example != under.Example {
			t.Errorf("infisical %s and infisical %s have different help", name, strings.Join(underPath, " "))
		}
	}
}

// Every example under secrets-manager must name a real command, pass its Args check and use only
// flags it has, so it runs as printed once its placeholders are filled in.
func TestSecretsManagerExamplesUseRealCommandsAndFlags(t *testing.T) {
	root := findCommand(t, []string{secretsManagerCommandName})
	for _, owner := range visibleCommands(root) {
		for _, line := range strings.Split(owner.Example, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			words := splitExample(line)
			if len(words) < 2 || words[0] != "infisical" {
				t.Errorf("%s: example %q doesn't start with `infisical`", owner.CommandPath(), line)
				continue
			}
			if problem := checkExample(words[1:]); problem != "" {
				t.Errorf("%s: example %q: %s", owner.CommandPath(), line, problem)
			}
		}
	}
}

func checkExample(words []string) string {
	cmd, rest, err := RootCmd.Find(words)
	if err != nil {
		return err.Error()
	}
	if cmd.Hidden {
		return "names a hidden command"
	}
	for i, word := range rest {
		if word == ">" || word == "|" {
			rest = rest[:i]
			break
		}
	}
	// Some Args checks read flags (run's `--`, create's --file), so the example is parsed into the
	// real command, whose flags are shared with every other test and are put back afterwards.
	defer restoreFlags(cmd.Flags())()
	if err := cmd.ParseFlags(rest); err != nil {
		return err.Error()
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		return err.Error()
	}
	return ""
}

func restoreFlags(flags *pflag.FlagSet) func() {
	type saved struct {
		value   string
		slice   []string
		changed bool
	}
	before := map[*pflag.Flag]saved{}
	flags.VisitAll(func(f *pflag.Flag) {
		s := saved{value: f.Value.String(), changed: f.Changed}
		if slice, ok := f.Value.(pflag.SliceValue); ok {
			s.slice = append([]string(nil), slice.GetSlice()...)
		}
		before[f] = s
	})
	return func() {
		for f, s := range before {
			if slice, ok := f.Value.(pflag.SliceValue); ok {
				slice.Replace(s.slice)
			} else {
				f.Value.Set(s.value)
			}
			f.Changed = s.changed
		}
	}
}

func splitExample(line string) []string {
	var words []string
	var current strings.Builder
	quote := rune(0)
	inWord := false
	for _, r := range line {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			current.WriteRune(r)
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, current.String())
				current.Reset()
				inWord = false
			}
		default:
			current.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, current.String())
	}
	return words
}
