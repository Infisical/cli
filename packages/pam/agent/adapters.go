package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
)

// Delivery describes how the instruction document reaches a particular agent.
type Delivery struct {
	// Args replaces the child argv, if the agent takes instructions on the command line.
	Args []string
	// Cleanup undoes anything written to disk. Always safe to call.
	Cleanup func()
	// Summary is a short human-readable description of what was done.
	Summary string
}

// Adapter wires the instruction document into one agent's own convention.
type Adapter struct {
	Name string
	// contextFile is the file this agent reads for project instructions, if any.
	contextFile string
	// useSystemPromptFlag appends the document as a CLI flag instead of writing a file.
	useSystemPromptFlag bool
}

var adapters = []Adapter{
	// Claude Code takes instructions on the command line, so nothing needs to touch the repo.
	{Name: "claude", useSystemPromptFlag: true},
	{Name: "codex", contextFile: "AGENTS.md"},
	{Name: "gemini", contextFile: "GEMINI.md"},
}

// fallbackAdapter handles any agent we don't know about. AGENTS.md is the closest thing to a
// cross-agent convention, and an agent that ignores it still gets the environment variables.
var fallbackAdapter = Adapter{Name: "generic", contextFile: "AGENTS.md"}

// knownAgentNames lists every value --agent accepts. Built from the adapters themselves so it cannot
// drift from what is actually supported.
func knownAgentNames() []string {
	names := make([]string, 0, len(adapters)+1)
	for _, adapter := range adapters {
		names = append(names, adapter.Name)
	}
	return append(names, fallbackAdapter.Name)
}

// SelectAdapter picks an adapter from the child command name, or by explicit override.
//
// The two routes to the fallback are not the same thing, so only one of them is allowed to be quiet.
// Reaching it by detection is the ordinary case: an unrecognised command is what running a custom
// agent looks like, and the fallback is how that is supported. Reaching it through --agent is a
// mistake, because naming an agent asserts that we handle it specially; someone passing
// '--agent opencode' would otherwise be handed the generic adapter and never learn that the agent
// they named is not one we know.
func SelectAdapter(argv []string, override string) (Adapter, error) {
	name := override
	if name == "" && len(argv) > 0 {
		name = filepath.Base(argv[0])
		// Strip a Windows extension so "claude.exe" still matches.
		name = strings.TrimSuffix(name, filepath.Ext(name))
	}

	for _, adapter := range adapters {
		if strings.EqualFold(adapter.Name, name) {
			return adapter, nil
		}
	}
	// Named explicitly, "generic" is a real choice rather than a fallback: it is what to ask for when
	// the agent is not one of the above and the AGENTS.md convention is the right delivery for it.
	if strings.EqualFold(fallbackAdapter.Name, name) {
		return fallbackAdapter, nil
	}

	if override != "" {
		return Adapter{}, fmt.Errorf(
			"unknown agent %q. Supported: %s. Without --agent the agent is detected from the command name, so '-- claude' selects claude",
			override, strings.Join(knownAgentNames(), ", "))
	}
	return fallbackAdapter, nil
}

// Apply delivers the document to the agent, returning the argv to run and a cleanup function.
func (a Adapter) Apply(document string, argv []string) (Delivery, error) {
	if a.useSystemPromptFlag {
		return Delivery{
			Args:    append(append([]string{}, argv...), "--append-system-prompt", document),
			Cleanup: func() {},
			Summary: "passed to claude via --append-system-prompt",
		}, nil
	}

	if a.contextFile == "" {
		return Delivery{Args: argv, Cleanup: func() {}}, nil
	}

	cleanup, err := writeManagedBlock(a.contextFile, document, RunID())
	if err != nil {
		return Delivery{}, err
	}

	return Delivery{
		Args:    argv,
		Cleanup: cleanup,
		Summary: fmt.Sprintf("written to ./%s", a.contextFile),
	}, nil
}

// Blocks are tagged with the run's PID so two agents running in the same directory can tell their
// blocks apart. Without that, whichever exits first would delete the other's instructions.
func blockMarkers(runID string) (begin, end string) {
	return fmt.Sprintf("<!-- BEGIN INFISICAL PAM %s -->", runID),
		fmt.Sprintf("<!-- END INFISICAL PAM %s -->", runID)
}

// managedBlockPattern matches a block from any run, capturing its run ID so blocks belonging to a
// run that is still alive can be told apart from ones left behind by a run that was killed.
var managedBlockPattern = regexp.MustCompile(`(?s)<!-- BEGIN INFISICAL PAM ([^\n>]*?)\s*-->.*?<!-- END INFISICAL PAM [^\n>]*-->\n?`)

// blankRunPattern collapses the gap left where a block was removed from the middle of a file.
var blankRunPattern = regexp.MustCompile(`\n{3,}`)

// RunID identifies this process's block. The PID is unique among concurrent runs and makes a
// leftover block traceable to the run that wrote it.
func RunID() string {
	return strconv.Itoa(os.Getpid())
}

// writeManagedBlock appends a delimited block to a context file, creating the file if needed.
//
// Blocks left behind by a run that was killed before it could clean up are cleared on write, so the
// agent can't read stale ports out of them. Blocks belonging to a run that is still going are kept,
// since that agent is still using them. Cleanup then removes only this run's block.
func writeManagedBlock(path, document, runID string) (func(), error) {
	existing, err := os.ReadFile(path)
	fileExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	begin, end := blockMarkers(runID)
	block := fmt.Sprintf("%s\n%s\n%s\n", begin, strings.TrimRight(document, "\n"), end)

	updated := block
	if fileExisted {
		body := stripStaleManagedBlocks(string(existing), runID)
		if strings.TrimSpace(body) != "" {
			updated = strings.TrimRight(body, "\n") + "\n\n" + block
		}
	}

	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", path, err)
	}

	cleanup := func() {
		current, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Warn().Err(err).Str("file", path).Msg("Could not read context file to clean up")
			}
			return
		}

		remaining := stripManagedBlock(string(current), runID)

		if !fileExisted && strings.TrimSpace(remaining) == "" {
			// We created the file and nothing else was added to it, so take it with us.
			if err := os.Remove(path); err != nil {
				log.Warn().Err(err).Str("file", path).Msg("Could not remove context file")
			}
			return
		}

		if remaining == string(current) {
			// Our block is already gone, most likely superseded by a later run in this directory.
			// Leave the file alone rather than touching a block that isn't ours.
			log.Debug().Str("file", path).Msg("No Infisical block from this run to clean up")
			return
		}

		if err := os.WriteFile(path, []byte(remaining), 0o644); err != nil {
			log.Warn().Err(err).Str("file", path).Msg("Could not clean up context file")
		}
	}

	return cleanup, nil
}

// stripManagedBlock removes only the block belonging to runID.
func stripManagedBlock(contents, runID string) string {
	begin, end := blockMarkers(runID)

	start := strings.Index(contents, begin)
	if start < 0 {
		return contents
	}

	stop := strings.Index(contents[start:], end)
	if stop < 0 {
		return contents
	}
	stop += start + len(end)

	// Take the trailing newline with the block if there is one.
	if stop < len(contents) && contents[stop] == '\n' {
		stop++
	}

	return joinAround(contents[:start], contents[stop:])
}

// stripStaleManagedBlocks removes this run's own block plus any block whose run is no longer
// running, and keeps blocks belonging to runs that are still going. Keeping them is what the run ID
// is for: an agent still working in this directory needs its instructions to stay put.
func stripStaleManagedBlocks(contents, ownRunID string) string {
	stripped := managedBlockPattern.ReplaceAllStringFunc(contents, func(block string) string {
		match := managedBlockPattern.FindStringSubmatch(block)
		if len(match) < 2 {
			return ""
		}
		if runID := match[1]; runID != ownRunID && runIsAlive(runID) {
			return block
		}
		return ""
	})

	if stripped == contents {
		return contents
	}
	return joinAround(blankRunPattern.ReplaceAllString(stripped, "\n\n"), "")
}

// runIsAlive reports whether the process that wrote a block is still running.
//
// A reused PID can keep a stale block alive until the next run, which is the safe direction to be
// wrong in, since the cost of the opposite is deleting a live agent's instructions. Anything that
// isn't a PID we recognize is left alone for the same reason.
func runIsAlive(runID string) bool {
	pid, err := strconv.Atoi(runID)
	if err != nil || pid <= 0 {
		return true
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	if runtime.GOOS == "windows" {
		// FindProcess opens the process on Windows, so finding it is proof enough that it exists.
		process.Release()
		return true
	}

	// On Unix FindProcess succeeds for any PID, so the process has to be probed.
	return process.Signal(syscall.Signal(0)) == nil
}

// joinAround stitches the text around a removed block back together without leaving a run of blank
// lines where it used to be.
func joinAround(before, after string) string {
	before = strings.TrimRight(before, "\n")
	after = strings.TrimLeft(after, "\n")

	if before == "" {
		return after
	}
	if strings.TrimSpace(after) == "" {
		return before + "\n"
	}
	return before + "\n\n" + after
}
