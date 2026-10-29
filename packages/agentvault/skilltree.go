package agentvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/gofrs/flock"
	"github.com/rs/zerolog/log"
)

const (
	ClaudeCodeAgent = "Claude Code"
	HermesAgent     = "Hermes"
)

// Every skill folder the CLI writes holds this file, and only a folder that holds it is ever replaced. Hidden,
// so skills push and zip uploads leave it out.
const SkillMarkerFile = ".infisical-agent-vault"

type skillMarker struct {
	SkillID string `json:"skillId"`
	Sha256  string `json:"sha256"`
}

// A variable so tests keep their locks out of the real data directory.
var skillsLockDir = DefaultDataDir

type InstallOptions struct {
	// Dir replaces ~/.agents/skills, and no agent folder is linked to it.
	Dir string
	// Symlink is os.Symlink unless a test replaces it.
	Symlink func(oldname, newname string) error
	// ForceClaude links for Claude Code even before its folder exists, for a run that starts Claude Code.
	ForceClaude bool
}

type InstallResult struct {
	Dir       string
	Installed int
	Failed    []string
	// Linked names the agents whose own skills folder received a link or copy of the installed skills.
	Linked     []LinkedAgent
	LinkFailed []string
}

type LinkedAgent struct {
	Agent string
	Dir   string
}

type linkTarget struct {
	agent string
	dir   string
}

// InstallSkills writes each skill as a real folder under the install directory, replacing only a folder it
// wrote before, and links it into the skills folder of every agent found on this machine. Skills stay after
// the run. Every skill ctx leaves unwritten is named, so the failures account for all of them.
func InstallSkills(ctx context.Context, skills []api.AgentVaultSessionSkill, opts InstallOptions) (InstallResult, error) {
	var result InstallResult
	dir := opts.Dir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return result, fmt.Errorf("unable to determine the home directory: %w", err)
		}
		dir = filepath.Join(home, ".agents", "skills")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return result, err
	}
	result.Dir = dir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return result, fmt.Errorf("failed to create %s: %w", dir, err)
	}
	unlock := lockSkillsDir(ctx, dir)
	defer unlock()

	var targets []linkTarget
	if opts.Dir == "" {
		targets = result.prepareLinks(dir, opts.ForceClaude)
	}
	symlink := opts.Symlink
	if symlink == nil {
		symlink = os.Symlink
	}
	linked := map[string]bool{}

	for i, skill := range skills {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				for _, rest := range skills[i:] {
					result.Failed = append(result.Failed, fmt.Sprintf("%s (timed out)", rest.Name))
				}
			}
			break
		}
		if SkillFilesSha256(skill.Files) != skill.Sha256 {
			result.Failed = append(result.Failed, fmt.Sprintf("%s (its files do not match their checksum)", skill.Name))
			continue
		}
		if err := installSkillFolder(dir, skill); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s (%v)", skill.Name, err))
			continue
		}
		result.Installed++
		for _, target := range targets {
			if err := linkSkill(symlink, dir, target.dir, skill); err != nil {
				result.LinkFailed = append(result.LinkFailed, fmt.Sprintf("%s for %s (%v)", skill.Name, target.agent, err))
				continue
			}
			linked[target.agent] = true
		}
	}
	for _, target := range targets {
		if linked[target.agent] {
			result.Linked = append(result.Linked, LinkedAgent{Agent: target.agent, Dir: target.dir})
		}
	}
	return result, nil
}

// prepareLinks returns the skills folder of each agent installed here, and of Claude Code when forceClaude is set.
func (r *InstallResult) prepareLinks(canonical string, forceClaude bool) []linkTarget {
	home, _ := os.UserHomeDir()
	agentDir := func(env, fallback string) string {
		if v := os.Getenv(env); v != "" {
			if abs, err := filepath.Abs(v); err == nil {
				return abs
			}
			return v
		}
		if home == "" {
			return ""
		}
		return filepath.Join(home, fallback)
	}
	canonicalInfo, canonicalErr := os.Stat(canonical)

	var targets []linkTarget
	for _, agent := range []struct {
		name  string
		dir   string
		force bool
	}{
		{ClaudeCodeAgent, agentDir("CLAUDE_CONFIG_DIR", ".claude"), forceClaude},
		{HermesAgent, agentDir("HERMES_HOME", ".hermes"), false},
	} {
		if agent.dir == "" {
			continue
		}
		if info, err := os.Stat(agent.dir); !agent.force && (err != nil || !info.IsDir()) {
			continue
		}
		skillsDir := filepath.Join(agent.dir, "skills")
		if err := os.MkdirAll(skillsDir, 0o755); err != nil {
			r.LinkFailed = append(r.LinkFailed, fmt.Sprintf("all skills for %s (failed to create %s: %v)", agent.name, skillsDir, err))
			continue
		}
		// By identity, not path: a link through another name still lands on the install directory, and linking a
		// skill there would replace it with a link to itself. The agent already sees the skills, so it is not
		// named as linked.
		if info, err := os.Stat(skillsDir); err == nil && canonicalErr == nil && os.SameFile(info, canonicalInfo) {
			continue
		}
		targets = append(targets, linkTarget{agent: agent.name, dir: skillsDir})
	}
	return targets
}

// lockSkillsDir keeps two runs from writing one install directory at once. The lock lives in the data
// directory, not beside the skills, so nothing extra appears in a folder agents read. A ctx that ends first
// returns a no-op unlock, and the caller's ctx check names what was left unwritten. A data directory that can't
// hold the lock, such as one on a read-only root file system, installs without it rather than not at all.
func lockSkillsDir(ctx context.Context, dir string) func() {
	lockDir, err := skillsLockDir()
	if err == nil {
		err = os.MkdirAll(lockDir, 0o700)
	}
	if err != nil {
		log.Debug().Err(err).Msg("agent-vault: installing skills without a lock")
		return func() {}
	}
	key := dir
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		key = resolved
	}
	sum := sha256.Sum256([]byte(key))
	fl := flock.New(filepath.Join(lockDir, "skills-"+hex.EncodeToString(sum[:8])+".lock"))
	locked, err := fl.TryLockContext(ctx, 50*time.Millisecond)
	switch {
	case locked:
		return func() { _ = fl.Unlock() }
	case ctx.Err() != nil:
		_ = fl.Close()
		return func() {}
	default:
		_ = fl.Close()
		log.Debug().Err(err).Msg("agent-vault: installing skills without a lock")
		return func() {}
	}
}

func installSkillFolder(dir string, skill api.AgentVaultSessionSkill) error {
	if !validSkillFolderName(skill.Name) {
		return fmt.Errorf("the name %q cannot be used as a folder name", skill.Name)
	}
	dest := filepath.Join(dir, skill.Name)
	owned, err := ownedSkillEntry(dir, skill.Name)
	if err != nil {
		return err
	}
	if owned && skillFolderIsCurrent(dest, skill) {
		return nil
	}
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("failed to replace %s: %w", dest, err)
	}
	if err := writeSkillFolder(dest, skill); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	return nil
}

// Where links are not allowed, such as Windows without developer mode, the agent gets a copy instead. Only a
// link into the install directory or a folder the CLI wrote is replaced; anything else is the user's.
func linkSkill(symlink func(oldname, newname string) error, installDir, agentSkillsDir string, skill api.AgentVaultSessionSkill) error {
	src := filepath.Join(installDir, skill.Name)
	dest := filepath.Join(agentSkillsDir, skill.Name)
	info, err := os.Lstat(dest)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("failed to read %s: %w", dest, err)
	case info.Mode()&os.ModeSymlink != 0:
		target, readErr := os.Readlink(dest)
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w", dest, readErr)
		}
		if target == src {
			return nil
		}
		if !linksIntoDir(agentSkillsDir, target, installDir) {
			return notInstalledByInfisical(agentSkillsDir, skill.Name, info)
		}
	case info.IsDir() && hasSkillMarker(dest):
		if skillFolderIsCurrent(dest, skill) {
			return nil
		}
	default:
		return notInstalledByInfisical(agentSkillsDir, skill.Name, info)
	}
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("failed to replace %s: %w", dest, err)
	}
	if err := symlink(src, dest); err == nil {
		return nil
	}
	_ = os.RemoveAll(dest)
	if err := writeSkillFolder(dest, skill); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	return nil
}

// ownedSkillEntry reports whether name exists in dir as a folder the CLI wrote. A missing entry is free to
// write, and anything else there is refused.
func ownedSkillEntry(dir, name string) (bool, error) {
	dest := filepath.Join(dir, name)
	info, err := os.Lstat(dest)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read %s: %w", dest, err)
	}
	if info.IsDir() && hasSkillMarker(dest) {
		return true, nil
	}
	return false, notInstalledByInfisical(dir, name, info)
}

func linksIntoDir(linkDir, target, dir string) bool {
	if !filepath.IsAbs(target) {
		target = filepath.Join(linkDir, target)
	}
	parent := filepath.Dir(filepath.Clean(target))
	if parent == dir {
		return true
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return false
	}
	dirInfo, err := os.Stat(dir)
	return err == nil && os.SameFile(parentInfo, dirInfo)
}

func hasSkillMarker(folder string) bool {
	info, err := os.Lstat(filepath.Join(folder, SkillMarkerFile))
	return err == nil && info.Mode().IsRegular()
}

// A folder already holding this version is left alone, so an agent reading it is not disturbed. The marker's
// checksum is only written once every file is, so a folder cut short is rewritten, and each file is compared
// too, so one an agent deleted or changed is put back. Files an agent added are not the skill's and stay.
func skillFolderIsCurrent(folder string, skill api.AgentVaultSessionSkill) bool {
	data, err := os.ReadFile(filepath.Join(folder, SkillMarkerFile))
	if err != nil {
		return false
	}
	var marker skillMarker
	if json.Unmarshal(data, &marker) != nil || marker.Sha256 == "" || marker.Sha256 != skill.Sha256 {
		return false
	}
	for _, file := range skill.Files {
		path := filepath.Join(folder, filepath.FromSlash(file.Path))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		// Windows keeps no executable bit, so the mode can only be compared elsewhere.
		if runtime.GOOS != "windows" && info.Mode().Perm() != skillFileMode(file.Mode) {
			return false
		}
		content, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil || int64(len(content)) != info.Size() {
			return false
		}
		onDisk, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(onDisk, content) {
			return false
		}
	}
	return true
}

// On a case-insensitive file system the entry can exist under another spelling, so the message names it as it
// is on disk.
func notInstalledByInfisical(dir, name string, info os.FileInfo) error {
	onDisk := name
	if entries, readErr := os.ReadDir(dir); readErr == nil {
		for _, entry := range entries {
			if entry.Name() == name {
				onDisk = name
				break
			}
			if strings.EqualFold(entry.Name(), name) {
				onDisk = entry.Name()
			}
		}
	}
	kind := "file"
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		kind = "link"
	case info.IsDir():
		kind = "folder"
	}
	return fmt.Errorf("a %s named %s already exists and wasn't installed by Infisical", kind, onDisk)
}

// Skill names become folder names, so anything that could step outside the install directory is refused.
func validSkillFolderName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.HasPrefix(name, ".") &&
		!strings.ContainsAny(name, `/\:`) && filepath.IsLocal(name)
}

// The marker goes in first, so a folder cut short is still known as the CLI's and replaced on the next run.
func writeSkillFolder(root string, skill api.AgentVaultSessionSkill) error {
	if err := os.Mkdir(root, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", root, err)
	}
	if err := writeSkillMarker(root, skillMarker{SkillID: skill.ID}); err != nil {
		return err
	}
	if err := writeSkillFiles(root, skill.Files); err != nil {
		return err
	}
	return writeSkillMarker(root, skillMarker{SkillID: skill.ID, Sha256: skill.Sha256})
}

func writeSkillMarker(root string, marker skillMarker) error {
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, SkillMarkerFile), data, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", SkillMarkerFile, err)
	}
	return nil
}

func writeSkillFiles(root string, files []api.AgentVaultSkillFile) error {
	for _, file := range files {
		rel := filepath.FromSlash(file.Path)
		if file.Path == "" || strings.Contains(file.Path, `\`) || !filepath.IsLocal(rel) || filepath.Clean(rel) == "." {
			return fmt.Errorf("it holds a file at %q, which is outside its folder", file.Path)
		}
		target := filepath.Join(root, rel)
		if inside, err := filepath.Rel(root, target); err != nil || !filepath.IsLocal(inside) {
			return fmt.Errorf("it holds a file at %q, which is outside its folder", file.Path)
		}
		content, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil {
			return fmt.Errorf("its file %q is not valid base64", file.Path)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("failed to create the folder for %q: %w", file.Path, err)
		}
		// O_EXCL so nothing already at the path, a symlink included, is ever written through.
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, skillFileMode(file.Mode))
		if err != nil {
			return fmt.Errorf("failed to write %q: %w", file.Path, err)
		}
		_, writeErr := f.Write(content)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return fmt.Errorf("failed to write %q: %w", file.Path, errors.Join(writeErr, closeErr))
		}
		// The umask may have narrowed the create mode; the masked mode is what the skill asked for.
		if err := os.Chmod(target, skillFileMode(file.Mode)); err != nil {
			return fmt.Errorf("failed to set the mode of %q: %w", file.Path, err)
		}
	}
	return nil
}

// Only the executable bit survives; nothing a skill sends can make a file writable by others or setuid.
func skillFileMode(mode string) os.FileMode {
	parsed, err := strconv.ParseUint(mode, 8, 32)
	if err == nil && parsed&0o111 != 0 {
		return 0o755
	}
	return 0o644
}
