package agentvault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
)

const (
	ClaudeCodeAgent = "Claude Code"
	HermesAgent     = "Hermes"
)

type InstallOptions struct {
	// Dir replaces ~/.agents/skills, and no agent folder is linked to it.
	Dir string
	// Symlink is os.Symlink unless a test replaces it.
	Symlink func(oldname, newname string) error
}

type InstallResult struct {
	Dir       string
	Installed int
	Failed    []string
	// Linked names the agents that can see the installed skills through their own skills folder.
	Linked     []string
	LinkFailed []string
}

type linkTarget struct {
	agent string
	dir   string
}

// InstallSkills writes each skill as a real folder under the install directory, replacing whatever has that
// name, and links it into the skills folder of every agent found on this machine. Skills stay after the run.
// Every skill ctx leaves unwritten is named, so the failures account for all of them.
func InstallSkills(ctx context.Context, skills []api.AgentVaultProxySkill, opts InstallOptions) (InstallResult, error) {
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

	var targets []linkTarget
	if opts.Dir == "" {
		targets = result.prepareLinks(dir)
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
		if err := installSkillFolder(dir, skill.Name, skill.Files); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s (%v)", skill.Name, err))
			continue
		}
		result.Installed++
		for _, target := range targets {
			if target.dir == "" {
				linked[target.agent] = true
				continue
			}
			if err := linkSkill(symlink, filepath.Join(dir, skill.Name), filepath.Join(target.dir, skill.Name), skill.Files); err != nil {
				result.LinkFailed = append(result.LinkFailed, fmt.Sprintf("%s for %s (%v)", skill.Name, target.agent, err))
				continue
			}
			linked[target.agent] = true
		}
	}
	for _, target := range targets {
		if linked[target.agent] {
			result.Linked = append(result.Linked, target.agent)
		}
	}
	return result, nil
}

// prepareLinks returns the skills folder of each agent installed here. An empty dir marks one that already
// resolves to the install directory, so the agent sees the skills without a link.
func (r *InstallResult) prepareLinks(canonical string) []linkTarget {
	home, _ := os.UserHomeDir()
	agentDir := func(env, fallback string) string {
		if v := os.Getenv(env); v != "" {
			return v
		}
		if home == "" {
			return ""
		}
		return filepath.Join(home, fallback)
	}
	resolvedCanonical, err := filepath.EvalSymlinks(canonical)
	if err != nil {
		resolvedCanonical = canonical
	}

	var targets []linkTarget
	for _, agent := range []struct{ name, dir string }{
		{ClaudeCodeAgent, agentDir("CLAUDE_CONFIG_DIR", ".claude")},
		{HermesAgent, agentDir("HERMES_HOME", ".hermes")},
	} {
		if agent.dir == "" {
			continue
		}
		if info, err := os.Stat(agent.dir); err != nil || !info.IsDir() {
			continue
		}
		skillsDir := filepath.Join(agent.dir, "skills")
		if err := os.MkdirAll(skillsDir, 0o755); err != nil {
			r.LinkFailed = append(r.LinkFailed, fmt.Sprintf("all skills for %s (failed to create %s: %v)", agent.name, skillsDir, err))
			continue
		}
		if resolved, err := filepath.EvalSymlinks(skillsDir); err == nil && resolved == resolvedCanonical {
			targets = append(targets, linkTarget{agent: agent.name})
			continue
		}
		targets = append(targets, linkTarget{agent: agent.name, dir: skillsDir})
	}
	return targets
}

func installSkillFolder(dir, name string, files []api.AgentVaultSkillFile) error {
	if !validSkillFolderName(name) {
		return fmt.Errorf("the name %q cannot be used as a folder name", name)
	}
	dest := filepath.Join(dir, name)
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("failed to replace %s: %w", dest, err)
	}
	if err := writeSkillFiles(dest, files); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	return nil
}

// Where links are not allowed, such as Windows without developer mode, the agent gets a copy instead.
func linkSkill(symlink func(oldname, newname string) error, src, dest string, files []api.AgentVaultSkillFile) error {
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("failed to replace %s: %w", dest, err)
	}
	if err := symlink(src, dest); err == nil {
		return nil
	}
	_ = os.RemoveAll(dest)
	if err := writeSkillFiles(dest, files); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	return nil
}

// Skill names become folder names, so anything that could step outside the install directory is refused.
func validSkillFolderName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.HasPrefix(name, ".") &&
		!strings.ContainsAny(name, `/\:`) && filepath.IsLocal(name)
}

func writeSkillFiles(root string, files []api.AgentVaultSkillFile) error {
	if err := os.Mkdir(root, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", root, err)
	}
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
