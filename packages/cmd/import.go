/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/manifoldco/promptui"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// Well-known env file names an AI-agent bootstrap should surface. Files
// without a stage suffix go to whichever env slug the caller picks (via --env
// or .infisical.json). A stage-specific file is only imported when its stage
// matches that env, so a default of "dev" never swallows .env.production.
// Stage matching only knows the conventional slugs; for a project whose
// production env is called something else (say "live"), --file names the
// files explicitly and --env the target, with no guessing.
var envFileCandidates = []struct {
	Name   string
	Stages []string // env slugs this file belongs to; empty means any
}{
	{Name: ".env"},
	{Name: ".env.local"},
	{Name: ".env.development", Stages: []string{"dev", "development"}},
	{Name: ".env.staging", Stages: []string{"staging", "stage"}},
	{Name: ".env.production", Stages: []string{"prod", "production"}},
}

var importCmd = &cobra.Command{
	Use:                   "import",
	Short:                 "Import secrets from local .env files into an Infisical environment (never deletes the source)",
	DisableFlagsInUseLine: true,
	Example:               "infisical import\n  infisical import --yes\n  infisical import --path=./api --env=staging --add-gitignore\n  infisical import --file=.env.production --env=live",
	Args:                  cobra.NoArgs,
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: runImport,
}

type importedFileResult struct {
	File     string   `json:"file"`
	Env      string   `json:"env"`
	Keys     []string `json:"keys"`
	Uploaded int      `json:"uploaded"`
	Error    string   `json:"error,omitempty"`
}

type skippedFile struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

type importResult struct {
	Files            []importedFileResult `json:"files"`
	Skipped          []skippedFile        `json:"skipped,omitempty"`
	GitignoreUpdated []string             `json:"gitignoreUpdated,omitempty"`
	GitignoreMissing []string             `json:"gitignoreMissing,omitempty"`
	GitignoreError   string               `json:"gitignoreError,omitempty"`
	Cancelled        bool                 `json:"cancelled,omitempty"`
}

func runImport(cmd *cobra.Command, args []string) {
	dir, _ := cmd.Flags().GetString("path")
	envSlug, _ := cmd.Flags().GetString("env")
	yes, _ := cmd.Flags().GetBool("yes")
	jsonOut, _ := cmd.Flags().GetBool("json")
	addGitignore, _ := cmd.Flags().GetBool("add-gitignore")
	explicitFiles, _ := cmd.Flags().GetStringSlice("file")

	// Named files skip stage matching, so the target env must be named too;
	// otherwise a default of "dev" could receive .env.production after all.
	if len(explicitFiles) > 0 && envSlug == "" {
		util.PrintErrorMessageAndExit("--file requires --env, so the files go to an environment you chose explicitly.")
	}

	if dir == "" {
		dir = "."
	}

	// Resolve the project from the scanned directory, not the working
	// directory: in a monorepo --path may point at an app linked to a
	// different project than the root.
	workspaceFile, err := findWorkspaceFileFrom(dir)
	if err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Cannot resolve project for %q. Run `infisical init` (or `infisical init --project-id <id>`) in that directory first.", dir))
	}
	projectId := workspaceFile.WorkspaceId

	// --env wins, else the env from that .infisical.json, else "dev". The
	// branch mapping is read from the repository --path lives in, which may
	// not be the one the command runs from.
	if envSlug == "" {
		if env := util.GetEnvironmentBasedOnGitBranchIn(workspaceFile, dir); env != "" {
			envSlug = env
		} else if workspaceFile.DefaultEnvironment != "" {
			envSlug = workspaceFile.DefaultEnvironment
		} else {
			envSlug = "dev"
		}
	}

	result := importResult{}

	// Explicit list rather than a dotfile scan: a wide scan would pick up
	// .envrc and other files that people don't want their vault to swallow.
	var found []string
	var candidateNames []string
	if len(explicitFiles) > 0 {
		realDir, err := resolveRealPath(dir)
		if err != nil {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Cannot resolve --path %q: %v", dir, err))
		}
		for _, name := range explicitFiles {
			p := name
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, name)
			}
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				util.PrintErrorMessageAndExit(fmt.Sprintf("--file %q is not a readable file.", name))
			}
			// Keep files under --path so the .gitignore check and entries
			// written there refer to the right file. Compare resolved paths:
			// the upload follows symlinks, so a link inside --path must not
			// reach a file outside it, and an absolute --file must compare
			// cleanly against a relative --path.
			realFile, err := resolveRealPath(p)
			if err != nil {
				util.PrintErrorMessageAndExit(fmt.Sprintf("Cannot resolve --file %q: %v", name, err))
			}
			if _, inside := relInside(realDir, realFile); !inside {
				util.PrintErrorMessageAndExit(fmt.Sprintf("--file %q is outside --path %q.", name, dir))
			}
			// The entry itself (a symlink, if it is one) must also sit under
			// --path, and its location there is what .gitignore has to name.
			// Resolve only its parent so the entry's own name is kept.
			realParent, err := resolveRealPath(filepath.Dir(p))
			if err != nil {
				util.PrintErrorMessageAndExit(fmt.Sprintf("Cannot resolve --file %q: %v", name, err))
			}
			entryRel, inside := relInside(realDir, filepath.Join(realParent, filepath.Base(p)))
			if !inside {
				util.PrintErrorMessageAndExit(fmt.Sprintf("--file %q is outside --path %q.", name, dir))
			}
			candidateNames = append(candidateNames, name)
			// Rewrite as a path under --path so the gitignore step below
			// derives the same relative entry the checks above did.
			found = append(found, filepath.Join(dir, entryRel))
		}
	} else {
		for _, c := range envFileCandidates {
			candidateNames = append(candidateNames, c.Name)
			p := filepath.Join(dir, c.Name)
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			if len(c.Stages) > 0 && !containsFold(c.Stages, envSlug) {
				// Don't suggest a slug: the project's env for this stage may
				// not be called any of the conventional names.
				reason := fmt.Sprintf("looks like a %s file but the target env is %q; to import it, re-run with --file=%s --env=<slug of the environment it belongs to>", c.Stages[0], envSlug, c.Name)
				result.Skipped = append(result.Skipped, skippedFile{File: p, Reason: reason})
				if !jsonOut {
					util.PrintfStderr("Skipping %s: %s\n", p, reason)
				}
				continue
			}
			found = append(found, p)
		}
	}

	if len(found) == 0 {
		if jsonOut && len(result.Skipped) > 0 {
			emitImportJSON(result)
			os.Exit(1)
		}
		util.PrintErrorMessageAndExit(fmt.Sprintf("No .env-style files to import into %q under %q. Looked for: %s", envSlug, dir, strings.Join(candidateNames, ", ")))
	}

	type fileScan struct {
		Path string
		Keys []string
	}
	var scans []fileScan
	invalid := false
	for _, f := range found {
		keys, err := extractEnvKeyNames(f)
		if err != nil {
			// Reject the whole import before anything is uploaded: the upload
			// parser would exit partway through otherwise.
			invalid = true
			result.Files = append(result.Files, importedFileResult{File: f, Env: envSlug, Error: err.Error()})
			if !jsonOut {
				util.PrintfStderr("Cannot import %s: %v\n", f, err)
			}
			continue
		}
		if len(keys) == 0 {
			result.Skipped = append(result.Skipped, skippedFile{File: f, Reason: "no keys found"})
			if !jsonOut {
				util.PrintfStderr("Skipping %s (no keys found)\n", f)
			}
			continue
		}
		scans = append(scans, fileScan{Path: f, Keys: keys})
	}

	if invalid {
		if jsonOut {
			emitImportJSON(result)
			os.Exit(1)
		}
		util.PrintErrorMessageAndExit("Fix the files above and re-run. Nothing was uploaded.")
	}

	if len(scans) == 0 {
		util.PrintErrorMessageAndExit("Nothing to import.")
	}

	if !jsonOut {
		util.PrintfStdout("About to import into env %q (project %s):\n", envSlug, projectId)
		for _, s := range scans {
			util.PrintfStdout("\n  %s  (%d key(s))\n", s.Path, len(s.Keys))
			for _, k := range s.Keys {
				util.PrintfStdout("    %s\n", k)
			}
		}
	}

	if !yes {
		prompt := promptui.Prompt{
			Label:     "Proceed with import",
			IsConfirm: true,
		}
		if _, err := prompt.Run(); err != nil {
			result.Cancelled = true
			if jsonOut {
				emitImportJSON(result)
				return
			}
			util.PrintlnStdout("Cancelled. No secrets were uploaded and no files were touched.")
			return
		}
	}

	userCreds := requireUserSession()
	tokenDetails := &models.TokenDetails{Type: "", Token: userCreds.UserCredentials.JTWToken}

	uploadFailed := false
	for _, s := range scans {
		r := importedFileResult{File: s.Path, Env: envSlug, Keys: s.Keys}
		ops, err := util.SetRawSecrets(nil, util.SECRET_TYPE_SHARED, envSlug, "/", projectId, tokenDetails, s.Path, nil)
		if err != nil {
			uploadFailed = true
			r.Error = err.Error()
			result.Files = append(result.Files, r)
			if !jsonOut {
				util.PrintfStderr("Failed to upload %s: %v\n", s.Path, err)
			}
			continue
		}
		r.Uploaded = len(ops)
		result.Files = append(result.Files, r)
		if !jsonOut {
			util.PrintfStdout("Uploaded %d secret(s) from %s into env %q\n", len(ops), s.Path, envSlug)
		}
	}

	gitignorePath := filepath.Join(dir, ".gitignore")
	existingLines := readGitignoreLines(gitignorePath)
	var missing []string
	absDir, _ := filepath.Abs(dir)
	for _, s := range scans {
		absFile, _ := filepath.Abs(s.Path)
		rel, inside := relInside(absDir, absFile)
		if !inside {
			// A "../" entry in this .gitignore would not ignore the file, so
			// never write one or report the file as protected by it.
			util.PrintfStderr("Warning: cannot check .gitignore coverage for %s: it is not under %s\n", s.Path, dir)
			continue
		}
		if !gitignoreCovers(existingLines, rel) {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		if addGitignore {
			if err := appendToGitignore(gitignorePath, missing); err != nil {
				result.GitignoreMissing = missing
				result.GitignoreError = err.Error()
				if !jsonOut {
					util.PrintfStderr("Warning: failed to update %s: %v. These files are still not ignored: %s\n", gitignorePath, err, strings.Join(missing, ", "))
				}
			} else {
				result.GitignoreUpdated = missing
				if !jsonOut {
					util.PrintfStdout("Added %d entry(ies) to %s\n", len(missing), gitignorePath)
				}
			}
		} else {
			result.GitignoreMissing = missing
			if !jsonOut {
				util.PrintWarning(fmt.Sprintf("These files are not in .gitignore: %s. Re-run with --add-gitignore to append them.", strings.Join(missing, ", ")))
			}
		}
	}

	if jsonOut {
		emitImportJSON(result)
	} else {
		util.PrintlnStdout("\nSource files were left in place; they were not deleted.")
	}

	Telemetry.CaptureEvent("cli-command:import", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("filesScanned", len(scans)))

	if uploadFailed {
		os.Exit(1)
	}
}

func emitImportJSON(r importResult) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		util.HandleError(err, "Unable to encode JSON")
	}
	util.PrintlnStdout(string(out))
}

// findWorkspaceFileFrom looks for .infisical.json in dir and its parents,
// mirroring util.FindWorkspaceConfigFile but anchored at dir instead of the
// working directory.
func findWorkspaceFileFrom(dir string) (models.WorkspaceConfigFile, error) {
	current, err := filepath.Abs(dir)
	if err != nil {
		return models.WorkspaceConfigFile{}, err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)); err == nil {
			return util.GetWorkSpaceFromFilePath(current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return models.WorkspaceConfigFile{}, fmt.Errorf("file not found: %s", util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		}
		current = parent
	}
}

// relInside returns target relative to base, and whether target is base
// itself or lies beneath it.
func relInside(base, target string) (string, bool) {
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// resolveRealPath returns p as an absolute path with every symlink resolved.
func resolveRealPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func containsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

// extractEnvKeyNames returns key names only (never values) and rejects the
// file under the same rules util.SetRawSecrets applies, so the preview and the
// upload agree on what is importable. Errors cite line numbers and key names
// but never line contents, since a malformed line may hold a secret.
func extractEnvKeyNames(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var keys []string
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	// PEM-style values run long; give the scanner room so a bad line
	// doesn't cap the preview well below what SetRawSecrets will accept.
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNo)
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("line %d: key is empty", lineNo)
		}
		if unicode.IsNumber(rune(key[0])) {
			return nil, fmt.Errorf("line %d: key %q cannot start with a number", lineNo, key)
		}
		if strings.Contains(key, " ") {
			return nil, fmt.Errorf("line %d: key %q cannot contain spaces", lineNo, key)
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("line %d: key %q has an empty value", lineNo, key)
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

func readGitignoreLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines
}

// gitignoreCovers answers the narrow question "will git commit this file by
// accident?" for a file next to the .gitignore. It handles globs, anchored
// and "**/" patterns, and negation (last match wins), and skips
// directory-only patterns. It is not a full gitignore implementation, so when
// in doubt it reports the file as uncovered.
func gitignoreCovers(lines []string, rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	covered := false
	for _, l := range lines {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		negate := strings.HasPrefix(l, "!")
		pattern := strings.TrimPrefix(l, "!")
		if strings.HasSuffix(pattern, "/") {
			continue
		}
		pattern = strings.TrimPrefix(pattern, "**/")

		var matched bool
		if strings.Contains(pattern, "/") {
			matched, _ = path.Match(strings.TrimPrefix(pattern, "/"), rel)
		} else {
			matched, _ = path.Match(pattern, base)
		}
		if matched {
			covered = !negate
		}
	}
	return covered
}

func appendToGitignore(path string, entries []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Preamble newline in case the existing file didn't end in one.
	if _, err := f.WriteString("\n# Added by `infisical import`\n"); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := f.WriteString(e + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	importCmd.Flags().String("path", "", "Directory to scan for .env-style files (default: current working directory).")
	importCmd.Flags().String("env", "", "Environment slug to upload into (default: env from .infisical.json, else \"dev\").")
	importCmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt. Required for non-interactive / agent runs.")
	importCmd.Flags().Bool("json", false, "Emit a machine-readable summary of the import (files scanned, keys per file, upload counts, gitignore status).")
	importCmd.Flags().StringSlice("file", nil, "Import exactly these files (relative to --path) instead of scanning for well-known names. Skips stage matching, so --env is required. Repeatable.")
	importCmd.Flags().Bool("add-gitignore", false, "Append every imported file that is not already in .gitignore to .gitignore.")
	RootCmd.AddCommand(importCmd)
}
