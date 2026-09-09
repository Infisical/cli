/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/manifoldco/promptui"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// Well-known env file names an AI-agent bootstrap should surface. Nothing in
// this list is auto-mapped to a specific environment: the caller picks one env
// slug (via --env or .infisical.json) and every discovered file goes there.
// Splitting files across environments requires running `import` per file,
// which keeps the mental model of the command simple.
var envFileCandidates = []string{
	".env",
	".env.local",
	".env.development",
	".env.staging",
	".env.production",
}

var importCmd = &cobra.Command{
	Use:                   "import",
	Short:                 "Import secrets from local .env files into an Infisical environment (never deletes the source)",
	DisableFlagsInUseLine: true,
	Example:               "infisical import\n  infisical import --yes\n  infisical import --path=./api --env=staging --add-gitignore",
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

type importResult struct {
	Files            []importedFileResult `json:"files"`
	GitignoreUpdated []string             `json:"gitignoreUpdated,omitempty"`
	GitignoreMissing []string             `json:"gitignoreMissing,omitempty"`
	Cancelled        bool                 `json:"cancelled,omitempty"`
}

func runImport(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	envSlug, _ := cmd.Flags().GetString("env")
	yes, _ := cmd.Flags().GetBool("yes")
	jsonOut, _ := cmd.Flags().GetBool("json")
	addGitignore, _ := cmd.Flags().GetBool("add-gitignore")

	if path == "" {
		path = "."
	}

	// --env wins, else the env from .infisical.json, else "dev".
	if envSlug == "" {
		if envFromWorkspace := util.GetEnvFromWorkspaceFile(); envFromWorkspace != "" {
			envSlug = envFromWorkspace
		} else {
			envSlug = "dev"
		}
	}

	workspaceFile, err := util.GetWorkSpaceFromFile()
	if err != nil {
		util.PrintErrorMessageAndExit("Cannot resolve project. Run `infisical init` (or `infisical init --project-id <id>`) in this directory first.")
	}
	projectId := workspaceFile.WorkspaceId

	// Explicit list rather than a dotfile scan: a wide scan would pick up
	// .envrc and other files that people don't want their vault to swallow.
	var found []string
	for _, name := range envFileCandidates {
		p := filepath.Join(path, name)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		found = append(found, p)
	}

	if len(found) == 0 {
		util.PrintErrorMessageAndExit(fmt.Sprintf("No .env-style files found under %q. Looked for: %s", path, strings.Join(envFileCandidates, ", ")))
	}

	type fileScan struct {
		Path string
		Keys []string
	}
	var scans []fileScan
	for _, f := range found {
		keys, err := extractEnvKeyNames(f)
		if err != nil {
			util.PrintfStderr("Skipping %s: %v\n", f, err)
			continue
		}
		if len(keys) == 0 {
			util.PrintfStderr("Skipping %s (no keys found)\n", f)
			continue
		}
		scans = append(scans, fileScan{Path: f, Keys: keys})
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

	result := importResult{}
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

	for _, s := range scans {
		r := importedFileResult{File: s.Path, Env: envSlug, Keys: s.Keys}
		ops, err := util.SetRawSecrets(nil, util.SECRET_TYPE_SHARED, envSlug, "/", projectId, tokenDetails, s.Path, nil)
		if err != nil {
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

	gitignorePath := filepath.Join(path, ".gitignore")
	existingLines := readGitignoreLines(gitignorePath)
	var missing []string
	for _, s := range scans {
		rel, err := filepath.Rel(path, s.Path)
		if err != nil {
			rel = filepath.Base(s.Path)
		}
		if !gitignoreCovers(existingLines, rel) {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		if addGitignore {
			if err := appendToGitignore(gitignorePath, missing); err != nil {
				util.PrintfStderr("Warning: failed to update %s: %v\n", gitignorePath, err)
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
}

func emitImportJSON(r importResult) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		util.HandleError(err, "Unable to encode JSON")
	}
	util.PrintlnStdout(string(out))
}

// extractEnvKeyNames returns key names only (never values) using the same
// comment and key=value rules as util.parseSecrets so the preview and the
// eventual upload agree on what constitutes a line.
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
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
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

// gitignoreCovers is deliberately conservative: it matches only exact entries
// and the common .env glob patterns. The narrow question this answers is
// "will git commit this file by accident?" — the answer is worth surfacing
// even without a full gitignore-pattern matcher.
func gitignoreCovers(lines []string, rel string) bool {
	for _, l := range lines {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if l == rel || l == "/"+rel {
			return true
		}
		if l == ".env*" || l == "*.env" || l == "**/.env*" {
			return true
		}
	}
	return false
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
	importCmd.Flags().Bool("add-gitignore", false, "Append every imported file that is not already in .gitignore to .gitignore.")
	RootCmd.AddCommand(importCmd)
}
