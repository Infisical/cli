package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
)

var agentVaultSkillsCmd = &cobra.Command{
	Use:   "skills",
	Short: "Manage the skills Agent Vault delivers to agents",
}

var agentVaultSkillsPushCmd = &cobra.Command{
	Use:   "push <folder>",
	Short: "Create a skill from a folder, or publish the folder as its next version",
	Long: `Create a skill from a folder, or publish the folder as its next version.

The folder holds one skill, with SKILL.md at its root. The name in the SKILL.md header picks the skill: a new
name creates it, and an existing one gets a new version unless nothing changed.

The skill belongs to the Agent Vault project from --project-id, or else INFISICAL_AGENT_VAULT_PROJECT_ID or
INFISICAL_PROJECT_ID, in that order.`,
	Example:               "  infisical agent-vault skills push ./skills/code-review",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		files, name, err := readAgentVaultSkillFolder(args[0])
		if err != nil {
			util.HandleError(err)
		}
		httpClient, project := newAgentVaultSkillsAPIClient(cmd)

		result, err := pushAgentVaultSkill(httpClient, project.ID, name, files)
		if err != nil {
			util.HandleError(err, agentVaultProjectHints(err, project)...)
		}
		fmt.Println(result)
	},
}

var agentVaultSkillsGetCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "List the skills in an Agent Vault project, or show one",
	Long: `List the skills in an Agent Vault project, with each skill's latest version and the access bundles it is in.
With a name, show that skill and the files in its latest version. To download the files, use
'infisical agent-vault skills pull'.

A member sees only the skills on access bundles they have been granted.

The project comes from --project-id, or else INFISICAL_AGENT_VAULT_PROJECT_ID or INFISICAL_PROJECT_ID, in that order.`,
	Example:               "  infisical agent-vault skills get\n  infisical agent-vault skills get code-review -o json",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat := crudOutputFormat(cmd, "skills")
		httpClient, project := newAgentVaultSkillsAPIClient(cmd)

		if len(args) == 0 {
			skills, err := listAgentVaultSkills(httpClient, project)
			if err != nil {
				exitWithError(cmd, err, "Unable to list the skills")
			}
			if outputFormat != "" {
				printFormattedOutput(outputFormat, skills)
				return
			}
			if len(skills) == 0 {
				util.PrintlnStderr("No skills in this project. Add one with infisical agent-vault skills push <folder>.")
				return
			}
			printAgentVaultSkillsTable(cmd, skills)
			return
		}

		skill, err := getAgentVaultSkill(httpClient, project, args[0])
		if err != nil {
			exitWithError(cmd, err, "Unable to get the skill")
		}
		if outputFormat != "" {
			printFormattedOutput(outputFormat, skill)
			return
		}
		printAgentVaultSkillsTable(cmd, []api.AgentVaultSkill{skill.AgentVaultSkill})
		fmt.Fprintln(cmd.OutOrStdout(), "\nFILES")
		for _, file := range skill.Files {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", util.SanitizeDisplay(file.Path))
		}
	},
}

var agentVaultSkillsPullCmd = &cobra.Command{
	Use:   "pull <name> [folder]",
	Short: "Download a skill's files to a folder",
	Long: `Download a skill's files to a folder, ready to edit and push again.

The files go to ./<name> unless you pass a folder. The command refuses a folder that already exists; --force
replaces it, so it holds exactly the skill's files and nothing else, hidden files such as .git included.

--version pulls an earlier version. Only an Admin of the project can pull a version other than the latest.

The project comes from --project-id, or else INFISICAL_AGENT_VAULT_PROJECT_ID or INFISICAL_PROJECT_ID, in that order.`,
	Example:               "  infisical agent-vault skills pull code-review\n  infisical agent-vault skills pull code-review ./skills/code-review --version 3",
	DisableFlagsInUseLine: true,
	Args:                  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		folder := name
		if len(args) == 2 {
			folder = args[1]
		} else if !agentvault.ValidSkillFolderName(name) {
			exitWithError(cmd, errAgentVaultSkillNameNotAFolder(name))
		}
		version, err := cmd.Flags().GetInt("version")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}
		if cmd.Flags().Changed("version") && version < 1 {
			exitWithError(cmd, errAgentVaultSkillVersionInvalid())
		}
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}
		if err := checkAgentVaultSkillPullTarget(cmd, args, folder, force); err != nil {
			exitWithError(cmd, err)
		}
		httpClient, project := newAgentVaultSkillsAPIClient(cmd)

		result, err := pullAgentVaultSkill(httpClient, project, name, folder, version, force)
		if err != nil {
			exitWithError(cmd, err, "Unable to pull the skill")
		}
		fmt.Println(result)
	},
}

var agentVaultSkillsDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a skill from an Agent Vault project",
	Long: `Delete a skill from an Agent Vault project. It is removed from every access bundle, so agents stop getting it
the next time they start.

The command asks you to type the skill's name. Pass --yes to skip the question, as a script or agent must.

A delete needs --project-id. It never reads the project from INFISICAL_AGENT_VAULT_PROJECT_ID or INFISICAL_PROJECT_ID.`,
	Example:               "  infisical agent-vault skills delete code-review --project-id <project-id>\n  infisical agent-vault skills delete code-review --project-id <project-id> --yes",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat := crudOutputFormat(cmd, "skills")
		if !cmd.Flags().Changed("project-id") {
			exitWithError(cmd, errAgentVaultSkillDeleteProjectRequired())
		}
		httpClient, project := newAgentVaultSkillsAPIClient(cmd)

		skill, err := requireAgentVaultSkill(httpClient, project, args[0])
		if err != nil {
			exitWithError(cmd, err, "Unable to delete the skill")
		}
		if err := confirmDestructive(cmd, args, agentVaultSkillDeleteAction(skill, project.ID)); err != nil {
			exitWithError(cmd, err)
		}
		deleted, err := api.CallDeleteAgentVaultSkill(httpClient, skill.ID)
		if err != nil {
			exitWithError(cmd, agentVaultSkillAPIError(err, project, skill.Name), "Unable to delete the skill")
		}
		if outputFormat != "" {
			// The delete response has no bundles, so the lookup's say which bundles the skill was removed from.
			deleted.Skill.AccessBundles = skill.AccessBundles
			printFormattedOutput(outputFormat, deleted.Skill)
			return
		}
		fmt.Printf("%s: deleted\n", util.SanitizeDisplay(skill.Name))
	},
}

func newAgentVaultSkillsAPIClient(cmd *cobra.Command) (*resty.Client, agentVaultProject) {
	project, err := resolveAgentVaultProject(cmd)
	if err != nil {
		exitWithError(cmd, err)
	}
	echoAgentVaultProject(cmd, project)

	identity := resolveAgentVaultIdentityToken(cmd)
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Failed to build the API client")
	}
	httpClient.SetAuthToken(identity)
	return httpClient, project
}

func printAgentVaultSkillsTable(cmd *cobra.Command, skills []api.AgentVaultSkill) {
	writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tVERSION\tACCESS BUNDLES")
	for _, skill := range skills {
		bundles := make([]string, 0, len(skill.AccessBundles))
		for _, bundle := range skill.AccessBundles {
			bundles = append(bundles, util.SanitizeDisplay(bundle.Name))
		}
		if len(bundles) == 0 {
			bundles = append(bundles, "-")
		}
		fmt.Fprintf(writer, "%s\tv%d\t%s\n", util.SanitizeDisplay(skill.Name), skill.LatestVersion, strings.Join(bundles, ", "))
	}
	writer.Flush()
}

func findAgentVaultSkill(httpClient *resty.Client, projectID, name string) (api.AgentVaultSkill, bool, error) {
	listed, err := api.CallListAgentVaultSkillsByName(httpClient, projectID, name)
	if err != nil {
		return api.AgentVaultSkill{}, false, fmt.Errorf("unable to look up the skill %q: %w", name, err)
	}
	for _, skill := range listed.Skills {
		if skill.Name == name {
			return skill, true, nil
		}
	}
	return api.AgentVaultSkill{}, false, nil
}

func requireAgentVaultSkill(httpClient *resty.Client, project agentVaultProject, name string) (api.AgentVaultSkill, error) {
	skill, found, err := findAgentVaultSkill(httpClient, project.ID, name)
	if err != nil {
		return api.AgentVaultSkill{}, classifyAgentVaultAPIError(err, project, "")
	}
	if !found {
		return api.AgentVaultSkill{}, errAgentVaultSkillNotFound(name, project)
	}
	return skill, nil
}

// agentVaultSkillAPIError classifies an error from a route that names the skill by ID, where a 404 means the
// skill is gone (deleted since it was looked up), not that the project is.
func agentVaultSkillAPIError(err error, project agentVaultProject, name string) error {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound && apiErr.Name != infisicalRouteMissingName {
		return errAgentVaultSkillNotFound(name, project)
	}
	return classifyAgentVaultAPIError(err, project, "")
}

// agentVaultSkillDetail is what `skills get <name>` shows: the skill and its file list, without file contents,
// which `skills pull` downloads.
type agentVaultSkillDetail struct {
	api.AgentVaultSkill
	Files []agentVaultSkillFileEntry `json:"files"`
}

type agentVaultSkillFileEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

func getAgentVaultSkill(httpClient *resty.Client, project agentVaultProject, name string) (agentVaultSkillDetail, error) {
	skill, err := requireAgentVaultSkill(httpClient, project, name)
	if err != nil {
		return agentVaultSkillDetail{}, err
	}
	got, err := api.CallGetAgentVaultSkill(httpClient, skill.ID)
	if err != nil {
		return agentVaultSkillDetail{}, agentVaultSkillAPIError(err, project, name)
	}
	detail := agentVaultSkillDetail{AgentVaultSkill: got.Skill.AgentVaultSkill, Files: []agentVaultSkillFileEntry{}}
	for _, file := range got.Skill.Files {
		detail.Files = append(detail.Files, agentVaultSkillFileEntry{Path: file.Path, Mode: file.Mode})
	}
	return detail, nil
}

const agentVaultSkillsPageSize = 100

func listAgentVaultSkills(httpClient *resty.Client, project agentVaultProject) ([]api.AgentVaultSkill, error) {
	skills := []api.AgentVaultSkill{}
	for {
		page, err := api.CallListAgentVaultSkills(httpClient, project.ID, agentVaultSkillsPageSize, len(skills))
		if err != nil {
			return nil, classifyAgentVaultAPIError(err, project, "")
		}
		skills = append(skills, page.Skills...)
		// An empty page ends the loop too, so a count that moves while paging can't spin it.
		if len(page.Skills) == 0 || len(skills) >= page.TotalCount {
			return skills, nil
		}
	}
}

// checkAgentVaultSkillPullTarget runs before anything is downloaded, so a pull that can't write fails fast. The
// swap in replaceAgentVaultSkillFolder renames the folder, which a symlink, the working folder or one holding it
// can't survive.
func checkAgentVaultSkillPullTarget(cmd *cobra.Command, args []string, folder string, force bool) error {
	info, err := os.Lstat(folder)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to check %s: %w", folder, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return errAgentVaultSkillPullTarget(folder, "is a symbolic link. Pass a folder instead.")
	}
	if !info.IsDir() {
		return errAgentVaultSkillPullTarget(folder, "already exists and is not a folder. Pass another folder.")
	}
	if !force {
		return errAgentVaultSkillFolderExists(cmd, args, folder)
	}
	target, err := filepath.Abs(folder)
	if err == nil {
		target, err = filepath.EvalSymlinks(target)
	}
	if err != nil {
		return fmt.Errorf("unable to check %s: %w", folder, err)
	}
	if wd, err := os.Getwd(); err == nil {
		if wd, err = filepath.EvalSymlinks(wd); err == nil {
			if rel, err := filepath.Rel(target, wd); err == nil && filepath.IsLocal(rel) {
				return errAgentVaultSkillPullTargetHoldsWorkingFolder()
			}
		}
	}
	return nil
}

func pullAgentVaultSkill(httpClient *resty.Client, project agentVaultProject, name, folder string, version int, force bool) (string, error) {
	skill, err := requireAgentVaultSkill(httpClient, project, name)
	if err != nil {
		return "", err
	}

	var files []api.AgentVaultSkillFile
	switch {
	case version == 0 || version == skill.LatestVersion:
		got, err := api.CallGetAgentVaultSkill(httpClient, skill.ID)
		if err != nil {
			return "", agentVaultSkillAPIError(err, project, name)
		}
		files, version = got.Skill.Files, got.Skill.LatestVersion
	case version > skill.LatestVersion:
		return "", errAgentVaultSkillVersionNotFound(name, version, skill.LatestVersion)
	default:
		got, err := api.CallGetAgentVaultSkillVersion(httpClient, skill.ID, version)
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound && apiErr.Name != infisicalRouteMissingName {
			// A member is answered 404 for any version but the latest, even one that exists.
			return "", errAgentVaultSkillVersionAdminOnly(name, skill.LatestVersion, err)
		}
		if err != nil {
			return "", agentVaultSkillAPIError(err, project, name)
		}
		files = got.Version.Files
	}

	if err := replaceAgentVaultSkillFolder(folder, files, force); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: v%d -> %s", util.SanitizeDisplay(skill.Name), version, folder), nil
}

// replaceAgentVaultSkillFolder writes the files next to folder and then swaps them in, so a write that fails
// partway leaves the old folder as it was.
func replaceAgentVaultSkillFolder(folder string, files []api.AgentVaultSkillFile, force bool) error {
	target, err := filepath.Abs(folder)
	if err != nil {
		return fmt.Errorf("unable to write %s: %w", folder, err)
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("unable to create %s: %w", parent, err)
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(target)+".pull-")
	if err != nil {
		return fmt.Errorf("unable to write %s: %w", folder, err)
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("unable to write %s: %w", folder, err)
	}
	if err := agentvault.WriteSkillFiles(staging, files); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("unable to write %s: %w", folder, err)
	}

	if _, err := os.Lstat(target); err == nil {
		if !force {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("%s already exists. Pass --force to replace it", folder)
		}
		aside := staging + "-old"
		if err := os.Rename(target, aside); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("unable to replace %s: %w", folder, err)
		}
		if err := os.Rename(staging, target); err != nil {
			_ = os.Rename(aside, target)
			_ = os.RemoveAll(staging)
			return fmt.Errorf("unable to replace %s: %w", folder, err)
		}
		if err := os.RemoveAll(aside); err != nil {
			return fmt.Errorf("pulled into %s, but unable to remove the old copy at %s: %w", folder, aside, err)
		}
		return nil
	}
	if err := os.Rename(staging, target); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("unable to write %s: %w", folder, err)
	}
	return nil
}

func agentVaultSkillDeleteAction(skill api.AgentVaultSkill, projectID string) destructiveAction {
	description := fmt.Sprintf("skill %s", skill.Name)
	switch n := len(skill.AccessBundles); n {
	case 0:
	case 1:
		description += " and removes it from 1 access bundle"
	default:
		description += fmt.Sprintf(" and removes it from %d access bundles", n)
	}
	return destructiveAction{
		Target:      fmt.Sprintf("skill %q", skill.Name),
		Expected:    skill.Name,
		Label:       "the skill name",
		Description: description,
		Scope:       []scopeFlag{{Name: "project-id", Value: projectID}},
	}
}

// pushAgentVaultSkill publishes a version of the skill with this name in the project, or creates it there. A create that loses a
// race with another push of the same name gets 409, and publishes to the skill the other push made.
func pushAgentVaultSkill(httpClient *resty.Client, projectID, name string, files []api.AgentVaultSkillFile) (string, error) {
	publish := func(skillID string) (string, error) {
		published, err := api.CallUpdateAgentVaultSkill(httpClient, skillID, api.AgentVaultSkillFilesRequest{Files: files})
		if err != nil {
			return "", fmt.Errorf("unable to publish a new version of %q: %w", name, err)
		}
		if published.Unchanged {
			return fmt.Sprintf("%s: unchanged (v%d)", name, published.Version.Version), nil
		}
		return fmt.Sprintf("%s: v%d", name, published.Version.Version), nil
	}
	find := func() (string, error) {
		skill, found, err := findAgentVaultSkill(httpClient, projectID, name)
		if err != nil || !found {
			return "", err
		}
		return skill.ID, nil
	}

	skillID, err := find()
	if err != nil {
		return "", err
	}
	if skillID != "" {
		return publish(skillID)
	}

	created, err := api.CallCreateAgentVaultSkill(httpClient, api.CreateAgentVaultSkillRequest{ProjectID: projectID, Files: files})
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
		if existing, findErr := find(); findErr == nil && existing != "" {
			return publish(existing)
		}
	}
	if err != nil {
		return "", fmt.Errorf("unable to create the skill %q: %w", name, err)
	}
	return fmt.Sprintf("%s: created v%d", created.Skill.Name, created.Version.Version), nil
}

// readAgentVaultSkillFolder reads every regular file under dir. Limits are left to Infisical, which owns them.
func readAgentVaultSkillFolder(dir string) ([]api.AgentVaultSkillFile, string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, "", fmt.Errorf("unable to read the skill folder: %w", err)
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("%s is not a folder; pass the folder that holds SKILL.md", dir)
	}

	// WalkDir does not follow a symlinked root, so a folder reached through a link would read as one file.
	// Links inside the folder are still refused below.
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, "", fmt.Errorf("unable to read the skill folder: %w", err)
	}

	var files []api.AgentVaultSkillFile
	var skillMd []byte
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root && strings.HasPrefix(entry.Name(), ".") {
			// Hidden entries are tooling (.git, .DS_Store), never part of the skill.
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file; a skill holds only files and folders", rel)
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := "0644"
		if fileInfo.Mode().Perm()&0o111 != 0 {
			mode = "0755"
		}
		if rel == "SKILL.md" {
			skillMd = content
		}
		files = append(files, api.AgentVaultSkillFile{Path: rel, Mode: mode, ContentBase64: base64.StdEncoding.EncodeToString(content)})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to read the skill folder: %w", err)
	}
	if skillMd == nil {
		return nil, "", fmt.Errorf("%s has no SKILL.md at its root", dir)
	}
	name, err := agentvault.SkillHeaderName(skillMd)
	if err != nil {
		return nil, "", err
	}
	return files, name, nil
}

func init() {
	agentVaultSkillsPushCmd.Flags().String("project-id", "", "Agent Vault project the skill belongs to (falls back to "+agentVaultProjectIDEnv+", then INFISICAL_PROJECT_ID)")
	agentVaultSkillsPushCmd.Flags().String("client-id", "", "universal auth client id of the machine identity to push as (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	agentVaultSkillsPushCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	for _, cmd := range []*cobra.Command{agentVaultSkillsGetCmd, agentVaultSkillsPullCmd, agentVaultSkillsDeleteCmd} {
		cmd.Flags().String("project-id", "", "Agent Vault project the skill belongs to (falls back to "+agentVaultProjectIDEnv+", then INFISICAL_PROJECT_ID)")
		cmd.Flags().String("client-id", "", "universal auth client id of the machine identity to run as (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
		cmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")
	}
	agentVaultSkillsDeleteCmd.Flags().Lookup("project-id").Usage = "Agent Vault project the skill belongs to (required: a delete never reads it from " + agentVaultProjectIDEnv + " or INFISICAL_PROJECT_ID)"
	addProjectsOutputFlag(agentVaultSkillsGetCmd, "The output to format the skills in")
	addProjectsOutputFlag(agentVaultSkillsDeleteCmd, "The output to format the deleted skill in")
	agentVaultSkillsPullCmd.Flags().Int("version", 0, "the version to pull instead of the latest; only an Admin can pull an earlier one")
	agentVaultSkillsPullCmd.Flags().Bool("force", false, "replace the folder if it already exists, removing every file the skill doesn't have")
	addConfirmFlags(agentVaultSkillsDeleteCmd)

	agentVaultSkillsCmd.AddCommand(agentVaultSkillsPushCmd, agentVaultSkillsGetCmd, agentVaultSkillsPullCmd, agentVaultSkillsDeleteCmd)
	agentVaultCmd.AddCommand(agentVaultSkillsCmd)
}
