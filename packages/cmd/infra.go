/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// ============================================
// Context & helpers
// ============================================

type infraContext struct {
	httpClient *resty.Client
	projectId  string
}

func getInfraProjectContext(cmd *cobra.Command) infraContext {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	projectId, err := cmd.Flags().GetString("projectId")
	if err != nil {
		util.HandleError(err, "Unable to parse projectId flag")
	}

	if projectId == "" {
		workspaceFile, err := util.GetWorkSpaceFromFile()
		if err != nil {
			util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --projectId flag")
		}
		projectId = workspaceFile.WorkspaceId
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Unable to create HTTP client")
	}

	if token != nil && (token.Type == util.SERVICE_TOKEN_IDENTIFIER || token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER) {
		httpClient.SetAuthToken(token.Token)
	} else {
		util.RequireLogin()

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil {
			util.HandleError(err, "Unable to authenticate")
		}

		if loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		httpClient.SetAuthToken(loggedInUserDetails.UserCredentials.JTWToken)
	}

	return infraContext{httpClient: httpClient, projectId: projectId}
}

func scanTfFiles(dirPath string) (map[string]string, error) {
	pattern := filepath.Join(dirPath, "*.tf")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error scanning for .tf files: %w", err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no .tf files found in %s", dirPath)
	}

	files := make(map[string]string)
	for _, match := range matches {
		content, err := os.ReadFile(match)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", match, err)
		}
		files[filepath.Base(match)] = string(content)
	}

	return files, nil
}

func computeChecksum(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "dial tcp") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "network is unreachable") {
		return true
	}

	if _, ok := err.(net.Error); ok {
		return true
	}

	return false
}

// ============================================
// Color helpers
// ============================================

var (
	greenBold   = color.New(color.FgGreen, color.Bold)
	yellowBold  = color.New(color.FgYellow, color.Bold)
	redBold     = color.New(color.FgRed, color.Bold)
	cyanBold    = color.New(color.FgCyan, color.Bold)
	dimWhite    = color.New(color.FgHiBlack)
	boldWhite   = color.New(color.FgWhite, color.Bold)
	plainGreen  = color.New(color.FgGreen)
	plainYellow = color.New(color.FgYellow)
	plainRed    = color.New(color.FgRed)
	plainCyan   = color.New(color.FgCyan)
)

func statusColor(status string) *color.Color {
	switch strings.ToLower(status) {
	case "success":
		return plainGreen
	case "failed":
		return plainRed
	case "running":
		return plainCyan
	case "pending":
		return plainYellow
	case "awaiting_approval":
		return plainYellow
	default:
		return dimWhite
	}
}

// ============================================
// Mock data
// ============================================

func mockInfraFiles() api.GetInfraFilesResponse {
	now := time.Now().Format(time.RFC3339)
	return api.GetInfraFilesResponse{
		Files: []api.InfraFile{
			{
				ID:        "f1a2b3c4-d5e6-7890-abcd-ef1234567890",
				ProjectID: "mock-project-id",
				Name:      "main.tf",
				Content: `resource "null_resource" "hello" {
  triggers = {
    message = var.greeting
  }
}
`,
				CreatedAt: now,
				UpdatedAt: now,
			},
			{
				ID:        "a9b8c7d6-e5f4-3210-fedc-ba0987654321",
				ProjectID: "mock-project-id",
				Name:      "variables.tf",
				Content: `variable "greeting" {
  description = "A greeting message"
  type        = string
  default     = "Hello from Infisical Infra!"
}
`,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}
}

func mockTriggerRun(mode string) api.TriggerInfraRunResponse {
	aiSummary := `Plan Summary
  Resources: 2 to add, 0 to change, 0 to destroy

  + null_resource.hello          (create)
  + random_pet.server_name       (create)

Cost Estimate
  No cloud resources with costs detected.
  Total                            $0.00/mo`

	return api.TriggerInfraRunResponse{
		Output: `Initializing the backend...

Initializing provider plugins...
- Finding latest version of hashicorp/null...
- Installing hashicorp/null v3.2.3...
- Installed hashicorp/null v3.2.3 (signed by HashiCorp)

OpenTofu has been successfully initialized!

null_resource.hello: Creating...
null_resource.hello: Creation complete after 0s [id=123456]
random_pet.server_name: Creating...
random_pet.server_name: Creation complete after 0s [id=brave-fluffy-penguin]

` + mode + ` complete! Resources: 2 added, 0 changed, 0 destroyed.
`,
		Status:    "success",
		RunID:     "run-mock-" + time.Now().Format("20060102150405"),
		AISummary: &aiSummary,
	}
}

func mockInfraRuns() api.GetInfraRunsResponse {
	now := time.Now()
	return api.GetInfraRunsResponse{
		Runs: []api.InfraRun{
			{
				ID:        "run-abc123def456",
				ProjectID: "mock-project-id",
				Type:      "plan",
				Status:    "success",
				CreatedAt: now.Add(-10 * time.Minute).Format(time.RFC3339),
			},
			{
				ID:        "run-789ghi012jkl",
				ProjectID: "mock-project-id",
				Type:      "apply",
				Status:    "success",
				CreatedAt: now.Add(-25 * time.Minute).Format(time.RFC3339),
			},
			{
				ID:        "run-345mno678pqr",
				ProjectID: "mock-project-id",
				Type:      "plan",
				Status:    "failed",
				CreatedAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			},
		},
	}
}

// ============================================
// File sync logic
// ============================================

type fileSyncResult struct {
	newFiles       []string
	modifiedFiles  []string
	unchangedFiles []string
	remoteOnly     []string
}

func (s fileSyncResult) isInSync() bool {
	return len(s.newFiles) == 0 && len(s.modifiedFiles) == 0 && len(s.remoteOnly) == 0
}

func (s fileSyncResult) uploadCount() int {
	return len(s.newFiles) + len(s.modifiedFiles)
}

func computeFileSync(localFiles map[string]string, remoteFiles []api.InfraFile) fileSyncResult {
	result := fileSyncResult{}

	remoteChecksums := make(map[string]string)
	for _, rf := range remoteFiles {
		remoteChecksums[rf.Name] = computeChecksum(rf.Content)
	}

	localNames := make([]string, 0, len(localFiles))
	for name := range localFiles {
		localNames = append(localNames, name)
	}
	sort.Strings(localNames)

	for _, name := range localNames {
		content := localFiles[name]
		localChecksum := computeChecksum(content)

		if remoteChecksum, exists := remoteChecksums[name]; exists {
			if localChecksum == remoteChecksum {
				result.unchangedFiles = append(result.unchangedFiles, name)
			} else {
				result.modifiedFiles = append(result.modifiedFiles, name)
			}
		} else {
			result.newFiles = append(result.newFiles, name)
		}
	}

	for _, rf := range remoteFiles {
		if _, exists := localFiles[rf.Name]; !exists {
			result.remoteOnly = append(result.remoteOnly, rf.Name)
		}
	}
	sort.Strings(result.remoteOnly)

	return result
}

func displaySyncStatus(sync fileSyncResult) {
	if sync.isInSync() {
		plainGreen.Println("  Files are in sync.")
		fmt.Println()
		return
	}

	fmt.Println()
	for _, name := range sync.newFiles {
		greenBold.Printf("    + %s", name)
		dimWhite.Println("  (new)")
	}
	for _, name := range sync.modifiedFiles {
		yellowBold.Printf("    ~ %s", name)
		dimWhite.Println("  (modified)")
	}
	for _, name := range sync.unchangedFiles {
		dimWhite.Printf("    = %s  (unchanged)\n", name)
	}
	for _, name := range sync.remoteOnly {
		plainYellow.Printf("    ! %s", name)
		dimWhite.Println("  (cloud only)")
	}

	fmt.Println()
	fmt.Printf("  %d to upload, %d unchanged", sync.uploadCount(), len(sync.unchangedFiles))
	if len(sync.remoteOnly) > 0 {
		fmt.Printf(", %d cloud only", len(sync.remoteOnly))
	}
	fmt.Println()
	fmt.Println()
}

func uploadFiles(ctx infraContext, localFiles map[string]string, filesToUpload []string, useMock bool) {
	for _, name := range filesToUpload {
		fmt.Printf("  Uploading %s... ", name)

		if !useMock {
			_, err := api.CallUpsertInfraFile(ctx.httpClient, api.UpsertInfraFileRequest{
				ProjectID: ctx.projectId,
				Name:      name,
				Content:   localFiles[name],
			})
			if err != nil {
				plainRed.Println("failed")
				util.HandleError(err, fmt.Sprintf("Failed to upload %s", name))
			}
		} else {
			time.Sleep(200 * time.Millisecond)
		}

		plainGreen.Println("done")
	}
}

func fetchRemoteFiles(ctx infraContext) (api.GetInfraFilesResponse, bool) {
	resp, err := api.CallGetInfraFiles(ctx.httpClient, api.GetInfraFilesRequest{ProjectID: ctx.projectId})
	if err != nil {
		if isConnectionError(err) {
			plainYellow.Println("  Using mock data (backend unavailable)")
			return mockInfraFiles(), true
		}
		util.HandleError(err, "Unable to fetch remote files")
	}
	return resp, false
}

func runSyncAndUpload(ctx infraContext, dirPath string) (fileSyncResult, bool) {
	localFiles, err := scanTfFiles(dirPath)
	if err != nil {
		util.HandleError(err)
	}

	boldWhite.Printf("  Scanning %d .tf file(s)...\n", len(localFiles))

	remoteFilesResp, useMock := fetchRemoteFiles(ctx)

	sync := computeFileSync(localFiles, remoteFilesResp.Files)
	displaySyncStatus(sync)

	filesToUpload := append(sync.newFiles, sync.modifiedFiles...)
	if len(filesToUpload) == 0 {
		return sync, useMock
	}

	prompt := promptui.Select{
		Label: "Upload changed files?",
		Items: []string{"Yes", "No"},
	}
	_, result, promptErr := prompt.Run()
	if promptErr != nil || result == "No" {
		dimWhite.Println("  Cancelled.")
		os.Exit(0)
	}
	fmt.Println()

	uploadFiles(ctx, localFiles, filesToUpload, useMock)
	fmt.Println()
	plainGreen.Printf("  %d file(s) uploaded.\n", len(filesToUpload))

	return sync, useMock
}

// ============================================
// Run execution (synchronous — backend blocks until done)
// ============================================

// triggerRun calls POST /run which blocks until the run completes.
// Returns the full result (output, status, runId, aiSummary).
func triggerRun(ctx infraContext, mode string, useMock bool, approved ...bool) (api.TriggerInfraRunResponse, bool) {
	if useMock {
		time.Sleep(3 * time.Second)
		return mockTriggerRun(mode), true
	}

	req := api.TriggerInfraRunRequest{
		ProjectID: ctx.projectId,
		Mode:      mode,
	}
	if len(approved) > 0 && approved[0] {
		t := true
		req.Approved = &t
	}

	resp, err := api.CallTriggerInfraRun(ctx.httpClient, req)
	if err != nil {
		if isConnectionError(err) {
			plainYellow.Println("  Using mock data (backend unavailable)")
			time.Sleep(3 * time.Second)
			return mockTriggerRun(mode), true
		}
		util.HandleError(err, fmt.Sprintf("Unable to trigger %s", mode))
	}
	return resp, useMock
}

func displayRunOutput(output string) {
	if output == "" {
		return
	}
	fmt.Println(output)
}

type aiInsight struct {
	Summary string `json:"summary"`
	Costs   *struct {
		Estimated []struct {
			Resource    string `json:"resource"`
			MonthlyCost string `json:"monthlyCost"`
			Source      string `json:"source"`
		} `json:"estimated"`
		AIEstimated []struct {
			Resource    string `json:"resource"`
			MonthlyCost string `json:"monthlyCost"`
			Source      string `json:"source"`
		} `json:"aiEstimated"`
		TotalMonthly string `json:"totalMonthly"`
		DeltaMonthly string `json:"deltaMonthly"`
	} `json:"costs"`
	Security *struct {
		Issues []struct {
			Severity    string `json:"severity"`
			Resource    string `json:"resource"`
			Description string `json:"description"`
		} `json:"issues"`
		ShouldApprove bool `json:"shouldApprove"`
	} `json:"security"`
}

func displayAISummary(summary string) {
	var insight aiInsight
	if err := json.Unmarshal([]byte(summary), &insight); err != nil {
		// Not JSON — display as plain text
		for _, line := range strings.Split(summary, "\n") {
			fmt.Println("  " + line)
		}
		return
	}

	// Parse and display the summary field (markdown-ish)
	if insight.Summary != "" {
		displayParsedSummary(insight.Summary)
	}

	// Security issues
	if insight.Security != nil && len(insight.Security.Issues) > 0 {
		fmt.Println()
		boldWhite.Println("  Security Findings")
		fmt.Println()
		for _, issue := range insight.Security.Issues {
			sev := strings.ToUpper(issue.Severity)
			var sevColor *color.Color
			switch sev {
			case "HIGH", "CRITICAL":
				sevColor = redBold
			case "MEDIUM":
				sevColor = yellowBold
			default:
				sevColor = plainCyan
			}
			sevColor.Printf("    [%s] ", sev)
			fmt.Printf("%s\n", issue.Resource)
			dimWhite.Printf("           %s\n", issue.Description)
		}
	}

	// Cost estimate
	if insight.Costs != nil {
		allCosts := append(insight.Costs.Estimated, insight.Costs.AIEstimated...)
		if len(allCosts) > 0 || insight.Costs.TotalMonthly != "" {
			fmt.Println()
			boldWhite.Println("  Cost Estimate")
			fmt.Println()

			if len(allCosts) > 0 {
				// Find longest resource name for alignment
				maxLen := 0
				for _, c := range allCosts {
					if len(c.Resource) > maxLen {
						maxLen = len(c.Resource)
					}
				}

				for _, c := range allCosts {
					padding := strings.Repeat(" ", maxLen-len(c.Resource)+2)
					dimWhite.Printf("    %s%s", c.Resource, padding)
					boldWhite.Printf("%s", c.MonthlyCost)
					if c.Source != "" && c.Source != "estimate" {
						dimWhite.Printf("  (%s)", c.Source)
					}
					fmt.Println()
				}
				fmt.Println()
			}

			if insight.Costs.TotalMonthly != "" {
				dimWhite.Print("    Total                          ")
				boldWhite.Printf("%s/mo", insight.Costs.TotalMonthly)
				if insight.Costs.DeltaMonthly != "" {
					dimWhite.Printf("  (%s)", insight.Costs.DeltaMonthly)
				}
				fmt.Println()
			}
		}
	}
}

func extractResourceAction(entry string) (string, string) {
	// "aws_eip.nat (create)" -> "aws_eip.nat", "create"
	if idx := strings.LastIndex(entry, "("); idx > 0 {
		action := strings.TrimSuffix(strings.TrimSpace(entry[idx+1:]), ")")
		name := strings.TrimSpace(entry[:idx])
		return name, action
	}
	return entry, ""
}

func displayParsedSummary(summary string) {
	// Strip markdown bold markers and backticks
	text := strings.ReplaceAll(summary, "**", "")
	text = strings.ReplaceAll(text, "`", "")

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "- ") {
			entry := strings.TrimPrefix(trimmed, "- ")
			name, action := extractResourceAction(entry)

			switch action {
			case "create":
				plainGreen.Printf("    + %-45s (create)\n", name)
			case "delete", "destroy":
				plainRed.Printf("    - %-45s (destroy)\n", name)
			case "update", "update in-place":
				plainYellow.Printf("    ~ %-45s (update)\n", name)
			case "replace", "must replace":
				yellowBold.Printf("    ! %-45s (replace)\n", name)
			default:
				fmt.Printf("    %s\n", entry)
			}
		} else if strings.HasPrefix(trimmed, "Plan:") || strings.HasPrefix(trimmed, "Estimated cost:") {
			boldWhite.Println("  " + trimmed)
		} else {
			fmt.Println("  " + trimmed)
		}
	}
}

// ============================================
// Commands
// ============================================

var infraCmd = &cobra.Command{
	Use:   "infra",
	Short: "Manage infrastructure-as-code with Infisical Infra",
	Long: `Push, pull, plan, and apply OpenTofu/Terraform configurations through the Infisical backend.

Infisical Infra lets you manage your infrastructure files, trigger plan/apply runs,
and get AI-powered insights on your infrastructure changes.`,
	DisableFlagsInUseLine: true,
	Example: `  infisical infra push
  infisical infra plan
  infisical infra apply
  infisical infra status`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// --- push ---

var infraPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push local .tf files to Infisical",
	Long:  "Scans the current directory (or specified path) for .tf files and uploads them to your Infisical project.",
	Example: `  infisical infra push
  infisical infra push --path ./terraform`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := getInfraProjectContext(cmd)
		dirPath, _ := cmd.Flags().GetString("path")

		fmt.Println()
		boldWhite.Println("Push")
		fmt.Println()

		runSyncAndUpload(ctx, dirPath)
		fmt.Println()

		Telemetry.CaptureEvent("cli-command:infra push",
			posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

// --- pull ---

var infraPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Download .tf files from Infisical to local directory",
	Long:  "Fetches all .tf files stored in your Infisical project and writes them to the local directory.",
	Example: `  infisical infra pull
  infisical infra pull --path ./terraform`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := getInfraProjectContext(cmd)
		dirPath, _ := cmd.Flags().GetString("path")

		fmt.Println()
		boldWhite.Println("Pull")
		fmt.Println()

		filesResp, _ := fetchRemoteFiles(ctx)

		// Build set of remote file names
		remoteByName := make(map[string]string, len(filesResp.Files))
		for _, f := range filesResp.Files {
			remoteByName[f.Name] = f.Content
		}

		// Scan local .tf files to detect files that should be deleted
		var toDelete []string
		localTfFiles, _ := filepath.Glob(filepath.Join(dirPath, "*.tf"))
		for _, localPath := range localTfFiles {
			name := filepath.Base(localPath)
			if _, existsRemote := remoteByName[name]; !existsRemote {
				toDelete = append(toDelete, name)
			}
		}
		sort.Strings(toDelete)

		if len(filesResp.Files) == 0 && len(toDelete) == 0 {
			dimWhite.Println("  No files found in this project and no local .tf files to clean up.")
			fmt.Println()
			return
		}

		// Categorize remote files vs local
		var toCreate []string
		var toOverwrite []string
		var unchanged []string

		for _, file := range filesResp.Files {
			localPath := filepath.Join(dirPath, file.Name)
			existing, err := os.ReadFile(localPath)
			if err != nil {
				toCreate = append(toCreate, file.Name)
			} else if computeChecksum(string(existing)) != computeChecksum(file.Content) {
				toOverwrite = append(toOverwrite, file.Name)
			} else {
				unchanged = append(unchanged, file.Name)
			}
		}

		// Display summary
		fmt.Println()
		for _, name := range toCreate {
			greenBold.Printf("    + %s", name)
			dimWhite.Println("  (create)")
		}
		for _, name := range toOverwrite {
			yellowBold.Printf("    ~ %s", name)
			dimWhite.Println("  (overwrite)")
		}
		for _, name := range toDelete {
			redBold.Printf("    - %s", name)
			dimWhite.Println("  (delete)")
		}
		for _, name := range unchanged {
			dimWhite.Printf("    = %s  (unchanged)\n", name)
		}
		fmt.Println()

		changeCount := len(toCreate) + len(toOverwrite) + len(toDelete)
		if changeCount == 0 {
			plainGreen.Println("  All files are already up to date.")
			fmt.Println()
			return
		}

		// Print counts
		parts := []string{}
		if len(toCreate) > 0 {
			parts = append(parts, fmt.Sprintf("%d to create", len(toCreate)))
		}
		if len(toOverwrite) > 0 {
			parts = append(parts, fmt.Sprintf("%d to overwrite", len(toOverwrite)))
		}
		if len(toDelete) > 0 {
			parts = append(parts, fmt.Sprintf("%d to delete", len(toDelete)))
		}
		if len(unchanged) > 0 {
			parts = append(parts, fmt.Sprintf("%d unchanged", len(unchanged)))
		}
		fmt.Printf("  %s\n", strings.Join(parts, ", "))
		fmt.Println()

		prompt := promptui.Select{
			Label: fmt.Sprintf("Apply %d change(s) to %s?", changeCount, dirPath),
			Items: []string{"Yes", "No"},
		}
		_, result, promptErr := prompt.Run()
		if promptErr != nil || result == "No" {
			dimWhite.Println("  Cancelled.")
			os.Exit(0)
		}
		fmt.Println()

		if err := os.MkdirAll(dirPath, 0755); err != nil {
			util.HandleError(err, fmt.Sprintf("Unable to create directory %s", dirPath))
		}

		// Write new + overwritten files
		filesToWrite := append(toCreate, toOverwrite...)
		for _, name := range filesToWrite {
			fmt.Printf("  Writing %s... ", name)
			outputPath := filepath.Join(dirPath, name)
			if err := os.WriteFile(outputPath, []byte(remoteByName[name]), 0644); err != nil {
				plainRed.Println("failed")
				util.HandleError(err, fmt.Sprintf("Unable to write %s", outputPath))
			}
			plainGreen.Println("done")
		}

		// Delete local-only files
		for _, name := range toDelete {
			fmt.Printf("  Deleting %s... ", name)
			deletePath := filepath.Join(dirPath, name)
			if err := os.Remove(deletePath); err != nil {
				plainRed.Println("failed")
				util.HandleError(err, fmt.Sprintf("Unable to delete %s", deletePath))
			}
			plainRed.Println("done")
		}

		fmt.Println()
		summary := []string{}
		if len(filesToWrite) > 0 {
			summary = append(summary, fmt.Sprintf("%d written", len(filesToWrite)))
		}
		if len(toDelete) > 0 {
			summary = append(summary, fmt.Sprintf("%d deleted", len(toDelete)))
		}
		plainGreen.Printf("  %s in %s\n", strings.Join(summary, ", "), dirPath)
		fmt.Println()

		Telemetry.CaptureEvent("cli-command:infra pull",
			posthog.NewProperties().
				Set("fileCount", len(filesResp.Files)).
				Set("version", util.CLI_VERSION))
	},
}

// --- plan ---

var infraPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Push files and trigger an infrastructure plan",
	Long: `Pushes local .tf files to Infisical and triggers a plan run.
The backend executes the plan and returns the full output and AI-powered summary.`,
	Example: `  infisical infra plan
  infisical infra plan --push=false
  infisical infra plan --path ./terraform`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := getInfraProjectContext(cmd)
		dirPath, _ := cmd.Flags().GetString("path")
		shouldPush, _ := cmd.Flags().GetBool("push")

		fmt.Println()
		boldWhite.Println("Plan")
		fmt.Println()

		useMock := false

		if shouldPush {
			_, useMock = runSyncAndUpload(ctx, dirPath)
		} else {
			localFiles, err := scanTfFiles(dirPath)
			if err == nil {
				var remoteResp api.GetInfraFilesResponse
				remoteResp, useMock = fetchRemoteFiles(ctx)
				sync := computeFileSync(localFiles, remoteResp.Files)
				if !sync.isInSync() {
					plainYellow.Println("  Warning: local files differ from cloud.")
					displaySyncStatus(sync)
				} else {
					plainGreen.Println("  Files are in sync.")
					fmt.Println()
				}
			}
		}

		boldWhite.Println("  Running plan...")
		dimWhite.Println("  (waiting for backend to execute...)")
		fmt.Println()

		result, _ := triggerRun(ctx, "plan", useMock)

		dimWhite.Printf("  Run ID: %s\n\n", result.RunID)
		displayRunOutput(result.Output)

		if result.Status == "success" {
			greenBold.Println("  Plan succeeded.")
		} else {
			redBold.Println("  Plan failed.")
		}

		if result.AISummary != nil && *result.AISummary != "" {
			fmt.Println()
			cyanBold.Println("  ---- AI Analysis ----")
			fmt.Println()
			displayAISummary(*result.AISummary)
			fmt.Println()
			dimWhite.Println("  ----------------------")
		}

		fmt.Println()

		Telemetry.CaptureEvent("cli-command:infra plan",
			posthog.NewProperties().
				Set("status", result.Status).
				Set("version", util.CLI_VERSION))
	},
}

// --- apply ---

var infraApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Push files and apply infrastructure changes",
	Long: `Pushes local .tf files to Infisical, runs a plan first to preview changes,
asks for your confirmation, then applies changes to your cloud provider.

If the backend detects security issues, the apply may require additional approval.`,
	Example: `  infisical infra apply
  infisical infra apply --push=false
  infisical infra apply --path ./terraform`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := getInfraProjectContext(cmd)
		dirPath, _ := cmd.Flags().GetString("path")
		shouldPush, _ := cmd.Flags().GetBool("push")

		fmt.Println()
		boldWhite.Println("Apply")
		fmt.Println()

		useMock := false

		// Step 1: Sync files
		if shouldPush {
			_, useMock = runSyncAndUpload(ctx, dirPath)
		} else {
			localFiles, err := scanTfFiles(dirPath)
			if err == nil {
				var remoteResp api.GetInfraFilesResponse
				remoteResp, useMock = fetchRemoteFiles(ctx)
				sync := computeFileSync(localFiles, remoteResp.Files)
				if !sync.isInSync() {
					plainYellow.Println("  Warning: local files differ from cloud.")
					displaySyncStatus(sync)
				} else {
					plainGreen.Println("  Files are in sync.")
					fmt.Println()
				}
			}
		}

		// Step 2: Run plan first so the user can review before applying
		boldWhite.Println("  Running plan...")
		dimWhite.Println("  (waiting for backend to execute...)")
		fmt.Println()

		planResult, useMock := triggerRun(ctx, "plan", useMock)

		dimWhite.Printf("  Run ID: %s\n\n", planResult.RunID)
		displayRunOutput(planResult.Output)

		if planResult.Status == "failed" {
			redBold.Println("  Plan failed. Cannot proceed with apply.")
			fmt.Println()
			os.Exit(1)
		}

		greenBold.Println("  Plan succeeded.")

		// Show AI analysis from plan
		if planResult.AISummary != nil && *planResult.AISummary != "" {
			fmt.Println()
			cyanBold.Println("  ---- AI Analysis ----")
			fmt.Println()
			displayAISummary(*planResult.AISummary)
			fmt.Println()
			dimWhite.Println("  ----------------------")
		}

		// Step 3: User must confirm before apply
		fmt.Println()
		redBold.Println("  This will apply the changes above to your cloud provider.")
		fmt.Println()

		prompt := promptui.Select{
			Label: "Do you want to apply these changes?",
			Items: []string{"Yes, apply", "No, cancel"},
		}
		_, choice, promptErr := prompt.Run()
		if promptErr != nil || strings.HasPrefix(choice, "No") {
			fmt.Println()
			dimWhite.Println("  Apply cancelled.")
			fmt.Println()
			os.Exit(0)
		}

		// Step 4: Trigger apply (backend runs plan + apply in one call)
		fmt.Println()
		boldWhite.Println("  Applying...")
		dimWhite.Println("  (waiting for backend to execute...)")
		fmt.Println()

		applyResult, useMock := triggerRun(ctx, "apply", useMock)

		dimWhite.Printf("  Run ID: %s\n\n", applyResult.RunID)
		displayRunOutput(applyResult.Output)

		// Step 5: Handle awaiting_approval (security gate from AI)
		if applyResult.Status == "awaiting_approval" {
			fmt.Println()
			yellowBold.Println("  Security issues detected — apply requires approval.")

			if applyResult.AISummary != nil && *applyResult.AISummary != "" {
				fmt.Println()
				cyanBold.Println("  ---- AI Analysis ----")
				fmt.Println()
				displayAISummary(*applyResult.AISummary)
				fmt.Println()
				dimWhite.Println("  ----------------------")
			}

			fmt.Println()
			approvePrompt := promptui.Select{
				Label: "Approve apply despite security issues?",
				Items: []string{"Yes, approve and apply", "No, deny"},
			}
			_, approveChoice, approveErr := approvePrompt.Run()
			if approveErr != nil || strings.HasPrefix(approveChoice, "No") {
				if !useMock {
					api.CallDenyInfraRun(ctx.httpClient, api.DenyInfraRunRequest{
						ProjectID: ctx.projectId,
						RunID:     applyResult.RunID,
					})
				}
				fmt.Println()
				dimWhite.Println("  Apply denied.")
				fmt.Println()
				os.Exit(0)
			}

			// Approve the run
			if !useMock {
				_, err := api.CallApproveInfraRun(ctx.httpClient, api.ApproveInfraRunRequest{
					ProjectID: ctx.projectId,
					RunID:     applyResult.RunID,
				})
				if err != nil && !isConnectionError(err) {
					util.HandleError(err, "Unable to approve run")
				}
			}

			// Re-trigger apply after approval
			fmt.Println()
			boldWhite.Println("  Applying after approval...")
			dimWhite.Println("  (waiting for backend to execute...)")
			fmt.Println()

			applyResult, _ = triggerRun(ctx, "apply", useMock)
			dimWhite.Printf("  Run ID: %s\n\n", applyResult.RunID)
			displayRunOutput(applyResult.Output)
		}

		if applyResult.Status == "success" {
			greenBold.Println("  Apply complete!")
		} else if applyResult.Status != "awaiting_approval" {
			redBold.Println("  Apply failed.")
		}

		if applyResult.AISummary != nil && *applyResult.AISummary != "" && applyResult.Status != "awaiting_approval" {
			fmt.Println()
			cyanBold.Println("  ---- AI Analysis ----")
			fmt.Println()
			displayAISummary(*applyResult.AISummary)
			fmt.Println()
			dimWhite.Println("  ----------------------")
		}

		fmt.Println()

		Telemetry.CaptureEvent("cli-command:infra apply",
			posthog.NewProperties().
				Set("status", applyResult.Status).
				Set("version", util.CLI_VERSION))
	},
}

// --- destroy ---

var infraDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy all infrastructure managed by this project",
	Long: `Runs a destroy plan to preview which resources will be removed,
then asks for your confirmation before executing the destruction.

All resources managed by the project's OpenTofu state will be destroyed.`,
	Example: `  infisical infra destroy`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := getInfraProjectContext(cmd)

		fmt.Println()
		boldWhite.Println("Destroy")
		fmt.Println()

		// Step 1: Trigger destroy — backend runs tofu plan -destroy, always returns awaiting_approval
		boldWhite.Println("  Running destroy plan...")
		dimWhite.Println("  (waiting for backend to execute...)")
		fmt.Println()

		result, useMock := triggerRun(ctx, "destroy", false)

		dimWhite.Printf("  Run ID: %s\n\n", result.RunID)
		displayRunOutput(result.Output)

		if result.Status == "failed" {
			redBold.Println("  Destroy plan failed.")
			fmt.Println()
			os.Exit(1)
		}

		// Show AI analysis
		if result.AISummary != nil && *result.AISummary != "" {
			fmt.Println()
			cyanBold.Println("  ---- AI Analysis ----")
			fmt.Println()
			displayAISummary(*result.AISummary)
			fmt.Println()
			dimWhite.Println("  ----------------------")
		}

		// Step 2: Destroy always requires approval
		if result.Status == "awaiting_approval" {
			fmt.Println()
			redBold.Println("  This will DESTROY all resources shown above.")
			fmt.Println()

			prompt := promptui.Select{
				Label: "Do you want to destroy these resources?",
				Items: []string{"Yes, destroy", "No, cancel"},
			}
			_, choice, promptErr := prompt.Run()
			if promptErr != nil || strings.HasPrefix(choice, "No") {
				if !useMock {
					api.CallDenyInfraRun(ctx.httpClient, api.DenyInfraRunRequest{
						ProjectID: ctx.projectId,
						RunID:     result.RunID,
					})
				}
				fmt.Println()
				dimWhite.Println("  Destroy cancelled.")
				fmt.Println()
				os.Exit(0)
			}

			// Approve the run
			if !useMock {
				_, err := api.CallApproveInfraRun(ctx.httpClient, api.ApproveInfraRunRequest{
					ProjectID: ctx.projectId,
					RunID:     result.RunID,
				})
				if err != nil && !isConnectionError(err) {
					util.HandleError(err, "Unable to approve run")
				}
			}

			// Re-trigger destroy with approved=true
			fmt.Println()
			boldWhite.Println("  Destroying resources...")
			dimWhite.Println("  (waiting for backend to execute...)")
			fmt.Println()

			result, _ = triggerRun(ctx, "destroy", useMock, true)
			dimWhite.Printf("  Run ID: %s\n\n", result.RunID)
			displayRunOutput(result.Output)
		}

		if result.Status == "success" {
			greenBold.Println("  Destroy complete! All resources have been removed.")
		} else if result.Status == "failed" {
			redBold.Println("  Destroy failed.")
		}

		if result.AISummary != nil && *result.AISummary != "" && result.Status != "awaiting_approval" {
			fmt.Println()
			cyanBold.Println("  ---- AI Analysis ----")
			fmt.Println()
			displayAISummary(*result.AISummary)
			fmt.Println()
			dimWhite.Println("  ----------------------")
		}

		fmt.Println()

		Telemetry.CaptureEvent("cli-command:infra destroy",
			posthog.NewProperties().
				Set("status", result.Status).
				Set("version", util.CLI_VERSION))
	},
}

// --- status ---

var infraStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show project infrastructure files and recent runs",
	Long:  "Displays the .tf files stored in your Infisical project and the history of recent plan/apply runs.",
	Example: `  infisical infra status`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := getInfraProjectContext(cmd)

		useMock := false

		filesResp, err := api.CallGetInfraFiles(ctx.httpClient, api.GetInfraFilesRequest{ProjectID: ctx.projectId})
		if err != nil {
			if isConnectionError(err) {
				plainYellow.Println("Using mock data (backend unavailable)")
				filesResp = mockInfraFiles()
				useMock = true
			} else {
				util.HandleError(err, "Unable to fetch files")
			}
		}

		var runsResp api.GetInfraRunsResponse
		if !useMock {
			runsResp, err = api.CallGetInfraRuns(ctx.httpClient, api.GetInfraRunsRequest{ProjectID: ctx.projectId})
			if err != nil {
				if isConnectionError(err) {
					plainYellow.Println("Using mock data (backend unavailable)")
					runsResp = mockInfraRuns()
				} else {
					util.HandleError(err, "Unable to fetch runs")
				}
			}
		} else {
			runsResp = mockInfraRuns()
		}

		fmt.Println()
		boldWhite.Println("Project Files")
		fmt.Println()

		if len(filesResp.Files) == 0 {
			dimWhite.Println("  No files found. Use 'infisical infra push' to upload .tf files.")
		} else {
			fileHeaders := []string{"FILE NAME", "LAST UPDATED"}
			fileRows := make([][]string, 0, len(filesResp.Files))
			for _, f := range filesResp.Files {
				updated := f.UpdatedAt
				if t, parseErr := time.Parse(time.RFC3339, f.UpdatedAt); parseErr == nil {
					updated = t.Local().Format("2006-01-02 15:04:05")
				}
				fileRows = append(fileRows, []string{f.Name, updated})
			}
			visualize.GenericTable(fileHeaders, fileRows)
		}

		fmt.Println()
		boldWhite.Println("Recent Runs")
		fmt.Println()

		if len(runsResp.Runs) == 0 {
			dimWhite.Println("  No runs found. Use 'infisical infra plan' to trigger a plan.")
		} else {
			runHeaders := []string{"RUN ID", "TYPE", "STATUS", "CREATED"}
			runRows := make([][]string, 0, len(runsResp.Runs))
			for _, r := range runsResp.Runs {
				created := r.CreatedAt
				if t, parseErr := time.Parse(time.RFC3339, r.CreatedAt); parseErr == nil {
					created = t.Local().Format("2006-01-02 15:04:05")
				}

				displayId := r.ID
				if len(displayId) > 16 {
					displayId = displayId[:16] + "..."
				}

				statusStr := statusColor(r.Status).Sprint(r.Status)
				runRows = append(runRows, []string{displayId, r.Type, statusStr, created})
			}
			visualize.GenericTable(runHeaders, runRows)
		}

		fmt.Println()

		Telemetry.CaptureEvent("cli-command:infra status",
			posthog.NewProperties().
				Set("fileCount", len(filesResp.Files)).
				Set("runCount", len(runsResp.Runs)).
				Set("version", util.CLI_VERSION))
	},
}

// ============================================
// Registration
// ============================================

func init() {
	infraCmd.PersistentFlags().String("token", "", "Authenticate with Infisical using a service token or machine identity access token")
	infraCmd.PersistentFlags().String("projectId", "", "The Infisical project ID to target")

	// Push
	infraPushCmd.Flags().String("path", ".", "Path to directory containing .tf files")
	infraCmd.AddCommand(infraPushCmd)

	// Pull
	infraPullCmd.Flags().String("path", ".", "Path to write downloaded .tf files")
	infraCmd.AddCommand(infraPullCmd)

	// Plan
	infraPlanCmd.Flags().String("path", ".", "Path to directory containing .tf files")
	infraPlanCmd.Flags().Bool("push", true, "Push local files before planning")
	infraCmd.AddCommand(infraPlanCmd)

	// Apply
	infraApplyCmd.Flags().String("path", ".", "Path to directory containing .tf files")
	infraApplyCmd.Flags().Bool("push", true, "Push local files before applying")
	infraCmd.AddCommand(infraApplyCmd)

	// Destroy
	infraCmd.AddCommand(infraDestroyCmd)

	// Status
	infraCmd.AddCommand(infraStatusCmd)

	RootCmd.AddCommand(infraCmd)
}
