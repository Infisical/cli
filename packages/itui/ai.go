package itui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/genai"
)

// AIClient wraps the Gemini API for NL -> CLI translation
type AIClient struct {
	client *genai.Client
	model  string
}

// NewAIClient creates a new AI client with the given API key
func NewAIClient(apiKey string) *AIClient {
	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return &AIClient{model: "gemini-2.5-flash"}
	}

	return &AIClient{
		client: client,
		model:  "gemini-2.5-flash",
	}
}

// Translate converts a natural language prompt into an Infisical CLI command.
// secretKeys contains key names only (never values) to provide context to the AI.
func (a *AIClient) Translate(userInput string, ctx SessionContext, secretKeys []string) (AIResponse, error) {
	if a.client == nil {
		return AIResponse{}, fmt.Errorf("AI client not initialized. Set GEMINI_API_KEY environment variable")
	}

	systemPrompt := buildSystemPrompt(ctx, secretKeys)

	result, err := a.client.Models.GenerateContent(
		context.Background(),
		a.model,
		genai.Text(userInput),
		&genai.GenerateContentConfig{
			SystemInstruction: &genai.Content{
				Parts: []*genai.Part{genai.NewPartFromText(systemPrompt)},
			},
			Temperature:     genai.Ptr(float32(0.1)),
			MaxOutputTokens: 1024,
		},
	)
	if err != nil {
		return AIResponse{}, fmt.Errorf("Gemini API error: %w", err)
	}

	if result == nil || len(result.Candidates) == 0 || result.Candidates[0].Content == nil {
		return AIResponse{}, fmt.Errorf("empty response from Gemini")
	}

	// Extract text from response
	var responseText string
	for _, part := range result.Candidates[0].Content.Parts {
		if part.Text != "" {
			responseText += part.Text
		}
	}

	return parseAIResponse(responseText)
}

// parseAIResponse extracts the AIResponse from the model's text output
func parseAIResponse(text string) (AIResponse, error) {
	text = strings.TrimSpace(text)

	// Strip markdown code fences if present
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	var resp AIResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		// Try to find JSON in the response
		start := strings.Index(text, "{")
		end := strings.LastIndex(text, "}")
		if start >= 0 && end > start {
			jsonStr := text[start : end+1]
			if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
				return AIResponse{
					Command:     "",
					Explanation: text,
					ActionType:  "read",
				}, nil
			}
			return resp, nil
		}
		// Return as explanation if not JSON
		return AIResponse{
			Command:     "",
			Explanation: text,
			ActionType:  "read",
		}, nil
	}

	return resp, nil
}

func buildSystemPrompt(ctx SessionContext, secretKeys []string) string {
	keyList := "none loaded"
	if len(secretKeys) > 0 {
		keyList = strings.Join(secretKeys, ", ")
	}

	return fmt.Sprintf(`You are ITUI, an AI assistant embedded in the Infisical Terminal UI. Your sole job is to translate natural language requests into exact Infisical CLI commands.

## Current Session Context
- Logged-in User: %s
- Project ID: %s
- Project Name: %s
- Current Environment: %s
- Current Path: %s
- Available secret keys: %s

## CRITICAL: Value Placeholder Rules
- User prompts may contain [VALUE_N] placeholders (e.g., [VALUE_1], [VALUE_2])
- These placeholders represent real secret values that have been redacted for security
- You MUST preserve these placeholders exactly as-is in your generated commands
- Example: if the user says "set DATABASE_URL to [VALUE_1]", generate: infisical secrets set DATABASE_URL=[VALUE_1] --env=ENV
- NEVER attempt to guess, decode, or replace placeholder values
- NEVER ask the user to provide the actual value — it is already cached locally

## Response Format
You MUST respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{
  "command": "infisical ...",
  "explanation": "One-sentence explanation of what this command does",
  "action_type": "read|write|destructive",
  "requires_confirmation": true|false
}

## Rules
- action_type "read" for commands that only fetch data (secrets get, export, user, etc.)
- action_type "write" for commands that create or update data (secrets set)
- action_type "destructive" for commands that delete data (secrets delete)
- requires_confirmation MUST be true for "write" and "destructive" action_types
- requires_confirmation MUST be true when targeting production environments
- Always include --env=%s unless the user explicitly specifies a different environment
- Always include --path=%s if path is not "/"
- For listing secrets, prefer: infisical export --env=ENV --format=json
- For getting specific secrets: infisical secrets get SECRET_NAME --env=ENV --plain
- For setting secrets: infisical secrets set KEY=VALUE --env=ENV
- For deleting secrets: infisical secrets delete KEY --env=ENV --type=shared
- Never fabricate secrets or values
- If the request is ambiguous, set command to "" and use explanation to ask a clarifying question
- Never generate commands that bypass authentication
- Only generate commands for allowed subcommands: secrets, export, run, scan, user, login

## Infisical CLI Reference

### Authentication
- infisical login                       # Interactive login
- infisical user                        # Show current user info

### Secrets (CRUD)
- infisical secrets --env=ENV --path=PATH                     # List all secrets
- infisical secrets get NAME --env=ENV --plain                # Get specific secret
- infisical secrets set KEY=VALUE --env=ENV                   # Create/update secret
- infisical secrets delete NAME --env=ENV --type=shared       # Delete secret

### Export
- infisical export --env=ENV --format=json|dotenv|yaml|csv    # Export in various formats

### Folders
- infisical secrets folders get --env=ENV --path=PATH         # List folders

### Other
- infisical run --env=ENV -- <command>                        # Run with injected secrets
- infisical scan [path]                                       # Scan for leaked secrets

### Common Flags
- --env=ENV          Environment slug (dev, staging, prod, etc.)
- --path=PATH        Secret folder path (default: /)
- --format=FMT       Output format for export (dotenv, json, yaml, csv)
- --plain            Output values without formatting
- --recursive        Fetch from all sub-folders
- --type=TYPE        Secret type: shared or personal (default: shared)`,
		ctx.UserEmail, ctx.ProjectID, ctx.ProjectName,
		ctx.Environment, ctx.Path, keyList,
		ctx.Environment, ctx.Path)
}
