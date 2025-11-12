package util

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
)

func HandleError(err error, messages ...string) {
	PrintErrorAndExit(1, err, messages...)
}

func IsTestRun() bool {
	return flag.Lookup("test.v") != nil
}

func PrintErrorAndExit(exitCode int, err error, messages ...string) {
	// Check if it's an API error for special formatting
	if apiErr, ok := err.(*api.APIError); ok {
		if len(messages) > 0 {
			apiErr.ExtraMessages = messages
		}

		printPrettyAPIError(*apiErr)
	} else {
		printError(err)

		// Print additional messages for both API and non-API errors
		if len(messages) > 0 {
			for _, message := range messages {
				fmt.Fprintln(os.Stderr, message)
			}
		}

	}

	if IsTestRun() {
		// Panic to allow for recovery and assertion in tests
		panic(messages[0])
	}
	os.Exit(exitCode)
}

func PrintWarning(message string) {
	color.New(color.FgYellow).Fprintf(os.Stderr, "Warning: %v \n", message)
}

func PrintSuccessMessage(message string) {
	color.New(color.FgGreen).Println(message)
}

func PrintErrorMessageAndExit(messages ...string) {
	if len(messages) > 0 {
		for _, message := range messages {
			fmt.Fprintln(os.Stderr, message)
		}
	}

	if IsTestRun() {
		// Panic to allow for recovery and assertion in tests
		panic(messages[0])
	}
	os.Exit(1)
}

func printError(e error) {
	color.New(color.FgRed).Fprintf(os.Stderr, "error: %v\n", e)
}

func printPrettyAPIError(apiErr api.APIError) {
	// Using ANSI color codes
	red := lipgloss.Color("196")    // Bright red
	yellow := lipgloss.Color("184") // Bright yellow/gold
	gray := lipgloss.Color("245")   // Light gray
	white := lipgloss.Color("255")  // White

	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(red)

	valueStyle := lipgloss.NewStyle().
		Foreground(white)

	detailStyle := lipgloss.NewStyle().
		Foreground(yellow).
		MarginLeft(2)

	// Build the error content
	var content strings.Builder

	// Status code with color coding
	statusColor := getStatusCodeColor(apiErr.StatusCode)
	statusStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(statusColor))

	// Request details
	content.WriteString(labelStyle.Render("Request: "))
	content.WriteString(valueStyle.Render(fmt.Sprintf("%s %s", apiErr.Method, apiErr.URL)))
	content.WriteString("\n")

	// Request ID if available
	if apiErr.ReqId != "" {
		content.WriteString(labelStyle.Render("Request ID: "))
		content.WriteString(valueStyle.Render(apiErr.ReqId))
		content.WriteString("\n")
	}

	content.WriteString(labelStyle.Render("Response Code: "))
	content.WriteString(statusStyle.Render(fmt.Sprintf("%d", apiErr.StatusCode)))
	content.WriteString(" ")
	content.WriteString(http.StatusText(apiErr.StatusCode))

	// Error message if available
	if apiErr.ErrorMessage != "" {
		content.WriteString("\n")
		content.WriteString(labelStyle.Render("Message: "))
		content.WriteString(apiErr.ErrorMessage)
	}

	// Additional context if available
	if apiErr.AdditionalContext != "" {
		content.WriteString("\n")
		content.WriteString(labelStyle.Render("Context: "))
		content.WriteString("\n")
		content.WriteString(detailStyle.Render(apiErr.AdditionalContext))
		content.WriteString("\n")
	}

	if len(apiErr.ExtraMessages) > 0 && apiErr.Details != nil {
		content.WriteString("\n")
		content.WriteString(labelStyle.Render("Details:"))
		content.WriteString("\n")
	} else {
		content.WriteString("\n")
	}

	for _, msg := range apiErr.ExtraMessages {
		content.WriteString(detailStyle.Render(fmt.Sprintf("• %s", msg)))
		content.WriteString("\n")
	}

	// Details if available
	if apiErr.Details != nil {
		// Handle different types of Details
		switch details := apiErr.Details.(type) {
		case []string:
			// Array of strings
			for _, detail := range details {
				content.WriteString(detailStyle.Render(fmt.Sprintf("• %s", detail)))
				content.WriteString("\n")
			}
		case []any:
			// Array of any type
			for _, detail := range details {
				if str, ok := detail.(string); ok {
					content.WriteString(detailStyle.Render(fmt.Sprintf("• %s", str)))
				} else if detailJSON, err := json.Marshal(detail); err == nil {
					content.WriteString(detailStyle.Render(fmt.Sprintf("• %s", string(detailJSON))))
				} else {
					content.WriteString(detailStyle.Render(fmt.Sprintf("• %v", detail)))
				}
				content.WriteString("\n")
			}
		case map[string]any:
			// JSON object
			if detailsJSON, err := json.Marshal(details); err == nil {
				content.WriteString(detailStyle.Render(string(detailsJSON)))
			} else {
				content.WriteString(detailStyle.Render(fmt.Sprintf("%v", details)))
			}
			content.WriteString("\n")
		case string:
			// Single string
			content.WriteString(detailStyle.Render(fmt.Sprintf("• %s", details)))
			content.WriteString("\n")
		default:
			// Any other type - try to JSON marshal it
			if detailsJSON, err := json.Marshal(details); err == nil {
				content.WriteString(detailStyle.Render(string(detailsJSON)))
			} else {
				content.WriteString(detailStyle.Render(fmt.Sprintf("%v", details)))
			}
			content.WriteString("\n")
		}
	}

	// Support message with styled link
	supportStyle := lipgloss.NewStyle().
		Foreground(gray).
		MarginTop(1)

	linkStyle := lipgloss.NewStyle().
		Foreground(yellow).
		Underline(true)

	supportMsg := supportStyle.Render("If this issue continues, get support at ") + linkStyle.Render("https://infisical.com/slack")
	content.WriteString(supportMsg)

	fmt.Fprintln(os.Stderr, content.String())
}

func getStatusCodeColor(statusCode int) string {
	switch {
	case statusCode >= 400 && statusCode < 500:
		return "220" // Yellow for client errors
	case statusCode >= 500:
		return "196" // Red for server errors
	default:
		return "255" // White for unknown
	}
}
