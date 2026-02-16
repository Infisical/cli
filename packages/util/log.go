package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
)

// GetStderrWriter is a function that returns the stderr writer to use.
// It can be set by the cmd package to use RootCmd's stderr.
// If not set, it defaults to returning os.Stderr.
var GetStderrWriter func() io.Writer = func() io.Writer {
	return os.Stderr
}

// GetStdoutWriter is a function that returns the stdout writer to use.
// It can be set by the cmd package to use RootCmd's stdout.
// If not set, it defaults to returning os.Stdout.
var GetStdoutWriter func() io.Writer = func() io.Writer {
	return os.Stdout
}

// PrintStderr prints to stderr using GetStderrWriter (which proxies to RootCmd's stderr).
// This is equivalent to fmt.Print but uses RootCmd's stderr.
func PrintStderr(a ...interface{}) {
	fmt.Fprint(GetStderrWriter(), a...)
}

// PrintlnStderr prints to stderr using GetStderrWriter (which proxies to RootCmd's stderr).
// This is equivalent to fmt.Println but uses RootCmd's stderr.
func PrintlnStderr(a ...interface{}) {
	fmt.Fprintln(GetStderrWriter(), a...)
}

// PrintfStderr prints to stderr using GetStderrWriter (which proxies to RootCmd's stderr).
// This is equivalent to fmt.Printf but uses RootCmd's stderr.
func PrintfStderr(format string, a ...interface{}) {
	fmt.Fprintf(GetStderrWriter(), format, a...)
}

// PrintStdout prints to stdout using GetStdoutWriter (which proxies to RootCmd's stdout).
// This is equivalent to fmt.Print but uses RootCmd's stdout.
func PrintStdout(a ...interface{}) {
	fmt.Fprint(GetStdoutWriter(), a...)
}

// PrintlnStdout prints to stdout using GetStdoutWriter (which proxies to RootCmd's stdout).
// This is equivalent to fmt.Println but uses RootCmd's stdout.
func PrintlnStdout(a ...interface{}) {
	fmt.Fprintln(GetStdoutWriter(), a...)
}

// PrintfStdout prints to stdout using GetStdoutWriter (which proxies to RootCmd's stdout).
// This is equivalent to fmt.Printf but uses RootCmd's stdout.
func PrintfStdout(format string, a ...interface{}) {
	fmt.Fprintf(GetStdoutWriter(), format, a...)
}

func HandleError(err error, messages ...string) {
	PrintErrorAndExit(1, err, messages...)
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
				PrintlnStderr(message)
			}
		}

	}

	os.Exit(exitCode)
}

func PrintWarning(message string) {
	PrintWarningWithWriter(message, GetStderrWriter())
}

func PrintWarningWithWriter(message string, w io.Writer) {
	color.New(color.FgYellow).Fprintf(w, "Warning: %v \n", message)
}

func PrintSuccessMessage(message string) {
	color.New(color.FgGreen).Println(message)
}

func PrintErrorMessageAndExit(messages ...string) {
	if len(messages) > 0 {
		for _, message := range messages {
			PrintlnStderr(message)
		}
	}

	os.Exit(1)
}

func printError(e error) {
	color.New(color.FgRed).Fprintf(GetStderrWriter(), "error: %v\n", e)
}

func printPrettyAPIError(apiErr api.APIError) {
	isDark := lipgloss.HasDarkBackground()

	var (
		labelColor       lipgloss.Color = lipgloss.Color("196") // Bright Red
		primaryTextColor lipgloss.Color = lipgloss.Color("235") // Dark Gray
		accentColor      lipgloss.Color = lipgloss.Color("17")  // Dark Blue
	)

	if isDark {
		primaryTextColor = lipgloss.Color("245") // Light Gray
		accentColor = lipgloss.Color("27")       // Light Blue
	}

	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(labelColor)

	valueStyle := lipgloss.NewStyle().
		Foreground(primaryTextColor)

	detailStyle := lipgloss.NewStyle().
		Foreground(accentColor).
		MarginLeft(2)

	// Build the error content
	var content strings.Builder

	// Status code with color coding
	statusColor := getStatusCodeColor(apiErr.StatusCode)
	statusStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(statusColor))

	domain := extractDomainFromURL(apiErr.URL)

	// Request details
	content.WriteString(labelStyle.Render("Request: "))
	content.WriteString(valueStyle.Render(fmt.Sprintf("%s %s", apiErr.Method, apiErr.URL)))
	content.WriteString("\n")

	// Show which instance is being used
	if domain != "" {
		content.WriteString(labelStyle.Render("Instance: "))
		content.WriteString(valueStyle.Render(domain))
		content.WriteString("\n")
	}

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
		Foreground(primaryTextColor).
		MarginTop(1)

	linkStyle := lipgloss.NewStyle().
		Foreground(accentColor).
		Underline(true)

	supportMsg := supportStyle.Render("If this issue continues, get support at ") + linkStyle.Render("https://infisical.com/slack")
	content.WriteString(supportMsg)

	PrintlnStderr(content.String())
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

func extractDomainFromURL(urlStr string) string {
	if urlStr == "" {
		return ""
	}

	if parsedURL, err := url.Parse(urlStr); err == nil && parsedURL.Host != "" {
		return parsedURL.Scheme + "://" + parsedURL.Host
	}

	return ""
}
