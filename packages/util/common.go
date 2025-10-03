package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"unicode"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/agnivade/levenshtein"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	OUTPUT_FORMAT_YAML   = "yaml"
	OUTPUT_FORMAT_JSON   = "json"
	OUTPUT_FORMAT_DOTENV = "dotenv"

	SUPPORTED_OUTPUT_FORMATS = []string{OUTPUT_FORMAT_YAML, OUTPUT_FORMAT_JSON, OUTPUT_FORMAT_DOTENV}
)

func GetHomeDir() (string, error) {
	directory, err := os.UserHomeDir()
	return directory, err
}

// write file to given path. If path does not exist throw error
func WriteToFile(fileName string, dataToWrite []byte, filePerm os.FileMode) error {
	err := os.WriteFile(fileName, dataToWrite, filePerm)
	if err != nil {
		return fmt.Errorf("unable to wrote to file [err=%v]", err)
	}

	return nil
}

func ValidateInfisicalAPIConnection() (ok bool) {
	_, err := http.Get(fmt.Sprintf("%v/status", config.INFISICAL_URL))
	return err == nil
}

func GetRestyClientWithCustomHeaders() (*resty.Client, error) {
	httpClient := resty.New()
	customHeaders := os.Getenv("INFISICAL_CUSTOM_HEADERS")
	if customHeaders != "" {
		headers, err := GetInfisicalCustomHeadersMap()
		if err != nil {
			return nil, err
		}

		httpClient.SetHeaders(headers)
	}
	return httpClient, nil
}

func GetInfisicalCustomHeadersMap() (map[string]string, error) {
	customHeaders := os.Getenv("INFISICAL_CUSTOM_HEADERS")
	if customHeaders == "" {
		return nil, nil
	}

	headers := map[string]string{}

	pos := 0
	for pos < len(customHeaders) {
		for pos < len(customHeaders) && unicode.IsSpace(rune(customHeaders[pos])) {
			pos++
		}

		if pos >= len(customHeaders) {
			break
		}

		keyStart := pos
		for pos < len(customHeaders) && customHeaders[pos] != '=' && !unicode.IsSpace(rune(customHeaders[pos])) {
			pos++
		}

		if pos >= len(customHeaders) || customHeaders[pos] != '=' {
			return nil, fmt.Errorf("invalid custom header format. Expected \"headerKey1=value1 headerKey2=value2 ....\" but got %v", customHeaders)
		}

		key := customHeaders[keyStart:pos]
		pos++

		for pos < len(customHeaders) && unicode.IsSpace(rune(customHeaders[pos])) {
			pos++
		}

		var value string

		if pos < len(customHeaders) {
			if customHeaders[pos] == '"' || customHeaders[pos] == '\'' {
				quoteChar := customHeaders[pos]
				pos++
				valueStart := pos

				for pos < len(customHeaders) &&
					(customHeaders[pos] != quoteChar ||
						(pos > 0 && customHeaders[pos-1] == '\\')) {
					pos++
				}

				if pos < len(customHeaders) {
					value = customHeaders[valueStart:pos]
					pos++
				} else {
					value = customHeaders[valueStart:]
				}
			} else {
				valueStart := pos
				for pos < len(customHeaders) && !unicode.IsSpace(rune(customHeaders[pos])) {
					pos++
				}
				value = customHeaders[valueStart:pos]
			}
		}

		if key != "" && !strings.EqualFold(key, "User-Agent") && !strings.EqualFold(key, "Accept") {
			headers[key] = value
		}
	}

	return headers, nil
}

func findClosestMatch(input string, options []string) string {
	minDistance := len(input) + 10
	closestMatch := ""

	for _, option := range options {
		distance := levenshtein.ComputeDistance(
			strings.ToLower(input),
			strings.ToLower(option),
		)

		if distance < minDistance && distance <= 2 {
			minDistance = distance
			closestMatch = option
		}
	}

	return closestMatch
}

type FormatOutputOptions struct {
	DotEnvArrayKeyAttribute   string
	DotEnvArrayValueAttribute string
}

func FormatOutput[T any](outputFormat string, input T, options *FormatOutputOptions) (string, error) {

	if !slices.Contains(SUPPORTED_OUTPUT_FORMATS, outputFormat) {
		closestMatch := findClosestMatch(outputFormat, SUPPORTED_OUTPUT_FORMATS)

		errorMessage := fmt.Sprintf("invalid output format: %s. Supported formats are %s.", outputFormat, strings.Join(SUPPORTED_OUTPUT_FORMATS, ", "))

		if closestMatch != "" {
			errorMessage += fmt.Sprintf("\nDid you mean '%s'?", closestMatch)
		}

		return "", errors.New(errorMessage)
	}

	formatAsJson := func(input T) (string, error) {
		// can directly marshal to json without worrying about formatting

		jsonBytes, err := json.Marshal(input)
		if err != nil {
			return "", err
		}
		return string(jsonBytes), nil
	}

	formatAsDotEnv := func(input T) (string, error) {
		jsonBytes, err := json.Marshal(input)
		if err != nil {
			return "", err
		}

		// try to unmarshal as array first
		var dataArray []map[string]any
		if err := json.Unmarshal(jsonBytes, &dataArray); err == nil {
			// if it succeeds we are dealing with an array of objects
			var dotenv string
			var lastIndex int
			for i, item := range dataArray {

				if options != nil && options.DotEnvArrayKeyAttribute != "" && options.DotEnvArrayValueAttribute != "" {
					dotenv += fmt.Sprintf("%s=%s\n", item[options.DotEnvArrayKeyAttribute], item[options.DotEnvArrayValueAttribute])
					continue
				}

				for key, value := range item {
					if lastIndex != i {
						dotenv += "\n"
						lastIndex = i
					}
					dotenv += fmt.Sprintf("%s=%v\n", key, value)
				}
			}
			return dotenv, nil
		}

		// try to marshal to a string map directly
		var dataMap map[string]any
		if err := json.Unmarshal(jsonBytes, &dataMap); err != nil {
			return "", fmt.Errorf("input must be an object or array of objects")
		}

		var dotenv string
		for key, value := range dataMap {
			dotenv += fmt.Sprintf("%s=%v\n", key, value)
		}
		return dotenv, nil
	}

	formatAsYaml := func(input T) (string, error) {
		// special handling is needed in order to respect the json tags attributed to the struct fields

		// check if its a map[string]any, if it is we can print it directly as yaml without worrying about formatting
		if _, ok := any(input).(map[string]any); ok {
			yamlBytes, err := yaml.Marshal(input)
			if err != nil {
				return "", err
			}
			return string(yamlBytes), nil
		}

		// convert to json first (forces it to use json tags (if any) attributed to the struct fields)
		jsonBytes, err := json.Marshal(input)
		if err != nil {
			return "", err
		}

		// unmarshal to map[string]any to preserve JSON field names (in case of nested structs)
		var data any
		if err := json.Unmarshal(jsonBytes, &data); err != nil {
			return "", err
		}

		// marshal to YAML (will use the JSON field names)
		yamlBytes, err := yaml.Marshal(data)
		if err != nil {
			return "", err
		}
		return string(yamlBytes), nil
	}

	switch outputFormat {
	case OUTPUT_FORMAT_YAML:
		return formatAsYaml(input)
	case OUTPUT_FORMAT_JSON:
		return formatAsJson(input)
	case OUTPUT_FORMAT_DOTENV:
		return formatAsDotEnv(input)
	default:
		return "", fmt.Errorf("invalid output format: %s. Supported formats are %s", outputFormat, strings.Join(SUPPORTED_OUTPUT_FORMATS, ", "))
	}
}

func AddOutputFlagsToCmd(cmd *cobra.Command, outputDescription string) {

	supportedFormats := strings.Join(SUPPORTED_OUTPUT_FORMATS, ", ")

	if outputDescription != "" && outputDescription[len(outputDescription)-1] == '.' {
		outputDescription = outputDescription[:len(outputDescription)-1]
	}

	cmd.Flags().StringP("output", "o", "", fmt.Sprintf("%s. Supported formats are %s", outputDescription, supportedFormats))
}
