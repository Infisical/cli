/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeFolderTree returns a listChildren func backed by a static folder tree, so the
// path-resolution logic can be unit-tested without a live Infisical backend.
func fakeFolderTree() func(string) ([]string, error) {
	tree := map[string][]string{
		"/":         {"/apps", "/packages"},
		"/apps":     {"/apps/cli", "/apps/api", "/apps/web"},
		"/packages": {"/packages/eslint-config"},
	}
	return func(parent string) ([]string, error) {
		return tree[parent], nil
	}
}

func TestExpandToFilePaths(t *testing.T) {
	listChildren := fakeFolderTree()

	tests := []struct {
		name     string
		pattern  string
		expected []string
	}{
		{
			name:     "glob expands to immediate children only",
			pattern:  "apps/*",
			expected: []string{"/apps/cli", "/apps/api", "/apps/web"},
		},
		{
			name:     "glob normalizes a leading-slash prefix",
			pattern:  "/apps/*",
			expected: []string{"/apps/cli", "/apps/api", "/apps/web"},
		},
		{
			name:     "root glob lists top-level folders, not recursively",
			pattern:  "/*",
			expected: []string{"/apps", "/packages"},
		},
		{
			name:     "concrete path resolves to itself",
			pattern:  "/apps/cli",
			expected: []string{"/apps/cli"},
		},
		{
			name:     "concrete path without leading slash is normalized",
			pattern:  "apps/cli",
			expected: []string{"/apps/cli"},
		},
		{
			name:     "root path walks the whole tree recursively",
			pattern:  "/",
			expected: []string{"/", "/apps", "/apps/cli", "/apps/api", "/apps/web", "/packages", "/packages/eslint-config"},
		},
		{
			name:     "empty path is treated as root",
			pattern:  "",
			expected: []string{"/", "/apps", "/apps/cli", "/apps/api", "/apps/web", "/packages", "/packages/eslint-config"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandToFilePaths(tt.pattern, listChildren)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapPathToFile(t *testing.T) {
	tests := []struct {
		name       string
		secretPath string
		format     string
		expected   string
	}{
		{name: "dotenv mirrors the logical path", secretPath: "/apps/cli", format: "dotenv", expected: "apps/cli/.env"},
		{name: "root maps to default filename in cwd", secretPath: "/", format: "dotenv", expected: ".env"},
		{name: "json uses the json default filename", secretPath: "/apps/api", format: "json", expected: "apps/api/secrets.json"},
		{name: "yaml uses the yaml default filename", secretPath: "/packages/eslint-config", format: "yaml", expected: "packages/eslint-config/secrets.yaml"},
		{name: "trailing and leading slashes are trimmed", secretPath: "/apps/web/", format: "dotenv", expected: "apps/web/.env"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapPathToFile(tt.secretPath, tt.format))
		})
	}
}

func TestExpandToFilePathsTerminatesOnCycle(t *testing.T) {
	// A buggy/adversarial server could return a folder graph with a cycle.
	tree := map[string][]string{
		"/":    {"/a"},
		"/a":   {"/a/b"},
		"/a/b": {"/a"}, // cycle back to an ancestor
	}
	listChildren := func(parent string) ([]string, error) {
		return tree[parent], nil
	}

	result, err := expandToFilePaths("/", listChildren)
	assert.NoError(t, err)
	assert.Equal(t, []string{"/", "/a", "/a/b"}, result)
}

func TestIsSafeFolderSegment(t *testing.T) {
	tests := []struct {
		name string
		safe bool
	}{
		{name: "apps", safe: true},
		{name: "eslint-config", safe: true},
		{name: "", safe: false},
		{name: ".", safe: false},
		{name: "..", safe: false},
		{name: "../../.ssh", safe: false},
		{name: "a/b", safe: false},
		{name: "a\\b", safe: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.safe, isSafeFolderSegment(tt.name))
		})
	}
}
