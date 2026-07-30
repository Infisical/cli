//go:build unix

// File modes are a POSIX concept. On Windows os.Chmod only toggles the
// read-only bit, so these tests would assert something meaningless there.
package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFileMode(t *testing.T) {
	cases := []struct {
		name       string
		permission string
		want       *os.FileMode
		wantErr    bool
	}{
		{name: "empty means unset", permission: "", want: nil},
		{name: "leading zero", permission: "0600", want: fileMode(0600)},
		{name: "without leading zero", permission: "600", want: fileMode(0600)},
		{name: "world readable", permission: "0644", want: fileMode(0644)},
		{name: "maximum", permission: "0777", want: fileMode(0777)},
		{name: "not a number", permission: "invalid", wantErr: true},
		{name: "not octal", permission: "0800", wantErr: true},
		{name: "setuid rejected", permission: "4600", wantErr: true},
		{name: "sticky bit rejected", permission: "1777", wantErr: true},
		{name: "negative", permission: "-1", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFileMode(tc.permission)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.permission)
				return
			}

			require.NoError(t, err)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

func TestWriteBytesToFileAppliesConfiguredMode(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "app.env")

	require.NoError(t, WriteBytesToFile(bytes.NewBufferString("SECRET=1"), destination, fileMode(0600)))

	assert.Equal(t, os.FileMode(0600), statMode(t, destination))
	assert.Equal(t, "SECRET=1", readFile(t, destination))
}

// The case a bare os.Create gets wrong: a mode passed to open is only honoured
// when the file is created, so an already-present file keeps its old mode
// unless it is chmod'ed explicitly. This is also umask-independent, which
// makes it the strongest evidence that the chmod is doing the work.
func TestWriteBytesToFileTightensExistingFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "app.env")
	require.NoError(t, os.WriteFile(destination, []byte("stale"), 0666))
	require.NoError(t, os.Chmod(destination, 0666))

	require.NoError(t, WriteBytesToFile(bytes.NewBufferString("SECRET=1"), destination, fileMode(0600)))

	assert.Equal(t, os.FileMode(0600), statMode(t, destination))
	assert.Equal(t, "SECRET=1", readFile(t, destination))
}

// A nil mode must behave exactly like the pre-existing implementation, which
// left the mode to the process umask. Comparing against a reference file keeps
// the assertion correct under any umask the test runner happens to have.
func TestWriteBytesToFileNilModeMatchesOsCreate(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "app.env")
	reference := filepath.Join(dir, "reference.env")

	referenceFile, err := os.Create(reference)
	require.NoError(t, err)
	require.NoError(t, referenceFile.Close())

	require.NoError(t, WriteBytesToFile(bytes.NewBufferString("SECRET=1"), destination, nil))

	assert.Equal(t, statMode(t, reference), statMode(t, destination))
}

// A chmod failure must not cost the caller the content that was already on
// disk. This is reachable whenever the destination is writable but owned by
// another user, where the open succeeds and the fchmod returns EPERM. The
// failure is injected because fchmod cannot be made to fail portably from an
// unprivileged test process.
func TestWriteBytesToFilePreservesContentWhenChmodFails(t *testing.T) {
	original := chmodFile
	t.Cleanup(func() { chmodFile = original })
	chmodFile = func(*os.File, os.FileMode) error {
		return errors.New("operation not permitted")
	}

	destination := filepath.Join(t.TempDir(), "app.env")
	require.NoError(t, os.WriteFile(destination, []byte("PREVIOUS=1"), 0644))

	err := WriteBytesToFile(bytes.NewBufferString("SECRET=1"), destination, fileMode(0600))

	require.Error(t, err)
	assert.Equal(t, "PREVIOUS=1", readFile(t, destination))
}

// The open no longer passes O_TRUNC, so guard the explicit truncate that
// replaced it. Without it a shorter render would leave a tail of the previous
// one, which for a dotenv file means stale secrets the consumer still parses.
func TestWriteBytesToFileReplacesLongerContent(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode *os.FileMode
	}{
		{name: "with configured mode", mode: fileMode(0600)},
		{name: "without configured mode", mode: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "app.env")
			require.NoError(t, os.WriteFile(destination, []byte("PREVIOUS=aaaaaaaaaaaaaaaaaaaaaaaa"), 0644))

			require.NoError(t, WriteBytesToFile(bytes.NewBufferString("NEW=1"), destination, tc.mode))

			assert.Equal(t, "NEW=1", readFile(t, destination))
		})
	}
}

// WriteTemplateToFile is the function the reported issue is about, so cover
// the whole path from a parsed template config through to the mode on disk.
// It never touches its receiver, hence the zero-value AgentManager.
func TestWriteTemplateToFileAppliesConfiguredPermission(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "app.env")

	template := &Template{DestinationPath: destination}
	template.Config.Permission = "0600"

	(&AgentManager{}).WriteTemplateToFile(bytes.NewBufferString("SECRET=1"), template, 1)

	assert.Equal(t, os.FileMode(0600), statMode(t, destination))
	assert.Equal(t, "SECRET=1", readFile(t, destination))
}

func TestWriteTemplateToFileTightensExistingFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "app.env")
	require.NoError(t, os.WriteFile(destination, []byte("stale"), 0666))
	require.NoError(t, os.Chmod(destination, 0666))

	template := &Template{DestinationPath: destination}
	template.Config.Permission = "0600"

	(&AgentManager{}).WriteTemplateToFile(bytes.NewBufferString("SECRET=1"), template, 1)

	assert.Equal(t, os.FileMode(0600), statMode(t, destination))
	assert.Equal(t, "SECRET=1", readFile(t, destination))
}

func TestWriteTemplateToFileWithoutPermissionMatchesOsCreate(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "app.env")
	reference := filepath.Join(dir, "reference.env")

	referenceFile, err := os.Create(reference)
	require.NoError(t, err)
	require.NoError(t, referenceFile.Close())

	(&AgentManager{}).WriteTemplateToFile(
		bytes.NewBufferString("SECRET=1"),
		&Template{DestinationPath: destination},
		1,
	)

	assert.Equal(t, statMode(t, reference), statMode(t, destination))
	assert.Equal(t, "SECRET=1", readFile(t, destination))
}

func TestParseAgentConfigReadsPermissions(t *testing.T) {
	snapshotInfisicalURL(t)

	parsed, err := ParseAgentConfig([]byte(`
sinks:
  - type: file
    config:
      path: access-token
      permission: "0600"
templates:
  - source-path: dotenv.tmpl
    destination-path: app.env
    config:
      polling-interval: 60s
      permission: "0640"
`))
	require.NoError(t, err)

	assert.Equal(t, "0600", parsed.Sinks[0].Config.Permission)
	assert.Equal(t, "0640", parsed.Templates[0].Config.Permission)
}

// A typo must stop the agent at startup. Falling through to a looser mode at
// the first render would be invisible until somebody stats the file.
func TestParseAgentConfigRejectsInvalidPermissions(t *testing.T) {
	cases := []struct {
		name       string
		configFile string
		wantField  string
	}{
		{
			name:      "template",
			wantField: "templates[0].config.permission",
			configFile: `
templates:
  - source-path: dotenv.tmpl
    destination-path: app.env
    config:
      permission: "600x"
`,
		},
		{
			name:      "sink",
			wantField: "sinks[0].config.permission",
			configFile: `
sinks:
  - type: file
    config:
      path: access-token
      permission: "rw-------"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshotInfisicalURL(t)

			_, err := ParseAgentConfig([]byte(tc.configFile))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantField)
		})
	}
}

func TestParseAgentConfigAllowsOmittedPermissions(t *testing.T) {
	snapshotInfisicalURL(t)

	parsed, err := ParseAgentConfig([]byte(`
sinks:
  - type: file
    config:
      path: access-token
templates:
  - source-path: dotenv.tmpl
    destination-path: app.env
`))
	require.NoError(t, err)

	assert.Empty(t, parsed.Sinks[0].Config.Permission)
	assert.Empty(t, parsed.Templates[0].Config.Permission)
}

func fileMode(mode os.FileMode) *os.FileMode {
	return &mode
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(contents)
}

// ParseAgentConfig writes the resolved address into package-level config, so
// snapshot it and let withMockInfisicalURL restore it during cleanup. Passing
// the current value keeps this a pure save and restore.
func snapshotInfisicalURL(t *testing.T) {
	t.Helper()
	withMockInfisicalURL(t, config.INFISICAL_URL)
}
