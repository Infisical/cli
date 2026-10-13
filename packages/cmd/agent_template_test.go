package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On Windows t.TempDir() returns a backslash path, which regressed with
// "is an incomplete or empty template" when the template name was derived with path.Base.
func TestProcessTemplate_RendersFileFromSourcePath(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "runlist.tmpl")
	require.NoError(t, os.WriteFile(templatePath, []byte(`greeting={{ "hello" | upper }}`), 0600))

	currentEtag := ""
	rendered, err := ProcessTemplate(1, templatePath, nil, "", &currentEtag, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "greeting=HELLO", rendered.String())
}
