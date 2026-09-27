package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretsTypeFlagDefaults(t *testing.T) {
	tests := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"secrets set", secretsSetCmd},
		{"secrets delete", secretsDeleteCmd},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flag := tc.cmd.Flags().Lookup("type")
			require.NotNil(t, flag, "the type flag should be registered")
			assert.Equal(t, util.SECRET_TYPE_SHARED, flag.DefValue)
		})
	}
}
