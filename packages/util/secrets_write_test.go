package util

import (
	"errors"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

// A repeated key is refused before any request: without a server to answer, reaching the network would
// return a different error.
func TestWriteRawSecretsRefusesRepeatedKeysBeforeWriting(t *testing.T) {
	for _, mode := range []SecretWriteMode{SecretWriteCreateOnly, SecretWriteUpdateOnly} {
		_, err := WriteRawSecrets(mode, []string{"DUP=a", "OTHER=b", "DUP=b"}, SECRET_TYPE_SHARED, "dev", "/", "project", &models.TokenDetails{}, "", nil)
		var repeated *SecretWriteRepeated
		if !errors.As(err, &repeated) || repeated.Key != "DUP" {
			t.Errorf("mode %d: got %v", mode, err)
		}
	}
}
