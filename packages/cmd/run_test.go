package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInjectingSecretsMessage(t *testing.T) {
	assert.Equal(t, "Injecting 0 Infisical secrets into your application process", injectingSecretsMessage(0))
	assert.Equal(t, "Injecting 1 Infisical secret into your application process", injectingSecretsMessage(1))
	assert.Equal(t, "Injecting 2 Infisical secrets into your application process", injectingSecretsMessage(2))
}
