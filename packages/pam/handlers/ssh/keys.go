package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// generateRSAKey generates a 2048-bit RSA private key
func generateRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return privateKey, nil
}
