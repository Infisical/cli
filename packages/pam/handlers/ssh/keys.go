package ssh

import (
	"crypto/rand"
	"crypto/rsa"
)

// generateRSAKey generates a 2048-bit RSA private key
func generateRSAKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		// For POC, panic is acceptable. In production, handle properly
		panic(err)
	}
	return privateKey
}

