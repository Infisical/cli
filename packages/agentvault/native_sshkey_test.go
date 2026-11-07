package agentvault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newSSHKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

func certificateFor(t *testing.T, key ssh.PublicKey) string {
	t.Helper()
	authority, _ := newSSHKey(t)
	cert := &ssh.Certificate{Key: key, CertType: ssh.UserCert, ValidPrincipals: []string{"agent"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(cert))
}

func sshKeyService(privateKey []byte, certificate string) *resolvedService {
	return &resolvedService{
		name:       "bastion",
		kind:       serviceKindSSH,
		credential: credential{kind: credentialSSHKey, username: "agent", privateKey: privateKey, certificate: certificate},
	}
}

func TestACertificateForTheStoredKeyIsAccepted(t *testing.T) {
	signer, privateKey := newSSHKey(t)
	if err := checkSSHKey(sshKeyService(privateKey, certificateFor(t, signer.PublicKey()))); err != nil {
		t.Fatalf("a matching key and certificate were refused: %v", err)
	}
}

func TestACertificateForAnotherKeyIsRefusedReadably(t *testing.T) {
	other, _ := newSSHKey(t)
	_, privateKey := newSSHKey(t)

	err := checkSSHKey(sshKeyService(privateKey, certificateFor(t, other.PublicKey())))
	if err == nil || !strings.Contains(err.Error(), `the SSH certificate stored on service "bastion" doesn't match its private key`) {
		t.Fatalf("a certificate for another key: %v, want the mismatch refusal", err)
	}
}
