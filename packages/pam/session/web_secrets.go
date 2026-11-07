package session

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func webSecretsPath(id string) string {
	return filepath.Join(GetSessionRecordingDir(), "webapp", id+".secrets")
}

func AtomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pam-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (cm *CredentialsManager) persistWebSecrets(id string) error {
	key, err := cm.GetPAMSessionEncryptionKey()
	if err != nil {
		return err
	}
	b, err := json.Marshal(cm.GetRecordingSecrets(id))
	if err != nil {
		return err
	}
	b, err = EncryptData(b, key)
	if err != nil {
		return err
	}
	return AtomicWrite(webSecretsPath(id), b)
}

func (cm *CredentialsManager) loadWebSecrets(id string) error {
	b, err := os.ReadFile(webSecretsPath(id))
	if err != nil {
		return err
	}
	key, err := cm.GetPAMSessionEncryptionKey()
	if err != nil {
		return err
	}
	b, err = DecryptData(b, key)
	if err != nil {
		return err
	}
	var secrets PAMRecordingSecrets
	if err := json.Unmarshal(b, &secrets); err != nil {
		return err
	}
	cm.recordingSecretsMu.Lock()
	cm.recordingSecrets[id] = &secrets
	cm.recordingSecretsMu.Unlock()
	return nil
}

func (cm *CredentialsManager) RestoreWebRecordingSecrets(id string) error {
	return cm.loadWebSecrets(id)
}

func (cm *CredentialsManager) InvalidateSessionCredentials(id string) {
	cm.cacheMutex.Lock()
	delete(cm.credentialsCache, id)
	cm.cacheMutex.Unlock()
}
