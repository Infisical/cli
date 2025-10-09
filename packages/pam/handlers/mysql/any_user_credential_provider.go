package mysql

type AnyUserCredentialProvider struct{}

func (m *AnyUserCredentialProvider) CheckUsername(username string) (found bool, err error) {
	return true, nil
}

func (m *AnyUserCredentialProvider) GetCredential(username string) (password string, found bool, err error) {
	return "", true, nil
}
