//go:build !pkcs11

package gatewayv2

func setupPkcs11ModuleForConfig(_ string) (Pkcs11Module, error) {
	return nil, nil
}
