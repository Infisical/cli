//go:build !pkcs11

package gatewayv2

func LoadPkcs11Module(_ string) (Pkcs11Module, error) {
	return nil, &Pkcs11Error{
		Code:    Pkcs11ErrNotSupported,
		Message: "This Gateway build was compiled without PKCS#11 support. Use the infisical-pkcs11 release artifact, or build from source with `go build -tags pkcs11` (cgo + dynamic linking required).",
	}
}
