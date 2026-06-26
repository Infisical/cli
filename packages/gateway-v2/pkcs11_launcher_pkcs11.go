//go:build pkcs11

package gatewayv2

func MaybeExecPkcs11Launcher(_ string, _ []string) error {
	return nil
}
