//go:build pkcs11

package gatewayv2

import "github.com/rs/zerolog/log"

func setupPkcs11ModuleForConfig(path string) (Pkcs11Module, error) {
	if path == "" {
		return nil, nil
	}
	mod, err := LoadPkcs11Module(path)
	if err != nil {
		return nil, err
	}
	log.Info().Str("path", path).Msg("PKCS#11 module loaded")
	return mod, nil
}
