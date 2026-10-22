package certscan

import (
	"errors"

	"go.mozilla.org/pkcs7"
)

const maxPKCS7ParseBytes = 512 * 1024

var errPKCS7TooLarge = errors.New("pkcs7: input too large to parse safely")

func parsePKCS7(der []byte) (*pkcs7.PKCS7, error) {
	if len(der) > maxPKCS7ParseBytes {
		return nil, errPKCS7TooLarge
	}
	return pkcs7.Parse(der)
}
