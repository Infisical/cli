package certscan

import (
	"errors"

	"go.mozilla.org/pkcs7"
)

const maxPKCS7NestingDepth = 1024

var errPKCS7TooDeeplyNested = errors.New("pkcs7: structure nested too deeply")

func parsePKCS7(der []byte) (*pkcs7.PKCS7, error) {
	if err := ensurePKCS7NestingWithinLimit(der); err != nil {
		return nil, err
	}
	return pkcs7.Parse(der)
}

func ensurePKCS7NestingWithinLimit(ber []byte) error {
	if len(ber) == 0 {
		return nil
	}
	_, err := walkBERObject(ber, 0, 0)
	return err
}

func walkBERObject(ber []byte, offset, depth int) (int, error) {
	if depth > maxPKCS7NestingDepth {
		return offset, errPKCS7TooDeeplyNested
	}

	berLen := len(ber)
	if offset >= berLen {
		return offset, nil
	}

	b := ber[offset]
	offset++
	if offset >= berLen {
		return offset, nil
	}

	if b&0x1f == 0x1f {
		for offset < berLen && ber[offset] >= 0x80 {
			offset++
		}
		offset++
		if offset >= berLen {
			return offset, nil
		}
	}

	kind := b & 0x20

	l := ber[offset]
	offset++
	if offset > berLen {
		return offset, nil
	}

	length := 0
	indefinite := false
	switch {
	case l > 0x80:
		numberOfBytes := int(l & 0x7f)
		if numberOfBytes > 4 || offset+numberOfBytes > berLen {
			return offset, nil
		}
		if numberOfBytes == 4 && int(ber[offset]) > 0x7f {
			return offset, nil
		}
		if int(ber[offset]) == 0x0 {
			return offset, nil
		}
		for range numberOfBytes {
			length = length*256 + int(ber[offset])
			offset++
		}
	case l == 0x80:
		indefinite = true
	default:
		length = int(l)
	}

	if length < 0 {
		return offset, nil
	}

	contentEnd := offset + length
	if contentEnd > berLen {
		return offset, nil
	}
	if indefinite && kind == 0 {
		return offset, nil
	}

	if kind == 0 {
		return contentEnd, nil
	}

	for offset < contentEnd || indefinite {
		var err error
		offset, err = walkBERObject(ber, offset, depth+1)
		if err != nil {
			return offset, err
		}
		if indefinite {
			if offset+2 > berLen {
				return offset, nil
			}
			if ber[offset] == 0x0 && ber[offset+1] == 0x0 {
				break
			}
		}
	}

	if indefinite {
		contentEnd = offset + 2
	}
	return contentEnd, nil
}
