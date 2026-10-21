package certscan

import (
	"errors"

	"go.mozilla.org/pkcs7"
)

const maxPKCS7NestingDepth = 64

var errPKCS7TooDeeplyNested = errors.New("pkcs7: structure nested too deeply")

func parsePKCS7(der []byte) (*pkcs7.PKCS7, error) {
	if !asn1NestingWithinLimit(der, maxPKCS7NestingDepth) {
		return nil, errPKCS7TooDeeplyNested
	}
	return pkcs7.Parse(der)
}

func asn1NestingWithinLimit(data []byte, maxDepth int) bool {
	type frame struct{ end int }
	var stack []frame
	pos, n := 0, len(data)
	for pos < n {
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if top.end >= 0 && pos >= top.end {
				stack = stack[:len(stack)-1]
				continue
			}
			break
		}
		tag := data[pos]
		pos++
		if tag == 0x00 {
			if pos < n && data[pos] == 0x00 {
				pos++
				if len(stack) > 0 && stack[len(stack)-1].end < 0 {
					stack = stack[:len(stack)-1]
				}
			}
			continue
		}
		if tag&0x1f == 0x1f {
			for pos < n && data[pos]&0x80 != 0 {
				pos++
			}
			if pos < n {
				pos++
			}
		}
		if pos >= n {
			return true
		}
		lengthByte := data[pos]
		pos++
		constructed := tag&0x20 != 0
		if lengthByte == 0x80 {
			if constructed {
				if len(stack)+1 > maxDepth {
					return false
				}
				stack = append(stack, frame{end: -1})
			}
			continue
		}
		length := int(lengthByte)
		if lengthByte&0x80 != 0 {
			numBytes := int(lengthByte & 0x7f)
			if numBytes == 0 || numBytes > 4 || pos+numBytes > n {
				return true
			}
			length = 0
			for range numBytes {
				length = length<<8 | int(data[pos])
				pos++
			}
		}
		if constructed {
			if len(stack)+1 > maxDepth {
				return false
			}
			end := pos + length
			if end > n {
				end = n
			}
			stack = append(stack, frame{end: end})
		} else {
			pos += length
		}
	}
	return true
}
