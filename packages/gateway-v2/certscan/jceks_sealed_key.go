package certscan

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	javaStreamMagic   = 0xACED
	javaStreamVersion = 5

	javaTCNull         = 0x70
	javaTCReference    = 0x71
	javaTCClassDesc    = 0x72
	javaTCObject       = 0x73
	javaTCString       = 0x74
	javaTCArray        = 0x75
	javaTCEndBlockData = 0x78
	javaBaseWireHandle = 0x7E0000
	javaSCWriteMethod  = 0x01
	javaSCSerializable = 0x02

	maxJavaStreamDepth   = 32
	maxJavaStreamHandles = 4096
)

var errUnsupportedSealedKey = errors.New("keystore secret key entry could not be skipped")

type javaClassDesc struct {
	name       string
	flags      byte
	fieldTypes []byte
	super      *javaClassDesc
}

var javaPrimitiveSizes = map[byte]int{'B': 1, 'Z': 1, 'C': 2, 'S': 2, 'I': 4, 'F': 4, 'J': 8, 'D': 8}

type javaStreamSkipper struct {
	r       *jksReader
	handles []*javaClassDesc
}

func skipSealedSecretKey(r *jksReader) error {
	header, err := r.take(4)
	if err != nil {
		return err
	}
	if binary.BigEndian.Uint16(header) != javaStreamMagic || binary.BigEndian.Uint16(header[2:]) != javaStreamVersion {
		return errUnsupportedSealedKey
	}
	s := &javaStreamSkipper{r: r}
	_, err = s.content(0)
	return err
}

func (s *javaStreamSkipper) addHandle(desc *javaClassDesc) error {
	if len(s.handles) >= maxJavaStreamHandles {
		return errUnsupportedSealedKey
	}
	s.handles = append(s.handles, desc)
	return nil
}

func (s *javaStreamSkipper) byteValue() (byte, error) {
	b, err := s.r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (s *javaStreamSkipper) skip(n int) error {
	_, err := s.r.take(n)
	return err
}

func (s *javaStreamSkipper) content(depth int) (*javaClassDesc, error) {
	if depth > maxJavaStreamDepth {
		return nil, errUnsupportedSealedKey
	}
	tc, err := s.byteValue()
	if err != nil {
		return nil, err
	}
	switch tc {
	case javaTCNull:
		return nil, nil
	case javaTCReference:
		raw, err := s.r.take(4)
		if err != nil {
			return nil, err
		}
		index := int64(binary.BigEndian.Uint32(raw)) - javaBaseWireHandle
		if index < 0 || index >= int64(len(s.handles)) {
			return nil, errUnsupportedSealedKey
		}
		return s.handles[index], nil
	case javaTCClassDesc:
		return s.classDescBody(depth)
	case javaTCString:
		n, err := s.r.uint16()
		if err != nil {
			return nil, err
		}
		return nil, errors.Join(s.skip(n), s.addHandle(nil))
	case javaTCArray:
		return nil, s.array(depth)
	case javaTCObject:
		desc, err := s.classDesc(depth)
		if err != nil {
			return nil, err
		}
		if err := s.addHandle(nil); err != nil {
			return nil, err
		}
		return nil, s.classData(desc, depth)
	default:
		return nil, fmt.Errorf("%w: unexpected stream element 0x%02x", errUnsupportedSealedKey, tc)
	}
}

func (s *javaStreamSkipper) classDesc(depth int) (*javaClassDesc, error) {
	tc, err := s.byteValue()
	if err != nil {
		return nil, err
	}
	switch tc {
	case javaTCNull:
		return nil, nil
	case javaTCClassDesc:
		return s.classDescBody(depth)
	case javaTCReference:
		s.r.pos--
		return s.content(depth + 1)
	default:
		return nil, errUnsupportedSealedKey
	}
}

func (s *javaStreamSkipper) classDescBody(depth int) (*javaClassDesc, error) {
	name, err := s.r.utf()
	if err != nil {
		return nil, err
	}
	if err := s.skip(8); err != nil {
		return nil, err
	}
	desc := &javaClassDesc{name: name}
	if err := s.addHandle(desc); err != nil {
		return nil, err
	}
	flags, err := s.byteValue()
	if err != nil {
		return nil, err
	}
	desc.flags = flags
	fieldCount, err := s.r.uint16()
	if err != nil {
		return nil, err
	}
	for i := 0; i < fieldCount; i++ {
		fieldType, err := s.byteValue()
		if err != nil {
			return nil, err
		}
		if _, err := s.r.utf(); err != nil {
			return nil, err
		}
		if fieldType == 'L' || fieldType == '[' {
			if _, err := s.content(depth + 1); err != nil {
				return nil, err
			}
		} else if _, ok := javaPrimitiveSizes[fieldType]; !ok {
			return nil, errUnsupportedSealedKey
		}
		desc.fieldTypes = append(desc.fieldTypes, fieldType)
	}
	if err := s.blockDataUntilEnd(depth); err != nil {
		return nil, err
	}
	if desc.super, err = s.classDesc(depth + 1); err != nil {
		return nil, err
	}
	return desc, nil
}

func (s *javaStreamSkipper) classData(desc *javaClassDesc, depth int) error {
	var hierarchy []*javaClassDesc
	for d := desc; d != nil; d = d.super {
		if len(hierarchy) > maxJavaStreamDepth {
			return errUnsupportedSealedKey
		}
		hierarchy = append([]*javaClassDesc{d}, hierarchy...)
	}
	for _, d := range hierarchy {
		if d.flags&javaSCSerializable == 0 {
			continue
		}
		for _, fieldType := range d.fieldTypes {
			if size, ok := javaPrimitiveSizes[fieldType]; ok {
				if err := s.skip(size); err != nil {
					return err
				}
				continue
			}
			if _, err := s.content(depth + 1); err != nil {
				return err
			}
		}
		if d.flags&javaSCWriteMethod != 0 {
			if err := s.blockDataUntilEnd(depth); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *javaStreamSkipper) array(depth int) error {
	desc, err := s.classDesc(depth + 1)
	if err != nil {
		return err
	}
	if desc == nil || len(desc.name) < 2 || desc.name[0] != '[' {
		return errUnsupportedSealedKey
	}
	size, ok := javaPrimitiveSizes[desc.name[1]]
	if !ok {
		return errUnsupportedSealedKey
	}
	if err := s.addHandle(nil); err != nil {
		return err
	}
	length, err := s.r.uint32()
	if err != nil {
		return err
	}
	return s.skip(length * size)
}

func (s *javaStreamSkipper) blockDataUntilEnd(depth int) error {
	for {
		tc, err := s.byteValue()
		if err != nil {
			return err
		}
		if tc == javaTCEndBlockData {
			return nil
		}
		s.r.pos--
		if _, err := s.content(depth + 1); err != nil {
			return err
		}
	}
}
