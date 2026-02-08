package pam

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// EncryptedConn wraps a net.Conn with AES-256-GCM encryption.
// Frame format: [4-byte big-endian total-frame-length][12-byte random nonce][ciphertext + 16-byte GCM auth tag]
type EncryptedConn struct {
	inner net.Conn
	gcm   cipher.AEAD

	readMu  sync.Mutex
	readBuf []byte

	writeMu sync.Mutex
}

func NewEncryptedConn(inner net.Conn, aesKey []byte) (*EncryptedConn, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &EncryptedConn{
		inner: inner,
		gcm:   gcm,
	}, nil
}

func (ec *EncryptedConn) Read(b []byte) (int, error) {
	ec.readMu.Lock()
	defer ec.readMu.Unlock()

	// Serve from buffer if available
	if len(ec.readBuf) > 0 {
		n := copy(b, ec.readBuf)
		ec.readBuf = ec.readBuf[n:]
		return n, nil
	}

	// Read frame length
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(ec.inner, lengthBuf); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint32(lengthBuf)
	if frameLen > 1<<24 {
		return 0, fmt.Errorf("encrypted frame too large: %d bytes", frameLen)
	}

	// Read the full frame (nonce + ciphertext)
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(ec.inner, frame); err != nil {
		return 0, fmt.Errorf("failed to read encrypted frame: %w", err)
	}

	nonceSize := ec.gcm.NonceSize()
	if int(frameLen) < nonceSize {
		return 0, fmt.Errorf("frame too short for nonce")
	}

	nonce := frame[:nonceSize]
	ciphertext := frame[nonceSize:]

	plaintext, err := ec.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("GCM decryption failed: %w", err)
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		ec.readBuf = plaintext[n:]
	}
	return n, nil
}

func (ec *EncryptedConn) Write(b []byte) (int, error) {
	ec.writeMu.Lock()
	defer ec.writeMu.Unlock()

	nonce := make([]byte, ec.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := ec.gcm.Seal(nil, nonce, b, nil)

	// Frame = nonce + ciphertext
	frameLen := len(nonce) + len(ciphertext)
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(frameLen))

	if _, err := ec.inner.Write(lengthBuf); err != nil {
		return 0, fmt.Errorf("failed to write frame length: %w", err)
	}
	if _, err := ec.inner.Write(nonce); err != nil {
		return 0, fmt.Errorf("failed to write nonce: %w", err)
	}
	if _, err := ec.inner.Write(ciphertext); err != nil {
		return 0, fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return len(b), nil
}

func (ec *EncryptedConn) Close() error {
	return ec.inner.Close()
}

func (ec *EncryptedConn) LocalAddr() net.Addr {
	return ec.inner.LocalAddr()
}

func (ec *EncryptedConn) RemoteAddr() net.Addr {
	return ec.inner.RemoteAddr()
}

func (ec *EncryptedConn) SetDeadline(t time.Time) error {
	return ec.inner.SetDeadline(t)
}

func (ec *EncryptedConn) SetReadDeadline(t time.Time) error {
	return ec.inner.SetReadDeadline(t)
}

func (ec *EncryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.inner.SetWriteDeadline(t)
}
