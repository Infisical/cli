package ssh

import (
	"encoding/binary"
	"fmt"
)

// SFTP packet types we care about for logging
const (
	sshFxpInit     = 1
	sshFxpOpen     = 3
	sshFxpClose    = 4
	sshFxpRead     = 5
	sshFxpWrite    = 6
	sshFxpOpendir  = 11
	sshFxpReaddir  = 12
	sshFxpRemove   = 13
	sshFxpMkdir    = 14
	sshFxpRmdir    = 15
	sshFxpRealpath = 16
	sshFxpStat     = 17
	sshFxpRename   = 18
	sshFxpReadlink = 19
	sshFxpSymlink  = 20
)

// SFTPOperation represents a parsed SFTP operation
type SFTPOperation struct {
	Type     string
	Path     string
	DestPath string // For rename operations
	IsWrite  bool   // For OPEN operations: true = upload/write, false = download/read
}

// SFTPParser parses SFTP protocol packets to extract file operations
type SFTPParser struct {
	buffer []byte
}

// NewSFTPParser creates a new SFTP packet parser
func NewSFTPParser() *SFTPParser {
	return &SFTPParser{
		buffer: make([]byte, 0, 64*1024),
	}
}

// Parse processes incoming data and returns any complete SFTP operations found
// Returns nil if no complete operation was parsed (partial packet)
func (p *SFTPParser) Parse(data []byte) []SFTPOperation {
	p.buffer = append(p.buffer, data...)

	var operations []SFTPOperation

	for {
		op, bytesConsumed := p.parseOnePacket()
		if bytesConsumed == 0 {
			break
		}

		// Remove consumed bytes from buffer
		p.buffer = p.buffer[bytesConsumed:]

		if op != nil {
			operations = append(operations, *op)
		}
	}

	// Compact buffer to release consumed memory
	// Without this, the backing array grows indefinitely during long sessions
	if len(p.buffer) > 0 {
		p.buffer = append([]byte(nil), p.buffer...)
	} else {
		p.buffer = p.buffer[:0]
	}

	return operations
}

// parseOnePacket attempts to parse a single SFTP packet from the buffer
// Returns the operation (if relevant) and number of bytes consumed
func (p *SFTPParser) parseOnePacket() (*SFTPOperation, int) {
	// Need at least 5 bytes: 4 for length + 1 for type
	if len(p.buffer) < 5 {
		return nil, 0
	}

	// Read packet length (does not include the length field itself)
	packetLen := binary.BigEndian.Uint32(p.buffer[0:4])

	// Sanity check - SFTP packets shouldn't be huge
	if packetLen > 256*1024 {
		// Likely corrupted or not SFTP - skip one byte and try again
		return nil, 1
	}

	// Check if we have the full packet
	totalLen := 4 + int(packetLen)
	if len(p.buffer) < totalLen {
		return nil, 0
	}

	// Parse packet type
	packetType := p.buffer[4]

	// Parse based on type
	op := p.parsePacketByType(packetType, p.buffer[5:totalLen])

	return op, totalLen
}

// parsePacketByType parses the packet payload based on its type
// Only parses operations that represent meaningful user actions
func (p *SFTPParser) parsePacketByType(packetType byte, payload []byte) *SFTPOperation {
	switch packetType {
	case sshFxpOpen:
		return p.parseOpenPacket(payload)
	case sshFxpOpendir:
		return p.parsePathedPacket(payload, "OPENDIR")
	case sshFxpRemove:
		return p.parsePathedPacket(payload, "REMOVE")
	case sshFxpMkdir:
		return p.parsePathedPacket(payload, "MKDIR")
	case sshFxpRmdir:
		return p.parsePathedPacket(payload, "RMDIR")
	case sshFxpRename:
		return p.parseRenamePacket(payload)
	case sshFxpSymlink:
		return p.parseSymlinkPacket(payload)
	// Skipping STAT, REALPATH, READLINK as they're metadata operations
	// that happen automatically and aren't meaningful user actions
	default:
		return nil
	}
}

// SFTP open flags
const (
	sshFxfRead   = 0x00000001
	sshFxfWrite  = 0x00000002
	sshFxfAppend = 0x00000004
	sshFxfCreat  = 0x00000008
	sshFxfTrunc  = 0x00000010
	sshFxfExcl   = 0x00000020
)

// parseOpenPacket parses SSH_FXP_OPEN packet
// Format: uint32 request-id, string filename, uint32 pflags, ATTRS attrs
func (p *SFTPParser) parseOpenPacket(payload []byte) *SFTPOperation {
	// Skip request-id (4 bytes)
	if len(payload) < 4 {
		return nil
	}

	path, n := readString(payload[4:])
	if path == "" || n == 0 {
		return nil
	}

	// Read pflags (4 bytes after request-id and path)
	flagsOffset := 4 + n
	if len(payload) < flagsOffset+4 {
		return &SFTPOperation{
			Type: "OPEN",
			Path: path,
		}
	}

	pflags := binary.BigEndian.Uint32(payload[flagsOffset : flagsOffset+4])
	isWrite := (pflags & (sshFxfWrite | sshFxfCreat | sshFxfTrunc | sshFxfAppend)) != 0

	return &SFTPOperation{
		Type:    "OPEN",
		Path:    path,
		IsWrite: isWrite,
	}
}

// parsePathedPacket parses packets that have: uint32 request-id, string path
func (p *SFTPParser) parsePathedPacket(payload []byte, opType string) *SFTPOperation {
	if len(payload) < 4 {
		return nil
	}

	path, _ := readString(payload[4:])
	if path == "" {
		return nil
	}

	return &SFTPOperation{
		Type: opType,
		Path: path,
	}
}

// parseRenamePacket parses SSH_FXP_RENAME packet
// Format: uint32 request-id, string oldpath, string newpath
func (p *SFTPParser) parseRenamePacket(payload []byte) *SFTPOperation {
	if len(payload) < 4 {
		return nil
	}

	oldPath, n := readString(payload[4:])
	if oldPath == "" || n == 0 {
		return nil
	}

	newPath, _ := readString(payload[4+n:])
	if newPath == "" {
		return nil
	}

	return &SFTPOperation{
		Type:     "RENAME",
		Path:     oldPath,
		DestPath: newPath,
	}
}

// parseSymlinkPacket parses SSH_FXP_SYMLINK packet
// Format: uint32 request-id, string linkpath, string targetpath
func (p *SFTPParser) parseSymlinkPacket(payload []byte) *SFTPOperation {
	if len(payload) < 4 {
		return nil
	}

	linkPath, n := readString(payload[4:])
	if linkPath == "" || n == 0 {
		return nil
	}

	targetPath, _ := readString(payload[4+n:])
	if targetPath == "" {
		return nil
	}

	return &SFTPOperation{
		Type:     "SYMLINK",
		Path:     targetPath,
		DestPath: linkPath,
	}
}

// readString reads an SFTP string (uint32 length + data)
// Returns the string and total bytes consumed
func readString(data []byte) (string, int) {
	if len(data) < 4 {
		return "", 0
	}

	strLen := binary.BigEndian.Uint32(data[0:4])

	// Sanity check
	if strLen > 4096 || int(strLen) > len(data)-4 {
		return "", 0
	}

	return string(data[4 : 4+strLen]), 4 + int(strLen)
}

// FormatOperation formats an SFTP operation for user-friendly logging
func FormatOperation(op SFTPOperation) string {
	switch op.Type {
	case "OPEN":
		if op.IsWrite {
			return fmt.Sprintf("Uploaded file: %s", op.Path)
		}
		return fmt.Sprintf("Downloaded file: %s", op.Path)
	case "OPENDIR":
		return fmt.Sprintf("Listed directory: %s", op.Path)
	case "MKDIR":
		return fmt.Sprintf("Created directory: %s", op.Path)
	case "RMDIR":
		return fmt.Sprintf("Removed directory: %s", op.Path)
	case "REMOVE":
		return fmt.Sprintf("Deleted file: %s", op.Path)
	case "RENAME":
		return fmt.Sprintf("Renamed: %s → %s", op.Path, op.DestPath)
	case "SYMLINK":
		return fmt.Sprintf("Created link: %s → %s", op.DestPath, op.Path)
	default:
		return fmt.Sprintf("%s: %s", op.Type, op.Path)
	}
}
