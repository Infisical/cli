package oracle

import (
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
)

// Advanced Negotiation (ANO) handling. Our gateway is configured to REFUSE
// authentication, encryption and data-integrity services on the client-facing leg,
// because the mTLS tunnel between the CLI and the gateway already provides
// confidentiality and integrity. The Supervisor service is accepted with a trivial CID.
//
// On-wire structure (see go-ora/v2/advanced_nego/comm.go):
//
//	outer:          magic(4) | length(2) | version(4) | servCount(2) | flags(1)
//	per service:    serviceType(2) | numSubPackets(2) | errNum(4) | {sub-packets}
//	sub-packet:     length(2) | type(2) | body(length)
//	types:          0=string, 1=bytes, 2=UB1, 3=UB2, 4=UB4, 5=version, 6=status, 7=?

const anoMagic uint32 = 0xDEADBEEF

// Service-type IDs.
const (
	anoServiceAuth       = 1
	anoServiceEncrypt    = 2
	anoServiceIntegrity  = 3
	anoServiceSupervisor = 4
)

// ANO sub-packet types (from comm.go validatePacketHeader).
const (
	anoTypeString  = 0
	anoTypeBytes   = 1
	anoTypeUB1     = 2
	anoTypeUB2     = 3
	anoTypeUB4     = 4
	anoTypeVersion = 5
	anoTypeStatus  = 6
)

const (
	// anoStatusSupervisorOK is what the Supervisor service must respond with.
	anoStatusSupervisorOK uint16 = 31
	// anoStatusAuthRefused is the "I heard you, but I'm declining this service" code.
	anoStatusAuthRefused uint16 = 0xFBFF
)

// ANO version numbers observed in a real RDS Oracle 19c listener's response.
// The outer header version is 0; per-service version sub-packets carry Oracle's own
// version encoding (high byte = major version; bits 12-15 of the second half indicate
// a "modern" service). We mirror these exactly — go-ora's internal constant
// 0xB200200 is client-side and servers don't use it.
const (
	anoOuterVersion          = 0
	anoServiceVersion_Super  = 0x13000000 // supervisor emits this
	anoServiceVersion_Modern = 0x13001000 // auth/encrypt/integrity emit this
)

// handleANOPayload parses an ANO request payload (magic already confirmed at [0:4]) —
// we only skim it to confirm well-formedness — then writes our refusal response.
func handleANOPayload(payload []byte, conn net.Conn, use32BitLen bool) error {
	r := NewTTCReader(payload)
	// Skip outer header: magic(4) + length(2) + version(4) + servCount(2) + flags(1) = 13 bytes
	if _, err := r.GetBytes(13); err != nil {
		return fmt.Errorf("ANO header: %w", err)
	}
	// We intentionally don't walk every sub-packet. The response is what matters,
	// and detecting =REQUIRED would require parsing config state the client also
	// doesn't transmit on the wire. If the client insists on ENCRYPTION_CLIENT=REQUIRED
	// it will validate our refusal response and close itself with ORA-12660.
	return writeANOResponse(conn, use32BitLen)
}

// writeANOResponse sends our refusal: supervisor accepted (status=31) with an empty
// servArray, authentication/encryption/integrity all replied with status/algoID 0 or
// the "not activated" code.
func writeANOResponse(conn net.Conn, use32BitLen bool) error {
	// Build each service body first so we can sum the total length.
	supervisorBody := buildSupervisorService()
	authBody := buildAuthRefusalService()
	encryptBody := buildEncryptRefusalService()
	integrityBody := buildIntegrityRefusalService()

	totalServiceLen := len(supervisorBody) + len(authBody) + len(encryptBody) + len(integrityBody)
	headerLen := 13
	totalLen := headerLen + totalServiceLen

	b := NewTTCBuilder()
	// Outer header
	b.PutUint(uint64(anoMagic), 4, true, false)
	b.PutInt(int64(totalLen), 2, true, false)
	b.PutInt(int64(anoOuterVersion), 4, true, false)
	b.PutInt(4, 2, true, false) // service count = 4
	b.PutBytes(0)               // flags

	// Order matches go-ora's AdvNego.Write(): supervisor, auth, encrypt, integrity
	b.PutBytes(supervisorBody...)
	b.PutBytes(authBody...)
	b.PutBytes(encryptBody...)
	b.PutBytes(integrityBody...)

	resp := b.Bytes()
	log.Info().
		Int("anoRespLen", len(resp)).
		Int("declaredTotalLen", totalLen).
		Str("anoRespHex", fmt.Sprintf("% X", resp)).
		Msg("Oracle ANO response built")

	return writeDataPayload(conn, resp, use32BitLen)
}

// buildSupervisorService returns the supervisor service body: header + version + status(31) +
// UB2Array (CID magic + array of supported service types).
func buildSupervisorService() []byte {
	b := NewTTCBuilder()
	// Service header
	b.PutInt(anoServiceSupervisor, 2, true, false)
	b.PutInt(3, 2, true, false) // 3 sub-packets
	b.PutInt(0, 4, true, false) // errNum
	// Sub 1: version (supervisor uses the _Super variant, observed from RDS)
	writeAnoVersion(b, anoServiceVersion_Super)
	// Sub 2: status = 31 (supervisor OK)
	writeAnoStatus(b, anoStatusSupervisorOK)
	// Sub 3: UB2Array — RDS sends [4, 1] for its 19c listener; mirror that.
	writeAnoUB2Array(b, []int{4, 1})
	return b.Bytes()
}

// buildAuthRefusalService returns the auth service body indicating we refuse auth.
func buildAuthRefusalService() []byte {
	b := NewTTCBuilder()
	b.PutInt(anoServiceAuth, 2, true, false)
	b.PutInt(2, 2, true, false) // 2 sub-packets
	b.PutInt(0, 4, true, false)
	writeAnoVersion(b, anoServiceVersion_Modern)
	writeAnoStatus(b, anoStatusAuthRefused)
	return b.Bytes()
}

// buildEncryptRefusalService returns the encrypt service body indicating no encryption.
// Mirrors go-ora encryptService.readServiceData(): version + UB1(algoID=0).
func buildEncryptRefusalService() []byte {
	b := NewTTCBuilder()
	b.PutInt(anoServiceEncrypt, 2, true, false)
	b.PutInt(2, 2, true, false)
	b.PutInt(0, 4, true, false)
	writeAnoVersion(b, anoServiceVersion_Modern)
	writeAnoUB1(b, 0) // algoID 0 = no encryption
	return b.Bytes()
}

// buildIntegrityRefusalService mirrors encrypt but for data integrity.
func buildIntegrityRefusalService() []byte {
	b := NewTTCBuilder()
	b.PutInt(anoServiceIntegrity, 2, true, false)
	b.PutInt(2, 2, true, false)
	b.PutInt(0, 4, true, false)
	writeAnoVersion(b, anoServiceVersion_Modern)
	writeAnoUB1(b, 0) // algoID 0 = no integrity
	return b.Bytes()
}

// writeAnoVersion emits a version sub-packet: length=4, type=5, body=uint32 BE.
func writeAnoVersion(b *TTCBuilder, version uint32) {
	b.PutInt(4, 2, true, false) // length
	b.PutInt(anoTypeVersion, 2, true, false)
	b.PutUint(uint64(version), 4, true, false)
}

// writeAnoStatus emits a status sub-packet: length=2, type=6, body=uint16 BE.
func writeAnoStatus(b *TTCBuilder, status uint16) {
	b.PutInt(2, 2, true, false)
	b.PutInt(anoTypeStatus, 2, true, false)
	b.PutUint(uint64(status), 2, true, false)
}

// writeAnoUB1 emits a UB1 sub-packet: length=1, type=2, body=byte.
func writeAnoUB1(b *TTCBuilder, v uint8) {
	b.PutInt(1, 2, true, false)
	b.PutInt(anoTypeUB1, 2, true, false)
	b.PutBytes(v)
}

// writeAnoUB2Array emits the supervisor service's UB2Array sub-packet, which has a
// non-standard body framed with the 0xDEADBEEF magic (see comm.go writeUB2Array).
func writeAnoUB2Array(b *TTCBuilder, input []int) {
	b.PutInt(int64(10+len(input)*2), 2, true, false) // length field
	b.PutInt(anoTypeBytes, 2, true, false)           // type = 1 (bytes)
	// Body
	b.PutUint(uint64(anoMagic), 4, true, false)
	b.PutInt(3, 2, true, false) // constant
	b.PutInt(int64(len(input)), 4, true, false)
	for _, v := range input {
		b.PutInt(int64(v), 2, true, false)
	}
}
