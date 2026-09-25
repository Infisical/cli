package gatewayv2

type Pkcs11Module interface {
	Test(slotLabel string, pin []byte) (SlotInfo, error)

	GenerateKeyPair(slotLabel string, pin []byte, keyLabel string, keyAlgorithm string) ([]byte, error)

	GetPublicKey(slotLabel string, pin []byte, keyLabel string) ([]byte, error)

	Sign(slotLabel string, pin []byte, keyLabel string, mechanism string, data []byte, isDigest bool) ([]byte, error)

	Finalize() error
}

type SlotInfo struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Firmware     string `json:"firmware"`
}

type Pkcs11ErrorCode string

const (
	Pkcs11ErrPinIncorrect      Pkcs11ErrorCode = "pin_incorrect"
	Pkcs11ErrPinLocked         Pkcs11ErrorCode = "pin_locked"
	Pkcs11ErrSlotNotFound      Pkcs11ErrorCode = "slot_not_found"
	Pkcs11ErrKeyNotFound       Pkcs11ErrorCode = "key_not_found"
	Pkcs11ErrMechanismInvalid  Pkcs11ErrorCode = "mechanism_invalid"
	Pkcs11ErrDriverUnavailable Pkcs11ErrorCode = "driver_unavailable"
	Pkcs11ErrLoginFailed       Pkcs11ErrorCode = "login_failed"
	Pkcs11ErrNotSupported      Pkcs11ErrorCode = "pkcs11_not_supported"
	Pkcs11ErrBadRequest        Pkcs11ErrorCode = "bad_request"
	Pkcs11ErrInternal          Pkcs11ErrorCode = "internal"
)

type Pkcs11Error struct {
	Code    Pkcs11ErrorCode
	Message string
}

func (e *Pkcs11Error) Error() string {
	return string(e.Code) + ": " + e.Message
}

// Supported keyAlgorithm values.
const (
	KeyAlgorithmRSA2048 = "RSA_2048"
	KeyAlgorithmRSA4096 = "RSA_4096"
	KeyAlgorithmECCP256 = "ECC_P256"
	KeyAlgorithmECCP384 = "ECC_P384"
)

const CapabilityPkcs11 = "pkcs11"
