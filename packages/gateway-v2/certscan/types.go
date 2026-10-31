package certscan

type FileStatus string

const (
	StatusOK             FileStatus = "ok"
	StatusLocked         FileStatus = "locked"
	StatusPasswordFailed FileStatus = "passwordFailed"
	StatusAccessDenied   FileStatus = "accessDenied"
	StatusNotFound       FileStatus = "notFound"
	StatusTooLarge       FileStatus = "tooLarge"
	StatusParseError     FileStatus = "parseError"
	StatusUnsupported    FileStatus = "unsupported"
	StatusNoCertificates FileStatus = "noCertificates"
	StatusReadFailed     FileStatus = "readFailed"
)

type TruncatedReason string

const (
	TruncatedFileList     TruncatedReason = "fileList"
	TruncatedMaxFiles     TruncatedReason = "maxFiles"
	TruncatedResponseSize TruncatedReason = "responseSize"
	TruncatedTimeLimit    TruncatedReason = "timeLimit"
	TruncatedIncomplete   TruncatedReason = "incomplete"
)

type Format string

const (
	FormatPEM    Format = "pem"
	FormatDER    Format = "der"
	FormatPKCS7  Format = "pkcs7"
	FormatPKCS12 Format = "pkcs12"
	FormatJKS    Format = "jks"
	FormatJCEKS  Format = "jceks"
)

type ChainKind string

const (
	ChainKindLeaf ChainKind = "leaf"
	ChainKindCA   ChainKind = "ca"
)

type Chain struct {
	Kind         ChainKind `json:"kind"`
	Certificates [][]byte  `json:"certificates"`
}

type ParseResult struct {
	Format     Format     `json:"format,omitempty"`
	IsKeystore bool       `json:"isKeystore"`
	Status     FileStatus `json:"status"`
	Chains     []Chain    `json:"chains"`
	Err        string     `json:"-"`
}

type KeystorePassword struct {
	Path     string `json:"path"`
	Password string `json:"password"`
}

type Request struct {
	SearchFolderPaths []string           `json:"searchFolderPaths"`
	SkipFolderPaths   []string           `json:"skipFolderPaths"`
	MaxFolderDepth    int                `json:"maxFolderDepth"`
	MaxFileSizeBytes  int                `json:"maxFileSizeBytes"`
	FilePaths         []string           `json:"filePaths"`
	KeystorePasswords []KeystorePassword `json:"keystorePasswords"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
}

type FileResult struct {
	Path     string `json:"path"`
	RealPath string `json:"realPath"`
	ParseResult
}

type Response struct {
	Host            HostInfo        `json:"host"`
	Files           []FileResult    `json:"files"`
	DeniedFolders   []string        `json:"deniedFolders"`
	TruncatedReason TruncatedReason `json:"truncatedReason,omitempty"`
}
