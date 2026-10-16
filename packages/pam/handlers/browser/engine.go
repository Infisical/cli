package browser

import (
	"context"
	"errors"
	"time"
)

var ErrAtCapacity = errors.New("browser session limit reached")

type BrowserEngine interface {
	Start(ctx context.Context, opts StartOptions) (Session, error)
}

type StartOptions struct {
	SessionID   string
	Width       int
	Height      int
	AllowedHost string
	// The App URL's exact origin, so the credential never reaches another port or plain HTTP.
	CredentialOrigin  string
	CredentialHeaders map[string]string
	HiddenSelectors   []string
	AllowDownloads    bool
	IgnoreTLSErrors   bool
}

type Session interface {
	Navigate(ctx context.Context, url string) error
	Resize(ctx context.Context, width, height int) error
	Input(ctx context.Context, input Input) error
	HandleDialog(ctx context.Context, accept bool, promptText string) error
	ElementAt(ctx context.Context, x, y float64) (Element, error)
	FocusedElement(ctx context.Context) (Element, error)
	// The next frame is produced only once this one is taken, so a slow reader slows the stream.
	Frames() <-chan Frame
	// Ends with EventEnded, then closes.
	Events() <-chan Event
	// reason is one of the End* codes.
	Stop(reason string)
}

type Element struct {
	Label string
	// Typed text isn't recorded: password fields, and frames that can't be seen into.
	Masked bool
}

type Frame struct {
	JPEG []byte
	// The viewport in CSS pixels, which can be larger than the scaled JPEG.
	Width     int
	Height    int
	Timestamp time.Time
}

type EventType string

const (
	EventNavigation     EventType = "navigation"
	EventCursor         EventType = "cursor"
	EventDialog         EventType = "dialog"
	EventDialogClosed   EventType = "dialog_closed"
	EventDownload       EventType = "download"
	EventBlockedRequest EventType = "blocked_request"
	EventHTTPRequest    EventType = "http_request"
	EventHTTPResponse   EventType = "http_response"
	EventEnded          EventType = "ended"
)

type Event struct {
	Type          EventType
	URL           string
	Method        string
	Title         string
	Text          string
	DialogType    string
	DefaultPrompt string
	Accepted      bool
	Request       *HTTPRequest
	Response      *HTTPResponse
}

// Bodies are left out: a login form's body carries the password the input recording masks.
type HTTPRequest struct {
	ID           string
	Method       string
	URL          string
	Headers      map[string]string
	ResourceType string
	BodySize     int
}

type HTTPResponse struct {
	ID         string
	Status     int
	StatusText string
	Headers    map[string]string
	MimeType   string
	BodySize   int
	FromCache  bool
}

type InputType string

const (
	InputMouse InputType = "mouse"
	InputWheel InputType = "wheel"
	InputKey   InputType = "key"
	InputText  InputType = "text"
)

type Input struct {
	Type      InputType
	Action    string
	X         float64
	Y         float64
	Button    string
	Buttons   int // held buttons, so a drag keeps its button down
	Clicks    int
	DeltaX    float64
	DeltaY    float64
	Key       string
	Code      string
	KeyCode   int // Chromium needs it for editing keys such as Backspace
	Modifiers int
	Text      string
}
