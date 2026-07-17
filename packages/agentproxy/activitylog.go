package agentproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

const (
	decisionBrokered    = "brokered"
	decisionPassthrough = "passthrough"
	decisionBlocked     = "blocked"
	decisionError       = "error"
)

const (
	formatPretty = "pretty"
	formatJSON   = "json"

	filterAll      = "all"
	filterBrokered = "brokered"
	filterErrors   = "errors"
)

const (
	activitySchemaVersion = 1
	activityEventType     = "agent-proxy.request"

	maxLoggedPathLen = 2048
)

type activityRecord struct {
	SchemaVersion int                 `json:"schemaVersion"`
	EventType     string              `json:"eventType"`
	OccurredAt    time.Time           `json:"occurredAt"`
	AgentID       string              `json:"agentId"`
	AgentName     *string             `json:"agentName"`
	ProjectID     string              `json:"projectId"`
	Environment   string              `json:"environment"`
	SecretPath    string              `json:"secretPath"`
	ServiceID     *string             `json:"serviceId"`
	ServiceName   *string             `json:"serviceName"`
	Decision      string              `json:"decision"`
	Method        string              `json:"method"`
	Host          string              `json:"host"`
	Port          int                 `json:"port"`
	Path          string              `json:"path"`
	Status        int                 `json:"status"`
	Credentials   []AppliedCredential `json:"credentials"`
}

type activityLogger struct {
	enabled bool
	format  string
	filter  string
	sink    string
	w       io.Writer
	file    *os.File
	colored bool
	mu      sync.Mutex
}

func newActivityLogger(opts Options) (*activityLogger, error) {
	if !opts.ActivityLog {
		return &activityLogger{enabled: false}, nil
	}

	var w io.Writer
	var file *os.File
	isTTY := false
	sink := "stdout"
	if opts.ActivityLogFile != "" {
		f, err := os.OpenFile(opts.ActivityLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("failed to open activity log file %q: %w", opts.ActivityLogFile, err)
		}
		w = f
		file = f
		sink = opts.ActivityLogFile
	} else {
		w = os.Stdout
		isTTY = isatty.IsTerminal(os.Stdout.Fd())
	}

	format := opts.ActivityLogFormat
	if format == "" {
		if isTTY {
			format = formatPretty
		} else {
			format = formatJSON
		}
	}

	filter := opts.ActivityLogFilter
	if filter == "" {
		filter = filterAll
	}

	return &activityLogger{
		enabled: true,
		format:  format,
		filter:  filter,
		sink:    sink,
		w:       w,
		file:    file,
		colored: isTTY && format == formatPretty,
	}, nil
}

// reopen swaps in a freshly opened file so logrotate can rotate via a SIGHUP postrotate hook. No-op for stdout.
func (l *activityLogger) reopen() error {
	if l == nil || !l.enabled || l.file == nil {
		return nil
	}
	f, err := os.OpenFile(l.sink, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to reopen activity log file %q: %w", l.sink, err)
	}
	l.mu.Lock()
	old := l.file
	l.file = f
	l.w = f
	l.mu.Unlock()
	_ = old.Close()
	return nil
}

func (l *activityLogger) shouldLog(decision string) bool {
	switch l.filter {
	case filterErrors:
		return decision == decisionBlocked || decision == decisionError
	case filterBrokered:
		return decision != decisionPassthrough
	default:
		return true
	}
}

func (l *activityLogger) Record(rec activityRecord) {
	if l == nil || !l.enabled || !l.shouldLog(rec.Decision) {
		return
	}

	var line []byte
	if l.format == formatPretty {
		line = []byte(l.prettyLine(rec))
	} else {
		b, err := json.Marshal(toECS(rec))
		if err != nil {
			log.Warn().Err(err).Msg("failed to encode activity record")
			return
		}
		line = append(b, '\n')
	}

	l.mu.Lock()
	_, err := l.w.Write(line)
	l.mu.Unlock()
	if err != nil {
		log.Warn().Err(err).Msg("failed to write activity record")
	}
}

func (l *activityLogger) prettyLine(rec activityRecord) string {
	agent := "-"
	if rec.AgentName != nil && *rec.AgentName != "" {
		agent = *rec.AgentName
	} else if rec.AgentID != "" {
		agent = rec.AgentID
	}
	service := "-"
	if rec.ServiceName != nil && *rec.ServiceName != "" {
		service = *rec.ServiceName
	}

	proj := rec.ProjectID
	if len(proj) > 8 {
		proj = proj[:8] + ".."
	}
	scope := fmt.Sprintf("%s/%s:%s", proj, rec.Environment, rec.SecretPath)

	line := fmt.Sprintf("%s  %-11s  %-16s  %-32s  %-16s  %-5s %s%s  %d  %s",
		rec.OccurredAt.Format("15:04:05"),
		rec.Decision,
		agent,
		scope,
		service,
		rec.Method,
		rec.Host,
		rec.Path,
		rec.Status,
		credShorthand(rec.Credentials),
	)
	line = strings.TrimRight(line, " ")
	line = stripControl(line)
	if l.colored {
		line = colorForDecision(rec.Decision).Sprint(line)
	}
	return line + "\n"
}

// stripControl drops control bytes so untrusted request data can't inject newlines or terminal escapes.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func (l *activityLogger) describe() string {
	if l == nil || !l.enabled {
		return "off"
	}
	return fmt.Sprintf("%s(%s) · filter: %s", l.format, l.sink, l.filter)
}

func credShorthand(creds []AppliedCredential) string {
	parts := make([]string, 0, len(creds))
	for _, c := range creds {
		label := c.Key
		if c.DynamicSecretName != "" {
			label = c.DynamicSecretName + "/" + c.DynamicSecretField
		}
		if c.Role == roleCredentialSub {
			parts = append(parts, strings.Join(c.Surfaces, ",")+":"+label)
		} else {
			parts = append(parts, "header:"+label)
		}
	}
	return strings.Join(parts, " ")
}

type ecsDoc struct {
	Timestamp string       `json:"@timestamp"`
	Event     ecsEvent     `json:"event"`
	HTTP      ecsHTTP      `json:"http"`
	URL       ecsURL       `json:"url"`
	Server    ecsServer    `json:"server"`
	User      *ecsUser     `json:"user,omitempty"`
	Infisical ecsInfisical `json:"infisical"`
}

type ecsEvent struct {
	Kind     string   `json:"kind"`
	Category []string `json:"category"`
	Action   string   `json:"action"`
	Outcome  string   `json:"outcome"`
	Dataset  string   `json:"dataset"`
}

type ecsHTTP struct {
	Request  ecsHTTPRequest  `json:"request"`
	Response ecsHTTPResponse `json:"response"`
}

type ecsHTTPRequest struct {
	Method string `json:"method"`
}

type ecsHTTPResponse struct {
	StatusCode int `json:"status_code"`
}

type ecsURL struct {
	Path string `json:"path"`
}

type ecsServer struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
}

type ecsUser struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ecsService struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ecsProject struct {
	ID string `json:"id"`
}

type ecsInfisical struct {
	SchemaVersion int                 `json:"schema_version"`
	Decision      string              `json:"decision"`
	Project       ecsProject          `json:"project"`
	Environment   string              `json:"environment"`
	SecretPath    string              `json:"secret_path"`
	Service       *ecsService         `json:"service,omitempty"`
	Credentials   []AppliedCredential `json:"credentials,omitempty"`
}

func ecsOutcome(decision string) string {
	switch decision {
	case decisionBrokered, decisionPassthrough:
		return "success"
	case decisionBlocked, decisionError:
		return "failure"
	default:
		return "unknown"
	}
}

func toECS(r activityRecord) ecsDoc {
	d := ecsDoc{
		Timestamp: r.OccurredAt.UTC().Format(time.RFC3339Nano),
		Event: ecsEvent{
			Kind:     "event",
			Category: []string{"network"},
			Action:   r.EventType,
			Outcome:  ecsOutcome(r.Decision),
			Dataset:  "infisical.agent_proxy",
		},
		HTTP:   ecsHTTP{Request: ecsHTTPRequest{Method: r.Method}, Response: ecsHTTPResponse{StatusCode: r.Status}},
		URL:    ecsURL{Path: r.Path},
		Server: ecsServer{Address: r.Host, Port: r.Port},
		Infisical: ecsInfisical{
			SchemaVersion: r.SchemaVersion,
			Decision:      r.Decision,
			Project:       ecsProject{ID: r.ProjectID},
			Environment:   r.Environment,
			SecretPath:    r.SecretPath,
			Credentials:   r.Credentials,
		},
	}
	if r.AgentID != "" || r.AgentName != nil {
		u := &ecsUser{ID: r.AgentID}
		if r.AgentName != nil {
			u.Name = *r.AgentName
		}
		d.User = u
	}
	if r.ServiceID != nil || r.ServiceName != nil {
		s := &ecsService{}
		if r.ServiceID != nil {
			s.ID = *r.ServiceID
		}
		if r.ServiceName != nil {
			s.Name = *r.ServiceName
		}
		d.Infisical.Service = s
	}
	return d
}

func colorForDecision(decision string) *color.Color {
	switch decision {
	case decisionBrokered:
		return color.New(color.FgGreen)
	case decisionBlocked:
		return color.New(color.FgYellow)
	case decisionError:
		return color.New(color.FgRed)
	default:
		return color.New(color.Faint)
	}
}
