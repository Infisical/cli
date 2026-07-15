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

// Decisions recorded per request. See the design doc's decision table.
const (
	decisionBrokered    = "brokered"
	decisionPassthrough = "passthrough"
	decisionBlocked     = "blocked"
	decisionError       = "error"
)

// Activity-log formats and filters. Values are validated at the CLI layer before reaching Options.
const (
	formatPretty = "pretty"
	formatJSON   = "json"

	filterAll      = "all"
	filterBrokered = "brokered"
	filterErrors   = "errors"
)

// Record envelope. schemaVersion lets consumers' parsers survive additive changes to the record shape;
// eventType makes a record self-identifying when it lands in a stream mixed with other event types.
// Bump activitySchemaVersion whenever the record's field set changes.
const (
	activitySchemaVersion = 1
	activityEventType     = "agent-proxy.request"
)

// activityRecord is one line of the activity log: what the proxy did for a single request. It never carries
// a secret value; path is snapshotted before substitution so it only ever shows the placeholder.
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

// activityLogger serializes activity records to a sink (stdout or a file). Records are emitted from concurrent
// tunnel goroutines, so every write is serialized under the mutex to keep one JSON object per line.
type activityLogger struct {
	enabled bool
	format  string
	filter  string
	sink    string // "stdout" or the file path, for the startup summary
	w       io.Writer
	file    *os.File // non-nil only for a file sink; used to reopen on SIGHUP for log rotation
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

// reopen closes and reopens the file sink so an operator can rotate the log the standard way: logrotate
// renames the file, then its postrotate hook sends SIGHUP and the proxy starts writing to the fresh file.
// A no-op for the stdout sink (containers rely on the platform to rotate). The new file is opened before the
// writer is swapped under the mutex, so a concurrent Record either fully lands in the old file or the new one.
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

// shouldLog applies the decision filter: all logs everything; brokered drops passthrough noise; errors keeps
// only blocked and error.
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

// Record writes one record, honoring enabled state and the filter. A write error is logged and swallowed: it
// must never block or fail a proxied request.
func (l *activityLogger) Record(rec activityRecord) {
	if l == nil || !l.enabled || !l.shouldLog(rec.Decision) {
		return
	}

	var line []byte
	if l.format == formatPretty {
		line = []byte(l.prettyLine(rec))
	} else {
		// json output follows ECS with OTel semantic-convention field names, so it drops into an OTel/Elastic
		// pipeline (or the OTel Collector's filelog receiver) with no field mapping.
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

	// Scope column: a shared proxy serves many projects/envs/paths, so surface which one. The project UUID is
	// truncated since the human just needs to tell projects apart, and the full value is in the json output.
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
	// Strip control bytes before we add our own color codes and newline, so no field (chiefly the
	// agent-influenced path) can inject line breaks or terminal escapes into the human/text log.
	line = stripControl(line)
	if l.colored {
		line = colorForDecision(rec.Decision).Sprint(line)
	}
	return line + "\n"
}

// stripControl removes ASCII control characters (including newlines, CR, and ESC) from a string. Applied to
// the pretty line so untrusted request data can't forge records or emit terminal escape sequences.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// describe is the startup-summary string, e.g. "file(/var/log/activity.log, json) · filter: all" or "off".
func (l *activityLogger) describe() string {
	if l == nil || !l.enabled {
		return "off"
	}
	return fmt.Sprintf("%s(%s) · filter: %s", l.format, l.sink, l.filter)
}

func credShorthand(creds []AppliedCredential) string {
	parts := make([]string, 0, len(creds))
	for _, c := range creds {
		if c.Role == roleCredentialSub {
			parts = append(parts, strings.Join(c.Surfaces, ",")+":"+c.Key)
		} else {
			parts = append(parts, "header:"+c.Key)
		}
	}
	return strings.Join(parts, " ")
}

// ecsDoc is the ECS / OTel-semantic-convention shape of a record. Standard fields use their conventional
// names; everything domain-specific lives under the namespaced "infisical" object, which ECS permits.
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

// ecsOutcome maps our decision to ECS event.outcome. The precise decision is preserved in infisical.decision.
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
