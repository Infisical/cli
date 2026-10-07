package certscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type fakeFile struct {
	realPath string
	data     []byte
	rootOnly bool
}

type runHook func(ctx context.Context) (RunResult, error)

type fakeRunner struct {
	mu            sync.Mutex
	sudo          bool
	files         map[string]fakeFile
	find          string
	findErr       string
	findTruncated bool
	findExitCode  int
	findHook      runHook
	sudoFind      string
	sudoFindHook  runHook
	sudoFinds     map[string]runHook
	readHooks     map[string]runHook
	batchHook     func(context.Context, RunResult) (RunResult, error)
	commands      []string
}

func (f *fakeRunner) Run(ctx context.Context, command string, _ int) (RunResult, error) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	switch {
	case strings.Contains(command, "uname -n"):
		out := "H:web-01\nM:abc\nT:1\n"
		if f.sudo {
			out += "S:1\n"
		}
		return RunResult{Stdout: []byte(out)}, nil
	case strings.Contains(command, "sudo -n find -L"):
		for folder, hook := range f.sudoFinds {
			if strings.Contains(command, "find -L "+util.ShellQuote(folder)+" ") {
				return hook(ctx)
			}
		}
		if f.sudoFindHook != nil {
			return f.sudoFindHook(ctx)
		}
		return RunResult{Stdout: []byte(f.sudoFind)}, nil
	case strings.Contains(command, "find -L") && f.findHook != nil:
		return f.findHook(ctx)
	case strings.Contains(command, "find -L"):
		exitCode := 1
		if f.findExitCode != 0 {
			exitCode = f.findExitCode
		}
		return RunResult{Stdout: []byte(f.find), Stderr: []byte(f.findErr), ExitCode: exitCode, Truncated: f.findTruncated}, nil
	case strings.Contains(command, "sh -c "):
		res := f.readBatch(command)
		if f.batchHook != nil {
			return f.batchHook(ctx, res)
		}
		return res, nil
	case strings.Contains(command, "readlink -f"):
		for p, hook := range f.readHooks {
			if strings.Contains(command, util.ShellQuote(p)) {
				return hook(ctx)
			}
		}
		sudo := strings.Contains(command, "sudo -n readlink")
		for p, file := range f.files {
			if !strings.Contains(command, util.ShellQuote(p)) {
				continue
			}
			if file.rootOnly && !sudo {
				return RunResult{Stderr: []byte("head: cannot open: Permission denied"), ExitCode: 1}, nil
			}
			return RunResult{Stdout: append([]byte(file.realPath+"\n"), file.data...)}, nil
		}
		return RunResult{Stderr: []byte("readlink: No such file or directory"), ExitCode: 1}, nil
	}
	return RunResult{ExitCode: 127}, nil
}

func shellWords(command string) []string {
	var words []string
	var word strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case quoted && c == '\'':
			quoted = false
		case quoted:
			word.WriteByte(c)
		case c == '\'':
			quoted, inWord = true, true
		case c == '\\' && i+1 < len(command):
			i++
			word.WriteByte(command[i])
			inWord = true
		case c == ' ':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

func wordsAfter(command, marker string) []string {
	words := shellWords(command)
	for i, w := range words {
		if w == marker {
			return words[i+1:]
		}
	}
	return nil
}

func base64Lines(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\n")
		encoded = encoded[76:]
	}
	if encoded != "" {
		b.WriteString(encoded + "\n")
	}
	return b.String()
}

var batchLimitPattern = regexp.MustCompile(`head -c (\d+) -- "\$f"; echo`)

func (f *fakeRunner) readBatch(command string) RunResult {
	args := wordsAfter(command, "-c")
	limit, _ := strconv.Atoi(batchLimitPattern.FindStringSubmatch(args[0])[1])
	var out strings.Builder
	for j, p := range args[2:] {
		if _, hooked := f.readHooks[p]; hooked {
			continue
		}
		fmt.Fprintf(&out, "\x1eF%d\n", j)
		file, ok := f.files[p]
		switch {
		case !ok:
			fmt.Fprintf(&out, "\x1eRhead: cannot open '%s' for reading: No such file or directory\n", p)
		case file.rootOnly:
			fmt.Fprintf(&out, "\x1eRhead: cannot open '%s' for reading: Permission denied\n", p)
		default:
			data := file.data[:min(len(file.data), limit)]
			fmt.Fprintf(&out, "\x1eK\n%s\x1eD\n%s\x1eE0\n", base64Lines([]byte(file.realPath+"\n")), base64Lines(data))
		}
	}
	return RunResult{Stdout: []byte(out.String())}
}

func normalizedScan(t *testing.T, ctx context.Context, runner Runner, req Request) (Response, error) {
	t.Helper()
	if req.MaxFolderDepth == 0 {
		req.MaxFolderDepth = 8
	}
	if req.MaxFileSizeBytes == 0 {
		req.MaxFileSizeBytes = 512 * 1024
	}
	if err := Normalize(&req); err != nil {
		t.Fatal(err)
	}
	return Scan(ctx, runner, req)
}

func TestScanFindsDedupesAndRetriesWithSudo(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	big := make([]byte, 2048)
	runner := &fakeRunner{
		sudo: true,
		files: map[string]fakeFile{
			"/etc/ssl/api.pem":                 {realPath: "/etc/ssl/api.pem", data: leafPEM},
			"/etc/ssl/link.pem":                {realPath: "/etc/ssl/api.pem", data: leafPEM},
			"/etc/ssl/huge.pem":                {realPath: "/etc/ssl/huge.pem", data: big},
			"/etc/ssl/private.key.pem":         {realPath: "/etc/ssl/private.key.pem", data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
			"/etc/letsencrypt/live/x/cert.pem": {realPath: "/etc/letsencrypt/live/x/cert.pem", data: leafPEM, rootOnly: true},
		},
		find:     "/etc/ssl/api.pem\x00/etc/ssl/link.pem\x00/etc/ssl/huge.pem\x00/etc/ssl/private.key.pem\x00",
		findErr:  "find: '/etc/letsencrypt/live': Permission denied\n",
		sudoFind: "/etc/letsencrypt/live/x/cert.pem\x00",
	}
	resp, err := normalizedScan(t, context.Background(), runner, Request{
		SearchFolderPaths: []string{"/etc/ssl", "/etc/letsencrypt"},
		MaxFileSizeBytes:  1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Host.Hostname != "web-01" {
		t.Fatalf("unexpected host %+v", resp.Host)
	}
	byPath := map[string]FileResult{}
	for _, f := range resp.Files {
		byPath[f.RealPath] = f
	}
	if byPath["/etc/ssl/api.pem"].Status != StatusOK {
		t.Fatalf("unexpected api file %+v", byPath["/etc/ssl/api.pem"])
	}
	for _, f := range resp.Files {
		if f.Path == "/etc/ssl/link.pem" {
			t.Fatal("a symlink to a file already reported must not be reported again")
		}
	}
	if byPath["/etc/ssl/huge.pem"].Status != StatusTooLarge {
		t.Fatalf("expected tooLarge, got %+v", byPath["/etc/ssl/huge.pem"])
	}
	if _, ok := byPath["/etc/ssl/private.key.pem"]; ok {
		t.Fatal("files without certificates must be left out of a folder scan")
	}
	le := byPath["/etc/letsencrypt/live/x/cert.pem"]
	if le.Status != StatusOK {
		t.Fatalf("expected sudo read, got %+v", le)
	}
	if len(resp.DeniedFolders) != 0 {
		t.Fatalf("expected no denied folders after sudo, got %v", resp.DeniedFolders)
	}
}

func TestScanWithoutSudoReportsDenied(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	runner := &fakeRunner{
		files: map[string]fakeFile{
			"/etc/ssl/secret.pem": {realPath: "/etc/ssl/secret.pem", data: leafPEM, rootOnly: true},
		},
		find:    "/etc/ssl/secret.pem\x00",
		findErr: "find: '/etc/ssl/private': Permission denied\n",
	}
	resp, err := normalizedScan(t, context.Background(), runner, Request{SearchFolderPaths: []string{"/etc/ssl"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Files) != 1 || resp.Files[0].Status != StatusAccessDenied {
		t.Fatalf("expected accessDenied, got %+v", resp.Files)
	}
	if len(resp.DeniedFolders) != 1 || resp.DeniedFolders[0] != "/etc/ssl/private" {
		t.Fatalf("unexpected denied %v", resp.DeniedFolders)
	}
	for _, c := range runner.commands[1:] {
		if strings.Contains(c, "sudo -n readlink") || strings.Contains(c, "sudo -n find") {
			t.Fatalf("sudo must not be used when unavailable: %s", c)
		}
	}
}

func TestScanExplicitFileUsesPassword(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	runner := &fakeRunner{files: map[string]fakeFile{"/opt/app/a.pem": {realPath: "/opt/app/a.pem", data: leafPEM}}}
	resp, err := normalizedScan(t, context.Background(), runner, Request{FilePaths: []string{"/opt/app/a.pem", "/opt/app/missing.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Files) != 2 {
		t.Fatalf("explicit files must always be reported, got %+v", resp.Files)
	}
	for _, c := range runner.commands {
		if strings.Contains(c, "find -L") {
			t.Fatal("explicit file scans must not walk folders")
		}
	}
}

func TestNormalizeRejectsBadInput(t *testing.T) {
	if err := Normalize(&Request{}); err == nil {
		t.Fatal("expected an error without folders or files")
	}
	if err := Normalize(&Request{SearchFolderPaths: []string{"/etc"}, MaxFolderDepth: 50, MaxFileSizeBytes: 1024}); err == nil {
		t.Fatal("expected an error for a depth over the limit")
	}
}

func TestReadCommandOpensFileBeforeResolvingIt(t *testing.T) {
	s := &scanner{hasTimeout: true}
	cmd := readCommand("/etc/ssl/private/a b.pem", 1024, s.commandPrefix(readTimeout, true))
	want := `timeout -s KILL 20 sudo -n head -c 0 -- '/etc/ssl/private/a b.pem' && timeout -s KILL 20 sudo -n readlink -f -- '/etc/ssl/private/a b.pem' && timeout -s KILL 20 sudo -n head -c 1025 -- '/etc/ssl/private/a b.pem'`
	if cmd != want {
		t.Fatalf("got %s", cmd)
	}
}

func TestCommandsRunInTheCLocale(t *testing.T) {
	runner := &fakeRunner{files: map[string]fakeFile{"/opt/a.pem": {realPath: "/opt/a.pem", data: []byte("x")}}}
	if _, err := normalizedScan(t, context.Background(), runner, Request{FilePaths: []string{"/opt/a.pem"}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range runner.commands {
		if strings.Contains(c, "readlink -f") && !strings.HasPrefix(c, "export LC_ALL=C; ") {
			t.Fatalf("expected the read to run in the C locale, got %q", c)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureScanLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	previous := log.Logger
	log.Logger = zerolog.New(buf)
	t.Cleanup(func() { log.Logger = previous })
	return buf
}

func waitForDeadline(ctx context.Context) (RunResult, error) {
	<-ctx.Done()
	return RunResult{}, fmt.Errorf("command did not finish: %w", context.Cause(ctx))
}

func TestScanReportsReadFailuresWithoutRawTransportText(t *testing.T) {
	logs := captureScanLogs(t)
	runner := &fakeRunner{files: map[string]fakeFile{"/opt/e.pem": {realPath: "/opt/e.pem", data: []byte("\xff0")}}, readHooks: map[string]runHook{
		"/opt/a.pem": func(context.Context) (RunResult, error) {
			return RunResult{}, errors.New("ssh: session failed: use of closed network connection")
		},
		"/opt/b.pem": func(context.Context) (RunResult, error) {
			return RunResult{Stderr: []byte("head: error reading '/opt/b.pem': Input/output error"), ExitCode: 1}, nil
		},
		"/opt/c.pem": func(context.Context) (RunResult, error) {
			return RunResult{Stdout: []byte("no newline")}, nil
		},
		"/opt/d.pem": func(context.Context) (RunResult, error) {
			panic("boom from read")
		},
	}}
	resp, err := normalizedScan(t, context.Background(), runner, Request{FilePaths: []string{"/opt/a.pem", "/opt/b.pem", "/opt/c.pem", "/opt/d.pem", "/opt/e.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Files) != 5 {
		t.Fatalf("expected every explicit file to be reported, got %+v", resp.Files)
	}
	for _, f := range resp.Files {
		if f.Status != StatusReadFailed {
			t.Fatalf("expected readFailed, got %+v", f)
		}
	}
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), "closed network connection") || strings.Contains(string(encoded), "Input/output error") {
		t.Fatalf("raw transport text leaked into the response: %s", encoded)
	}
	if resp.TruncatedReason != "" {
		t.Fatalf("read failures must not mark the scan truncated, got %q", resp.TruncatedReason)
	}
	if !strings.Contains(logs.String(), "recovered from panic while reading a file") || !strings.Contains(logs.String(), "boom from read") || !strings.Contains(logs.String(), "index out of range") {
		t.Fatalf("expected the panic to be logged, got %q", logs.String())
	}
}

func TestScanDeadlineMarksTimeLimitAndDropsUnreadFiles(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	hooks := map[string]runHook{}
	paths := []string{"/opt/a.pem"}
	for _, name := range []string{"b", "c", "d", "e", "f", "g"} {
		path := "/opt/" + name + ".pem"
		hooks[path] = waitForDeadline
		paths = append(paths, path)
	}
	runner := &fakeRunner{
		files:     map[string]fakeFile{"/opt/a.pem": {realPath: "/opt/a.pem", data: leafPEM}},
		readHooks: hooks,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	resp, err := normalizedScan(t, ctx, runner, Request{FilePaths: paths})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TruncatedReason != TruncatedTimeLimit {
		t.Fatalf("expected a timeLimit truncation, got %q", resp.TruncatedReason)
	}
	if len(resp.Files) != 1 || resp.Files[0].Path != "/opt/a.pem" || resp.Files[0].Status != StatusOK {
		t.Fatalf("files cut by the deadline must not be reported, got %+v", resp.Files)
	}
	if len(resp.Files) != 1 {
		t.Fatalf("expected one file, got %+v", resp.Files)
	}
}

func TestMarkTruncatedKeepsFirstReason(t *testing.T) {
	var resp Response
	resp.markTruncated(TruncatedFileList)
	resp.markTruncated(TruncatedMaxFiles)
	if resp.TruncatedReason != TruncatedFileList {
		t.Fatalf("expected the first reason to win, got %q", resp.TruncatedReason)
	}
}

func TestScanSudoFindFailuresAreNotReportedAsDenied(t *testing.T) {
	cases := []struct {
		name       string
		hook       runHook
		timeout    time.Duration
		wantDenied bool
		wantReason TruncatedReason
	}{
		{
			name: "transport error",
			hook: func(context.Context) (RunResult, error) {
				return RunResult{}, errors.New("ssh: session failed")
			},
		},
		{
			name: "unrelated failure",
			hook: func(context.Context) (RunResult, error) {
				return RunResult{Stderr: []byte("find: memory exhausted"), ExitCode: 1}, nil
			},
		},
		{
			name:       "deadline",
			hook:       waitForDeadline,
			timeout:    200 * time.Millisecond,
			wantReason: TruncatedTimeLimit,
		},
		{
			name: "sudo refused",
			hook: func(context.Context) (RunResult, error) {
				return RunResult{Stderr: []byte("sudo: a password is required"), ExitCode: 1}, nil
			},
			wantDenied: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{
				sudo:         true,
				findErr:      "find: '/etc/private': Permission denied\n",
				sudoFindHook: tc.hook,
			}
			ctx := context.Background()
			if tc.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}
			resp, err := normalizedScan(t, ctx, runner, Request{SearchFolderPaths: []string{"/etc"}})
			if err != nil {
				t.Fatal(err)
			}
			if denied := len(resp.DeniedFolders) == 1 && resp.DeniedFolders[0] == "/etc/private"; denied != tc.wantDenied || !tc.wantDenied && len(resp.DeniedFolders) != 0 {
				t.Fatalf("unexpected denied folders %v", resp.DeniedFolders)
			}
			if resp.TruncatedReason != tc.wantReason {
				t.Fatalf("unexpected truncation %q", resp.TruncatedReason)
			}
		})
	}
}

func TestClassifyReadFailureDefaultsToReadFailed(t *testing.T) {
	if got := classifyReadFailure([]byte("head: error reading: Input/output error")); got != StatusReadFailed {
		t.Fatalf("expected readFailed, got %s", got)
	}
	if got := classifyReadFailure([]byte("head: cannot open: Permission denied")); got != StatusAccessDenied {
		t.Fatalf("expected accessDenied, got %s", got)
	}
}

func TestScanMarksAFindKilledByTheRemoteTimeout(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	runner := &fakeRunner{
		files:        map[string]fakeFile{"/etc/ssl/a.pem": {realPath: "/etc/ssl/a.pem", data: leafPEM}},
		find:         "/etc/ssl/a.pem\x00/etc/ssl/b",
		findExitCode: timeoutKilledExitCode,
	}
	resp, err := normalizedScan(t, context.Background(), runner, Request{SearchFolderPaths: []string{"/etc/ssl"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TruncatedReason != TruncatedTimeLimit {
		t.Fatalf("expected a timeLimit truncation, got %q", resp.TruncatedReason)
	}
	if len(resp.Files) != 1 || resp.Files[0].Path != "/etc/ssl/a.pem" {
		t.Fatalf("expected only the complete path, got %+v", resp.Files)
	}
}

func TestScanMarksASudoFindKilledByTheRemoteTimeout(t *testing.T) {
	runner := &fakeRunner{
		sudo:    true,
		find:    "",
		findErr: "find: '/etc/private': Permission denied\n",
		sudoFindHook: func(context.Context) (RunResult, error) {
			return RunResult{ExitCode: timeoutKilledExitCode}, nil
		},
	}
	resp, err := normalizedScan(t, context.Background(), runner, Request{SearchFolderPaths: []string{"/etc"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TruncatedReason != TruncatedTimeLimit {
		t.Fatalf("expected a timeLimit truncation, got %q", resp.TruncatedReason)
	}
}

func TestScanKeepsPathsFromAFindCutOffByTheGatewayLimit(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	runner := &fakeRunner{
		files: map[string]fakeFile{"/etc/ssl/a.pem": {realPath: "/etc/ssl/a.pem", data: leafPEM}},
		findHook: func(context.Context) (RunResult, error) {
			return RunResult{Stdout: []byte("/etc/ssl/a.pem\x00/etc/ssl/b")}, fmt.Errorf("command did not finish: %w", context.DeadlineExceeded)
		},
	}
	resp, err := normalizedScan(t, context.Background(), runner, Request{SearchFolderPaths: []string{"/etc/ssl"}})
	if err != nil {
		t.Fatalf("expected the partial listing to be scanned, got %v", err)
	}
	if resp.TruncatedReason != TruncatedTimeLimit || len(resp.Files) != 1 || resp.Files[0].Path != "/etc/ssl/a.pem" {
		t.Fatalf("expected a timeLimit truncation with the complete path, got %q %+v", resp.TruncatedReason, resp.Files)
	}
}

func commandsContaining(commands []string, needle string) []string {
	var matched []string
	for _, c := range commands {
		if strings.Contains(c, needle) {
			matched = append(matched, c)
		}
	}
	return matched
}

const perFileRead = "readlink -f -- '"

func TestScanReadsUnprivilegedFilesInOneBatch(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	runner := &fakeRunner{files: map[string]fakeFile{
		"/opt/a.pem":   {realPath: "/opt/a.pem", data: leafPEM},
		"/opt/b.pem":   {realPath: "/opt/b.pem", data: leafPEM},
		"/opt/big.pem": {realPath: "/opt/big.pem", data: make([]byte, 1025)},
		"/opt/fit.pem": {realPath: "/opt/fit.pem", data: append(leafPEM, make([]byte, 1024-len(leafPEM))...)},
	}}
	resp, err := normalizedScan(t, context.Background(), runner, Request{
		FilePaths:        []string{"/opt/a.pem", "/opt/b.pem", "/opt/big.pem", "/opt/fit.pem", "/opt/missing.pem"},
		MaxFileSizeBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	batches := commandsContaining(runner.commands, "sh -c ")
	if len(batches) != 1 || !strings.HasPrefix(batches[0], "export LC_ALL=C; timeout -s KILL 60 sh -c ") {
		t.Fatalf("expected one bounded batch read, got %q", batches)
	}
	if reads := commandsContaining(runner.commands, perFileRead); len(reads) != 0 {
		t.Fatalf("expected no per-file reads, got %q", reads)
	}
	want := map[string]FileStatus{"/opt/a.pem": StatusOK, "/opt/b.pem": StatusOK, "/opt/big.pem": StatusTooLarge, "/opt/fit.pem": StatusOK, "/opt/missing.pem": StatusNotFound}
	if len(resp.Files) != len(want) {
		t.Fatalf("expected %d files, got %+v", len(want), resp.Files)
	}
	for _, f := range resp.Files {
		if f.Status != want[f.Path] || f.RealPath != f.Path {
			t.Fatalf("unexpected result %+v", f)
		}
	}
}

func TestScanFallsBackToPerFileReadsForIncompleteBatchRecords(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	cutAfterFirstRecord := func(res RunResult) []byte {
		end := bytes.Index(res.Stdout, []byte("\x1eF1\n"))
		return res.Stdout[:end+len("\x1eF1\n\x1eK\nL29w")]
	}
	cases := []struct {
		name          string
		hook          func(context.Context, RunResult) (RunResult, error)
		wantFallbacks int
	}{
		{"truncated output", func(_ context.Context, res RunResult) (RunResult, error) {
			return RunResult{Stdout: cutAfterFirstRecord(res), Truncated: true}, nil
		}, 2},
		{"killed by the remote timeout", func(_ context.Context, res RunResult) (RunResult, error) {
			return RunResult{Stdout: cutAfterFirstRecord(res), ExitCode: timeoutKilledExitCode}, nil
		}, 2},
		{"transport error", func(_ context.Context, res RunResult) (RunResult, error) {
			return res, errors.New("ssh: session failed")
		}, 3},
		{"head failed mid-read", func(_ context.Context, res RunResult) (RunResult, error) {
			res.Stdout = bytes.Replace(res.Stdout, []byte("\x1eE0\n"), []byte("\x1eE1\n"), 1)
			return res, nil
		}, 1},
		{"corrupt base64", func(_ context.Context, res RunResult) (RunResult, error) {
			res.Stdout = bytes.Replace(res.Stdout, []byte("\x1eD\n"), []byte("\x1eD\n#\n"), 1)
			return res, nil
		}, 1},
		{"records out of order", func(_ context.Context, res RunResult) (RunResult, error) {
			res.Stdout = bytes.Replace(res.Stdout, []byte("\x1eF1\n"), []byte("\x1eF0\n"), 1)
			return res, nil
		}, 2},
		{"unexpected framing", func(_ context.Context, res RunResult) (RunResult, error) {
			return RunResult{Stdout: append([]byte("noise\n"), res.Stdout...)}, nil
		}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{
				files: map[string]fakeFile{
					"/opt/a.pem": {realPath: "/opt/a.pem", data: leafPEM},
					"/opt/b.pem": {realPath: "/opt/b.pem", data: leafPEM},
					"/opt/c.pem": {realPath: "/opt/c.pem", data: leafPEM},
				},
				batchHook: tc.hook,
			}
			resp, err := normalizedScan(t, context.Background(), runner, Request{FilePaths: []string{"/opt/a.pem", "/opt/b.pem", "/opt/c.pem"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(resp.Files) != 3 || resp.TruncatedReason != "" {
				t.Fatalf("expected every file to be reported, got %q %+v", resp.TruncatedReason, resp.Files)
			}
			for _, f := range resp.Files {
				if f.Status != StatusOK || len(f.Chains) == 0 {
					t.Fatalf("expected a complete read, got %+v", f)
				}
			}
			if reads := commandsContaining(runner.commands, perFileRead); len(reads) != tc.wantFallbacks {
				t.Fatalf("expected %d per-file reads, got %q", tc.wantFallbacks, reads)
			}
		})
	}
}

func TestScanEscalatesABatchAccessDeniedStraightToSudo(t *testing.T) {
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	runner := &fakeRunner{
		sudo: true,
		files: map[string]fakeFile{
			"/opt/a.pem":    {realPath: "/opt/a.pem", data: leafPEM},
			"/opt/root.pem": {realPath: "/opt/root.pem", data: leafPEM, rootOnly: true},
		},
	}
	resp, err := normalizedScan(t, context.Background(), runner, Request{FilePaths: []string{"/opt/a.pem", "/opt/root.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Files) != 2 || resp.Files[0].Status != StatusOK || resp.Files[1].Status != StatusOK {
		t.Fatalf("unexpected files %+v", resp.Files)
	}
	reads := commandsContaining(runner.commands, perFileRead)
	if len(reads) != 1 || !strings.Contains(reads[0], "sudo -n head -c 0 -- '/opt/root.pem'") {
		t.Fatalf("expected a single sudo read, got %q", reads)
	}
}

func TestUnprivilegedBatchesBoundCountAndArgumentBytes(t *testing.T) {
	s := &scanner{sudoPaths: map[string]bool{"/sudo.pem": true}}
	long := "/" + strings.Repeat("x", batchArgumentBytes/2)
	batches := s.unprivilegedBatches([]string{"/a", "/sudo.pem", "/b", "/c", long, long + "y", "/d"}, 3)
	want := [][]int{{0, 2, 3}, {4}, {5, 6}}
	if fmt.Sprint(batches) != fmt.Sprint(want) {
		t.Fatalf("expected %v, got %v", want, batches)
	}
}

func TestScanListsDeniedFoldersConcurrentlyInFolderOrder(t *testing.T) {
	folders := []string{"/etc/a", "/etc/b", "/etc/c", "/etc/d"}
	var inFlight sync.WaitGroup
	inFlight.Add(len(folders))
	allStarted := make(chan struct{})
	go func() {
		inFlight.Wait()
		close(allStarted)
	}()
	hooks := map[string]runHook{}
	var findErr strings.Builder
	for i, folder := range folders {
		findErr.WriteString("find: '" + folder + "': Permission denied\n")
		hooks[folder] = func(ctx context.Context) (RunResult, error) {
			inFlight.Done()
			select {
			case <-allStarted:
			case <-ctx.Done():
				return RunResult{}, ctx.Err()
			}
			time.Sleep(time.Duration(len(folders)-i) * 10 * time.Millisecond)
			return RunResult{
				Stdout:   []byte(folder + "/x.pem\x00"),
				Stderr:   []byte("find: '" + folder + "/deeper': Permission denied\n"),
				ExitCode: 1,
			}, nil
		}
	}
	runner := &fakeRunner{sudo: true, findErr: findErr.String(), sudoFinds: hooks}
	s := &scanner{runner: runner, req: Request{SearchFolderPaths: []string{"/etc"}, MaxFolderDepth: 8}, sudoPaths: map[string]bool{}}
	if _, err := s.probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	paths, denied, reason, err := s.find(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("expected the sudo listings to run concurrently")
	}
	for i, folder := range folders {
		if paths[i] != folder+"/x.pem" || denied[i] != folder+"/deeper" || !s.sudoPaths[paths[i]] {
			t.Fatalf("expected results in folder order, got %v %v", paths, denied)
		}
	}
	if reason != "" {
		t.Fatalf("unexpected truncation %q", reason)
	}
}
