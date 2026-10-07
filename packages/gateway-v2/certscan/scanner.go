package certscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

const (
	maxFolderDepth   = 20
	maxFileSizeBytes = 10 * 1024 * 1024
	maxFiles         = 5000
	maxResponseBytes = 8 * 1024 * 1024

	timeoutKilledExitCode = 128 + 9

	commandTimeoutGrace = 5 * time.Second

	probeHostnameMarker = "H:"
	probeTimeoutMarker  = "T:"
	probeSudoMarker     = "S:"
	probeSudoCommand    = "sudo -n find / -maxdepth 0"

	readConcurrency     = 4
	sudoFindConcurrency = 4
	probeTimeout        = 30 * time.Second
	findTimeout         = 120 * time.Second
	readTimeout         = 20 * time.Second
	findOutputLimit     = 16 * 1024 * 1024
	probeOutputLimit    = 64 * 1024
	maxSudoListings     = 64
	maxDeniedFolders    = 1000
)

var errResponseFull = errors.New("the scan found more certificate data than one response can hold")

type RunResult struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
}

type Runner interface {
	Run(ctx context.Context, command string, outputLimit int) (RunResult, error)
}

func Normalize(req *Request) error {
	if req.MaxFolderDepth < 1 || req.MaxFolderDepth > maxFolderDepth {
		return fmt.Errorf("folder depth must be between 1 and %d", maxFolderDepth)
	}
	if req.MaxFileSizeBytes < 1 || req.MaxFileSizeBytes > maxFileSizeBytes {
		return fmt.Errorf("file size limit must be between 1 and %d bytes", maxFileSizeBytes)
	}
	if len(req.SearchFolderPaths) == 0 && len(req.FilePaths) == 0 {
		return errors.New("at least one folder or file is required")
	}
	return nil
}

type scanner struct {
	runner     Runner
	req        Request
	retained   atomic.Int64
	stopReads  context.CancelCauseFunc
	claimedMu  sync.Mutex
	claimed    map[string]bool
	hasTimeout bool
	sudo       bool
	sudoPaths  map[string]bool
	passwords  map[string]*string
}

func (s *scanner) commandPrefix(limit time.Duration, sudo bool) string {
	prefix := ""
	if s.hasTimeout {
		prefix = fmt.Sprintf("timeout -s KILL %d ", int(limit.Seconds()))
	}
	if sudo {
		prefix += "sudo -n "
	}
	return prefix
}

func (s *scanner) listFiles(ctx context.Context, command string, outputLimit int) (RunResult, bool, error) {
	res, err := s.run(ctx, command, findTimeout, outputLimit)
	if errors.Is(err, context.DeadlineExceeded) {
		return res, true, nil
	}
	if err != nil {
		return res, false, err
	}
	return res, s.hasTimeout && res.ExitCode == timeoutKilledExitCode, nil
}

func (s *scanner) run(ctx context.Context, command string, limit time.Duration, outputLimit int) (RunResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, limit+commandTimeoutGrace)
	defer cancel()
	return s.runner.Run(runCtx, "export LC_ALL=C; "+command, outputLimit)
}

func probeValue(stdout []byte, prefix string) string {
	for _, line := range strings.Split(string(stdout), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func (s *scanner) probe(ctx context.Context) (HostInfo, error) {
	command := fmt.Sprintf(`printf '%s%%s\n' "$(uname -n 2>/dev/null)"; command -v timeout >/dev/null 2>&1 && echo '%s1'; %s >/dev/null 2>&1 && echo '%s1'; true`,
		probeHostnameMarker, probeTimeoutMarker, probeSudoCommand, probeSudoMarker)
	runCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res, err := s.runner.Run(runCtx, command, probeOutputLimit)
	if err != nil {
		return HostInfo{}, err
	}
	s.hasTimeout = probeValue(res.Stdout, probeTimeoutMarker) == "1"
	s.sudo = probeValue(res.Stdout, probeSudoMarker) == "1"
	return HostInfo{Hostname: probeValue(res.Stdout, probeHostnameMarker)}, nil
}

func (s *scanner) find(ctx context.Context) ([]string, []string, TruncatedReason, error) {
	command := s.commandPrefix(findTimeout, false) + buildFindCommand(s.req.SearchFolderPaths, s.req.SkipFolderPaths, s.req.MaxFolderDepth)
	res, timedOut, err := s.listFiles(ctx, command, findOutputLimit)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to list files: %w", err)
	}
	if !timedOut && res.ExitCode > 1 {
		line, _, _ := strings.Cut(strings.TrimSpace(string(res.Stderr)), "\n")
		return nil, nil, "", fmt.Errorf("failed to list files: exit code %d: %s", res.ExitCode, line)
	}
	paths := parseFindOutput(res.Stdout)
	var reason TruncatedReason
	switch {
	case timedOut:
		reason = TruncatedTimeLimit
	case res.Truncated:
		reason = TruncatedFileList
	}
	denied := parseDeniedFolders(res.Stderr)

	if len(denied) == 0 || !s.sudo {
		return paths, denied, reason, nil
	}

	var stillDenied []string
	if len(denied) > maxSudoListings {
		stillDenied = denied[maxSudoListings:]
		denied = denied[:maxSudoListings]
	}
	listings := make([]sudoListing, len(denied))
	listingOutputLimit := findOutputLimit / len(denied)
	runBounded(ctx, "listing a folder", len(denied), sudoFindConcurrency, func(i int) {
		listings[i] = s.sudoListFolder(ctx, denied[i], listingOutputLimit)
	}, nil)

	for _, listing := range listings {
		if reason == "" && (!listing.ran || listing.timedOut) {
			reason = TruncatedTimeLimit
		}
		for _, p := range listing.paths {
			s.sudoPaths[p] = true
			paths = append(paths, p)
		}
		if reason == "" && listing.truncated {
			reason = TruncatedFileList
		}
		if reason == "" && listing.failed {
			reason = TruncatedIncomplete
		}
		stillDenied = append(stillDenied, listing.denied...)
	}
	return paths, stillDenied, reason, nil
}

type sudoListing struct {
	ran       bool
	failed    bool
	timedOut  bool
	truncated bool
	paths     []string
	denied    []string
}

func (s *scanner) sudoListFolder(ctx context.Context, folder string, outputLimit int) sudoListing {
	depth := remainingDepth(folder, s.req.SearchFolderPaths, s.req.MaxFolderDepth)
	if depth < 0 {
		return sudoListing{ran: true}
	}
	command := s.commandPrefix(findTimeout, true) + buildFindCommand([]string{folder}, s.req.SkipFolderPaths, depth)
	res, timedOut, err := s.listFiles(ctx, command, outputLimit)
	if err != nil {
		log.Debug().Err(err).Str("folder", folder).Msg("certscan: sudo folder listing did not complete")
		return sudoListing{ran: true, failed: true}
	}
	listing := sudoListing{ran: true, timedOut: timedOut}
	if res.ExitCode != 0 && len(res.Stdout) == 0 {
		if classifyReadFailure(res.Stderr) == StatusAccessDenied {
			listing.denied = []string{folder}
		} else {
			listing.failed = true
		}
		return listing
	}
	listing.paths = parseFindOutput(res.Stdout)
	listing.truncated = res.Truncated
	listing.denied = parseDeniedFolders(res.Stderr)
	return listing
}

func runBounded(ctx context.Context, label string, count, limit int, work func(int), onPanic func(int)) {
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range count {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if value := recover(); value != nil {
					log.Error().Str("panic", fmt.Sprint(value)).Bytes("stack", debug.Stack()).Msg("certscan: recovered from panic while " + label)
					if onPanic != nil {
						onPanic(i)
					}
				}
			}()
			work(i)
		}()
	}
	wg.Wait()
}

type readOutcome struct {
	duplicate bool
	realPath  string
	data      []byte
	status    FileStatus
	parsed    ParseResult
}

func classifyReadFailure(stderr []byte) FileStatus {
	text := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(text, "no such file"):
		return StatusNotFound
	case strings.Contains(text, "permission denied"), strings.Contains(text, "password is required"),
		strings.Contains(text, "a terminal is required"), strings.Contains(text, "not allowed"):
		return StatusAccessDenied
	default:
		return StatusReadFailed
	}
}

func readCommand(p string, limit int, prefix string) string {
	quoted := util.ShellQuote(p)
	return fmt.Sprintf("%shead -c 0 -- %s && %sreadlink -f -- %s && %shead -c %d -- %s",
		prefix, quoted, prefix, quoted, prefix, limit+1, quoted)
}

func (s *scanner) readOnce(ctx context.Context, p string, sudo bool) (readOutcome, error) {
	res, err := s.run(ctx, readCommand(p, s.req.MaxFileSizeBytes, s.commandPrefix(readTimeout, sudo)), readTimeout, s.req.MaxFileSizeBytes+64*1024)
	if err != nil {
		return readOutcome{}, err
	}
	if res.ExitCode != 0 {
		status := classifyReadFailure(res.Stderr)
		if status == StatusReadFailed {
			log.Debug().Str("path", p).Int("exitCode", res.ExitCode).Str("stderr", strings.TrimSpace(string(res.Stderr))).Msg("certscan: failed to read file")
		}
		return readOutcome{status: status}, nil
	}
	newline := bytes.IndexByte(res.Stdout, '\n')
	if newline < 0 {
		log.Debug().Str("path", p).Msg("certscan: unexpected read output")
		return readOutcome{status: StatusReadFailed}, nil
	}
	return readOutcome{realPath: string(res.Stdout[:newline]), data: res.Stdout[newline+1:], status: StatusOK}, nil
}

func (s *scanner) read(ctx context.Context, p string, sudo bool) readOutcome {
	outcome, err := s.readOnce(ctx, p, sudo)
	if err != nil {
		return readFailure(ctx, p, err)
	}
	if outcome.status == StatusAccessDenied && s.sudo && !sudo {
		sudoOutcome, sudoErr := s.readOnce(ctx, p, true)
		if sudoErr == nil {
			return sudoOutcome
		}
		if ctx.Err() != nil {
			return readOutcome{}
		}
	}
	return outcome
}

func readFailure(ctx context.Context, p string, err error) readOutcome {
	if ctx.Err() != nil {
		return readOutcome{}
	}
	log.Debug().Err(err).Str("path", p).Msg("certscan: failed to read file")
	return readOutcome{status: StatusReadFailed}
}

func (s *scanner) complete(p string, outcome readOutcome) readOutcome {
	if outcome.realPath == "" {
		outcome.realPath = p
	}
	if outcome.status == StatusOK && len(outcome.data) > s.req.MaxFileSizeBytes {
		outcome.status = StatusTooLarge
	}
	if outcome.status == StatusOK {
		outcome.parsed = Parse(outcome.data, s.passwords[outcome.realPath])
	}
	outcome.data = nil
	if !s.claimRealPath(outcome.realPath) {
		return readOutcome{realPath: outcome.realPath, status: outcome.status, duplicate: true}
	}
	copies := map[*byte][]byte{}
	retained := 0
	for _, chain := range outcome.parsed.Chains {
		for _, certificate := range chain.Certificates {
			if _, seen := copies[&certificate[0]]; !seen {
				copies[&certificate[0]] = nil
				retained += len(certificate)
			}
		}
	}
	if s.retained.Add(int64(retained)) > maxResponseBytes {
		s.stopReads(errResponseFull)
		return readOutcome{}
	}
	for _, chain := range outcome.parsed.Chains {
		for i, certificate := range chain.Certificates {
			if copies[&certificate[0]] == nil {
				copies[&certificate[0]] = bytes.Clone(certificate)
			}
			chain.Certificates[i] = copies[&certificate[0]]
		}
	}
	return outcome
}

func (s *scanner) claimRealPath(realPath string) bool {
	s.claimedMu.Lock()
	defer s.claimedMu.Unlock()
	if s.claimed[realPath] {
		return false
	}
	s.claimed[realPath] = true
	return true
}

func (s *scanner) readAll(ctx context.Context, paths []string) []readOutcome {
	ctx, s.stopReads = context.WithCancelCause(ctx)
	defer s.stopReads(nil)
	outcomes := make([]readOutcome, len(paths))
	escalate := make([]bool, len(paths))
	batches := s.unprivilegedBatches(paths, readBatchSize)
	runBounded(ctx, "reading a batch of files", len(batches), readConcurrency, func(b int) {
		s.readBatch(ctx, paths, batches[b], outcomes, escalate)
	}, nil)

	var pending []int
	for i := range paths {
		if outcomes[i].status == "" {
			pending = append(pending, i)
		}
	}
	runBounded(ctx, "reading a file", len(pending), readConcurrency, func(j int) {
		i := pending[j]
		outcomes[i] = s.complete(paths[i], s.read(ctx, paths[i], s.sudoPaths[paths[i]] || escalate[i]))
	}, func(j int) {
		outcomes[pending[j]] = readOutcome{realPath: paths[pending[j]], status: StatusReadFailed}
	})
	return outcomes
}

const fileResultOverheadBytes = 256

func estimateSize(file FileResult) int {
	size := fileResultOverheadBytes + len(file.Path) + len(file.RealPath)
	for _, chain := range file.Chains {
		for _, certificate := range chain.Certificates {
			size += base64.StdEncoding.EncodedLen(len(certificate)) + 4
		}
	}
	return size
}

func (r *Response) markTruncated(reason TruncatedReason) {
	if r.TruncatedReason == "" {
		r.TruncatedReason = reason
	}
}

func Scan(ctx context.Context, runner Runner, req Request) (Response, error) {
	s := &scanner{runner: runner, req: req, sudoPaths: map[string]bool{}, passwords: map[string]*string{}, claimed: map[string]bool{}}
	for _, kp := range req.KeystorePasswords {
		s.passwords[kp.Path] = &kp.Password
	}

	host, err := s.probe(ctx)
	if err != nil {
		return Response{}, err
	}
	resp := Response{Host: host}

	explicit := len(req.FilePaths) > 0
	candidates := req.FilePaths
	if !explicit {
		found, denied, truncatedReason, findErr := s.find(ctx)
		if findErr != nil {
			return Response{}, findErr
		}
		candidates, resp.DeniedFolders = found, denied
		resp.markTruncated(truncatedReason)
	}

	unique := slices.Clone(candidates)
	slices.Sort(unique)
	unique = slices.Compact(unique)
	if len(unique) > maxFiles {
		unique = unique[:maxFiles]
		resp.markTruncated(TruncatedMaxFiles)
	}

	outcomes := s.readAll(ctx, unique)
	if s.retained.Load() > maxResponseBytes {
		resp.markTruncated(TruncatedResponseSize)
	}

	if len(resp.DeniedFolders) > maxDeniedFolders {
		resp.DeniedFolders = resp.DeniedFolders[:maxDeniedFolders]
		resp.markTruncated(TruncatedIncomplete)
	}
	seenRealPaths := make(map[string]bool)
	size := 0
	for _, folder := range resp.DeniedFolders {
		size += len(folder) + 4
	}
	for i, p := range unique {
		outcome := outcomes[i]
		if outcome.status == "" {
			resp.markTruncated(TruncatedTimeLimit)
			continue
		}
		if outcome.duplicate || seenRealPaths[outcome.realPath] {
			continue
		}

		file := FileResult{Path: p, RealPath: outcome.realPath, ParseResult: outcome.parsed}
		if outcome.status != StatusOK {
			file.Status = outcome.status
		}
		if file.Err != "" {
			log.Debug().Str("path", p).Str("status", string(file.Status)).Str("error", file.Err).Msg("certscan: file was not fully parsed")
		}
		if !explicit && (file.Status == StatusNoCertificates || file.Status == StatusNotFound) {
			continue
		}

		fileSize := estimateSize(file)
		if size+fileSize > maxResponseBytes {
			resp.markTruncated(TruncatedResponseSize)
			break
		}
		size += fileSize
		seenRealPaths[outcome.realPath] = true
		resp.Files = append(resp.Files, file)
	}

	return resp, nil
}
