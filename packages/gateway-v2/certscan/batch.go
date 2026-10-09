package certscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

const (
	batchArgumentBytes      = 64 * 1024
	readBatchSize           = 32
	readBatchTimeout        = 60 * time.Second
	readBatchOutputBytes    = 4 * 1024 * 1024
	readBatchRecordOverhead = 8 * 1024

	batchMarker   = '\x1e'
	batchStart    = 'F'
	batchOK       = 'K'
	batchData     = 'D'
	batchEnd      = 'E'
	batchReadFail = 'R'
)

func (s *scanner) unprivilegedBatches(paths []string, maxCount int) [][]int {
	var batches [][]int
	var current []int
	size := 0
	for i, p := range paths {
		if s.sudoPaths[p] {
			continue
		}
		quoted := len(util.ShellQuote(p)) + 1
		if len(current) > 0 && (len(current) == maxCount || size+quoted > batchArgumentBytes) {
			batches = append(batches, current)
			current, size = nil, 0
		}
		current = append(current, i)
		size += quoted
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

func quotePaths(paths []string, indices []int) string {
	quoted := make([]string, len(indices))
	for j, i := range indices {
		quoted[j] = util.ShellQuote(paths[i])
	}
	return strings.Join(quoted, " ")
}

func readBatchScript(limit int) string {
	return `exec 4>&1; i=0; for f in "$@"; do printf '\036F%d\n' "$i"; i=$((i+1)); ` +
		`if e=$(head -c 0 -- "$f" 2>&1); then printf '\036K\n'; readlink -f -- "$f" | base64; printf '\036D\n'; ` +
		`s=$( { { head -c ` + strconv.Itoa(limit+1) + ` -- "$f"; echo $? >&3; } | base64 >&4; } 3>&1 ); printf '\036E%s\n' "$s"; ` +
		`else printf '\036R%s\n' "$(printf '%s\n' "$e" | head -n 1)"; fi; done`
}

func (s *scanner) readBatchCommand(paths []string, batch []int) string {
	return s.commandPrefix(readBatchTimeout, false) + "sh -c " + util.ShellQuote(readBatchScript(s.req.MaxFileSizeBytes)) + " sh " + quotePaths(paths, batch)
}

func (s *scanner) readBatchOutputLimit() int {
	encoded := base64.StdEncoding.EncodedLen(s.req.MaxFileSizeBytes + 1)
	return max(readBatchOutputBytes, encoded+encoded/76+1) + readBatchSize*readBatchRecordOverhead
}

func (s *scanner) readBatch(ctx context.Context, paths []string, batch []int, outcomes []readOutcome, escalate []bool) {
	res, err := s.run(ctx, s.readBatchCommand(paths, batch), readBatchTimeout, s.readBatchOutputLimit())
	if err != nil {
		log.Debug().Err(err).Int("files", len(batch)).Msg("certscan: batch read did not complete")
		return
	}
	parseReadBatch(res.Stdout, len(batch), func(j int, record batchRecord) {
		if ctx.Err() != nil {
			return
		}
		i := batch[j]
		if !record.read {
			status := classifyReadFailure([]byte(record.errText))
			if status == StatusAccessDenied && s.sudo {
				escalate[i] = true
				return
			}
			outcomes[i] = readOutcome{realPath: paths[i], status: status}
			return
		}
		outcomes[i] = s.complete(paths[i], readOutcome{realPath: record.realPath, data: record.data, status: StatusOK})
	})
}

type batchRecord struct {
	read     bool
	realPath string
	data     []byte
	errText  string
}

type batchState int

const (
	batchIdle batchState = iota
	batchHeader
	batchRealPath
	batchContent
)

func parseReadBatch(stdout []byte, count int, onRecord func(int, batchRecord)) {
	end := bytes.LastIndexByte(stdout, '\n')
	if end < 0 {
		return
	}
	index := -1
	state := batchIdle
	var realPath, data bytes.Buffer
	for _, line := range bytes.Split(stdout[:end], []byte{'\n'}) {
		var tag byte
		var value []byte
		if len(line) > 0 && line[0] == batchMarker {
			if len(line) < 2 {
				return
			}
			tag, value = line[1], line[2:]
		}
		switch {
		case tag == batchStart:
			next, err := strconv.Atoi(string(value))
			if err != nil || next <= index || next >= count {
				return
			}
			index, state = next, batchHeader
			realPath.Reset()
			data.Reset()
		case state == batchHeader && tag == batchOK:
			state = batchRealPath
		case state == batchHeader && tag == batchReadFail:
			state = batchIdle
			onRecord(index, batchRecord{errText: string(value)})
		case state == batchRealPath && tag == 0:
			realPath.Write(line)
		case state == batchRealPath && tag == batchData:
			state = batchContent
		case state == batchContent && tag == 0:
			data.Write(line)
		case state == batchContent && tag == batchEnd:
			state = batchIdle
			if string(value) != "0" {
				continue
			}
			decodedPath, pathErr := base64.StdEncoding.AppendDecode(nil, realPath.Bytes())
			decoded, dataErr := base64.StdEncoding.AppendDecode(nil, data.Bytes())
			if pathErr != nil || dataErr != nil {
				continue
			}
			onRecord(index, batchRecord{read: true, realPath: strings.TrimSuffix(string(decodedPath), "\n"), data: decoded})
		default:
			return
		}
	}
}
