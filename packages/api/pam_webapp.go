package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

type PAMWebDestination struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
}

type PAMWebConnectionDetails struct {
	StartURL             string              `json:"startUrl"`
	StartOrigin          string              `json:"startOrigin"`
	AllowedDestinations  []PAMWebDestination `json:"allowedDestinations"`
	ExtraDenyCIDRs       []string            `json:"extraDenyCidrs"`
	AllowTypedNavigation bool                `json:"allowTypedNavigation"`
}

type PAMWebPolicy struct {
	ReconnectGraceSeconds int `json:"reconnectGraceSeconds"`
	MaxFPS                int `json:"maxFps"`
	JPEGQuality           int `json:"jpegQuality"`
	MaxWidth              int `json:"maxWidth"`
	MaxHeight             int `json:"maxHeight"`
}

type PAMWebStateRequest struct {
	ReportSeq     uint64 `json:"reportSeq"`
	AllocationGen uint32 `json:"allocationGen"`
	ControllerGen uint32 `json:"controllerGen"`
	State         string `json:"state"`
	Reason        string `json:"reason,omitempty"`
	ChunksEmitted int    `json:"chunksEmitted"`
	LastFrameSeq  uint32 `json:"lastFrameSeq"`
	UploadToken   string `json:"uploadToken"`
}

type PAMWebStateResponse struct {
	LeaseSeconds int `json:"leaseSeconds"`

	LeaseUntil time.Time `json:"leaseUntil"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Cancel     bool      `json:"cancel"`
}

type PAMWebGap struct {
	FromElapsedUs int64  `json:"fromElapsedUs"`
	ToElapsedUs   int64  `json:"toElapsedUs"`
	Reason        string `json:"reason"`
}

type PAMWebFinal struct {
	RecordingFailed       bool        `json:"recordingFailed"`
	ChunksEmitted         int         `json:"chunksEmitted"`
	LastEndElapsedMs      int64       `json:"lastEndElapsedMs"`
	Gaps                  []PAMWebGap `json:"gaps"`
	DroppedCaptureFrames  uint64      `json:"droppedCaptureFrames"`
	DroppedMoves          uint64      `json:"droppedMoves"`
	TerminalEventIncluded bool        `json:"terminalEventIncluded"`
	UploadToken           string      `json:"uploadToken"`
}

func CallPAMWebReport(ctx context.Context, client *resty.Client, sessionID, route string, body, result any) error {
	resp, err := client.R().SetContext(ctx).SetHeader("User-Agent", USER_AGENT).SetBody(body).SetResult(result).
		Post(fmt.Sprintf("%s/v1/pam/sessions/%s/%s", config.INFISICAL_URL, sessionID, route))
	if err != nil {
		return NewGenericRequestError("PAMWebReport", err)
	}
	if resp.IsError() {
		return NewAPIErrorWithResponse("PAMWebReport", resp, nil)
	}
	return nil
}

func PAMReportRefusal(err error) (int, bool) {
	e, ok := errors.AsType[*APIError](err)
	if !ok {
		return 0, false
	}
	return e.StatusCode, e.StatusCode >= 400 && e.StatusCode < 500 && e.StatusCode != 429
}
