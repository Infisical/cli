package browser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessagesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeJSON(&buf, urlMessage{Type: ServerURL, URL: "https://app.internal/"}))
	require.NoError(t, WriteFrame(&buf, FrameHeader{Seq: 7, ElapsedMs: 1500, Width: 1280, Height: 800}, []byte("jpeg-bytes")))
	length := binary.BigEndian.Uint32(buf.Bytes()[:lengthFieldSize])

	messageType, payload, err := ReadMessage(&buf, 1024)
	require.NoError(t, err)
	require.Equal(t, MessageJSON, messageType)
	require.Equal(t, uint32(len(payload)+1), length, "the length counts the type byte, as the viewer's decoder expects")
	require.JSONEq(t, `{"type":"url","url":"https://app.internal/","title":""}`, string(payload))

	messageType, payload, err = ReadMessage(&buf, 1024)
	require.NoError(t, err)
	require.Equal(t, MessageFrame, messageType)
	header, jpeg, err := DecodeFrame(payload)
	require.NoError(t, err)
	require.Equal(t, FrameHeader{Seq: 7, ElapsedMs: 1500, Width: 1280, Height: 800}, header)
	require.Equal(t, []byte("jpeg-bytes"), jpeg)
}

func TestReadMessageRefusesBadLengths(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteMessage(&buf, MessageJSON, make([]byte, 2048)))
	_, _, err := ReadMessage(&buf, 1024)
	require.ErrorContains(t, err, "exceeds")

	_, _, err = ReadMessage(bytes.NewReader([]byte{0, 0, 0, 0, MessageJSON}), 1024)
	require.ErrorContains(t, err, "zero")
}

func TestServerMessagesKeepTheFieldsTheViewerRequires(t *testing.T) {
	cases := map[string]struct {
		message any
		want    string
	}{
		"ready": {
			readyMessage{Type: ServerReady, URL: "https://app.internal/", Width: 1280, Height: 800},
			`{"type":"ready","url":"https://app.internal/","width":1280,"height":800}`,
		},
		"dialog with an empty message": {
			dialogMessage{Type: ServerDialog, ID: 1, Kind: "alert"},
			`{"type":"dialog","id":1,"kind":"alert","message":""}`,
		},
		"blocked": {
			blockedMessage{Type: ServerBlocked, URL: "https://other.internal/", Reason: blockedHostNotAllowed},
			`{"type":"blocked","url":"https://other.internal/","reason":"host_not_allowed"}`,
		},
		"end without a message": {
			endMessage{Type: ServerEnd, Reason: EndUserQuit},
			`{"type":"end","reason":"user_quit"}`,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(c.message)
			require.NoError(t, err)
			require.JSONEq(t, c.want, string(data))
		})
	}
}

func TestClampViewport(t *testing.T) {
	cases := []struct{ width, height, wantWidth, wantHeight int }{
		{0, 0, DefaultViewportWidth, DefaultViewportHeight},
		{5000, 3000, maxViewportWidth, maxViewportHeight},
		{100, 100, minViewportWidth, minViewportHeight},
		{1920, 1080, 1920, 1080},
	}
	for _, c := range cases {
		width, height := clampViewport(c.width, c.height)
		require.Equal(t, [2]int{c.wantWidth, c.wantHeight}, [2]int{width, height}, "%dx%d", c.width, c.height)
	}
}
