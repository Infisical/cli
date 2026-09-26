package clickhouse

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
)

func TestSniffProtocol(t *testing.T) {
	cases := []struct {
		name       string
		first      []byte
		wantNative bool
	}{
		{name: "native hello", first: []byte{0x00}, wantNative: true},
		{name: "http get", first: []byte("GET / HTTP/1.1\r\n"), wantNative: false},
		{name: "http post", first: []byte("POST / HTTP/1.1\r\n"), wantNative: false},
		{name: "http head", first: []byte("HEAD / HTTP/1.1\r\n"), wantNative: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			go func() { _, _ = client.Write(tc.first) }()

			conn, isNative, err := sniffProtocol(server)
			require.NoError(t, err)
			require.Equal(t, tc.wantNative, isNative)

			// The byte used to decide has to still be readable by the handler that takes the connection.
			buf := make([]byte, len(tc.first))
			_, err = bufio.NewReader(conn).Read(buf[:1])
			require.NoError(t, err)
			require.Equal(t, tc.first[0], buf[0])
		})
	}
}

func TestHandleConnectionRoutesHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy := NewClickHouseProxy(ClickHouseProxyConfig{
		TargetAddr: strings.TrimPrefix(upstream.URL, "http://"),
		Username:   "account",
		SessionID:  "sniff-test",
	})

	client, server := net.Pipe()
	defer client.Close()

	go func() { _ = proxy.HandleConnection(context.Background(), server) }()

	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := client.Write([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nSELECT 1"))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleConnectionRefusesNativeWithoutPort(t *testing.T) {
	proxy := NewClickHouseProxy(ClickHouseProxyConfig{
		TargetAddr: "127.0.0.1:1",
		Username:   "account",
		SessionID:  "sniff-test",
	})

	client, server := net.Pipe()
	defer client.Close()

	go func() { _ = proxy.HandleConnection(context.Background(), server) }()

	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	var b proto.Buffer
	proto.ClientHello{
		Name:            "test",
		ProtocolVersion: proto.Version,
		Database:        "default",
		User:            "someone",
	}.Encode(&b)
	_, err := client.Write(b.Buf)
	require.NoError(t, err)

	code, message := readNativeException(t, client)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "native port")
}

func readNativeException(t *testing.T, conn net.Conn) (int, string) {
	t.Helper()

	r := proto.NewReader(newTap(conn))

	code, err := r.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeException, proto.ServerCode(code), fmt.Sprintf("unexpected packet %d", code))

	var e proto.Exception
	require.NoError(t, e.DecodeAware(r, proto.Version))
	return int(e.Code), e.Message
}
