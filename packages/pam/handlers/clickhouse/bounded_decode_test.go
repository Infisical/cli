package clickhouse

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func readerOver(b []byte) *proto.Reader {
	return proto.NewReader(bytes.NewReader(b))
}

// A field read in the wrong order desynchronises the stream, which is the failure this decoder exists to
// prevent. Encoding with ch-go and decoding with ours is what pins the two together.
func TestBoundedQueryDecodeMatchesChGo(t *testing.T) {
	span := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{9, 8, 7, 6, 5, 4, 3, 2},
		TraceFlags: trace.FlagsSampled,
	})

	cases := map[string]proto.Query{
		"a bare statement": {
			Body:  "SELECT 1",
			Stage: proto.StageComplete,
		},
		"settings and parameters": {
			ID:          "query-id",
			Body:        "SELECT {who:String}",
			Secret:      "interserver",
			Stage:       proto.StageComplete,
			Compression: proto.CompressionEnabled,
			Settings: []proto.Setting{
				{Key: "max_block_size", Value: "1024"},
				{Key: "readonly", Value: "1", Important: true},
				{Key: "obsolete_one", Value: "x", Obsolete: true},
			},
			Parameters: []proto.Parameter{
				{Key: "who", Value: "someone"},
				{Key: "other", Value: "value"},
			},
		},
		"a fully populated client info": {
			Body:  "SELECT 2",
			Stage: proto.StageComplete,
			Info: proto.ClientInfo{
				InitialUser:                "initial",
				InitialQueryID:             "initial-query",
				InitialTime:                1727212345,
				OSUser:                     "os-user",
				ClientHostname:             "hostname",
				ClientName:                 "client-name",
				QuotaKey:                   "quota",
				DistributedDepth:           2,
				Patch:                      7,
				Span:                       span,
				CollaborateWithInitiator:   true,
				CountParticipatingReplicas: 3,
				NumberOfCurrentReplica:     1,
			},
		},
		"a large but legal body": {
			Body:  "SELECT '" + strings.Repeat("x", 1<<20) + "'",
			Stage: proto.StageComplete,
		},
	}

	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			for _, rev := range []int{54455, 54458, maxNativeRevision} {
				q := query
				q.Info.Query = proto.ClientQueryInitial
				q.Info.Interface = proto.InterfaceTCP
				q.Info.InitialAddress = "127.0.0.1:0"
				q.Info.Major, q.Info.Minor, q.Info.ProtocolVersion = 24, 8, rev

				var b proto.Buffer
				q.EncodeAware(&b, rev)

				// The packet code ch-go writes first is consumed by the caller, so skip it here.
				r := readerOver(b.Buf)
				code, err := r.UVarInt()
				require.NoError(t, err)
				require.Equal(t, proto.ClientCodeQuery, proto.ClientCode(code))

				var theirs proto.Query
				require.NoError(t, theirs.DecodeAware(readerSkippingCode(t, b.Buf), rev))

				ours, err := decodeBoundedQuery(readerSkippingCode(t, b.Buf), rev)
				require.NoError(t, err, "revision %d", rev)
				require.Equal(t, theirs, ours, "revision %d", rev)
			}
		})
	}
}

func readerSkippingCode(t *testing.T, payload []byte) *proto.Reader {
	t.Helper()
	r := readerOver(payload)
	_, err := r.UVarInt()
	require.NoError(t, err)
	return r
}

func TestBoundedQueryRefusesAnOversizedField(t *testing.T) {
	for name, build := range map[string]func(*proto.Buffer){
		"query id": func(b *proto.Buffer) {
			b.PutUVarInt(uint64(maxHandshakeStringLen) + 1)
		},
		"query body": func(b *proto.Buffer) {
			var q proto.Query
			q.ID = "id"
			q.Info.Query = proto.ClientQueryInitial
			q.Info.Interface = proto.InterfaceTCP
			q.Info.InitialAddress = "127.0.0.1:0"
			q.Info.Major, q.Info.Minor, q.Info.ProtocolVersion = 24, 8, maxNativeRevision
			q.Stage = proto.StageComplete
			q.Body = "SELECT 1"

			var full proto.Buffer
			q.EncodeAware(&full, maxNativeRevision)

			// Re-encode everything up to the body, then declare an absurd length in its place.
			trimmed := full.Buf[:bytes.LastIndex(full.Buf, []byte("SELECT 1"))-1]
			b.Buf = append(b.Buf, trimmed[1:]...) // drop the packet code
			b.PutUVarInt(1 << 40)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var b proto.Buffer
			build(&b)

			_, err := decodeBoundedQuery(readerOver(b.Buf), maxNativeRevision)
			require.Error(t, err)
			require.Contains(t, err.Error(), "exceeds the",
				"an absurd length must be refused before it is allocated")
		})
	}
}

func TestBoundedQueryRefusesTooManySettings(t *testing.T) {
	var b proto.Buffer
	q := proto.Query{ID: "id", Body: "SELECT 1", Stage: proto.StageComplete}
	q.Info.Query = proto.ClientQueryInitial
	q.Info.Interface = proto.InterfaceTCP
	q.Info.InitialAddress = "127.0.0.1:0"
	q.Info.Major, q.Info.Minor, q.Info.ProtocolVersion = 24, 8, maxNativeRevision
	for i := 0; i <= maxQuerySettings; i++ {
		q.Settings = append(q.Settings, proto.Setting{Key: fmt.Sprintf("s%d", i), Value: "1"})
	}
	q.EncodeAware(&b, maxNativeRevision)

	_, err := decodeBoundedQuery(readerSkippingCode(t, b.Buf), maxNativeRevision)
	require.Error(t, err)
	require.Contains(t, err.Error(), "more than")
}
