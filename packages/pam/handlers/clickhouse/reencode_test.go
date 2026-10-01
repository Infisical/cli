package clickhouse

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go/compress"
	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
)

func dataPacket(t *testing.T, block proto.Block, input proto.Input, compressor *compress.Writer) []byte {
	t.Helper()

	var b proto.Buffer
	proto.ClientCodeData.Encode(&b)
	b.PutString("")
	start := len(b.Buf)
	require.NoError(t, block.EncodeBlock(&b, proto.Version, input))
	if compressor != nil {
		require.NoError(t, compressor.Compress(b.Buf[start:]))
		b.Buf = append(b.Buf[:start], compressor.Data...)
	}
	return b.Buf
}

type typedColumn struct {
	proto.Column
	declared proto.ColumnType
}

func (c typedColumn) Type() proto.ColumnType { return c.declared }

func (c typedColumn) EncodeState(b *proto.Buffer) {
	if s, ok := c.Column.(proto.StateEncoder); ok {
		s.EncodeState(b)
	}
}

func (c typedColumn) Prepare() error {
	if p, ok := c.Column.(proto.Preparable); ok {
		return p.Prepare()
	}
	return nil
}

func sampleInput(t *testing.T) proto.Input {
	t.Helper()

	strs := new(proto.ColStr)
	strs.AppendArr([]string{"a", "", "ccc"})

	lowCardinality := proto.NewLowCardinality[string](new(proto.ColStr))
	for _, v := range []string{"x", "y", "x"} {
		lowCardinality.Append(v)
	}

	nullable := new(proto.ColStr).Nullable()
	nullable.Append(proto.NewNullable("set"))
	nullable.Append(proto.Null[string]())
	nullable.Append(proto.NewNullable(""))

	arrays := new(proto.ColInt32).Array()
	arrays.Append([]int32{1, 2})
	arrays.Append(nil)
	arrays.Append([]int32{3})

	strArrays := new(proto.ColStr).Array()
	strArrays.Append([]string{"one", "two"})
	strArrays.Append(nil)
	strArrays.Append([]string{""})

	enum := new(proto.ColEnum)
	require.NoError(t, enum.Infer("Enum8('a' = 1, 'b' = 2)"))
	enum.AppendArr([]string{"a", "b", "a"})

	times := new(proto.ColDateTime64)
	require.NoError(t, times.Infer("DateTime64(3, 'UTC')"))
	times.AppendArr([]time.Time{time.UnixMilli(1), time.UnixMilli(2), time.UnixMilli(3)})

	uuids := new(proto.ColUUID)
	for i := byte(1); i <= 3; i++ {
		uuids.Append([16]byte{i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i})
	}

	maps := proto.NewMap[string, string](new(proto.ColStr), new(proto.ColStr))
	maps.Append(map[string]string{"k": "v"})
	maps.Append(map[string]string{})
	maps.Append(map[string]string{"a": "", "b": "c"})

	return proto.Input{
		{Name: "int", Data: &proto.ColInt32{1, -2, 3}},
		{Name: "big", Data: &proto.ColUInt64{1, 2, 3}},
		{Name: "str", Data: strs},
		{Name: "decimal", Data: typedColumn{Column: &proto.ColDecimal64{100, 250, -5}, declared: "Decimal(10, 2)"}},
		{Name: "low_cardinality", Data: typedColumn{Column: lowCardinality, declared: "LowCardinality(String)"}},
		{Name: "nullable", Data: nullable},
		{Name: "array", Data: arrays},
		{Name: "str_array", Data: strArrays},
		{Name: "enum", Data: typedColumn{Column: enum, declared: "Enum8('a' = 1, 'b' = 2)"}},
		{Name: "time", Data: typedColumn{Column: times, declared: "DateTime64(3, 'UTC')"}},
		{Name: "uuid", Data: uuids},
		{Name: "map", Data: typedColumn{Column: maps, declared: "Map(String, String)"}},
	}
}

type countingReader struct {
	src  []byte
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.read >= len(c.src) {
		return 0, io.EOF
	}
	p[0] = c.src[c.read]
	c.read++
	return 1, nil
}

func readerOver(b []byte) *proto.Reader {
	return proto.NewReader(bytes.NewReader(b))
}

func TestNativeForwardsTheParsedBlockRatherThanTheClientsBytes(t *testing.T) {
	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	clientHandshake(t, conn, "someone", "")

	writeQuery(t, conn, proto.Query{Body: "INSERT INTO t VALUES"})

	var sent proto.Buffer
	proto.ClientCodeData.Encode(&sent)
	sent.PutString("")
	proto.BlockInfo{BucketNum: -1}.Encode(&sent)
	sent.PutUVarInt(1)
	sent.Buf = append(sent.Buf, 0x83, 0x00)
	proto.InputColumn{Name: "n", Data: &proto.ColInt32{}}.EncodeStart(&sent, proto.Version)
	(&proto.ColInt32{1, 2, 3}).EncodeColumn(&sent)
	_, err := conn.Write(sent.Buf)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		_, packets := upstream.received()
		return len(packets) == 1
	}, 5*time.Second, 20*time.Millisecond)

	canonical := dataPacket(t, proto.Block{Info: proto.BlockInfo{BucketNum: -1}, Columns: 1, Rows: 3},
		proto.Input{{Name: "n", Data: &proto.ColInt32{1, 2, 3}}}, nil)

	events, packets := upstream.received()
	require.Equal(t, []string{"query: INSERT INTO t VALUES", "data: 3 rows"}, events)
	require.Equal(t, canonical, packets[0])
	require.NotEqual(t, sent.Buf, packets[0])

	_, err = conn.Write([]byte{byte(proto.ClientCodePing)})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, _, _, seen := upstream.snapshot()
		return seen >= 3
	}, 5*time.Second, 20*time.Millisecond)
	_, packets = upstream.received()
	require.Len(t, packets, 1)
}

func TestNativeRecompressesTheParsedBlock(t *testing.T) {
	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	clientHandshake(t, conn, "someone", "")

	writeQuery(t, conn, proto.Query{Body: "INSERT INTO t VALUES", Compression: proto.CompressionEnabled})

	input := sampleInput(t)
	packet := dataPacket(t, proto.Block{Columns: len(input), Rows: 3}, input,
		compress.NewWriter(compress.Level(0), compress.ZSTD))
	_, err := conn.Write(packet)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		_, packets := upstream.received()
		return len(packets) == 1
	}, 5*time.Second, 20*time.Millisecond)

	events, packets := upstream.received()
	require.Equal(t, []string{"query: INSERT INTO t VALUES", "data: 3 rows"}, events)

	const lz4Method, zstdMethod = 0x82, 0x90
	require.Equal(t, byte(zstdMethod), packet[2+16])
	require.Equal(t, byte(lz4Method), packets[0][2+16], "the forwarded block must be the gateway's own encoding")
}

func TestNativeRefusesACompressedFrameTooLargeToTrust(t *testing.T) {
	upstream := startFakeClickHouse(t)
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: upstream.addr(), Username: "account", SessionID: "unit"})
	r := clientHandshake(t, conn, "someone", "")

	writeQuery(t, conn, proto.Query{Body: "INSERT INTO t VALUES", Compression: proto.CompressionEnabled})

	var b proto.Buffer
	proto.ClientCodeData.Encode(&b)
	b.PutString("")
	frame := make([]byte, 25)
	frame[16] = 0x82
	binary.LittleEndian.PutUint32(frame[17:21], 100<<20)
	binary.LittleEndian.PutUint32(frame[21:25], 100<<20)
	b.Buf = append(b.Buf, frame...)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	code, message := decodeException(t, r)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "size should be")

	_, packets := upstream.received()
	require.Empty(t, packets, "a refused frame must not be relayed upstream")
}

func TestNativeRefusesAnOversizedDataBlock(t *testing.T) {
	upstream := startFakeClickHouse(t)
	recorder := &recordingLogger{}
	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr: upstream.addr(), Username: "account", SessionID: "unit", SessionLogger: recorder,
	})
	r := clientHandshake(t, conn, "someone", "whatever")
	writeQuery(t, conn, proto.Query{Body: "INSERT INTO t VALUES"})

	var b proto.Buffer
	proto.ClientCodeData.Encode(&b)
	b.PutString("")
	proto.BlockInfo{BucketNum: -1}.Encode(&b)
	b.PutUVarInt(1)
	b.PutUVarInt(100_000_000)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	code, message := decodeException(t, r)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "rows")

	_, packets := upstream.received()
	require.Empty(t, packets, "a refused block must not be relayed upstream")
	require.Eventually(t, func() bool { return strings.Contains(recorder.dump(), "INTERRUPTED") },
		5*time.Second, 20*time.Millisecond, "the recording must say the block was not forwarded")
}

func TestNativeBlockedStatementKeepsTheSession(t *testing.T) {
	upstream := startFakeClickHouse(t)
	upstream.answerQueries = true
	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr:      upstream.addr(),
		Username:        "account",
		SessionID:       "unit",
		SessionLogger:   &recordingLogger{},
		BlockedCommands: []*regexp.Regexp{regexp.MustCompile(`(?i)\bdrop\b`)},
	})
	reader := clientHandshake(t, conn, "someone", "")

	writeStatement := func(body string) {
		var b proto.Buffer
		q := proto.Query{Body: body, Stage: proto.StageComplete}
		q.Info.ProtocolVersion, q.Info.Major, q.Info.Minor = proto.Version, 24, 8
		q.Info.Interface, q.Info.Query, q.Info.InitialAddress = proto.InterfaceTCP, proto.ClientQueryInitial, "127.0.0.1:0"
		q.EncodeAware(&b, proto.Version)
		proto.ClientCodeData.Encode(&b)
		b.PutString("")
		require.NoError(t, proto.Block{}.EncodeBlock(&b, proto.Version, nil))
		_, err := conn.Write(b.Buf)
		require.NoError(t, err)
	}

	writeStatement("DROP TABLE important")

	code, message := decodeException(t, reader)
	require.Equal(t, codeAccessDenied, code)
	require.Contains(t, message, "blocked by the command blocking policy")

	writeStatement("SELECT 1")

	next, err := reader.UVarInt()
	require.NoError(t, err)
	require.Equal(t, proto.ServerCodeProgress, proto.ServerCode(next))

	require.Eventually(t, func() bool {
		events, _ := upstream.received()
		return len(events) == 2
	}, 5*time.Second, 20*time.Millisecond)
	events, _ := upstream.received()
	require.Equal(t, []string{"query: SELECT 1", "data: 0 rows"}, events,
		"the blocked statement's data block must not reach ClickHouse")
}

func startHTTPResponder(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 64))
				_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: Close\r\n\r\n"))
			}()
		}
	}()
	return listener.Addr().String()
}

func TestNativeSessionNamesAnHTTPPortEnteredAsTheNativeOne(t *testing.T) {
	conn := dialProxy(t, ClickHouseProxyConfig{NativeAddr: startHTTPResponder(t), Username: "account", SessionID: "unit"})

	var b proto.Buffer
	proto.ClientHello{Name: "unit-test client", Major: 24, Minor: 8, ProtocolVersion: proto.Version}.Encode(&b)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	code, message := decodeException(t, proto.NewReader(newTap(conn)))
	require.Equal(t, codeNetworkError, code)
	require.Contains(t, message, "looks like ClickHouse's HTTP port")
}

func TestNativeConnectionTestNamesAnHTTPPort(t *testing.T) {
	err := TestNativeConnection(t.Context(), ClickHouseProxyConfig{NativeAddr: startHTTPResponder(t), Username: "account"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "looks like ClickHouse's HTTP port")
	require.False(t, bytes.Contains([]byte(err.Error()), []byte("packet 72")))
}
