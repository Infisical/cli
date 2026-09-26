package clickhouse

import (
	"fmt"
	"io"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/segmentio/asm/bswap"
	"go.opentelemetry.io/otel/trace"
)

// ch-go allocates a declared string length before it reads a single byte, and rejects only a length that
// goes negative. A client that names a terabyte therefore kills the process outright: the allocation is a
// fatal runtime error rather than a panic anything can recover. These decoders mirror ch-go's field for
// field and differ only in reading every string through a cap.
const (
	// Short identifiers: names, users, hostnames, the quota key.
	maxHandshakeStringLen = 64 << 10
	// Query bodies and setting values. ClickHouse's own max_query_size defaults to 256 KB.
	maxQueryStringLen = 16 << 20
	// A settings or parameters list terminates on an empty key, so it also needs a count bound.
	maxQuerySettings = 4096
)

func readCappedStr(r *proto.Reader, limit int) (string, error) {
	n, err := r.UVarInt()
	if err != nil {
		return "", err
	}
	if n > uint64(limit) {
		return "", fmt.Errorf("declared string of %d bytes exceeds the %d byte cap", n, limit)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readBoundedStr(r *proto.Reader) (string, error) {
	return readCappedStr(r, maxHandshakeStringLen)
}

func decodeBoundedClientHello(r *proto.Reader) (proto.ClientHello, error) {
	var h proto.ClientHello
	var err error
	if h.Name, err = readBoundedStr(r); err != nil {
		return h, fmt.Errorf("name: %w", err)
	}
	if h.Major, err = r.Int(); err != nil {
		return h, fmt.Errorf("major: %w", err)
	}
	if h.Minor, err = r.Int(); err != nil {
		return h, fmt.Errorf("minor: %w", err)
	}
	if h.ProtocolVersion, err = r.Int(); err != nil {
		return h, fmt.Errorf("protocol version: %w", err)
	}
	if h.Database, err = readBoundedStr(r); err != nil {
		return h, fmt.Errorf("database: %w", err)
	}
	if h.User, err = readBoundedStr(r); err != nil {
		return h, fmt.Errorf("user: %w", err)
	}
	if h.Password, err = readBoundedStr(r); err != nil {
		return h, fmt.Errorf("password: %w", err)
	}
	return h, nil
}

// Mirrors proto.Setting.Decode. An empty key terminates the list and leaves the rest unread.
func decodeBoundedSetting(r *proto.Reader) (proto.Setting, error) {
	var s proto.Setting

	key, err := readBoundedStr(r)
	if err != nil {
		return s, fmt.Errorf("key: %w", err)
	}
	if key == "" {
		return s, nil
	}

	flags, err := r.UVarInt()
	if err != nil {
		return s, fmt.Errorf("flags: %w", err)
	}
	value, err := readCappedStr(r, maxQueryStringLen)
	if err != nil {
		return s, fmt.Errorf("value (%s): %w", key, err)
	}

	s.Key = key
	s.Value = value
	s.Important = flags&0x01 != 0
	s.Custom = flags&0x02 != 0
	s.Obsolete = flags&0x04 != 0
	return s, nil
}

// Mirrors proto.ClientInfo.DecodeAware.
func decodeBoundedClientInfo(r *proto.Reader, version int) (proto.ClientInfo, error) {
	var c proto.ClientInfo

	kind, err := r.UInt8()
	if err != nil {
		return c, fmt.Errorf("query kind: %w", err)
	}
	c.Query = proto.ClientQueryKind(kind)
	if !c.Query.IsAClientQueryKind() {
		return c, fmt.Errorf("unknown query kind %d", kind)
	}

	if c.InitialUser, err = readBoundedStr(r); err != nil {
		return c, fmt.Errorf("initial user: %w", err)
	}
	if c.InitialQueryID, err = readBoundedStr(r); err != nil {
		return c, fmt.Errorf("initial query id: %w", err)
	}
	if c.InitialAddress, err = readBoundedStr(r); err != nil {
		return c, fmt.Errorf("initial address: %w", err)
	}

	if proto.FeatureQueryStartTime.In(version) {
		if c.InitialTime, err = r.Int64(); err != nil {
			return c, fmt.Errorf("query start time: %w", err)
		}
	}

	iface, err := r.UInt8()
	if err != nil {
		return c, fmt.Errorf("interface: %w", err)
	}
	c.Interface = proto.Interface(iface)
	if !c.Interface.IsAInterface() {
		return c, fmt.Errorf("unknown interface %d", iface)
	}
	if c.Interface != proto.InterfaceTCP {
		return c, fmt.Errorf("only tcp interface is supported")
	}

	if c.OSUser, err = readBoundedStr(r); err != nil {
		return c, fmt.Errorf("os user: %w", err)
	}
	if c.ClientHostname, err = readBoundedStr(r); err != nil {
		return c, fmt.Errorf("client hostname: %w", err)
	}
	if c.ClientName, err = readBoundedStr(r); err != nil {
		return c, fmt.Errorf("client name: %w", err)
	}
	if c.Major, err = r.Int(); err != nil {
		return c, fmt.Errorf("major version: %w", err)
	}
	if c.Minor, err = r.Int(); err != nil {
		return c, fmt.Errorf("minor version: %w", err)
	}
	if c.ProtocolVersion, err = r.Int(); err != nil {
		return c, fmt.Errorf("protocol version: %w", err)
	}

	if proto.FeatureQuotaKeyInClientInfo.In(version) {
		if c.QuotaKey, err = readBoundedStr(r); err != nil {
			return c, fmt.Errorf("quota key: %w", err)
		}
	}
	if proto.FeatureDistributedDepth.In(version) {
		if c.DistributedDepth, err = r.Int(); err != nil {
			return c, fmt.Errorf("distributed depth: %w", err)
		}
	}
	if proto.FeatureVersionPatch.In(version) && c.Interface == proto.InterfaceTCP {
		if c.Patch, err = r.Int(); err != nil {
			return c, fmt.Errorf("patch version: %w", err)
		}
	}

	if proto.FeatureOpenTelemetry.In(version) {
		hasTrace, err := r.Bool()
		if err != nil {
			return c, fmt.Errorf("open telemetry start: %w", err)
		}
		if hasTrace {
			var cfg trace.SpanContextConfig
			raw, err := r.ReadRaw(len(cfg.TraceID))
			if err != nil {
				return c, fmt.Errorf("trace id: %w", err)
			}
			bswap.Swap64(raw)
			copy(cfg.TraceID[:], raw)

			raw, err = r.ReadRaw(len(cfg.SpanID))
			if err != nil {
				return c, fmt.Errorf("span id: %w", err)
			}
			bswap.Swap64(raw)
			copy(cfg.SpanID[:], raw)

			state, err := readBoundedStr(r)
			if err != nil {
				return c, fmt.Errorf("trace state: %w", err)
			}
			parsed, err := trace.ParseTraceState(state)
			if err != nil {
				return c, fmt.Errorf("parse trace state: %w", err)
			}
			cfg.TraceState = parsed

			flags, err := r.Byte()
			if err != nil {
				return c, fmt.Errorf("trace flag: %w", err)
			}
			cfg.TraceFlags = trace.TraceFlags(flags)
			c.Span = trace.NewSpanContext(cfg)
		}
	}

	if proto.FeatureParallelReplicas.In(version) {
		collaborate, err := r.Int()
		if err != nil {
			return c, fmt.Errorf("parallel replicas: %w", err)
		}
		c.CollaborateWithInitiator = collaborate == 1
		if c.CountParticipatingReplicas, err = r.Int(); err != nil {
			return c, fmt.Errorf("count participating replicas: %w", err)
		}
		if c.NumberOfCurrentReplica, err = r.Int(); err != nil {
			return c, fmt.Errorf("number of current replica: %w", err)
		}
	}

	return c, nil
}

// Mirrors proto.Query.DecodeAware.
func decodeBoundedQuery(r *proto.Reader, version int) (proto.Query, error) {
	var q proto.Query
	var err error

	if q.ID, err = readBoundedStr(r); err != nil {
		return q, fmt.Errorf("query id: %w", err)
	}

	if proto.FeatureClientWriteInfo.In(version) {
		if q.Info, err = decodeBoundedClientInfo(r, version); err != nil {
			return q, fmt.Errorf("client info: %w", err)
		}
	}

	if !proto.FeatureSettingsSerializedAsStrings.In(version) {
		return q, fmt.Errorf("unsupported version")
	}

	for {
		s, err := decodeBoundedSetting(r)
		if err != nil {
			return q, fmt.Errorf("setting: %w", err)
		}
		if s.Key == "" {
			break
		}
		if len(q.Settings) >= maxQuerySettings {
			return q, fmt.Errorf("more than %d settings", maxQuerySettings)
		}
		q.Settings = append(q.Settings, s)
	}

	if proto.FeatureInterServerSecret.In(version) {
		if q.Secret, err = readBoundedStr(r); err != nil {
			return q, fmt.Errorf("inter-server secret: %w", err)
		}
	}

	stage, err := r.UVarInt()
	if err != nil {
		return q, fmt.Errorf("stage: %w", err)
	}
	q.Stage = proto.Stage(stage)
	if !q.Stage.IsAStage() {
		return q, fmt.Errorf("unknown stage %d", stage)
	}

	compression, err := r.UVarInt()
	if err != nil {
		return q, fmt.Errorf("compression: %w", err)
	}
	q.Compression = proto.Compression(compression)
	if !q.Compression.IsACompression() {
		return q, fmt.Errorf("unknown compression %d", compression)
	}

	if q.Body, err = readCappedStr(r, maxQueryStringLen); err != nil {
		return q, fmt.Errorf("query body: %w", err)
	}

	if proto.FeatureParameters.In(version) {
		for {
			s, err := decodeBoundedSetting(r)
			if err != nil {
				return q, fmt.Errorf("parameter: %w", err)
			}
			if s.Key == "" {
				break
			}
			if len(q.Parameters) >= maxQuerySettings {
				return q, fmt.Errorf("more than %d parameters", maxQuerySettings)
			}
			q.Parameters = append(q.Parameters, proto.Parameter{Key: s.Key, Value: s.Value})
		}
	}

	return q, nil
}
