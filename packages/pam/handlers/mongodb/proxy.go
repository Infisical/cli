package mongodb

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/bson"
)

// MongoDBProxyConfig configures the MongoDB proxy.
// Host and Port are separate (unlike TargetAddr in other handlers) because
// SRV resolution discovers the port from DNS, not from config.
type MongoDBProxyConfig struct {
	Host           string
	Port           int // 0 means SRV (mongodb+srv://)
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

type MongoDBProxy struct {
	config MongoDBProxyConfig
}

func NewMongoDBProxy(config MongoDBProxyConfig) *MongoDBProxy {
	return &MongoDBProxy{config: config}
}

func (p *MongoDBProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", p.config.SessionID).
		Msg("New MongoDB connection for PAM session")

	serverConn, err := p.connectToServer()
	if err != nil {
		return fmt.Errorf("failed to connect to target MongoDB: %w", err)
	}
	defer serverConn.Close()

	b := newBridge(serverConn, clientConn, p.config.SessionLogger, p.config.InjectDatabase)
	return b.run(ctx)
}

// connectToServer establishes a direct TCP/TLS connection to the MongoDB server
// and authenticates using SCRAM. This avoids the overhead of the Go mongo driver's
// connection pooling, heartbeats, and topology monitoring — matching the approach
// used by the Postgres, MySQL, MSSQL, and Redis handlers.
func (p *MongoDBProxy) connectToServer() (net.Conn, error) {
	totalStart := time.Now() // [DIAG-CONNPOOL]
	isSRV := p.config.Port == 0

	var host string
	var port int
	var authSource string

	if isSRV {
		srvStart := time.Now() // [DIAG-CONNPOOL]
		resolvedHost, resolvedPort, opts, err := resolveSRV(p.config.Host)
		if err != nil {
			return nil, fmt.Errorf("SRV resolution failed: %w", err)
		}
		log.Info().Dur("elapsed_ms", time.Since(srvStart)).Str("resolved", fmt.Sprintf("%s:%d", resolvedHost, resolvedPort)).Msg("[DIAG-CONNPOOL] SRV resolution complete") // [DIAG-CONNPOOL]
		host = resolvedHost
		port = resolvedPort
		authSource = opts["authSource"]
		if authSource == "" {
			authSource = "admin"
		}
	} else {
		host = p.config.Host
		port = p.config.Port
		authSource = "admin"
	}

	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	dialStart := time.Now() // [DIAG-CONNPOOL]
	if p.config.EnableTLS || isSRV {
		tlsCfg := &tls.Config{}
		if p.config.TLSConfig != nil {
			tlsCfg = p.config.TLSConfig.Clone()
		}
		// For SRV, the certificate is issued for the resolved hostname (e.g.
		// "shard-00-00.abc.mongodb.net"), not the SRV record hostname (e.g.
		// "cluster0.abc.mongodb.net"). Override ServerName to match.
		if isSRV {
			tlsCfg.ServerName = host
		} else if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = p.config.Host
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", targetAddr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", targetAddr)
	}
	log.Info().Dur("elapsed_ms", time.Since(dialStart)).Str("target", targetAddr).Bool("tls", p.config.EnableTLS || isSRV).Msg("[DIAG-CONNPOOL] TCP/TLS dial complete") // [DIAG-CONNPOOL]

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
	}

	if p.config.InjectUsername != "" && p.config.InjectPassword != "" {
		authStart := time.Now() // [DIAG-CONNPOOL]
		if err := p.authenticateWithServer(conn, authSource); err != nil {
			conn.Close()
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		log.Info().Dur("elapsed_ms", time.Since(authStart)).Msg("[DIAG-CONNPOOL] SCRAM auth complete") // [DIAG-CONNPOOL]
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Str("host", host).
		Int("port", port).
		Bool("srv", isSRV).
		Dur("total_connect_ms", time.Since(totalStart)). // [DIAG-CONNPOOL]
		Msg("Connected to target MongoDB")

	return conn, nil
}

// resolveSRV resolves a MongoDB SRV hostname to an actual host:port and connection options.
func resolveSRV(hostname string) (host string, port int, opts map[string]string, err error) {
	_, addrs, err := net.LookupSRV("mongodb", "tcp", hostname)
	if err != nil {
		return "", 0, nil, fmt.Errorf("SRV lookup failed for %s: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return "", 0, nil, fmt.Errorf("no SRV records found for %s", hostname)
	}

	host = strings.TrimSuffix(addrs[0].Target, ".")
	port = int(addrs[0].Port)

	// Parse TXT record for connection options (authSource, replicaSet, etc.)
	opts = make(map[string]string)
	txts, txtErr := net.LookupTXT(hostname)
	if txtErr == nil {
		for _, txt := range txts {
			for _, pair := range strings.Split(txt, "&") {
				k, v, ok := strings.Cut(pair, "=")
				if ok {
					opts[k] = v
				}
			}
		}
	}

	log.Debug().
		Str("hostname", hostname).
		Str("resolved", fmt.Sprintf("%s:%d", host, port)).
		Interface("opts", opts).
		Msg("SRV resolution complete")

	return host, port, opts, nil
}

// authenticateWithServer performs SCRAM authentication against the MongoDB server.
// Sends hello to discover supported mechanisms, then performs the SCRAM exchange.
func (p *MongoDBProxy) authenticateWithServer(conn net.Conn, authSource string) error {
	// Send hello to discover supported auth mechanisms
	helloCmd, err := bson.Marshal(bson.D{
		{Key: "hello", Value: 1},
		{Key: "saslSupportedMechs", Value: fmt.Sprintf("%s.%s", authSource, p.config.InjectUsername)},
		{Key: "$db", Value: authSource},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal hello: %w", err)
	}

	helloResp, err := sendCommand(conn, helloCmd)
	if err != nil {
		return fmt.Errorf("hello failed: %w", err)
	}

	mechanism := pickSCRAMMechanism(helloResp)
	if mechanism == "" {
		return fmt.Errorf("server does not support SCRAM authentication")
	}

	log.Debug().Str("mechanism", mechanism).Msg("Using SCRAM mechanism for MongoDB auth")

	// Create SCRAM client. SHA-1 requires pre-hashed password (MD5 digest),
	// SHA-256 uses SASLprep on the plain password.
	var hashGen scram.HashGeneratorFcn
	var client *scram.Client

	switch mechanism {
	case "SCRAM-SHA-256":
		hashGen = scram.SHA256
		client, err = hashGen.NewClient(p.config.InjectUsername, p.config.InjectPassword, "")
	case "SCRAM-SHA-1":
		hashGen = scram.SHA1
		pw := mongoPasswordDigest(p.config.InjectUsername, p.config.InjectPassword)
		client, err = hashGen.NewClientUnprepped(p.config.InjectUsername, pw, "")
	default:
		return fmt.Errorf("unsupported SCRAM mechanism: %s", mechanism)
	}
	if err != nil {
		return fmt.Errorf("failed to create SCRAM client: %w", err)
	}

	conv := client.NewConversation()

	// Step 1: client-first-message -> saslStart
	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM step 1 failed: %w", err)
	}

	saslStartCmd, err := bson.Marshal(bson.D{
		{Key: "saslStart", Value: 1},
		{Key: "mechanism", Value: mechanism},
		{Key: "payload", Value: []byte(clientFirst)},
		{Key: "$db", Value: authSource},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal saslStart: %w", err)
	}

	saslStartResp, err := sendCommand(conn, saslStartCmd)
	if err != nil {
		return fmt.Errorf("saslStart failed: %w", err)
	}

	if err := checkCommandOk(saslStartResp); err != nil {
		return fmt.Errorf("saslStart error: %w", err)
	}

	serverPayload, convID, err := extractSASLResponse(saslStartResp)
	if err != nil {
		return fmt.Errorf("failed to parse saslStart response: %w", err)
	}

	// Step 2: server-first-message -> client-final-message via saslContinue
	clientFinal, err := conv.Step(serverPayload)
	if err != nil {
		return fmt.Errorf("SCRAM step 2 failed: %w", err)
	}

	saslContinueCmd, err := bson.Marshal(bson.D{
		{Key: "saslContinue", Value: 1},
		{Key: "conversationId", Value: convID},
		{Key: "payload", Value: []byte(clientFinal)},
		{Key: "$db", Value: authSource},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal saslContinue: %w", err)
	}

	saslContinueResp, err := sendCommand(conn, saslContinueCmd)
	if err != nil {
		return fmt.Errorf("saslContinue failed: %w", err)
	}

	if err := checkCommandOk(saslContinueResp); err != nil {
		return fmt.Errorf("saslContinue error: %w", err)
	}

	serverFinal, _, err := extractSASLResponse(saslContinueResp)
	if err != nil {
		return fmt.Errorf("failed to parse saslContinue response: %w", err)
	}

	// Step 3: verify server signature
	_, err = conv.Step(serverFinal)
	if err != nil {
		return fmt.Errorf("SCRAM server verification failed: %w", err)
	}

	// Some servers send done:false and require one more empty saslContinue
	if !isDone(saslContinueResp) {
		finalCmd, err := bson.Marshal(bson.D{
			{Key: "saslContinue", Value: 1},
			{Key: "conversationId", Value: convID},
			{Key: "payload", Value: []byte{}},
			{Key: "$db", Value: authSource},
		})
		if err != nil {
			return fmt.Errorf("failed to marshal final saslContinue: %w", err)
		}

		finalResp, err := sendCommand(conn, finalCmd)
		if err != nil {
			return fmt.Errorf("final saslContinue failed: %w", err)
		}

		if err := checkCommandOk(finalResp); err != nil {
			return fmt.Errorf("final saslContinue error: %w", err)
		}
	}

	log.Debug().Str("mechanism", mechanism).Msg("SCRAM authentication successful")
	return nil
}

// sendCommand sends a BSON command as OP_MSG and reads the response document.
func sendCommand(conn net.Conn, cmdDoc bson.Raw) (bson.Raw, error) {
	msg := buildOpMsg(0, cmdDoc) // responseTo=0 for requests
	if err := writeWireMessage(conn, msg); err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	hdr, raw, err := readWireMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if hdr.OpCode == opMsgOpCode {
		respMsg, err := parseOpMsg(hdr, raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse response OP_MSG: %w", err)
		}
		return respMsg.Body, nil
	}

	return nil, fmt.Errorf("unexpected response opcode: %d", hdr.OpCode)
}

func pickSCRAMMechanism(helloResp bson.Raw) string {
	var doc bson.M
	if err := bson.Unmarshal(helloResp, &doc); err != nil {
		return "SCRAM-SHA-256"
	}

	mechs, ok := doc["saslSupportedMechs"]
	if !ok {
		return "SCRAM-SHA-256"
	}

	mechArr, ok := mechs.(bson.A)
	if !ok {
		return "SCRAM-SHA-256"
	}

	hasSHA256 := false
	hasSHA1 := false
	for _, v := range mechArr {
		str, ok := v.(string)
		if !ok {
			continue
		}
		switch str {
		case "SCRAM-SHA-256":
			hasSHA256 = true
		case "SCRAM-SHA-1":
			hasSHA1 = true
		}
	}

	if hasSHA256 {
		return "SCRAM-SHA-256"
	}
	if hasSHA1 {
		return "SCRAM-SHA-1"
	}
	return ""
}

func checkCommandOk(resp bson.Raw) error {
	var doc bson.M
	if err := bson.Unmarshal(resp, &doc); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if toFloat64(doc["ok"]) != 1 {
		errmsg, _ := doc["errmsg"].(string)
		return fmt.Errorf("command failed: %s", errmsg)
	}
	return nil
}

func extractSASLResponse(resp bson.Raw) (payload string, convID int32, err error) {
	payloadVal, err := resp.LookupErr("payload")
	if err != nil {
		return "", 0, fmt.Errorf("missing payload field")
	}

	_, payloadBytes, ok := payloadVal.BinaryOK()
	if !ok {
		return "", 0, fmt.Errorf("payload is not binary")
	}

	convIDVal, err := resp.LookupErr("conversationId")
	if err != nil {
		return "", 0, fmt.Errorf("missing conversationId field")
	}
	convID = convIDVal.Int32()

	return string(payloadBytes), convID, nil
}

func isDone(resp bson.Raw) bool {
	var doc bson.M
	if err := bson.Unmarshal(resp, &doc); err != nil {
		return false
	}
	done, _ := doc["done"].(bool)
	return done
}

// mongoPasswordDigest computes the MD5 digest used by SCRAM-SHA-1.
// MongoDB SCRAM-SHA-1 requires md5(username:mongo:password) as the password input.
func mongoPasswordDigest(username, password string) string {
	h := md5.New()
	h.Write([]byte(username + ":mongo:" + password))
	return hex.EncodeToString(h.Sum(nil))
}
