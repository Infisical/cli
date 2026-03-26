package mongodb

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/bson"
)

// requestIDCounter is used to generate unique request IDs for wire protocol messages
// sent during the authentication phase.
var requestIDCounter atomic.Int32

func nextRequestID() int32 {
	return requestIDCounter.Add(1)
}

// authenticateScram performs SCRAM authentication against a MongoDB server using the
// specified mechanism ("SCRAM-SHA-256" or "SCRAM-SHA-1").
//
// The mechanism is selected based on what the server advertises in its hello response
// via saslSupportedMechs. SCRAM-SHA-256 is preferred when available, with SCRAM-SHA-1
// as a fallback (e.g. DigitalOcean managed MongoDB only supports SHA-1).
//
// The authDB parameter specifies which database contains the user account. This is
// typically the application database, but may be "admin" depending on how the user
// was created. The correct value is provided by the backend via InjectDatabase.
func authenticateScram(conn io.ReadWriter, username, password, authDB, mechanism string) error {
	var hashGen scram.HashGeneratorFcn
	switch mechanism {
	case "SCRAM-SHA-1":
		hashGen = scram.SHA1
	case "SCRAM-SHA-256":
		hashGen = scram.SHA256
	default:
		return fmt.Errorf("unsupported SCRAM mechanism: %s", mechanism)
	}

	client, err := hashGen.NewClient(username, password, "")
	if err != nil {
		return fmt.Errorf("create SCRAM client: %w", err)
	}

	conv := client.NewConversation()
	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM client-first: %w", err)
	}

	// Step 1: saslStart
	log.Debug().Msg("MongoDB auth: sending saslStart")
	saslStartDoc := bson.D{
		{Key: "saslStart", Value: int32(1)},
		{Key: "mechanism", Value: mechanism},
		{Key: "payload", Value: []byte(clientFirst)},
		{Key: "$db", Value: authDB},
	}
	saslStartBytes, err := BuildOpMsg(nextRequestID(), 0, saslStartDoc)
	if err != nil {
		return fmt.Errorf("build saslStart message: %w", err)
	}
	if _, err := conn.Write(saslStartBytes); err != nil {
		return fmt.Errorf("send saslStart: %w", err)
	}

	// Read server response to saslStart
	resp, err := ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read saslStart response: %w", err)
	}
	serverFirst, conversationID, done, err := parseSASLResponse(resp)
	if err != nil {
		return fmt.Errorf("parse saslStart response: %w", err)
	}
	if done {
		return fmt.Errorf("server completed SCRAM unexpectedly after saslStart")
	}

	// Step 2: saslContinue with client-final
	clientFinal, err := conv.Step(serverFirst)
	if err != nil {
		return fmt.Errorf("SCRAM client-final: %w", err)
	}

	log.Debug().Msg("MongoDB auth: sending saslContinue (client-final)")
	saslContinueDoc := bson.D{
		{Key: "saslContinue", Value: int32(1)},
		{Key: "conversationId", Value: conversationID},
		{Key: "payload", Value: []byte(clientFinal)},
		{Key: "$db", Value: authDB},
	}
	saslContinueBytes, err := BuildOpMsg(nextRequestID(), 0, saslContinueDoc)
	if err != nil {
		return fmt.Errorf("build saslContinue message: %w", err)
	}
	if _, err := conn.Write(saslContinueBytes); err != nil {
		return fmt.Errorf("send saslContinue: %w", err)
	}

	// Read server response (server-final)
	resp, err = ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read saslContinue response: %w", err)
	}
	serverFinal, conversationID, done, err := parseSASLResponse(resp)
	if err != nil {
		return fmt.Errorf("parse saslContinue response: %w", err)
	}

	// Verify server signature
	_, err = conv.Step(serverFinal)
	if err != nil {
		return fmt.Errorf("SCRAM server verification failed: %w", err)
	}

	// Some MongoDB versions require one more empty saslContinue if done=false
	if !done {
		log.Debug().Msg("MongoDB auth: sending final saslContinue")
		finalDoc := bson.D{
			{Key: "saslContinue", Value: int32(1)},
			{Key: "conversationId", Value: conversationID},
			{Key: "payload", Value: []byte{}},
			{Key: "$db", Value: authDB},
		}
		finalBytes, err := BuildOpMsg(nextRequestID(), 0, finalDoc)
		if err != nil {
			return fmt.Errorf("build final saslContinue: %w", err)
		}
		if _, err := conn.Write(finalBytes); err != nil {
			return fmt.Errorf("send final saslContinue: %w", err)
		}

		resp, err = ReadMessage(conn)
		if err != nil {
			return fmt.Errorf("read final saslContinue response: %w", err)
		}
		_, _, done, err = parseSASLResponse(resp)
		if err != nil {
			return fmt.Errorf("parse final saslContinue response: %w", err)
		}
		if !done {
			return fmt.Errorf("SCRAM authentication did not complete after final exchange")
		}
	}

	log.Info().Str("mechanism", mechanism).Msg("MongoDB SCRAM authentication successful")
	return nil
}

// parseSASLResponse extracts payload, conversationId, and done flag from a SASL response OP_MSG.
func parseSASLResponse(msg *MongoMessage) (payload string, conversationID int32, done bool, err error) {
	if msg.Header.OpCode != OpMsg {
		return "", 0, false, fmt.Errorf("expected OP_MSG response, got opCode %d", msg.Header.OpCode)
	}

	body, err := ParseOpMsgBody(msg.Payload)
	if err != nil {
		return "", 0, false, fmt.Errorf("parse response body: %w", err)
	}

	// Check for errors first
	okVal, err := body.LookupErr("ok")
	if err == nil {
		var ok float64
		switch okVal.Type {
		case bson.TypeDouble:
			ok = okVal.Double()
		case bson.TypeInt32:
			ok = float64(okVal.Int32())
		case bson.TypeInt64:
			ok = float64(okVal.Int64())
		}
		if ok != 1 {
			errmsg := ""
			if v, lookupErr := body.LookupErr("errmsg"); lookupErr == nil {
				errmsg = v.StringValue()
			}
			return "", 0, false, fmt.Errorf("SASL auth error: %s", errmsg)
		}
	}

	// Extract payload (Binary data)
	payloadVal, err := body.LookupErr("payload")
	if err != nil {
		return "", 0, false, fmt.Errorf("missing payload field in SASL response")
	}
	_, payloadBytes := payloadVal.Binary()

	// Extract conversationId
	convVal, err := body.LookupErr("conversationId")
	if err != nil {
		return "", 0, false, fmt.Errorf("missing conversationId in SASL response")
	}
	conversationID = convVal.Int32()

	// Extract done flag
	doneVal, err := body.LookupErr("done")
	if err == nil {
		done = doneVal.Boolean()
	}

	return string(payloadBytes), conversationID, done, nil
}
