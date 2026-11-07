package webapp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestWireConformance(t *testing.T) {
	b, err := os.ReadFile("testdata/protocol-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int
		Vectors []struct {
			Name, Direction, FrameHex, TCPHex, TCPHexLength string
			TCPLengthHex                                    string `json:"tcpLengthHex"`
			TCPHexParts, ExpectFrames, SequenceTCPHex       []string
			JSON                                            json.RawMessage
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 2 {
		t.Fatal("wrong conformance fixture")
	}
	decode := func(h string) []byte {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			direction := FromViewer
			if strings.HasPrefix(v.Direction, "gateway") {
				direction = FromGateway
			}
			if v.Direction == "platform->gateway" {
				direction = FromPlatform
			}
			if len(v.SequenceTCPHex) > 0 {
				joined := []byte{}
				for _, h := range v.SequenceTCPHex {
					joined = append(joined, decode(h)...)
				}
				reader := bytes.NewReader(joined)
				if _, err := ReadFrame(reader, FromPlatform, false); err != nil {
					t.Fatal(err)
				}
				if _, err := ReadFrame(reader, FromPlatform, true); err != nil {
					t.Fatal(err)
				}
				if _, err := ReadFrame(reader, FromPlatform, true); err == nil {
					t.Fatal("second attach accepted")
				}
				return
			}
			if len(v.TCPHexParts) > 0 {
				var joined []byte
				for _, h := range v.TCPHexParts {
					joined = append(joined, decode(h)...)
				}
				reader := &oneByteReader{Reader: bytes.NewReader(joined)}
				for _, expected := range v.ExpectFrames {
					b, err := ReadFrame(reader, FromGateway, true)
					if err != nil || !bytes.Equal(b, decode(expected)) {
						t.Fatalf("reassembly: %x %v", b, err)
					}
				}
				return
			}
			if v.TCPLengthHex != "" {
				if _, err := ReadFrame(bytes.NewReader(decode(v.TCPLengthHex)), direction, false); err == nil {
					t.Fatal("oversize accepted")
				}
				return
			}
			if v.FrameHex == "" && v.TCPHex == "" {
				return
			}
			var b []byte
			var err error
			if v.TCPHex != "" {
				b, err = ReadFrame(bytes.NewReader(decode(v.TCPHex)), direction, false)
			} else {
				b = decode(v.FrameHex)
				err = ValidateFrame(b, direction, false)
			}
			if strings.HasPrefix(v.Name, "reject-") {
				if err == nil {
					t.Fatal("forbidden frame accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(v.JSON) > 0 {
				var got, want any
				if json.Unmarshal(b[1:], &got) != nil || json.Unmarshal(v.JSON, &want) != nil {
					t.Fatal("invalid fixture JSON")
				}
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(want)
				if !bytes.Equal(g, w) {
					t.Fatal("wire JSON differs")
				}
			}
			var out bytes.Buffer
			if err := WriteFrame(&out, b); err != nil {
				t.Fatal(err)
			}
			if v.TCPHex != "" && !bytes.Equal(out.Bytes(), decode(v.TCPHex)) {
				t.Fatal("TCP encoding differs")
			}
		})
	}
}

func TestAttachAuthorityAndMalformedFrames(t *testing.T) {
	var attach Attach
	_ = json.Unmarshal([]byte(`{"t":"attach","v":1,"sessionId":"session","allocationGen":1,"controllerGen":3,"actor":{"id":"actor"}}`), &attach)
	binding := Binding{AllocationGen: 1, ControllerGen: 3, ActorID: "actor"}
	if err := attach.Validate("session", binding); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Binding{{2, 3, "actor"}, {1, 4, "actor"}, {1, 3, "forged"}} {
		if attach.Validate("session", bad) == nil {
			t.Fatal("forged authority accepted")
		}
	}
	if attach.Validate("wrong", binding) == nil {
		t.Fatal("wrong session accepted")
	}
	for _, b := range [][]byte{{Control, '{'}, {Control, '[', ']'}, {Input, 0xff}, append([]byte{Input}, bytes.Repeat([]byte{' '}, 4097)...)} {
		if ValidateFrame(b, FromViewer, true) == nil {
			t.Fatal("malformed frame accepted")
		}
	}
	if err := ValidateFrame(ControlFrame(map[string]string{"t": "paste"}), FromViewer, true); err == nil {
		t.Fatal("removed paste control accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0}), FromViewer, false); err != io.ErrUnexpectedEOF {
		t.Fatalf("short header: %v", err)
	}
}
