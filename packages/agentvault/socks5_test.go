package agentvault

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSocks5SessionTokenShape(t *testing.T) {
	valid := "agv_" + strings.Repeat("aZ0-_", 8) + "abc"
	for _, tc := range []struct {
		name  string
		token string
		want  bool
	}{
		{"a token as Infisical issues it", valid, true},
		{"empty", "", false},
		{"no prefix", "xyz_" + valid[4:], false},
		{"one character short", valid[:len(valid)-1], false},
		{"one character long", valid + "a", false},
		{"padding is not base64url", valid[:len(valid)-1] + "=", false},
		{"a trailing newline from an env file", valid[:len(valid)-1] + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := plausibleSessionToken(tc.token); got != tc.want {
				t.Errorf("plausibleSessionToken(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

func TestSocks5Greeting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		frame   []byte
		offers  bool
		wantErr bool
	}{
		{"username and password offered", []byte{5, 2, 0, 2}, true, false},
		{"only no-auth offered", []byte{5, 1, 0}, false, false},
		{"no methods at all", []byte{5, 0}, false, false},
		{"SOCKS4", []byte{4, 1, 0}, false, true},
		{"cut short", []byte{5, 2, 0}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offers, err := readSocks5Greeting(bytes.NewReader(tc.frame))
			if (err != nil) != tc.wantErr || offers != tc.offers {
				t.Errorf("got offers=%v err=%v, want offers=%v err=%v", offers, err, tc.offers, tc.wantErr)
			}
		})
	}
}

func TestSocks5AuthIgnoresTheUsername(t *testing.T) {
	for _, tc := range []struct {
		name     string
		frame    []byte
		password string
		wantErr  bool
	}{
		{"username and password", append([]byte{1, 3, 'b', 'o', 'b', 3}, "pwd"...), "pwd", false},
		{"empty username", append([]byte{1, 0, 3}, "pwd"...), "pwd", false},
		{"empty password", []byte{1, 3, 'b', 'o', 'b', 0}, "", false},
		{"wrong sub-negotiation version", append([]byte{5, 0, 3}, "pwd"...), "", true},
		{"cut short", []byte{1, 3, 'b'}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password, err := readSocks5Auth(bytes.NewReader(tc.frame))
			if (err != nil) != tc.wantErr || password != tc.password {
				t.Errorf("got %q err=%v, want %q err=%v", password, err, tc.password, tc.wantErr)
			}
		})
	}
}

func TestSocks5Request(t *testing.T) {
	domain := func(cmd byte, host string, port uint16) []byte {
		frame := []byte{5, cmd, 0, socks5AtypDomain, byte(len(host))}
		frame = append(frame, host...)
		return append(frame, byte(port>>8), byte(port))
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		host  string
		port  uint16
		rep   byte
	}{
		{"domain", domain(1, "api.example.com", 443), "api.example.com", 443, 0},
		{"IPv4", []byte{5, 1, 0, socks5AtypIPv4, 10, 0, 0, 1, 0, 80}, "10.0.0.1", 80, 0},
		{"IPv6", append([]byte{5, 1, 0, socks5AtypIPv6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 1, 187), "2001:db8::1", 443, 0},
		{"a non-zero reserved byte is accepted", []byte{5, 1, 7, socks5AtypIPv4, 1, 2, 3, 4, 0, 80}, "1.2.3.4", 80, 0},
		{"BIND is refused", domain(2, "api.example.com", 443), "", 0, socks5RepCmdUnsup},
		{"UDP ASSOCIATE is refused", domain(3, "api.example.com", 443), "", 0, socks5RepCmdUnsup},
		{"unknown address type", []byte{5, 1, 0, 9, 1, 2, 3, 4, 0, 80}, "", 0, socks5RepAtypUnsup},
		{"empty domain", domain(1, "", 443), "", 0, socks5RepFailure},
		{"port 0", domain(1, "api.example.com", 0), "", 0, socks5RepFailure},
		{"wrong version", []byte{4, 1, 0, socks5AtypIPv4, 1, 2, 3, 4, 0, 80}, "", 0, socks5RepFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, rep, err := readSocks5Request(bytes.NewReader(tc.frame))
			if tc.rep != 0 {
				if err == nil || rep != tc.rep {
					t.Fatalf("got rep=%#x err=%v, want rep=%#x", rep, err, tc.rep)
				}
				return
			}
			if err != nil || req.host != tc.host || req.port != tc.port {
				t.Fatalf("got %+v err=%v, want %s:%d", req, err, tc.host, tc.port)
			}
		})
	}
}

// Whatever the client sends after the request is the tunnel's first bytes, so the parsers must not read
// past their own frames.
func TestSocks5ParsersLeavePipelinedBytesUnread(t *testing.T) {
	var stream bytes.Buffer
	stream.Write([]byte{5, 1, 2})
	stream.Write(append([]byte{1, 1, 'u', 3}, "pwd"...))
	stream.Write([]byte{5, 1, 0, socks5AtypIPv4, 127, 0, 0, 1, 1, 187})
	stream.WriteString("\x16\x03\x01rest-of-the-client-hello")

	r := &stream
	if _, err := readSocks5Greeting(r); err != nil {
		t.Fatal(err)
	}
	if _, err := readSocks5Auth(r); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSocks5Request(r); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "\x16\x03\x01rest-of-the-client-hello" {
		t.Fatalf("the tunnel's bytes were consumed: %q", rest)
	}
}

func FuzzSocks5Request(f *testing.F) {
	f.Add([]byte{5, 1, 0, socks5AtypDomain, 3, 'a', '.', 'b', 1, 187})
	f.Add([]byte{5, 1, 0, socks5AtypIPv4, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{5, 1, 0, socks5AtypIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80})
	f.Add([]byte{5, 2, 0, 9})
	f.Add([]byte{5, 1, 0, socks5AtypDomain, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		req, rep, err := readSocks5Request(r)
		if err != nil {
			if rep != 0 && rep != socks5RepFailure && rep != socks5RepCmdUnsup && rep != socks5RepAtypUnsup {
				t.Fatalf("unexpected reply code %#x", rep)
			}
			return
		}
		if req.host == "" || req.port == 0 || req.cmd != socks5CmdConnect {
			t.Fatalf("accepted an incomplete request: %+v", req)
		}
		if consumed := len(data) - r.Len(); consumed > len(data) {
			t.Fatal("read past the input")
		}
	})
}

func TestSocks5ReplyIsAlwaysWellFormed(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSocks5Reply(&buf, socks5RepCmdUnsup); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, []byte{5, socks5RepCmdUnsup, 0, 1, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("reply = %v", got)
	}
}

func TestSocks5GreetingFromANonSocksClient(t *testing.T) {
	_, err := readSocks5Greeting(strings.NewReader("GET / HTTP/1.1\r\n"))
	if !errors.Is(err, errSocks5Version) {
		t.Fatalf("err = %v, want errSocks5Version", err)
	}
}
