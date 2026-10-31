package agentvault

import (
	"encoding/base64"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func enabledGrantWire(key string) api.AgentVaultSessionLogGrant {
	return api.AgentVaultSessionLogGrant{Enabled: true, SessionKey: key}
}

func aKey(b byte) []byte {
	key := make([]byte, sessionLogKeyBytes)
	for i := range key {
		key[i] = b
	}
	return key
}

func TestTheFirstResolveTakesTheKeyOffTheWire(t *testing.T) {
	want := aKey(7)
	got := toSessionLogGrant("s1", enabledGrantWire(base64.StdEncoding.EncodeToString(want)), nil)

	if got == nil {
		t.Fatal("session logs were on but no grant was built")
	}
	if got.sessionID != "s1" {
		t.Fatalf("grant names session %q", got.sessionID)
	}
	if string(got.key) != string(want) {
		t.Fatal("the key on the grant is not the key Infisical sent")
	}
}

func TestACachedKeySurvivesAResolveThatOmitsIt(t *testing.T) {
	held := &sessionLogGrant{sessionID: "s1", key: aKey(9)}

	got := toSessionLogGrant("s1", enabledGrantWire(""), held)

	if got == nil {
		t.Fatal("the grant was cleared when the response carried no key; logging would stop after one poll")
	}
	if string(got.key) != string(held.key) {
		t.Fatal("the cached key was not carried forward")
	}
}

func TestNoKeyAndNoCachedCopyMeansNoRecording(t *testing.T) {
	if got := toSessionLogGrant("s1", enabledGrantWire(""), nil); got != nil {
		t.Fatal("a grant was built with no key at all")
	}
}

func TestSessionLogBeingOffClearsAnyCachedGrant(t *testing.T) {
	held := &sessionLogGrant{sessionID: "s1", key: aKey(9)}

	if got := toSessionLogGrant("s1", api.AgentVaultSessionLogGrant{Enabled: false}, held); got != nil {
		t.Fatal("the proxy kept recording after logging was switched off")
	}
}

func TestAnUnusableKeyIsRefusedRatherThanUsed(t *testing.T) {
	for _, wire := range []struct {
		name string
		key  string
	}{
		{"not base64", "!!!!not base64!!!!"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 64))},
	} {
		if got := toSessionLogGrant("s1", enabledGrantWire(wire.key), nil); got != nil {
			t.Fatalf("a key that is %s was accepted", wire.name)
		}
	}
}
