package agentvault

import (
	"encoding/base64"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func enabledGrantWire(key string) api.AgentVaultActivityGrant {
	return api.AgentVaultActivityGrant{Enabled: true, SessionKey: key, ProjectID: "proj-1"}
}

func aKey(b byte) []byte {
	key := make([]byte, activityKeyBytes)
	for i := range key {
		key[i] = b
	}
	return key
}

func TestTheFirstResolveTakesTheKeyOffTheWire(t *testing.T) {
	want := aKey(7)
	got := toActivityGrant("s1", enabledGrantWire(base64.StdEncoding.EncodeToString(want)), nil)

	if got == nil {
		t.Fatal("activity was enabled but no grant was built")
	}
	if got.sessionID != "s1" || got.projectID != "proj-1" {
		t.Fatalf("grant names session %q project %q", got.sessionID, got.projectID)
	}
	if string(got.key) != string(want) {
		t.Fatal("the key on the grant is not the key Infisical sent")
	}
}

// The key is sent exactly once per session, because unwrapping it costs a KMS round trip. Every poll
// after the first answers with an empty sessionKey, and the cached copy has to be carried onto the
// refreshed entry. Getting this backwards silently stops all logging after the first poll, which is why
// it has a test of its own.
func TestACachedKeySurvivesAResolveThatOmitsIt(t *testing.T) {
	held := &activityGrant{sessionID: "s1", projectID: "proj-1", key: aKey(9)}

	got := toActivityGrant("s1", enabledGrantWire(""), held)

	if got == nil {
		t.Fatal("the grant was cleared when the response carried no key; logging would stop after one poll")
	}
	if string(got.key) != string(held.key) {
		t.Fatal("the cached key was not carried forward")
	}
}

func TestNoKeyAndNoCachedCopyMeansNoRecording(t *testing.T) {
	// The proxy said it had no key and was sent none, so there is nothing to seal with. Recording
	// anything here would produce chunks nobody can ever open.
	if got := toActivityGrant("s1", enabledGrantWire(""), nil); got != nil {
		t.Fatal("a grant was built with no key at all")
	}
}

func TestActivityBeingOffClearsAnyCachedGrant(t *testing.T) {
	held := &activityGrant{sessionID: "s1", projectID: "proj-1", key: aKey(9)}

	// An admin switching logging off has to reach a running proxy on its next poll.
	if got := toActivityGrant("s1", api.AgentVaultActivityGrant{Enabled: false}, held); got != nil {
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
		if got := toActivityGrant("s1", enabledGrantWire(wire.key), nil); got != nil {
			t.Fatalf("a key that is %s was accepted", wire.name)
		}
	}
}

func TestAGrantWithoutAProjectIsRefused(t *testing.T) {
	// The project id is part of the AAD, so a chunk sealed without it could never be opened.
	wire := api.AgentVaultActivityGrant{Enabled: true, SessionKey: base64.StdEncoding.EncodeToString(aKey(7))}
	if got := toActivityGrant("s1", wire, nil); got != nil {
		t.Fatal("a grant was built with no project named")
	}
}
