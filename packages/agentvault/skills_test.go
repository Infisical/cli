package agentvault

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestSkillFilesSha256MatchesJSONStringify(t *testing.T) {
	files := []api.AgentVaultSkillFile{
		{Path: "z.sh", Mode: "0755", ContentBase64: "eA=="},
		{Path: "a<&> \"\\\n.md", Mode: "0644", ContentBase64: "eQ=="},
	}
	// What JSON.stringify(sortedFiles) prints for the same input.
	stringified := `[{"path":"a<&>` + " " + `\"\\\n.md","mode":"0644","contentBase64":"eQ=="},{"path":"z.sh","mode":"0755","contentBase64":"eA=="}]`
	sum := sha256.Sum256([]byte(stringified))
	if got, want := SkillFilesSha256(files), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash %s, want %s", got, want)
	}
	if files[0].Path != "z.sh" {
		t.Fatal("hashing reordered the caller's slice")
	}
}

// U+FF5A sorts after an astral character in UTF-16 but before it in UTF-8, and Infisical sorts by UTF-8 bytes.
func TestSkillFilesSha256SortsByUTF8Bytes(t *testing.T) {
	files := []api.AgentVaultSkillFile{
		{Path: "\U0001D49C.md", Mode: "0644", ContentBase64: "eA=="},
		{Path: "ｚ.md", Mode: "0644", ContentBase64: "eQ=="},
	}
	stringified := `[{"path":"` + "ｚ" + `.md","mode":"0644","contentBase64":"eQ=="},{"path":"` + "\U0001D49C" + `.md","mode":"0644","contentBase64":"eA=="}]`
	sum := sha256.Sum256([]byte(stringified))
	if got, want := SkillFilesSha256(files), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash %s, want %s", got, want)
	}
}
