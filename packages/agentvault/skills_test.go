package agentvault

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
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

func TestSkillHeaderName(t *testing.T) {
	cases := map[string]string{
		"---\nname: code-review\ndescription: x\n---\nbody":    "code-review",
		"---\r\ndescription: x\r\nname: \"quoted\"\r\n---\r\n": "quoted",
		"---\nname: 'single'\n---\n":                           "single",
		"---\nname: code-review # the reviewer\n---\n":         "code-review",
		"---\nname: \"a # b\"\n---\n":                          "a # b",
		"---\nmetadata:\n  name: nested\nname: top\n---\n":     "top",
		"--- \nname: trailing\n---\t\n":                        "trailing",
	}
	cases["\ufeff---\nname: with-bom\n---\n"] = "with-bom"
	for in, want := range cases {
		got, err := SkillHeaderName([]byte(in))
		if err != nil || got != want {
			t.Fatalf("%q: got %q, %v", in, got, err)
		}
	}
	for _, in := range []string{
		"no header",
		"---\ndescription: x\n---\nname: late\n",
		"",
		"---\nname: unterminated\n",
		"---\nmetadata:\n  name: nested\n---\n",
		"---\nname:\n---\n",
		"---\nname: [a, b]\n---\n",
		"---\nname: \"open\n---\n",
		" ---\nname: indented-open\n---\n",
		"---\nname: indented-close\n  ---\n",
	} {
		if _, err := SkillHeaderName([]byte(in)); err == nil {
			t.Fatalf("%q was accepted", in)
		}
	}
	if _, err := SkillHeaderName([]byte("---\nname: 123\n---\n")); err == nil || !strings.Contains(err.Error(), "Put it in quotes") {
		t.Fatalf("a number name gave %v", err)
	}
}
