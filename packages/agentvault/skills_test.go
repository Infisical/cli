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

func TestSkillHeaderNameSaysWhichLineIsNotYAML(t *testing.T) {
	bom := "\ufeff"
	for in, want := range map[string]string{
		"---\nname: audit\ndescription: Audit a change set for coherence: map every goal to code. Read-only.\n---\n": "Line 3 of SKILL.md: the 'description' value contains ': '. Put the value in double quotes.",
		"---\r\nname: infi\r\ndescription: Drive a local stack: print a JWT.\r\n---\r\n":                             "Line 3 of SKILL.md: the 'description' value contains ': '. Put the value in double quotes.",
		bom + "---\nname: s\nmetadata:\n  a: b\nsummary: one: two\n---\n":                                            "Line 5 of SKILL.md: the 'summary' value contains ': '. Put the value in double quotes.",
		"---\nname: a\nb: c\n  d: e\n---\n":                                                                          "Line 4 of SKILL.md: the header is not valid YAML (mapping values are not allowed in this context).",
		"---\r\nname: a\r\n\tbad: x\r\n---\r\n":                                                                      "Line 3 of SKILL.md: the header is not valid YAML (found a tab character that violates indentation).",
		"---\nname: a\ndescription: d\nx: 1\nhint: [x\n---\n":                                                        "Line 5 of SKILL.md: the 'hint' value opens a '[' that never closes.",
		"---\nname: a\ndescription: d\nx: 1\nhint: {x\n---\n":                                                        "Line 5 of SKILL.md: the 'hint' value opens a '{' that never closes.",
		"---\nname: a\ndescription: d\nx: 1\nhint: \"x\n---\n":                                                       "Line 5 of SKILL.md: the 'hint' value opens a double quote that never closes.",
		"---\nname: a\ndescription: d\nx: 1\nhint: 'x\n---\n":                                                        "Line 5 of SKILL.md: the 'hint' value opens a single quote that never closes.",
		"---\nname: a\nlist: [a,\n  b]\nhint: {x\n---\n":                                                             "Line 5 of SKILL.md: the 'hint' value opens a '{' that never closes.",
		"---\r\nname: a\r\ndescription: d\r\nx: 1\r\nhint: [x\r\n---\r\n":                                            "Line 5 of SKILL.md: the 'hint' value opens a '[' that never closes.",
		bom + "---\nname: a\ndescription: d\nx: 1\nhint: [x\n---\n":                                                  "Line 5 of SKILL.md: the 'hint' value opens a '[' that never closes.",
		"---\nname: x\nname: y\n---\n":                                                                               "Line 3 of SKILL.md: the header is not valid YAML (mapping key \"name\" already defined at line 2).",
	} {
		if _, err := SkillHeaderName([]byte(in)); err == nil || err.Error() != want {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
	for _, in := range []string{
		"---\nname: a\ndescription: \"quoted: fine\"\n---\n",
		"---\nname: a\ndescription: 'quoted: fine'\n---\n",
		"---\nname: a\ndescription: >\n  folded: fine\n---\n",
		"---\nname: a\ndescription: no colon space:here\n---\n",
	} {
		if _, err := SkillHeaderName([]byte(in)); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{
		"---\nname: a\ndescription: fine # see: below\nhint: [unclosed\n---\n",
		"---\n- a: b: c\n---\n",
	} {
		if _, err := SkillHeaderName([]byte(in)); err == nil || strings.Contains(err.Error(), "value contains ': '") {
			t.Errorf("%q: got %v, want a YAML error that doesn't blame a ': ' value", in, err)
		}
	}
	for _, in := range []string{
		"---\ndescription: \"first\nsecond\"\nname: a\nname: b\n---\n",
		"---\nhint: [a,\n# note\n  b]\nname: a\nname: b\n---\n",
	} {
		if _, err := SkillHeaderName([]byte(in)); err == nil || strings.Contains(err.Error(), "never closes") {
			t.Errorf("%q: got %v, want the duplicate key error, not a valid value blamed", in, err)
		}
	}
	if _, err := SkillHeaderName([]byte("---\nname: \"oops\ndescription: y\n---\n")); err == nil || err.Error() != "Line 2 of SKILL.md: the 'name' value opens a double quote that never closes." {
		t.Errorf("unclosed quote before the next key: got %v", err)
	}
}
