package agentvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/api"
	"gopkg.in/yaml.v3"
)

// SkillFilesSha256 is the hash Infisical stores for a version: sha256 over the files sorted by the UTF-8 bytes
// of their paths, as the JSON array [{path, mode, contentBase64}] that JavaScript's JSON.stringify produces.
// encoding/json is not used because it escapes <, >, & and U+2028/U+2029 where JSON.stringify does not.
func SkillFilesSha256(files []api.AgentVaultSkillFile) string {
	sorted := append([]api.AgentVaultSkillFile(nil), files...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, f := range sorted {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"path":`)
		writeJSString(&buf, f.Path)
		buf.WriteString(`,"mode":`)
		writeJSString(&buf, f.Mode)
		buf.WriteString(`,"contentBase64":`)
		writeJSString(&buf, f.ContentBase64)
		buf.WriteByte('}')
	}
	buf.WriteByte(']')
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func writeJSString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[r>>4])
				buf.WriteByte(hexDigits[r&0xf])
				continue
			}
			var enc [utf8.UTFMax]byte
			n := utf8.EncodeRune(enc[:], r)
			buf.Write(enc[:n])
		}
	}
	buf.WriteByte('"')
}

// SkillHeaderName reads only the name from a SKILL.md header. Infisical parses and validates the whole header.
func SkillHeaderName(skillMd []byte) (string, error) {
	lines := strings.Split(string(bytes.TrimPrefix(skillMd, []byte("\ufeff"))), "\n")
	isDelimiter := func(line string) bool { return strings.TrimRight(line, " \t\r") == "---" }
	end := slices.IndexFunc(lines[1:], isDelimiter)
	if !isDelimiter(lines[0]) || end < 0 {
		return "", errors.New("SKILL.md must start with a header between '---' lines that sets name")
	}
	var header map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(lines[1:end+1], "\n")), &header); err != nil {
		return "", fmt.Errorf("the SKILL.md header is not valid YAML: %w", err)
	}
	name, isText := header["name"].(string)
	if !isText && header["name"] != nil {
		return "", errors.New("the 'name' in the SKILL.md header must be text. Put it in quotes")
	}
	if strings.TrimSpace(name) == "" {
		return "", errors.New("the SKILL.md header does not set name")
	}
	return name, nil
}
