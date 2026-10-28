package agentvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
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
	headerLines := lines[1 : end+1]
	var header map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(headerLines, "\n")), &header); err != nil {
		return "", skillHeaderYAMLError(headerLines, err)
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

// skillHeaderYAMLError words a header that does not parse the way Infisical does. Line numbers count from the
// top of SKILL.md, where the opening '---' is line 1 and the header starts on line 2.
func skillHeaderYAMLError(headerLines []string, err error) error {
	const firstHeaderLine = 2
	for i, line := range headerLines {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), ": ")
		if !ok || key == "" || strings.ContainsAny(key[:1], " \t#-") {
			continue
		}
		value = strings.TrimSpace(value)
		if comment := strings.Index(value, " #"); comment >= 0 {
			value = value[:comment]
		}
		if value != "" && !strings.ContainsAny(value[:1], "\"'|>[{") && strings.Contains(value, ": ") {
			return fmt.Errorf("Line %d of SKILL.md: the '%s' value contains ': '. Put the value in double quotes.", i+firstHeaderLine, key)
		}
	}
	if line, key, opener, found := findUnclosedValue(headerLines); found {
		what := fmt.Sprintf("a '%c'", opener)
		switch opener {
		case '"':
			what = "a double quote"
		case '\'':
			what = "a single quote"
		}
		return fmt.Errorf("Line %d of SKILL.md: the '%s' value opens %s that never closes.", line+firstHeaderLine, key, what)
	}
	message := strings.TrimPrefix(err.Error(), "yaml: ")
	message = strings.TrimLeft(strings.TrimPrefix(message, "unmarshal errors:"), " \n")
	if rest, ok := strings.CutPrefix(message, "line "); ok {
		number, reason, _ := strings.Cut(rest, ": ")
		reason, _, _ = strings.Cut(reason, "\n")
		if line, convErr := strconv.Atoi(number); convErr == nil && reason != "" {
			// A duplicate key also names the line of the first one, counted from the header too.
			if before, earlier, found := strings.Cut(reason, " at line "); found {
				if earlierLine, earlierErr := strconv.Atoi(earlier); earlierErr == nil {
					reason = fmt.Sprintf("%s at line %d", before, earlierLine+firstHeaderLine-1)
				}
			}
			return fmt.Errorf("Line %d of SKILL.md: the header is not valid YAML (%s).", line+firstHeaderLine-1, strings.TrimSuffix(reason, "."))
		}
	}
	return fmt.Errorf("the SKILL.md header is not valid YAML: %w", err)
}

func isBlankByte(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

// startsTopLevelKey reports whether line begins a new top-level key. A quoted or flow value may continue on lines
// that start at column zero, and comments may sit between its lines, so only the next key ends it.
func startsTopLevelKey(line string) bool {
	if line == "" || strings.ContainsAny(line[:1], " \t#-") {
		return false
	}
	colon := strings.IndexByte(line, ':')
	return colon > 0 && (colon == len(line)-1 || line[colon+1] == ' ' || line[colon+1] == '\t')
}

// findUnclosedValue finds a flow or quoted value that never closes. Its whole block, up to the next top-level key,
// is scanned first. It mirrors findUnclosedValue in Infisical's agent-vault-skill-fns.ts.
func findUnclosedValue(headerLines []string) (line int, key string, opener byte, found bool) {
	for i, raw := range headerLines {
		k, value, ok := strings.Cut(strings.TrimRight(raw, "\r"), ": ")
		if !ok || k == "" || strings.ContainsAny(k[:1], " \t#-") {
			continue
		}
		value = strings.TrimLeft(value, " \t")
		if value == "" || !strings.ContainsAny(value[:1], "[{\"'") {
			continue
		}
		block := []string{value}
		for _, next := range headerLines[i+1:] {
			next = strings.TrimRight(next, "\r")
			if startsTopLevelKey(next) {
				break
			}
			block = append(block, next)
		}
		if !valueCloses(strings.Join(block, "\n")) {
			return i, strings.TrimRight(k, " \t"), value[0], true
		}
	}
	return 0, "", 0, false
}

func valueCloses(text string) bool {
	depth := 0
	var quote, previous byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				if depth == 0 {
					return true
				}
				quote, previous = 0, c
			}
		case quote == '\'':
			if c == '\'' && i+1 < len(text) && text[i+1] == '\'' {
				i++
			} else if c == '\'' {
				if depth == 0 {
					return true
				}
				quote, previous = 0, c
			}
		case c == '#' && (i == 0 || isBlankByte(text[i-1])):
			newline := strings.IndexByte(text[i:], '\n')
			if newline < 0 {
				return false
			}
			i += newline
		case (c == '"' || c == '\'') && strings.IndexByte("\x00[{,:", previous) >= 0:
			quote = c
		default:
			if c == '[' || c == '{' {
				depth++
			}
			if c == ']' || c == '}' {
				depth--
				if depth == 0 {
					return true
				}
			}
			if !isBlankByte(c) {
				previous = c
			}
		}
	}
	return false
}
