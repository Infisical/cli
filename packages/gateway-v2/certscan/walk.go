package certscan

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/util"
)

var certificatePatterns = []string{
	"*.pem", "*.crt", "*.cer", "*.cert", "*.der", "*.p7b", "*.p7c", "*.pfx", "*.p12", "*.jks", "*.keystore", "*.truststore", "*.jceks", "*.ks", "cacerts",
}

var pseudoFilesystems = []string{"/proc", "/sys", "/dev"}

var findPatternEscaper = strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`)

const (
	findErrorPrefix       = "find: "
	findPermissionDenied  = ": Permission denied"
	findQuoteChars        = "'\"‘"
	findClosingQuoteChars = "'\"’"
)

var cEscapes = map[byte]byte{'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}

func buildFindCommand(roots, skips []string, depth int) string {
	var b strings.Builder
	b.WriteString("find -L")
	for _, root := range roots {
		b.WriteString(" ")
		b.WriteString(util.ShellQuote(root))
	}
	fmt.Fprintf(&b, " -maxdepth %d \\(", depth)
	pruned := slices.Clone(pseudoFilesystems)
	for _, skip := range skips {
		pruned = append(pruned, findPatternEscaper.Replace(skip))
	}
	for i, p := range pruned {
		if i > 0 {
			b.WriteString(" -o")
		}
		b.WriteString(" -path ")
		b.WriteString(util.ShellQuote(strings.TrimRight(p, "/")))
	}
	b.WriteString(" \\) -prune -o -type f \\(")
	for i, pattern := range certificatePatterns {
		if i > 0 {
			b.WriteString(" -o")
		}
		b.WriteString(" -iname ")
		b.WriteString(util.ShellQuote(pattern))
	}
	b.WriteString(" \\) -print0")
	return b.String()
}

func parseFindOutput(stdout []byte) []string {
	end := bytes.LastIndexByte(stdout, 0)
	if end < 0 {
		return nil
	}
	var paths []string
	for _, part := range bytes.Split(stdout[:end], []byte{0}) {
		if len(part) == 0 || bytes.ContainsAny(part, "\n\r") {
			continue
		}
		paths = append(paths, string(part))
	}
	return paths
}

// parseDeniedFolders reads GNU find's quoted, C-escaped paths ('/a\303\261o', '/it\'s') and busybox's raw unquoted ones.
func parseDeniedFolders(stderr []byte) []string {
	var denied []string
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, findErrorPrefix) || !strings.HasSuffix(line, findPermissionDenied) {
			continue
		}
		folder := strings.TrimSuffix(strings.TrimPrefix(line, findErrorPrefix), findPermissionDenied)
		if strings.HasPrefix(folder, "/") {
			denied = append(denied, folder)
			continue
		}
		if unquoted, ok := unquoteFindPath(folder); ok {
			denied = append(denied, unquoted)
		}
	}
	return denied
}

func unquoteFindPath(quoted string) (string, bool) {
	open, openSize := utf8.DecodeRuneInString(quoted)
	closing, closeSize := utf8.DecodeLastRuneInString(quoted)
	if len(quoted) < openSize+closeSize || !strings.ContainsRune(findQuoteChars, open) || !strings.ContainsRune(findClosingQuoteChars, closing) {
		return "", false
	}
	body := quoted[openSize : len(quoted)-closeSize]
	var out []byte
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' || i+1 == len(body) {
			out = append(out, body[i])
			continue
		}
		i++
		if n := octalRun(body[i:]); n > 0 {
			v, _ := strconv.ParseUint(body[i:i+n], 8, 8)
			out = append(out, byte(v))
			i += n - 1
			continue
		}
		if c, ok := cEscapes[body[i]]; ok {
			out = append(out, c)
			continue
		}
		out = append(out, body[i])
	}
	folder := string(out)
	return folder, strings.HasPrefix(folder, "/")
}

func octalRun(s string) int {
	n := 0
	for n < 3 && n < len(s) && s[n] >= '0' && s[n] <= '7' {
		n++
	}
	if n == 3 && s[0] > '3' {
		return 0
	}
	return n
}

func remainingDepth(folder string, roots []string, depth int) int {
	best := -1
	for _, root := range roots {
		root = strings.TrimRight(root, "/")
		if root == "" {
			root = "/"
		}
		if folder != root && !strings.HasPrefix(folder, root+"/") && root != "/" {
			continue
		}
		rel := strings.Trim(strings.TrimPrefix(folder, root), "/")
		levels := 0
		if rel != "" {
			levels = len(strings.Split(rel, "/"))
		}
		if left := depth - levels; left > best {
			best = left
		}
	}
	return best
}
