package certscan

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
)

var certificatePatterns = []string{
	"*.pem", "*.crt", "*.cer", "*.cert", "*.der", "*.p7b", "*.p7c", "*.pfx", "*.p12", "*.jks", "*.keystore", "*.truststore", "*.jceks", "*.ks", "cacerts",
}

var pseudoFilesystems = []string{"/proc", "/sys", "/dev"}

var findPatternEscaper = strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`)

var findPermissionDenied = regexp.MustCompile(`find: [‘'"](.+?)[’'"]: Permission denied`)

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

func parseDeniedFolders(stderr []byte) []string {
	var denied []string
	for _, match := range findPermissionDenied.FindAllSubmatch(stderr, -1) {
		denied = append(denied, string(match[1]))
	}
	return denied
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
