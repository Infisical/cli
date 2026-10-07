package certscan

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildFindCommand(t *testing.T) {
	cmd := buildFindCommand([]string{"/etc/ssl", "/opt/my app"}, []string{"/etc/ssl/certs/"}, 8)
	for _, want := range []string{"find -L '/etc/ssl' '/opt/my app' -maxdepth 8", "-path '/proc'", "-path '/etc/ssl/certs' \\)", "-iname '*.pfx'", "-iname 'cacerts'", "-print0"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q is missing %q", cmd, want)
		}
	}
}

func TestParseFindOutput(t *testing.T) {
	got := parseFindOutput([]byte("/a.pem\x00/b\nc.pem\x00/c d.crt\x00"))
	if !reflect.DeepEqual(got, []string{"/a.pem", "/c d.crt"}) {
		t.Fatalf("unexpected paths %v", got)
	}
}

func TestParseFindOutputDropsAPathCutOffMidway(t *testing.T) {
	got := parseFindOutput([]byte("/a.pem\x00/opt/app/ce"))
	if !reflect.DeepEqual(got, []string{"/a.pem"}) {
		t.Fatalf("unexpected paths %v", got)
	}
	if got := parseFindOutput([]byte("/opt/app/ce")); len(got) != 0 {
		t.Fatalf("expected no complete paths, got %v", got)
	}
}

func TestParseDeniedFolders(t *testing.T) {
	stderr := "find: ‘/etc/letsencrypt/live’: Permission denied\nfind: '/opt/x': Permission denied\nfind: '/y': No such file or directory\n"
	got := parseDeniedFolders([]byte(stderr))
	if !reflect.DeepEqual(got, []string{"/etc/letsencrypt/live", "/opt/x"}) {
		t.Fatalf("unexpected denied %v", got)
	}
}

func TestRemainingDepth(t *testing.T) {
	if d := remainingDepth("/etc/letsencrypt/live", []string{"/etc/letsencrypt"}, 8); d != 7 {
		t.Fatalf("expected 7, got %d", d)
	}
	if d := remainingDepth("/var/x", []string{"/etc"}, 8); d != -1 {
		t.Fatalf("expected -1, got %d", d)
	}
}
