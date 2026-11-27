package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

const testCertificateID = "0b9e4f1a-2c3d-4e5f-8a7b-6c5d4e3f2a1b"

func certManagerConstructedErrors() []*util.CLIError {
	cause := errors.New("cause")
	return []*util.CLIError{
		errApplicationRequired(),
		errApplicationNotFound("payments-api", cause),
		errProfileNotFound("devices", "payments-api", []string{"web"}),
		errProfileNotAPIEnabled("devices", "payments-api"),
		errProfileRequired("payments-api", []string{"web", "internal"}),
		errProfileRequired("payments-api", nil),
		errCertificateNotFound(testCertificateID, "payments-api", cause),
		errCertificateRequestNotFound(testCertificateID, "payments-api", cause),
		errCertificateRequestPending(testCertificateID, "pending_approval", "payments-api", "", "Infisical reports: DigiCert order 123 is awaiting validation."),
		errCertificateRequestPending(testCertificateID, "pending_validation", "payments-api", "", ""),
		errCertificateRequestRejected(testCertificateID, "rejected", "Rejected by an approver.", "issue"),
		errCertificateRevocationPending(testCertificateID, testProjectID, "payments-api", "", false, ""),
		errCertificateRevocationRejected(testCertificateID, testProjectID, "expired"),
		errCertificateRevocationUndecidable(testCertificateID, testProjectID),
		errCertificateRequestRejected(testCertificateID, "failed", "The CA is unreachable.", "renew"),
		errCertificateRequestWithoutApplication(testCertificateID, "payments-api"),
		errPrivateKeyUnavailable(testCertificateID),
		errCertificateUnavailable(testCertificateID),
		errCertificateRevocationPending(testCertificateID, testProjectID, "payments-api", " --domain https://example.com", true, "The last check failed: 503."),
		errInvalidChoice("key-usage", "signing", certKeyUsages),
		errInvalidFlag("timeout", "must be a positive duration, such as 5m"),
		errFlagsConflict("ttl", "not-after", "pass either a TTL or a validity range"),
		errOutputFileExists("output-certificate-file", "cert.pem"),
		errNotAnID("certificate", "abc"),
	}
}

func certSubcommand(t *testing.T, name string) *cobra.Command {
	t.Helper()
	cmd, _, err := buildCertManagerCertificatesCmd().Find([]string{name})
	if err != nil || cmd.Name() != name {
		t.Fatalf("no certificates %s command: %v", name, err)
	}
	return cmd
}

func setFlags(t *testing.T, cmd *cobra.Command, flags ...string) {
	t.Helper()
	for i := 0; i < len(flags); i += 2 {
		if err := cmd.Flags().Set(flags[i], flags[i+1]); err != nil {
			t.Fatalf("set --%s: %v", flags[i], err)
		}
	}
}

func TestSubjectAlternativeNameType(t *testing.T) {
	for value, want := range map[string]string{
		"app.example.com":          "dns_name",
		"*.example.com":            "dns_name",
		"10.0.0.5":                 "ip_address",
		"2001:db8::1":              "ip_address",
		"ops@example.com":          "email",
		"spiffe://example.com/svc": "uri",
		"https://user@example.com": "uri",
		"urn:uuid:1234":            "uri",
		"mailto:ops@example.com":   "uri",
	} {
		if got := subjectAlternativeName(value); got.Type != want || got.Value != value {
			t.Errorf("subjectAlternativeName(%q) = %+v, want type %s", value, got, want)
		}
	}
}

func TestSelectIssuanceProfile(t *testing.T) {
	apiConfig := "c0ffee00-0000-4000-8000-000000000000"
	web := api.PkiApplicationProfile{ProfileID: "p-web", ProfileSlug: "web", APIConfigID: &apiConfig}
	internal := api.PkiApplicationProfile{ProfileID: "p-internal", ProfileSlug: "internal", APIConfigID: &apiConfig}
	devices := api.PkiApplicationProfile{ProfileID: "p-devices", ProfileSlug: "devices"}

	cases := []struct {
		name     string
		profiles []api.PkiApplicationProfile
		flag     string
		wantID   string
		wantCode string
	}{
		{"only API profile picked", []api.PkiApplicationProfile{web, devices}, "", "p-web", ""},
		{"several API profiles", []api.PkiApplicationProfile{web, internal}, "", "", errCodeProfileRequired},
		{"no API profile", []api.PkiApplicationProfile{devices}, "", "", errCodeProfileRequired},
		{"named API profile", []api.PkiApplicationProfile{web, internal}, "internal", "p-internal", ""},
		{"named profile without API enrollment", []api.PkiApplicationProfile{web, devices}, "devices", "", errCodeProfileNotAPIEnabled},
		{"named profile not attached", []api.PkiApplicationProfile{web}, "other", "", errCodeProfileNotFound},
	}
	for _, c := range cases {
		profile, err := selectIssuanceProfile(c.profiles, c.flag, "payments-api")
		if c.wantCode != "" {
			if err == nil || err.Code != c.wantCode {
				t.Errorf("%s: got %v, want %s", c.name, err, c.wantCode)
			}
			continue
		}
		if err != nil || profile.ProfileID != c.wantID {
			t.Errorf("%s: got %q, %v; want %q", c.name, profile.ProfileID, err, c.wantID)
		}
	}
}

func TestParseRevocationReason(t *testing.T) {
	for input, want := range map[string]string{"key_compromise": "KEY_COMPROMISE", "KEY_COMPROMISE": "KEY_COMPROMISE", " Superseded ": "SUPERSEDED"} {
		if got, err := parseRevocationReason(input); err != nil || got != want {
			t.Errorf("parseRevocationReason(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "bogus"} {
		if _, err := parseRevocationReason(input); err == nil || err.Code != errCodeInvalidFlagValue {
			t.Errorf("parseRevocationReason(%q) = %v, want invalid_flag_value", input, err)
		}
	}
}

func TestReadCertRequestInputBuildsAttributes(t *testing.T) {
	cmd := certSubcommand(t, "issue")
	setFlags(t, cmd,
		"common-name", "app.example.com",
		"subject-alternative-name", "app.example.com",
		"subject-alternative-name", "10.0.0.5",
		"key-usage", "digital_signature",
		"extended-key-usage", "server_auth",
		"ttl", "30d",
		"is-ca", "true",
		"path-length", "0",
		"custom-extension", "1.3.6.1.4.1.311.25.2=S-1-5-21-1",
		"critical-extension", " 1.3.6.1.4.1.311.25.2 ",
		"critical-extension", "1.2.3.4",
		"critical-extension", "1.2.3.4 ",
		"remove-roots-from-chain", "true",
	)
	input, err := readCertRequestInput(cmd)
	if err != nil {
		t.Fatal(err)
	}
	a := input.Attributes
	if a == nil || a.CommonName != "app.example.com" || a.TTL != "30d" || !input.RemoveRoot {
		t.Fatalf("attributes = %+v, removeRoot = %v", a, input.RemoveRoot)
	}
	if len(a.AltNames) != 2 || a.AltNames[1].Type != "ip_address" {
		t.Errorf("altNames = %+v", a.AltNames)
	}
	if a.BasicConstraints == nil || !a.BasicConstraints.IsCA || a.BasicConstraints.PathLength == nil || *a.BasicConstraints.PathLength != 0 {
		t.Errorf("basicConstraints = %+v", a.BasicConstraints)
	}
	want := []api.CertificateCustomExtension{{OID: "1.3.6.1.4.1.311.25.2", Value: "S-1-5-21-1", Critical: true}, {OID: "1.2.3.4", Critical: true}}
	if len(a.CustomExtensions) != 2 || a.CustomExtensions[0] != want[0] || a.CustomExtensions[1] != want[1] {
		t.Errorf("customExtensions = %+v, want %+v", a.CustomExtensions, want)
	}
}

func TestReadCertRequestInputWithoutFlagsSendsNoAttributes(t *testing.T) {
	input, err := readCertRequestInput(certSubcommand(t, "renew"))
	if err != nil || input.Attributes != nil || input.CSR != "" {
		t.Errorf("got %+v, %v; want no attributes", input, err)
	}
}

func TestReadCertRequestInputRejects(t *testing.T) {
	dir := t.TempDir()
	csrPath := filepath.Join(dir, "req.csr")
	if err := os.WriteFile(csrPath, []byte("-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	csrBlock := "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"
	csrWithKey := filepath.Join(dir, "with-key.pem")
	csrAfterText := filepath.Join(dir, "after-text.pem")
	largeCSR := filepath.Join(dir, "large.csr")
	for path, contents := range map[string]string{
		csrWithKey:   csrBlock + "-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n",
		csrAfterText: "secret=hunter2\n" + csrBlock,
		largeCSR:     csrBlock + strings.Repeat(" ", certCSRMaxBytes),
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	notCSR := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(notCSR, []byte("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]string{
		"csr with common name":     {"csr", csrPath, "common-name", "a.example.com"},
		"csr with key file":        {"csr", csrPath, "output-private-key-file", "k.pem"},
		"csr with custom ext":      {"csr", csrPath, "custom-extension", "1.2.3=x"},
		"missing csr":              {"csr", filepath.Join(dir, "missing.csr")},
		"not a csr":                {"csr", notCSR},
		"ttl and not-after":        {"ttl", "30d", "not-after", "2030-01-01T00:00:00Z"},
		"bad not-before":           {"not-before", "tomorrow"},
		"unknown key usage":        {"key-usage", "signing"},
		"unknown eku":              {"extended-key-usage", "serverAuth"},
		"path length without ca":   {"path-length", "1"},
		"custom ext without value": {"custom-extension", "1.2.3"},
		"empty common name":        {"common-name", " "},
		"empty csr":                {"csr", "", "common-name", "a.example.com"},
		"unknown key algorithm":    {"key-algorithm", "RSA-2048"},
		"unknown sig algorithm":    {"signature-algorithm", "SHA256"},
		"csr with a private key":   {"csr", csrWithKey},
		"csr after other text":     {"csr", csrAfterText},
		"csr that is a directory":  {"csr", dir},
		"csr too large":            {"csr", largeCSR},
	}
	for name, flags := range cases {
		cmd := certSubcommand(t, "issue")
		setFlags(t, cmd, flags...)
		if _, err := readCertRequestInput(cmd); err == nil || err.Code != errCodeInvalidFlagValue {
			t.Errorf("%s: got %v, want invalid_flag_value", name, err)
		}
	}

	cmd := certSubcommand(t, "issue")
	setFlags(t, cmd, "csr", csrPath, "ttl", "30d")
	if input, err := readCertRequestInput(cmd); err != nil || input.CSR != csrBlock || input.Attributes.TTL != "30d" {
		t.Errorf("csr with ttl: got %+v, %v", input, err)
	}
}

func TestReadCertRequestInputReportsTheFirstInvalidFlag(t *testing.T) {
	for range 20 {
		cmd := certSubcommand(t, "issue")
		setFlags(t, cmd, "key-algorithm", "bogus", "signature-algorithm", "bogus", "common-name", " ")
		if _, err := readCertRequestInput(cmd); err == nil || !strings.Contains(err.Message, "--common-name") {
			t.Fatalf("got %v, want the --common-name error first", err)
		}
	}
}

func TestCertOutputFilesRejectBlankAndDirectoryPaths(t *testing.T) {
	cmd := certSubcommand(t, "issue")
	setFlags(t, cmd, "output-private-key-file", " ")
	if _, err := readCertOutputFiles(cmd); err == nil || err.Code != errCodeInvalidFlagValue {
		t.Errorf("blank --output-private-key-file: got %v, want invalid_flag_value", err)
	}
	if err := (certOutputFiles{Cert: t.TempDir(), Force: true}).checkOverwrite(); err == nil {
		t.Error("a directory was accepted as --output-certificate-file")
	}
}

func TestCertOutputFilesSeeThroughSymlinkedDirectories(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	files := certOutputFiles{Key: filepath.Join(real, "pair.pem"), Cert: filepath.Join(dir, "link", "pair.pem"), Force: true}
	if err := files.checkOverwrite(); err == nil {
		t.Error("two flags naming one file through a symlink were accepted")
	}
}

func TestCertOutputFilesKeepTheDeployedPairWhenAWriteFails(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "blocked", "cert.pem")
	if err := os.WriteFile(keyPath, []byte("OLD KEY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// A regular file where the certificate's directory should be makes its staging fail.
	if err := os.WriteFile(filepath.Join(dir, "blocked"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := (certOutputFiles{Key: keyPath, Cert: certPath, Force: true}).write(api.CertificateData{Certificate: "CERT", PrivateKey: "NEW KEY"})
	if err == nil || !strings.Contains(err.Error(), "--output-certificate-file") {
		t.Fatalf("got %v, want a --output-certificate-file write error", err)
	}
	if contents, _ := os.ReadFile(keyPath); string(contents) != "OLD KEY\n" {
		t.Errorf("key = %q after a failed write, want the old key", contents)
	}
}

func TestCurrentCertificateStatus(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	later, earlier := now.Add(time.Hour), now.Add(-time.Hour)
	cases := []struct {
		certificate api.RetrievedCertificate
		want        string
	}{
		{api.RetrievedCertificate{Status: "active", NotAfter: later}, "active"},
		{api.RetrievedCertificate{Status: "active", NotAfter: earlier}, "expired"},
		{api.RetrievedCertificate{Status: "active", NotAfter: later, RenewedByCertificateID: testCertificateID}, "renewed"},
		{api.RetrievedCertificate{Status: "active", NotAfter: earlier, RenewedByCertificateID: testCertificateID}, "expired"},
		{api.RetrievedCertificate{Status: "revoked", NotAfter: earlier}, "revoked"},
	}
	for _, c := range cases {
		if got := currentCertificateStatus(c.certificate, now); got != c.want {
			t.Errorf("currentCertificateStatus(%+v) = %q, want %q", c.certificate, got, c.want)
		}
	}
}

func TestCertUsageFlagsUseTheFlagSpelling(t *testing.T) {
	got := certUsageFlags([]string{"digitalSignature", "cRLSign", "serverAuth", "anyExtendedKeyUsage", "digital_signature"})
	want := []string{"digital_signature", "crl_sign", "server_auth", "any_purpose", "digital_signature"}
	if !slices.Equal(got, want) {
		t.Errorf("certUsageFlags = %v, want %v", got, want)
	}
	for _, value := range got {
		if !slices.Contains(certKeyUsages, value) && !slices.Contains(certExtendedKeyUsages, value) {
			t.Errorf("%q isn't a value --key-usage or --extended-key-usage takes", value)
		}
	}
}

func TestApplicationLookupErrorHidesApplicationsTheCallerCantAccess(t *testing.T) {
	for _, apiErr := range []*api.APIError{{StatusCode: 403, Name: "ForbiddenError"}, {StatusCode: 404, Name: "NotFound"}} {
		var cliErr *util.CLIError
		if err := applicationLookupError(apiErr, "payments-api"); !errors.As(err, &cliErr) || cliErr.Code != errCodeApplicationNotFound {
			t.Errorf("%d %s: got %v, want application_not_found", apiErr.StatusCode, apiErr.Name, err)
		}
	}
}

func TestIsTransientPollError(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{errors.New("connection reset"), true},
		{&api.APIError{StatusCode: 503}, true},
		{&api.APIError{StatusCode: 429}, true},
		{&api.APIError{StatusCode: 401, Name: "TokenError"}, false},
		{&api.APIError{StatusCode: 403, Name: "ForbiddenError"}, false},
		{&api.APIError{StatusCode: 404}, false},
	} {
		if got := isTransientPollError(c.err); got != c.want {
			t.Errorf("isTransientPollError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestCertOutputFilesRefuseOverwriteAndWritePrivately(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	// The umask can narrow the mode WriteFile asked for.
	if err := os.Chmod(certPath, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := certSubcommand(t, "issue")
	setFlags(t, cmd, "output-certificate-file", certPath)
	if _, err := readCertOutputFiles(cmd); err == nil || err.Code != errCodeInvalidFlagValue || !strings.Contains(err.Message, "--force") {
		t.Fatalf("existing file: got %v, want a refusal naming --force", err)
	}

	setFlags(t, cmd, "force", "true", "output-private-key-file", filepath.Join(dir, "nested", "key.pem"))
	files, err := readCertOutputFiles(cmd)
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := files.write(api.CertificateData{Certificate: "CERT", PrivateKey: "KEY"})
	if writeErr != nil || len(written) != 2 {
		t.Fatalf("write: %v, %v", written, writeErr)
	}
	// A replaced certificate keeps its deployed mode, so a service reading it still can; a key is private.
	for path, want := range map[string]struct {
		contents string
		mode     os.FileMode
	}{certPath: {"CERT\n", 0644}, files.Key: {"KEY\n", 0600}} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want.mode {
			t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want.mode)
		}
		if contents, _ := os.ReadFile(path); string(contents) != want.contents {
			t.Errorf("%s = %q, want %q", path, contents, want.contents)
		}
	}

	if err := (certOutputFiles{Cert: certPath, Key: "key.pem", Chain: "./key.pem", Force: true}).checkOverwrite(); err == nil {
		t.Error("two flags naming the same file were accepted")
	}

	if _, err := (certOutputFiles{Cert: certPath}).write(api.CertificateData{Certificate: "NEW"}); err == nil {
		t.Error("write without --force replaced a file created after the check")
	}
	if contents, _ := os.ReadFile(certPath); string(contents) != "CERT\n" {
		t.Errorf("%s = %q after a refused write", certPath, contents)
	}
}

func TestPkiIDAcceptsAnyCase(t *testing.T) {
	upper := strings.ToUpper(testCertificateID)
	if id, ok := pkiID(upper); !ok || id != strings.ToLower(testCertificateID) {
		t.Errorf("pkiID(%q) = %q, %v", upper, id, ok)
	}
	for _, value := range []string{"payments-api", strings.ReplaceAll(testCertificateID, "-", "")} {
		if _, ok := pkiID(value); ok {
			t.Errorf("pkiID(%q) accepted a non-ID", value)
		}
	}
}

func TestCollectPagesStopsOnTotalOrEmptyPage(t *testing.T) {
	calls := 0
	items, err := collectPages(func(offset int) ([]int, int, error) {
		calls++
		if offset >= 3 {
			return nil, 10, nil
		}
		return []int{offset, offset + 1, offset + 2}, 10, nil
	})
	if err != nil || len(items) != 3 || calls != 2 {
		t.Errorf("got %v, %v after %d calls", items, err, calls)
	}
}

func TestRevokeRerunKeepsTimeoutAndSuggestionsKeepOrg(t *testing.T) {
	cmd := certSubcommand(t, "revoke")
	setFlags(t, cmd, "application", "payments-api", "reason", "superseded", "timeout", "30s")
	if rerun := rerunWithYes(cmd, []string{testCertificateID}, nil); !strings.Contains(rerun, "--timeout 30s") {
		t.Errorf("rerun = %q, want --timeout 30s", rerun)
	}

	cmd.Flags().String("org", "", "")
	setFlags(t, cmd, "org", "staging")
	if flags := instanceFlags(cmd); !strings.Contains(flags, "--org staging") {
		t.Errorf("instanceFlags = %q, want --org staging", flags)
	}
}

func TestRenewTakesExtensionsWithACSR(t *testing.T) {
	csrPath := filepath.Join(t.TempDir(), "req.csr")
	if err := os.WriteFile(csrPath, []byte("-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := certSubcommand(t, "renew")
	setFlags(t, cmd, "csr", csrPath, "custom-extension", "1.2.3=x", "critical-extension", "1.2.3")
	if input, err := readCertRequestInput(cmd); err != nil || len(input.Attributes.CustomExtensions) != 1 {
		t.Errorf("renew --csr with a custom extension: got %+v, %v", input, err)
	}
}

func TestRenewKeepsTheCAPathLength(t *testing.T) {
	two := 2
	ca := api.RetrievedCertificate{BasicConstraints: &api.CertificateBasicConstraints{IsCA: true, PathLength: &two}}

	cmd := certSubcommand(t, "renew")
	setFlags(t, cmd, "is-ca", "true")
	input, err := readCertRequestInput(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if invalid := keepPathLength(cmd, input.Attributes, ca); invalid != nil || input.Attributes.BasicConstraints.PathLength == nil || *input.Attributes.BasicConstraints.PathLength != 2 {
		t.Errorf("--is-ca alone: got %+v, %v; want path length 2 kept", input.Attributes.BasicConstraints, invalid)
	}

	cmd = certSubcommand(t, "renew")
	setFlags(t, cmd, "path-length", "0")
	if input, err = readCertRequestInput(cmd); err != nil {
		t.Fatal(err)
	}
	if invalid := keepPathLength(cmd, input.Attributes, ca); invalid != nil || !input.Attributes.BasicConstraints.IsCA || *input.Attributes.BasicConstraints.PathLength != 0 {
		t.Errorf("--path-length alone on a CA: got %+v, %v", input.Attributes.BasicConstraints, invalid)
	}
	if invalid := keepPathLength(cmd, input.Attributes, api.RetrievedCertificate{}); invalid == nil {
		t.Error("--path-length alone on a leaf certificate was accepted")
	}
}

func TestCertOutputFilesCatchEverySpellingOfOneFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for name, files := range map[string]certOutputFiles{
		"through a symlink into a new directory": {Key: filepath.Join(real, "new", "pair.pem"), Cert: filepath.Join(dir, "link", "new", "pair.pem")},
		"in another letter case":                 {Key: filepath.Join(dir, "Pair.pem"), Cert: filepath.Join(dir, "pair.pem")},
	} {
		files.Force = true
		if err := files.checkOverwrite(); err == nil {
			t.Errorf("%s: two flags naming one file were accepted", name)
		}
	}
}

func TestCertOutputFilesTreatADanglingSymlinkAsExisting(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "cert.pem")
	if err := os.Symlink(filepath.Join(dir, "missing.pem"), link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := (certOutputFiles{Cert: link}).checkOverwrite(); err == nil || !strings.Contains(err.Message, "--force") {
		t.Errorf("got %v, want a refusal naming --force", err)
	}
}

func TestCertOutputFilesForceWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "cert1.pem"), filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(target, []byte("OLD\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := (certOutputFiles{Cert: link, Force: true}).write(api.CertificateData{Certificate: "NEW"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink was replaced: %v, %v", info, err)
	}
	if contents, _ := os.ReadFile(target); string(contents) != "NEW\n" {
		t.Errorf("target = %q, want the new certificate", contents)
	}
}

func TestCertOutputFilesRemoveWhatAFailedWriteCreated(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "blocked", "cert.pem")
	if err := os.WriteFile(filepath.Join(dir, "blocked"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (certOutputFiles{Key: keyPath, Cert: certPath}).write(api.CertificateData{Certificate: "CERT", PrivateKey: "KEY"}); err == nil {
		t.Fatal("the write succeeded")
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the key file was left behind: %v", err)
	}
}

func TestPickupFlagsRepeatTheFileDelivery(t *testing.T) {
	options := issuanceOptions{files: certOutputFiles{Cert: "cert.pem", Key: "key.pem", Force: true}, removeRoot: true}
	got := options.pickupFlags(certSubcommand(t, "issue"))
	for _, want := range []string{"--remove-roots-from-chain", "--output-private-key-file <output-private-key-file>", "--output-certificate-file <output-certificate-file>", "--force"} {
		if !strings.Contains(got, want) {
			t.Errorf("pickup flags %q lack %q", got, want)
		}
	}
}

func TestWaitDetailReportsTheMessageAndTheLastFailure(t *testing.T) {
	got := waitDetail("Order 42 awaits DNS validation.", errors.New("connection refused"))
	if got != "Infisical reports: Order 42 awaits DNS validation. The last check failed: connection refused." {
		t.Errorf("got %q", got)
	}
	if waitDetail(" ", nil) != "" {
		t.Error("an empty wait detail isn't empty")
	}
}

func TestRevocationApprovalOutcome(t *testing.T) {
	for _, c := range []struct {
		body         string
		wantApproved bool
		wantErr      string
	}{
		{`{"request":{"status":"pending"}}`, false, ""},
		{`{"request":{"status":"pending","approversCanNoLongerApprove":true}}`, false, "too few of the approvers"},
		{`{"request":{"status":"approved","approversCanNoLongerApprove":true}}`, true, ""},
		{`{"request":{"status":"rejected"}}`, false, "was rejected"},
		{`{"request":{"status":"pending","expiresAt":"2020-01-01T00:00:00Z"}}`, false, "was expired"},
	} {
		var response api.GetApprovalRequestResponse
		if err := json.Unmarshal([]byte(c.body), &response); err != nil {
			t.Fatal(err)
		}
		approved, err := revocationApprovalOutcome(response.Request, testCertificateID, testProjectID, time.Now())
		if approved != c.wantApproved {
			t.Errorf("%s: approved = %v, want %v", c.body, approved, c.wantApproved)
		}
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", c.body, err)
			}
			continue
		}
		var cliErr *util.CLIError
		if !errors.As(err, &cliErr) || cliErr.Code != errCodeCertificateRevocationRejected || !strings.Contains(cliErr.Message, c.wantErr) {
			t.Errorf("%s: error = %v, want certificate_revocation_rejected containing %q", c.body, err, c.wantErr)
		}
	}
}

func TestCertificateDetailsDomainComponentsAndMetadata(t *testing.T) {
	for _, c := range []struct {
		body           string
		wantComponents []string
		wantMetadata   []api.CertificateMetadataEntry
	}{
		{`{"certificate":{"id":"c1","subject":{"domainComponents":["example","com"]},"metadata":[{"key":"team","value":"payments"}]}}`,
			[]string{"example", "com"}, []api.CertificateMetadataEntry{{Key: "team", Value: "payments"}}},
		{`{"certificate":{"id":"c1"}}`, []string{}, []api.CertificateMetadataEntry{}},
	} {
		var response api.RetrieveCertificateResponse
		if err := json.Unmarshal([]byte(c.body), &response); err != nil {
			t.Fatal(err)
		}
		details := certificateDetailsFrom(response.Certificate, api.CertificateData{}, false, time.Now())
		if !slices.Equal(details.DomainComponents, c.wantComponents) || details.DomainComponents == nil {
			t.Errorf("%s: domainComponents = %#v, want %#v", c.body, details.DomainComponents, c.wantComponents)
		}
		if !slices.Equal(details.Metadata, c.wantMetadata) || details.Metadata == nil {
			t.Errorf("%s: metadata = %#v, want %#v", c.body, details.Metadata, c.wantMetadata)
		}
	}
}
