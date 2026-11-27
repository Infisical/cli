/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var (
	certKeyUsages         = certUsageFlagNames(certKeyUsageSpellings)
	certExtendedKeyUsages = certUsageFlagNames(certExtendedKeyUsageSpellings)
	// The post-quantum algorithms name both the key and the signature.
	certPostQuantumAlgorithms = []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
		"SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-128f",
		"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256s"}
	certKeyAlgorithms = slices.Concat([]string{"RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1",
		"EC_secp521r1"}, certPostQuantumAlgorithms)
	certSignatureAlgorithms = slices.Concat([]string{"RSA-SHA256", "RSA-SHA384", "RSA-SHA512", "ECDSA-SHA256",
		"ECDSA-SHA384", "ECDSA-SHA512"}, certPostQuantumAlgorithms)
	certStatuses = []string{string(api.CertificateStatusActive), string(api.CertificateStatusExpired),
		string(api.CertificateStatusRevoked), string(api.CertificateStatusRenewed)}
	certRequestStatuses = []string{api.CertificateRequestStatusPendingApproval, api.CertificateRequestStatusPending,
		api.CertificateRequestStatusPendingValidation, api.CertificateRequestStatusIssued,
		api.CertificateRequestStatusFailed, api.CertificateRequestStatusRejected}
)

// crlReasons are the backend's revocation reasons in the order --reason lists them, with the RFC 5280
// code it stores on a revoked certificate. They're shown lower-case and sent upper-case.
type crlReason struct {
	Code int
	Name string
}

var crlReasons = []crlReason{{1, "key_compromise"}, {4, "superseded"}, {5, "cessation_of_operation"}, {3, "affiliation_changed"},
	{2, "ca_compromise"}, {6, "certificate_hold"}, {9, "privilege_withdrawn"}, {10, "a_a_compromise"}, {0, "unspecified"}}

func certRevocationReasons() []string {
	names := make([]string, 0, len(crlReasons))
	for _, reason := range crlReasons {
		names = append(names, reason.Name)
	}
	return names
}

const (
	certPollInterval    = 5 * time.Second
	certMaxPollInterval = 30 * time.Second
	certDefaultTimeout  = 5 * time.Minute
	certListPageSize    = 100
)

func init() {
	certManagerCmd.Long = "Issue, fetch, renew and revoke certificates in your Certificate Manager applications, and run the certificate agent."
	certManagerCmd.AddCommand(buildCertManagerApplicationsCmd())
	certManagerCmd.AddCommand(buildCertManagerCertificatesCmd())
}

func buildCertManagerApplicationsCmd() *cobra.Command {
	applicationsCmd := &cobra.Command{
		Use:   "applications",
		Short: "Show the Certificate Manager applications you can access",
		Example: `infisical cert-manager applications get
infisical cert-manager applications get payments-api`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	getCmd := &cobra.Command{
		Use:   "get [name-or-id]",
		Short: "List your applications, or show one and its profiles with API enrollment",
		Long: `List the Certificate Manager applications you can access, or show one.

For one application, it lists the attached profiles that have API enrollment, the ones the CLI can
issue from. In the certificates commands, use the application's name or ID as --application, and a
profile's name as --certificate-profile.`,
		Example: `# The applications you can access
infisical cert-manager applications get

# One application and its profiles with API enrollment
infisical cert-manager applications get payments-api -o json`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runCertApplicationsGet,
		Annotations:           serviceTokenUnsupported,
	}
	addCertCommonFlags(getCmd, "The output to format the applications in")
	applicationsCmd.AddCommand(getCmd)

	return applicationsCmd
}

func buildCertManagerCertificatesCmd() *cobra.Command {
	certificatesCmd := &cobra.Command{
		Use:   "certificates",
		Short: "Issue, fetch, renew and revoke certificates in an application",
		Long: `Issue, fetch, renew and revoke certificates in a Certificate Manager application.

Every command acts inside the application you pass with --application, by name or ID. To find
your applications and their profiles with API enrollment, run: infisical cert-manager applications get`,
		Example: `infisical cert-manager certificates issue --application payments-api --certificate-profile web --common-name app.example.com --output-certificate-file cert.pem --output-private-key-file key.pem --output-chain-file chain.pem
infisical cert-manager certificates get --application payments-api
infisical cert-manager certificates renew <certificate-id> --application payments-api --output-certificate-file cert.pem --output-private-key-file key.pem --force
infisical cert-manager certificates revoke <certificate-id> --application payments-api --reason key_compromise`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	issueCmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate from one of the application's profiles",
		Long: `Issue a certificate from one of the application's profiles.

By default Infisical generates the private key. With --csr, Infisical issues the certificate for
the key in your CSR and returns no key. Flags you leave out take the profile's defaults.

When the application requires approval, or the CA issues later, the command waits up to --timeout,
then writes the files. If the timeout passes first, it exits with certificate_request_pending and
prints the command that picks the certificate up later:
'infisical cert-manager certificates requests get <request-id> --application <name-or-id> --wait'.
With --no-wait it doesn't wait: a certificate issued at once is written as usual, and a pending one
prints its request ID and exits 0.`,
		Example: `# Issue with a key from Infisical and write the files
infisical cert-manager certificates issue --application payments-api --certificate-profile web --common-name app.example.com --subject-alternative-name app.example.com --output-certificate-file cert.pem --output-private-key-file key.pem --output-chain-file chain.pem

# Issue for your own key
infisical cert-manager certificates issue --application payments-api --certificate-profile web --csr request.csr --output-certificate-file cert.pem

# Print the result as JSON without waiting for an approval
infisical cert-manager certificates issue --application payments-api --common-name app.example.com --no-wait -o json`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run:                   runCertIssue,
		Annotations:           serviceTokenUnsupported,
	}
	addCertApplicationFlag(issueCmd)
	issueCmd.Flags().String("certificate-profile", "", "Name of the certificate profile to issue from (default: the application's only profile with API enrollment)")
	addCertAttributeFlags(issueCmd)
	addCertWaitFlags(issueCmd, true)
	addCertFileFlags(issueCmd)
	issueCmd.Flags().StringArray("metadata", nil, "Metadata to store on the certificate, as key=value (repeatable)")
	addCertCommonFlags(issueCmd, "The output to format the certificate in")
	certificatesCmd.AddCommand(issueCmd)

	getCmd := &cobra.Command{
		Use:   "get [certificate-id]",
		Short: "List the application's certificates, or show and download one",
		Long: `List the application's certificates, or show one.

With a certificate ID and file flags, it writes the certificate, its chain and its private key.
The private key is printed only with --include-private-key.`,
		Example: `infisical cert-manager certificates get --application payments-api
infisical cert-manager certificates get --application payments-api --certificate-profile web --status active --expires-within 30d -o json
infisical cert-manager certificates get <certificate-id> --application payments-api
infisical cert-manager certificates get <certificate-id> --application payments-api --output-certificate-file cert.pem --output-private-key-file key.pem --output-chain-file chain.pem`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runCertGet,
		Annotations:           serviceTokenUnsupported,
	}
	addCertApplicationFlag(getCmd)
	getCmd.Flags().String("certificate-profile", "", "List only certificates issued from this certificate profile")
	getCmd.Flags().String("status", "", "List only certificates with this status: "+strings.Join(certStatuses, ", "))
	getCmd.Flags().String("expires-within", "", "List only certificates that haven't expired and expire within this duration, such as 30d or 12h")
	addCertFileFlags(getCmd)
	addCertCommonFlags(getCmd, "The output to format the certificates in")
	certificatesCmd.AddCommand(getCmd)

	renewCmd := &cobra.Command{
		Use:   "renew <certificate-id>",
		Short: "Renew a certificate, with a new key from Infisical or from your CSR",
		Long: `Renew a certificate.

Without --csr, Infisical generates a new private key. With --csr, the renewed certificate is for
the key in your CSR. The attribute flags change only the fields you pass; everything else comes from
the request the certificate was issued from, or from the certificate itself when Infisical has no such
request. With --csr, the subject and names come from the CSR. Approvals are waited for as with issue.`,
		Example: `infisical cert-manager certificates renew <certificate-id> --application payments-api --output-certificate-file cert.pem --output-private-key-file key.pem --output-chain-file chain.pem --force
infisical cert-manager certificates renew <certificate-id> --application payments-api --ttl 30d --subject-alternative-name new.example.com -o json
infisical cert-manager certificates renew <certificate-id> --application payments-api --csr request.csr --output-certificate-file cert.pem --force`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runCertRenew,
		Annotations:           serviceTokenUnsupported,
	}
	addCertApplicationFlag(renewCmd)
	addCertAttributeFlags(renewCmd)
	addCertWaitFlags(renewCmd, true)
	addCertFileFlags(renewCmd)
	addCertCommonFlags(renewCmd, "The output to format the renewed certificate in")
	certificatesCmd.AddCommand(renewCmd)

	revokeCmd := &cobra.Command{
		Use:   "revoke <certificate-id>",
		Short: "Revoke a certificate",
		Long: `Revoke a certificate, asking first. --yes skips the question.

When the application requires approval to revoke, the certificate isn't revoked until the request is
approved: the command waits up to --timeout for the revocation. With --no-wait it returns the approval
request ID at once; follow it under Approval Requests in Certificate Manager.`,
		Example: `infisical cert-manager certificates revoke <certificate-id> --application payments-api --reason key_compromise

# Without asking, for scripts and agents
infisical cert-manager certificates revoke <certificate-id> --application payments-api --reason superseded --yes`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runCertRevoke,
		Annotations:           serviceTokenUnsupported,
	}
	addCertApplicationFlag(revokeCmd)
	revokeCmd.Flags().String("reason", "", "Why the certificate is revoked, required: "+strings.Join(certRevocationReasons(), ", "))
	addConfirmFlagsFor(revokeCmd, "Revoke")
	addCertWaitFlags(revokeCmd, true)
	addCertCommonFlags(revokeCmd, "The output to format the revocation in")
	certificatesCmd.AddCommand(revokeCmd)

	requestsCmd := &cobra.Command{
		Use:   "requests",
		Short: "List and pick up the application's certificate requests",
		Example: `infisical cert-manager certificates requests get --application payments-api
infisical cert-manager certificates requests get <request-id> --application payments-api --output-certificate-file cert.pem --wait`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	requestsGetCmd := &cobra.Command{
		Use:   "get [request-id]",
		Short: "List the application's certificate requests, or show one and pick up its certificate",
		Long: `List the application's certificate requests, newest first, or show one.

For a request that's issued, it writes or prints the certificate, like certificates get. For one
that's still pending, it writes nothing and exits 1; --wait waits up to --timeout for it instead.`,
		Example: `infisical cert-manager certificates requests get --application payments-api --status pending_approval
infisical cert-manager certificates requests get <request-id> --application payments-api
infisical cert-manager certificates requests get <request-id> --application payments-api --output-certificate-file cert.pem --output-private-key-file key.pem --output-chain-file chain.pem --wait --timeout 10m`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runCertRequestsGet,
		Annotations:           serviceTokenUnsupported,
	}
	addCertApplicationFlag(requestsGetCmd)
	requestsGetCmd.Flags().String("status", "", "List only requests with this status ("+api.CertificateRequestStatusPending+" also matches the other pending statuses): "+strings.Join(certRequestStatuses, ", "))
	requestsGetCmd.Flags().Bool("wait", false, "Wait for a pending request to be issued or rejected, up to --timeout")
	requestsGetCmd.Flags().Bool("remove-roots-from-chain", false, "Leave the root CA certificates out of the chain")
	addCertWaitFlags(requestsGetCmd, false)
	addCertFileFlags(requestsGetCmd)
	addCertCommonFlags(requestsGetCmd, "The output to format the requests in")
	requestsCmd.AddCommand(requestsGetCmd)
	certificatesCmd.AddCommand(requestsCmd)

	return certificatesCmd
}

func addCertCommonFlags(cmd *cobra.Command, outputDescription string) {
	cmd.Flags().String("token", "", "Authenticate with a machine identity access token instead of your login")
	addProjectsOutputFlag(cmd, outputDescription)
}

func addCertApplicationFlag(cmd *cobra.Command) {
	cmd.Flags().String("application", "", "Name or ID of the application, required. To find it, run: infisical cert-manager applications get")
}

func addCertWaitFlags(cmd *cobra.Command, noWait bool) {
	cmd.Flags().Duration("timeout", certDefaultTimeout, "How long to wait for an approval or a pending certificate")
	if noWait {
		cmd.Flags().Bool("no-wait", false, "Don't wait for an approval or a pending certificate: if the operation is pending, print its request ID and exit")
	}
}

func addCertFileFlags(cmd *cobra.Command) {
	if cmd.Name() == "renew" {
		cmd.Flags().String("output-certificate-file", "", "Write the certificate to this file. Without --csr, the renewed certificate has a new key, so also pass --output-private-key-file or --include-private-key")
	} else {
		cmd.Flags().String("output-certificate-file", "", "Write the certificate to this file")
	}
	cmd.Flags().String("output-private-key-file", "", "Write the private key to this file (mode 0600)")
	cmd.Flags().String("output-chain-file", "", "Write the certificate chain to this file")
	cmd.Flags().Bool("force", false, "Overwrite files that already exist. A replaced certificate or chain keeps its mode, and outside Windows its owner and group, so run as a user allowed to set them, such as root")
	cmd.Flags().Bool("include-private-key", false, "Print the private key, and include it as privateKey in -o json or yaml")
}

func addCertAttributeFlags(cmd *cobra.Command) {
	cmd.Flags().String("common-name", "", "Subject common name (CN)")
	cmd.Flags().String("organization", "", "Subject organization (O)")
	cmd.Flags().String("organizational-unit", "", "Subject organizational unit (OU)")
	cmd.Flags().String("country", "", "Subject country (C), as a two-letter code")
	cmd.Flags().String("state", "", "Subject state or province (ST)")
	cmd.Flags().String("locality", "", "Subject locality (L)")
	cmd.Flags().StringArray("domain-component", nil, "Subject domain component (DC) (repeatable)")
	cmd.Flags().StringArray("subject-alternative-name", nil, "Subject alternative name: an IP address, an email, a URI, or a DNS name (repeatable)")
	// Renewal takes no validity range: the backend's renew attributes have only a TTL.
	if cmd.Name() == "renew" {
		cmd.Flags().String("ttl", "", "Validity, such as 90d or 12h")
	} else {
		cmd.Flags().String("ttl", "", "Validity, such as 90d or 12h. Can't be used with --not-before or --not-after")
		cmd.Flags().String("not-before", "", "Start of validity, in RFC 3339 (2026-01-02T15:04:05Z)")
		cmd.Flags().String("not-after", "", "End of validity, in RFC 3339 (2027-01-02T15:04:05Z)")
	}
	cmd.Flags().String("key-algorithm", "", "Key algorithm: "+strings.Join(certKeyAlgorithms, ", "))
	cmd.Flags().String("signature-algorithm", "", "Signature algorithm: "+strings.Join(certSignatureAlgorithms, ", "))
	cmd.Flags().StringArray("key-usage", nil, "Key usage (repeatable): "+strings.Join(certKeyUsages, ", "))
	cmd.Flags().StringArray("extended-key-usage", nil, "Extended key usage (repeatable): "+strings.Join(certExtendedKeyUsages, ", "))
	cmd.Flags().String("csr", "", "Path to a PEM certificate signing request; Infisical issues the certificate for its key")
	cmd.Flags().Bool("is-ca", false, "Issue a CA certificate (basic constraints cA), if the profile's policy allows it")
	if cmd.Name() == "renew" {
		cmd.Flags().Int("path-length", 0, "Path length constraint of a CA certificate (needs --is-ca, unless the certificate renewed is a CA)")
	} else {
		cmd.Flags().Int("path-length", 0, "Path length constraint of a CA certificate (needs --is-ca)")
	}
	cmd.Flags().StringArray("custom-extension", nil, "Custom extension, as <oid>=<value> (repeatable)")
	cmd.Flags().StringArray("critical-extension", nil, "Mark the custom extension with this OID critical (repeatable)")
	cmd.Flags().Bool("remove-roots-from-chain", false, "Leave the root CA certificates out of the chain")
}

func certHTTPClient(cmd *cobra.Command) *resty.Client {
	return secretsManagerHTTPClient(cmd, "manage certificates")
}

func certNotice(cmd *cobra.Command, message string) {
	if !isStructuredOutputRequested(cmd) {
		printProjectsTip(cmd, message)
	}
}

func captureCertEvent(command string, properties posthog.Properties) {
	Telemetry.CaptureEvent("cli-command:cert-manager "+command, properties.Set("version", util.CLI_VERSION))
}

// certApplicationFlag reads --application. There's no environment or .infisical.yaml fallback:
// revoke is destructive, and one rule for every certificate command is easier to predict.
func certApplicationFlag(cmd *cobra.Command) (string, *util.CLIError) {
	application, _ := cmd.Flags().GetString("application")
	if application = strings.TrimSpace(application); application == "" {
		return "", errApplicationRequired()
	}
	return application, nil
}

// pkiID reads a UUID in any letter case as the canonical lower-case ID the API stores.
func pkiID(value string) (string, bool) {
	parsed, err := uuid.Parse(value)
	if err != nil || len(value) != len(parsed.String()) {
		return "", false
	}
	return parsed.String(), true
}

// certApplicationName matches what the backend accepts as an application name. Anything else is
// refused before it's sent, so a value pasted by mistake, such as a token, never reaches a request URL.
var certApplicationName = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

func resolveCertApplication(cmd *cobra.Command, client *resty.Client, nameOrID string) api.PkiApplication {
	var application api.PkiApplication
	var err error
	if id, ok := pkiID(nameOrID); ok {
		application, err = api.CallGetPkiApplicationByID(client, id)
	} else if certApplicationName.MatchString(nameOrID) {
		application, err = api.CallGetPkiApplicationByName(client, nameOrID)
	} else {
		exitCertError(cmd, errApplicationNotFound(nameOrID, nil))
	}
	if err != nil {
		exitCertError(cmd, applicationLookupError(err, nameOrID), "Unable to get the application")
	}
	return application
}

// applicationLookupError reports an application the caller isn't a member of the same way as one that
// doesn't exist: the backend answers 403 ForbiddenError for it, and the CLI doesn't confirm it exists.
func applicationLookupError(err error, nameOrID string) error {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 403 && apiErr.Name == "ForbiddenError" {
		return errApplicationNotFound(nameOrID, err)
	}
	return classifyAPIError(err, errorScope{}, func(cause error) *util.CLIError {
		return errApplicationNotFound(nameOrID, cause)
	})
}

func listCertApplicationProfiles(cmd *cobra.Command, client *resty.Client, application api.PkiApplication) []api.PkiApplicationProfile {
	profiles, err := api.CallListPkiApplicationProfiles(client, application.ID)
	if err != nil {
		exitCertError(cmd, classifyAPIError(err, errorScope{}, func(cause error) *util.CLIError {
			return errApplicationNotFound(application.Name, cause)
		}), "Unable to list the application's profiles")
	}
	return profiles
}

func hasAPIEnrollment(profile api.PkiApplicationProfile) bool {
	return profile.APIConfigID != nil && *profile.APIConfigID != ""
}

func findCertProfile(profiles []api.PkiApplicationProfile, name string) int {
	return slices.IndexFunc(profiles, func(p api.PkiApplicationProfile) bool { return p.ProfileSlug == name })
}

// selectIssuanceProfile picks the profile to issue from: the named one when it's attached with API
// enrollment, or the application's only API-enabled profile when none is named.
func selectIssuanceProfile(profiles []api.PkiApplicationProfile, name, application string) (api.PkiApplicationProfile, *util.CLIError) {
	if name != "" {
		if index := findCertProfile(profiles, name); index >= 0 {
			if !hasAPIEnrollment(profiles[index]) {
				return api.PkiApplicationProfile{}, errProfileNotAPIEnabled(name, application)
			}
			return profiles[index], nil
		}
	}
	var enabled []api.PkiApplicationProfile
	var names []string
	for _, profile := range profiles {
		if hasAPIEnrollment(profile) {
			enabled = append(enabled, profile)
			names = append(names, profile.ProfileSlug)
		}
	}
	if name != "" {
		return api.PkiApplicationProfile{}, errProfileNotFound(name, application, names)
	}
	if len(enabled) != 1 {
		return api.PkiApplicationProfile{}, errProfileRequired(application, names)
	}
	return enabled[0], nil
}

// subjectAlternativeName detects a SAN's type from its value. A URI is checked before an email
// because a URI can hold an @.
func subjectAlternativeName(value string) api.AltName {
	if net.ParseIP(value) != nil {
		return api.AltName{Type: api.AltNameTypeIP, Value: value}
	}
	if parsed, err := url.Parse(value); err == nil && parsed.IsAbs() {
		return api.AltName{Type: api.AltNameTypeURI, Value: value}
	}
	switch {
	case strings.Contains(value, "@"):
		return api.AltName{Type: api.AltNameTypeEmail, Value: value}
	default:
		return api.AltName{Type: api.AltNameTypeDNS, Value: value}
	}
}

func validateChoices(flag string, values, choices []string) *util.CLIError {
	for _, value := range values {
		if !slices.Contains(choices, value) {
			return errInvalidChoice(flag, value, choices)
		}
	}
	return nil
}

func parseRevocationReason(reason string) (string, *util.CLIError) {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	names := certRevocationReasons()
	if normalized == "" {
		return "", errFlagRequired("reason", "why the certificate is revoked, one of "+strings.Join(names, ", "))
	}
	if !slices.Contains(names, normalized) {
		return "", errInvalidChoice("reason", reason, names)
	}
	return strings.ToUpper(normalized), nil
}

// csrConflicts are the flags a CSR already carries, or that the backend ignores when it signs one.
// Renewal applies custom extensions over a CSR, but issuance refuses them.
var (
	csrConflicts = []string{"common-name", "organization", "organizational-unit", "country", "state", "locality",
		"domain-component", "subject-alternative-name", "key-algorithm", "signature-algorithm", "key-usage",
		"extended-key-usage", "output-private-key-file", "include-private-key"}
	csrIssueConflicts = []string{"custom-extension", "critical-extension"}
)

// certCSRMaxBytes is the backend's limit on a CSR.
const certCSRMaxBytes = 128 * 1024

type certRequestInput struct {
	CSR        string
	Attributes *api.CertificateAttributes
	RemoveRoot bool
}

// readCSRFile reads --csr and returns only its certificate signing request, re-encoded, so nothing
// else in the file (such as the private key the CSR was made with) is ever sent.
func readCSRFile(path string) (string, *util.CLIError) {
	unreadable := func(err error) *util.CLIError {
		cause := err
		if unwrapped := errors.Unwrap(err); unwrapped != nil {
			cause = unwrapped
		}
		return errInvalidFlag("csr", fmt.Sprintf("%s can't be read (%s)", quoted(path, "file"), util.SanitizeDisplay(cause.Error())))
	}
	// A FIFO or device could block the read before anything is checked.
	info, err := os.Stat(path)
	if err != nil {
		return "", unreadable(err)
	}
	if !info.Mode().IsRegular() {
		return "", errInvalidFlag("csr", fmt.Sprintf("%s isn't a regular file", quoted(path, "file")))
	}
	file, err := os.Open(path)
	if err != nil {
		return "", unreadable(err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, certCSRMaxBytes+1))
	if err != nil {
		return "", unreadable(err)
	}
	if len(contents) > certCSRMaxBytes {
		return "", errInvalidFlag("csr", fmt.Sprintf("%s is larger than a certificate signing request can be (128 KiB)", quoted(path, "file")))
	}
	trimmed := bytes.TrimSpace(contents)
	block, rest := pem.Decode(trimmed)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return "", errInvalidFlag("csr", fmt.Sprintf("%s isn't a PEM certificate signing request", quoted(path, "file")))
	}
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) || len(bytes.TrimSpace(rest)) > 0 {
		return "", errInvalidFlag("csr", fmt.Sprintf("%s holds more than a certificate signing request: pass a file with only the CSR, so nothing else, such as a private key, is sent", quoted(path, "file")))
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})), nil
}

// readCertRequestInput reads and checks the attribute flags and --csr, before anything is sent.
// Flags are checked in a fixed order, so the same invalid input always reports the same flag.
func readCertRequestInput(cmd *cobra.Command) (certRequestInput, *util.CLIError) {
	flags := cmd.Flags()
	var input certRequestInput
	input.RemoveRoot, _ = flags.GetBool("remove-roots-from-chain")

	if flags.Changed("csr") {
		csrPath, _ := flags.GetString("csr")
		if csrPath = strings.TrimSpace(csrPath); csrPath == "" {
			return input, errInvalidFlag("csr", "can't be empty")
		}
		conflicts := csrConflicts
		if cmd.Name() != "renew" {
			conflicts = slices.Concat(csrConflicts, csrIssueConflicts)
		}
		for _, other := range conflicts {
			if flags.Changed(other) {
				return input, errFlagsConflict(other, "csr", "with a CSR, the subject, names and key come from the CSR and the rest from the profile")
			}
		}
		csr, invalid := readCSRFile(csrPath)
		if invalid != nil {
			return input, invalid
		}
		input.CSR = csr
	}

	attributes := &api.CertificateAttributes{}
	supplied := false
	stringFlags := []struct {
		flag    string
		field   *string
		choices []string
	}{
		{"common-name", &attributes.CommonName, nil}, {"organization", &attributes.Organization, nil},
		{"organizational-unit", &attributes.OrganizationalUnit, nil}, {"country", &attributes.Country, nil},
		{"state", &attributes.State, nil}, {"locality", &attributes.Locality, nil}, {"ttl", &attributes.TTL, nil},
		{"not-before", &attributes.NotBefore, nil}, {"not-after", &attributes.NotAfter, nil},
		{"key-algorithm", &attributes.KeyAlgorithm, certKeyAlgorithms},
		{"signature-algorithm", &attributes.SignatureAlgorithm, certSignatureAlgorithms},
	}
	for _, f := range stringFlags {
		if !flags.Changed(f.flag) {
			continue
		}
		value, _ := flags.GetString(f.flag)
		if value = strings.TrimSpace(value); value == "" {
			return input, errInvalidFlag(f.flag, "can't be empty")
		}
		if f.choices != nil {
			if invalid := validateChoices(f.flag, []string{value}, f.choices); invalid != nil {
				return input, invalid
			}
		}
		if f.flag == "not-before" || f.flag == "not-after" {
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				return input, errInvalidFlag(f.flag, fmt.Sprintf("%s isn't an RFC 3339 time such as 2027-01-02T15:04:05Z", quoted(value, f.flag)))
			}
		}
		*f.field = value
		supplied = true
	}
	if attributes.TTL != "" && (attributes.NotBefore != "" || attributes.NotAfter != "") {
		other := "not-before"
		if attributes.NotAfter != "" {
			other = "not-after"
		}
		return input, errFlagsConflict("ttl", other, "pass either a TTL or a validity range")
	}

	arrayFlag := func(flag string) []string {
		values, _ := flags.GetStringArray(flag)
		if len(values) == 0 {
			return nil
		}
		supplied = true
		return values
	}
	attributes.DomainComponents = arrayFlag("domain-component")
	attributes.KeyUsages = arrayFlag("key-usage")
	if invalid := validateChoices("key-usage", attributes.KeyUsages, certKeyUsages); invalid != nil {
		return input, invalid
	}
	attributes.ExtendedKeyUsages = arrayFlag("extended-key-usage")
	if invalid := validateChoices("extended-key-usage", attributes.ExtendedKeyUsages, certExtendedKeyUsages); invalid != nil {
		return input, invalid
	}
	for _, san := range arrayFlag("subject-alternative-name") {
		if san = strings.TrimSpace(san); san == "" {
			return input, errInvalidFlag("subject-alternative-name", "can't be empty")
		}
		attributes.AltNames = append(attributes.AltNames, subjectAlternativeName(san))
	}

	// renew can take --path-length alone for a CA certificate; runCertRenew checks that it is one.
	isCA, _ := flags.GetBool("is-ca")
	if flags.Changed("path-length") {
		if !isCA && (cmd.Name() != "renew" || flags.Changed("is-ca")) {
			return input, errInvalidFlag("path-length", "needs --is-ca: a path length only applies to a CA certificate")
		}
		pathLength, _ := flags.GetInt("path-length")
		if pathLength < 0 || pathLength > 255 {
			return input, errInvalidFlag("path-length", "must be between 0 and 255")
		}
		attributes.BasicConstraints = &api.CertificateBasicConstraints{IsCA: isCA, PathLength: &pathLength}
		supplied = true
	}
	if flags.Changed("is-ca") {
		supplied = true
		if attributes.BasicConstraints == nil {
			attributes.BasicConstraints = &api.CertificateBasicConstraints{IsCA: isCA}
		}
	}

	extensions, invalid := readCustomExtensions(cmd)
	if invalid != nil {
		return input, invalid
	}
	attributes.CustomExtensions = extensions

	if supplied || len(extensions) > 0 {
		input.Attributes = attributes
	}
	return input, nil
}

func readCustomExtensions(cmd *cobra.Command) ([]api.CertificateCustomExtension, *util.CLIError) {
	values, _ := cmd.Flags().GetStringArray("custom-extension")
	criticalFlags, _ := cmd.Flags().GetStringArray("critical-extension")
	var critical []string
	for _, oid := range criticalFlags {
		if oid = strings.TrimSpace(oid); oid == "" {
			return nil, errInvalidFlag("critical-extension", "can't be empty")
		}
		if !slices.Contains(critical, oid) {
			critical = append(critical, oid)
		}
	}
	var extensions []api.CertificateCustomExtension
	for _, value := range values {
		oid, extensionValue, ok := strings.Cut(value, "=")
		oid = strings.TrimSpace(oid)
		if !ok || oid == "" || strings.TrimSpace(extensionValue) == "" {
			return nil, errInvalidFlag("custom-extension", "must be <oid>=<value>, such as 1.3.6.1.4.1.311.25.2=<value>")
		}
		if slices.ContainsFunc(extensions, func(e api.CertificateCustomExtension) bool { return e.OID == oid }) {
			return nil, errInvalidFlag("custom-extension", fmt.Sprintf("names OID %s more than once", quoted(oid, "oid")))
		}
		extensions = append(extensions, api.CertificateCustomExtension{OID: oid, Value: extensionValue, Critical: slices.Contains(critical, oid)})
	}
	for _, oid := range critical {
		if !slices.ContainsFunc(extensions, func(e api.CertificateCustomExtension) bool { return e.OID == oid }) {
			extensions = append(extensions, api.CertificateCustomExtension{OID: oid, Critical: true})
		}
	}
	return extensions, nil
}

func readCertMetadata(cmd *cobra.Command) ([]api.CertificateMetadataEntry, *util.CLIError) {
	values, _ := cmd.Flags().GetStringArray("metadata")
	var entries []api.CertificateMetadataEntry
	for _, value := range values {
		key, entryValue, ok := strings.Cut(value, "=")
		if key = strings.TrimSpace(key); !ok || key == "" {
			return nil, errInvalidFlag("metadata", "must be key=value")
		}
		entries = append(entries, api.CertificateMetadataEntry{Key: key, Value: entryValue})
	}
	return entries, nil
}

func readWaitFlags(cmd *cobra.Command) (time.Duration, bool, *util.CLIError) {
	timeout, _ := cmd.Flags().GetDuration("timeout")
	if timeout <= 0 {
		return 0, false, errInvalidFlag("timeout", "must be a positive duration, such as 5m")
	}
	noWait, _ := cmd.Flags().GetBool("no-wait")
	return timeout, noWait, nil
}

type certOutputFiles struct {
	Cert, Key, Chain  string
	Force, IncludeKey bool
}

func (f certOutputFiles) any() bool { return f.Cert != "" || f.Key != "" || f.Chain != "" }

func (f certOutputFiles) wantsKey() bool { return f.Key != "" || f.IncludeKey }

// flags repeats the file flags in a suggested command, so it delivers the certificate the same way.
func (f certOutputFiles) flags() string {
	var flags string
	for _, file := range f.destinations() {
		flags += " --" + file.flag + " " + util.SuggestedValue(file.path, file.flag)
	}
	if f.Force {
		flags += " --force"
	}
	if f.IncludeKey {
		flags += " --include-private-key"
	}
	return flags
}

// certFileFlags are the flags that only apply to downloading one certificate.
var certFileFlags = []string{"output-certificate-file", "output-private-key-file", "output-chain-file", "force", "include-private-key"}

// rejectFlagsWithoutID refuses flags that need an ID when the command lists instead.
func rejectFlagsWithoutID(cmd *cobra.Command, flags []string, problem string) {
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			exitCertError(cmd, errInvalidFlag(flag, problem))
		}
	}
}

// readCertOutputFiles refuses a path that exists unless --force is given, before anything is sent,
// so an issued certificate isn't left unwritten because a file was already there.
func readCertOutputFiles(cmd *cobra.Command) (certOutputFiles, *util.CLIError) {
	var files certOutputFiles
	for _, f := range []struct {
		flag string
		path *string
	}{{"output-certificate-file", &files.Cert}, {"output-private-key-file", &files.Key}, {"output-chain-file", &files.Chain}} {
		*f.path, _ = cmd.Flags().GetString(f.flag)
		if cmd.Flags().Changed(f.flag) && strings.TrimSpace(*f.path) == "" {
			return files, errInvalidFlag(f.flag, "can't be empty")
		}
	}
	files.Force, _ = cmd.Flags().GetBool("force")
	files.IncludeKey, _ = cmd.Flags().GetBool("include-private-key")
	return files, files.checkOverwrite()
}

type certOutputFile struct{ flag, path string }

// destinations are the requested files in the order they're written: the key first, so a failed key
// write leaves no certificate without its key.
func (f certOutputFiles) destinations() []certOutputFile {
	var files []certOutputFile
	for _, file := range []certOutputFile{{"output-private-key-file", f.Key}, {"output-certificate-file", f.Cert}, {"output-chain-file", f.Chain}} {
		if file.path != "" {
			files = append(files, file)
		}
	}
	return files
}

// resolvedPath follows symlinks in the path's nearest existing ancestor, so two flags naming one file
// through a symlinked directory compare equal, even when directories below it are still to be created.
func resolvedPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = filepath.Clean(path)
	}
	missing := ""
	for existing := absolute; ; {
		if resolved, err := filepath.EvalSymlinks(existing); err == nil {
			return filepath.Join(resolved, missing)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return absolute
		}
		missing = filepath.Join(filepath.Base(existing), missing)
		existing = parent
	}
}

// writeTarget is the file a write replaces: the target of a symlink, so --force updates a linked file
// (such as certbot's live/ links) instead of replacing the link.
func writeTarget(path string) string {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			return resolved
		}
	}
	return path
}

// checkOverwrite compares paths without letter case: on a case-insensitive volume, Pair.pem and
// pair.pem are one file, and the certificate would replace the key.
func (f certOutputFiles) checkOverwrite() *util.CLIError {
	seen := map[string]string{}
	for _, file := range f.destinations() {
		resolved := strings.ToLower(resolvedPath(file.path))
		if other, ok := seen[resolved]; ok {
			return errFlagsConflict(file.flag, other, "they name the same file")
		}
		seen[resolved] = file.flag
		// Lstat, so a symlink whose target is missing still counts as an existing name.
		if _, err := os.Lstat(file.path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return errInvalidFlag(file.flag, fmt.Sprintf("%s can't be checked (%s)", quoted(file.path, "file"), util.SanitizeDisplay(pathErrorReason(err))))
		}
		if info, err := os.Stat(file.path); err == nil && info.IsDir() {
			return errInvalidFlag(file.flag, fmt.Sprintf("%s is a directory: pass a file path", quoted(file.path, "file")))
		}
		if !f.Force {
			return errOutputFileExists(file.flag, file.path)
		}
	}
	return nil
}

func writeNewCertFile(path, contents string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	// O_EXCL so a file created since readCertOutputFiles checked the path is never overwritten.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(contents)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// pathErrorReason is the OS error without the path-bearing fs.PathError wrapper.
func pathErrorReason(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return err.Error()
}

func certFileError(file certOutputFile, err error) error {
	return fmt.Errorf("unable to write --%s %s: %s", file.flag, quoted(file.path, "file"), util.SanitizeDisplay(pathErrorReason(err)))
}

type previousCertFile struct {
	contents []byte
	info     os.FileInfo
}

// write leaves the files as they were when it fails: without --force it removes the files it created,
// and with --force every file is staged before any existing one is replaced, and the replaced ones are
// put back. The caller checks first that a requested key is there.
func (f certOutputFiles) write(bundle api.CertificateData) ([]string, error) {
	contents := map[string]string{"output-private-key-file": bundle.PrivateKey, "output-certificate-file": bundle.Certificate, "output-chain-file": bundle.CertificateChain}
	var written []string
	if !f.Force {
		var created []string
		for _, file := range f.destinations() {
			if err := writeNewCertFile(file.path, ensureTrailingNewline(contents[file.flag])); err != nil {
				for _, path := range created {
					_ = os.Remove(path)
				}
				return nil, certFileError(file, err)
			}
			created = append(created, file.path)
			written = append(written, file.path)
		}
		return written, nil
	}

	staged := map[string]string{}
	defer func() {
		for _, path := range staged {
			_ = os.Remove(path)
		}
	}()
	targets := map[string]string{}
	previous := map[string]*previousCertFile{}
	for _, file := range f.destinations() {
		target := writeTarget(file.path)
		targets[file.flag] = target
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return nil, certFileError(file, err)
		}
		mode := os.FileMode(0600)
		var prepare func(*os.File) error
		var ownerErr error
		if info, err := os.Stat(target); err == nil {
			old, err := os.ReadFile(target)
			if err != nil {
				return nil, certFileError(file, err)
			}
			previous[file.flag] = &previousCertFile{old, info}
			// A service under another account may read the deployed certificate or chain, as its owner or
			// through its group. A new key stays private to whoever runs the CLI.
			if file.flag != "output-private-key-file" {
				mode = info.Mode().Perm()
				prepare = func(f *os.File) error {
					ownerErr = keepOwner(f, info)
					return ownerErr
				}
			}
		}
		path, err := util.StageFile(target, []byte(ensureTrailingNewline(contents[file.flag])), mode, prepare)
		if ownerErr != nil {
			return nil, fmt.Errorf("unable to keep the owner and group of --%s %s: %s", file.flag, quoted(file.path, "file"), util.SanitizeDisplay(pathErrorReason(ownerErr)))
		}
		if err != nil {
			return nil, certFileError(file, err)
		}
		staged[file.flag] = path
	}
	for i, file := range f.destinations() {
		if err := os.Rename(staged[file.flag], targets[file.flag]); err != nil {
			failed := certFileError(file, err)
			for _, done := range f.destinations()[:i] {
				if restoreErr := restoreCertFile(targets[done.flag], previous[done.flag]); restoreErr != nil {
					failed = fmt.Errorf("%w; --%s %s couldn't be put back and holds the new file (%s)", failed, done.flag, quoted(done.path, "file"), util.SanitizeDisplay(pathErrorReason(restoreErr)))
				}
			}
			return nil, failed
		}
		delete(staged, file.flag)
		written = append(written, file.path)
	}
	return written, nil
}

// restoreCertFile puts back a file write replaced, or removes one it created.
func restoreCertFile(target string, previous *previousCertFile) error {
	if previous == nil {
		return os.Remove(target)
	}
	path, err := util.StageFile(target, previous.contents, previous.info.Mode().Perm(), func(f *os.File) error {
		return keepOwner(f, previous.info)
	})
	if err != nil {
		return err
	}
	if err := os.Rename(path, target); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func ensureTrailingNewline(contents string) string {
	if contents == "" || strings.HasSuffix(contents, "\n") {
		return contents
	}
	return contents + "\n"
}

// requireMaterial runs before any result is printed, so a missing certificate or key never follows
// output that looks like success. A reply that isn't the certificate, such as a proxy's sign-in page,
// decodes as no certificate and must not replace a deployed one.
func requireMaterial(cmd *cobra.Command, files certOutputFiles, bundle api.CertificateData) {
	if block, _ := pem.Decode([]byte(bundle.Certificate)); block == nil || block.Type != "CERTIFICATE" {
		exitCertError(cmd, fmt.Errorf("the response held no PEM certificate"),
			fmt.Sprintf("Unable to read certificate %s from Infisical. Nothing was written", util.SanitizeDisplay(bundle.CertificateID)))
	}
	if files.wantsKey() && bundle.PrivateKey == "" {
		exitCertError(cmd, errPrivateKeyUnavailable(bundle.CertificateID))
	}
}

// writeCertificateFiles runs before the result is printed, so stdout never shows a result whose files
// weren't written. retry is the command that delivers them again, so a failed write keeps the caller's
// choices, such as --remove-roots-from-chain on a request pickup.
func writeCertificateFiles(cmd *cobra.Command, files certOutputFiles, bundle api.CertificateData, retry string) []string {
	if !files.any() {
		return nil
	}
	written, err := files.write(bundle)
	if err != nil {
		exitCertError(cmd, err, fmt.Sprintf("Certificate %s is in Infisical, but its files weren't written. Fix the problem above, then download it with: %s",
			util.SanitizeDisplay(bundle.CertificateID), retry))
	}
	return written
}

func certificateDownload(cmd *cobra.Command, certificateID, application string, files certOutputFiles) string {
	return certManagerPrefix + " certificates get " + util.SuggestedValue(certificateID, "certificate-id") + applicationFlag(application) + instanceFlags(cmd) + files.flags()
}

// printCertificateOutput follows the printed result: it names the files written, or prints the
// certificate PEM (and the key with --include-private-key) when no file flag is given and the output
// is plain text.
func printCertificateOutput(cmd *cobra.Command, files certOutputFiles, bundle api.CertificateData, outputFormat string, written []string) {
	if files.any() {
		certNotice(cmd, fmt.Sprintf("Wrote %s.", strings.Join(written, ", ")))
		if outputFormat == "" && files.IncludeKey {
			util.PrintStdout(ensureTrailingNewline(bundle.PrivateKey))
		}
		return
	}
	if outputFormat != "" {
		return
	}
	util.PrintStdout(ensureTrailingNewline(bundle.Certificate))
	if files.IncludeKey {
		util.PrintStdout(ensureTrailingNewline(bundle.PrivateKey))
	}
}

func rfc3339(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func display(value *string) string {
	if value == nil {
		return "-"
	}
	return util.SanitizeDisplay(*value)
}

// certificateIssueResult is the structured output of issue and renew. Fields are never renamed or
// removed (CLI.md); certificate fields are null while the request is pending.
type certificateIssueResult struct {
	Status               string  `json:"status"`
	CertificateRequestID string  `json:"certificateRequestId"`
	CertificateID        *string `json:"certificateId"`
	SerialNumber         *string `json:"serialNumber"`
	CommonName           *string `json:"commonName"`
	NotBefore            *string `json:"notBefore"`
	NotAfter             *string `json:"notAfter"`
	Certificate          *string `json:"certificate"`
	CertificateChain     *string `json:"certificateChain"`
	Message              *string `json:"message"`
	PrivateKey           *string `json:"privateKey,omitempty"`
	// Only renew sets it.
	RenewedFromCertificateID *string `json:"renewedFromCertificateId,omitempty"`
}

// fillFromLeaf fills the fields the backend response may lack from the issued certificate itself.
func fillFromLeaf(certificatePEM string, commonName, notBefore, notAfter **string) {
	leaf, ok := parseLeafCertificate([]byte(certificatePEM))
	if !ok {
		return
	}
	if *commonName == nil {
		*commonName = optional(leaf.Subject.CommonName)
	}
	if *notBefore == nil {
		*notBefore = rfc3339(leaf.NotBefore)
	}
	if *notAfter == nil {
		*notAfter = rfc3339(leaf.NotAfter)
	}
}

func (result *certificateIssueResult) fillIssued(bundle api.CertificateData, includeKey bool) {
	result.Status = api.CertificateRequestStatusIssued
	result.CertificateID = optional(bundle.CertificateID)
	result.SerialNumber = optional(bundle.SerialNumber)
	result.Certificate = optional(bundle.Certificate)
	result.CertificateChain = optional(bundle.CertificateChain)
	fillFromLeaf(bundle.Certificate, &result.CommonName, &result.NotBefore, &result.NotAfter)
	if includeKey {
		result.PrivateKey = optional(bundle.PrivateKey)
	}
}

func printIssueResult(outputFormat string, result certificateIssueResult) {
	if outputFormat != "" {
		printFormattedOutput(outputFormat, result)
		return
	}
	visualize.GenericTable(
		[]string{"STATUS", "CERTIFICATE ID", "SERIAL NUMBER", "COMMON NAME", "NOT AFTER", "REQUEST ID"},
		[][]string{{result.Status, display(result.CertificateID), display(result.SerialNumber), display(result.CommonName), display(result.NotAfter), util.SanitizeDisplay(result.CertificateRequestID)}})
}

func isPendingRequestStatus(status string) bool {
	return status == api.CertificateRequestStatusPendingApproval || status == api.CertificateRequestStatusPending ||
		status == api.CertificateRequestStatusPendingValidation
}

func requestBundle(cmd *cobra.Command, client *resty.Client, request *api.GetCertificateRequestResponse, application, requestID, pickupFlags string, wantKey bool) api.CertificateData {
	bundle, ok := request.IssuedCertificateData()
	if !ok {
		exitCertError(cmd, errCertificateUnavailable(requestID))
	}
	// The request endpoint returns the key only to callers who can read private keys; the bundle
	// endpoint tells a missing permission apart from a certificate that has no key.
	if wantKey && bundle.PrivateKey == "" {
		full, err := getCertificateBundle(client, bundle.CertificateID)
		if err != nil {
			exitWithPickup(cmd, err, requestID, application, pickupFlags, "Unable to get the certificate's private key")
		}
		bundle.PrivateKey, bundle.CertificateChain = full.PrivateKey, full.CertificateChain
	}
	// The request endpoint returns no chain, so it's read from the issued certificate.
	if bundle.CertificateChain == "" {
		body, err := api.CallGetCertificateBody(client, bundle.CertificateID)
		if err != nil {
			exitWithPickup(cmd, err, requestID, application, pickupFlags, "Unable to get the certificate chain")
		}
		bundle.CertificateChain = body.CertificateChain
	}
	return bundle
}

// getCertificateBundle reads a certificate with its private key. A caller who can read the
// certificate but not its key gets a 403 ForbiddenError.
func getCertificateBundle(client *resty.Client, certificateID string) (*api.CertificateBundleResponse, error) {
	bundle, err := api.CallGetCertificateBundle(client, certificateID)
	if err != nil {
		return nil, forbiddenAsPermissionDenied(err)
	}
	return bundle, nil
}

// forbiddenAsPermissionDenied maps Certificate Manager's role denials, a 403 ForbiddenError that
// classifyAPIError leaves unclassified, to permission_denied.
func forbiddenAsPermissionDenied(err error) error {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 403 && apiErr.Name == "ForbiddenError" {
		return errPermissionDenied(apiErr.ErrorMessage, err)
	}
	return err
}

// revocationDenied is forbiddenAsPermissionDenied for revoke, whose denials already say who can revoke
// the certificate, such as an Application Admin, so the generic advice to ask a project admin is left out.
func revocationDenied(err error) error {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 403 && apiErr.Name == "ForbiddenError" {
		return &util.CLIError{Code: errCodePermissionDenied, Cause: err, Message: util.SanitizeDisplay(apiErr.ErrorMessage)}
	}
	return err
}

// exitWithPickup is exitWithError for a failure while a request is open, so the request ID isn't
// lost and the certificate can still be picked up.
func exitWithPickup(cmd *cobra.Command, err error, requestID, application, pickupFlags, message string) {
	pickup := util.NextStep{Purpose: "To pick up the certificate later", Command: certificateRequestPickup(requestID, application, pickupFlags)}
	classified := classifyAPIError(err, errorScope{}, nil)
	var cliErr *util.CLIError
	if errors.As(classified, &cliErr) {
		cliErr.Next = append(cliErr.Next, pickup)
		exitCertError(cmd, cliErr)
		return
	}
	exitCertError(cmd, classified, fmt.Sprintf("%s for certificate request %s. %s, run: %s", message, util.SanitizeDisplay(requestID), pickup.Purpose, pickup.Command))
}

// pollUntil calls check until it returns true or an error, or ctx ends. The interval doubles from
// certPollInterval up to certMaxPollInterval, since every read of a request or an approval is audited
// and a decision can take minutes.
func pollUntil(ctx context.Context, check func() (bool, error)) (bool, error) {
	interval := certPollInterval
	for {
		done, err := check()
		if done || err != nil {
			return done, err
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(interval):
		}
		interval = min(interval*2, certMaxPollInterval)
	}
}

// isTransientPollError is a failure a wait keeps polling through: a dropped connection, a rate limit
// or a server error during a deploy. Anything else, such as an expired token, ends the wait.
func isTransientPollError(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.StatusCode == 429 || apiErr.StatusCode >= 500
}

// pollFailure is a failed read during a wait: nil when the wait ran out or should keep polling, the
// error when it should end. lastErr keeps the latest transient failure, to report if the wait runs out.
func pollFailure(ctx context.Context, err error, lastErr *error) error {
	if ctx.Err() != nil {
		return nil
	}
	if isTransientPollError(err) {
		*lastErr = err
		return nil
	}
	return err
}

// waitDetail is what a wait that ran out last learned: the request's pending message, and the failure
// that kept the last checks from reading it.
func waitDetail(message string, lastErr error) string {
	var detail []string
	if message = strings.TrimSpace(message); message != "" {
		detail = append(detail, fmt.Sprintf("Infisical reports: %s.", strings.TrimSuffix(message, ".")))
	}
	if lastErr != nil {
		detail = append(detail, fmt.Sprintf("The last check failed: %s.", lastErr.Error()))
	}
	return util.SanitizeDisplay(strings.Join(detail, " "))
}

// waitForCertificateRequest polls a pending request until it's settled or the timeout passes, and
// returns the request as it last read, which is still pending after a timeout, with the latest
// transient failure. An error ends the wait.
func waitForCertificateRequest(cmd *cobra.Command, client *resty.Client, request *api.GetCertificateRequestResponse, requestID string, timeout time.Duration) (*api.GetCertificateRequestResponse, error, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	announced := ""
	var lastErr error
	_, err := pollUntil(ctx, func() (bool, error) {
		latest, err := api.CallGetCertificateRequest(ctx, client, requestID)
		if err != nil {
			return false, pollFailure(ctx, err, &lastErr)
		}
		request, lastErr = latest, nil
		if !isPendingRequestStatus(request.Status) {
			return true, nil
		}
		if state := request.Status + "\x00" + pendingMessage(request); announced != state {
			announced = state
			waiting := "for the certificate"
			if request.Status == api.CertificateRequestStatusPendingApproval {
				waiting = "for approval"
			}
			notice := fmt.Sprintf("Certificate request %s is %s.", util.SanitizeDisplay(requestID), request.Status) + pendingValidationHint(request.Status)
			if detail := waitDetail(pendingMessage(request), nil); detail != "" {
				notice += " " + detail
			}
			certNotice(cmd, fmt.Sprintf("%s Waiting up to %s %s...", notice, timeout, waiting))
		}
		return false, nil
	})
	return request, lastErr, err
}

func pendingMessage(request *api.GetCertificateRequestResponse) string {
	if request.PendingMessage != nil {
		return *request.PendingMessage
	}
	return ""
}

func errorMessage(request *api.GetCertificateRequestResponse) string {
	if request.ErrorMessage != nil {
		return *request.ErrorMessage
	}
	return ""
}

// issuanceOptions are what issue and renew asked for, beyond the request itself.
type issuanceOptions struct {
	files        certOutputFiles
	outputFormat string
	timeout      time.Duration
	noWait       bool
	removeRoot   bool
}

// pickupFlags are the flags a suggested pickup command repeats, so it reaches the same instance and
// delivers the files and chain the original command asked for.
func (o issuanceOptions) pickupFlags(cmd *cobra.Command) string {
	flags := instanceFlags(cmd)
	if o.removeRoot {
		flags += " --remove-roots-from-chain"
	}
	return flags + o.files.flags()
}

// withKey fills a private key the issue or renew response left out. The backend withholds it from a
// caller who can't read private keys; the bundle endpoint reports that as permission_denied.
func withKey(cmd *cobra.Command, client *resty.Client, bundle api.CertificateData) api.CertificateData {
	if bundle.PrivateKey != "" || bundle.CertificateID == "" {
		return bundle
	}
	full, err := getCertificateBundle(client, bundle.CertificateID)
	if err != nil {
		exitCertError(cmd, withContext(classifyAPIError(err, errorScope{}, nil), fmt.Sprintf("Certificate %s was issued, but its private key couldn't be read", util.SanitizeDisplay(bundle.CertificateID))))
	}
	bundle.PrivateKey = full.PrivateKey
	return bundle
}

// exitCertError is exitWithError for the cert-manager commands: the commands an error suggests repeat
// the instance flags, so they reach the same Infisical as the command that failed.
func exitCertError(cmd *cobra.Command, err error, messages ...string) {
	var cliErr *util.CLIError
	if instance := instanceFlags(cmd); instance != "" && errors.As(err, &cliErr) {
		for i, next := range cliErr.Next {
			if strings.HasPrefix(next.Command, certManagerPrefix) && !strings.Contains(next.Command, instance) {
				cliErr.Next[i].Command += instance
			}
		}
	}
	exitWithError(cmd, err, messages...)
}

// withContext puts what had already happened in front of an error's message: exitWithError prints a
// CLIError on its own, without extra messages.
func withContext(err error, context string) error {
	var cliErr *util.CLIError
	if errors.As(err, &cliErr) {
		cliErr.Message = context + ". " + cliErr.Message
		return cliErr
	}
	return fmt.Errorf("%s: %w", context, err)
}

// finishIssuance handles a response from issue or renew: delivers an issued certificate, or waits
// for a pending one (unless noWait), then prints the result.
func finishIssuance(cmd *cobra.Command, client *resty.Client, application string, options issuanceOptions, result certificateIssueResult, issued *api.CertificateData) {
	requestID := result.CertificateRequestID
	if issued == nil && isPendingRequestStatus(result.Status) && !options.noWait {
		request, lastErr, err := waitForCertificateRequest(cmd, client, &api.GetCertificateRequestResponse{Status: result.Status, PendingMessage: result.Message}, requestID, options.timeout)
		if err != nil {
			exitWithPickup(cmd, err, requestID, application, options.pickupFlags(cmd), "Unable to check the request")
		}
		switch {
		case request.Status == api.CertificateRequestStatusIssued:
			bundle := requestBundle(cmd, client, request, application, requestID, options.pickupFlags(cmd), options.files.wantsKey())
			// The chain read after the wait is the stored one, which keeps the root.
			if options.removeRoot {
				bundle.CertificateChain = withoutRootCertificates(bundle.CertificateChain)
			}
			issued = &bundle
			result.Message = nil
		case isPendingRequestStatus(request.Status):
			exitCertError(cmd, errCertificateRequestPending(requestID, request.Status, application, options.pickupFlags(cmd), waitDetail(pendingMessage(request), lastErr)))
		default:
			exitCertError(cmd, errCertificateRequestRejected(requestID, request.Status, errorMessage(request), cmd.Name()))
		}
	} else if issued != nil && options.files.wantsKey() {
		bundle := withKey(cmd, client, *issued)
		issued = &bundle
	}

	if issued == nil {
		if !isPendingRequestStatus(result.Status) {
			message := ""
			if result.Message != nil {
				message = *result.Message
			}
			exitCertError(cmd, errCertificateRequestRejected(requestID, result.Status, message, cmd.Name()))
		}
		printIssueResult(options.outputFormat, result)
		certNotice(cmd, fmt.Sprintf("Certificate request %s is %s.%s To pick up the certificate once it's issued, run: %s --wait", util.SanitizeDisplay(requestID), result.Status, pendingValidationHint(result.Status), certificateRequestPickup(requestID, application, options.pickupFlags(cmd))))
		return
	}

	requireMaterial(cmd, options.files, *issued)
	retry := certificateDownload(cmd, issued.CertificateID, application, options.files)
	if requestID != "" {
		retry = certificateRequestPickup(requestID, application, options.pickupFlags(cmd))
	}
	written := writeCertificateFiles(cmd, options.files, *issued, retry)
	result.fillIssued(*issued, options.files.IncludeKey)
	printIssueResult(options.outputFormat, result)
	printCertificateOutput(cmd, options.files, *issued, options.outputFormat, written)
}

// collectPages reads every page of an offset-paged list. An empty page ends it too, so a total that
// moves while paging can't loop forever.
func collectPages[T any](fetch func(offset int) ([]T, int, error)) ([]T, error) {
	var items []T
	for {
		page, total, err := fetch(len(items))
		if err != nil {
			return nil, err
		}
		items = append(items, page...)
		if len(page) == 0 || len(items) >= total {
			return items, nil
		}
	}
}

type applicationItem struct {
	ApplicationID   string  `json:"applicationId"`
	ApplicationName string  `json:"applicationName"`
	Description     *string `json:"description"`
}

var applicationHeaders = []string{"APPLICATION NAME", "APPLICATION ID", "DESCRIPTION"}

func newApplicationItem(application api.PkiApplication) applicationItem {
	return applicationItem{application.ID, application.Name, application.Description}
}

func (a applicationItem) row() []string {
	return []string{util.SanitizeDisplay(a.ApplicationName), util.SanitizeDisplay(a.ApplicationID), display(a.Description)}
}

func runCertApplicationsGet(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "applications")
	client := certHTTPClient(cmd)

	if len(args) == 0 {
		applications, err := collectPages(func(offset int) ([]api.PkiApplication, int, error) {
			page, err := api.CallListPkiApplications(client, offset, certListPageSize)
			return page.Applications, page.Total, err
		})
		if err != nil {
			exitCertError(cmd, classifyAPIError(err, errorScope{}, nil), "Unable to list applications")
		}
		items := make([]applicationItem, 0, len(applications))
		rows := make([][]string, 0, len(applications))
		for _, application := range applications {
			item := newApplicationItem(application)
			items = append(items, item)
			rows = append(rows, item.row())
		}
		switch {
		case outputFormat != "":
			printFormattedOutput(outputFormat, items)
		case len(items) == 0:
			printProjectsTip(cmd, "You can't access any Certificate Manager application. Ask an application's admin to add you.")
		default:
			visualize.GenericTable(applicationHeaders, rows)
		}
		captureCertEvent("applications get", posthog.NewProperties().Set("applicationCount", len(items)))
		return
	}

	application := resolveCertApplication(cmd, client, strings.TrimSpace(args[0]))
	profiles := listCertApplicationProfiles(cmd, client, application)
	type profileItem struct {
		ProfileID   string  `json:"profileId"`
		ProfileName string  `json:"profileName"`
		Description *string `json:"description"`
	}
	result := struct {
		applicationItem
		Profiles []profileItem `json:"profiles"`
	}{newApplicationItem(application), []profileItem{}}
	var rows [][]string
	for _, profile := range profiles {
		if !hasAPIEnrollment(profile) {
			continue
		}
		result.Profiles = append(result.Profiles, profileItem{profile.ProfileID, profile.ProfileSlug, profile.ProfileDescription})
		rows = append(rows, []string{util.SanitizeDisplay(profile.ProfileSlug), util.SanitizeDisplay(profile.ProfileID), display(profile.ProfileDescription)})
	}
	if outputFormat != "" {
		printFormattedOutput(outputFormat, result)
	} else {
		visualize.GenericTable(applicationHeaders, [][]string{result.row()})
		if len(rows) == 0 {
			printProjectsTip(cmd, "This application has no profile with API enrollment, so the CLI can't issue in it yet. Configure API enrollment under the application's Settings tab in Infisical.")
		} else {
			visualize.GenericTable([]string{"PROFILE NAME", "PROFILE ID", "DESCRIPTION"}, rows)
		}
	}
	captureCertEvent("applications get", posthog.NewProperties().Set("profileCount", len(result.Profiles)))
}

func runCertIssue(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "certificates")
	applicationName, invalid := certApplicationFlag(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	input, invalid := readCertRequestInput(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	metadata, invalid := readCertMetadata(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	timeout, noWait, invalid := readWaitFlags(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	files, invalid := readCertOutputFiles(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	profileName, invalid := optionalFlag(cmd, "certificate-profile")
	if invalid != nil {
		exitCertError(cmd, invalid)
	}

	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	profile, invalid := selectIssuanceProfile(listCertApplicationProfiles(cmd, client, application), profileName, application.Name)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}

	response, err := api.CallIssueCertificate(client, api.IssueCertificateRequest{
		ProfileID:            profile.ProfileID,
		ApplicationID:        application.ID,
		CSR:                  input.CSR,
		Attributes:           input.Attributes,
		RemoveRootsFromChain: input.RemoveRoot,
		Metadata:             metadata,
	})
	if err != nil {
		exitCertError(cmd, classifyAPIError(err, errorScope{}, nil), "Unable to issue the certificate")
	}

	issued := response.Certificate
	status := response.Status
	if status == "" && issued != nil {
		status = api.CertificateRequestStatusIssued
	}
	captureCertEvent("certificates issue", posthog.NewProperties().Set("csr", input.CSR != "").Set("status", status))
	finishIssuance(cmd, client, application.Name, issuanceOptions{files, outputFormat, timeout, noWait, input.RemoveRoot},
		certificateIssueResult{Status: status, CertificateRequestID: response.CertificateRequestID, Message: optional(response.Message)}, issued)
}

// certificateInApplication reads a certificate and refuses one from another application with
// certificate_not_found, so a mistyped ID can't act on a certificate elsewhere.
func certificateInApplication(cmd *cobra.Command, client *resty.Client, certificateID string, application api.PkiApplication) *api.RetrieveCertificateResponse {
	certificate, err := api.CallRetrieveCertificate(context.Background(), client, certificateID)
	if err != nil {
		// Another organization's certificate gets a 403 ForbiddenError, reported like one that doesn't exist.
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 403 && apiErr.Name == "ForbiddenError" {
			exitCertError(cmd, errCertificateNotFound(certificateID, application.Name, err))
		}
		exitCertError(cmd, classifyAPIError(err, errorScope{}, func(cause error) *util.CLIError {
			return errCertificateNotFound(certificateID, application.Name, cause)
		}), "Unable to get the certificate")
	}
	if certificate.Certificate.ApplicationID == nil || *certificate.Certificate.ApplicationID != application.ID {
		exitCertError(cmd, errCertificateNotFound(certificateID, application.Name, nil))
	}
	return certificate
}

func certificateIDArg(cmd *cobra.Command, value string) string {
	id, ok := pkiID(value)
	if !ok {
		exitCertError(cmd, errNotAnID("certificate", value))
	}
	return id
}

func runCertRenew(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "certificates")
	certificateID := certificateIDArg(cmd, args[0])
	applicationName, invalid := certApplicationFlag(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	input, invalid := readCertRequestInput(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	timeout, noWait, invalid := readWaitFlags(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	files, invalid := readCertOutputFiles(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	if input.CSR == "" && files.Cert != "" && !files.wantsKey() {
		exitCertError(cmd, errInvalidFlag("output-certificate-file", "needs --output-private-key-file or --include-private-key without --csr: Infisical generates a new key for the renewed certificate, and the certificate is no use without it"))
	}

	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	existing := certificateInApplication(cmd, client, certificateID, application).Certificate
	if invalid := keepPathLength(cmd, input.Attributes, existing); invalid != nil {
		exitCertError(cmd, invalid)
	}

	request := api.RenewCertificateRequest{RemoveRootsFromChain: input.RemoveRoot, RenewalKeySource: "new", Attributes: input.Attributes}
	if input.CSR != "" {
		request.RenewalKeySource, request.CSR = "csr", input.CSR
	}
	response, err := api.CallRenewCertificate(client, certificateID, request)
	if err != nil {
		exitCertError(cmd, classifyAPIError(err, errorScope{}, func(cause error) *util.CLIError {
			return errCertificateNotFound(certificateID, application.Name, cause)
		}), "Unable to renew the certificate")
	}

	var issued *api.CertificateData
	if response.Certificate != "" {
		data := response.CertificateData()
		issued = &data
	}
	status := response.Status
	if status == "" && issued != nil {
		status = api.CertificateRequestStatusIssued
	}
	captureCertEvent("certificates renew", posthog.NewProperties().Set("csr", input.CSR != "").Set("status", status))
	finishIssuance(cmd, client, application.Name, issuanceOptions{files, outputFormat, timeout, noWait, input.RemoveRoot},
		certificateIssueResult{Status: status, CertificateRequestID: response.CertificateRequestID, RenewedFromCertificateID: &certificateID}, issued)
}

// keepPathLength applies renew's basic constraints to a CA certificate: the backend replaces them
// whole, so --is-ca alone keeps the certificate's path length, and --path-length alone keeps it a CA.
func keepPathLength(cmd *cobra.Command, attributes *api.CertificateAttributes, existing api.RetrievedCertificate) *util.CLIError {
	if attributes == nil || attributes.BasicConstraints == nil {
		return nil
	}
	constraints := attributes.BasicConstraints
	existingCA := existing.BasicConstraints != nil && existing.BasicConstraints.IsCA
	if !cmd.Flags().Changed("is-ca") {
		if !existingCA {
			return errInvalidFlag("path-length", "needs --is-ca: the certificate isn't a CA certificate, and a path length only applies to one")
		}
		constraints.IsCA = true
	}
	if constraints.IsCA && constraints.PathLength == nil && existingCA {
		constraints.PathLength = existing.BasicConstraints.PathLength
	}
	return nil
}

func runCertGet(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "certificates")
	applicationName, invalid := certApplicationFlag(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	if len(args) == 0 {
		rejectFlagsWithoutID(cmd, certFileFlags, "needs a certificate ID: pass the ID of the certificate to download")
		listCertificates(cmd, applicationName, outputFormat)
		return
	}

	certificateID := certificateIDArg(cmd, args[0])
	for _, flag := range []string{"certificate-profile", "status", "expires-within"} {
		if cmd.Flags().Changed(flag) {
			exitCertError(cmd, errInvalidFlag(flag, "only filters the list: leave out the certificate ID, or this flag"))
		}
	}
	files, invalid := readCertOutputFiles(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}

	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	certificate := certificateInApplication(cmd, client, certificateID, application).Certificate
	if files.wantsKey() && !certificate.HasPrivateKey {
		exitCertError(cmd, errPrivateKeyUnavailable(certificateID))
	}

	bundle := api.CertificateData{CertificateID: certificateID}
	notFound := func(cause error) *util.CLIError {
		return errCertificateNotFound(certificateID, application.Name, cause)
	}
	if files.wantsKey() {
		full, err := getCertificateBundle(client, certificateID)
		if err != nil {
			exitCertError(cmd, classifyAPIError(err, errorScope{}, notFound), "Unable to get the certificate's private key")
		}
		bundle.Certificate, bundle.CertificateChain, bundle.PrivateKey = full.Certificate, full.CertificateChain, full.PrivateKey
	} else {
		body, err := api.CallGetCertificateBody(client, certificateID)
		if err != nil {
			exitCertError(cmd, classifyAPIError(err, errorScope{}, notFound), "Unable to get the certificate")
		}
		bundle.Certificate, bundle.CertificateChain = body.Certificate, body.CertificateChain
	}

	requireMaterial(cmd, files, bundle)
	written := writeCertificateFiles(cmd, files, bundle, certificateDownload(cmd, bundle.CertificateID, application.Name, files))
	details := certificateDetailsFrom(certificate, bundle, files.IncludeKey, time.Now())
	if outputFormat != "" {
		printFormattedOutput(outputFormat, details)
	} else {
		visualize.GenericTable([]string{"CERTIFICATE ID", "COMMON NAME", "STATUS", "SERIAL NUMBER", "PROFILE", "NOT AFTER"},
			[][]string{{details.CertificateID, display(details.CommonName), details.Status, details.SerialNumber, display(details.ProfileName), display(details.NotAfter)}})
	}
	printCertificateOutput(cmd, files, bundle, outputFormat, written)
	captureCertEvent("certificates get", posthog.NewProperties().Set("download", files.any()))
}

type certificateDetails struct {
	CertificateID            string                         `json:"certificateId"`
	ApplicationID            *string                        `json:"applicationId"`
	ApplicationName          *string                        `json:"applicationName"`
	ProfileID                *string                        `json:"profileId"`
	ProfileName              *string                        `json:"profileName"`
	Status                   string                         `json:"status"`
	SerialNumber             string                         `json:"serialNumber"`
	CommonName               *string                        `json:"commonName"`
	SubjectAlternativeNames  []api.AltName                  `json:"subjectAlternativeNames"`
	Organization             *string                        `json:"organization"`
	OrganizationalUnit       *string                        `json:"organizationalUnit"`
	Country                  *string                        `json:"country"`
	State                    *string                        `json:"state"`
	Locality                 *string                        `json:"locality"`
	DomainComponents         []string                       `json:"domainComponents"`
	NotBefore                *string                        `json:"notBefore"`
	NotAfter                 *string                        `json:"notAfter"`
	KeyAlgorithm             *string                        `json:"keyAlgorithm"`
	SignatureAlgorithm       *string                        `json:"signatureAlgorithm"`
	KeyUsages                []string                       `json:"keyUsages"`
	ExtendedKeyUsages        []string                       `json:"extendedKeyUsages"`
	IsCA                     *bool                          `json:"isCA"`
	PathLength               *int                           `json:"pathLength"`
	CaName                   *string                        `json:"caName"`
	HasPrivateKey            bool                           `json:"hasPrivateKey"`
	RevokedAt                *string                        `json:"revokedAt"`
	RevocationReason         *string                        `json:"revocationReason"`
	RenewedFromCertificateID *string                        `json:"renewedFromCertificateId"`
	RenewedByCertificateID   *string                        `json:"renewedByCertificateId"`
	Metadata                 []api.CertificateMetadataEntry `json:"metadata"`
	CreatedAt                *string                        `json:"createdAt"`
	Certificate              *string                        `json:"certificate"`
	CertificateChain         *string                        `json:"certificateChain"`
	PrivateKey               *string                        `json:"privateKey,omitempty"`
}

// currentCertificateStatus is the status certificate search reports: the stored status doesn't change
// when a certificate expires or is renewed. The order follows the backend's CURRENT_STATUS_SQL.
func currentCertificateStatus(certificate api.RetrievedCertificate, now time.Time) string {
	switch {
	case certificate.Status == string(api.CertificateStatusRevoked):
		return certificate.Status
	case !certificate.NotAfter.IsZero() && !certificate.NotAfter.After(now):
		return string(api.CertificateStatusExpired)
	case certificate.RenewedByCertificateID != "":
		return string(api.CertificateStatusRenewed)
	}
	return certificate.Status
}

// certUsageSpelling pairs the spelling --key-usage and --extended-key-usage take with the one the
// certificate GET returns, so values copy from the output to a renew. The lists are in help order.
type certUsageSpelling struct{ flag, returned string }

var (
	certKeyUsageSpellings = []certUsageSpelling{{"digital_signature", "digitalSignature"}, {"key_encipherment", "keyEncipherment"},
		{"non_repudiation", "nonRepudiation"}, {"data_encipherment", "dataEncipherment"}, {"key_agreement", "keyAgreement"},
		{"key_cert_sign", "keyCertSign"}, {"crl_sign", "cRLSign"}, {"encipher_only", "encipherOnly"}, {"decipher_only", "decipherOnly"}}
	certExtendedKeyUsageSpellings = []certUsageSpelling{{"client_auth", "clientAuth"}, {"server_auth", "serverAuth"},
		{"code_signing", "codeSigning"}, {"email_protection", "emailProtection"}, {"ocsp_signing", "ocspSigning"},
		{"smart_card_logon", "smartCardLogon"}, {"time_stamping", "timeStamping"}, {"any_purpose", "anyExtendedKeyUsage"}}
)

func certUsageFlagNames(spellings []certUsageSpelling) []string {
	names := make([]string, 0, len(spellings))
	for _, spelling := range spellings {
		names = append(names, spelling.flag)
	}
	return names
}

func certUsageFlags(usages []string) []string {
	values := make([]string, 0, len(usages))
	for _, usage := range usages {
		matches := func(s certUsageSpelling) bool { return s.returned == usage }
		if index := slices.IndexFunc(certKeyUsageSpellings, matches); index >= 0 {
			usage = certKeyUsageSpellings[index].flag
		} else if index := slices.IndexFunc(certExtendedKeyUsageSpellings, matches); index >= 0 {
			usage = certExtendedKeyUsageSpellings[index].flag
		}
		values = append(values, usage)
	}
	return values
}

func certificateDetailsFrom(certificate api.RetrievedCertificate, bundle api.CertificateData, includeKey bool, now time.Time) certificateDetails {
	details := certificateDetails{
		CertificateID:            certificate.ID,
		ApplicationID:            certificate.ApplicationID,
		ApplicationName:          certificate.ApplicationName,
		ProfileID:                certificate.ProfileID,
		ProfileName:              certificate.ProfileName,
		Status:                   currentCertificateStatus(certificate, now),
		SerialNumber:             certificate.SerialNumber,
		CommonName:               optional(certificate.CommonName),
		SubjectAlternativeNames:  []api.AltName{},
		DomainComponents:         []string{},
		NotBefore:                rfc3339(certificate.NotBefore),
		NotAfter:                 rfc3339(certificate.NotAfter),
		KeyAlgorithm:             certificate.KeyAlgorithm,
		SignatureAlgorithm:       certificate.SignatureAlgorithm,
		KeyUsages:                certUsageFlags(certificate.KeyUsages),
		ExtendedKeyUsages:        certUsageFlags(certificate.ExtendedKeyUsages),
		CaName:                   certificate.CaName,
		HasPrivateKey:            certificate.HasPrivateKey,
		RenewedFromCertificateID: certificate.RenewedFromCertificateID,
		RenewedByCertificateID:   optional(certificate.RenewedByCertificateID),
		Metadata:                 []api.CertificateMetadataEntry{},
		CreatedAt:                rfc3339(certificate.CreatedAt),
		Certificate:              optional(bundle.Certificate),
		CertificateChain:         optional(bundle.CertificateChain),
	}
	if certificate.RevokedAt != nil {
		details.RevokedAt = rfc3339(*certificate.RevokedAt)
	}
	if certificate.RevocationReason != nil {
		if index := slices.IndexFunc(crlReasons, func(r crlReason) bool { return r.Code == *certificate.RevocationReason }); index >= 0 {
			details.RevocationReason = &crlReasons[index].Name
		}
	}
	if includeKey {
		details.PrivateKey = optional(bundle.PrivateKey)
	}
	if subject := certificate.Subject; subject != nil {
		details.Organization = optional(subject.Organization)
		details.OrganizationalUnit = optional(subject.OrganizationalUnit)
		details.Country = optional(subject.Country)
		details.State = optional(subject.State)
		details.Locality = optional(subject.Locality)
		if subject.DomainComponents != nil {
			details.DomainComponents = subject.DomainComponents
		}
	}
	if certificate.Metadata != nil {
		details.Metadata = certificate.Metadata
	}
	if constraints := certificate.BasicConstraints; constraints != nil {
		details.IsCA = &constraints.IsCA
		details.PathLength = constraints.PathLength
	}
	// The server stores SANs as one untyped string, so their types come from the certificate itself.
	if leaf, ok := parseLeafCertificate([]byte(bundle.Certificate)); ok {
		details.SubjectAlternativeNames = leafSANs(leaf)
	}
	return details
}

func leafSANs(leaf *x509.Certificate) []api.AltName {
	sans := []api.AltName{}
	for _, name := range leaf.DNSNames {
		sans = append(sans, api.AltName{Type: api.AltNameTypeDNS, Value: name})
	}
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, api.AltName{Type: api.AltNameTypeIP, Value: ip.String()})
	}
	for _, email := range leaf.EmailAddresses {
		sans = append(sans, api.AltName{Type: api.AltNameTypeEmail, Value: email})
	}
	for _, uri := range leaf.URIs {
		sans = append(sans, api.AltName{Type: api.AltNameTypeURI, Value: uri.String()})
	}
	return sans
}

// optionalFlag reads a string flag that may be left out, but not passed empty: an empty value usually
// comes from an unset shell variable, and treating it as left out would drop a filter or a choice.
func optionalFlag(cmd *cobra.Command, flag string) (string, *util.CLIError) {
	value, _ := cmd.Flags().GetString(flag)
	value = strings.TrimSpace(value)
	if cmd.Flags().Changed(flag) && value == "" {
		return "", errInvalidFlag(flag, "can't be empty")
	}
	return value, nil
}

func listCertificates(cmd *cobra.Command, applicationName, outputFormat string) {
	status, invalid := optionalFlag(cmd, "status")
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	if status != "" {
		if invalid := validateChoices("status", []string{status}, certStatuses); invalid != nil {
			exitCertError(cmd, invalid)
		}
	}
	expiresWithin, invalid := optionalFlag(cmd, "expires-within")
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	request := api.SearchCertificatesRequest{Limit: certListPageSize}
	if expiresWithin != "" {
		within, err := parseDurationWithDays(expiresWithin)
		if err != nil || within <= 0 {
			exitCertError(cmd, errInvalidFlag("expires-within", fmt.Sprintf("%s isn't a duration such as 30d or 12h", quoted(expiresWithin, "expires-within"))))
		}
		now := time.Now().UTC()
		request.NotAfterFrom, request.NotAfterTo = now.Format(time.RFC3339), now.Add(within).Format(time.RFC3339)
	}
	profileName, invalid := optionalFlag(cmd, "certificate-profile")
	if invalid != nil {
		exitCertError(cmd, invalid)
	}

	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	request.ApplicationIDs = []string{application.ID}
	if status != "" {
		request.Status = []string{status}
	}
	if profileName != "" {
		profiles := listCertApplicationProfiles(cmd, client, application)
		index := findCertProfile(profiles, profileName)
		if index < 0 {
			var attached []string
			for _, profile := range profiles {
				attached = append(attached, profile.ProfileSlug)
			}
			exitCertError(cmd, errProfileNotFound(profileName, application.Name, attached))
		}
		request.ProfileIDs = []string{profiles[index].ProfileID}
	}

	certificates, err := collectPages(func(offset int) ([]api.CertificateSearchResult, int, error) {
		request.Offset = offset
		page, err := api.CallSearchCertificates(client, request)
		return page.Certificates, page.TotalCount, err
	})
	if err != nil {
		exitCertError(cmd, classifyAPIError(err, errorScope{}, nil), "Unable to list the certificates")
	}

	type certificateItem struct {
		CertificateID string  `json:"certificateId"`
		CommonName    *string `json:"commonName"`
		SerialNumber  string  `json:"serialNumber"`
		Status        string  `json:"status"`
		ProfileName   *string `json:"profileName"`
		NotBefore     *string `json:"notBefore"`
		NotAfter      *string `json:"notAfter"`
		KeyAlgorithm  *string `json:"keyAlgorithm"`
		HasPrivateKey bool    `json:"hasPrivateKey"`
	}
	items := make([]certificateItem, 0, len(certificates))
	rows := make([][]string, 0, len(certificates))
	for _, c := range certificates {
		item := certificateItem{c.ID, optional(c.CommonName), c.SerialNumber, c.Status, c.ProfileName, rfc3339(c.NotBefore), rfc3339(c.NotAfter), c.KeyAlgorithm, c.HasPrivateKey}
		items = append(items, item)
		rows = append(rows, []string{util.SanitizeDisplay(c.ID), display(item.CommonName), util.SanitizeDisplay(c.Status), display(c.ProfileName), display(item.NotAfter)})
	}
	switch {
	case outputFormat != "":
		printFormattedOutput(outputFormat, items)
	case len(items) == 0 && (status != "" || expiresWithin != "" || profileName != ""):
		printProjectsTip(cmd, fmt.Sprintf("No certificates in application %s match the filters. To see them all, run [%s certificates get%s%s].", util.SanitizeDisplay(application.Name), certManagerPrefix, applicationFlag(application.Name), instanceFlags(cmd)))
	case len(items) == 0:
		printProjectsTip(cmd, fmt.Sprintf("No certificates found in application %s. Issue one with [%s certificates issue%s%s].", util.SanitizeDisplay(application.Name), certManagerPrefix, applicationFlag(application.Name), instanceFlags(cmd)))
	default:
		visualize.GenericTable([]string{"CERTIFICATE ID", "COMMON NAME", "STATUS", "PROFILE", "NOT AFTER"}, rows)
	}
	captureCertEvent("certificates get", posthog.NewProperties().Set("certificateCount", len(items)))
}

func runCertRevoke(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "certificates")
	certificateID := certificateIDArg(cmd, args[0])
	applicationName, invalid := certApplicationFlag(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	reasonFlag, _ := cmd.Flags().GetString("reason")
	reason, invalid := parseRevocationReason(reasonFlag)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	timeout, noWait, invalid := readWaitFlags(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}

	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	certificate := certificateInApplication(cmd, client, certificateID, application).Certificate

	expected, label, names := certificate.CommonName, "the certificate's common name", certificate.CommonName+", "
	if expected == "" {
		expected, label, names = certificateID, "the certificate ID", ""
	}
	if err := confirmDestructive(cmd, args, destructiveAction{
		Target:      "certificate " + quoted(certificateID, "certificate-id"),
		Expected:    expected,
		Label:       label,
		Description: fmt.Sprintf("certificate %s (%sserial %s) in application %s, for reason %s", certificateID, names, certificate.SerialNumber, application.Name, strings.ToLower(reason)),
		Verb:        verbRevoke,
	}); err != nil {
		// The rerun it suggests already repeats the instance flags.
		exitWithError(cmd, err)
	}
	// The certificate could have moved to another application while the question was open.
	if yes, _ := cmd.Flags().GetBool("yes"); !yes {
		certificateInApplication(cmd, client, certificateID, application)
	}

	response, err := api.CallRevokeCertificate(client, certificateID, api.RevokeCertificateRequest{RevocationReason: reason})
	if err != nil {
		exitCertError(cmd, classifyAPIError(revocationDenied(err), errorScope{}, func(cause error) *util.CLIError {
			return errCertificateNotFound(certificateID, application.Name, cause)
		}), "Unable to revoke the certificate")
	}

	// An answer that is neither, such as a proxy's page decoded as nothing, must not read as revoked.
	if response.Status != string(api.CertificateStatusRevoked) &&
		(response.Status != api.CertificateRequestStatusPendingApproval || response.ApprovalRequestID == nil) {
		exitCertError(cmd, fmt.Errorf("unexpected revocation status %s", quoted(response.Status, "status")),
			fmt.Sprintf("Unable to confirm the revocation of certificate %s. Check its status with %s certificates get %s%s%s", certificateID, certManagerPrefix, util.SuggestedValue(certificateID, "certificate-id"), applicationFlag(application.Name), instanceFlags(cmd)))
	}

	result := struct {
		CertificateID     string  `json:"certificateId"`
		SerialNumber      string  `json:"serialNumber"`
		Status            string  `json:"status"`
		RevocationReason  string  `json:"revocationReason"`
		RevokedAt         *string `json:"revokedAt"`
		ApprovalRequestID *string `json:"approvalRequestId"`
		CrlWarning        *string `json:"crlWarning"`
	}{certificateID, response.SerialNumber, response.Status, strings.ToLower(reason), nil, response.ApprovalRequestID, response.CrlWarning}
	if response.RevokedAt != nil {
		result.RevokedAt = rfc3339(*response.RevokedAt)
	}
	if result.SerialNumber == "" {
		result.SerialNumber = certificate.SerialNumber
	}
	captureCertEvent("certificates revoke", posthog.NewProperties().Set("status", response.Status))

	if response.Status == api.CertificateRequestStatusPendingApproval {
		approvalRequestID := display(response.ApprovalRequestID)
		if noWait {
			certNotice(cmd, fmt.Sprintf("The revocation of certificate %s is waiting for approval (approval request %s). Follow it under Approval Requests in Certificate Manager, and check the certificate with: %s certificates get %s%s%s", certificateID, approvalRequestID, certManagerPrefix, util.SuggestedValue(certificateID, "certificate-id"), applicationFlag(application.Name), instanceFlags(cmd)))
		} else {
			revokedAt, err := waitForRevocation(cmd, client, certificateID, approvalRequestID, application.Name, timeout)
			if err != nil {
				exitCertError(cmd, err)
			}
			result.Status, result.RevokedAt = string(api.CertificateStatusRevoked), revokedAt
		}
	}

	if result.CrlWarning != nil {
		util.PrintWarning(util.SanitizeDisplay(*result.CrlWarning))
	}
	if outputFormat != "" {
		printFormattedOutput(outputFormat, result)
	} else {
		visualize.GenericTable([]string{"CERTIFICATE ID", "SERIAL NUMBER", "STATUS", "APPROVAL REQUEST ID"},
			[][]string{{certificateID, util.SanitizeDisplay(result.SerialNumber), result.Status, display(result.ApprovalRequestID)}})
	}
}

// revocationApprovalOutcome reads one check of a revocation's approval request: whether it's approved,
// or the error that ends the wait.
func revocationApprovalOutcome(approval api.ApprovalRequestStatus, certificateID, approvalRequestID string, now time.Time) (bool, error) {
	status := approval.Status
	// Expiry is applied lazily, so a request can still read pending after it has expired.
	if status == "pending" && approval.ExpiresAt != nil && now.After(*approval.ExpiresAt) {
		status = "expired"
	}
	switch {
	case status == "rejected" || status == "expired" || status == "cancelled":
		return false, errCertificateRevocationRejected(certificateID, approvalRequestID, status)
	case status == "approved":
		return true, nil
	case approval.ApproversCanNoLongerApprove:
		return false, errCertificateRevocationUndecidable(certificateID, approvalRequestID)
	}
	return false, nil
}

// waitForRevocation polls the approval request of a pending revocation until it's decided or the
// timeout passes, and returns when the certificate was revoked. An error ends the wait.
func waitForRevocation(cmd *cobra.Command, client *resty.Client, certificateID, approvalRequestID, application string, timeout time.Duration) (*string, error) {
	certNotice(cmd, fmt.Sprintf("The revocation of certificate %s needs approval (approval request %s); the certificate isn't revoked until it's approved. Waiting up to %s...", certificateID, approvalRequestID, timeout))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var revokedAt *string
	var lastErr error
	approved := false
	revoked, err := pollUntil(ctx, func() (bool, error) {
		if !approved {
			approval, err := api.CallGetCertificateRevocationApproval(ctx, client, approvalRequestID)
			if err != nil {
				if err := pollFailure(ctx, err, &lastErr); err != nil {
					return false, withContext(classifyAPIError(err, errorScope{}, nil), fmt.Sprintf("Unable to check approval request %s for the revocation of certificate %s", approvalRequestID, certificateID))
				}
				return false, nil
			}
			lastErr = nil
			if approved, err = revocationApprovalOutcome(approval, certificateID, approvalRequestID, time.Now()); !approved {
				return false, err
			}
		}
		// The certificate is revoked once the approval is applied, which can trail the decision.
		certificate, err := api.CallRetrieveCertificate(ctx, client, certificateID)
		if err != nil {
			if err := pollFailure(ctx, err, &lastErr); err != nil {
				return false, withContext(classifyAPIError(err, errorScope{}, nil), fmt.Sprintf("Approval request %s for the revocation of certificate %s was approved, but the certificate couldn't be read", approvalRequestID, certificateID))
			}
			return false, nil
		}
		lastErr = nil
		if certificate.Certificate.Status != string(api.CertificateStatusRevoked) {
			return false, nil
		}
		if certificate.Certificate.RevokedAt != nil {
			revokedAt = rfc3339(*certificate.Certificate.RevokedAt)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !revoked {
		return nil, errCertificateRevocationPending(certificateID, approvalRequestID, application, instanceFlags(cmd), approved, waitDetail("", lastErr))
	}
	return revokedAt, nil
}

func runCertRequestsGet(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "certificate requests")
	applicationName, invalid := certApplicationFlag(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	if len(args) == 0 {
		rejectFlagsWithoutID(cmd, slices.Concat(certFileFlags, []string{"wait", "timeout", "remove-roots-from-chain"}),
			"needs a request ID: pass the ID of the certificate request to pick up")
		listCertificateRequests(cmd, applicationName, outputFormat)
		return
	}

	requestID, ok := pkiID(args[0])
	if !ok {
		exitCertError(cmd, errNotAnID("certificate request", args[0]))
	}
	if cmd.Flags().Changed("status") {
		exitCertError(cmd, errInvalidFlag("status", "only filters the list: leave out the request ID, or this flag"))
	}
	wait, _ := cmd.Flags().GetBool("wait")
	if cmd.Flags().Changed("timeout") && !wait {
		exitCertError(cmd, errInvalidFlag("timeout", "only applies with --wait: pass --wait too, or leave out --timeout"))
	}
	timeout, _, invalid := readWaitFlags(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	files, invalid := readCertOutputFiles(cmd)
	if invalid != nil {
		exitCertError(cmd, invalid)
	}

	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	request, err := api.CallGetCertificateRequest(context.Background(), client, requestID)
	if err != nil {
		exitCertError(cmd, classifyAPIError(err, errorScope{}, func(cause error) *util.CLIError {
			return errCertificateRequestNotFound(requestID, application.Name, cause)
		}), "Unable to get the certificate request")
	}
	if request.ApplicationID == nil {
		exitCertError(cmd, errCertificateRequestWithoutApplication(requestID, application.Name))
	}
	if *request.ApplicationID != application.ID {
		exitCertError(cmd, errCertificateRequestNotFound(requestID, application.Name, nil))
	}
	removeRoot, _ := cmd.Flags().GetBool("remove-roots-from-chain")
	pickupFlags := issuanceOptions{files: files, removeRoot: removeRoot}.pickupFlags(cmd)
	var lastErr error
	if wait && isPendingRequestStatus(request.Status) {
		request, lastErr, err = waitForCertificateRequest(cmd, client, request, requestID, timeout)
		if err != nil {
			exitWithPickup(cmd, err, requestID, application.Name, pickupFlags, "Unable to check the request")
		}
	}

	result := certificateRequestDetails{
		CertificateRequestID: requestID,
		ApplicationID:        request.ApplicationID,
		ApplicationName:      request.ApplicationName,
		Status:               request.Status,
		ProfileName:          request.ProfileName,
		CommonName:           optional(request.CommonName),
		CertificateID:        request.CertificateID,
		Message:              optional(cmp.Or(errorMessage(request), pendingMessage(request))),
		CreatedAt:            rfc3339(request.CreatedAt),
		UpdatedAt:            rfc3339(request.UpdatedAt),
	}
	captureCertEvent("certificates requests get", posthog.NewProperties().Set("status", request.Status))

	if request.Status != api.CertificateRequestStatusIssued {
		printCertificateRequest(outputFormat, result)
		if isPendingRequestStatus(request.Status) {
			exitCertError(cmd, errCertificateRequestPending(requestID, request.Status, application.Name, pickupFlags, waitDetail(pendingMessage(request), lastErr)))
		}
		exitCertError(cmd, errCertificateRequestRejected(requestID, request.Status, errorMessage(request), "issue"))
	}

	bundle := requestBundle(cmd, client, request, application.Name, requestID, pickupFlags, files.wantsKey())
	if removeRoot {
		bundle.CertificateChain = withoutRootCertificates(bundle.CertificateChain)
	}
	requireMaterial(cmd, files, bundle)
	written := writeCertificateFiles(cmd, files, bundle, certificateRequestPickup(requestID, application.Name, pickupFlags))
	result.SerialNumber = request.SerialNumber
	result.Certificate, result.CertificateChain = optional(bundle.Certificate), optional(bundle.CertificateChain)
	fillFromLeaf(bundle.Certificate, &result.CommonName, &result.NotBefore, &result.NotAfter)
	if files.IncludeKey {
		result.PrivateKey = optional(bundle.PrivateKey)
	}
	printCertificateRequest(outputFormat, result)
	printCertificateOutput(cmd, files, bundle, outputFormat, written)
}

type certificateRequestDetails struct {
	CertificateRequestID string  `json:"certificateRequestId"`
	ApplicationID        *string `json:"applicationId"`
	ApplicationName      *string `json:"applicationName"`
	Status               string  `json:"status"`
	ProfileName          *string `json:"profileName"`
	CommonName           *string `json:"commonName"`
	CertificateID        *string `json:"certificateId"`
	Message              *string `json:"message"`
	CreatedAt            *string `json:"createdAt"`
	UpdatedAt            *string `json:"updatedAt"`
	SerialNumber         *string `json:"serialNumber,omitempty"`
	NotBefore            *string `json:"notBefore,omitempty"`
	NotAfter             *string `json:"notAfter,omitempty"`
	Certificate          *string `json:"certificate,omitempty"`
	CertificateChain     *string `json:"certificateChain,omitempty"`
	PrivateKey           *string `json:"privateKey,omitempty"`
}

func printCertificateRequest(outputFormat string, result certificateRequestDetails) {
	if outputFormat != "" {
		printFormattedOutput(outputFormat, result)
		return
	}
	visualize.GenericTable([]string{"REQUEST ID", "STATUS", "COMMON NAME", "PROFILE", "CERTIFICATE ID", "MESSAGE"},
		[][]string{{result.CertificateRequestID, result.Status, display(result.CommonName), display(result.ProfileName), display(result.CertificateID), display(result.Message)}})
}

func listCertificateRequests(cmd *cobra.Command, applicationName, outputFormat string) {
	status, invalid := optionalFlag(cmd, "status")
	if invalid != nil {
		exitCertError(cmd, invalid)
	}
	if status != "" {
		if invalid := validateChoices("status", []string{status}, certRequestStatuses); invalid != nil {
			exitCertError(cmd, invalid)
		}
	}
	client := certHTTPClient(cmd)
	application := resolveCertApplication(cmd, client, applicationName)
	request := api.SearchCertificateRequestsRequest{ApplicationID: application.ID, Status: status, SortBy: "createdAt", SortOrder: "desc", Limit: certListPageSize}

	requests, err := collectPages(func(offset int) ([]api.CertificateRequestSearchResult, int, error) {
		request.Offset = offset
		page, err := api.CallSearchCertificateRequests(client, request)
		return page.CertificateRequests, page.TotalCount, err
	})
	if err != nil {
		exitCertError(cmd, classifyAPIError(err, errorScope{}, nil), "Unable to list the certificate requests")
	}

	type requestItem struct {
		CertificateRequestID string  `json:"certificateRequestId"`
		Status               string  `json:"status"`
		CommonName           *string `json:"commonName"`
		ProfileName          *string `json:"profileName"`
		CertificateID        *string `json:"certificateId"`
		CreatedAt            *string `json:"createdAt"`
	}
	items := make([]requestItem, 0, len(requests))
	rows := make([][]string, 0, len(requests))
	for _, r := range requests {
		item := requestItem{r.ID, r.Status, r.CommonName, r.ProfileName, r.CertificateID, rfc3339(r.CreatedAt)}
		items = append(items, item)
		rows = append(rows, []string{util.SanitizeDisplay(r.ID), util.SanitizeDisplay(r.Status), display(r.CommonName), display(r.ProfileName), display(r.CertificateID), display(item.CreatedAt)})
	}
	switch {
	case outputFormat != "":
		printFormattedOutput(outputFormat, items)
	case len(items) == 0:
		printProjectsTip(cmd, fmt.Sprintf("No certificate requests found in application %s.", util.SanitizeDisplay(application.Name)))
	default:
		visualize.GenericTable([]string{"REQUEST ID", "STATUS", "COMMON NAME", "PROFILE", "CERTIFICATE ID", "CREATED AT"}, rows)
	}
	captureCertEvent("certificates requests get", posthog.NewProperties().Set("requestCount", len(items)))
}
