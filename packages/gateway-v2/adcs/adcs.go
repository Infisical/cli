// Package adcs implements a Microsoft AD CS client that speaks the native
// Windows Client Certificate Enrollment Protocol (MS-WCCE) over DCOM/RPC.
//
// It is used by the gateway to discover certificate templates, read the CA
// chain, and enroll certificates on behalf of the Infisical control plane,
// which sits outside the customer network and cannot speak DCOM directly.
//
// The connection is authenticated with the supplied Windows credentials and
// sealed with RPC packet privacy (encryption + integrity), so no TLS or server
// certificate is involved. Only the ICertRequestD2 interface is bound: binding
// the older ICertRequestD first makes D2 calls resolve to the wrong interface
// and fail with RPC_S_UNKNOWN_IF.
package adcs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode/utf16"

	config "github.com/oiweiwei/go-msrpc/config"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	iactivation "github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	iobjectexporter "github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	icertrequestd2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/icertrequestd2/v0"
	winreg "github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"

	"go.mozilla.org/pkcs7"
)

// clsidCertRequestD is the CLSID of the CertSrv Request DCOM class
// (CCertRequestD), MS-WCCE section 1.9.
var clsidCertRequestD = uuid.MustParse("d99e6e74-fc88-11d0-b498-00a0c90312f3")

const (
	crPropCASigCertChain = 0x0000000D
	crPropTemplates      = 0x0000001D

	propTypeBinary = 0x00000003
	propTypeString = 0x00000004

	// dwFlags for a binary DER PKCS#10 request.
	crInBinary = 0x00000002
	crInPKCS10 = 0x00000100

	// CR_DISP_ISSUED: the request was issued.
	dispositionIssued = 3
)

// Credentials identifies and authenticates to the CA host.
type Credentials struct {
	Host     string // CA server FQDN (or IP)
	Username string // DOMAIN\user or user@domain
	Password string
}

// Template is a certificate template published on the CA.
type Template struct {
	Name string `json:"name"`
}

// EnrollResult is the outcome of a certificate request.
type EnrollResult struct {
	Disposition        uint32 `json:"disposition"`
	RequestID          uint32 `json:"requestId"`
	CertificatePem     string `json:"certificatePem"`
	ChainPem           string `json:"chainPem"`
	DispositionMessage string `json:"dispositionMessage,omitempty"`
	HResult            int32  `json:"hresult,omitempty"`
}

// Client is an authenticated ICertRequestD2 session against one CA host.
type Client struct {
	d2   icertrequestd2.CertRequestD2Client
	this *dcom.ORPCThis
	top  dcerpc.Conn
	dyn  dcerpc.Conn
}

// Dial establishes an authenticated MS-WCCE session over DCOM.
func Dial(ctx context.Context, creds Credentials) (*Client, error) {
	cfg := config.New()
	cfg.Server = "ncacn_ip_tcp:" + creds.Host // ServerAddr() returns this when Protocol is empty
	cfg.Auth.Level = "privacy"                // RPC packet privacy: seals and integrity-protects the channel
	cfg.Username = creds.Username             // credential pkg parses DOMAIN\user or user@domain
	cfg.Credential.Password = creds.Password

	sctx := gssapi.NewSecurityContext(ctx)

	top, err := dcerpc.Dial(sctx, cfg.ServerAddr(), cfg.DialOptions(sctx)...)
	if err != nil {
		return nil, fmt.Errorf("dial CA endpoint mapper (port 135): %w", err)
	}

	oxc, err := iobjectexporter.NewObjectExporterClient(sctx, top, cfg.ClientOptions(sctx)...)
	if err != nil {
		_ = top.Close(sctx)
		return nil, fmt.Errorf("create object exporter client: %w", err)
	}
	srv, err := oxc.ServerAlive2(sctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		_ = top.Close(sctx)
		return nil, fmt.Errorf("authenticate to CA (check host and credentials): %w", err)
	}

	iact, err := iactivation.NewActivationClient(sctx, top, cfg.ClientOptions(sctx)...)
	if err != nil {
		_ = top.Close(sctx)
		return nil, fmt.Errorf("create activation client: %w", err)
	}
	act, err := iact.RemoteActivation(sctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    dtyp.GUIDFromUUID(clsidCertRequestD),
		IIDs:                       []*dcom.IID{icertrequestd2.CertRequestD2IID},
		RequestedProtocolSequences: []uint16{7}, // ncacn_ip_tcp
	})
	if err != nil {
		_ = top.Close(sctx)
		return nil, fmt.Errorf("activate certificate service: %w", err)
	}
	if act.HResult != 0 {
		_ = top.Close(sctx)
		return nil, fmt.Errorf("activate certificate service: %s", hresult.FromCode(uint32(act.HResult)))
	}

	dyn, err := dcerpc.Dial(sctx, cfg.ServerAddr(),
		append(cfg.DialOptions(sctx), act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)...)
	if err != nil {
		_ = top.Close(sctx)
		return nil, fmt.Errorf("dial certificate service endpoint: %w", err)
	}

	// Fresh GSSAPI security context for the second physical connection (the dynamic
	// endpoint): the activation connection's context can't be reused across the new dial.
	bctx := gssapi.NewSecurityContext(sctx)
	// Bind ONLY the ICertRequestD2 syntax so the default presentation context is D2.
	d2conn, err := dyn.Bind(bctx, append(cfg.ClientOptions(bctx),
		dcerpc.WithAbstractSyntax(icertrequestd2.CertRequestD2SyntaxV0_0))...)
	if err != nil {
		_ = dyn.Close(sctx)
		_ = top.Close(sctx)
		return nil, fmt.Errorf("bind ICertRequestD2: %w", err)
	}
	d2, err := icertrequestd2.NewCertRequestD2Client(bctx, d2conn, dcerpc.WithNoBind(d2conn))
	if err != nil {
		_ = dyn.Close(sctx)
		_ = top.Close(sctx)
		return nil, fmt.Errorf("create ICertRequestD2 client: %w", err)
	}
	if len(act.InterfaceData) == 0 {
		_ = dyn.Close(sctx)
		_ = top.Close(sctx)
		return nil, fmt.Errorf("activation returned no interface data")
	}
	d2 = d2.IPID(bctx, act.InterfaceData[0].IPID())

	return &Client{d2: d2, this: &dcom.ORPCThis{Version: srv.COMVersion}, top: top, dyn: dyn}, nil
}

// Close releases the underlying connections.
func (c *Client) Close(ctx context.Context) {
	if c.dyn != nil {
		_ = c.dyn.Close(ctx)
	}
	if c.top != nil {
		_ = c.top.Close(ctx)
	}
}

// Ping verifies the certificate service is answering. It needs no CA name, so
// it validates that the host is reachable and the credentials are accepted.
func (c *Client) Ping(ctx context.Context) error {
	if _, err := c.d2.Ping2(ctx, &icertrequestd2.Ping2Request{This: c.this}); err != nil {
		return fmt.Errorf("ping certificate service: %w", err)
	}
	return nil
}

func (c *Client) getStringProperty(ctx context.Context, caName string, propID int32) (string, error) {
	resp, err := c.d2.GetCAProperty(ctx, &icertrequestd2.GetCAPropertyRequest{
		This: c.this, Authority: caName, PropertyID: propID, PropertyType: propTypeString,
	})
	if err != nil {
		return "", err
	}
	// The CA reports a rejected request (e.g. wrong authority name) via a non-zero Return
	// HRESULT rather than a transport error, leaving PropertyValue undefined.
	if resp.Return != 0 {
		return "", fmt.Errorf("read CA property: %s", hresult.FromCode(uint32(resp.Return)))
	}
	if resp.PropertyValue == nil {
		return "", fmt.Errorf("read CA property: empty response")
	}
	return utf16le(resp.PropertyValue.Buffer), nil
}

func (c *Client) getChainPem(ctx context.Context, caName string) (string, error) {
	resp, err := c.d2.GetCAProperty(ctx, &icertrequestd2.GetCAPropertyRequest{
		This: c.this, Authority: caName, PropertyID: crPropCASigCertChain, PropertyType: propTypeBinary,
	})
	if err != nil {
		return "", fmt.Errorf("read CA chain: %w", err)
	}
	if resp.Return != 0 {
		return "", fmt.Errorf("read CA chain: %s", hresult.FromCode(uint32(resp.Return)))
	}
	if resp.PropertyValue == nil {
		return "", fmt.Errorf("read CA chain: empty response")
	}
	return pkcs7ToPem(resp.PropertyValue.Buffer)
}

// Templates lists the certificate templates published on the CA.
func (c *Client) Templates(ctx context.Context, caName string) ([]Template, error) {
	raw, err := c.getStringProperty(ctx, caName, crPropTemplates)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	// CR_PROP_TEMPLATES returns "name\noid\nname\noid\n..." pairs; only the name is needed.
	parts := strings.Split(strings.Trim(raw, "\n"), "\n")
	var out []Template
	for i := 0; i+1 < len(parts); i += 2 {
		out = append(out, Template{Name: parts[i]})
	}
	return out, nil
}

// Enroll submits a DER-encoded PKCS#10 CSR against the named template and
// returns the issued certificate and CA chain.
func (c *Client) Enroll(ctx context.Context, caName, template string, csrDER []byte) (*EnrollResult, error) {
	resp, err := c.d2.Request2(ctx, &icertrequestd2.Request2Request{
		This:       c.this,
		Authority:  caName,
		Flags:      crInBinary | crInPKCS10,
		Attributes: "CertificateTemplate:" + template,
		Request:    &wcce.CertTransportBlob{Length: uint32(len(csrDER)), Buffer: csrDER},
	})
	if err != nil {
		return nil, fmt.Errorf("submit certificate request: %w", err)
	}

	result := &EnrollResult{Disposition: resp.Disposition, RequestID: resp.RequestID, HResult: resp.Return}
	if resp.DispositionMessage != nil {
		result.DispositionMessage = utf16le(resp.DispositionMessage.Buffer)
	}
	if resp.Disposition != dispositionIssued || resp.EncodedCert == nil || len(resp.EncodedCert.Buffer) == 0 {
		return result, nil
	}

	certPem, err := issuedCertToPem(resp.EncodedCert.Buffer)
	if err != nil {
		return nil, err
	}
	result.CertificatePem = certPem

	chain, err := c.getChainPem(ctx, caName)
	if err != nil {
		return nil, err
	}
	result.ChainPem = chain
	return result, nil
}

// issuedCertToPem accepts either a bare DER certificate or a PKCS#7 bundle and
// returns the leaf certificate as PEM.
func issuedCertToPem(b []byte) (string, error) {
	if cert, err := x509.ParseCertificate(b); err == nil {
		return string(certToPem(cert)), nil
	}
	p7, err := pkcs7.Parse(b)
	if err != nil {
		return "", fmt.Errorf("parse issued certificate: %w", err)
	}
	if len(p7.Certificates) == 0 {
		return "", fmt.Errorf("issued certificate response contained no certificates")
	}
	for _, cert := range p7.Certificates {
		if !cert.IsCA {
			return string(certToPem(cert)), nil
		}
	}
	return string(certToPem(p7.Certificates[0])), nil
}

// pkcs7ToPem converts a PKCS#7 (CERTTRANSBLOB) chain into concatenated PEM certs.
func pkcs7ToPem(der []byte) (string, error) {
	if len(der) == 0 {
		return "", nil
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return "", fmt.Errorf("parse PKCS#7 chain: %w", err)
	}
	var sb strings.Builder
	for _, cert := range p7.Certificates {
		sb.Write(certToPem(cert))
	}
	return sb.String(), nil
}

func certToPem(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// certSvcActiveValuePath is the registry key holding the active CA's sanitized
// name in its "Active" value. MS-WCCE offers no way to enumerate the CA name
// (every call requires it as input), so we read it from the registry over
// MS-RRP. Requires the Remote Registry service to be running on the CA host.
const certSvcActiveValuePath = `SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`

// DiscoverCAName reads the active CA name from the host's registry over MS-RRP,
// using the same host and credentials as the WCCE path.
func DiscoverCAName(ctx context.Context, creds Credentials) (string, error) {
	// The Remote Registry service (winreg) is exposed over named pipes (SMB), not
	// the TCP endpoint mapper, so use ncacn_np and skip EPM. SMB supports only the
	// insecure or seal (privacy) RPC security levels.
	cfg := config.New().DisableEPM()
	cfg.Protocol = "ncacn_np"
	cfg.ServerAddress = creds.Host
	cfg.Auth.Level = "privacy"
	cfg.Username = creds.Username
	cfg.Credential.Password = creds.Password

	sctx := gssapi.NewSecurityContext(ctx)
	cc, err := dcerpc.Dial(sctx, cfg.ServerAddr(), cfg.DialOptions(sctx)...)
	if err != nil {
		return "", fmt.Errorf("dial remote registry: %w", err)
	}
	defer func() { _ = cc.Close(sctx) }()

	cli, err := winreg.NewWinregClient(sctx, cc, cfg.ClientOptions(sctx)...)
	if err != nil {
		return "", fmt.Errorf("create winreg client (is the Remote Registry service running?): %w", err)
	}

	hklm, err := cli.OpenLocalMachine(sctx, &winreg.OpenLocalMachineRequest{DesiredAccess: winreg.KeyQueryValue})
	if err != nil {
		return "", fmt.Errorf("open HKLM: %w", err)
	}
	// winreg reports failures via a non-zero Return (Win32 error code), not a transport error.
	if hklm.Return != 0 {
		return "", fmt.Errorf("open HKLM: winreg error %d", hklm.Return)
	}

	sub, err := cli.BaseRegOpenKey(sctx, &winreg.BaseRegOpenKeyRequest{
		Key:           hklm.Key,
		SubKey:        &winreg.UnicodeString{Buffer: certSvcActiveValuePath + "\x00"},
		DesiredAccess: winreg.KeyQueryValue,
	})
	if err != nil {
		return "", fmt.Errorf("open CertSvc configuration key (is AD CS installed on this host?): %w", err)
	}
	if sub.Return != 0 {
		return "", fmt.Errorf("open CertSvc configuration key (is AD CS installed on this host?): winreg error %d", sub.Return)
	}

	const bufLen = 1024
	resp, err := cli.BaseRegQueryValue(sctx, &winreg.BaseRegQueryValueRequest{
		Key:        sub.ResultKey,
		ValueName:  &winreg.UnicodeString{Buffer: "Active\x00"},
		Data:       make([]byte, bufLen),
		DataLength: bufLen,
		Length:     bufLen,
	})
	if err != nil {
		return "", fmt.Errorf("read Active CA value: %w", err)
	}
	if resp.Return != 0 {
		return "", fmt.Errorf("read Active CA value: winreg error %d", resp.Return)
	}

	decoded, err := winreg.DecodeValue(resp.Type, resp.Data)
	if err != nil {
		return "", fmt.Errorf("decode Active CA value: %w", err)
	}
	name, ok := decoded.(string)
	if !ok || name == "" {
		return "", fmt.Errorf("no active CA name found on this host")
	}
	return name, nil
}

func utf16le(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}
