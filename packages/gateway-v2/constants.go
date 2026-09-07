package gatewayv2

import "time"

const (
	KUBERNETES_SERVICE_HOST_ENV_NAME              = "KUBERNETES_SERVICE_HOST"
	KUBERNETES_SERVICE_PORT_HTTPS_ENV_NAME        = "KUBERNETES_SERVICE_PORT_HTTPS"
	KUBERNETES_SERVICE_ACCOUNT_CA_CERT_PATH       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH         = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	INFISICAL_PAM_SESSION_RECORDING_PATH_ENV_NAME = "INFISICAL_PAM_SESSION_RECORDING_PATH"
	INFISICAL_PKCS11_MODULE_ENV_NAME              = "INFISICAL_PKCS11_MODULE"

	RELAY_NAME_ENV_NAME     = "INFISICAL_RELAY_NAME"
	LISTEN_ADDRESS_ENV_NAME = "INFISICAL_GATEWAY_LISTEN_ADDRESS"
	BIND_ADDRESS_ENV_NAME   = "INFISICAL_GATEWAY_BIND_ADDRESS"
	RELAY_HOST_ENV_NAME     = "INFISICAL_RELAY_HOST"
	RELAY_TYPE_ENV_NAME     = "INFISICAL_RELAY_TYPE"
	GATEWAY_NAME_ENV_NAME   = "INFISICAL_GATEWAY_NAME"

	RELAY_AUTH_SECRET_ENV_NAME = "INFISICAL_RELAY_AUTH_SECRET"
	INFISICAL_TOKEN_ENV_NAME   = "INFISICAL_TOKEN"

	INFISICAL_HTTP_PROXY_ACTION_HEADER = "x-infisical-action"

	// A direct gateway accepts connections from anyone who can route to it, so an unauthenticated
	// peer must not be able to tie up a slot indefinitely. The handshake budget bounds one
	// connection; the in-flight cap bounds how many can be mid-handshake at once, which is what
	// keeps file descriptors and goroutines from being exhausted by peers that never finish.
	directHandshakeTimeout     = 10 * time.Second
	maxPendingDirectHandshakes = 256

	// Gateway auth-method discriminators. Used both for matching the user's --enroll-method
	// flag value and as the `method` field on the /v3/gateways/login request body.
	EnrollMethodAws        = "aws"
	EnrollMethodKubernetes = "kubernetes"
	EnrollMethodToken      = "token"
)

type HttpProxyAction string

const (
	HttpProxyActionInjectGatewayK8sServiceAccountToken HttpProxyAction = "inject-k8s-sa-auth-token"
	HttpProxyActionUseGatewayK8sServiceAccount         HttpProxyAction = "use-k8s-sa"
)
