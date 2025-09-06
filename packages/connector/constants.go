package connector

const (
	KUBERNETES_SERVICE_HOST_ENV_NAME        = "KUBERNETES_SERVICE_HOST"
	KUBERNETES_SERVICE_PORT_HTTPS_ENV_NAME  = "KUBERNETES_SERVICE_PORT_HTTPS"
	KUBERNETES_SERVICE_ACCOUNT_CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH   = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	RELAY_NAME_ENV_NAME     = "INFISICAL_RELAY_NAME"
	CONNECTOR_NAME_ENV_NAME = "INFISICAL_CONNECTOR_NAME"

	RELAY_AUTH_SECRET_ENV_NAME = "INFISICAL_RELAY_AUTH_SECRET"

	INFISICAL_HTTP_PROXY_ACTION_HEADER = "x-infisical-action"
)

type HttpProxyAction string

const (
	HttpProxyActionInjectConnectorK8sServiceAccountToken HttpProxyAction = "inject-k8s-sa-auth-token"
	HttpProxyActionUseConnectorK8sServiceAccount         HttpProxyAction = "use-k8s-sa"
)
