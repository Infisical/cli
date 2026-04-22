package oracle

// ProxyPasswordPlaceholder is the fixed password string clients must present to the
// gateway's client-facing O5Logon. Real authentication happens upstream with the real
// credentials injected by the gateway. The placeholder is not a secret — security is
// enforced by the mTLS tunnel between CLI, backend and gateway, and by session-scoped
// client certs. Oracle's O5Logon cannot be bypassed the way MySQL/Postgres auth can,
// so the gateway and the client must agree on some shared string; this is it.
const ProxyPasswordPlaceholder = "password"
