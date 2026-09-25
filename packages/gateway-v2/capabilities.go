package gatewayv2

// Declared at each heartbeat. The platform stores the map verbatim, so an absent key means the gateway is
// too old to report it, not that the capability is off.
const CapabilitySessionLogMaskingBuiltInDetection = "sessionLogMaskingBuiltInDetection"

const CapabilitySupportedAccountTypes = "supported_account_types"

// Reported separately from the account type, because a gateway can support ClickHouse accounts and still
// predate the native protocol. Without it the platform cannot tell the difference, and an account with a
// native port would save against an old gateway and then fail every native client at session time.
const CapabilityClickhouseNativeProtocol = "clickhouseNativeProtocol"
