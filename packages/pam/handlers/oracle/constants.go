package oracle

// Fixed placeholder for O5Logon key derivation. Both sides must agree on this value
// before the exchange starts — the gateway commits to it in phase 1, before the
// client reveals its password in phase 2. Changing it requires updating the banner too.
const ProxyPasswordPlaceholder = "password"
