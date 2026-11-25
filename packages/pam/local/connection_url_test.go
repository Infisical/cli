package pam

import (
	"net/url"
	"strings"
	"testing"
)

func TestConnectionURLsEscapeServerValues(t *testing.T) {
	database := "prod?host=db.example&hostaddr=203.0.113.10&port=5432&user=admin"
	username := "app@evil.example:5432/x"
	for _, accountType := range []string{AccountTypePostgres, AccountTypeMySQL, AccountTypeMsSQL, AccountTypeMongoDB, AccountTypeClickhouse, AccountTypeRedis} {
		display, ok := ConnectionDisplayFor(accountType)
		if !ok || display.ConnectionString == nil {
			continue
		}
		raw := display.ConnectionString(username, database, 5432)
		parsed, err := url.Parse(strings.TrimPrefix(raw, "jdbc:"))
		if err != nil {
			t.Fatalf("%s: %q doesn't parse: %v", accountType, raw, err)
		}
		if parsed.Hostname() != "127.0.0.1" || parsed.Port() != "5432" {
			t.Errorf("%s: %q points at %s", accountType, raw, parsed.Host)
		}
		for _, key := range []string{"host", "hostaddr", "user"} {
			if parsed.Query().Has(key) {
				t.Errorf("%s: %q gained query parameter %s", accountType, raw, key)
			}
		}
	}
}
