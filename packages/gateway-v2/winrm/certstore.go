package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/gateway-v2/certscan"
)

// Store names are interpolated into the script, so only these are allowed.
var allowedCertificateStores = map[string]bool{
	"My":             true,
	"WebHosting":     true,
	"CA":             true,
	"Root":           true,
	"Remote Desktop": true,
}

var issuerStores = []string{"CA", "Root"}

const (
	storeRecordMarker = '\x1e'
	// WinRM re-encodes stdout on the wire, so this must stay well under maxWinRMReadBytes per connection.
	storeScanOutputBudget  = 14 * 1024 * 1024
	maxStoreScanOutputSize = 16 * 1024 * 1024
	maxIssuerRecords       = 2000
	storeScanTimeout       = 90 * time.Second
)

type StoreScanResult struct {
	Hostname               string
	Records                []certscan.StoreCertificate
	DeniedStores           []string
	UnreadableIssuerStores []string
	TruncatedIssuerStores  []string
	HitLimit               bool
	OverBudget             bool
	Truncated              bool
	TimedOut               bool
	Diagnostic             string
}

func IsAllowedCertificateStore(name string) bool {
	return allowedCertificateStores[name]
}

// Marked lines keep profile banners out of the data; requested issuer stores are re-listed by reference (R).
const storeScanScriptTemplate = `$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$m = [string][char]0x1E
$t = [string][char]0x09
[Console]::Out.WriteLine($m + 'H' + $t + [System.Net.Dns]::GetHostName())
$requested = @(%[1]s)
$issuers = @(%[2]s)
$max = %[3]d
$maxIssuers = %[4]d
$budget = %[5]d
$written = 0
$issuerCount = 0
$read = @{}
$unreadable = @{}
$cut = @{}
foreach ($name in $issuers) {
  $isRequested = $requested -contains $name
  if (-not (Test-Path -LiteralPath ('Cert:\LocalMachine\' + $name))) { continue }
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
  try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
  } catch {
    $unreadable[$name] = $true
    if (-not $isRequested) { [Console]::Out.WriteLine($m + 'I' + $t + $name) }
    continue
  }
  $entries = New-Object System.Collections.Generic.List[object]
  $seen = New-Object System.Collections.Generic.HashSet[string]
  try {
    foreach ($c in $store.Certificates) {
      if (-not $seen.Add($c.Thumbprint)) { continue }
      if ($isRequested -and $written -ge $budget) { $cut[$name] = $true; break }
      if (-not $isRequested -or $entries.Count -ge $max) {
        if ($issuerCount -ge $maxIssuers) {
          if ($isRequested) { $cut[$name] = $true } else { [Console]::Out.WriteLine($m + 'J' + $t + $name) }
          break
        }
        $issuerCount++
      }
      $line = $m + 'C' + $t + $name + $t + $c.Thumbprint + $t + [int]$c.HasPrivateKey + $t + '0' + $t + [Convert]::ToBase64String($c.RawData)
      [Console]::Out.WriteLine($line)
      $written += $line.Length + 2
      $entries.Add(@($c.Thumbprint, [int]$c.HasPrivateKey))
    }
  } finally {
    $store.Close()
  }
  $read[$name] = $entries
}
$count = 0
$stop = $false
$full = $false
foreach ($name in $requested) {
  if ($stop) { break }
  if ($unreadable.ContainsKey($name)) { [Console]::Out.WriteLine($m + 'D' + $t + $name); continue }
  if ($read.ContainsKey($name)) {
    foreach ($e in $read[$name]) {
      if ($count -ge $max) { [Console]::Out.WriteLine($m + 'L'); $stop = $true; break }
      [Console]::Out.WriteLine($m + 'R' + $t + $name + $t + $e[0] + $t + $e[1])
      $count++
    }
    if (-not $stop -and $cut.ContainsKey($name)) {
      if ($written -ge $budget) { [Console]::Out.WriteLine($m + 'B'); $full = $true } else { [Console]::Out.WriteLine($m + 'L'); $stop = $true }
    }
    continue
  }
  if ($full) { continue }
  if (-not (Test-Path -LiteralPath ('Cert:\LocalMachine\' + $name))) { continue }
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
  try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
  } catch {
    [Console]::Out.WriteLine($m + 'D' + $t + $name)
    continue
  }
  $seen = New-Object System.Collections.Generic.HashSet[string]
  try {
    foreach ($c in $store.Certificates) {
      if (-not $seen.Add($c.Thumbprint)) { continue }
      if ($count -ge $max) { [Console]::Out.WriteLine($m + 'L'); $stop = $true; break }
      if ($written -ge $budget) { [Console]::Out.WriteLine($m + 'B'); $full = $true; break }
      $line = $m + 'C' + $t + $name + $t + $c.Thumbprint + $t + [int]$c.HasPrivateKey + $t + '1' + $t + [Convert]::ToBase64String($c.RawData)
      [Console]::Out.WriteLine($line)
      $written += $line.Length + 2
      $count++
    }
  } finally {
    $store.Close()
  }
}
[Console]::Out.WriteLine($m + 'Z')
`

func powerShellStringList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, "'"+escapePowerShellSingleQuotes(v)+"'")
	}
	return strings.Join(quoted, ", ")
}

func buildStoreScanScript(requested []string, maxRequested int) (string, error) {
	if len(requested) == 0 {
		return "", errors.New("at least one certificate store is required")
	}
	if maxRequested <= 0 {
		return "", errors.New("the certificate limit must be positive")
	}
	seen := map[string]bool{}
	var unique []string
	for _, name := range requested {
		if !IsAllowedCertificateStore(name) {
			return "", fmt.Errorf("unsupported certificate store %q", name)
		}
		if !seen[name] {
			seen[name] = true
			unique = append(unique, name)
		}
	}
	return fmt.Sprintf(
		storeScanScriptTemplate,
		powerShellStringList(unique),
		powerShellStringList(issuerStores),
		maxRequested,
		maxIssuerRecords,
		storeScanOutputBudget,
	), nil
}

// parseStoreScanOutput drops the last line when stdout was cut, since it is partial.
func parseStoreScanOutput(stdout []byte, maxRequested int, cut bool) StoreScanResult {
	var result StoreScanResult
	complete := false
	requested := 0
	index := map[string]int{}
	lines := bytes.Split(stdout, []byte{'\n'})
	if cut && len(lines) > 0 {
		lines = lines[:len(lines)-1]
	}
	markRequested := func(i int) {
		if requested >= maxRequested {
			result.HitLimit = true
			return
		}
		requested++
		result.Records[i].Requested = true
	}
	for _, raw := range lines {
		start := bytes.IndexByte(raw, storeRecordMarker)
		if start < 0 {
			continue
		}
		line := strings.TrimRight(string(raw[start+1:]), "\r")
		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "H":
			if len(fields) == 2 {
				result.Hostname = strings.TrimSpace(fields[1])
			}
		case "D":
			if len(fields) == 2 && IsAllowedCertificateStore(fields[1]) {
				result.DeniedStores = append(result.DeniedStores, fields[1])
			}
		case "I":
			if len(fields) == 2 && IsAllowedCertificateStore(fields[1]) {
				result.UnreadableIssuerStores = append(result.UnreadableIssuerStores, fields[1])
			}
		case "J":
			if len(fields) == 2 && IsAllowedCertificateStore(fields[1]) {
				result.TruncatedIssuerStores = append(result.TruncatedIssuerStores, fields[1])
			}
		case "C":
			record, ok := parseStoreRecord(fields)
			if !ok {
				continue
			}
			key := record.Store + "\x00" + record.Thumbprint
			if _, dup := index[key]; dup {
				continue
			}
			wantRequested := record.Requested
			record.Requested = false
			index[key] = len(result.Records)
			result.Records = append(result.Records, record)
			if wantRequested {
				markRequested(index[key])
			}
		case "R":
			if len(fields) != 4 {
				continue
			}
			if i, ok := index[fields[1]+"\x00"+strings.ToUpper(strings.TrimSpace(fields[2]))]; ok && !result.Records[i].Requested {
				markRequested(i)
			}
		case "L":
			result.HitLimit = true
		case "B":
			result.OverBudget = true
		case "Z":
			complete = true
		}
	}
	if !complete {
		result.Truncated = true
	}
	return result
}

func parseStoreRecord(fields []string) (certscan.StoreCertificate, bool) {
	if len(fields) != 6 || !IsAllowedCertificateStore(fields[1]) {
		return certscan.StoreCertificate{}, false
	}
	thumbprint := strings.ToUpper(strings.TrimSpace(fields[2]))
	if !isThumbprint(thumbprint) {
		return certscan.StoreCertificate{}, false
	}
	der, err := base64.StdEncoding.DecodeString(fields[5])
	if err != nil || len(der) == 0 {
		return certscan.StoreCertificate{}, false
	}
	requested, _ := strconv.Atoi(fields[4])
	return certscan.StoreCertificate{
		Store:         fields[1],
		Thumbprint:    thumbprint,
		HasPrivateKey: fields[3] == "1",
		Requested:     requested == 1,
		DER:           der,
	}, true
}

func isThumbprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// ScanCertificateStores exports public certificates only; private keys never leave the host.
func ScanCertificateStores(ctx context.Context, creds Credentials, stores []string, maxRequested int) (StoreScanResult, error) {
	script, err := buildStoreScanScript(stores, maxRequested)
	if err != nil {
		return StoreScanResult{}, err
	}
	run, err := runScript(ctx, creds, script, storeScanTimeout, maxStoreScanOutputSize)
	if err != nil {
		return StoreScanResult{}, err
	}

	cut := run.stdoutWriter.truncated || run.timedOut
	result := parseStoreScanOutput(run.stdout.Bytes(), maxRequested, cut)
	if result.Hostname == "" && len(result.Records) == 0 {
		if run.timedOut {
			return StoreScanResult{}, fmt.Errorf("reading the certificate stores timed out after %s", storeScanTimeout)
		}
		msg := strings.TrimSpace(normalizePowerShellStderr(run.stderr.String()))
		if msg == "" {
			msg = "PowerShell returned no output"
		}
		return StoreScanResult{}, fmt.Errorf("failed to read the certificate stores: %s", truncate(msg, 300))
	}
	result.TimedOut = run.timedOut
	if cut {
		result.Truncated = true
	}
	if result.Truncated {
		result.Diagnostic = truncate(strings.TrimSpace(normalizePowerShellStderr(run.stderr.String())), 300)
	}
	return result, nil
}
