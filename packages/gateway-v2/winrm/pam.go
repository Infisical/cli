package winrm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// normalizeJSONArray coerces ConvertTo-Json output (an object for a single item, an array for many,
// empty for none) into a JSON array so callers always parse a list.
func normalizeJSONArray(s string) json.RawMessage {
	s = strings.TrimSpace(s)
	if s == "" {
		return json.RawMessage("[]")
	}
	if strings.HasPrefix(s, "[") {
		return json.RawMessage(s)
	}
	return json.RawMessage("[" + s + "]")
}

// ErrorActionPreference=Stop so a Get-LocalUser failure is a hard error (matching the dependencies script)
// rather than a silent short list that reads as "this machine has fewer local accounts".
const enumerateAccountsScript = `$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; ` +
	`Get-LocalUser | Select-Object Name, Enabled, @{Name='SID';Expression={$_.SID.Value}} | ConvertTo-Json -Compress`

// EnumerateLocalAccounts lists the host's local user accounts as a JSON array.
func EnumerateLocalAccounts(ctx context.Context, creds Credentials) (json.RawMessage, error) {
	client, err := newClient(ctx, creds)
	if err != nil {
		return nil, err
	}
	out, err := run(ctx, client, enumerateAccountsScript)
	if err != nil {
		return nil, err
	}
	return normalizeJSONArray(out), nil
}

// enumerateDependenciesScript collects services, password-based scheduled tasks, and IIS app pools that
// run as a named account, with their run-as identity, so the control plane can anchor each to an account.
// Services and scheduled tasks are always present on a Windows Server, so a failure enumerating either is a
// hard error: the control plane must treat the machine as not-scanned rather than silently prune the rows it
// couldn't see this run. IIS is optional (an absent module just means no app pools), so it is best-effort.
const enumerateDependenciesScript = `
$ErrorActionPreference = 'Stop'
$deps = @()

try {
  foreach ($s in (Get-CimInstance Win32_Service)) {
    if (-not $s.StartName) { continue }
    $deps += [pscustomobject]@{
      type = 'windows-service'; runAs = $s.StartName; name = $s.Name
      data = @{ displayName = $s.DisplayName; startMode = $s.StartMode; state = [string]$s.State;
                processId = $s.ProcessId; pathName = $s.PathName; description = $s.Description; runAsAccount = $s.StartName }
    }
  }
} catch { throw "service enumeration failed: $($_.Exception.Message)" }

try {
  foreach ($t in (Get-ScheduledTask | Where-Object { ($_.Principal.LogonType -eq 'Password' -or $_.Principal.LogonType -eq 'InteractiveOrPassword') -and $_.Principal.UserId })) {
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath } catch {}
    # Principal.UserId is unqualified (e.g. 'Administrator'), so qualify it via the machine's own LSA: a bare
    # name is the local account on a member (DOMAIN\user only on a DC), and must not anchor to the domain account.
    $q = $t.Principal.UserId
    try { $q = (New-Object System.Security.Principal.NTAccount($q)).Translate([System.Security.Principal.SecurityIdentifier]).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    $deps += [pscustomobject]@{
      type = 'scheduled-task'; runAs = $q; name = ($t.TaskPath + $t.TaskName)
      data = @{ taskPath = $t.TaskPath; taskName = $t.TaskName; logonType = [string]$t.Principal.LogonType;
                runLevel = [string]$t.Principal.RunLevel; state = [string]$t.State; runAsAccount = $q;
                lastRunTime = if ($info) { [string]$info.LastRunTime } else { $null };
                nextRunTime = if ($info) { [string]$info.NextRunTime } else { $null };
                lastTaskResult = if ($info) { $info.LastTaskResult } else { $null } }
    }
  }
} catch { throw "scheduled task enumeration failed: $($_.Exception.Message)" }

if (Get-Module -ListAvailable -Name WebAdministration) {
  # Module present means IIS is installed, so enumerate it; an error here now propagates (hard fail) instead of
  # being swallowed, which would leave a "scanned" machine missing its app-pool deps and prune real rows.
  Import-Module WebAdministration
  foreach ($p in (Get-ChildItem 'IIS:\AppPools')) {
    if ($p.processModel.identityType -ne 'SpecificUser') { continue }
    if (-not $p.processModel.userName) { continue }
    $deps += [pscustomobject]@{
      type = 'iis-app-pool'; runAs = $p.processModel.userName; name = $p.Name
      data = @{ identityType = [string]$p.processModel.identityType; managedRuntimeVersion = [string]$p.managedRuntimeVersion;
                managedPipelineMode = [string]$p.managedPipelineMode; autoStart = [bool]$p.autoStart;
                state = [string]$p.state; runAsAccount = $p.processModel.userName }
    }
  }
}

$deps | ConvertTo-Json -Depth 5 -Compress
`

// EnumerateDependencies lists services / scheduled tasks / IIS app pools that run as a named account.
func EnumerateDependencies(ctx context.Context, creds Credentials) (json.RawMessage, error) {
	client, err := newClient(ctx, creds)
	if err != nil {
		return nil, err
	}
	out, err := run(ctx, client, enumerateDependenciesScript)
	if err != nil {
		return nil, err
	}
	return normalizeJSONArray(out), nil
}

// RotateCredential resets the password of a local or domain account. The connecting credentials
// (an administrator/rotation identity) must be authorized to change the target account's password.
func RotateCredential(ctx context.Context, creds Credentials, kind, username, newPassword string) error {
	client, err := newClient(ctx, creds)
	if err != nil {
		return err
	}
	u := escapePowerShellSingleQuotes(username)
	p := escapePowerShellSingleQuotes(newPassword)

	var script string
	switch kind {
	case "local":
		script = fmt.Sprintf(
			`$ErrorActionPreference='Stop'; Set-LocalUser -Name '%s' -Password (ConvertTo-SecureString '%s' -AsPlainText -Force)`,
			u, p,
		)
	case "domain":
		script = fmt.Sprintf(
			`$ErrorActionPreference='Stop'; Import-Module ActiveDirectory; `+
				`Set-ADAccountPassword -Identity '%s' -Reset -NewPassword (ConvertTo-SecureString '%s' -AsPlainText -Force)`,
			u, p,
		)
	default:
		return fmt.Errorf("unsupported credential kind %q", kind)
	}
	// The password is only ever a ConvertTo-SecureString value (never printed), so run() is safe and surfaces
	// the real host error; the control plane redacts secrets from it before storing.
	_, err = run(ctx, client, script)
	return err
}

// ValidateLocalCredential checks whether a local account's password is correct, run by the connecting
// (administrator) identity via PrincipalContext.ValidateCredentials. This lets rotation verify a local
// credential without logging in AS the account, which an ordinary local account cannot do over WinRM.
func ValidateLocalCredential(ctx context.Context, creds Credentials, username, password string) (bool, error) {
	client, err := newClient(ctx, creds)
	if err != nil {
		return false, err
	}
	u := escapePowerShellSingleQuotes(username)
	p := escapePowerShellSingleQuotes(password)
	script := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.DirectoryServices.AccountManagement; `+
			`$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine'); `+
			`if ($ctx.ValidateCredentials('%s','%s')) { 'VALID' } else { 'INVALID' }`,
		u, p,
	)
	out, err := run(ctx, client, script)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "VALID", nil
}

// SyncDependency writes a new password into a service / scheduled task / IIS app pool that runs as the
// account, then restarts it so it re-authenticates. For scheduled tasks, name is the full task path.
func SyncDependency(ctx context.Context, creds Credentials, depType, name, runAsUsername, newPassword string) error {
	client, err := newClient(ctx, creds)
	if err != nil {
		return err
	}
	n := escapePowerShellSingleQuotes(name)
	u := escapePowerShellSingleQuotes(runAsUsername)
	p := escapePowerShellSingleQuotes(newPassword)

	var script string
	switch depType {
	case "windows-service":
		// Use the CIM Change() method, not sc.exe: PowerShell 5.1 does not escape embedded quotes when
		// quoting arguments to a native executable, so a password containing " would reach sc.exe mangled.
		// Passing it as a method argument keeps it entirely within PowerShell. Only restart a service that
		// was already running, so a deliberately-stopped service is not started as a side effect.
		script = fmt.Sprintf(
			`$ErrorActionPreference='Stop'; `+
				`$svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -eq '%s' }; `+
				`if (-not $svc) { throw 'service not found' }; `+
				`$wasRunning = $svc.State -eq 'Running'; `+
				`$r = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ StartName = '%s'; StartPassword = '%s' }; `+
				`if ($r.ReturnValue -ne 0) { throw "service credential update failed (return $($r.ReturnValue))" }; `+
				`if ($wasRunning) { Restart-Service -Name '%s' -Force }`,
			n, u, p, n,
		)
	case "scheduled-task":
		// Set-ScheduledTask keeps the password in PowerShell, avoiding schtasks.exe's native-arg re-quoting.
		script = fmt.Sprintf(
			`$ErrorActionPreference='Stop'; `+
				`$t = Get-ScheduledTask | Where-Object { ($_.TaskPath + $_.TaskName) -eq '%s' }; `+
				`if (-not $t) { throw 'scheduled task not found' }; `+
				`Set-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -User '%s' -Password '%s' | Out-Null`,
			n, u, p,
		)
	case "iis-app-pool":
		// -LiteralPath so an app-pool name containing PowerShell wildcard characters ([, ], *, ?) is matched
		// literally rather than expanded as a pattern (which could update the wrong pool, several, or none).
		// Only the password is written: the run-as identity does not change during a rotation, and dropping the
		// separate userName write means a single write that can't leave the pool on a new identity with the old
		// password. Only restart a pool that was already started (Restart-WebAppPool throws on a stopped pool).
		script = fmt.Sprintf(
			`$ErrorActionPreference='Stop'; Import-Module WebAdministration; `+
				`Set-ItemProperty -LiteralPath 'IIS:\AppPools\%s' -Name processModel.password -Value '%s'; `+
				`if ((Get-WebAppPoolState -Name '%s').Value -eq 'Started') { Restart-WebAppPool -Name '%s' }`,
			n, p, n, n,
		)
	default:
		return fmt.Errorf("unsupported dependency type %q", depType)
	}
	// The scripts pass the password only as PowerShell string/method values (never printed), so run() is safe
	// and surfaces the real host error; the control plane redacts secrets from it before storing.
	_, err = run(ctx, client, script)
	return err
}
