#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server Hardening Script aligned with CIS Benchmarks (Server 2016+).

.DESCRIPTION
    Remediates common Windows Server configuration vulnerabilities across ~175 controls.
    Supports audit-only mode (-ReportOnly), category exclusion, and optional registry backup.

.PARAMETER ReportOnly
    Audit-only mode: report compliance status without making changes.

.PARAMETER LogPath
    Path to the log file. If not specified, a timestamped log is created in the script directory.

.PARAMETER SkipFirewall
    Skip firewall profile changes (use in environments with third-party firewalls).

.PARAMETER SkipServices
    Skip service disablement controls.

.PARAMETER ExcludeCategory
    Array of category names to exclude (e.g., 'TLS','SMB','Firewall','Services','RDP','Defender','AccountPolicies','AuditPolicies','LocalPolicies','RegistryMisc').

.PARAMETER BackupRegistry
    Export registry hives (HKLM\SYSTEM, HKLM\SOFTWARE) before making changes.

.EXAMPLE
    .\Harden-WindowsServer.ps1 -ReportOnly
    Audit current compliance without making changes.

.EXAMPLE
    .\Harden-WindowsServer.ps1 -BackupRegistry -ExcludeCategory 'TLS'
    Harden the server, backing up registry first, skipping TLS controls.
#>
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [string]$LogPath,
    [switch]$SkipFirewall,
    [switch]$SkipServices,
    [string[]]$ExcludeCategory,
    [switch]$BackupRegistry
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
$script:Results     = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ErrorCount  = 0
$script:ChangeCount = 0
$script:PassCount   = 0
$script:SkipCount   = 0
$script:FailCount   = 0

if (-not $LogPath) {
    $LogPath = Join-Path $PSScriptRoot ("HardenLog_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
function Write-HardenLog {
    param(
        [string]$Message,
        [ValidateSet('PASS','CHANGE','FAIL','SKIP','ERROR','INFO','WARN')]
        [string]$Status = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Status] $Message"

    $color = switch ($Status) {
        'PASS'   { 'Green'   }
        'CHANGE' { 'Cyan'    }
        'FAIL'   { 'Red'     }
        'SKIP'   { 'Yellow'  }
        'ERROR'  { 'Magenta' }
        'WARN'   { 'Yellow'  }
        default  { 'White'   }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

function Set-RegistryHarden {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type,          # DWORD, String, etc.
        [string]$CISRef,
        [string]$Description,
        [string]$Category
    )
    $id = "$Category | $CISRef | $Description"
    try {
        # Check current value
        $current = $null
        if (Test-Path $Path) {
            $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $prop) {
                $current = $prop.$Name
            }
        }

        if ($current -eq $Value) {
            Write-HardenLog "$id — Already compliant (Value=$Value)" -Status 'PASS'
            $script:PassCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='PASS'; Current=$current; Expected=$Value })
            return
        }

        if ($ReportOnly) {
            Write-HardenLog "$id — Non-compliant (Current=$current, Expected=$Value)" -Status 'FAIL'
            $script:FailCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='FAIL'; Current=$current; Expected=$Value })
            return
        }

        # Apply
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-HardenLog "$id — Remediated (Was=$current, Set=$Value)" -Status 'CHANGE'
        $script:ChangeCount++
        $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='CHANGE'; Current=$current; Expected=$Value })
    }
    catch {
        Write-HardenLog "$id — ERROR: $_" -Status 'ERROR'
        $script:ErrorCount++
        $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='ERROR'; Current=$null; Expected=$Value })
    }
}

function Set-ServiceHarden {
    param(
        [string]$ServiceName,
        [string]$StartupType,   # Disabled, Manual
        [string]$CISRef,
        [string]$Description,
        [string]$Category
    )
    $id = "$Category | $CISRef | $Description"
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            Write-HardenLog "$id — Service '$ServiceName' not installed (compliant by absence)" -Status 'PASS'
            $script:PassCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='PASS'; Current='NotInstalled'; Expected=$StartupType })
            return
        }

        $currentStartup = (Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue).StartMode
        # Map WMI start modes to PowerShell names
        $modeMap = @{ 'Auto'='Automatic'; 'Manual'='Manual'; 'Disabled'='Disabled' }
        $currentMapped = if ($modeMap.ContainsKey($currentStartup)) { $modeMap[$currentStartup] } else { $currentStartup }

        if ($currentMapped -eq $StartupType) {
            Write-HardenLog "$id — Already compliant ($ServiceName=$StartupType)" -Status 'PASS'
            $script:PassCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='PASS'; Current=$currentMapped; Expected=$StartupType })
            return
        }

        if ($ReportOnly) {
            Write-HardenLog "$id — Non-compliant ($ServiceName=$currentMapped, Expected=$StartupType)" -Status 'FAIL'
            $script:FailCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='FAIL'; Current=$currentMapped; Expected=$StartupType })
            return
        }

        Set-Service -Name $ServiceName -StartupType $StartupType -Force -ErrorAction Stop
        if ($svc.Status -eq 'Running' -and $StartupType -eq 'Disabled') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        Write-HardenLog "$id — Remediated (${ServiceName}: $currentMapped → $StartupType)" -Status 'CHANGE'
        $script:ChangeCount++
        $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='CHANGE'; Current=$currentMapped; Expected=$StartupType })
    }
    catch {
        Write-HardenLog "$id — ERROR: $_" -Status 'ERROR'
        $script:ErrorCount++
        $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='ERROR'; Current=$null; Expected=$StartupType })
    }
}

function Set-AuditPolicyHarden {
    param(
        [string]$Subcategory,
        [string]$Setting,       # 'Success','Failure','Success and Failure','No Auditing'
        [string]$CISRef,
        [string]$Description,
        [string]$Category
    )
    $id = "$Category | $CISRef | $Description"
    try {
        $raw = auditpol /get /subcategory:"$Subcategory" /r 2>&1
        $csv = $raw | ConvertFrom-Csv -ErrorAction SilentlyContinue
        $current = if ($csv) { ($csv | Select-Object -First 1).'Inclusion Setting' } else { 'Unknown' }

        if ($current -eq $Setting) {
            Write-HardenLog "$id — Already compliant ($Subcategory=$Setting)" -Status 'PASS'
            $script:PassCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='PASS'; Current=$current; Expected=$Setting })
            return
        }

        if ($ReportOnly) {
            Write-HardenLog "$id — Non-compliant ($Subcategory=$current, Expected=$Setting)" -Status 'FAIL'
            $script:FailCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='FAIL'; Current=$current; Expected=$Setting })
            return
        }

        # Build auditpol arguments
        $auditArgs = @('/set', '/subcategory:"' + $Subcategory + '"')
        switch ($Setting) {
            'Success'             { $auditArgs += '/success:enable',  '/failure:disable' }
            'Failure'             { $auditArgs += '/success:disable', '/failure:enable'  }
            'Success and Failure' { $auditArgs += '/success:enable',  '/failure:enable'  }
            'No Auditing'        { $auditArgs += '/success:disable', '/failure:disable' }
        }
        $result = & auditpol $auditArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed: $result" }

        Write-HardenLog "$id — Remediated (${Subcategory}: $current → $Setting)" -Status 'CHANGE'
        $script:ChangeCount++
        $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='CHANGE'; Current=$current; Expected=$Setting })
    }
    catch {
        Write-HardenLog "$id — ERROR: $_" -Status 'ERROR'
        $script:ErrorCount++
        $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$CISRef; Control=$Description; Status='ERROR'; Current=$null; Expected=$Setting })
    }
}

function Set-AccountPolicyHarden {
    <#
    .DESCRIPTION
        Applies account/password policies via secedit. Exports current config, checks values,
        modifies the INF, and re-imports if changes are needed.
    #>
    param(
        [hashtable[]]$Policies,   # Array of @{ Name; Value; CISRef; Description }
        [string]$Category
    )
    $tempDir  = Join-Path $env:TEMP 'HardenSecedit'
    $infFile  = Join-Path $tempDir 'current.inf'
    $dbFile   = Join-Path $tempDir 'secedit.sdb'

    try {
        if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null }

        # Export current security policy
        $null = secedit /export /cfg $infFile /quiet 2>&1
        if (-not (Test-Path $infFile)) { throw 'secedit export failed' }

        $content = Get-Content $infFile -Raw
        $needsApply = $false

        foreach ($pol in $Policies) {
            $id = "$Category | $($pol.CISRef) | $($pol.Description)"
            # Parse current value from INF
            $pattern = "(?m)^\s*$([regex]::Escape($pol.Name))\s*=\s*(.+)$"
            $match = [regex]::Match($content, $pattern)
            $current = if ($match.Success) { $match.Groups[1].Value.Trim() } else { 'NotSet' }

            if ($current -eq [string]$pol.Value) {
                Write-HardenLog "$id — Already compliant ($($pol.Name)=$($pol.Value))" -Status 'PASS'
                $script:PassCount++
                $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$pol.CISRef; Control=$pol.Description; Status='PASS'; Current=$current; Expected=$pol.Value })
                continue
            }

            if ($ReportOnly) {
                Write-HardenLog "$id — Non-compliant ($($pol.Name)=$current, Expected=$($pol.Value))" -Status 'FAIL'
                $script:FailCount++
                $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$pol.CISRef; Control=$pol.Description; Status='FAIL'; Current=$current; Expected=$pol.Value })
                continue
            }

            # Replace or insert value
            if ($match.Success) {
                $content = $content -replace $pattern, "$($pol.Name) = $($pol.Value)"
            }
            else {
                # Insert into [System Access] section
                $content = $content -replace '(?m)(\[System Access\])', "`$1`r`n$($pol.Name) = $($pol.Value)"
            }
            $needsApply = $true
            Write-HardenLog "$id — Remediated ($($pol.Name): $current → $($pol.Value))" -Status 'CHANGE'
            $script:ChangeCount++
            $script:Results.Add([PSCustomObject]@{ Category=$Category; CIS=$pol.CISRef; Control=$pol.Description; Status='CHANGE'; Current=$current; Expected=$pol.Value })
        }

        if ($needsApply -and -not $ReportOnly) {
            Set-Content -Path $infFile -Value $content -Force
            $null = secedit /configure /db $dbFile /cfg $infFile /quiet 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-HardenLog "$Category — secedit /configure returned exit code $LASTEXITCODE" -Status 'WARN'
            }
        }
    }
    catch {
        Write-HardenLog "$Category — Account policy ERROR: $_" -Status 'ERROR'
        $script:ErrorCount++
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-ComplianceSummary {
    Write-HardenLog '═══════════════════════════════════════════════════════════════' -Status 'INFO'
    Write-HardenLog '                    COMPLIANCE SUMMARY                        ' -Status 'INFO'
    Write-HardenLog '═══════════════════════════════════════════════════════════════' -Status 'INFO'

    $categories = $script:Results | Group-Object Category
    $summaryTable = foreach ($cat in ($categories | Sort-Object Name)) {
        $p = ($cat.Group | Where-Object Status -eq 'PASS').Count
        $c = ($cat.Group | Where-Object Status -eq 'CHANGE').Count
        $f = ($cat.Group | Where-Object Status -eq 'FAIL').Count
        $s = ($cat.Group | Where-Object Status -eq 'SKIP').Count
        $e = ($cat.Group | Where-Object Status -eq 'ERROR').Count
        [PSCustomObject]@{
            Category = $cat.Name
            Total    = $cat.Count
            Pass     = $p
            Change   = $c
            Fail     = $f
            Skip     = $s
            Error    = $e
        }
    }
    $summaryTable | Format-Table -AutoSize | Out-String | ForEach-Object {
        Write-HardenLog $_ -Status 'INFO'
    }

    $total = $script:Results.Count
    Write-HardenLog "Totals: $total controls | PASS=$script:PassCount CHANGE=$script:ChangeCount FAIL=$script:FailCount SKIP=$script:SkipCount ERROR=$script:ErrorCount" -Status 'INFO'
}

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────
Write-HardenLog "Harden-WindowsServer.ps1 started (ReportOnly=$ReportOnly)" -Status 'INFO'
Write-HardenLog "Log file: $LogPath" -Status 'INFO'

# Admin check
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-HardenLog 'This script must be run as Administrator. Exiting.' -Status 'ERROR'
    exit 1
}

# OS version check
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
if ($build -lt 14393) {   # Server 2016 = build 14393
    Write-HardenLog "Unsupported OS build $build. Server 2016+ (build 14393+) required. Exiting." -Status 'ERROR'
    exit 1
}
Write-HardenLog "OS: $($os.Caption) Build $build" -Status 'INFO'

# Domain-joined warning
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-HardenLog 'WARNING: This server is domain-joined. Consider using Group Policy (GPO) for centralized management.' -Status 'WARN'
}

# Registry backup
if ($BackupRegistry -and -not $ReportOnly) {
    $backupDir = Join-Path $PSScriptRoot ("RegistryBackup_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    Write-HardenLog "Backing up registry hives to $backupDir ..." -Status 'INFO'
    reg export 'HKLM\SYSTEM'   (Join-Path $backupDir 'HKLM_SYSTEM.reg')   /y 2>&1 | Out-Null
    reg export 'HKLM\SOFTWARE' (Join-Path $backupDir 'HKLM_SOFTWARE.reg') /y 2>&1 | Out-Null
    Write-HardenLog 'Registry backup complete.' -Status 'INFO'
}

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY SKIP HELPER
# ─────────────────────────────────────────────────────────────────────────────
function Test-CategoryExcluded {
    param([string]$CategoryName)
    if ($ExcludeCategory -and $ExcludeCategory -contains $CategoryName) {
        Write-HardenLog "Category '$CategoryName' excluded by -ExcludeCategory parameter." -Status 'SKIP'
        return $true
    }
    return $false
}

# ═════════════════════════════════════════════════════════════════════════════
# 1. ACCOUNT POLICIES (CIS §1)
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'AccountPolicies')) {
    Write-HardenLog '── Category: Account Policies (CIS §1) ──' -Status 'INFO'

    $accountPolicies = @(
        @{ Name='PasswordHistorySize';           Value='24';  CISRef='1.1.1'; Description='Enforce password history (24 passwords)' }
        @{ Name='MaximumPasswordAge';            Value='365'; CISRef='1.1.2'; Description='Maximum password age (365 days)' }
        @{ Name='MinimumPasswordAge';            Value='1';   CISRef='1.1.3'; Description='Minimum password age (1 day)' }
        @{ Name='MinimumPasswordLength';         Value='14';  CISRef='1.1.4'; Description='Minimum password length (14 characters)' }
        @{ Name='PasswordComplexity';            Value='1';   CISRef='1.1.5'; Description='Password must meet complexity requirements' }
        @{ Name='ClearTextPassword';             Value='0';   CISRef='1.1.6'; Description='Store passwords using reversible encryption (disabled)' }
        @{ Name='LockoutBadCount';               Value='5';   CISRef='1.2.1'; Description='Account lockout threshold (5 attempts)' }
        @{ Name='ResetLockoutCount';             Value='15';  CISRef='1.2.2'; Description='Reset account lockout counter after (15 min)' }
        @{ Name='LockoutDuration';               Value='15';  CISRef='1.2.3'; Description='Account lockout duration (15 min)' }
    )

    Set-AccountPolicyHarden -Policies $accountPolicies -Category 'AccountPolicies'
}

# ═════════════════════════════════════════════════════════════════════════════
# 2. LOCAL POLICIES / SECURITY OPTIONS (CIS §2.3)
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'LocalPolicies')) {
    Write-HardenLog '── Category: Local Policies / Security Options (CIS §2.3) ──' -Status 'INFO'

    $localPolicies = @(
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='NoConnectedUser'; Value=3; Type='DWord';
           CISRef='2.3.1.2'; Description='Block Microsoft accounts' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LimitBlankPasswordUse'; Value=1; Type='DWord';
           CISRef='2.3.1.4'; Description='Limit local account use of blank passwords to console logon only' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Value=1; Type='DWord';
           CISRef='2.3.8.1'; Description='Microsoft network client: Digitally sign communications (always)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnableSecuritySignature'; Value=1; Type='DWord';
           CISRef='2.3.8.2'; Description='Microsoft network client: Digitally sign communications (if server agrees)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnablePlainTextPassword'; Value=0; Type='DWord';
           CISRef='2.3.8.3'; Description='Microsoft network client: Send unencrypted password to third-party SMB servers (disabled)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='AutoDisconnect'; Value=15; Type='DWord';
           CISRef='2.3.9.1'; Description='Microsoft network server: Amount of idle time required before suspending session (15 min)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RequireSecuritySignature'; Value=1; Type='DWord';
           CISRef='2.3.9.2'; Description='Microsoft network server: Digitally sign communications (always)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='EnableSecuritySignature'; Value=1; Type='DWord';
           CISRef='2.3.9.3'; Description='Microsoft network server: Digitally sign communications (if client agrees)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Value=1; Type='DWord';
           CISRef='2.3.10.2'; Description='Network access: Do not allow anonymous enumeration of SAM accounts' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Value=1; Type='DWord';
           CISRef='2.3.10.3'; Description='Network access: Do not allow anonymous enumeration of SAM accounts and shares' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='EveryoneIncludesAnonymous'; Value=0; Type='DWord';
           CISRef='2.3.10.5'; Description='Network access: Let Everyone permissions apply to anonymous users (disabled)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictRemoteSAM'; Value='O:BAG:BAD:(A;;RC;;;BA)'; Type='String';
           CISRef='2.3.10.11'; Description='Network access: Restrict clients allowed to make remote calls to SAM' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RestrictNullSessAccess'; Value=1; Type='DWord';
           CISRef='2.3.10.9'; Description='Network access: Restrict anonymous access to Named Pipes and Shares' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Value=5; Type='DWord';
           CISRef='2.3.11.7'; Description='Network security: LAN Manager authentication level (Send NTLMv2 response only, refuse LM & NTLM)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinClientSec'; Value=537395200; Type='DWord';
           CISRef='2.3.11.9'; Description='Network security: Minimum session security for NTLM SSP based clients (Require NTLMv2 + 128-bit)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinServerSec'; Value=537395200; Type='DWord';
           CISRef='2.3.11.10'; Description='Network security: Minimum session security for NTLM SSP based servers (Require NTLMv2 + 128-bit)' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Value=1; Type='DWord';
           CISRef='2.3.17.1'; Description='UAC: Admin Approval Mode for the Built-in Administrator account' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Value=2; Type='DWord';
           CISRef='2.3.17.2'; Description='UAC: Behavior of elevation prompt for administrators (Prompt for consent on secure desktop)' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Value=0; Type='DWord';
           CISRef='2.3.17.3'; Description='UAC: Behavior of elevation prompt for standard users (Automatically deny)' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Value=1; Type='DWord';
           CISRef='2.3.17.4'; Description='UAC: Detect application installations and prompt for elevation' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableSecureUIAPaths'; Value=1; Type='DWord';
           CISRef='2.3.17.5'; Description='UAC: Only elevate UIAccess applications installed in secure locations' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableVirtualization'; Value=1; Type='DWord';
           CISRef='2.3.17.7'; Description='UAC: Virtualize file and registry write failures to per-user locations' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Value=1; Type='DWord';
           CISRef='2.3.17.8'; Description='UAC: Admin Approval Mode for Built-in Administrator' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='DisableDomainCreds'; Value=1; Type='DWord';
           CISRef='2.3.10.1'; Description='Network access: Do not allow storage of passwords and credentials for network authentication' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Value=1; Type='DWord';
           CISRef='2.3.11.7b'; Description='Network security: Do not store LAN Manager hash value on next password change' }
    )

    foreach ($pol in $localPolicies) {
        Set-RegistryHarden @pol -Category 'LocalPolicies'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# 3. AUDIT POLICIES (CIS §17)
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'AuditPolicies')) {
    Write-HardenLog '── Category: Audit Policies (CIS §17) ──' -Status 'INFO'

    $auditPolicies = @(
        @{ Subcategory='Credential Validation';            Setting='Success and Failure'; CISRef='17.1.1'; Description='Audit Credential Validation' }
        @{ Subcategory='Application Group Management';     Setting='Success and Failure'; CISRef='17.2.1'; Description='Audit Application Group Management' }
        @{ Subcategory='Computer Account Management';      Setting='Success';             CISRef='17.2.2'; Description='Audit Computer Account Management' }
        @{ Subcategory='Other Account Management Events';  Setting='Success and Failure'; CISRef='17.2.4'; Description='Audit Other Account Management Events' }
        @{ Subcategory='Security Group Management';        Setting='Success';             CISRef='17.2.5'; Description='Audit Security Group Management' }
        @{ Subcategory='User Account Management';          Setting='Success and Failure'; CISRef='17.2.6'; Description='Audit User Account Management' }
        @{ Subcategory='PNP Activity';                     Setting='Success';             CISRef='17.3.1'; Description='Audit PNP Activity' }
        @{ Subcategory='Process Creation';                 Setting='Success';             CISRef='17.3.2'; Description='Audit Process Creation' }
        @{ Subcategory='Account Lockout';                  Setting='Failure';             CISRef='17.5.1'; Description='Audit Account Lockout' }
        @{ Subcategory='Group Membership';                 Setting='Success';             CISRef='17.5.2'; Description='Audit Group Membership' }
        @{ Subcategory='Logoff';                           Setting='Success';             CISRef='17.5.3'; Description='Audit Logoff' }
        @{ Subcategory='Logon';                            Setting='Success and Failure'; CISRef='17.5.4'; Description='Audit Logon' }
        @{ Subcategory='Other Logon/Logoff Events';        Setting='Success and Failure'; CISRef='17.5.5'; Description='Audit Other Logon/Logoff Events' }
        @{ Subcategory='Special Logon';                    Setting='Success';             CISRef='17.5.6'; Description='Audit Special Logon' }
        @{ Subcategory='Removable Storage';                Setting='Success and Failure'; CISRef='17.6.1'; Description='Audit Removable Storage' }
        @{ Subcategory='Audit Policy Change';              Setting='Success and Failure'; CISRef='17.7.1'; Description='Audit Audit Policy Change' }
        @{ Subcategory='Authentication Policy Change';     Setting='Success';             CISRef='17.7.2'; Description='Audit Authentication Policy Change' }
        @{ Subcategory='Authorization Policy Change';      Setting='Success';             CISRef='17.7.3'; Description='Audit Authorization Policy Change' }
        @{ Subcategory='MPSSVC Rule-Level Policy Change';  Setting='Success and Failure'; CISRef='17.7.4'; Description='Audit MPSSVC Rule-Level Policy Change' }
        @{ Subcategory='Other Policy Change Events';       Setting='Failure';             CISRef='17.7.5'; Description='Audit Other Policy Change Events' }
        @{ Subcategory='Sensitive Privilege Use';           Setting='Success and Failure'; CISRef='17.8.1'; Description='Audit Sensitive Privilege Use' }
        @{ Subcategory='IPsec Driver';                     Setting='Success and Failure'; CISRef='17.9.1'; Description='Audit IPsec Driver' }
        @{ Subcategory='Other System Events';              Setting='Success and Failure'; CISRef='17.9.2'; Description='Audit Other System Events' }
        @{ Subcategory='Security State Change';            Setting='Success';             CISRef='17.9.3'; Description='Audit Security State Change' }
        @{ Subcategory='Security System Extension';        Setting='Success and Failure'; CISRef='17.9.4'; Description='Audit Security System Extension' }
        @{ Subcategory='System Integrity';                 Setting='Success and Failure'; CISRef='17.9.5'; Description='Audit System Integrity' }
        @{ Subcategory='Distribution Group Management';    Setting='Success';             CISRef='17.2.3'; Description='Audit Distribution Group Management' }
        @{ Subcategory='Detailed File Share';              Setting='Failure';             CISRef='17.6.2'; Description='Audit Detailed File Share' }
    )

    foreach ($pol in $auditPolicies) {
        Set-AuditPolicyHarden @pol -Category 'AuditPolicies'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# 4. SERVICES (CIS §5)
# ═════════════════════════════════════════════════════════════════════════════
if (-not $SkipServices -and -not (Test-CategoryExcluded 'Services')) {
    Write-HardenLog '── Category: Services (CIS §5) ──' -Status 'INFO'

    $servicesToDisable = @(
        @{ ServiceName='Browser';         CISRef='5.1';  Description='Computer Browser' }
        @{ ServiceName='IISADMIN';        CISRef='5.2';  Description='IIS Admin Service' }
        @{ ServiceName='irmon';           CISRef='5.3';  Description='Infrared Monitor Service' }
        @{ ServiceName='SharedAccess';    CISRef='5.4';  Description='Internet Connection Sharing (ICS)' }
        @{ ServiceName='LxssManager';     CISRef='5.5';  Description='Windows Subsystem for Linux (LxssManager)' }
        @{ ServiceName='FTPSVC';          CISRef='5.6';  Description='Microsoft FTP Service' }
        @{ ServiceName='RpcLocator';      CISRef='5.7';  Description='Remote Procedure Call (RPC) Locator' }
        @{ ServiceName='RemoteAccess';    CISRef='5.8';  Description='Routing and Remote Access' }
        @{ ServiceName='simptcp';         CISRef='5.9';  Description='Simple TCP/IP Services' }
        @{ ServiceName='SNMPTRAP';        CISRef='5.10'; Description='SNMP Trap' }
        @{ ServiceName='SSDPSRV';         CISRef='5.11'; Description='SSDP Discovery' }
        @{ ServiceName='upnphost';        CISRef='5.12'; Description='UPnP Device Host' }
        @{ ServiceName='W3SVC';           CISRef='5.13'; Description='World Wide Web Publishing Service' }
        @{ ServiceName='WMSvc';           CISRef='5.14'; Description='Web Management Service' }
        @{ ServiceName='WMPNetworkSvc';   CISRef='5.15'; Description='Windows Media Player Network Sharing Service' }
        @{ ServiceName='icssvc';          CISRef='5.16'; Description='Windows Mobile Hotspot Service' }
        @{ ServiceName='XblAuthManager';  CISRef='5.17'; Description='Xbox Live Auth Manager' }
        @{ ServiceName='XblGameSave';     CISRef='5.18'; Description='Xbox Live Game Save' }
        @{ ServiceName='XboxNetApiSvc';   CISRef='5.19'; Description='Xbox Live Networking Service' }
    )

    foreach ($svc in $servicesToDisable) {
        Set-ServiceHarden -ServiceName $svc.ServiceName -StartupType 'Disabled' -CISRef $svc.CISRef -Description $svc.Description -Category 'Services'
    }
}
elseif ($SkipServices) {
    Write-HardenLog 'Services category skipped by -SkipServices parameter.' -Status 'SKIP'
    $script:SkipCount++
}

# ═════════════════════════════════════════════════════════════════════════════
# 5. FIREWALL (CIS §9)
# ═════════════════════════════════════════════════════════════════════════════
if (-not $SkipFirewall -and -not (Test-CategoryExcluded 'Firewall')) {
    Write-HardenLog '── Category: Firewall (CIS §9) ──' -Status 'INFO'

    $firewallProfiles = @('Domain', 'Private', 'Public')

    foreach ($profile in $firewallProfiles) {
        $id = "Firewall | CIS §9 | $profile profile"
        try {
            $fw = Get-NetFirewallProfile -Name $profile -ErrorAction Stop

            $issues = @()
            if ($fw.Enabled -ne 'True' -and $fw.Enabled -ne $true)        { $issues += "Enabled=$($fw.Enabled)" }
            if ($fw.DefaultInboundAction -ne 'Block')                      { $issues += "Inbound=$($fw.DefaultInboundAction)" }
            if ($fw.LogFileName -eq $null)                                  { $issues += 'LogFileName=NotSet' }
            if ($fw.LogMaxSizeKilobytes -lt 16384)                         { $issues += "LogMaxSize=$($fw.LogMaxSizeKilobytes)KB" }
            if ($fw.LogBlocked -ne 'True' -and $fw.LogBlocked -ne $true)  { $issues += "LogBlocked=$($fw.LogBlocked)" }

            if ($issues.Count -eq 0) {
                Write-HardenLog "$id — Already compliant" -Status 'PASS'
                $script:PassCount++
                $script:Results.Add([PSCustomObject]@{ Category='Firewall'; CIS="9.$profile"; Control="$profile profile settings"; Status='PASS'; Current='Compliant'; Expected='Enabled,BlockInbound,Log16MB' })
                continue
            }

            if ($ReportOnly) {
                Write-HardenLog "$id — Non-compliant: $($issues -join ', ')" -Status 'FAIL'
                $script:FailCount++
                $script:Results.Add([PSCustomObject]@{ Category='Firewall'; CIS="9.$profile"; Control="$profile profile settings"; Status='FAIL'; Current=($issues -join ', '); Expected='Enabled,BlockInbound,Log16MB' })
                continue
            }

            $logDir = '%SystemRoot%\System32\LogFiles\Firewall'
            Set-NetFirewallProfile -Name $profile `
                -Enabled True `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Allow `
                -LogBlocked True `
                -LogMaxSizeKilobytes 16384 `
                -LogFileName "$logDir\pfirewall.log" `
                -ErrorAction Stop

            Write-HardenLog "$id — Remediated ($($issues -join ', '))" -Status 'CHANGE'
            $script:ChangeCount++
            $script:Results.Add([PSCustomObject]@{ Category='Firewall'; CIS="9.$profile"; Control="$profile profile settings"; Status='CHANGE'; Current=($issues -join ', '); Expected='Enabled,BlockInbound,Log16MB' })
        }
        catch {
            Write-HardenLog "$id — ERROR: $_" -Status 'ERROR'
            $script:ErrorCount++
            $script:Results.Add([PSCustomObject]@{ Category='Firewall'; CIS="9.$profile"; Control="$profile profile settings"; Status='ERROR'; Current=$null; Expected='Enabled,BlockInbound,Log16MB' })
        }
    }
}
elseif ($SkipFirewall) {
    Write-HardenLog 'Firewall category skipped by -SkipFirewall parameter.' -Status 'SKIP'
    $script:SkipCount++
}

# ═════════════════════════════════════════════════════════════════════════════
# 6. TLS/SSL (SCHANNEL)
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'TLS')) {
    Write-HardenLog '── Category: TLS/SSL Configuration ──' -Status 'INFO'

    $schannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

    # Protocols to disable
    $disableProtocols = @(
        @{ Protocol='SSL 2.0'; CISRef='TLS-1'; Description='Disable SSL 2.0 (Server)' }
        @{ Protocol='SSL 2.0'; CISRef='TLS-2'; Description='Disable SSL 2.0 (Client)'; Role='Client' }
        @{ Protocol='SSL 3.0'; CISRef='TLS-3'; Description='Disable SSL 3.0 (Server)' }
        @{ Protocol='SSL 3.0'; CISRef='TLS-4'; Description='Disable SSL 3.0 (Client)'; Role='Client' }
        @{ Protocol='TLS 1.0'; CISRef='TLS-5'; Description='Disable TLS 1.0 (Server)' }
        @{ Protocol='TLS 1.0'; CISRef='TLS-6'; Description='Disable TLS 1.0 (Client)'; Role='Client' }
        @{ Protocol='TLS 1.1'; CISRef='TLS-7'; Description='Disable TLS 1.1 (Server)' }
        @{ Protocol='TLS 1.1'; CISRef='TLS-8'; Description='Disable TLS 1.1 (Client)'; Role='Client' }
    )

    foreach ($p in $disableProtocols) {
        $role = if ($p.ContainsKey('Role')) { $p.Role } else { 'Server' }
        $path = "$schannelBase\Protocols\$($p.Protocol)\$role"
        Set-RegistryHarden -Path $path -Name 'Enabled' -Value 0 -Type 'DWord' -CISRef $p.CISRef -Description $p.Description -Category 'TLS'
        Set-RegistryHarden -Path $path -Name 'DisabledByDefault' -Value 1 -Type 'DWord' -CISRef "$($p.CISRef)b" -Description "$($p.Description) (DisabledByDefault)" -Category 'TLS'
    }

    # Protocols to enable
    $enableProtocols = @(
        @{ Protocol='TLS 1.2'; CISRef='TLS-9';  Description='Enable TLS 1.2 (Server)' }
        @{ Protocol='TLS 1.2'; CISRef='TLS-10'; Description='Enable TLS 1.2 (Client)'; Role='Client' }
        @{ Protocol='TLS 1.3'; CISRef='TLS-11'; Description='Enable TLS 1.3 (Server)' }
        @{ Protocol='TLS 1.3'; CISRef='TLS-12'; Description='Enable TLS 1.3 (Client)'; Role='Client' }
    )

    foreach ($p in $enableProtocols) {
        $role = if ($p.ContainsKey('Role')) { $p.Role } else { 'Server' }
        $path = "$schannelBase\Protocols\$($p.Protocol)\$role"
        Set-RegistryHarden -Path $path -Name 'Enabled' -Value 1 -Type 'DWord' -CISRef $p.CISRef -Description $p.Description -Category 'TLS'
        Set-RegistryHarden -Path $path -Name 'DisabledByDefault' -Value 0 -Type 'DWord' -CISRef "$($p.CISRef)b" -Description "$($p.Description) (DisabledByDefault=0)" -Category 'TLS'
    }

    # Disable weak ciphers
    $weakCiphers = @(
        @{ Cipher='DES 56/56';    CISRef='TLS-C1'; Description='Disable DES 56-bit cipher' }
        @{ Cipher='RC2 40/128';   CISRef='TLS-C2'; Description='Disable RC2 40-bit cipher' }
        @{ Cipher='RC2 56/128';   CISRef='TLS-C3'; Description='Disable RC2 56-bit cipher' }
        @{ Cipher='RC2 128/128';  CISRef='TLS-C4'; Description='Disable RC2 128-bit cipher' }
        @{ Cipher='RC4 40/128';   CISRef='TLS-C5'; Description='Disable RC4 40-bit cipher' }
        @{ Cipher='RC4 56/128';   CISRef='TLS-C6'; Description='Disable RC4 56-bit cipher' }
        @{ Cipher='RC4 64/128';   CISRef='TLS-C7'; Description='Disable RC4 64-bit cipher' }
        @{ Cipher='RC4 128/128';  CISRef='TLS-C8'; Description='Disable RC4 128-bit cipher' }
        @{ Cipher='NULL';         CISRef='TLS-C9'; Description='Disable NULL cipher' }
    )

    foreach ($c in $weakCiphers) {
        $path = "$schannelBase\Ciphers\$($c.Cipher)"
        Set-RegistryHarden -Path $path -Name 'Enabled' -Value 0 -Type 'DWord' -CISRef $c.CISRef -Description $c.Description -Category 'TLS'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# 7. SMB HARDENING
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'SMB')) {
    Write-HardenLog '── Category: SMB Hardening ──' -Status 'INFO'

    $smbSettings = @(
        # Disable SMBv1
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'; Value=0; Type='DWord';
           CISRef='SMB-1'; Description='Disable SMBv1 server' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name='Start'; Value=4; Type='DWord';
           CISRef='SMB-2'; Description='Disable SMBv1 client driver (mrxsmb10)' }
        # Require signing
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RequireSecuritySignature'; Value=1; Type='DWord';
           CISRef='SMB-3'; Description='SMB server: require signing' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='EnableSecuritySignature'; Value=1; Type='DWord';
           CISRef='SMB-4'; Description='SMB server: enable signing' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Value=1; Type='DWord';
           CISRef='SMB-5'; Description='SMB client: require signing' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnableSecuritySignature'; Value=1; Type='DWord';
           CISRef='SMB-6'; Description='SMB client: enable signing' }
        # Encryption
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='EncryptData'; Value=1; Type='DWord';
           CISRef='SMB-7'; Description='SMB server: enable encryption' }
        # Restrict null sessions
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RestrictNullSessAccess'; Value=1; Type='DWord';
           CISRef='SMB-8'; Description='SMB: restrict null session access' }
    )

    foreach ($setting in $smbSettings) {
        Set-RegistryHarden @setting -Category 'SMB'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# 8. RDP HARDENING
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'RDP')) {
    Write-HardenLog '── Category: RDP Hardening ──' -Status 'INFO'

    $rdpBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $rdpSettings = @(
        @{ Path=$rdpBase; Name='UserAuthentication'; Value=1; Type='DWord';
           CISRef='18.9.65.3.9.1'; Description='Require NLA for Remote Desktop' }
        @{ Path=$rdpBase; Name='SecurityLayer'; Value=2; Type='DWord';
           CISRef='18.9.65.3.9.2'; Description='RDP: Require SSL security layer' }
        @{ Path=$rdpBase; Name='MinEncryptionLevel'; Value=3; Type='DWord';
           CISRef='18.9.65.3.9.3'; Description='RDP: Set client connection encryption level to High' }
        @{ Path=$rdpBase; Name='MaxIdleTime'; Value=900000; Type='DWord';
           CISRef='18.9.65.3.10.1'; Description='RDP: Set idle session timeout (15 min = 900000 ms)' }
        @{ Path=$rdpBase; Name='MaxDisconnectionTime'; Value=60000; Type='DWord';
           CISRef='18.9.65.3.10.2'; Description='RDP: Set disconnected session timeout (1 min = 60000 ms)' }
        @{ Path=$rdpBase; Name='DeleteTempDirsOnExit'; Value=1; Type='DWord';
           CISRef='18.9.65.3.11.1'; Description='RDP: Delete temp folders on exit' }
        @{ Path=$rdpBase; Name='fDisableCdm'; Value=1; Type='DWord';
           CISRef='18.9.65.3.3.2'; Description='RDP: Do not allow drive redirection' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowUnsolicited'; Value=0; Type='DWord';
           CISRef='18.9.65.2.1'; Description='Disable unsolicited Remote Assistance offers' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Value=0; Type='DWord';
           CISRef='18.9.65.2.2'; Description='Disable solicited Remote Assistance' }
        @{ Path=$rdpBase; Name='fEncryptRPCTraffic'; Value=1; Type='DWord';
           CISRef='18.9.65.3.9.5'; Description='RDP: Require encryption for RPC traffic' }
        @{ Path=$rdpBase; Name='KeepAliveInterval'; Value=1; Type='DWord';
           CISRef='18.9.65.3.2'; Description='RDP: Keep-alive interval (1 min)' }
    )

    foreach ($setting in $rdpSettings) {
        Set-RegistryHarden @setting -Category 'RDP'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# 9. REGISTRY MISC (CIS §18)
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'RegistryMisc')) {
    Write-HardenLog '── Category: Registry Misc (CIS §18) ──' -Status 'INFO'

    $registryMisc = @(
        # IP Source Routing
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting'; Value=2; Type='DWord';
           CISRef='18.4.2'; Description='Disable IP source routing (highest protection)' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name='DisableIPSourceRouting'; Value=2; Type='DWord';
           CISRef='18.4.3'; Description='Disable IPv6 source routing (highest protection)' }
        # ICMP Redirects
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect'; Value=0; Type='DWord';
           CISRef='18.4.4'; Description='Disable ICMP redirects' }
        # KeepAlive time
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='KeepAliveTime'; Value=300000; Type='DWord';
           CISRef='18.4.6'; Description='TCP KeepAlive time (300000 ms = 5 min)' }
        # NetBIOS over TCP/IP node type — P-node (no broadcast)
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NodeType'; Value=2; Type='DWord';
           CISRef='18.4.8'; Description='NetBIOS node type P-node (point-to-point)' }
        # Perform Router Discovery
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='PerformRouterDiscovery'; Value=0; Type='DWord';
           CISRef='18.4.9'; Description='Disable IRDP (router discovery)' }
        # SafeDllSearchMode
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name='SafeDllSearchMode'; Value=1; Type='DWord';
           CISRef='18.4.11'; Description='Enable Safe DLL search mode' }
        # Screen Saver Grace Period
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='ScreenSaverGracePeriod'; Value='0'; Type='String';
           CISRef='18.4.12'; Description='Screen saver grace period (0 seconds)' }
        # AutoPlay / AutoRun
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Value=255; Type='DWord';
           CISRef='18.9.8.1'; Description='Disable AutoRun for all drives' }
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Value=1; Type='DWord';
           CISRef='18.9.8.2'; Description='Disable AutoPlay for all drives' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Value=1; Type='DWord';
           CISRef='18.9.8.3'; Description='Disable AutoPlay for non-volume devices' }
        # PowerShell Script Block Logging
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Value=1; Type='DWord';
           CISRef='18.9.100.1'; Description='Enable PowerShell Script Block Logging' }
        # PowerShell Transcription
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'; Value=1; Type='DWord';
           CISRef='18.9.100.2'; Description='Enable PowerShell Transcription' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableInvocationHeader'; Value=1; Type='DWord';
           CISRef='18.9.100.3'; Description='Enable PowerShell Transcription invocation headers' }
        # WinRM hardening
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowBasic'; Value=0; Type='DWord';
           CISRef='18.9.102.1.1'; Description='WinRM Service: Disallow Basic authentication' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowUnencryptedTraffic'; Value=0; Type='DWord';
           CISRef='18.9.102.1.2'; Description='WinRM Service: Disallow unencrypted traffic' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowBasic'; Value=0; Type='DWord';
           CISRef='18.9.102.2.1'; Description='WinRM Client: Disallow Basic authentication' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowUnencryptedTraffic'; Value=0; Type='DWord';
           CISRef='18.9.102.2.2'; Description='WinRM Client: Disallow unencrypted traffic' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowDigest'; Value=0; Type='DWord';
           CISRef='18.9.102.2.3'; Description='WinRM Client: Disallow Digest authentication' }
        # Hardened UNC Paths
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\NETLOGON'; Value='RequireMutualAuthentication=1, RequireIntegrity=1'; Type='String';
           CISRef='18.5.14.1'; Description='Hardened UNC path: NETLOGON' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\SYSVOL'; Value='RequireMutualAuthentication=1, RequireIntegrity=1'; Type='String';
           CISRef='18.5.14.2'; Description='Hardened UNC path: SYSVOL' }
        # SmartScreen
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableSmartScreen'; Value=1; Type='DWord';
           CISRef='18.9.85.1.1'; Description='Enable Windows SmartScreen (Explorer)' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='ShellSmartScreenLevel'; Value='Block'; Type='String';
           CISRef='18.9.85.1.2'; Description='SmartScreen: Warn and prevent bypass' }
        # SEHOP (Structured Exception Handler Overwrite Protection)
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name='DisableExceptionChainValidation'; Value=0; Type='DWord';
           CISRef='18.3.4'; Description='Enable SEHOP (Structured Exception Handler Overwrite Protection)' }
        # Remote Desktop connection solicitation
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDenyTSConnections'; Value=0; Type='DWord';
           CISRef='18.9.65.1'; Description='Allow RDP connections (manage via firewall)' }
        # Disable Windows Search indexing of encrypted files
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowIndexingEncryptedStoresOrItems'; Value=0; Type='DWord';
           CISRef='18.9.67.3'; Description='Disable indexing of encrypted files' }
        # Credential Guard / Device Guard (if supported)
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='EnableVirtualizationBasedSecurity'; Value=1; Type='DWord';
           CISRef='18.8.5.1'; Description='Enable Virtualization Based Security' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='RequirePlatformSecurityFeatures'; Value=3; Type='DWord';
           CISRef='18.8.5.2'; Description='Require Secure Boot and DMA protection for VBS' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='LsaCfgFlags'; Value=1; Type='DWord';
           CISRef='18.8.5.3'; Description='Enable Credential Guard (with UEFI lock)' }
        # DNS Client - disable multicast name resolution (LLMNR)
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Value=0; Type='DWord';
           CISRef='18.5.4.2'; Description='Disable LLMNR (multicast name resolution)' }
        # MSS Legacy — disable WPAD
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'; Name='WpadOverride'; Value=1; Type='DWord';
           CISRef='18.4.14'; Description='Disable WPAD' }
    )

    foreach ($setting in $registryMisc) {
        Set-RegistryHarden @setting -Category 'RegistryMisc'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# 10. WINDOWS DEFENDER
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-CategoryExcluded 'Defender')) {
    Write-HardenLog '── Category: Windows Defender ──' -Status 'INFO'

    $defenderBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $defenderSettings = @(
        @{ Path=$defenderBase; Name='DisableAntiSpyware'; Value=0; Type='DWord';
           CISRef='18.9.47.1'; Description='Ensure Windows Defender is not disabled' }
        @{ Path="$defenderBase\Real-Time Protection"; Name='DisableRealtimeMonitoring'; Value=0; Type='DWord';
           CISRef='18.9.47.9.1'; Description='Enable real-time protection' }
        @{ Path="$defenderBase\Real-Time Protection"; Name='DisableBehaviorMonitoring'; Value=0; Type='DWord';
           CISRef='18.9.47.9.2'; Description='Enable behavior monitoring' }
        @{ Path="$defenderBase\Real-Time Protection"; Name='DisableScriptScanning'; Value=0; Type='DWord';
           CISRef='18.9.47.9.3'; Description='Enable script scanning' }
        @{ Path="$defenderBase\Real-Time Protection"; Name='DisableIOAVProtection'; Value=0; Type='DWord';
           CISRef='18.9.47.9.4'; Description='Enable scanning of downloaded files and attachments' }
        @{ Path=$defenderBase; Name='PUAProtection'; Value=1; Type='DWord';
           CISRef='18.9.47.11'; Description='Enable Potentially Unwanted Application (PUA) protection' }
        @{ Path="$defenderBase\SpyNet"; Name='SpyNetReporting'; Value=2; Type='DWord';
           CISRef='18.9.47.12.1'; Description='Enable cloud-delivered protection (MAPS: Advanced)' }
        @{ Path="$defenderBase\MpEngine"; Name='MpCloudBlockLevel'; Value=2; Type='DWord';
           CISRef='18.9.47.12.2'; Description='Cloud protection level: High' }
        @{ Path="$defenderBase\Scan"; Name='DisableRemovableDriveScanning'; Value=0; Type='DWord';
           CISRef='18.9.47.13.1'; Description='Enable scanning of removable drives' }
        @{ Path="$defenderBase\Scan"; Name='DisableEmailScanning'; Value=0; Type='DWord';
           CISRef='18.9.47.13.2'; Description='Enable email scanning' }
    )

    foreach ($setting in $defenderSettings) {
        Set-RegistryHarden @setting -Category 'Defender'
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# SUMMARY AND EXIT
# ═════════════════════════════════════════════════════════════════════════════
Get-ComplianceSummary

if ($ReportOnly) {
    Write-HardenLog 'Mode: REPORT ONLY — No changes were made.' -Status 'INFO'
}
else {
    Write-HardenLog 'Mode: REMEDIATION — Changes applied where needed.' -Status 'INFO'
    if ($script:ChangeCount -gt 0) {
        Write-HardenLog 'NOTE: Some changes may require a reboot to take effect.' -Status 'WARN'
    }
}

Write-HardenLog "Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Status 'INFO'

# Exit codes
if ($script:ErrorCount -gt 0) {
    exit 2    # Remediation errors occurred
}
elseif ($ReportOnly -and $script:FailCount -gt 0) {
    exit 3    # Non-compliant items found (ReportOnly)
}
else {
    exit 0    # Success
}
