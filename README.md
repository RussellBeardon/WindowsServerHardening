# Harden-WindowsServer

A PowerShell script for hardening Windows Server configurations aligned with CIS Benchmarks. Covers ~175 controls across 10 categories and supports audit-only mode, selective category exclusion, and optional registry backup before applying changes.

**Supported OS:** Windows Server 2016, 2019, 2022 (build 14393+)

**Requirements:** Must be run as Administrator.

---

## Usage

```powershell
# Audit current compliance without making changes
.\Harden-WindowsServer.ps1 -ReportOnly

# Harden with registry backup
.\Harden-WindowsServer.ps1 -BackupRegistry

# Skip specific categories
.\Harden-WindowsServer.ps1 -ExcludeCategory 'TLS','Firewall'

# Skip firewall changes (e.g. third-party firewall in use)
.\Harden-WindowsServer.ps1 -SkipFirewall

# Combine options
.\Harden-WindowsServer.ps1 -BackupRegistry -ExcludeCategory 'TLS' -ReportOnly
```

---

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ReportOnly` | Switch | Audit-only mode — reports compliance status without making any changes |
| `-LogPath` | String | Path to the log file. Defaults to a timestamped file in the script directory |
| `-SkipFirewall` | Switch | Skip firewall profile changes (for environments using third-party firewalls) |
| `-SkipServices` | Switch | Skip service disablement controls |
| `-ExcludeCategory` | String[] | One or more category names to skip (see categories below) |
| `-BackupRegistry` | Switch | Export `HKLM\SYSTEM` and `HKLM\SOFTWARE` before making changes |

---

## Categories

| Category Name | CIS Section | Description |
|---------------|-------------|-------------|
| `AccountPolicies` | §1 | Password policy, lockout policy, Kerberos policy |
| `LocalPolicies` | §2.3 | Security options (interactive logon, network access, UAC, etc.) |
| `AuditPolicies` | §17 | Advanced audit policy (logon, account management, privilege use, etc.) |
| `Services` | — | Disable unnecessary/risky Windows services |
| `Firewall` | — | Windows Firewall profile settings (Domain, Private, Public) |
| `TLS` | — | TLS/SSL protocol and cipher suite hardening |
| `SMB` | — | SMB signing, SMBv1 disable, Null sessions |
| `RDP` | — | RDP encryption, NLA requirement, idle timeouts |
| `RegistryMisc` | — | Miscellaneous registry hardening (NTLMv2, LDAP, AutoRun, etc.) |
| `Defender` | — | Windows Defender / antimalware settings |

---

## Output

Each control produces one of the following statuses:

| Status | Meaning |
|--------|---------|
| `PASS` | Control is already compliant |
| `CHANGE` | Control was remediated |
| `FAIL` | Control is non-compliant (in `-ReportOnly` mode) |
| `SKIP` | Control was excluded via parameter |
| `ERROR` | An error occurred while checking or applying the control |

A compliance summary table is printed at the end, broken down by category with counts for each status. All output is also written to the log file.

---

## Potential Usability Impact

Some controls may disrupt existing functionality depending on the server's role and environment. Review these before running in production.

### High Impact — Could Break Functionality

| Control | Category | What Breaks | Mitigation |
|---------|----------|-------------|------------|
| W3SVC, IISADMIN, WMSvc disabled | `Services` | All IIS-hosted websites, web apps, and IIS remote management stop working | Use `-SkipServices` or `-ExcludeCategory Services` on web servers |
| FTPSVC disabled | `Services` | FTP server functionality stops | Use `-SkipServices` if FTP is required |
| TLS 1.0 / TLS 1.1 disabled | `TLS` | Legacy apps, older .NET (<4.6), ODBC/OLEDB connectors, and Java runtimes that haven't been updated to TLS 1.2+ will fail to connect | Audit application TLS support before applying; use `-ExcludeCategory TLS` if needed |
| SMB encryption required (`EncryptData=1`) | `SMB` | Clients on Windows 7 / Server 2008 R2 or older (SMB 2.x) are completely blocked from accessing shares | Use `-ExcludeCategory SMB` if legacy SMB clients are present |
| Credential Guard with UEFI lock (`LsaCfgFlags=1`) | `RegistryMisc` | Written to UEFI firmware — cannot be reversed by registry edit alone. Can break nested virtualisation (VMware, Hyper-V nested), and apps relying on certain Kerberos delegation or NTLM configurations. May fail silently on hardware without IOMMU | Verify VBS/Secure Boot hardware support before applying; test on a non-production system first |
| VBS requires Secure Boot + DMA (`RequirePlatformSecurityFeatures=3`) | `RegistryMisc` | Silently fails on hardware or VMs lacking IOMMU support, leaving an inconsistent configuration | Confirm IOMMU/DMA protection is available before applying |

### Medium Impact — Workflow Disruption

| Control | Category | What Breaks | Mitigation |
|---------|----------|-------------|------------|
| RDP drive redirection disabled (`fDisableCdm=1`) | `RDP` | Administrators and users cannot copy files to/from their local machine via RDP clipboard or drive mapping | Use `-ExcludeCategory RDP` if drive redirection is needed |
| RDP disconnected session timeout: 1 minute | `RDP` | Any brief network disruption terminates the RDP session and all processes running in it | Consider adjusting `MaxDisconnectionTime` to 5–15 min for the environment |
| Remote Assistance fully disabled | `RDP` | IT support staff cannot use Windows Remote Assistance for help sessions | Re-enable via Group Policy if Remote Assistance is part of the support workflow |
| UAC standard users: automatically deny elevation | `LocalPolicies` | Standard users receive a silent failure when any app requests elevation — no credential prompt is shown | Expected CIS behaviour; ensure users understand they need an admin to install software |
| WinRM Basic authentication disabled | `RegistryMisc` | Scripts, Ansible playbooks, or tools authenticating to WinRM with Basic auth will break | Migrate to Kerberos or certificate-based WinRM authentication |
| Network credential storage disabled (`DisableDomainCreds=1`) | `LocalPolicies` | Saved credentials in Credential Manager for mapped drives and network resources are no longer stored; users are re-prompted every session | Acceptable on servers; may affect scheduled tasks using saved credentials |

### Lower Impact — Worth Noting

| Control | Category | What Breaks | Mitigation |
|---------|----------|-------------|------------|
| LLMNR disabled | `RegistryMisc` | Unqualified hostname resolution fails in networks not fully covered by DNS (common with workgroups, some printers and IoT devices) | Ensure DNS covers all required hostnames before disabling |
| WPAD disabled | `RegistryMisc` | Automatic proxy detection via DHCP/DNS stops working | Configure proxy settings explicitly if a proxy is in use |
| Account lockout: 5 attempts / 15 min | `AccountPolicies` | Service accounts or users with stale saved credentials can trigger lockouts quickly | Ensure service accounts have their credentials updated before applying; consider lockout exclusions |
| SMB signing required (client + server) | `SMB` | Adds CPU overhead on high-throughput file servers | Negligible on modern hardware; monitor on older systems |
| LxssManager (WSL) disabled | `Services` | Windows Subsystem for Linux stops working | Use `-SkipServices` if WSL is used for admin tooling or development |

---

## Notes

- **Domain-joined servers:** The script warns if the server is domain-joined. On domain members, prefer Group Policy (GPO) for centralized management of these settings.
- **Registry backup:** When `-BackupRegistry` is used, registry exports are saved to a timestamped folder (`RegistryBackup_YYYYMMDD_HHmmss`) in the script directory.
- **Log files:** Logs are written to `HardenLog_YYYYMMDD_HHmmss.log` in the script directory unless `-LogPath` is specified.
- **Idempotent:** Safe to run multiple times. Controls already at the expected value are logged as `PASS` and not modified.
