# Monitoring

PowerShell tools for proactive system monitoring, health checks, and alerting.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-SystemHealthReport.ps1` | Comprehensive health assessment: CPU, memory, disk, services, uptime, event logs, network connectivity — with threshold-based alerting and email notifications |
| `Get-DiskSpaceMonitor.ps1` | Disk capacity monitoring with Warning/Critical thresholds, historical trend tracking, growth rate analysis, and email alerts |
| `Get-ServiceMonitor.ps1` | Critical service monitoring with auto-restart, dependency checking, predefined server-role profiles, and failure history tracking |
| `Invoke-SystemOnlineMonitor.ps1` | Monitor system availability with Microsoft Graph API email alerts, port scanning, and detailed system information collection |

---

## Get-SystemHealthReport.ps1

Collects CPU, memory, disk, service status, uptime, network connectivity, and recent event log errors in a single pass. Designed for both ad-hoc troubleshooting and scheduled monitoring runs. Supports pipeline input for multi-server sweeps.

```powershell
# Health check on the local machine
.\Get-SystemHealthReport.ps1

# Check a remote server and export an HTML report
.\Get-SystemHealthReport.ps1 -ComputerName "SERVER01" -ExportPath "C:\Reports\Health.html"

# Include 48 hours of event logs, show only items exceeding thresholds
.\Get-SystemHealthReport.ps1 -IncludeEventLogs -EventLogHours 48 -WarningOnly

# Custom thresholds — alert at 70% CPU / 85% memory / 80% disk
.\Get-SystemHealthReport.ps1 -CPUThreshold 70 -MemoryThreshold 85 -DiskThreshold 80

# Test network connectivity to critical endpoints during health check
.\Get-SystemHealthReport.ps1 -ComputerName "SERVER01" -TestConnectivity

# Email results when any threshold is exceeded
.\Get-SystemHealthReport.ps1 `
    -ComputerName "SERVER01" `
    -EmailTo "alerts@contoso.com" `
    -EmailFrom "monitor@contoso.com" `
    -SmtpServer "smtp.contoso.com"

# Multi-server sweep from a text file — consolidated CSV report
Get-Content servers.txt | .\Get-SystemHealthReport.ps1 -WarningOnly -ExportPath "C:\Reports\AllServers.csv"
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-ComputerName` | Local machine | Target computer(s) — supports pipeline |
| `-CPUThreshold` | 85% | CPU usage % to trigger warning |
| `-MemoryThreshold` | 90% | Memory usage % to trigger warning |
| `-DiskThreshold` | 85% | Disk usage % to trigger warning |
| `-ExportPath` | Console only | Output file (CSV, JSON, HTML, or XML) |
| `-IncludeEventLogs` | $false | Include recent System/Application errors |
| `-EventLogHours` | 24 | Hours of event log history to analyze |
| `-TestConnectivity` | $false | Test connectivity to DNS, gateway, internet |
| `-WarningOnly` | $false | Suppress healthy items from output |

---

## Get-DiskSpaceMonitor.ps1

Monitors local and network drives with two-level thresholds (Warning/Critical), tracks historical usage to CSV for growth trending, and sends email alerts. Designed to run as a scheduled task for proactive capacity management.

```powershell
# Monitor local drives on the current machine
.\Get-DiskSpaceMonitor.ps1

# Monitor a remote server with custom thresholds
.\Get-DiskSpaceMonitor.ps1 -ComputerName "SERVER01" -WarningThreshold 75 -CriticalThreshold 85

# Include network-mapped drives, export HTML report
.\Get-DiskSpaceMonitor.ps1 -IncludeNetworkDrives -ExportPath "C:\Reports\DiskSpace.html"

# Track historical usage and calculate growth rate
.\Get-DiskSpaceMonitor.ps1 -HistoryPath "C:\Monitoring\DiskHistory.csv" -CalculateGrowth

# Email alerts on Critical threshold only (default)
.\Get-DiskSpaceMonitor.ps1 `
    -ComputerName "SERVER01" `
    -EmailTo "alerts@contoso.com" `
    -EmailFrom "monitor@contoso.com" `
    -SmtpServer "smtp.contoso.com"

# Email on Warning and Critical
.\Get-DiskSpaceMonitor.ps1 `
    -EmailTo "alerts@contoso.com" -EmailFrom "monitor@contoso.com" -SmtpServer "smtp.contoso.com" `
    -AlertOnWarning

# Silent multi-server sweep (scheduled task friendly)
Get-Content servers.txt | .\Get-DiskSpaceMonitor.ps1 -Quiet -ExportPath "C:\Reports\AllServers.csv"
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-ComputerName` | Local machine | Target computer(s) — supports pipeline |
| `-WarningThreshold` | 80% | Disk used % for Warning alert |
| `-CriticalThreshold` | 90% | Disk used % for Critical alert |
| `-MinimumSizeGB` | 1 GB | Skip drives smaller than this |
| `-IncludeNetworkDrives` | $false | Include network-mapped drives |
| `-HistoryPath` | None | CSV path for historical trend tracking |
| `-CalculateGrowth` | $false | Compute growth rate from history (requires `-HistoryPath`) |
| `-AlertOnWarning` | $false | Send email on Warning threshold (default: Critical only) |
| `-Quiet` | $false | Suppress console output |

---

## Get-ServiceMonitor.ps1

Monitors predefined service profiles for common server roles, custom service lists, or all automatic services. Automatically restarts stopped services and tracks failure history. Validates service dependencies before restart attempts.

```powershell
# Monitor essential Windows services on the local machine
.\Get-ServiceMonitor.ps1 -Profile Essential

# Monitor Domain Controller services with auto-restart
.\Get-ServiceMonitor.ps1 -Profile DomainController -AutoRestart

# Monitor DC services, check dependencies, restart failures, limit to 2 attempts
.\Get-ServiceMonitor.ps1 -Profile DomainController -CheckDependencies -AutoRestart -MaxRestartAttempts 2

# Monitor specific services by name
.\Get-ServiceMonitor.ps1 -ServiceName "Spooler","W32Time" -AutoRestart

# Monitor a remote file server, export HTML report
.\Get-ServiceMonitor.ps1 -ComputerName "SERVER01" -Profile FileServer -ExportPath "C:\Reports\Services.html"

# Monitor all automatic services, email on failures
.\Get-ServiceMonitor.ps1 -Profile All `
    -EmailTo "alerts@contoso.com" `
    -EmailFrom "monitor@contoso.com" `
    -SmtpServer "smtp.contoso.com"

# Silent multi-server monitoring with failure history
Get-Content servers.txt | .\Get-ServiceMonitor.ps1 -Profile Essential -Quiet -HistoryPath "C:\Monitoring\ServiceHistory.csv"
```

**Service Profiles:**

| Profile | Services Monitored |
|---------|-------------------|
| `Essential` | RPC, DNS Client, Event Log, Server, Workstation, WinRM, W32Time |
| `DomainController` | NTDS, Netlogon, DFSR, DNS, KDC, W32Time |
| `FileServer` | Server, Workstation, DFS Namespace, DFS Replication |
| `WebServer` | W3SVC, WAS, IISADMIN |
| `SQLServer` | MSSQLSERVER, SQL Agent, SQL Browser |
| `All` | All services with `StartType = Automatic` |

---

## Invoke-SystemOnlineMonitor.ps1

Detects when specified systems come online and sends a detailed report via Microsoft Graph API email — including open TCP ports, OS info, last logged-on user, hardware details, and network config. Designed for security monitoring and asset tracking. Built-in deduplication prevents repeat alerts for the same system within 24 hours.

```powershell
# Monitor two workstations, email via Graph API when online
.\Invoke-SystemOnlineMonitor.ps1 `
    -ComputerName "WORKSTATION01","WORKSTATION02" `
    -TenantId "12345678-1234-1234-1234-123456789012" `
    -ClientId "abcdef12-3456-7890-abcd-ef1234567890" `
    -ClientSecret "your_client_secret" `
    -EmailTo "security@contoso.com" `
    -EmailFrom "monitoring@contoso.com"

# Monitor from a file, scan custom ports, export JSON log
Get-Content "C:\MonitorList.txt" | .\Invoke-SystemOnlineMonitor.ps1 `
    -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
    -EmailTo "alerts@contoso.com" -EmailFrom "monitor@contoso.com" `
    -PortsToScan @(22,80,443,3389,5985) `
    -ExportPath "C:\Logs\OnlineReport.json"

# Track missing/stolen laptops — alert security team and manager
.\Invoke-SystemOnlineMonitor.ps1 `
    -ComputerName "LAPTOP-STOLEN","LAPTOP-MISSING" `
    -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
    -EmailTo "security-team@contoso.com","manager@contoso.com" `
    -EmailFrom "security-alerts@contoso.com"

# Set up as a scheduled task running every 15 minutes
$action  = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Invoke-SystemOnlineMonitor.ps1" -ComputerName "TARGET-PC" -TenantId "..." -ClientId "..." -ClientSecret "..." -EmailTo "alerts@company.com" -EmailFrom "monitor@company.com"'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15) `
    -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "SystemOnlineMonitor" -Action $action -Trigger $trigger -RunLevel Highest
```

**Graph API Setup:**

1. Register an Azure App in Entra ID
2. Add `Microsoft Graph > Application > Mail.Send` permission
3. Grant admin consent
4. Create a client secret and note the value, Client ID, and Tenant ID

---

## Requirements

- PowerShell 5.1+
- WinRM enabled for remote monitoring (`Get-SystemHealthReport`, `Get-DiskSpaceMonitor`, `Get-ServiceMonitor`)
- Administrator privileges for service restarts (`Get-ServiceMonitor`)
- Microsoft Graph API app registration for Graph-based alerts (`Invoke-SystemOnlineMonitor`)
- SMTP server for SMTP-based alerts (`Get-SystemHealthReport`, `Get-DiskSpaceMonitor`, `Get-ServiceMonitor`)

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
