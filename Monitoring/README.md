# Monitoring

PowerShell tools for proactive system monitoring, health checks, and alerting.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-SystemHealthReport.ps1` | Comprehensive health assessment: CPU, memory, disk, services, uptime, event logs, network connectivity |
| `Get-DiskSpaceMonitor.ps1` | Disk capacity monitoring with threshold alerts, growth trending, and days-to-full estimation |
| `Get-ServiceMonitor.ps1` | Critical service monitoring with auto-restart, dependency checking, and failure tracking |
| `Invoke-SystemOnlineMonitor.ps1` | Monitor system availability with Microsoft Graph API email alerts, port scanning, and detailed system information |

---

## Usage Examples

```powershell
# System health check with event logs
.\Get-SystemHealthReport.ps1 -ComputerName "SERVER01" -IncludeEventLogs -ExportPath "C:\Reports\Health.html"

# Disk monitoring with growth analysis
.\Get-DiskSpaceMonitor.ps1 -HistoryPath "C:\Monitoring\DiskHistory.csv" -CalculateGrowth

# Disk alerts via email
.\Get-DiskSpaceMonitor.ps1 -EmailTo "alerts@company.com" -SmtpServer "smtp.company.com" -AlertOnWarning

# Service monitoring with auto-restart
.\Get-ServiceMonitor.ps1 -Profile DomainController -AutoRestart

# Monitor specific services
.\Get-ServiceMonitor.ps1 -ServiceName "Spooler","W32Time" -AutoRestart -MaxRestartAttempts 3

# Multi-server monitoring
Get-Content servers.txt | .\Get-SystemHealthReport.ps1 -WarningOnly -ExportPath "C:\Reports\AllServers.html"

# Monitor system availability and send Graph API alerts
.\Invoke-SystemOnlineMonitor.ps1 -ComputerName "WORKSTATION01","WORKSTATION02" `
    -TenantId "12345678-1234-1234-1234-123456789012" `
    -ClientId "abcdef12-3456-7890-abcd-ef1234567890" `
    -ClientSecret "your_client_secret" `
    -EmailTo "security@company.com" `
    -EmailFrom "monitoring@company.com"

# Monitor from file with custom ports and JSON export
Get-Content "C:\MonitorList.txt" | .\Invoke-SystemOnlineMonitor.ps1 `
    -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
    -EmailTo "alerts@company.com" -EmailFrom "monitor@company.com" `
    -PortsToScan @(22,80,443,3389,5985) `
    -ExportPath "C:\Logs\OnlineReport.json"
```

---

## Microsoft Graph API Setup

The `Invoke-SystemOnlineMonitor.ps1` script requires Microsoft Graph API authentication for email alerts:

1. **Register Azure App** in Entra ID (Azure AD)
2. **Add API Permission**: Microsoft Graph > Application > Mail.Send
3. **Grant admin consent** for the permission
4. **Create client secret** and note the value
5. **Note Application ID** (Client ID) and Directory ID (Tenant ID)

### Security Best Practices

- Store credentials in Azure Key Vault or encrypted files
- Use least-privilege API permissions
- Restrict script access to authorized personnel
- Consider Managed Identity for Azure automation
- Audit email recipients regularly

---

## Service Profiles

| Profile | Services Monitored |
|---------|-------------------|
| Essential | RPC, DNS Client, Event Log, Server, Workstation, WinRM, W32Time |
| DomainController | NTDS, Netlogon, DFSR, DNS, KDC, W32Time |
| FileServer | Server, Workstation, DFS Namespace, DFS Replication |
| WebServer | W3SVC, WAS, IISADMIN |
| SQLServer | MSSQLSERVER, SQL Agent, SQL Browser |

---

## Common Parameters

| Parameter | Description |
|-----------|-------------|
| `-ComputerName` | Target computer (supports pipeline) |
| `-ExportPath` | Output file (CSV, JSON, HTML, XML) |
| `-EmailTo` | Alert recipient email (Graph API or SMTP) |
| `-SmtpServer` | SMTP server for alerts |
| `-PortsToScan` | TCP ports to scan (System Online Monitor) |
| `-IncludeOfflineSystems` | Include offline systems in reports |
| `-Quiet` | Suppress console output |

---

## Requirements

- PowerShell 5.1+
- WinRM enabled for remote monitoring
- SMTP server for email alerts (optional)
- Microsoft Graph API credentials for Graph-based alerts (Invoke-SystemOnlineMonitor.ps1)
- Administrative privileges for service restarts
- Network access to monitored systems

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
