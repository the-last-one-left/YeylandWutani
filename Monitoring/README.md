# Monitoring

PowerShell tools for proactive system monitoring, health checks, and alerting.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-SystemHealthReport.ps1` | Comprehensive health assessment: CPU, memory, disk, services, uptime, event logs, network connectivity |
| `Get-DiskSpaceMonitor.ps1` | Disk capacity monitoring with threshold alerts, growth trending, and days-to-full estimation |
| `Get-ServiceMonitor.ps1` | Critical service monitoring with auto-restart, dependency checking, and failure tracking |

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
```

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
| `-EmailTo` | Alert recipient email |
| `-SmtpServer` | SMTP server for alerts |
| `-Quiet` | Suppress console output |

---

## Requirements

- PowerShell 5.1+
- WinRM enabled for remote monitoring
- SMTP server for email alerts (optional)
- Administrative privileges for service restarts

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
