# Monitoring

PowerShell tools for proactive system monitoring, health checks, performance analysis, and alerting for MSP environments.

## Available Scripts

### Core Infrastructure Monitoring

#### Get-SystemHealthReport.ps1
Comprehensive system health assessment covering CPU, memory, disk space, critical services, uptime, and event logs.

**What It Monitors:**
- CPU usage with configurable thresholds
- Memory utilization (physical and page file)
- Disk space across all drives
- Critical service status (RPC, DNS, Event Log, etc.)
- System uptime and last boot time
- Network connectivity (DNS, gateway, internet)
- Recent critical/error events from System and Application logs

**Key Features:**
- Multi-level threshold alerting (CPU, Memory, Disk)
- Remote computer monitoring via WinRM
- Multiple export formats (CSV, JSON, HTML, XML)
- Email notifications for warnings/critical issues
- Event log analysis with configurable time windows
- Network health verification
- Color-coded console output

**Usage Examples:**
```powershell
# Quick health check of local computer
.\Get-SystemHealthReport.ps1

# Remote server check with HTML report
.\Get-SystemHealthReport.ps1 -ComputerName "SERVER01" -ExportPath "C:\Reports\SERVER01_Health.html"

# Full diagnostics with event logs and network tests
.\Get-SystemHealthReport.ps1 -IncludeEventLogs -EventLogHours 48 -TestConnectivity

# Monitor with email alerts on warnings
.\Get-SystemHealthReport.ps1 `
    -CPUThreshold 80 `
    -MemoryThreshold 85 `
    -DiskThreshold 90 `
    -EmailTo "alerts@company.com" `
    -EmailFrom "monitor@company.com" `
    -SmtpServer "smtp.company.com"

# Monitor multiple servers and export consolidated report
Get-Content servers.txt | .\Get-SystemHealthReport.ps1 -WarningOnly -ExportPath "C:\Reports\MultiServer.csv"

# Custom thresholds for high-performance server
.\Get-SystemHealthReport.ps1 -CPUThreshold 95 -MemoryThreshold 95 -DiskThreshold 95
```

**Real-World Scenarios:**

**Scenario 1: Morning Health Check Routine**
```powershell
# Run against all critical servers
$servers = "DC01","DC02","FILESERVER01","APPSERVER01"
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"

$servers | .\Get-SystemHealthReport.ps1 `
    -IncludeEventLogs `
    -ExportPath "C:\Reports\DailyHealth_$timestamp.html"

# Review HTML report for any warnings
# Investigate issues identified in red/yellow
```

**Scenario 2: Proactive Server Performance Check**
```powershell
# Deep health check before maintenance window
.\Get-SystemHealthReport.ps1 `
    -ComputerName "SQLSERVER01" `
    -IncludeEventLogs `
    -EventLogHours 168 `
    -TestConnectivity `
    -ExportPath "C:\Reports\PreMaintenance_SQL.html"

# Verify no warnings before proceeding with updates
```

**Scenario 3: Client Onboarding Assessment**
```powershell
# New client - assess all servers
$newClientServers = Import-Csv "C:\Clients\NewClient_Servers.csv"

$newClientServers | ForEach-Object {
    .\Get-SystemHealthReport.ps1 `
        -ComputerName $_.ServerName `
        -IncludeEventLogs `
        -ExportPath "C:\Clients\NewClient\$($_.ServerName)_Baseline.html"
}

# Review baseline health before SLA commitment
```

**What Gets Checked:**

**System Resources:**
- CPU: Current load percentage with historical average
- Memory: Usage percentage, used/total GB, page file status
- Disk: All fixed drives with % used, free space, growth trends

**Critical Services:**
- DHCP Client, DNS Client, Event Log
- Server/Workstation services
- RPC, WinRM, Time Service
- Netlogon, NTDS (if domain controller)

**Network Health:**
- Internet connectivity (8.8.8.8)
- DNS server reachability
- Default gateway connectivity

**Event Logs:**
- System log critical/error events
- Application log critical/error events
- Configurable time window (default 24 hours)
- Error code identification and descriptions

---

#### Get-DiskSpaceMonitor.ps1
Proactive disk capacity monitoring with threshold alerting, growth trending, and capacity planning.

**Key Features:**
- Multi-level thresholds (Warning: 80%, Critical: 90% - configurable)
- Historical usage tracking and growth rate calculation
- Days-to-full estimation based on growth trends
- Network drive monitoring support
- Minimum size filtering to skip small drives
- Email alerts for Warning and/or Critical thresholds
- Multiple export formats with visual HTML reports

**Advanced Capabilities:**
- **Growth Rate Analysis**: Calculates GB/day growth from historical data
- **Capacity Forecasting**: Estimates days until drive is full
- **Historical Trending**: Tracks usage over time for capacity planning
- **Scheduled Monitoring**: Designed for Task Scheduler integration
- **Silent Mode**: Quiet operation for automated monitoring

**Usage Examples:**
```powershell
# Basic monitoring with default thresholds (80% warning, 90% critical)
.\Get-DiskSpaceMonitor.ps1

# Custom thresholds for specific environment
.\Get-DiskSpaceMonitor.ps1 -WarningThreshold 75 -CriticalThreshold 85

# Monitor with historical tracking and growth calculation
.\Get-DiskSpaceMonitor.ps1 `
    -HistoryPath "C:\Monitoring\DiskHistory.csv" `
    -CalculateGrowth

# Include network drives in monitoring
.\Get-DiskSpaceMonitor.ps1 -IncludeNetworkDrives -MinimumSizeGB 10

# Silent monitoring with email alerts
.\Get-DiskSpaceMonitor.ps1 `
    -Quiet `
    -HistoryPath "C:\Monitoring\History.csv" `
    -EmailTo "storage@company.com" `
    -EmailFrom "monitor@company.com" `
    -SmtpServer "smtp.company.com" `
    -AlertOnWarning

# Monitor multiple servers and export HTML dashboard
Get-Content servers.txt | .\Get-DiskSpaceMonitor.ps1 `
    -Quiet `
    -ExportPath "C:\Reports\DiskSpace_$(Get-Date -Format 'yyyyMMdd').html"
```

**Real-World Scenarios:**

**Scenario 1: Daily Automated Monitoring**
```powershell
# Create scheduled task to run daily
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument `
    "-ExecutionPolicy Bypass -File C:\Scripts\Get-DiskSpaceMonitor.ps1 -Quiet -HistoryPath C:\Monitoring\DiskHistory.csv -CalculateGrowth -EmailTo storage@company.com -EmailFrom monitor@company.com -SmtpServer smtp.company.com -AlertOnWarning"

$trigger = New-ScheduledTaskTrigger -Daily -At 8am

Register-ScheduledTask -TaskName "DiskSpaceMonitor" -Action $action -Trigger $trigger -RunLevel Highest

# Receives email only when thresholds breached
# Tracks growth trends for capacity planning
```

**Scenario 2: File Server Capacity Crisis**
```powershell
# File server running low on space
.\Get-DiskSpaceMonitor.ps1 `
    -ComputerName "FILESERVER01" `
    -WarningThreshold 85 `
    -CriticalThreshold 95 `
    -HistoryPath "C:\Monitoring\FileServer_History.csv" `
    -CalculateGrowth `
    -ExportPath "C:\Reports\FileServer_Capacity.html"

# Review HTML report:
# - Current usage: 92% (CRITICAL)
# - Growth rate: 2.5 GB/day
# - Days to full: 14 days
# - ACTION: Immediate cleanup or expansion needed
```

**Scenario 3: Monthly Capacity Planning**
```powershell
# End of month - generate capacity report
$servers = "DC01","DC02","FILESERVER01","SQLSERVER01"

$servers | .\Get-DiskSpaceMonitor.ps1 `
    -HistoryPath "C:\Monitoring\Monthly_DiskHistory.csv" `
    -CalculateGrowth `
    -ExportPath "C:\Reports\MonthlyCapacity_$(Get-Date -Format 'yyyy-MM').html"

# Review growth trends
# Identify servers needing expansion in next quarter
# Plan disk upgrades based on days-to-full estimates
```

**Scenario 4: SAN/Storage Array Monitoring**
```powershell
# Monitor LUNs presented to server
.\Get-DiskSpaceMonitor.ps1 `
    -MinimumSizeGB 100 `
    -WarningThreshold 70 `
    -CriticalThreshold 80 `
    -HistoryPath "C:\Monitoring\SAN_History.csv" `
    -CalculateGrowth

# Large drives get lower thresholds (more warning time)
# Skip small system drives (<100GB)
# Track growth for SAN capacity planning
```

**Email Alert Format:**
```
Subject: CRITICAL: Disk Space Alert - 2 drive(s) critical

Disk Space Alerts
═══════════════════════════════════════════════

CRITICAL ALERTS (2):
───────────────────────────────────────────────
Computer: FILESERVER01
  Drive: D: (UserData)
  Usage: 94% (45.2 GB free / 800 GB)
  Status: CRITICAL (>= 90%)
  Est. Full: 18 days

Computer: SQLSERVER01
  Drive: E: (Databases)
  Usage: 91% (134.5 GB free / 1500 GB)
  Status: CRITICAL (>= 90%)
  Est. Full: 67 days

WARNING ALERTS (1):
───────────────────────────────────────────────
Computer: DC01
  Drive: C: (System)
  Usage: 82% (18.3 GB free / 100 GB)
  Status: WARNING (>= 80%)
  Est. Full: 92 days

Generated: 2025-12-26 08:00:15

--
Yeyland Wutani LLC - Building Better Systems
```

**Historical Tracking Benefits:**
- Trend analysis for capacity planning
- Growth rate calculations (GB/day)
- Predictive alerting (days until full)
- Budget planning for storage upgrades
- SLA compliance reporting

---

#### Get-ServiceMonitor.ps1
Critical service monitoring with automatic restart, dependency checking, and failure tracking.

**Service Profiles:**
- **Essential**: Core Windows services (RPC, DNS, Event Log, DHCP, etc.)
- **DomainController**: DC-specific services (NTDS, Netlogon, DFSR, KDC, DNS)
- **FileServer**: File/Print services (Server, Workstation, DFS, DFSR)
- **WebServer**: IIS services (W3SVC, WAS, IISADMIN, FTP)
- **SQLServer**: SQL Server services (all instances, Agent, Browser)
- **All**: All services with StartType = Automatic

**Key Features:**
- Predefined service profiles for common server roles
- Custom service list support
- Automatic service restart with configurable retry attempts
- Service dependency verification and cascading start
- Startup type validation (Automatic/Manual/Disabled)
- Historical failure tracking
- Email alerting for failures and restarts
- Process ID and executable path reporting

**Advanced Capabilities:**
- **Auto-Restart**: Automatically restart stopped services
- **Max Retry**: Configurable retry attempts (default: 3)
- **Dependency Checking**: Start dependent services first
- **Startup Type Validation**: Alert on unexpected configurations
- **Historical Tracking**: Log all failures for pattern analysis

**Usage Examples:**
```powershell
# Monitor essential services on local computer
.\Get-ServiceMonitor.ps1 -Profile Essential

# Monitor specific services with auto-restart
.\Get-ServiceMonitor.ps1 `
    -ServiceName "Spooler","W32Time","WinRM" `
    -AutoRestart `
    -MaxRestartAttempts 3

# Domain controller monitoring with dependencies
.\Get-ServiceMonitor.ps1 `
    -Profile DomainController `
    -AutoRestart `
    -CheckDependencies

# Monitor file server with email alerts
.\Get-ServiceMonitor.ps1 `
    -ComputerName "FILESERVER01" `
    -Profile FileServer `
    -AutoRestart `
    -EmailTo "alerts@company.com" `
    -EmailFrom "monitor@company.com" `
    -SmtpServer "smtp.company.com" `
    -ExportPath "C:\Reports\Services.html"

# Monitor all automatic services (comprehensive)
.\Get-ServiceMonitor.ps1 `
    -Profile All `
    -AutoRestart `
    -HistoryPath "C:\Monitoring\ServiceHistory.csv"

# Silent monitoring for scheduled task
Get-Content servers.txt | .\Get-ServiceMonitor.ps1 `
    -Profile Essential `
    -Quiet `
    -AutoRestart `
    -HistoryPath "C:\Monitoring\ServiceFailures.csv"

# Web server monitoring with custom services
.\Get-ServiceMonitor.ps1 `
    -Profile WebServer `
    -ServiceName "AppPool_CustomApp","CustomWebService" `
    -AutoRestart `
    -CheckDependencies
```

**Real-World Scenarios:**

**Scenario 1: Automated 5-Minute Service Monitoring**
```powershell
# Create scheduled task for continuous monitoring
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument `
    "-ExecutionPolicy Bypass -File C:\Scripts\Get-ServiceMonitor.ps1 -Profile DomainController -AutoRestart -Quiet -HistoryPath C:\Monitoring\ServiceHistory.csv -EmailTo alerts@company.com -EmailFrom monitor@company.com -SmtpServer smtp.company.com"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask -TaskName "ServiceMonitor_DC" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest

# Monitors every 5 minutes
# Auto-restarts failed services
# Emails on failures
# Tracks historical failures
```

**Scenario 2: Post-Reboot Service Verification**
```powershell
# After server restart, verify all services started
.\Get-ServiceMonitor.ps1 `
    -Profile All `
    -AutoRestart `
    -CheckDependencies `
    -IncludeHealthy `
    -ExportPath "C:\Reports\PostReboot_Services.html"

# Review HTML report
# Identify services that failed to start
# Auto-restart attempts logged
# Dependency issues highlighted
```

**Scenario 3: Print Spooler Auto-Recovery**
```powershell
# Common issue - Print Spooler crashes
.\Get-ServiceMonitor.ps1 `
    -ServiceName "Spooler" `
    -AutoRestart `
    -MaxRestartAttempts 5 `
    -HistoryPath "C:\Monitoring\Spooler_History.csv"

# Monitors Print Spooler
# Auto-restarts up to 5 times
# Logs all failures for pattern analysis
# If 5 attempts fail, alerts for manual intervention
```

**Scenario 4: SQL Server Production Monitoring**
```powershell
# Critical SQL Server - aggressive monitoring
.\Get-ServiceMonitor.ps1 `
    -ComputerName "SQLPROD01" `
    -Profile SQLServer `
    -ServiceName "MSSQL`$INSTANCE2","SQLAGENT`$INSTANCE2" `
    -AutoRestart `
    -CheckDependencies `
    -EmailTo "dba@company.com","alerts@company.com" `
    -EmailFrom "sqlmonitor@company.com" `
    -SmtpServer "smtp.company.com"

# Monitors all SQL services including named instances
# Auto-restarts with dependency checking
# Immediate email to DBA team on failures
# Logs historical data for RCA
```

**Scenario 5: Multi-Server Role-Based Monitoring**
```powershell
# Different profiles for different server roles
$dcServers = "DC01","DC02"
$fileServers = "FILE01","FILE02","FILE03"
$webServers = "WEB01","WEB02"

# Domain Controllers
$dcServers | .\Get-ServiceMonitor.ps1 `
    -Profile DomainController `
    -AutoRestart `
    -CheckDependencies `
    -Quiet `
    -HistoryPath "C:\Monitoring\DC_Services.csv"

# File Servers
$fileServers | .\Get-ServiceMonitor.ps1 `
    -Profile FileServer `
    -AutoRestart `
    -Quiet `
    -HistoryPath "C:\Monitoring\FileServer_Services.csv"

# Web Servers
$webServers | .\Get-ServiceMonitor.ps1 `
    -Profile WebServer `
    -AutoRestart `
    -Quiet `
    -HistoryPath "C:\Monitoring\WebServer_Services.csv"

# Role-specific monitoring
# Separate history files for analysis
# Auto-restart enabled for all
```

**Service Profile Details:**

**Essential Profile:**
- RPC (Remote Procedure Call)
- DHCP Client
- DNS Client
- Event Log
- Server (LanmanServer)
- Workstation (LanmanWorkstation)
- Windows Time (W32Time)
- WinRM
- Plug and Play
- BITS

**DomainController Profile:**
- NTDS (Active Directory)
- Netlogon
- DFSR (DFS Replication)
- DNS Server
- KDC (Kerberos)
- Windows Time (W32Time)
- Event Log
- RPC
- Intersite Messaging

**FileServer Profile:**
- Server (LanmanServer)
- Workstation (LanmanWorkstation)
- DFS Namespace
- DFS Replication
- SMB 1.0/2.0 services
- Security Accounts Manager
- Cryptographic Services

**WebServer Profile:**
- W3SVC (World Wide Web)
- WAS (Process Activation)
- IISADMIN
- W3C Logging
- FTP Service

**SQLServer Profile:**
- MSSQLSERVER (default instance)
- SQL Server Agent
- SQL Browser
- Full-text Filter Daemon
- CEIP/Telemetry

**Auto-Restart Workflow:**
1. Detect service stopped (should be running)
2. Check dependencies and start if needed
3. Attempt service start (up to MaxRestartAttempts)
4. Wait 3 seconds after start command
5. Verify service is running
6. If failed, wait 5 seconds and retry
7. Log success/failure to history
8. Send email notification

**Email Alert Format:**
```
Subject: Service Alert - 2 service(s) require attention

Service Monitoring Alerts
═══════════════════════════════════════════════

FAILED SERVICES (1):
───────────────────────────────────────────────
Computer: DC01
  Service: Active Directory Domain Services (NTDS)
  Status: Stopped - Failed to Restart
  Action: Restart failed after 3 attempts

RESTARTED SERVICES (1):
───────────────────────────────────────────────
Computer: FILESERVER01
  Service: DFS Replication (DFSR)
  Action: Restarted (attempt 2)
  Status: Now Running

Generated: 2025-12-26 08:15:22

--
Yeyland Wutani LLC - Building Better Systems
```

---

## Common Workflows

### Daily Health Check Routine
```powershell
# Morning routine - check all critical infrastructure
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"

# System health across all servers
Get-Content "C:\Servers\Production.txt" | .\Get-SystemHealthReport.ps1 `
    -IncludeEventLogs `
    -EventLogHours 24 `
    -WarningOnly `
    -ExportPath "C:\Reports\Daily\Health_$timestamp.html"

# Disk space monitoring
Get-Content "C:\Servers\Production.txt" | .\Get-DiskSpaceMonitor.ps1 `
    -HistoryPath "C:\Monitoring\DiskHistory.csv" `
    -CalculateGrowth `
    -ExportPath "C:\Reports\Daily\DiskSpace_$timestamp.html"

# Service status check
Get-Content "C:\Servers\Production.txt" | .\Get-ServiceMonitor.ps1 `
    -Profile Essential `
    -AutoRestart `
    -HistoryPath "C:\Monitoring\ServiceHistory.csv" `
    -ExportPath "C:\Reports\Daily\Services_$timestamp.html"
```

### Client Monthly Report
```powershell
# Generate monthly health report for client
$clientServers = Import-Csv "C:\Clients\ABC_Corp\Servers.csv"
$month = Get-Date -Format "yyyy-MM"

foreach ($server in $clientServers) {
    # Comprehensive health check
    .\Get-SystemHealthReport.ps1 `
        -ComputerName $server.Name `
        -IncludeEventLogs `
        -EventLogHours 720 `
        -TestConnectivity `
        -ExportPath "C:\Clients\ABC_Corp\Reports\$month\$($server.Name)_Health.html"
    
    # Disk capacity review
    .\Get-DiskSpaceMonitor.ps1 `
        -ComputerName $server.Name `
        -HistoryPath "C:\Clients\ABC_Corp\Monitoring\DiskHistory.csv" `
        -CalculateGrowth `
        -ExportPath "C:\Clients\ABC_Corp\Reports\$month\$($server.Name)_Capacity.html"
}

# Email consolidated report to client
```

### Emergency Troubleshooting
```powershell
# Server performance issue reported
$server = "PROBLEMSERVER01"

# Quick health snapshot
.\Get-SystemHealthReport.ps1 `
    -ComputerName $server `
    -IncludeEventLogs `
    -EventLogHours 72 `
    -TestConnectivity `
    -ExportPath "C:\Troubleshooting\$server_Emergency.html"

# Check for service failures
.\Get-ServiceMonitor.ps1 `
    -ComputerName $server `
    -Profile All `
    -IncludeHealthy `
    -ExportPath "C:\Troubleshooting\$server_Services.html"

# Verify disk space not causing issues
.\Get-DiskSpaceMonitor.ps1 `
    -ComputerName $server `
    -IncludeNetworkDrives

# Review HTML reports for root cause
```

### Scheduled Automated Monitoring
```powershell
# Create comprehensive monitoring tasks

# Task 1: Hourly service monitoring
$action1 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument `
    "-ExecutionPolicy Bypass -File C:\Scripts\Get-ServiceMonitor.ps1 -Profile Essential -AutoRestart -Quiet -HistoryPath C:\Monitoring\ServiceHistory.csv -EmailTo alerts@company.com -EmailFrom monitor@company.com -SmtpServer smtp.company.com"

$trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 1) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask -TaskName "Hourly_ServiceMonitor" -Action $action1 -Trigger $trigger1 -RunLevel Highest

# Task 2: Daily health and disk monitoring
$action2 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument `
    "-ExecutionPolicy Bypass -File C:\Scripts\Run-DailyMonitoring.ps1"

$trigger2 = New-ScheduledTaskTrigger -Daily -At 7am

Register-ScheduledTask -TaskName "Daily_HealthMonitor" -Action $action2 -Trigger $trigger2 -RunLevel Highest

# Run-DailyMonitoring.ps1 contains the daily workflow above
```

---

## Environment Considerations

**MSP Multi-Client Environment:**
- Scripts support remote monitoring via WinRM
- Works across different client domains
- No hardcoded values - all dynamic
- Compatible with typical MSP client infrastructure
- Supports scheduled task automation for 24/7 monitoring

**Typical Client Configurations:**
- Small clients: 2-5 servers (domain controller, file server, app server)
- Medium clients: 10-20 servers (multiple DCs, clustered services)
- Large clients: 50+ servers (geographically distributed, complex infrastructure)
- All scripts scale from single server to hundreds

**WinRM Requirements:**
For remote monitoring, ensure WinRM is configured:
```powershell
# On target servers
Enable-PSRemoting -Force

# Test connectivity from monitoring server
Test-WSMan -ComputerName "TARGETSERVER"
```

---

## Output Format Examples

### Console Output (Get-SystemHealthReport.ps1)
```
═══════════════════════════════════════════════════════════
 System Health Report: SERVER01
═══════════════════════════════════════════════════════════
Timestamp:       2025-12-26 08:15:22
Overall Health:  Warning
Warnings:        2

--- CPU ---
Usage:           45.2%

--- Memory ---
Usage:           87.5%
Used:            28.0 GB / 32.0 GB

--- Disk Space ---
C: 65.2% used (34.8 GB free / 100 GB total)
D: 92.1% used (63.2 GB free / 800 GB total)
E: 45.3% used (820.5 GB free / 1500 GB total)

--- Critical Services ---
Running:         9 / 10 services
Stopped:         1
  - DFS Replication: Stopped

--- System Uptime ---
Last Boot:       2025-12-20 06:23:15
Uptime:          6.07 days

--- Recent Event Log Issues (Last 24 hours) ---
Critical Events: 0
Error Events:    5

Most Recent Issues:
[2025-12-26 07:45:12] Event ID 4013
  The DFS Replication service stopped replication on volume...
═══════════════════════════════════════════════════════════
```

### HTML Report Features
- **Dashboard Summary**: Visual stats with color-coded metrics
- **Progress Bars**: Visual representation of disk usage
- **Sortable Tables**: Click column headers to sort
- **Color Coding**: Green (healthy), Yellow (warning), Red (critical)
- **Responsive Design**: Works on mobile devices
- **Yeyland Wutani Branding**: Orange/grey color scheme

---

## Requirements

### Software
- **PowerShell 5.1 or later**
- **WMI/CIM access** to target computers
- **WinRM enabled** for remote monitoring
- **SMTP server** for email alerting (optional)

### Permissions
- **Local monitoring**: Standard user (read-only metrics)
- **Remote monitoring**: Domain Admin or delegated WinRM permissions
- **Service restart**: Local Administrator or Domain Admin
- **Event log access**: Event Log Readers group or higher

### Network
- **WinRM**: TCP 5985 (HTTP) or 5986 (HTTPS)
- **ICMP**: For Test-Connection (ping)
- **SMTP**: Configured port (typically 25, 587, or 465)
- **Firewall**: Allow WMI/CIM and WinRM from monitoring server

---

## Best Practices

### Monitoring Strategy
- **Frequency**: Services (5-15 min), Disk (daily), Health (daily/hourly)
- **Thresholds**: Adjust based on baseline measurements
- **History**: Retain 90-365 days for trending
- **Alerting**: Critical issues = immediate, Warnings = daily digest
- **Escalation**: Failed auto-restart = page on-call engineer

### Data Management
- **Export Path**: Use dated folders (C:\Reports\2025\12\)
- **History Files**: Monthly rotation (DiskHistory_2025-12.csv)
- **Log Cleanup**: Purge exports older than retention period
- **Compression**: Archive old reports to save space

### Scheduled Tasks
- **Run As**: Service account with monitoring permissions
- **Error Handling**: Configure task to continue on failure
- **Logging**: Enable task history for troubleshooting
- **Timeout**: Set reasonable execution time limits
- **Notifications**: Email on task failure (separate from script alerts)

### Email Alerting
- **Distribution Lists**: Use groups, not individual addresses
- **Subject Lines**: Include severity and computer name
- **Body Format**: Clear, actionable information
- **Frequency**: Avoid alert storms (group similar issues)
- **Testing**: Verify email delivery before production

### Historical Analysis
```powershell
# Analyze disk growth over time
$history = Import-Csv "C:\Monitoring\DiskHistory.csv"
$d_drive = $history | Where-Object { $_.Drive -eq "D:" -and $_.ComputerName -eq "FILESERVER01" }
$d_drive | Select-Object Timestamp, PercentUsed, UsedGB | Format-Table

# Service failure patterns
$failures = Import-Csv "C:\Monitoring\ServiceHistory.csv"
$failures | Group-Object ServiceName | Sort-Object Count -Descending | Select-Object Count, Name

# Identify chronic issues
```

---

## Troubleshooting

### WinRM Connection Failures
```powershell
# Test WinRM connectivity
Test-WSMan -ComputerName "TARGETSERVER"

# Enable PSRemoting on target
Enable-PSRemoting -Force

# Check firewall rules
Get-NetFirewallRule -DisplayName "Windows Remote Management*"

# Verify WinRM service
Get-Service WinRM
```

### Email Delivery Issues
```powershell
# Test SMTP connectivity
Test-NetConnection -ComputerName "smtp.company.com" -Port 25

# Test send email
Send-MailMessage -To "test@company.com" -From "test@company.com" -Subject "Test" -Body "Test" -SmtpServer "smtp.company.com"

# Check SMTP authentication if required
```

### Permission Errors
```powershell
# Verify current user permissions
whoami /groups

# Check WinRM permissions
Get-PSSessionConfiguration

# Test remote command execution
Invoke-Command -ComputerName "TARGETSERVER" -ScriptBlock { Get-Service }
```

### High Memory Usage
```powershell
# For large environments, use -Quiet to reduce console overhead
# Process servers in batches
$allServers | ForEach-Object -Parallel {
    .\Get-SystemHealthReport.ps1 -ComputerName $_ -Quiet
} -ThrottleLimit 10
```

---

## Integration with RMM/PSA Tools

These scripts can integrate with common MSP tools:

**ConnectWise Automate:**
- Run as external scripts
- Store results in EDF (Extra Data Fields)
- Trigger tickets on failures

**Datto RMM:**
- Execute as monitors
- Parse output for component status
- Create alerts based on results

**N-able N-central:**
- Deploy as automation policies
- Import results into custom metrics
- Configure alert triggers

**PowerShell RMM (PSA):**
- Native PowerShell integration
- Import functions into modules
- Schedule via RMM task scheduler

---

## Support & Contributions

**Yeyland Wutani - Building Better Systems**

These scripts are maintained for MSP operations with focus on:
- Proactive monitoring and alerting
- Automated remediation (service restarts)
- Capacity planning and trending
- Multi-client scalability
- Email notifications for critical issues

For issues or enhancements, document findings with:
- Environment details (server roles, OS versions)
- Error messages or unexpected behavior
- Expected vs actual results
- Monitoring frequency and thresholds used

---

[← Back to Main Repository](../README.md)
