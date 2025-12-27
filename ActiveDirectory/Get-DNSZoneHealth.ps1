<#
.SYNOPSIS
    Performs comprehensive DNS zone health discovery and provides remediation options.

.DESCRIPTION
    This script analyzes AD-integrated DNS zones for common health issues including:
    - Zone configuration and replication scope analysis
    - Aging and scavenging settings verification
    - Stale record identification and cleanup
    - Orphaned PTR record detection (no matching A record)
    - Duplicate record identification
    - Critical AD DNS record verification (_msdcs, SRV records)
    - DNS server scavenging configuration
    - DCDiag DNS test integration
    
    Supports both discovery-only mode and interactive remediation with WhatIf support.

.PARAMETER DnsServer
    Target DNS server to analyze. Defaults to local domain controller.

.PARAMETER ZoneName
    Specific zone to analyze. If not specified, analyzes all AD-integrated zones.

.PARAMETER StaleThresholdDays
    Number of days without update to consider a record stale. Default: 14 days.

.PARAMETER IncludeReverseZones
    Include reverse lookup zones in the analysis.

.PARAMETER Remediate
    Enable interactive remediation mode for discovered issues.

.PARAMETER ExportPath
    Path to export HTML report. If not specified, opens report in browser.

.PARAMETER SkipDCDiag
    Skip DCDiag DNS tests (faster execution).

.EXAMPLE
    .\Get-DNSZoneHealth.ps1
    Runs discovery on all AD-integrated zones on the local DNS server.

.EXAMPLE
    .\Get-DNSZoneHealth.ps1 -ZoneName "contoso.com" -StaleThresholdDays 30 -Remediate
    Analyzes specific zone with 30-day stale threshold and enables remediation.

.EXAMPLE
    .\Get-DNSZoneHealth.ps1 -ExportPath "C:\Reports\DNSHealth.html" -IncludeReverseZones
    Exports full report including reverse zones to specified path.

.NOTES
    Author: Yeyland Wutani LLC - Building Better Systems
    Requires: DnsServer module, Domain Admin or DNS Admin rights
    Version: 1.0
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$DnsServer = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [string]$ZoneName,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,365)]
    [int]$StaleThresholdDays = 14,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeReverseZones,
    
    [Parameter(Mandatory=$false)]
    [switch]$Remediate,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDCDiag
)

#region Script Configuration
$script:CompanyName = "Yeyland Wutani LLC"
$script:Tagline = "Building Better Systems"
$script:Version = "1.0"
$script:PrimaryColor = "#FF6600"
$script:SecondaryColor = "#6B7280"

$script:HealthReport = @{
    ServerInfo = $null
    Zones = @()
    StaleRecords = @()
    OrphanedPTRs = @()
    DuplicateRecords = @()
    MissingCriticalRecords = @()
    AgingIssues = @()
    DCDiagResults = @()
    Summary = @{
        TotalZones = 0
        HealthyZones = 0
        ZonesWithIssues = 0
        TotalStaleRecords = 0
        TotalOrphanedPTRs = 0
        TotalDuplicates = 0
        MissingCritical = 0
        OverallScore = 100
    }
    Timestamp = Get-Date
}

$script:RemediationLog = @()
#endregion

#region Helper Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR")]
        [string]$Level = "INFO"
    )
    
    $colors = @{
        "INFO" = "Gray"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
    }
    
    $prefix = @{
        "INFO" = "[*]"
        "SUCCESS" = "[+]"
        "WARNING" = "[!]"
        "ERROR" = "[-]"
    }
    
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Show-Banner {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor DarkYellow
    Write-Host "        DNS Zone Health Discovery v$($script:Version)" -ForegroundColor DarkYellow
    Write-Host "        $($script:CompanyName) - $($script:Tagline)" -ForegroundColor DarkYellow
    Write-Host "  ======================================================" -ForegroundColor DarkYellow
    Write-Host ""
}

function Test-DnsServerModule {
    try {
        Import-Module DnsServer -ErrorAction Stop
        return $true
    } catch {
        Write-Log "DnsServer module not available. Install RSAT DNS Server Tools." -Level "ERROR"
        return $false
    }
}

function Get-ScoreColor {
    param([int]$Score)
    if ($Score -ge 90) { return "#22C55E" }      # Green
    elseif ($Score -ge 70) { return "#EAB308" }  # Yellow
    elseif ($Score -ge 50) { return "#F97316" }  # Orange
    else { return "#EF4444" }                     # Red
}

function Get-StatusBadge {
    param(
        [string]$Status,
        [string]$Color
    )
    return "<span style='background-color: $Color; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;'>$Status</span>"
}
#endregion

#region Discovery Functions
function Get-DnsServerInfo {
    param([string]$Server)
    
    Write-Log "Gathering DNS server information from $Server..." -Level "INFO"
    
    try {
        $serverSettings = Get-DnsServer -ComputerName $Server -ErrorAction Stop
        $scavengingSettings = Get-DnsServerScavenging -ComputerName $Server -ErrorAction Stop
        
        $info = [PSCustomObject]@{
            ServerName = $Server
            ScavengingState = $scavengingSettings.ScavengingState
            ScavengingInterval = $scavengingSettings.ScavengingInterval
            LastScavengeTime = $scavengingSettings.LastScavengeTime
            RefreshInterval = $scavengingSettings.RefreshInterval
            NoRefreshInterval = $scavengingSettings.NoRefreshInterval
            Forwarders = ($serverSettings.ServerForwarder.IPAddress.IPAddressToString -join ", ")
            RootHints = $serverSettings.ServerRootHint.Count
            ListeningAddresses = ($serverSettings.ServerSetting.ListeningIPAddress -join ", ")
            Issues = @()
        }
        
        # Check for server-level issues
        if (-not $scavengingSettings.ScavengingState) {
            $info.Issues += "Server-level scavenging is DISABLED"
        }
        
        Write-Log "DNS server info retrieved successfully" -Level "SUCCESS"
        return $info
    } catch {
        Write-Log "Failed to get DNS server info: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Get-ZoneHealth {
    param(
        [string]$Server,
        [string]$Zone
    )
    
    Write-Log "Analyzing zone: $Zone" -Level "INFO"
    
    try {
        $zoneInfo = Get-DnsServerZone -Name $Zone -ComputerName $Server -ErrorAction Stop
        $agingInfo = Get-DnsServerZoneAging -Name $Zone -ComputerName $Server -ErrorAction Stop
        
        $health = [PSCustomObject]@{
            ZoneName = $Zone
            ZoneType = $zoneInfo.ZoneType
            IsDsIntegrated = $zoneInfo.IsDsIntegrated
            IsReverseLookupZone = $zoneInfo.IsReverseLookupZone
            ReplicationScope = $zoneInfo.ReplicationScope
            DynamicUpdate = $zoneInfo.DynamicUpdate
            AgingEnabled = $agingInfo.AgingEnabled
            NoRefreshInterval = $agingInfo.NoRefreshInterval
            RefreshInterval = $agingInfo.RefreshInterval
            ScavengeServers = $agingInfo.ScavengeServers
            AvailForScavengeTime = $agingInfo.AvailForScavengeTime
            RecordCount = 0
            StaleCount = 0
            StaticCount = 0
            DynamicCount = 0
            Issues = @()
            HealthScore = 100
        }
        
        # Get record statistics
        $records = Get-DnsServerResourceRecord -ZoneName $Zone -ComputerName $Server -ErrorAction SilentlyContinue
        $health.RecordCount = ($records | Measure-Object).Count
        $health.DynamicCount = ($records | Where-Object { $_.Timestamp -ne $null } | Measure-Object).Count
        $health.StaticCount = $health.RecordCount - $health.DynamicCount
        
        # Identify issues
        if (-not $health.AgingEnabled -and $health.DynamicCount -gt 0) {
            $health.Issues += "Aging is DISABLED but zone has dynamic records"
            $health.HealthScore -= 15
        }
        
        if ($health.DynamicUpdate -eq "None") {
            $health.Issues += "Dynamic updates are DISABLED"
            $health.HealthScore -= 10
        }
        
        if ($health.DynamicUpdate -eq "NonsecureAndSecure") {
            $health.Issues += "Zone allows NONSECURE dynamic updates (security risk)"
            $health.HealthScore -= 20
        }
        
        if (-not $health.IsDsIntegrated -and $health.ZoneType -eq "Primary") {
            $health.Issues += "Primary zone is NOT AD-integrated"
            $health.HealthScore -= 10
        }
        
        return $health
    } catch {
        Write-Log "Failed to analyze zone $Zone : $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Find-StaleRecords {
    param(
        [string]$Server,
        [string]$Zone,
        [int]$ThresholdDays
    )
    
    Write-Log "  Scanning for stale records (threshold: $ThresholdDays days)..." -Level "INFO"
    
    $staleRecords = @()
    $cutoffDate = (Get-Date).AddDays(-$ThresholdDays)
    
    try {
        $records = Get-DnsServerResourceRecord -ZoneName $Zone -ComputerName $Server -ErrorAction Stop |
            Where-Object { 
                $_.Timestamp -ne $null -and 
                $_.Timestamp -lt $cutoffDate -and
                $_.RecordType -in @('A','AAAA','CNAME','PTR')
            }
        
        foreach ($record in $records) {
            $ageInDays = [math]::Round(((Get-Date) - $record.Timestamp).TotalDays, 1)
            
            $staleRecords += [PSCustomObject]@{
                ZoneName = $Zone
                HostName = $record.HostName
                RecordType = $record.RecordType
                RecordData = switch ($record.RecordType) {
                    'A' { $record.RecordData.IPv4Address.ToString() }
                    'AAAA' { $record.RecordData.IPv6Address.ToString() }
                    'CNAME' { $record.RecordData.HostNameAlias }
                    'PTR' { $record.RecordData.PtrDomainName }
                    default { "N/A" }
                }
                Timestamp = $record.Timestamp
                AgeDays = $ageInDays
                TTL = $record.TimeToLive
            }
        }
        
        if ($staleRecords.Count -gt 0) {
            Write-Log "  Found $($staleRecords.Count) stale record(s)" -Level "WARNING"
        } else {
            Write-Log "  No stale records found" -Level "SUCCESS"
        }
        
        return $staleRecords
    } catch {
        Write-Log "  Error scanning for stale records: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Find-OrphanedPTRRecords {
    param(
        [string]$Server,
        [string]$ReverseZone,
        [array]$ForwardZones
    )
    
    Write-Log "  Checking for orphaned PTR records in $ReverseZone..." -Level "INFO"
    
    $orphanedPTRs = @()
    
    try {
        $ptrRecords = Get-DnsServerResourceRecord -ZoneName $ReverseZone -ComputerName $Server -RRType PTR -ErrorAction Stop |
            Where-Object { $_.HostName -ne "@" }
        
        # Build lookup of all A records across forward zones
        $aRecordLookup = @{}
        foreach ($fwdZone in $ForwardZones) {
            $aRecords = Get-DnsServerResourceRecord -ZoneName $fwdZone -ComputerName $Server -RRType A -ErrorAction SilentlyContinue
            foreach ($a in $aRecords) {
                $ip = $a.RecordData.IPv4Address.ToString()
                if (-not $aRecordLookup.ContainsKey($ip)) {
                    $aRecordLookup[$ip] = @()
                }
                $aRecordLookup[$ip] += "$($a.HostName).$fwdZone"
            }
        }
        
        foreach ($ptr in $ptrRecords) {
            # Convert PTR to IP address
            $octets = $ptr.HostName -split '\.'
            [array]::Reverse($octets)
            
            # Extract network portion from zone name (e.g., "1.168.192.in-addr.arpa" -> "192.168.1")
            $zoneParts = ($ReverseZone -replace '\.in-addr\.arpa$','') -split '\.'
            [array]::Reverse($zoneParts)
            $networkPortion = $zoneParts -join '.'
            
            $ipAddress = "$networkPortion.$($octets -join '.')"
            
            # Check if there's a matching A record
            if (-not $aRecordLookup.ContainsKey($ipAddress)) {
                $orphanedPTRs += [PSCustomObject]@{
                    ZoneName = $ReverseZone
                    HostName = $ptr.HostName
                    PTRTarget = $ptr.RecordData.PtrDomainName
                    IPAddress = $ipAddress
                    Timestamp = $ptr.Timestamp
                    Reason = "No matching A record found"
                }
            }
        }
        
        if ($orphanedPTRs.Count -gt 0) {
            Write-Log "  Found $($orphanedPTRs.Count) orphaned PTR record(s)" -Level "WARNING"
        } else {
            Write-Log "  No orphaned PTR records found" -Level "SUCCESS"
        }
        
        return $orphanedPTRs
    } catch {
        Write-Log "  Error checking PTR records: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Find-DuplicateRecords {
    param(
        [string]$Server,
        [string]$Zone
    )
    
    Write-Log "  Checking for duplicate A/AAAA records..." -Level "INFO"
    
    $duplicates = @()
    
    try {
        $aRecords = Get-DnsServerResourceRecord -ZoneName $Zone -ComputerName $Server -RRType A -ErrorAction SilentlyContinue
        
        # Group by hostname to find duplicates
        $grouped = $aRecords | Group-Object -Property HostName | Where-Object { $_.Count -gt 1 }
        
        foreach ($group in $grouped) {
            $ips = $group.Group | ForEach-Object { $_.RecordData.IPv4Address.ToString() }
            $uniqueIps = $ips | Sort-Object -Unique
            
            # Only flag as duplicate if same hostname points to different IPs (true conflict)
            # or if there are multiple records with same IP (wasteful duplicates)
            if ($uniqueIps.Count -ne $group.Count) {
                $duplicates += [PSCustomObject]@{
                    ZoneName = $Zone
                    HostName = $group.Name
                    RecordType = 'A'
                    RecordCount = $group.Count
                    IPAddresses = $ips -join "; "
                    UniqueIPs = $uniqueIps.Count
                    IssueType = if ($uniqueIps.Count -gt 1) { "Multiple IPs" } else { "Duplicate entries" }
                }
            }
        }
        
        if ($duplicates.Count -gt 0) {
            Write-Log "  Found $($duplicates.Count) hostname(s) with duplicate records" -Level "WARNING"
        } else {
            Write-Log "  No problematic duplicate records found" -Level "SUCCESS"
        }
        
        return $duplicates
    } catch {
        Write-Log "  Error checking duplicates: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Test-CriticalADRecords {
    param(
        [string]$Server,
        [string]$Zone
    )
    
    Write-Log "  Verifying critical AD DNS records..." -Level "INFO"
    
    $missing = @()
    $domainName = $Zone
    
    # Critical SRV records that should exist
    $criticalRecords = @(
        @{ Name = "_ldap._tcp"; Type = "SRV"; Description = "LDAP service locator" }
        @{ Name = "_kerberos._tcp"; Type = "SRV"; Description = "Kerberos service locator" }
        @{ Name = "_kpasswd._tcp"; Type = "SRV"; Description = "Kerberos password change" }
        @{ Name = "_gc._tcp"; Type = "SRV"; Description = "Global Catalog locator" }
        @{ Name = "_ldap._tcp.dc._msdcs"; Type = "SRV"; Description = "Domain Controller locator" }
        @{ Name = "_kerberos._tcp.dc._msdcs"; Type = "SRV"; Description = "DC Kerberos locator" }
    )
    
    foreach ($record in $criticalRecords) {
        try {
            $found = Get-DnsServerResourceRecord -ZoneName $Zone -ComputerName $Server -Name $record.Name -RRType $record.Type -ErrorAction SilentlyContinue
            if (-not $found) {
                $missing += [PSCustomObject]@{
                    ZoneName = $Zone
                    RecordName = $record.Name
                    RecordType = $record.Type
                    Description = $record.Description
                    Severity = "Critical"
                }
            }
        } catch {
            # Record doesn't exist
            $missing += [PSCustomObject]@{
                ZoneName = $Zone
                RecordName = $record.Name
                RecordType = $record.Type
                Description = $record.Description
                Severity = "Critical"
            }
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Log "  Found $($missing.Count) missing critical AD record(s)" -Level "ERROR"
    } else {
        Write-Log "  All critical AD records present" -Level "SUCCESS"
    }
    
    return $missing
}

function Invoke-DCDiagDNS {
    param([string]$Server)
    
    Write-Log "Running DCDiag DNS tests..." -Level "INFO"
    
    $results = @()
    
    try {
        $dcdiagOutput = dcdiag /test:DNS /s:$Server /v 2>&1 | Out-String
        
        # Parse results using regex
        $matches = [regex]::Matches($dcdiagOutput, '\.+\s+(\S+)\s+(passed|failed)\s+test\s+(\S+)', 'IgnoreCase')
        
        foreach ($match in $matches) {
            $results += [PSCustomObject]@{
                Server = $match.Groups[1].Value
                TestName = $match.Groups[3].Value
                Result = $match.Groups[2].Value
                Passed = ($match.Groups[2].Value -eq "passed")
            }
        }
        
        $passedCount = ($results | Where-Object { $_.Passed }).Count
        $failedCount = ($results | Where-Object { -not $_.Passed }).Count
        
        Write-Log "DCDiag complete: $passedCount passed, $failedCount failed" -Level $(if ($failedCount -gt 0) { "WARNING" } else { "SUCCESS" })
        
        return $results
    } catch {
        Write-Log "DCDiag execution failed: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}
#endregion

#region Remediation Functions
function Invoke-StaleRecordCleanup {
    param(
        [array]$Records,
        [string]$Server
    )
    
    if ($Records.Count -eq 0) {
        Write-Log "No stale records to clean up" -Level "INFO"
        return
    }
    
    Write-Host ""
    Write-Host "Stale Record Cleanup" -ForegroundColor DarkYellow
    Write-Host "--------------------" -ForegroundColor DarkYellow
    Write-Host "Found $($Records.Count) stale record(s) for removal." -ForegroundColor Gray
    Write-Host ""
    
    # Show sample records
    $Records | Select-Object -First 10 | Format-Table ZoneName, HostName, RecordType, AgeDays -AutoSize
    
    if ($Records.Count -gt 10) {
        Write-Host "... and $($Records.Count - 10) more records" -ForegroundColor Gray
    }
    
    $confirmation = Read-Host "Remove these stale records? (Y/N/WhatIf)"
    
    switch ($confirmation.ToUpper()) {
        "Y" {
            $removed = 0
            $failed = 0
            foreach ($record in $Records) {
                try {
                    Remove-DnsServerResourceRecord -ZoneName $record.ZoneName -Name $record.HostName -RRType $record.RecordType -ComputerName $Server -Force -ErrorAction Stop
                    $removed++
                    $script:RemediationLog += "Removed: $($record.HostName).$($record.ZoneName) ($($record.RecordType))"
                } catch {
                    $failed++
                    $script:RemediationLog += "Failed to remove: $($record.HostName).$($record.ZoneName) - $($_.Exception.Message)"
                }
            }
            Write-Log "Removed $removed records, $failed failed" -Level $(if ($failed -gt 0) { "WARNING" } else { "SUCCESS" })
        }
        "WHATIF" {
            Write-Host ""
            Write-Host "WhatIf: Would remove the following records:" -ForegroundColor Cyan
            $Records | Format-Table ZoneName, HostName, RecordType, RecordData, AgeDays -AutoSize
        }
        default {
            Write-Log "Stale record cleanup skipped" -Level "INFO"
        }
    }
}

function Enable-ZoneAging {
    param(
        [array]$Zones,
        [string]$Server
    )
    
    $zonesWithoutAging = $Zones | Where-Object { -not $_.AgingEnabled -and $_.DynamicCount -gt 0 }
    
    if ($zonesWithoutAging.Count -eq 0) {
        Write-Log "No zones require aging configuration" -Level "INFO"
        return
    }
    
    Write-Host ""
    Write-Host "Zone Aging Configuration" -ForegroundColor DarkYellow
    Write-Host "------------------------" -ForegroundColor DarkYellow
    Write-Host "The following zones have dynamic records but aging is disabled:" -ForegroundColor Gray
    Write-Host ""
    
    $zonesWithoutAging | Format-Table ZoneName, DynamicCount, AgingEnabled -AutoSize
    
    $confirmation = Read-Host "Enable aging on these zones with default intervals (7 days)? (Y/N)"
    
    if ($confirmation.ToUpper() -eq "Y") {
        foreach ($zone in $zonesWithoutAging) {
            try {
                Set-DnsServerZoneAging -Name $zone.ZoneName -ComputerName $Server -Aging $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -ErrorAction Stop
                Write-Log "Enabled aging on zone: $($zone.ZoneName)" -Level "SUCCESS"
                $script:RemediationLog += "Enabled aging: $($zone.ZoneName)"
            } catch {
                Write-Log "Failed to enable aging on $($zone.ZoneName): $($_.Exception.Message)" -Level "ERROR"
                $script:RemediationLog += "Failed aging: $($zone.ZoneName) - $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "Zone aging configuration skipped" -Level "INFO"
    }
}

function Enable-ServerScavenging {
    param(
        [string]$Server,
        [PSCustomObject]$ServerInfo
    )
    
    if ($ServerInfo.ScavengingState) {
        Write-Log "Server scavenging is already enabled" -Level "INFO"
        return
    }
    
    Write-Host ""
    Write-Host "Server Scavenging Configuration" -ForegroundColor DarkYellow
    Write-Host "--------------------------------" -ForegroundColor DarkYellow
    Write-Host "Server-level scavenging is currently DISABLED." -ForegroundColor Yellow
    Write-Host "Without this, stale records will never be automatically removed." -ForegroundColor Gray
    Write-Host ""
    
    $confirmation = Read-Host "Enable server scavenging with 7-day interval? (Y/N)"
    
    if ($confirmation.ToUpper() -eq "Y") {
        try {
            Set-DnsServerScavenging -ComputerName $Server -ScavengingState $true -ScavengingInterval 7.00:00:00 -ErrorAction Stop
            Write-Log "Server scavenging enabled successfully" -Level "SUCCESS"
            $script:RemediationLog += "Enabled server scavenging"
        } catch {
            Write-Log "Failed to enable scavenging: $($_.Exception.Message)" -Level "ERROR"
            $script:RemediationLog += "Failed server scavenging: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Server scavenging configuration skipped" -Level "INFO"
    }
}

function Invoke-DCRegistration {
    param([string]$Server)
    
    Write-Host ""
    Write-Host "Re-register Domain Controller DNS Records" -ForegroundColor DarkYellow
    Write-Host "------------------------------------------" -ForegroundColor DarkYellow
    Write-Host "This will run 'nltest /dsregdns' and 'ipconfig /registerdns'" -ForegroundColor Gray
    Write-Host ""
    
    $confirmation = Read-Host "Proceed with DNS re-registration? (Y/N)"
    
    if ($confirmation.ToUpper() -eq "Y") {
        try {
            Write-Log "Running nltest /dsregdns..." -Level "INFO"
            $nltestResult = nltest /dsregdns 2>&1
            
            Write-Log "Running ipconfig /registerdns..." -Level "INFO"
            $ipconfigResult = ipconfig /registerdns 2>&1
            
            Write-Log "DNS re-registration commands executed" -Level "SUCCESS"
            $script:RemediationLog += "Executed DNS re-registration"
        } catch {
            Write-Log "DNS re-registration failed: $($_.Exception.Message)" -Level "ERROR"
            $script:RemediationLog += "Failed DNS re-registration: $($_.Exception.Message)"
        }
    } else {
        Write-Log "DNS re-registration skipped" -Level "INFO"
    }
}
#endregion

#region Report Generation
function New-HTMLReport {
    param([string]$OutputPath)
    
    $report = $script:HealthReport
    $scoreColor = Get-ScoreColor -Score $report.Summary.OverallScore
    
    $html = New-Object System.Text.StringBuilder
    
    [void]$html.AppendLine("<!DOCTYPE html>")
    [void]$html.AppendLine("<html lang='en'>")
    [void]$html.AppendLine("<head>")
    [void]$html.AppendLine("    <meta charset='UTF-8'>")
    [void]$html.AppendLine("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    [void]$html.AppendLine("    <title>DNS Zone Health Report - $($report.ServerInfo.ServerName)</title>")
    [void]$html.AppendLine("    <style>")
    [void]$html.AppendLine("        * { margin: 0; padding: 0; box-sizing: border-box; }")
    [void]$html.AppendLine("        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }")
    [void]$html.AppendLine("        .header { background: linear-gradient(135deg, $($script:PrimaryColor), #cc5200); padding: 30px; text-align: center; }")
    [void]$html.AppendLine("        .header h1 { font-size: 28px; margin-bottom: 5px; color: white; }")
    [void]$html.AppendLine("        .header .tagline { color: rgba(255,255,255,0.8); font-size: 14px; }")
    [void]$html.AppendLine("        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }")
    [void]$html.AppendLine("        .score-card { background: #16213e; border-radius: 12px; padding: 30px; text-align: center; margin: 20px 0; }")
    [void]$html.AppendLine("        .score-value { font-size: 72px; font-weight: bold; color: $scoreColor; }")
    [void]$html.AppendLine("        .score-label { color: $($script:SecondaryColor); font-size: 18px; }")
    [void]$html.AppendLine("        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }")
    [void]$html.AppendLine("        .stat-card { background: #16213e; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid $($script:PrimaryColor); }")
    [void]$html.AppendLine("        .stat-value { font-size: 32px; font-weight: bold; color: $($script:PrimaryColor); }")
    [void]$html.AppendLine("        .stat-label { color: $($script:SecondaryColor); font-size: 14px; margin-top: 5px; }")
    [void]$html.AppendLine("        .section { background: #16213e; border-radius: 8px; margin: 20px 0; overflow: hidden; }")
    [void]$html.AppendLine("        .section-header { background: #1e3a5f; padding: 15px 20px; font-size: 18px; font-weight: 600; }")
    [void]$html.AppendLine("        .section-content { padding: 20px; }")
    [void]$html.AppendLine("        table { width: 100%; border-collapse: collapse; }")
    [void]$html.AppendLine("        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #2a2a4a; }")
    [void]$html.AppendLine("        th { background: #1e3a5f; color: $($script:PrimaryColor); font-weight: 600; }")
    [void]$html.AppendLine("        tr:hover { background: rgba(255,102,0,0.1); }")
    [void]$html.AppendLine("        .badge { padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 500; }")
    [void]$html.AppendLine("        .badge-success { background: #22C55E; color: white; }")
    [void]$html.AppendLine("        .badge-warning { background: #EAB308; color: black; }")
    [void]$html.AppendLine("        .badge-danger { background: #EF4444; color: white; }")
    [void]$html.AppendLine("        .badge-info { background: #3B82F6; color: white; }")
    [void]$html.AppendLine("        .issue-list { list-style: none; }")
    [void]$html.AppendLine("        .issue-list li { padding: 8px 0; border-bottom: 1px solid #2a2a4a; }")
    [void]$html.AppendLine("        .issue-list li:last-child { border-bottom: none; }")
    [void]$html.AppendLine("        .footer { text-align: center; padding: 30px; color: $($script:SecondaryColor); font-size: 14px; }")
    [void]$html.AppendLine("        .server-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }")
    [void]$html.AppendLine("        .info-item { display: flex; justify-content: space-between; padding: 10px; background: #1e3a5f; border-radius: 4px; }")
    [void]$html.AppendLine("        .info-label { color: $($script:SecondaryColor); }")
    [void]$html.AppendLine("        .info-value { color: white; font-weight: 500; }")
    [void]$html.AppendLine("    </style>")
    [void]$html.AppendLine("</head>")
    [void]$html.AppendLine("<body>")
    
    # Header
    [void]$html.AppendLine("    <div class='header'>")
    [void]$html.AppendLine("        <h1>DNS Zone Health Report</h1>")
    [void]$html.AppendLine("        <div class='tagline'>$($script:CompanyName) - $($script:Tagline)</div>")
    [void]$html.AppendLine("    </div>")
    
    [void]$html.AppendLine("    <div class='container'>")
    
    # Score Card
    [void]$html.AppendLine("        <div class='score-card'>")
    [void]$html.AppendLine("            <div class='score-value'>$($report.Summary.OverallScore)%</div>")
    [void]$html.AppendLine("            <div class='score-label'>Overall DNS Health Score</div>")
    [void]$html.AppendLine("        </div>")
    
    # Summary Stats
    [void]$html.AppendLine("        <div class='grid'>")
    [void]$html.AppendLine("            <div class='stat-card'><div class='stat-value'>$($report.Summary.TotalZones)</div><div class='stat-label'>Total Zones</div></div>")
    [void]$html.AppendLine("            <div class='stat-card'><div class='stat-value'>$($report.Summary.HealthyZones)</div><div class='stat-label'>Healthy Zones</div></div>")
    [void]$html.AppendLine("            <div class='stat-card'><div class='stat-value'>$($report.Summary.TotalStaleRecords)</div><div class='stat-label'>Stale Records</div></div>")
    [void]$html.AppendLine("            <div class='stat-card'><div class='stat-value'>$($report.Summary.TotalOrphanedPTRs)</div><div class='stat-label'>Orphaned PTRs</div></div>")
    [void]$html.AppendLine("            <div class='stat-card'><div class='stat-value'>$($report.Summary.TotalDuplicates)</div><div class='stat-label'>Duplicate Issues</div></div>")
    [void]$html.AppendLine("            <div class='stat-card'><div class='stat-value'>$($report.Summary.MissingCritical)</div><div class='stat-label'>Missing Critical</div></div>")
    [void]$html.AppendLine("        </div>")
    
    # Server Information
    if ($report.ServerInfo) {
        [void]$html.AppendLine("        <div class='section'>")
        [void]$html.AppendLine("            <div class='section-header'>DNS Server Configuration</div>")
        [void]$html.AppendLine("            <div class='section-content'>")
        [void]$html.AppendLine("                <div class='server-info'>")
        [void]$html.AppendLine("                    <div class='info-item'><span class='info-label'>Server Name</span><span class='info-value'>$($report.ServerInfo.ServerName)</span></div>")
        
        $scavState = if ($report.ServerInfo.ScavengingState) { "<span class='badge badge-success'>Enabled</span>" } else { "<span class='badge badge-danger'>Disabled</span>" }
        [void]$html.AppendLine("                    <div class='info-item'><span class='info-label'>Scavenging State</span><span class='info-value'>$scavState</span></div>")
        [void]$html.AppendLine("                    <div class='info-item'><span class='info-label'>Scavenging Interval</span><span class='info-value'>$($report.ServerInfo.ScavengingInterval)</span></div>")
        [void]$html.AppendLine("                    <div class='info-item'><span class='info-label'>Last Scavenge</span><span class='info-value'>$($report.ServerInfo.LastScavengeTime)</span></div>")
        [void]$html.AppendLine("                    <div class='info-item'><span class='info-label'>Forwarders</span><span class='info-value'>$(if($report.ServerInfo.Forwarders){"$($report.ServerInfo.Forwarders)"}else{'None configured'})</span></div>")
        [void]$html.AppendLine("                </div>")
        
        if ($report.ServerInfo.Issues.Count -gt 0) {
            [void]$html.AppendLine("                <h4 style='margin-top: 20px; color: #EF4444;'>Server Issues:</h4>")
            [void]$html.AppendLine("                <ul class='issue-list'>")
            foreach ($issue in $report.ServerInfo.Issues) {
                [void]$html.AppendLine("                    <li>$issue</li>")
            }
            [void]$html.AppendLine("                </ul>")
        }
        [void]$html.AppendLine("            </div>")
        [void]$html.AppendLine("        </div>")
    }
    
    # Zone Health
    if ($report.Zones.Count -gt 0) {
        [void]$html.AppendLine("        <div class='section'>")
        [void]$html.AppendLine("            <div class='section-header'>Zone Health Analysis</div>")
        [void]$html.AppendLine("            <div class='section-content'>")
        [void]$html.AppendLine("                <table>")
        [void]$html.AppendLine("                    <thead><tr><th>Zone Name</th><th>Type</th><th>Records</th><th>Dynamic</th><th>Stale</th><th>Aging</th><th>Health</th></tr></thead>")
        [void]$html.AppendLine("                    <tbody>")
        
        foreach ($zone in $report.Zones) {
            $agingBadge = if ($zone.AgingEnabled) { "<span class='badge badge-success'>Enabled</span>" } else { "<span class='badge badge-warning'>Disabled</span>" }
            $healthColor = Get-ScoreColor -Score $zone.HealthScore
            $healthBadge = "<span class='badge' style='background: $healthColor; color: white;'>$($zone.HealthScore)%</span>"
            
            [void]$html.AppendLine("                    <tr>")
            [void]$html.AppendLine("                        <td>$($zone.ZoneName)</td>")
            [void]$html.AppendLine("                        <td>$($zone.ZoneType)</td>")
            [void]$html.AppendLine("                        <td>$($zone.RecordCount)</td>")
            [void]$html.AppendLine("                        <td>$($zone.DynamicCount)</td>")
            [void]$html.AppendLine("                        <td>$($zone.StaleCount)</td>")
            [void]$html.AppendLine("                        <td>$agingBadge</td>")
            [void]$html.AppendLine("                        <td>$healthBadge</td>")
            [void]$html.AppendLine("                    </tr>")
        }
        
        [void]$html.AppendLine("                    </tbody>")
        [void]$html.AppendLine("                </table>")
        [void]$html.AppendLine("            </div>")
        [void]$html.AppendLine("        </div>")
    }
    
    # Stale Records
    if ($report.StaleRecords.Count -gt 0) {
        [void]$html.AppendLine("        <div class='section'>")
        [void]$html.AppendLine("            <div class='section-header'>Stale Records ($($report.StaleRecords.Count) found)</div>")
        [void]$html.AppendLine("            <div class='section-content'>")
        [void]$html.AppendLine("                <table>")
        [void]$html.AppendLine("                    <thead><tr><th>Zone</th><th>Host Name</th><th>Type</th><th>Data</th><th>Age (Days)</th><th>Last Update</th></tr></thead>")
        [void]$html.AppendLine("                    <tbody>")
        
        foreach ($record in ($report.StaleRecords | Select-Object -First 50)) {
            [void]$html.AppendLine("                    <tr>")
            [void]$html.AppendLine("                        <td>$($record.ZoneName)</td>")
            [void]$html.AppendLine("                        <td>$($record.HostName)</td>")
            [void]$html.AppendLine("                        <td>$($record.RecordType)</td>")
            [void]$html.AppendLine("                        <td>$($record.RecordData)</td>")
            [void]$html.AppendLine("                        <td>$($record.AgeDays)</td>")
            [void]$html.AppendLine("                        <td>$($record.Timestamp)</td>")
            [void]$html.AppendLine("                    </tr>")
        }
        
        [void]$html.AppendLine("                    </tbody>")
        [void]$html.AppendLine("                </table>")
        if ($report.StaleRecords.Count -gt 50) {
            [void]$html.AppendLine("                <p style='margin-top: 15px; color: $($script:SecondaryColor);'>Showing first 50 of $($report.StaleRecords.Count) stale records</p>")
        }
        [void]$html.AppendLine("            </div>")
        [void]$html.AppendLine("        </div>")
    }
    
    # Missing Critical Records
    if ($report.MissingCriticalRecords.Count -gt 0) {
        [void]$html.AppendLine("        <div class='section'>")
        [void]$html.AppendLine("            <div class='section-header'>Missing Critical AD Records</div>")
        [void]$html.AppendLine("            <div class='section-content'>")
        [void]$html.AppendLine("                <table>")
        [void]$html.AppendLine("                    <thead><tr><th>Zone</th><th>Record Name</th><th>Type</th><th>Description</th><th>Severity</th></tr></thead>")
        [void]$html.AppendLine("                    <tbody>")
        
        foreach ($record in $report.MissingCriticalRecords) {
            [void]$html.AppendLine("                    <tr>")
            [void]$html.AppendLine("                        <td>$($record.ZoneName)</td>")
            [void]$html.AppendLine("                        <td>$($record.RecordName)</td>")
            [void]$html.AppendLine("                        <td>$($record.RecordType)</td>")
            [void]$html.AppendLine("                        <td>$($record.Description)</td>")
            [void]$html.AppendLine("                        <td><span class='badge badge-danger'>$($record.Severity)</span></td>")
            [void]$html.AppendLine("                    </tr>")
        }
        
        [void]$html.AppendLine("                    </tbody>")
        [void]$html.AppendLine("                </table>")
        [void]$html.AppendLine("            </div>")
        [void]$html.AppendLine("        </div>")
    }
    
    # DCDiag Results
    if ($report.DCDiagResults.Count -gt 0) {
        [void]$html.AppendLine("        <div class='section'>")
        [void]$html.AppendLine("            <div class='section-header'>DCDiag DNS Test Results</div>")
        [void]$html.AppendLine("            <div class='section-content'>")
        [void]$html.AppendLine("                <table>")
        [void]$html.AppendLine("                    <thead><tr><th>Server</th><th>Test Name</th><th>Result</th></tr></thead>")
        [void]$html.AppendLine("                    <tbody>")
        
        foreach ($result in $report.DCDiagResults) {
            $resultBadge = if ($result.Passed) { "<span class='badge badge-success'>Passed</span>" } else { "<span class='badge badge-danger'>Failed</span>" }
            [void]$html.AppendLine("                    <tr>")
            [void]$html.AppendLine("                        <td>$($result.Server)</td>")
            [void]$html.AppendLine("                        <td>$($result.TestName)</td>")
            [void]$html.AppendLine("                        <td>$resultBadge</td>")
            [void]$html.AppendLine("                    </tr>")
        }
        
        [void]$html.AppendLine("                    </tbody>")
        [void]$html.AppendLine("                </table>")
        [void]$html.AppendLine("            </div>")
        [void]$html.AppendLine("        </div>")
    }
    
    # Footer
    [void]$html.AppendLine("        <div class='footer'>")
    [void]$html.AppendLine("            <p>Generated by $($script:CompanyName) - $($script:Tagline)</p>")
    [void]$html.AppendLine("            <p>Report Date: $($report.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</p>")
    [void]$html.AppendLine("        </div>")
    
    [void]$html.AppendLine("    </div>")
    [void]$html.AppendLine("</body>")
    [void]$html.AppendLine("</html>")
    
    # Save or open report
    if ($OutputPath) {
        $html.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Log "Report saved to: $OutputPath" -Level "SUCCESS"
    } else {
        $tempPath = Join-Path $env:TEMP "DNSZoneHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $html.ToString() | Out-File -FilePath $tempPath -Encoding UTF8 -Force
        Start-Process $tempPath
        Write-Log "Report opened in browser" -Level "SUCCESS"
    }
}
#endregion

#region Main Execution
Show-Banner

# Verify requirements
if (-not (Test-DnsServerModule)) {
    exit 1
}

Write-Log "Target DNS Server: $DnsServer" -Level "INFO"
Write-Log "Stale Threshold: $StaleThresholdDays days" -Level "INFO"
Write-Host ""

# Get server information
$script:HealthReport.ServerInfo = Get-DnsServerInfo -Server $DnsServer
if (-not $script:HealthReport.ServerInfo) {
    Write-Log "Failed to connect to DNS server. Exiting." -Level "ERROR"
    exit 1
}

# Get zones to analyze
try {
    if ($ZoneName) {
        $zones = @(Get-DnsServerZone -Name $ZoneName -ComputerName $DnsServer -ErrorAction Stop)
    } else {
        $zones = Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop |
            Where-Object { 
                $_.ZoneType -in @('Primary') -and 
                -not $_.IsAutoCreated -and
                $_.ZoneName -ne 'TrustAnchors'
            }
        
        if (-not $IncludeReverseZones) {
            $zones = $zones | Where-Object { -not $_.IsReverseLookupZone }
        }
    }
    
    Write-Log "Found $($zones.Count) zone(s) to analyze" -Level "SUCCESS"
} catch {
    Write-Log "Failed to enumerate zones: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Store forward zones for PTR orphan checking
$forwardZones = ($zones | Where-Object { -not $_.IsReverseLookupZone }).ZoneName

# Analyze each zone
Write-Host ""
Write-Host "Zone Analysis" -ForegroundColor DarkYellow
Write-Host "=============" -ForegroundColor DarkYellow
Write-Host ""

foreach ($zone in $zones) {
    $zoneHealth = Get-ZoneHealth -Server $DnsServer -Zone $zone.ZoneName
    
    if ($zoneHealth) {
        # Find stale records
        $staleRecords = Find-StaleRecords -Server $DnsServer -Zone $zone.ZoneName -ThresholdDays $StaleThresholdDays
        $zoneHealth.StaleCount = $staleRecords.Count
        $script:HealthReport.StaleRecords += $staleRecords
        
        # Adjust health score for stale records
        if ($staleRecords.Count -gt 0) {
            $staleImpact = [math]::Min(($staleRecords.Count / 10), 20)
            $zoneHealth.HealthScore -= $staleImpact
        }
        
        # Check for duplicates (forward zones only)
        if (-not $zone.IsReverseLookupZone) {
            $duplicates = Find-DuplicateRecords -Server $DnsServer -Zone $zone.ZoneName
            $script:HealthReport.DuplicateRecords += $duplicates
            
            # Check critical AD records (only for domain zones)
            if ($zone.ZoneName -notmatch '^_msdcs\.') {
                $missingCritical = Test-CriticalADRecords -Server $DnsServer -Zone $zone.ZoneName
                $script:HealthReport.MissingCriticalRecords += $missingCritical
                
                if ($missingCritical.Count -gt 0) {
                    $zoneHealth.HealthScore -= ($missingCritical.Count * 10)
                    $zoneHealth.Issues += "Missing $($missingCritical.Count) critical AD DNS record(s)"
                }
            }
        }
        
        # Check for orphaned PTRs (reverse zones only)
        if ($zone.IsReverseLookupZone -and $forwardZones.Count -gt 0) {
            $orphanedPTRs = Find-OrphanedPTRRecords -Server $DnsServer -ReverseZone $zone.ZoneName -ForwardZones $forwardZones
            $script:HealthReport.OrphanedPTRs += $orphanedPTRs
        }
        
        # Ensure health score doesn't go below 0
        $zoneHealth.HealthScore = [math]::Max(0, $zoneHealth.HealthScore)
        
        $script:HealthReport.Zones += $zoneHealth
    }
    
    Write-Host ""
}

# Run DCDiag DNS tests
if (-not $SkipDCDiag) {
    Write-Host ""
    $script:HealthReport.DCDiagResults = Invoke-DCDiagDNS -Server $DnsServer
}

# Calculate summary
$script:HealthReport.Summary.TotalZones = $script:HealthReport.Zones.Count
$script:HealthReport.Summary.HealthyZones = ($script:HealthReport.Zones | Where-Object { $_.HealthScore -ge 90 }).Count
$script:HealthReport.Summary.ZonesWithIssues = ($script:HealthReport.Zones | Where-Object { $_.Issues.Count -gt 0 }).Count
$script:HealthReport.Summary.TotalStaleRecords = $script:HealthReport.StaleRecords.Count
$script:HealthReport.Summary.TotalOrphanedPTRs = $script:HealthReport.OrphanedPTRs.Count
$script:HealthReport.Summary.TotalDuplicates = $script:HealthReport.DuplicateRecords.Count
$script:HealthReport.Summary.MissingCritical = $script:HealthReport.MissingCriticalRecords.Count

# Calculate overall score
$zoneScoreAvg = if ($script:HealthReport.Zones.Count -gt 0) { 
    ($script:HealthReport.Zones | Measure-Object -Property HealthScore -Average).Average 
} else { 100 }

$dcdiagPenalty = if ($script:HealthReport.DCDiagResults.Count -gt 0) {
    $failedTests = ($script:HealthReport.DCDiagResults | Where-Object { -not $_.Passed }).Count
    $failedTests * 5
} else { 0 }

$serverPenalty = if ($script:HealthReport.ServerInfo.ScavengingState) { 0 } else { 10 }

$script:HealthReport.Summary.OverallScore = [math]::Max(0, [math]::Round($zoneScoreAvg - $dcdiagPenalty - $serverPenalty))

# Display summary
Write-Host ""
Write-Host "============================================" -ForegroundColor DarkYellow
Write-Host "               Discovery Summary            " -ForegroundColor DarkYellow
Write-Host "============================================" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Overall Health Score: " -NoNewline
$scoreColor = if ($script:HealthReport.Summary.OverallScore -ge 90) { "Green" }
    elseif ($script:HealthReport.Summary.OverallScore -ge 70) { "Yellow" }
    elseif ($script:HealthReport.Summary.OverallScore -ge 50) { "DarkYellow" }
    else { "Red" }
Write-Host "$($script:HealthReport.Summary.OverallScore)%" -ForegroundColor $scoreColor
Write-Host ""
Write-Host "  Zones Analyzed:       $($script:HealthReport.Summary.TotalZones)" -ForegroundColor Gray
Write-Host "  Healthy Zones:        $($script:HealthReport.Summary.HealthyZones)" -ForegroundColor Green
Write-Host "  Zones with Issues:    $($script:HealthReport.Summary.ZonesWithIssues)" -ForegroundColor $(if($script:HealthReport.Summary.ZonesWithIssues -gt 0){"Yellow"}else{"Gray"})
Write-Host "  Stale Records:        $($script:HealthReport.Summary.TotalStaleRecords)" -ForegroundColor $(if($script:HealthReport.Summary.TotalStaleRecords -gt 0){"Yellow"}else{"Gray"})
Write-Host "  Orphaned PTRs:        $($script:HealthReport.Summary.TotalOrphanedPTRs)" -ForegroundColor $(if($script:HealthReport.Summary.TotalOrphanedPTRs -gt 0){"Yellow"}else{"Gray"})
Write-Host "  Duplicate Issues:     $($script:HealthReport.Summary.TotalDuplicates)" -ForegroundColor $(if($script:HealthReport.Summary.TotalDuplicates -gt 0){"Yellow"}else{"Gray"})
Write-Host "  Missing Critical:     $($script:HealthReport.Summary.MissingCritical)" -ForegroundColor $(if($script:HealthReport.Summary.MissingCritical -gt 0){"Red"}else{"Gray"})
Write-Host ""

# Remediation mode
if ($Remediate) {
    Write-Host "============================================" -ForegroundColor DarkYellow
    Write-Host "             Remediation Mode               " -ForegroundColor DarkYellow
    Write-Host "============================================" -ForegroundColor DarkYellow
    Write-Host ""
    
    # Server scavenging
    if (-not $script:HealthReport.ServerInfo.ScavengingState) {
        Enable-ServerScavenging -Server $DnsServer -ServerInfo $script:HealthReport.ServerInfo
    }
    
    # Zone aging
    Enable-ZoneAging -Zones $script:HealthReport.Zones -Server $DnsServer
    
    # Stale record cleanup
    if ($script:HealthReport.StaleRecords.Count -gt 0) {
        Invoke-StaleRecordCleanup -Records $script:HealthReport.StaleRecords -Server $DnsServer
    }
    
    # Missing critical records
    if ($script:HealthReport.MissingCriticalRecords.Count -gt 0) {
        Write-Host ""
        Write-Host "Missing Critical AD DNS Records Detected" -ForegroundColor DarkYellow
        Write-Host "----------------------------------------" -ForegroundColor DarkYellow
        Write-Host "The following critical records are missing:" -ForegroundColor Gray
        $script:HealthReport.MissingCriticalRecords | Format-Table RecordName, RecordType, Description -AutoSize
        
        Invoke-DCRegistration -Server $DnsServer
    }
    
    # Display remediation log
    if ($script:RemediationLog.Count -gt 0) {
        Write-Host ""
        Write-Host "Remediation Log" -ForegroundColor DarkYellow
        Write-Host "---------------" -ForegroundColor DarkYellow
        foreach ($entry in $script:RemediationLog) {
            Write-Host "  - $entry" -ForegroundColor Gray
        }
    }
}

# Generate report
New-HTMLReport -OutputPath $ExportPath

Write-Host ""
Write-Log "DNS Zone Health Discovery complete" -Level "SUCCESS"
#endregion
