<#
.SYNOPSIS
    VLAN Discovery Tool - Identifies VLANs in use across the network environment.

.DESCRIPTION
    Comprehensive VLAN discovery using multiple native Windows methods.

.PARAMETER Method
    Discovery method(s) to use. Default: All available methods.
    Valid: All, Pktmon, DHCP, ADSites, ARP, Routes, Adapters, Probe

.PARAMETER DHCPServer
    Specific DHCP server(s) to query. If not specified, discovers from AD.

.PARAMETER PktmonDuration
    Duration in seconds for packet capture. Default: 30

.PARAMETER ProbeRanges
    Subnet ranges to probe for active gateways.

.PARAMETER RemoteHosts
    Additional hosts to query for ARP tables (requires WinRM).

.PARAMETER ExportPath
    Path to export results (CSV, JSON, or HTML).

.PARAMETER Quiet
    Suppress console output.

.EXAMPLE
    .\Get-VLANDiscovery.ps1
    Runs all available discovery methods with defaults.

.EXAMPLE
    .\Get-VLANDiscovery.ps1 -Method DHCP,ADSites -ExportPath "C:\Reports\VLANs.html"
    Query DHCP and AD Sites only, export to HTML.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, Admin rights for pktmon
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Pktmon', 'DHCP', 'ADSites', 'ARP', 'Routes', 'Adapters', 'Probe')]
    [string[]]$Method = @('All'),
    
    [Parameter(Mandatory = $false)]
    [string[]]$DHCPServer,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 300)]
    [int]$PktmonDuration = 30,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ProbeRanges,
    
    [Parameter(Mandatory = $false)]
    [string[]]$RemoteHosts,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeInactive,
    
    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

#region Configuration
$ErrorActionPreference = "Continue"
$script:BrandOrange = "#FF6600"
$script:BrandGrey = "#6B7280"
$script:CompanyName = "Yeyland Wutani LLC"
$script:Tagline = "Building Better Systems"
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"
$script:DiscoveredVLANs = [System.Collections.ArrayList]::new()
$script:DiscoveryLog = [System.Collections.ArrayList]::new()
$script:DefaultProbeRanges = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
#endregion

#region Helper Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    [void]$script:DiscoveryLog.Add($logEntry)
    if (-not $Quiet) {
        $color = switch ($Level) {
            "INFO" { "White" }
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR" { "Red" }
            "VLAN" { "Cyan" }
            default { "Gray" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Add-DiscoveredVLAN {
    param(
        [string]$Subnet,
        [string]$VLANId = "Unknown",
        [string]$Name = "",
        [string]$Gateway = "",
        [string]$Source,
        [string]$Site = "",
        [string]$Description = "",
        [int]$Confidence = 50,
        [int]$ActiveHosts = 0
    )
    $existing = $script:DiscoveredVLANs | Where-Object { $_.Subnet -eq $Subnet }
    if ($existing) {
        if ($Confidence -gt $existing.Confidence) {
            $existing.Confidence = $Confidence
            $existing.Source = $Source
        }
        if ($VLANId -ne "Unknown" -and $existing.VLANId -eq "Unknown") { $existing.VLANId = $VLANId }
        if ($Name -and -not $existing.Name) { $existing.Name = $Name }
        if ($Gateway -and -not $existing.Gateway) { $existing.Gateway = $Gateway }
        $existing.ActiveHosts = [Math]::Max($existing.ActiveHosts, $ActiveHosts)
    }
    else {
        $vlanEntry = [PSCustomObject]@{
            Subnet = $Subnet; VLANId = $VLANId; Name = $Name; Gateway = $Gateway
            SubnetMask = ""; Site = $Site; Description = $Description; Source = $Source
            Confidence = $Confidence; ActiveHosts = $ActiveHosts
            DiscoveredAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        [void]$script:DiscoveredVLANs.Add($vlanEntry)
        Write-Log "Found subnet: $Subnet (VLAN: $VLANId) via $Source" -Level "VLAN"
    }
}

function Get-SubnetFromIP {
    param([string]$IP, [int]$CIDR = 24)
    try {
        $ipBytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
        $maskBytes = @(0,0,0,0)
        for ($i = 0; $i -lt 4; $i++) {
            $bits = [Math]::Min(8, [Math]::Max(0, $CIDR - ($i * 8)))
            $maskBytes[$i] = [byte](256 - [Math]::Pow(2, 8 - $bits))
        }
        $networkBytes = @()
        for ($i = 0; $i -lt 4; $i++) { $networkBytes += $ipBytes[$i] -band $maskBytes[$i] }
        return ($networkBytes -join '.') + "/$CIDR"
    }
    catch { return $null }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandExists {
    param([string]$Command)
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}
#endregion

#region Discovery Methods
function Invoke-PktmonDiscovery {
    Write-Log "Starting pktmon VLAN tag capture..." -Level "INFO"
    if (-not (Test-CommandExists "pktmon")) {
        Write-Log "pktmon not available (requires Windows 10 2004+ or Server 2019+)" -Level "WARNING"
        return
    }
    if (-not (Test-IsAdmin)) {
        Write-Log "pktmon requires administrator privileges" -Level "WARNING"
        return
    }
    try {
        $tempPath = Join-Path $env:TEMP "pktmon_vlan_$script:Timestamp"
        $etlFile = "$tempPath.etl"
        $txtFile = "$tempPath.txt"
        $null = pktmon filter remove 2>$null
        Write-Log "Adding 802.1Q VLAN filter (EtherType 0x8100)..." -Level "INFO"
        $null = pktmon filter add VLAN8021Q -d 0x8100 2>$null
        Write-Log "Capturing packets for $PktmonDuration seconds..." -Level "INFO"
        $null = pktmon start --capture --file-name $etlFile 2>$null
        Start-Sleep -Seconds $PktmonDuration
        $null = pktmon stop 2>$null
        if (Test-Path $etlFile) {
            $fileSize = (Get-Item $etlFile).Length
            Write-Log "Captured $([math]::Round($fileSize/1KB, 2)) KB of traffic" -Level "INFO"
            $null = pktmon format $etlFile -o $txtFile 2>$null
            if (Test-Path $txtFile) {
                $content = Get-Content $txtFile -Raw -ErrorAction SilentlyContinue
                $vlanPattern = 'VLAN[:\s]+(\d+)|VID[:\s]+(\d+)|802\.1[Qq][:\s]+(\d+)'
                $regexMatches = [regex]::Matches($content, $vlanPattern)
                $foundVlans = @{}
                foreach ($m in $regexMatches) {
                    $vlanId = ($m.Groups[1..3] | Where-Object { $_.Success }).Value
                    if ($vlanId -and $vlanId -match '^\d+$' -and [int]$vlanId -gt 0 -and [int]$vlanId -lt 4095) {
                        $foundVlans[$vlanId] = $true
                    }
                }
                if ($foundVlans.Count -gt 0) {
                    foreach ($vid in $foundVlans.Keys) {
                        Add-DiscoveredVLAN -VLANId $vid -Source "pktmon" -Confidence 95 -Description "Detected via 802.1Q packet capture"
                    }
                    Write-Log "Found $($foundVlans.Count) VLAN tag(s) in packet capture" -Level "SUCCESS"
                }
                else { Write-Log "No 802.1Q VLAN tags detected (this is normal on access ports)" -Level "INFO" }
            }
        }
        else { Write-Log "No capture file created - may need trunk port or VLAN-aware NIC" -Level "WARNING" }
        $null = pktmon filter remove 2>$null
        Remove-Item "$tempPath*" -Force -ErrorAction SilentlyContinue
    }
    catch { Write-Log "pktmon error: $($_.Exception.Message)" -Level "ERROR" }
}

function Invoke-DHCPDiscovery {
    Write-Log "Starting DHCP scope discovery..." -Level "INFO"
    if (-not (Get-Module -ListAvailable -Name DhcpServer -ErrorAction SilentlyContinue)) {
        Write-Log "DhcpServer module not available (install RSAT-DHCP)" -Level "WARNING"
        return
    }
    try {
        Import-Module DhcpServer -ErrorAction Stop
        $dhcpServers = @()
        if ($DHCPServer) { $dhcpServers = $DHCPServer }
        else {
            try {
                $dhcpServers = (Get-DhcpServerInDC -ErrorAction Stop).DnsName
                Write-Log "Found $($dhcpServers.Count) DHCP server(s) in AD" -Level "INFO"
            }
            catch {
                Write-Log "Could not enumerate DHCP servers from AD: $($_.Exception.Message)" -Level "WARNING"
                return
            }
        }
        foreach ($server in $dhcpServers) {
            Write-Log "Querying DHCP server: $server" -Level "INFO"
            try {
                $scopes = Get-DhcpServerv4Scope -ComputerName $server -ErrorAction Stop
                foreach ($scope in $scopes) {
                    $vlanId = "Unknown"
                    $combinedText = "$($scope.Name) $($scope.Description)"
                    if ($combinedText -match 'V(?:LAN)?[-_\s]?(\d+)') { $vlanId = $Matches[1] }
                    $gateway = ""
                    try {
                        $options = Get-DhcpServerv4OptionValue -ComputerName $server -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                        $routerOption = $options | Where-Object { $_.OptionId -eq 3 }
                        if ($routerOption) { $gateway = $routerOption.Value -join ", " }
                    } catch { }
                    $activeHosts = 0
                    try {
                        $leases = Get-DhcpServerv4Lease -ComputerName $server -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                        $activeHosts = @($leases | Where-Object { $_.AddressState -eq "Active" }).Count
                    } catch { }
                    $cidr = 24
                    try {
                        $maskBytes = [System.Net.IPAddress]::Parse($scope.SubnetMask).GetAddressBytes()
                        $cidr = ($maskBytes | ForEach-Object { [Convert]::ToString($_, 2).Replace("0", "").Length } | Measure-Object -Sum).Sum
                    } catch { }
                    $subnet = "$($scope.ScopeId)/$cidr"
                    Add-DiscoveredVLAN -Subnet $subnet -VLANId $vlanId -Name $scope.Name -Gateway $gateway -Source "DHCP:$server" -Description $scope.Description -Confidence 90 -ActiveHosts $activeHosts
                }
                Write-Log "Found $($scopes.Count) scope(s) on $server" -Level "SUCCESS"
            }
            catch { Write-Log "Error querying ${server}: $($_.Exception.Message)" -Level "ERROR" }
        }
    }
    catch { Write-Log "DHCP discovery error: $($_.Exception.Message)" -Level "ERROR" }
}

function Invoke-ADSitesDiscovery {
    Write-Log "Starting AD Sites and Subnets discovery..." -Level "INFO"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $subnets = Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop
        foreach ($subnet in $subnets) {
            $siteName = ""
            if ($subnet.Site) { $siteName = ($subnet.Site -split ',')[0] -replace '^CN=', '' }
            $vlanId = "Unknown"
            $searchText = "$($subnet.Location) $($subnet.Description) $siteName"
            if ($searchText -match 'V(?:LAN)?[-_\s]?(\d+)') { $vlanId = $Matches[1] }
            Add-DiscoveredVLAN -Subnet $subnet.Name -VLANId $vlanId -Name $siteName -Site $siteName -Source "ADSites" -Description $subnet.Location -Confidence 85
        }
        Write-Log "Found $($subnets.Count) subnet(s) in AD Sites" -Level "SUCCESS"
    }
    catch {
        if ($_.Exception.Message -match "Unable to find a default server") { Write-Log "Not domain-joined or AD unavailable" -Level "WARNING" }
        else { Write-Log "AD Sites discovery error: $($_.Exception.Message)" -Level "ERROR" }
    }
}

function Invoke-ARPDiscovery {
    Write-Log "Starting ARP/Neighbor cache analysis..." -Level "INFO"
    $allNeighbors = @()
    try {
        $localNeighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' -and $_.IPAddress -notmatch '^(169\.254|224\.|239\.|255\.)' }
        $allNeighbors += $localNeighbors
        Write-Log "Found $($localNeighbors.Count) entries in local ARP cache" -Level "INFO"
    }
    catch {
        try {
            $arpOutput = arp -a 2>$null
            $arpEntries = $arpOutput | Select-String -Pattern '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\w+)' -AllMatches
            foreach ($m in $arpEntries.Matches) {
                $ip = $m.Groups[1].Value
                if ($ip -notmatch '^(169\.254|224\.|239\.|255\.)') { $allNeighbors += [PSCustomObject]@{ IPAddress = $ip } }
            }
        }
        catch { Write-Log "Could not read ARP cache" -Level "WARNING" }
    }
    if ($RemoteHosts) {
        foreach ($remoteHost in $RemoteHosts) {
            Write-Log "Querying ARP cache from $remoteHost..." -Level "INFO"
            try {
                $remoteNeighbors = Invoke-Command -ComputerName $remoteHost -ScriptBlock {
                    Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' -and $_.IPAddress -notmatch '^(169\.254|224\.|239\.|255\.)' }
                } -ErrorAction Stop
                $allNeighbors += $remoteNeighbors
                Write-Log "Found $($remoteNeighbors.Count) entries from $remoteHost" -Level "INFO"
            }
            catch { Write-Log "Could not query ${remoteHost}: $($_.Exception.Message)" -Level "WARNING" }
        }
    }
    $subnets = @{}
    foreach ($neighbor in $allNeighbors) {
        $subnet = Get-SubnetFromIP -IP $neighbor.IPAddress -CIDR 24
        if ($subnet) {
            if (-not $subnets.ContainsKey($subnet)) { $subnets[$subnet] = 0 }
            $subnets[$subnet]++
        }
    }
    foreach ($subnet in $subnets.Keys) {
        Add-DiscoveredVLAN -Subnet $subnet -Source "ARP" -Confidence 60 -ActiveHosts $subnets[$subnet] -Description "Detected via ARP cache analysis"
    }
    Write-Log "Identified $($subnets.Count) unique /24 subnet(s) from ARP data" -Level "SUCCESS"
}

function Invoke-RoutesDiscovery {
    Write-Log "Starting routing table analysis..." -Level "INFO"
    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.DestinationPrefix -ne '0.0.0.0/0' -and $_.DestinationPrefix -ne '255.255.255.255/32' -and
            $_.DestinationPrefix -notmatch '^(127\.|169\.254\.|224\.|239\.|255\.)' -and $_.DestinationPrefix -notmatch '/32$'
        }
        foreach ($route in $routes) {
            $gateway = if ($route.NextHop -eq '0.0.0.0') { "Direct" } else { $route.NextHop }
            $routeType = if ($route.RouteMetric -eq 0 -or $route.NextHop -eq '0.0.0.0') { "Connected" } else { "Remote" }
            $conf = if ($routeType -eq "Connected") { 80 } else { 40 }
            Add-DiscoveredVLAN -Subnet $route.DestinationPrefix -Gateway $gateway -Source "Routes:$routeType" -Confidence $conf -Description "Route type: $routeType, Interface: $($route.InterfaceAlias)"
        }
        Write-Log "Found $($routes.Count) relevant route(s)" -Level "SUCCESS"
    }
    catch { Write-Log "Routing table error: $($_.Exception.Message)" -Level "ERROR" }
}

function Invoke-AdaptersDiscovery {
    Write-Log "Starting network adapter VLAN analysis..." -Level "INFO"
    try {
        if (Get-Command Get-VMNetworkAdapterVlan -ErrorAction SilentlyContinue) {
            try {
                $vmVlans = Get-VMNetworkAdapterVlan -ErrorAction SilentlyContinue
                foreach ($vlan in $vmVlans) {
                    if ($vlan.AccessVlanId -gt 0) {
                        Add-DiscoveredVLAN -VLANId $vlan.AccessVlanId.ToString() -Source "Hyper-V" -Confidence 100 -Description "VM: $($vlan.VMName), Adapter: $($vlan.AdapterName)"
                        Write-Log "Found Hyper-V VLAN $($vlan.AccessVlanId) on $($vlan.VMName)" -Level "VLAN"
                    }
                }
            } catch { }
        }
        if (Get-Command Get-NetLbfoTeamNic -ErrorAction SilentlyContinue) {
            try {
                $teamNics = Get-NetLbfoTeamNic -ErrorAction SilentlyContinue
                foreach ($nic in $teamNics) {
                    if ($nic.VlanID -and $nic.VlanID -gt 0) {
                        Add-DiscoveredVLAN -VLANId $nic.VlanID.ToString() -Source "NICTeam" -Confidence 100 -Description "Team: $($nic.Team), NIC: $($nic.Name)"
                        Write-Log "Found NIC Team VLAN $($nic.VlanID) on $($nic.Name)" -Level "VLAN"
                    }
                }
            } catch { }
        }
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'VLAN|\.(\d+)$' -or $_.InterfaceDescription -match 'VLAN' }
        foreach ($adapter in $adapters) {
            $vlanId = "Unknown"
            if ($adapter.Name -match '\.(\d+)$|VLAN\s*(\d+)|VL(\d+)') {
                $vlanId = ($Matches[1], $Matches[2], $Matches[3] | Where-Object { $_ })[0]
            }
            Add-DiscoveredVLAN -VLANId $vlanId -Source "Adapter" -Confidence 95 -Description "Adapter: $($adapter.Name) - $($adapter.InterfaceDescription)"
        }
        $ipConfigs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' }
        foreach ($ip in $ipConfigs) {
            $networkSubnet = Get-SubnetFromIP -IP $ip.IPAddress -CIDR $ip.PrefixLength
            if ($networkSubnet) {
                Add-DiscoveredVLAN -Subnet $networkSubnet -Source "LocalIP" -Confidence 100 -Description "Local interface: $($ip.InterfaceAlias)"
            }
        }
        Write-Log "Adapter analysis complete" -Level "SUCCESS"
    }
    catch { Write-Log "Adapter analysis error: $($_.Exception.Message)" -Level "ERROR" }
}

function Invoke-SubnetProbe {
    Write-Log "Starting subnet gateway probe..." -Level "INFO"
    $ranges = if ($ProbeRanges) { $ProbeRanges } else { $script:DefaultProbeRanges }
    $gatewaysToProbe = @()
    foreach ($range in $ranges) {
        $parts = $range -split '/'
        $baseIP = $parts[0]
        $cidr = if ($parts.Count -gt 1) { [int]$parts[1] } else { 24 }
        $octets = $baseIP -split '\.'
        switch ($cidr) {
            8 {
                $commonSecondOctets = @(0, 1, 10, 20, 100, 200)
                $commonThirdOctets = @(0, 1, 10, 100)
                foreach ($second in $commonSecondOctets) {
                    foreach ($third in $commonThirdOctets) {
                        $gatewaysToProbe += "$($octets[0]).$second.$third.1"
                        $gatewaysToProbe += "$($octets[0]).$second.$third.254"
                    }
                }
            }
            {$_ -ge 12 -and $_ -le 16} {
                $commonThirdOctets = @(0, 1, 10, 20, 50, 100, 200)
                foreach ($third in $commonThirdOctets) {
                    $gatewaysToProbe += "$($octets[0]).$($octets[1]).$third.1"
                    $gatewaysToProbe += "$($octets[0]).$($octets[1]).$third.254"
                }
            }
            {$_ -ge 17 -and $_ -le 24} {
                for ($i = 0; $i -lt 10; $i++) {
                    $thirdOctet = [int]$octets[2] + $i
                    if ($thirdOctet -le 255) {
                        $gatewaysToProbe += "$($octets[0]).$($octets[1]).$thirdOctet.1"
                        $gatewaysToProbe += "$($octets[0]).$($octets[1]).$thirdOctet.254"
                    }
                }
            }
        }
    }
    $gatewaysToProbe = $gatewaysToProbe | Select-Object -Unique
    Write-Log "Probing $($gatewaysToProbe.Count) potential gateway addresses..." -Level "INFO"
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, 50)
    $runspacePool.Open()
    $jobs = @()
    $pingScript = {
        param($IP)
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $result = $ping.Send($IP, 500)
            if ($result.Status -eq 'Success') {
                return [PSCustomObject]@{ IP = $IP; ResponseTime = $result.RoundtripTime }
            }
        } catch { }
        return $null
    }
    foreach ($gateway in $gatewaysToProbe) {
        $powershell = [powershell]::Create().AddScript($pingScript).AddArgument($gateway)
        $powershell.RunspacePool = $runspacePool
        $jobs += @{ PowerShell = $powershell; Handle = $powershell.BeginInvoke(); Gateway = $gateway }
    }
    $respondingGateways = @()
    foreach ($job in $jobs) {
        try {
            $result = $job.PowerShell.EndInvoke($job.Handle)
            if ($result) { $respondingGateways += $result }
        } catch { }
        finally { $job.PowerShell.Dispose() }
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
    foreach ($gw in $respondingGateways) {
        $subnet = Get-SubnetFromIP -IP $gw.IP -CIDR 24
        if ($subnet) {
            Add-DiscoveredVLAN -Subnet $subnet -Gateway $gw.IP -Source "Probe" -Confidence 70 -Description "Gateway responded in $($gw.ResponseTime)ms"
        }
    }
    Write-Log "Found $($respondingGateways.Count) responding gateway(s)" -Level "SUCCESS"
}
#endregion

#region Export Functions
function Export-Results {
    param([string]$Path)
    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    switch ($extension) {
        '.csv' { $script:DiscoveredVLANs | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 }
        '.json' { $script:DiscoveredVLANs | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8 }
        '.html' { Export-HTMLReport -Path $Path }
        default { Export-HTMLReport -Path ($Path -replace '\.[^.]+$', '.html') }
    }
    Write-Log "Results exported to: $Path" -Level "SUCCESS"
}

function Export-HTMLReport {
    param([string]$Path)
    $sortedVLANs = $script:DiscoveredVLANs | Sort-Object Subnet
    $vlanRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($vlan in $sortedVLANs) {
        $confidenceColor = switch ([int]$vlan.Confidence) {
            {$_ -ge 90} { "#28a745" }
            {$_ -ge 70} { "#ffc107" }
            {$_ -ge 50} { "#fd7e14" }
            default { "#dc3545" }
        }
        $row = "<tr><td><strong>$($vlan.VLANId)</strong></td><td><code>$($vlan.Subnet)</code></td><td>$($vlan.Name)</td><td>$($vlan.Gateway)</td><td>$($vlan.Site)</td><td>$($vlan.Source)</td><td style=""text-align:center;""><span style=""background-color: $confidenceColor; color: white; padding: 2px 8px; border-radius: 4px;"">$($vlan.Confidence)%</span></td><td style=""text-align:center;"">$($vlan.ActiveHosts)</td><td>$($vlan.Description)</td></tr>"
        [void]$vlanRowsBuilder.AppendLine($row)
    }
    $vlanRows = $vlanRowsBuilder.ToString()
    $logBuilder = [System.Text.StringBuilder]::new()
    foreach ($entry in $script:DiscoveryLog) {
        [void]$logBuilder.AppendLine("<div>$entry</div>")
    }
    $logEntries = $logBuilder.ToString()
    $knownCount = @($sortedVLANs | Where-Object { $_.VLANId -ne 'Unknown' }).Count
    $hostSum = ($sortedVLANs | Measure-Object -Property ActiveHosts -Sum).Sum
    $sourceCount = @($sortedVLANs | Select-Object -ExpandProperty Source | ForEach-Object { ($_ -split ':')[0] } | Select-Object -Unique).Count
    $htmlBuilder = [System.Text.StringBuilder]::new()
    [void]$htmlBuilder.AppendLine('<!DOCTYPE html>')
    [void]$htmlBuilder.AppendLine('<html><head><meta charset="UTF-8"><title>VLAN Discovery Report</title>')
    [void]$htmlBuilder.AppendLine('<style>* { box-sizing: border-box; margin: 0; padding: 0; } body { font-family: Segoe UI, Tahoma, sans-serif; background: #f5f5f5; color: #333; }')
    [void]$htmlBuilder.AppendLine('.header { background: linear-gradient(135deg, #FF6600 0%, #cc5200 100%); color: white; padding: 30px; text-align: center; }')
    [void]$htmlBuilder.AppendLine('.header h1 { font-size: 2.5em; margin-bottom: 10px; }')
    [void]$htmlBuilder.AppendLine('.container { max-width: 1400px; margin: 0 auto; padding: 20px; }')
    [void]$htmlBuilder.AppendLine('.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }')
    [void]$htmlBuilder.AppendLine('.card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }')
    [void]$htmlBuilder.AppendLine('.card h3 { color: #6B7280; margin-bottom: 10px; font-size: 0.9em; text-transform: uppercase; }')
    [void]$htmlBuilder.AppendLine('.card .value { font-size: 2em; color: #FF6600; font-weight: bold; }')
    [void]$htmlBuilder.AppendLine('table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }')
    [void]$htmlBuilder.AppendLine('th { background: #6B7280; color: white; padding: 12px; text-align: left; }')
    [void]$htmlBuilder.AppendLine('td { padding: 10px 12px; border-bottom: 1px solid #eee; }')
    [void]$htmlBuilder.AppendLine('tr:hover { background: #f8f9fa; }')
    [void]$htmlBuilder.AppendLine('code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; }')
    [void]$htmlBuilder.AppendLine('.section-title { background: #FF6600; color: white; padding: 10px 20px; margin: 30px 0 0 0; border-radius: 8px 8px 0 0; }')
    [void]$htmlBuilder.AppendLine('.log-box { background: #1e1e1e; color: #d4d4d4; padding: 15px; font-family: Consolas, monospace; font-size: 0.85em; max-height: 300px; overflow-y: auto; border-radius: 0 0 8px 8px; }')
    [void]$htmlBuilder.AppendLine('.footer { text-align: center; padding: 30px; color: #6B7280; font-size: 0.9em; }</style>')
    [void]$htmlBuilder.AppendLine('</head><body>')
    [void]$htmlBuilder.AppendLine('<div class="header"><h1>VLAN Discovery Report</h1>')
    [void]$htmlBuilder.AppendLine("<div>$($script:CompanyName) - $($script:Tagline)</div>")
    [void]$htmlBuilder.AppendLine("<div style=""margin-top: 10px; opacity: 0.8;"">Generated: $($script:ReportDate)</div></div>")
    [void]$htmlBuilder.AppendLine('<div class="container">')
    [void]$htmlBuilder.AppendLine('<div class="summary">')
    [void]$htmlBuilder.AppendLine("<div class=""card""><h3>VLANs/Subnets Found</h3><div class=""value"">$($sortedVLANs.Count)</div></div>")
    [void]$htmlBuilder.AppendLine("<div class=""card""><h3>Known VLAN IDs</h3><div class=""value"">$knownCount</div></div>")
    [void]$htmlBuilder.AppendLine("<div class=""card""><h3>Active Hosts</h3><div class=""value"">$hostSum</div></div>")
    [void]$htmlBuilder.AppendLine("<div class=""card""><h3>Discovery Sources</h3><div class=""value"">$sourceCount</div></div>")
    [void]$htmlBuilder.AppendLine('</div>')
    [void]$htmlBuilder.AppendLine('<h2 class="section-title">Discovered VLANs and Subnets</h2>')
    [void]$htmlBuilder.AppendLine('<table><thead><tr><th>VLAN ID</th><th>Subnet</th><th>Name</th><th>Gateway</th><th>Site</th><th>Source</th><th>Confidence</th><th>Hosts</th><th>Description</th></tr></thead><tbody>')
    [void]$htmlBuilder.AppendLine($vlanRows)
    [void]$htmlBuilder.AppendLine('</tbody></table>')
    [void]$htmlBuilder.AppendLine('<h2 class="section-title">Discovery Log</h2>')
    [void]$htmlBuilder.AppendLine('<div class="log-box">')
    [void]$htmlBuilder.AppendLine($logEntries)
    [void]$htmlBuilder.AppendLine('</div></div>')
    [void]$htmlBuilder.AppendLine("<div class=""footer""><strong>$($script:CompanyName)</strong> - $($script:Tagline)<br>Report generated using Get-VLANDiscovery.ps1 v1.0</div>")
    [void]$htmlBuilder.AppendLine('</body></html>')
    $htmlBuilder.ToString() | Out-File -FilePath $Path -Encoding UTF8
}
#endregion

#region Main Execution
if (-not $Quiet) {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor DarkYellow
    Write-Host "            VLAN Discovery Tool v1.0" -ForegroundColor DarkYellow
    Write-Host "            $($script:CompanyName) - $($script:Tagline)" -ForegroundColor DarkYellow
    Write-Host "  ======================================================" -ForegroundColor DarkYellow
    Write-Host ""
}

if ($Method -contains 'All') {
    $Method = @('Adapters', 'Routes', 'ARP', 'ADSites', 'DHCP', 'Pktmon', 'Probe')
}

Write-Log "Starting VLAN discovery using methods: $($Method -join ', ')" -Level "INFO"
Write-Log "============================================================" -Level "INFO"

foreach ($m in $Method) {
    Write-Log "" -Level "INFO"
    switch ($m) {
        'Pktmon' { Invoke-PktmonDiscovery }
        'DHCP' { Invoke-DHCPDiscovery }
        'ADSites' { Invoke-ADSitesDiscovery }
        'ARP' { Invoke-ARPDiscovery }
        'Routes' { Invoke-RoutesDiscovery }
        'Adapters' { Invoke-AdaptersDiscovery }
        'Probe' { Invoke-SubnetProbe }
    }
}

Write-Log "" -Level "INFO"
Write-Log "============================================================" -Level "INFO"
Write-Log "Discovery complete. Found $($script:DiscoveredVLANs.Count) unique subnet(s)" -Level "SUCCESS"

if ($ExportPath) { Export-Results -Path $ExportPath }

if (-not $Quiet) {
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "--------" -ForegroundColor Cyan
    $sortedVLANs = $script:DiscoveredVLANs | Sort-Object -Property Subnet
    $tableData = foreach ($v in $sortedVLANs) {
        $nameDisplay = $v.Name
        if ($nameDisplay.Length -gt 20) { $nameDisplay = $nameDisplay.Substring(0,17) + "..." }
        $confValue = [string]$v.Confidence + [char]37
        [PSCustomObject]@{
            VLAN = $v.VLANId
            Subnet = $v.Subnet
            Name = $nameDisplay
            Gateway = $v.Gateway
            Source = $v.Source
            Conf = $confValue
            Hosts = $v.ActiveHosts
        }
    }
    $tableData | Format-Table -AutoSize
}

return $script:DiscoveredVLANs
#endregion
