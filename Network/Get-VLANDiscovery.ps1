<#
.SYNOPSIS
    VLAN Discovery Tool - Identifies VLANs in use across the network environment.

.DESCRIPTION
    Comprehensive VLAN discovery using multiple native Windows methods:
    
    1. PKTMON Analysis (Windows 10 2004+/Server 2019+)
       - Captures packets at driver level where 802.1Q tags may still be visible
       - Filters for VLAN-tagged traffic on trunk ports or VLAN-aware NICs
    
    2. DHCP Scope Enumeration
       - Queries Windows DHCP servers for all scopes (each scope typically = 1 VLAN)
       - Extracts subnet, gateway, VLAN ID from scope names/descriptions
    
    3. AD Sites and Subnets
       - Reads documented subnet-to-site mappings from Active Directory
       - Often correlates directly to VLAN assignments
    
    4. ARP/Neighbor Cache Analysis
       - Analyzes local ARP tables and can aggregate from multiple hosts
       - Identifies unique /24 subnets which often indicate separate VLANs
    
    5. Routing Table Analysis
       - Examines connected routes and gateway relationships
       - Identifies subnets the host has direct access to
    
    6. Network Adapter VLAN Configuration
       - Checks for VLAN-tagged virtual adapters (Hyper-V, Intel, Broadcom)
       - Detects NIC teaming VLAN configurations
    
    7. Subnet Probing
       - Optionally probes common VLAN subnet ranges to find active networks
       - Uses ICMP to detect gateways at .1 and .254

.PARAMETER Method
    Discovery method(s) to use. Default: All available methods.
    Valid: All, Pktmon, DHCP, ADSites, ARP, Routes, Adapters, Probe

.PARAMETER DHCPServer
    Specific DHCP server(s) to query. If not specified, discovers from AD.

.PARAMETER PktmonDuration
    Duration in seconds for packet capture. Default: 30

.PARAMETER ProbeRanges
    Subnet ranges to probe for active gateways. 
    Default: Common private ranges (10.x.x.1, 172.16-31.x.1, 192.168.x.1)

.PARAMETER RemoteHosts
    Additional hosts to query for ARP tables (requires WinRM).

.PARAMETER ExportPath
    Path to export results (CSV, JSON, or HTML).

.PARAMETER IncludeInactive
    Include subnets/VLANs that appear configured but have no active hosts.

.EXAMPLE
    .\Get-VLANDiscovery.ps1
    
    Runs all available discovery methods with defaults.

.EXAMPLE
    .\Get-VLANDiscovery.ps1 -Method DHCP,ADSites -ExportPath "C:\Reports\VLANs.html"
    
    Query DHCP and AD Sites only, export to HTML.

.EXAMPLE
    .\Get-VLANDiscovery.ps1 -Method Pktmon -PktmonDuration 60
    
    Run 60-second packet capture to detect VLAN tags.

.EXAMPLE
    .\Get-VLANDiscovery.ps1 -Method Probe -ProbeRanges @("10.0.0.0/8", "172.16.0.0/12")
    
    Probe specified ranges for active gateways.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, Admin rights for pktmon
    Version: 1.0
    
    VLAN Discovery Limitations:
    - 802.1Q tags are typically stripped by NIC drivers before Windows sees them
    - pktmon can sometimes capture tags on trunk ports or with specific NIC drivers
    - Most reliable methods are DHCP enumeration and AD Sites when available
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
$ProgressPreference = if ($Quiet) { "SilentlyContinue" } else { "Continue" }

# Branding
$script:BrandOrange = "#FF6600"
$script:BrandGrey = "#6B7280"
$script:CompanyName = "Yeyland Wutani LLC"
$script:Tagline = "Building Better Systems"

# Timestamp
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"

# Results collection
$script:DiscoveredVLANs = [System.Collections.ArrayList]::new()
$script:DiscoveryLog = [System.Collections.ArrayList]::new()

# Default probe ranges (common VLAN gateway addresses)
$script:DefaultProbeRanges = @(
    "10.0.0.0/8"
    "172.16.0.0/12"  
    "192.168.0.0/16"
)
#endregion

#region Helper Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    [void]$script:DiscoveryLog.Add($logEntry)
    
    if (-not $Quiet) {
        $color = switch ($Level) {
            "INFO"    { "White" }
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
            "VLAN"    { "Cyan" }
            default   { "Gray" }
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
    
    # Check for duplicates
    $existing = $script:DiscoveredVLANs | Where-Object { $_.Subnet -eq $Subnet }
    
    if ($existing) {
        # Update with higher confidence or more info
        if ($Confidence -gt $existing.Confidence) {
            $existing.Confidence = $Confidence
            $existing.Source = $Source
        }
        if ($VLANId -ne "Unknown" -and $existing.VLANId -eq "Unknown") {
            $existing.VLANId = $VLANId
        }
        if ($Name -and -not $existing.Name) {
            $existing.Name = $Name
        }
        if ($Gateway -and -not $existing.Gateway) {
            $existing.Gateway = $Gateway
        }
        $existing.ActiveHosts = [Math]::Max($existing.ActiveHosts, $ActiveHosts)
    }
    else {
        $vlanEntry = [PSCustomObject]@{
            Subnet       = $Subnet
            VLANId       = $VLANId
            Name         = $Name
            Gateway      = $Gateway
            SubnetMask   = ""
            Site         = $Site
            Description  = $Description
            Source       = $Source
            Confidence   = $Confidence
            ActiveHosts  = $ActiveHosts
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
        for ($i = 0; $i -lt 4; $i++) {
            $networkBytes += $ipBytes[$i] -band $maskBytes[$i]
        }
        
        return "$($networkBytes -join '.')/$CIDR"
    }
    catch {
        return $null
    }
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
    <#
    .DESCRIPTION
        Uses Windows Packet Monitor to capture traffic and detect 802.1Q VLAN tags.
        Requires Windows 10 2004+ or Server 2019+ and admin rights.
    #>
    
    Write-Log "Starting pktmon VLAN tag capture..." -Level "INFO"
    
    # Check prerequisites
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
        
        # Reset any existing filters
        $null = pktmon filter remove 2>$null
        
        # Add filter for 802.1Q tagged frames (EtherType 0x8100)
        Write-Log "Adding 802.1Q VLAN filter (EtherType 0x8100)..." -Level "INFO"
        $null = pktmon filter add VLAN8021Q -d 0x8100 2>$null
        
        # Start capture
        Write-Log "Capturing packets for $PktmonDuration seconds..." -Level "INFO"
        $null = pktmon start --capture --file-name $etlFile 2>$null
        
        # Wait for capture duration
        Start-Sleep -Seconds $PktmonDuration
        
        # Stop capture
        $null = pktmon stop 2>$null
        
        # Check if we got any packets
        if (Test-Path $etlFile) {
            $fileSize = (Get-Item $etlFile).Length
            Write-Log "Captured $([math]::Round($fileSize/1KB, 2)) KB of traffic" -Level "INFO"
            
            # Convert to text for analysis
            $null = pktmon format $etlFile -o $txtFile 2>$null
            
            if (Test-Path $txtFile) {
                $content = Get-Content $txtFile -Raw -ErrorAction SilentlyContinue
                
                # Parse for VLAN IDs (looking for 802.1Q headers)
                # VLAN ID is 12 bits in the 802.1Q tag
                $vlanPattern = 'VLAN[:\s]+(\d+)|VID[:\s]+(\d+)|802\.1[Qq][:\s]+(\d+)'
                $matches = [regex]::Matches($content, $vlanPattern)
                
                $foundVlans = @{}
                foreach ($match in $matches) {
                    $vlanId = ($match.Groups[1..3] | Where-Object { $_.Success }).Value
                    if ($vlanId -and $vlanId -match '^\d+$' -and [int]$vlanId -gt 0 -and [int]$vlanId -lt 4095) {
                        $foundVlans[$vlanId] = $true
                    }
                }
                
                if ($foundVlans.Count -gt 0) {
                    foreach ($vlanId in $foundVlans.Keys) {
                        Add-DiscoveredVLAN -VLANId $vlanId -Source "pktmon" -Confidence 95 -Description "Detected via 802.1Q packet capture"
                    }
                    Write-Log "Found $($foundVlans.Count) VLAN tag(s) in packet capture" -Level "SUCCESS"
                }
                else {
                    Write-Log "No 802.1Q VLAN tags detected (this is normal on access ports)" -Level "INFO"
                }
            }
        }
        else {
            Write-Log "No capture file created - may need trunk port or VLAN-aware NIC" -Level "WARNING"
        }
        
        # Cleanup
        $null = pktmon filter remove 2>$null
        Remove-Item "$tempPath*" -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "pktmon error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-DHCPDiscovery {
    <#
    .DESCRIPTION
        Enumerates DHCP scopes from Windows DHCP servers.
        Each scope typically represents one VLAN/subnet.
    #>
    
    Write-Log "Starting DHCP scope discovery..." -Level "INFO"
    
    # Check for DHCP module
    if (-not (Get-Module -ListAvailable -Name DhcpServer -ErrorAction SilentlyContinue)) {
        Write-Log "DhcpServer module not available (install RSAT-DHCP)" -Level "WARNING"
        return
    }
    
    try {
        Import-Module DhcpServer -ErrorAction Stop
        
        # Get DHCP servers
        $dhcpServers = @()
        
        if ($DHCPServer) {
            $dhcpServers = $DHCPServer
        }
        else {
            # Try to discover from AD
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
                    # Try to extract VLAN ID from scope name or description
                    $vlanId = "Unknown"
                    $combinedText = "$($scope.Name) $($scope.Description)"
                    
                    # Common patterns: "VLAN 10", "VLAN10", "V10", "VL10", "VLAN-10", "Vlan_10"
                    if ($combinedText -match 'V(?:LAN)?[-_\s]?(\d+)') {
                        $vlanId = $Matches[1]
                    }
                    # Also check for subnet-based naming like "10.10.10.0 - VLAN 10"
                    elseif ($combinedText -match '(\d+)\s*[-–]\s*(?:VLAN|Network|Subnet)') {
                        $vlanId = $Matches[1]
                    }
                    
                    # Get scope options for gateway
                    $gateway = ""
                    try {
                        $options = Get-DhcpServerv4OptionValue -ComputerName $server -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                        $routerOption = $options | Where-Object { $_.OptionId -eq 3 }
                        if ($routerOption) {
                            $gateway = $routerOption.Value -join ", "
                        }
                    }
                    catch { }
                    
                    # Get lease count for activity indication
                    $activeHosts = 0
                    try {
                        $leases = Get-DhcpServerv4Lease -ComputerName $server -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                        $activeHosts = ($leases | Where-Object { $_.AddressState -eq "Active" }).Count
                    }
                    catch { }
                    
                    # Calculate CIDR from subnet mask
                    $cidr = 24
                    try {
                        $maskBytes = [System.Net.IPAddress]::Parse($scope.SubnetMask).GetAddressBytes()
                        $cidr = ($maskBytes | ForEach-Object { [Convert]::ToString($_, 2).Replace("0", "").Length } | Measure-Object -Sum).Sum
                    }
                    catch { }
                    
                    $subnet = "$($scope.ScopeId)/$cidr"
                    
                    Add-DiscoveredVLAN `
                        -Subnet $subnet `
                        -VLANId $vlanId `
                        -Name $scope.Name `
                        -Gateway $gateway `
                        -Source "DHCP:$server" `
                        -Description $scope.Description `
                        -Confidence 90 `
                        -ActiveHosts $activeHosts
                }
                
                Write-Log "Found $($scopes.Count) scope(s) on $server" -Level "SUCCESS"
            }
            catch {
                Write-Log "Error querying $server`: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    catch {
        Write-Log "DHCP discovery error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-ADSitesDiscovery {
    <#
    .DESCRIPTION
        Reads subnet definitions from Active Directory Sites and Services.
        These are administratively defined and often map to VLANs.
    #>
    
    Write-Log "Starting AD Sites and Subnets discovery..." -Level "INFO"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $subnets = Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop
        
        foreach ($subnet in $subnets) {
            # Extract site name from distinguished name
            $siteName = ""
            if ($subnet.Site) {
                $siteName = ($subnet.Site -split ',')[0] -replace '^CN=', ''
            }
            
            # Try to extract VLAN from location or description
            $vlanId = "Unknown"
            $searchText = "$($subnet.Location) $($subnet.Description) $siteName"
            if ($searchText -match 'V(?:LAN)?[-_\s]?(\d+)') {
                $vlanId = $Matches[1]
            }
            
            Add-DiscoveredVLAN `
                -Subnet $subnet.Name `
                -VLANId $vlanId `
                -Name $siteName `
                -Site $siteName `
                -Source "ADSites" `
                -Description $subnet.Location `
                -Confidence 85
        }
        
        Write-Log "Found $($subnets.Count) subnet(s) in AD Sites" -Level "SUCCESS"
    }
    catch {
        if ($_.Exception.Message -match "Unable to find a default server") {
            Write-Log "Not domain-joined or AD unavailable" -Level "WARNING"
        }
        else {
            Write-Log "AD Sites discovery error: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Invoke-ARPDiscovery {
    <#
    .DESCRIPTION
        Analyzes ARP/neighbor cache to identify unique subnets.
        Can aggregate from multiple hosts for broader visibility.
    #>
    
    Write-Log "Starting ARP/Neighbor cache analysis..." -Level "INFO"
    
    $allNeighbors = @()
    
    # Get local ARP cache
    try {
        $localNeighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | 
            Where-Object { $_.State -ne 'Unreachable' -and $_.IPAddress -notmatch '^(169\.254|224\.|239\.|255\.)' }
        
        $allNeighbors += $localNeighbors
        Write-Log "Found $($localNeighbors.Count) entries in local ARP cache" -Level "INFO"
    }
    catch {
        # Fallback to arp -a
        try {
            $arpOutput = arp -a 2>$null
            $arpEntries = $arpOutput | Select-String -Pattern '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\w+)' -AllMatches
            
            foreach ($match in $arpEntries.Matches) {
                $ip = $match.Groups[1].Value
                if ($ip -notmatch '^(169\.254|224\.|239\.|255\.)') {
                    $allNeighbors += [PSCustomObject]@{ IPAddress = $ip }
                }
            }
        }
        catch {
            Write-Log "Could not read ARP cache" -Level "WARNING"
        }
    }
    
    # Query remote hosts if specified
    if ($RemoteHosts) {
        foreach ($remoteHost in $RemoteHosts) {
            Write-Log "Querying ARP cache from $remoteHost..." -Level "INFO"
            try {
                $remoteNeighbors = Invoke-Command -ComputerName $remoteHost -ScriptBlock {
                    Get-NetNeighbor -AddressFamily IPv4 | 
                        Where-Object { $_.State -ne 'Unreachable' -and $_.IPAddress -notmatch '^(169\.254|224\.|239\.|255\.)' }
                } -ErrorAction Stop
                
                $allNeighbors += $remoteNeighbors
                Write-Log "Found $($remoteNeighbors.Count) entries from $remoteHost" -Level "INFO"
            }
            catch {
                Write-Log "Could not query $remoteHost`: $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }
    
    # Group by /24 subnets
    $subnets = @{}
    foreach ($neighbor in $allNeighbors) {
        $subnet = Get-SubnetFromIP -IP $neighbor.IPAddress -CIDR 24
        if ($subnet) {
            if (-not $subnets.ContainsKey($subnet)) {
                $subnets[$subnet] = 0
            }
            $subnets[$subnet]++
        }
    }
    
    foreach ($subnet in $subnets.Keys) {
        Add-DiscoveredVLAN `
            -Subnet $subnet `
            -Source "ARP" `
            -Confidence 60 `
            -ActiveHosts $subnets[$subnet] `
            -Description "Detected via ARP cache analysis"
    }
    
    Write-Log "Identified $($subnets.Count) unique /24 subnet(s) from ARP data" -Level "SUCCESS"
}

function Invoke-RoutesDiscovery {
    <#
    .DESCRIPTION
        Analyzes routing table to identify connected and reachable subnets.
    #>
    
    Write-Log "Starting routing table analysis..." -Level "INFO"
    
    try {
        # Get IPv4 routes
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | 
            Where-Object { 
                $_.DestinationPrefix -ne '0.0.0.0/0' -and 
                $_.DestinationPrefix -ne '255.255.255.255/32' -and
                $_.DestinationPrefix -notmatch '^(127\.|169\.254\.|224\.|239\.|255\.)' -and
                $_.DestinationPrefix -notmatch '/32$'
            }
        
        foreach ($route in $routes) {
            $gateway = if ($route.NextHop -eq '0.0.0.0') { "Direct" } else { $route.NextHop }
            $routeType = if ($route.RouteMetric -eq 0 -or $route.NextHop -eq '0.0.0.0') { "Connected" } else { "Remote" }
            
            Add-DiscoveredVLAN `
                -Subnet $route.DestinationPrefix `
                -Gateway $gateway `
                -Source "Routes:$routeType" `
                -Confidence $(if ($routeType -eq "Connected") { 80 } else { 40 }) `
                -Description "Route type: $routeType, Interface: $($route.InterfaceAlias)"
        }
        
        Write-Log "Found $($routes.Count) relevant route(s)" -Level "SUCCESS"
    }
    catch {
        Write-Log "Routing table error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-AdaptersDiscovery {
    <#
    .DESCRIPTION
        Checks for VLAN-tagged virtual adapters and NIC teaming configurations.
    #>
    
    Write-Log "Starting network adapter VLAN analysis..." -Level "INFO"
    
    try {
        # Check for Hyper-V VLAN configurations
        if (Get-Command Get-VMNetworkAdapterVlan -ErrorAction SilentlyContinue) {
            try {
                $vmVlans = Get-VMNetworkAdapterVlan -ErrorAction SilentlyContinue
                foreach ($vlan in $vmVlans) {
                    if ($vlan.AccessVlanId -gt 0) {
                        Add-DiscoveredVLAN `
                            -VLANId $vlan.AccessVlanId.ToString() `
                            -Source "Hyper-V" `
                            -Confidence 100 `
                            -Description "VM: $($vlan.VMName), Adapter: $($vlan.AdapterName)"
                        Write-Log "Found Hyper-V VLAN $($vlan.AccessVlanId) on $($vlan.VMName)" -Level "VLAN"
                    }
                }
            }
            catch { }
        }
        
        # Check for NIC Teaming VLANs
        if (Get-Command Get-NetLbfoTeamNic -ErrorAction SilentlyContinue) {
            try {
                $teamNics = Get-NetLbfoTeamNic -ErrorAction SilentlyContinue
                foreach ($nic in $teamNics) {
                    if ($nic.VlanID -and $nic.VlanID -gt 0) {
                        Add-DiscoveredVLAN `
                            -VLANId $nic.VlanID.ToString() `
                            -Source "NICTeam" `
                            -Confidence 100 `
                            -Description "Team: $($nic.Team), NIC: $($nic.Name)"
                        Write-Log "Found NIC Team VLAN $($nic.VlanID) on $($nic.Name)" -Level "VLAN"
                    }
                }
            }
            catch { }
        }
        
        # Check adapter names for VLAN indicators
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match 'VLAN|\.(\d+)$' -or $_.InterfaceDescription -match 'VLAN' }
        
        foreach ($adapter in $adapters) {
            $vlanId = "Unknown"
            if ($adapter.Name -match '\.(\d+)$|VLAN\s*(\d+)|VL(\d+)') {
                $vlanId = ($Matches[1], $Matches[2], $Matches[3] | Where-Object { $_ })[0]
            }
            
            Add-DiscoveredVLAN `
                -VLANId $vlanId `
                -Source "Adapter" `
                -Confidence 95 `
                -Description "Adapter: $($adapter.Name) - $($adapter.InterfaceDescription)"
        }
        
        # Get IPs from all adapters to identify connected subnets
        $ipConfigs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
            Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' }
        
        foreach ($ip in $ipConfigs) {
            $subnet = "$($ip.IPAddress)/$($ip.PrefixLength)"
            # Calculate network address
            $networkSubnet = Get-SubnetFromIP -IP $ip.IPAddress -CIDR $ip.PrefixLength
            if ($networkSubnet) {
                Add-DiscoveredVLAN `
                    -Subnet $networkSubnet `
                    -Source "LocalIP" `
                    -Confidence 100 `
                    -Description "Local interface: $($ip.InterfaceAlias)"
            }
        }
        
        Write-Log "Adapter analysis complete" -Level "SUCCESS"
    }
    catch {
        Write-Log "Adapter analysis error: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-SubnetProbe {
    <#
    .DESCRIPTION
        Probes common gateway addresses to discover active subnets.
        Uses ICMP to find responding gateways at .1 and .254.
    #>
    
    Write-Log "Starting subnet gateway probe..." -Level "INFO"
    
    $ranges = if ($ProbeRanges) { $ProbeRanges } else { $script:DefaultProbeRanges }
    
    # Build list of gateway IPs to probe
    $gatewaysToProbe = @()
    
    foreach ($range in $ranges) {
        # Parse CIDR
        $parts = $range -split '/'
        $baseIP = $parts[0]
        $cidr = if ($parts.Count -gt 1) { [int]$parts[1] } else { 24 }
        
        # For /8 networks, only probe x.x.x.1 for each /24
        # For /16, probe x.x.x.1 for each /24
        # For /24, probe .1 and .254
        
        $octets = $baseIP -split '\.'
        
        switch ($cidr) {
            8 {
                # Probe common /24s: x.0.0.1, x.1.0.1, x.10.0.1, etc.
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
                # For /12-/16, probe some common third octets
                $commonThirdOctets = @(0, 1, 10, 20, 50, 100, 200)
                foreach ($third in $commonThirdOctets) {
                    $gatewaysToProbe += "$($octets[0]).$($octets[1]).$third.1"
                    $gatewaysToProbe += "$($octets[0]).$($octets[1]).$third.254"
                }
            }
            {$_ -ge 17 -and $_ -le 24} {
                # For /17-/24, probe .1 and .254 for each /24
                # Limit to first 10 subnets for speed
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
    
    # Parallel ping using runspaces for speed
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, 50)
    $runspacePool.Open()
    
    $jobs = @()
    $pingScript = {
        param($IP)
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $result = $ping.Send($IP, 500)
            if ($result.Status -eq 'Success') {
                return [PSCustomObject]@{
                    IP = $IP
                    ResponseTime = $result.RoundtripTime
                }
            }
        }
        catch { }
        return $null
    }
    
    foreach ($gateway in $gatewaysToProbe) {
        $powershell = [powershell]::Create().AddScript($pingScript).AddArgument($gateway)
        $powershell.RunspacePool = $runspacePool
        $jobs += @{
            PowerShell = $powershell
            Handle = $powershell.BeginInvoke()
            Gateway = $gateway
        }
    }
    
    # Collect results
    $respondingGateways = @()
    foreach ($job in $jobs) {
        try {
            $result = $job.PowerShell.EndInvoke($job.Handle)
            if ($result) {
                $respondingGateways += $result
            }
        }
        catch { }
        finally {
            $job.PowerShell.Dispose()
        }
    }
    
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    # Add discovered subnets
    foreach ($gw in $respondingGateways) {
        $subnet = Get-SubnetFromIP -IP $gw.IP -CIDR 24
        if ($subnet) {
            Add-DiscoveredVLAN `
                -Subnet $subnet `
                -Gateway $gw.IP `
                -Source "Probe" `
                -Confidence 70 `
                -Description "Gateway responded in $($gw.ResponseTime)ms"
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
        '.csv' {
            $script:DiscoveredVLANs | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        }
        '.json' {
            $script:DiscoveredVLANs | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
        }
        '.html' {
            Export-HTMLReport -Path $Path
        }
        default {
            Export-HTMLReport -Path ($Path -replace '\.[^.]+$', '.html')
        }
    }
    
    Write-Log "Results exported to: $Path" -Level "SUCCESS"
}

function Export-HTMLReport {
    param([string]$Path)
    
    $sortedVLANs = $script:DiscoveredVLANs | Sort-Object -Property @{Expression={[int]($_.VLANId -replace '\D','0')}}, Subnet
    
    $vlanRows = ""
    foreach ($vlan in $sortedVLANs) {
        $confidenceColor = switch ([int]$vlan.Confidence) {
            {$_ -ge 90} { "#28a745" }  # Green
            {$_ -ge 70} { "#ffc107" }  # Yellow
            {$_ -ge 50} { "#fd7e14" }  # Orange
            default     { "#dc3545" }  # Red
        }
        
        $vlanRows += @"
        <tr>
            <td><strong>$($vlan.VLANId)</strong></td>
            <td><code>$($vlan.Subnet)</code></td>
            <td>$($vlan.Name)</td>
            <td>$($vlan.Gateway)</td>
            <td>$($vlan.Site)</td>
            <td>$($vlan.Source)</td>
            <td style="text-align:center;">
                <span style="background-color: $confidenceColor; color: white; padding: 2px 8px; border-radius: 4px;">$($vlan.Confidence)%</span>
            </td>
            <td style="text-align:center;">$($vlan.ActiveHosts)</td>
            <td>$($vlan.Description)</td>
        </tr>
"@
    }
    
    $logEntries = ($script:DiscoveryLog | ForEach-Object { "<div>$_</div>" }) -join "`n"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>VLAN Discovery Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .header { background: linear-gradient(135deg, $($script:BrandOrange) 0%, #cc5200 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .tagline { color: rgba(255,255,255,0.9); font-size: 1.1em; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { color: $($script:BrandGrey); margin-bottom: 10px; font-size: 0.9em; text-transform: uppercase; }
        .card .value { font-size: 2em; color: $($script:BrandOrange); font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }
        th { background: $($script:BrandGrey); color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 10px 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }
        .section-title { background: $($script:BrandOrange); color: white; padding: 10px 20px; margin: 30px 0 0 0; border-radius: 8px 8px 0 0; }
        .log-box { background: #1e1e1e; color: #d4d4d4; padding: 15px; font-family: 'Consolas', monospace; font-size: 0.85em; max-height: 300px; overflow-y: auto; border-radius: 0 0 8px 8px; }
        .footer { text-align: center; padding: 30px; color: $($script:BrandGrey); font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 VLAN Discovery Report</h1>
        <div class="tagline">$($script:CompanyName) — $($script:Tagline)</div>
        <div style="margin-top: 10px; opacity: 0.8;">Generated: $($script:ReportDate)</div>
    </div>
    
    <div class="container">
        <div class="summary">
            <div class="card">
                <h3>VLANs/Subnets Found</h3>
                <div class="value">$($sortedVLANs.Count)</div>
            </div>
            <div class="card">
                <h3>Known VLAN IDs</h3>
                <div class="value">$(($sortedVLANs | Where-Object { $_.VLANId -ne 'Unknown' }).Count)</div>
            </div>
            <div class="card">
                <h3>Active Hosts</h3>
                <div class="value">$(($sortedVLANs | Measure-Object -Property ActiveHosts -Sum).Sum)</div>
            </div>
            <div class="card">
                <h3>Discovery Sources</h3>
                <div class="value">$(($sortedVLANs | Select-Object -ExpandProperty Source | ForEach-Object { ($_ -split ':')[0] } | Select-Object -Unique).Count)</div>
            </div>
        </div>
        
        <h2 class="section-title">Discovered VLANs and Subnets</h2>
        <table>
            <thead>
                <tr>
                    <th>VLAN ID</th>
                    <th>Subnet</th>
                    <th>Name</th>
                    <th>Gateway</th>
                    <th>Site</th>
                    <th>Source</th>
                    <th>Confidence</th>
                    <th>Hosts</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                $vlanRows
            </tbody>
        </table>
        
        <h2 class="section-title">Discovery Log</h2>
        <div class="log-box">
            $logEntries
        </div>
    </div>
    
    <div class="footer">
        <strong>$($script:CompanyName)</strong> — $($script:Tagline)<br>
        Report generated using Get-VLANDiscovery.ps1 v1.0
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $Path -Encoding UTF8
}

#endregion

#region Main Execution

# Banner
if (-not $Quiet) {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
    Write-Host "  ║           VLAN Discovery Tool v1.0                       ║" -ForegroundColor DarkYellow
    Write-Host "  ║           $($script:CompanyName) — $($script:Tagline)            ║" -ForegroundColor DarkYellow
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
    Write-Host ""
}

# Expand 'All' to individual methods
if ($Method -contains 'All') {
    $Method = @('Adapters', 'Routes', 'ARP', 'ADSites', 'DHCP', 'Pktmon', 'Probe')
}

Write-Log "Starting VLAN discovery using methods: $($Method -join ', ')" -Level "INFO"
Write-Log "=" * 60 -Level "INFO"

# Execute discovery methods
foreach ($m in $Method) {
    Write-Log "" -Level "INFO"
    switch ($m) {
        'Pktmon'   { Invoke-PktmonDiscovery }
        'DHCP'     { Invoke-DHCPDiscovery }
        'ADSites'  { Invoke-ADSitesDiscovery }
        'ARP'      { Invoke-ARPDiscovery }
        'Routes'   { Invoke-RoutesDiscovery }
        'Adapters' { Invoke-AdaptersDiscovery }
        'Probe'    { Invoke-SubnetProbe }
    }
}

Write-Log "" -Level "INFO"
Write-Log "=" * 60 -Level "INFO"
Write-Log "Discovery complete. Found $($script:DiscoveredVLANs.Count) unique subnet(s)" -Level "SUCCESS"

# Export if requested
if ($ExportPath) {
    Export-Results -Path $ExportPath
}

# Console summary
if (-not $Quiet) {
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "--------" -ForegroundColor Cyan
    
    $sortedVLANs = $script:DiscoveredVLANs | Sort-Object -Property Subnet
    
    # Build formatted output
    $tableData = foreach ($v in $sortedVLANs) {
        [PSCustomObject]@{
            VLAN    = $v.VLANId
            Subnet  = $v.Subnet
            Name    = if ($v.Name.Length -gt 20) { $v.Name.Substring(0,17) + "..." } else { $v.Name }
            Gateway = $v.Gateway
            Source  = $v.Source
            Conf    = "$($v.Confidence)%"
            Hosts   = $v.ActiveHosts
        }
    }
    
    $tableData | Format-Table -AutoSize
}

# Return results
return $script:DiscoveredVLANs

#endregion
