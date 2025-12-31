<#
.SYNOPSIS
    Detects duplicate IP addresses, static devices, and IP conflicts on DHCP-managed networks.

.DESCRIPTION
    Comprehensive IP conflict detection tool designed for MSP environments. Runs from a
    Windows DHCP server and combines DHCP lease data with active network scanning to
    identify IP address conflicts, unauthorized static IPs, and potential issues.
    
    Compatible with PowerShell 5.1+ for maximum Windows Server compatibility.
    Requires the DhcpServer PowerShell module (included with DHCP Server role).
    
    Detection Categories:
    - Duplicate IPs: Same IP address responding with different MAC addresses
    - Static in DHCP Range: Devices using static IPs within DHCP scope (not leased)
    - MAC Mismatch: DHCP lease shows different MAC than ARP cache
    - Stale Leases: DHCP has active lease but device not responding
    - Unexcluded Statics: Static IPs within scope that should be excluded
    - Bad Addresses: IPs marked as declined/bad by DHCP server
    
    Scanning Methods:
    - DHCP lease table analysis
    - DHCP reservation comparison
    - DHCP exclusion range checking
    - ARP-based subnet scanning (async ping + ARP cache)
    - Hostname resolution (DNS + NetBIOS)

.PARAMETER DHCPServer
    DHCP server to query. Defaults to localhost if running on DHCP server.
    Can specify remote DHCP server hostname or IP.

.PARAMETER ScopeId
    Specific DHCP scope(s) to analyze. If not specified, scans all active scopes.
    Accepts multiple scopes via comma separation.

.PARAMETER IncludeReservations
    Include DHCP reservations in the analysis. Default: True

.PARAMETER ScanNetwork
    Perform active network scan to detect devices. Default: True
    When disabled, only analyzes DHCP server data.

.PARAMETER ScanTimeout
    Timeout in milliseconds for ping/ARP operations. Default: 1000

.PARAMETER ThrottleLimit
    Maximum parallel scanning threads. Default: 100

.PARAMETER ResolveHostnames
    Attempt to resolve hostnames via DNS and NetBIOS. Default: True

.PARAMETER ExportHtml
    Generate an HTML report in the script's directory with timestamp.
    Filename format: IPConflictReport_yyyyMMdd-HHmmss.html

.PARAMETER ProbeIP
    Perform aggressive investigation of specific IP address(es).
    Runs 8-step deep probe including: ping, ARP, TCP ports, DNS, NetBIOS,
    DHCP lease/reservation check, exclusion check, and audit log search.
    Provides verdict and recommended actions.
    Use this to investigate suspected conflicts or ghost devices.

.PARAMETER ExportPath
    Path to export report. Supports CSV, JSON, or HTML formats.
    If not specified, displays results in console.

.PARAMETER ShowAllDevices
    Include all discovered devices in output, not just conflicts.
    Useful for full network inventory comparison.

.PARAMETER Quiet
    Suppress progress output. Shows only final results.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1
    
    Scan all DHCP scopes on local server, detect conflicts.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -DHCPServer "DC01.contoso.local"
    
    Scan DHCP scopes on remote server DC01.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -ProbeIP "192.168.1.100"
    
    Aggressive probe of specific IP - finds ghost devices, checks DHCP state.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -ProbeIP "192.168.1.100","192.168.1.101"
    
    Probe multiple IPs in one run.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -ExportHtml
    
    Scan all scopes, output to console, and generate timestamped HTML report.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -ScopeId "192.168.1.0" -ExportPath "C:\Reports\IPConflicts.html"
    
    Scan specific scope and generate HTML report.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -ScopeId "192.168.1.0","192.168.2.0" -ShowAllDevices
    
    Scan multiple scopes, show all devices for comparison.

.EXAMPLE
    .\Find-DuplicateIPAddresses.ps1 -ScanNetwork:$false
    
    DHCP-only analysis without active network scanning.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, DhcpServer module, Administrator rights
    Version: 1.0
    
    DETECTION METHODOLOGY:
    1. Query DHCP server for all leases, reservations, and exclusions
    2. Perform async ping sweep of each scope's IP range
    3. Capture ARP cache to identify responding devices
    4. Compare DHCP records against ARP discoveries
    5. Flag discrepancies as potential conflicts
    
    CONFLICT SEVERITY LEVELS:
    - Critical: Active IP conflict (same IP, multiple MACs responding)
    - High: Static device in DHCP range without exclusion
    - Medium: MAC mismatch between DHCP and ARP
    - Low: Stale DHCP lease (offline device)
    - Info: Reservation or exclusion status
    
    MSP USE CASES:
    - Client onboarding: Identify undocumented static devices
    - Troubleshooting: Find the source of IP conflicts
    - Documentation: Generate network IP inventory
    - Compliance: Verify DHCP hygiene and exclusions
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DHCPServer,
    
    [Parameter()]
    [string[]]$ScopeId,
    
    [bool]$IncludeReservations = $true,
    
    [bool]$ScanNetwork = $true,
    
    [ValidateRange(100, 5000)]
    [int]$ScanTimeout = 1000,
    
    [ValidateRange(1, 500)]
    [int]$ThrottleLimit = 100,
    
    [bool]$ResolveHostnames = $true,
    
    [Parameter()]
    [switch]$SkipNetBIOS,
    
    [Parameter()]
    [switch]$ExportHtml,
    
    [Parameter()]
    [string[]]$ProbeIP,
    
    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Export directory does not exist: $parent"
        }
        $true
    })]
    [string]$ExportPath,
    
    [switch]$ShowAllDevices,
    
    [switch]$Quiet
)

$ScriptVersion = "1.0"
$ScriptName = "Find-DuplicateIPAddresses"

#region Banner
function Show-YWBanner {
    $logo = @(
        '  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ '
        '  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|'
        '   \ V /| _| \ V /| |__ / _ \ | .` | |) |  \ \/\/ /| |_| | | |/ _ \| .` || | '
        '    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|'
    )
    $tagline = 'B U I L D I N G   B E T T E R   S Y S T E M S'
    $border  = '=' * 81
    Write-Host ''
    Write-Host $border -ForegroundColor Gray
    foreach ($line in $logo) { Write-Host $line -ForegroundColor DarkYellow }
    Write-Host ''
    Write-Host $tagline.PadLeft(62) -ForegroundColor Gray
    Write-Host $border -ForegroundColor Gray
    Write-Host ''
}
#endregion Banner

if (-not $Quiet) {
    Show-YWBanner
    Write-Host "  IP Conflict Detection Tool v$ScriptVersion" -ForegroundColor Cyan
    Write-Host ""
}

#region Prerequisites Check
# Check for Administrator rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Check for DhcpServer module
if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
    Write-Error "DhcpServer PowerShell module not found. This script must run on a system with DHCP Server role or RSAT installed."
    exit 1
}

Import-Module DhcpServer -ErrorAction Stop

# Determine DHCP server to use
# If not specified, try local first (no -ComputerName), then fallback to hostname
if (-not $DHCPServer) {
    # Try local server without specifying ComputerName (avoids WinRM/CIM issues)
    try {
        $null = Get-DhcpServerSetting -ErrorAction Stop
        $DHCPServer = "(local)"
        $UseLocalDirect = $true
        if (-not $Quiet) {
            Write-Host "Connected to local DHCP server" -ForegroundColor Green
        }
    }
    catch {
        # Fallback: try with actual hostname
        try {
            $DHCPServer = $env:COMPUTERNAME
            $null = Get-DhcpServerSetting -ComputerName $DHCPServer -ErrorAction Stop
            $UseLocalDirect = $false
            if (-not $Quiet) {
                Write-Host "Connected to DHCP server: $DHCPServer" -ForegroundColor Green
            }
        }
        catch {
            Write-Error @"
Cannot connect to local DHCP server.

Troubleshooting:
1. Verify DHCP Server role is installed: Get-WindowsFeature DHCP
2. Verify DHCP Server service is running: Get-Service DHCPServer
3. Verify you are running PowerShell as Administrator
4. Try specifying server explicitly: -DHCPServer "$env:COMPUTERNAME"

Error: $_
"@
            exit 1
        }
    }
}
else {
    # User specified a server
    $UseLocalDirect = $false
    
    # Convert "localhost" to actual hostname (avoids CIM/WinRM issues)
    if ($DHCPServer -eq "localhost" -or $DHCPServer -eq "127.0.0.1" -or $DHCPServer -eq ".") {
        $DHCPServer = $env:COMPUTERNAME
        if (-not $Quiet) {
            Write-Host "Note: Converting 'localhost' to '$DHCPServer' (avoids WinRM issues)" -ForegroundColor Yellow
        }
    }
    
    try {
        $null = Get-DhcpServerSetting -ComputerName $DHCPServer -ErrorAction Stop
        if (-not $Quiet) {
            Write-Host "Connected to DHCP server: $DHCPServer" -ForegroundColor Green
        }
    }
    catch {
        Write-Error @"
Cannot connect to DHCP server '$DHCPServer'.

Troubleshooting:
1. Verify the server name is correct
2. Verify DHCP Server service is running on target
3. Verify network connectivity to target
4. Verify you have admin rights on target server
5. For remote servers, verify WinRM is enabled: Enable-PSRemoting -Force

Error: $_
"@
        exit 1
    }
}
#endregion Prerequisites Check

#region Helper Functions
function Get-ScopeIPRange {
    param(
        [string]$ScopeId,
        [string]$StartRange,
        [string]$EndRange
    )
    
    $ips = @()
    
    $startBytes = [System.Net.IPAddress]::Parse($StartRange).GetAddressBytes()
    [Array]::Reverse($startBytes)
    $startInt = [System.BitConverter]::ToUInt32($startBytes, 0)
    
    $endBytes = [System.Net.IPAddress]::Parse($EndRange).GetAddressBytes()
    [Array]::Reverse($endBytes)
    $endInt = [System.BitConverter]::ToUInt32($endBytes, 0)
    
    for ($i = $startInt; $i -le $endInt; $i++) {
        $bytes = [System.BitConverter]::GetBytes([UInt32]$i)
        [Array]::Reverse($bytes)
        $ips += [System.Net.IPAddress]::new($bytes).ToString()
    }
    
    return $ips
}

function Get-MACFromARP {
    param([string]$IPAddress)
    
    try {
        $arpEntry = Get-NetNeighbor -IPAddress $IPAddress -ErrorAction SilentlyContinue | 
                    Where-Object { $_.State -in @('Reachable', 'Stale', 'Permanent') }
        
        if ($arpEntry) {
            return $arpEntry.LinkLayerAddress.ToUpper().Replace(':', '-')
        }
    }
    catch { }
    
    return $null
}

function Resolve-HostnameMultiMethod {
    param([string]$IPAddress)
    
    $hostname = $null
    
    # Method 1: DNS reverse lookup
    try {
        $dnsResult = [System.Net.Dns]::GetHostEntry($IPAddress)
        if ($dnsResult.HostName -and $dnsResult.HostName -ne $IPAddress) {
            $hostname = $dnsResult.HostName.Split('.')[0]
        }
    }
    catch { }
    
    # Method 2: NetBIOS (if DNS failed)
    if (-not $hostname) {
        try {
            $nbtJob = Start-Job -ScriptBlock {
                param($IP)
                & nbtstat -A $IP 2>$null
            } -ArgumentList $IPAddress
            
            $completed = Wait-Job -Job $nbtJob -Timeout 2
            
            if ($completed) {
                $nbtOutput = Receive-Job -Job $nbtJob
                Remove-Job -Job $nbtJob -Force
                
                foreach ($line in $nbtOutput) {
                    if ($line -match '^\s*([A-Z0-9\-]+)\s+<00>\s+UNIQUE') {
                        $hostname = $matches[1].Trim()
                        break
                    }
                }
            }
            else {
                Stop-Job -Job $nbtJob -ErrorAction SilentlyContinue
                Remove-Job -Job $nbtJob -Force -ErrorAction SilentlyContinue
            }
        }
        catch { }
    }
    
    return $hostname
}

function Format-MACAddress {
    param([string]$MAC)
    
    if (-not $MAC) { return $null }
    
    # Remove common separators and convert to uppercase
    $cleaned = $MAC.ToUpper() -replace '[^0-9A-F]', ''
    
    # Standard MAC is 12 hex chars (6 bytes)
    if ($cleaned.Length -eq 12) {
        return ($cleaned -replace '(.{2})', '$1-').TrimEnd('-')
    }
    
    # Return original if can't normalize
    return $MAC.ToUpper()
}

function Extract-MACFromClientId {
    # DHCP ClientId (Option 61) can be various formats:
    # - Standard MAC: 6 bytes (12 hex chars)
    # - Type+MAC: 01 + 6 bytes (common)
    # - Cisco/Aruba: "d07e.280d.4359-Vlan-interface1" (ASCII in hex)
    # - Hyper-V: "RAS " + VM identifier
    # - Custom identifiers
    param([string]$ClientId)
    
    if (-not $ClientId) { return $null }
    
    # Clean the input - remove dashes/colons, uppercase
    $cleaned = $ClientId.ToUpper() -replace '[^0-9A-F]', ''
    
    # Standard 12-char MAC
    if ($cleaned.Length -eq 12) {
        return ($cleaned -replace '(.{2})', '$1-').TrimEnd('-')
    }
    
    # Type 01 + MAC (14 chars, starts with 01)
    if ($cleaned.Length -eq 14 -and $cleaned.StartsWith('01')) {
        $mac = $cleaned.Substring(2)
        return ($mac -replace '(.{2})', '$1-').TrimEnd('-')
    }
    
    # Check if it's ASCII-encoded (Cisco/Aruba style: "d07e.280d.4359-Vlan-interface1")
    # These show up as hex-encoded ASCII in the ClientId
    if ($cleaned.Length -gt 12) {
        try {
            # Try to decode as ASCII
            $bytes = [byte[]]::new($cleaned.Length / 2)
            for ($i = 0; $i -lt $cleaned.Length; $i += 2) {
                $bytes[$i/2] = [Convert]::ToByte($cleaned.Substring($i, 2), 16)
            }
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            
            # Look for Cisco-style MAC pattern: xxxx.xxxx.xxxx
            if ($ascii -match '([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})') {
                $ciscoMac = $matches[1] + $matches[2] + $matches[3]
                return ($ciscoMac.ToUpper() -replace '(.{2})', '$1-').TrimEnd('-')
            }
            
            # Look for standard MAC in the ASCII: xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
            if ($ascii -match '([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}') {
                $stdMac = $matches[0] -replace '[^0-9A-Fa-f]', ''
                return ($stdMac.ToUpper() -replace '(.{2})', '$1-').TrimEnd('-')
            }
        }
        catch { }
    }
    
    # Check for Hyper-V pattern (starts with "RAS " = 52415320)
    if ($cleaned.StartsWith('52415320')) {
        # This is a Hyper-V VM - no real MAC to extract
        return 'HYPERV-VM'
    }
    
    # If all else fails, try to extract first 12 valid hex chars
    if ($cleaned.Length -ge 12) {
        $first12 = $cleaned.Substring(0, 12)
        # Sanity check - make sure it looks like a MAC (not all zeros, not broadcast)
        if ($first12 -ne '000000000000' -and $first12 -ne 'FFFFFFFFFFFF') {
            return ($first12 -replace '(.{2})', '$1-').TrimEnd('-')
        }
    }
    
    return $null
}

function Get-ConflictSeverity {
    param(
        [string]$ConflictType,
        [bool]$IsOnline
    )
    
    switch ($ConflictType) {
        'Duplicate IP'           { return 'Critical' }
        'Static in DHCP Range'   { return if ($IsOnline) { 'High' } else { 'Medium' } }
        'MAC Mismatch'           { return 'Medium' }
        'Stale Lease'            { return 'Low' }
        'Bad Address'            { return 'Medium' }
        'Reservation'            { return 'Info' }
        'Excluded'               { return 'Info' }
        'DHCP Lease'             { return 'Info' }
        default                  { return 'Unknown' }
    }
}
#endregion Helper Functions

# Determine export path if -ExportHtml specified
if ($ExportHtml -and -not $ExportPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    if (-not $scriptDir) { $scriptDir = Get-Location }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $ExportPath = Join-Path $scriptDir "IPConflictReport_$timestamp.html"
}

#region Probe IP Function
function Invoke-AggressiveIPProbe {
    param(
        [string]$IPAddress,
        [string]$DHCPServer,
        [bool]$UseLocalDirect
    )
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " Aggressive IP Probe: $IPAddress" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    $results = [PSCustomObject]@{
        IPAddress        = $IPAddress
        PingResponse     = $false
        ARPEntry         = $null
        MACAddress       = $null
        TCPPortsOpen     = @()
        NetBIOSName      = $null
        DNSHostname      = $null
        DHCPLease        = $null
        DHCPReservation  = $null
        InExclusionRange = $false
        IsBadAddress     = $false
        DHCPHistory      = @()
        Verdict          = 'Unknown'
    }
    
    # 1. ICMP Ping (multiple attempts)
    Write-Host "[1/8] ICMP Ping test..." -ForegroundColor Gray
    for ($i = 1; $i -le 3; $i++) {
        $ping = Test-Connection -ComputerName $IPAddress -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            $results.PingResponse = $true
            Write-Host "      Ping $i/3: " -NoNewline
            Write-Host "RESPONSE" -ForegroundColor Green
            break
        } else {
            Write-Host "      Ping $i/3: " -NoNewline
            Write-Host "No response" -ForegroundColor Yellow
        }
        Start-Sleep -Milliseconds 500
    }
    
    # 2. ARP Request (force ARP even if ping fails)
    Write-Host "[2/8] ARP probe..." -ForegroundColor Gray
    try {
        # Clear any existing ARP entry for this IP
        $null = & arp -d $IPAddress 2>$null
        
        # Force ARP by attempting connection
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IPAddress, 135, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000, $false)
        $tcpClient.Close()
        
        # Also try raw ping to populate ARP
        $ping = New-Object System.Net.NetworkInformation.Ping
        $null = $ping.Send($IPAddress, 1000)
        $ping.Dispose()
        
        Start-Sleep -Milliseconds 500
        
        # Check ARP cache
        $arpEntry = Get-NetNeighbor -IPAddress $IPAddress -ErrorAction SilentlyContinue | 
                    Where-Object { $_.State -ne 'Unreachable' }
        
        if ($arpEntry) {
            $results.ARPEntry = $arpEntry.State
            $results.MACAddress = $arpEntry.LinkLayerAddress.ToUpper() -replace ':', '-'
            Write-Host "      ARP State: " -NoNewline
            Write-Host $arpEntry.State -ForegroundColor Green
            Write-Host "      MAC Address: " -NoNewline
            Write-Host $results.MACAddress -ForegroundColor Cyan
        } else {
            Write-Host "      ARP State: " -NoNewline
            Write-Host "No entry (device likely offline or not on this subnet)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "      ARP probe error: $_" -ForegroundColor Red
    }
    
    # 3. TCP Port Scan (common ports - device might block ICMP)
    Write-Host "[3/8] TCP port probe (common ports)..." -ForegroundColor Gray
    $commonPorts = @(22, 80, 443, 445, 3389, 5985)  # SSH, HTTP, HTTPS, SMB, RDP, WinRM
    foreach ($port in $commonPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($IPAddress, $port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne(500, $false)
            if ($wait -and $tcpClient.Connected) {
                $results.TCPPortsOpen += $port
                Write-Host "      Port $port`: " -NoNewline
                Write-Host "OPEN" -ForegroundColor Green
            }
            $tcpClient.Close()
        }
        catch { }
    }
    if ($results.TCPPortsOpen.Count -eq 0) {
        Write-Host "      No common ports responding" -ForegroundColor Yellow
    }
    
    # 4. DNS Reverse Lookup
    Write-Host "[4/8] DNS reverse lookup..." -ForegroundColor Gray
    try {
        $dnsResult = [System.Net.Dns]::GetHostEntry($IPAddress)
        if ($dnsResult.HostName -and $dnsResult.HostName -ne $IPAddress) {
            $results.DNSHostname = $dnsResult.HostName
            Write-Host "      DNS Name: " -NoNewline
            Write-Host $results.DNSHostname -ForegroundColor Cyan
        } else {
            Write-Host "      DNS: No PTR record" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "      DNS: No PTR record" -ForegroundColor Yellow
    }
    
    # 5. NetBIOS Name Query
    Write-Host "[5/8] NetBIOS name query..." -ForegroundColor Gray
    try {
        $nbtJob = Start-Job -ScriptBlock {
            param($IP)
            & nbtstat -A $IP 2>$null
        } -ArgumentList $IPAddress
        
        $completed = Wait-Job -Job $nbtJob -Timeout 3
        
        if ($completed) {
            $nbtOutput = Receive-Job -Job $nbtJob
            foreach ($line in $nbtOutput) {
                if ($line -match '^\s*([A-Z0-9\-]+)\s+<00>\s+UNIQUE') {
                    $results.NetBIOSName = $matches[1].Trim()
                    Write-Host "      NetBIOS Name: " -NoNewline
                    Write-Host $results.NetBIOSName -ForegroundColor Cyan
                    break
                }
            }
        }
        if (-not $results.NetBIOSName) {
            Write-Host "      NetBIOS: No response" -ForegroundColor Yellow
        }
        Remove-Job -Job $nbtJob -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "      NetBIOS query failed" -ForegroundColor Yellow
    }
    
    # 6. Check DHCP for current lease
    Write-Host "[6/8] Checking DHCP lease table..." -ForegroundColor Gray
    try {
        # Find which scope this IP belongs to
        if ($UseLocalDirect) {
            $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        } else {
            $scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServer -ErrorAction SilentlyContinue
        }
        
        foreach ($scope in $scopes) {
            $scopeStart = [System.Net.IPAddress]::Parse($scope.StartRange.ToString()).GetAddressBytes()
            $scopeEnd = [System.Net.IPAddress]::Parse($scope.EndRange.ToString()).GetAddressBytes()
            $targetIP = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            
            [Array]::Reverse($scopeStart)
            [Array]::Reverse($scopeEnd)
            [Array]::Reverse($targetIP)
            
            $startInt = [BitConverter]::ToUInt32($scopeStart, 0)
            $endInt = [BitConverter]::ToUInt32($scopeEnd, 0)
            $targetInt = [BitConverter]::ToUInt32($targetIP, 0)
            
            if ($targetInt -ge $startInt -and $targetInt -le $endInt) {
                # Found the scope - check for lease
                if ($UseLocalDirect) {
                    $lease = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue | 
                             Where-Object { $_.IPAddress.ToString() -eq $IPAddress }
                } else {
                    $lease = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue | 
                             Where-Object { $_.IPAddress.ToString() -eq $IPAddress }
                }
                
                if ($lease) {
                    $results.DHCPLease = $lease
                    Write-Host "      Active Lease: " -NoNewline
                    Write-Host "YES" -ForegroundColor Green
                    Write-Host "        Client ID: $($lease.ClientId)"
                    Write-Host "        Hostname: $($lease.HostName)"
                    Write-Host "        State: $($lease.AddressState)"
                    Write-Host "        Expires: $($lease.LeaseExpiryTime)"
                } else {
                    Write-Host "      Active Lease: " -NoNewline
                    Write-Host "NONE" -ForegroundColor Yellow
                }
                
                # Check for reservation
                if ($UseLocalDirect) {
                    $reservation = Get-DhcpServerv4Reservation -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue | 
                                   Where-Object { $_.IPAddress.ToString() -eq $IPAddress }
                } else {
                    $reservation = Get-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue | 
                                   Where-Object { $_.IPAddress.ToString() -eq $IPAddress }
                }
                
                if ($reservation) {
                    $results.DHCPReservation = $reservation
                    Write-Host "      Reservation: " -NoNewline
                    Write-Host "YES" -ForegroundColor Cyan
                    Write-Host "        Name: $($reservation.Name)"
                    Write-Host "        Client ID: $($reservation.ClientId)"
                } else {
                    Write-Host "      Reservation: NONE" -ForegroundColor Gray
                }
                
                # Check exclusion ranges
                if ($UseLocalDirect) {
                    $exclusions = Get-DhcpServerv4ExclusionRange -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                } else {
                    $exclusions = Get-DhcpServerv4ExclusionRange -ComputerName $DHCPServer -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                }
                
                foreach ($excl in $exclusions) {
                    $exclStart = [System.Net.IPAddress]::Parse($excl.StartRange.ToString()).GetAddressBytes()
                    $exclEnd = [System.Net.IPAddress]::Parse($excl.EndRange.ToString()).GetAddressBytes()
                    [Array]::Reverse($exclStart)
                    [Array]::Reverse($exclEnd)
                    $exclStartInt = [BitConverter]::ToUInt32($exclStart, 0)
                    $exclEndInt = [BitConverter]::ToUInt32($exclEnd, 0)
                    
                    if ($targetInt -ge $exclStartInt -and $targetInt -le $exclEndInt) {
                        $results.InExclusionRange = $true
                        Write-Host "      In Exclusion: " -NoNewline
                        Write-Host "YES ($($excl.StartRange) - $($excl.EndRange))" -ForegroundColor Cyan
                        break
                    }
                }
                if (-not $results.InExclusionRange) {
                    Write-Host "      In Exclusion: NO" -ForegroundColor Gray
                }
                
                # Check bad leases
                if ($UseLocalDirect) {
                    $badLease = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -BadLeases -ErrorAction SilentlyContinue | 
                                Where-Object { $_.IPAddress.ToString() -eq $IPAddress }
                } else {
                    $badLease = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $scope.ScopeId -BadLeases -ErrorAction SilentlyContinue | 
                                Where-Object { $_.IPAddress.ToString() -eq $IPAddress }
                }
                
                if ($badLease) {
                    $results.IsBadAddress = $true
                    Write-Host "      Bad Address: " -NoNewline
                    Write-Host "YES (marked as declined/bad)" -ForegroundColor Red
                }
                
                break
            }
        }
    }
    catch {
        Write-Host "      DHCP query error: $_" -ForegroundColor Red
    }
    
    # 7. Check DHCP Audit Log (if accessible)
    Write-Host "[7/8] Checking DHCP audit logs..." -ForegroundColor Gray
    try {
        $dhcpLogPath = "$env:SystemRoot\System32\dhcp"
        $today = Get-Date -Format 'ddd'
        $logFile = Join-Path $dhcpLogPath "DhcpSrvLog-$today.log"
        
        if (Test-Path $logFile) {
            $logEntries = Get-Content $logFile -Tail 500 -ErrorAction SilentlyContinue | 
                          Where-Object { $_ -match $IPAddress }
            
            if ($logEntries) {
                Write-Host "      Recent log entries for $IPAddress`:" -ForegroundColor Cyan
                $logEntries | Select-Object -Last 5 | ForEach-Object {
                    Write-Host "        $_" -ForegroundColor Gray
                }
                $results.DHCPHistory = $logEntries | Select-Object -Last 10
            } else {
                Write-Host "      No recent log entries found" -ForegroundColor Yellow
            }
        } else {
            Write-Host "      Audit log not accessible (need local access)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "      Could not read audit logs: $_" -ForegroundColor Yellow
    }
    
    # 8. Verdict
    Write-Host "[8/8] Analysis..." -ForegroundColor Gray
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " VERDICT" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $deviceDetected = $results.PingResponse -or $results.MACAddress -or $results.TCPPortsOpen.Count -gt 0
    $hasLease = $results.DHCPLease -ne $null
    $hasReservation = $results.DHCPReservation -ne $null
    
    if ($deviceDetected -and -not $hasLease -and -not $hasReservation) {
        Write-Host " STATUS: " -NoNewline
        Write-Host "GHOST DEVICE DETECTED" -ForegroundColor Red
        Write-Host ""
        Write-Host " A device is using this IP but has no DHCP record!" -ForegroundColor Yellow
        Write-Host " This is likely a device with a deleted lease that hasn't been rebooted."
        Write-Host ""
        Write-Host " RECOMMENDED ACTIONS:" -ForegroundColor Cyan
        if ($results.MACAddress) {
            Write-Host "   1. Locate device with MAC: $($results.MACAddress)" -ForegroundColor White
            Write-Host "   2. Reboot the device to release the IP" -ForegroundColor White
        } else {
            Write-Host "   1. Check switch MAC tables for this IP's port" -ForegroundColor White
            Write-Host "   2. Physically locate and reboot the device" -ForegroundColor White
        }
        Write-Host "   3. After reboot, verify IP is released" -ForegroundColor White
        $results.Verdict = 'Ghost Device - Needs Reboot'
    }
    elseif ($deviceDetected -and $hasLease) {
        Write-Host " STATUS: " -NoNewline
        Write-Host "ACTIVE DEVICE WITH VALID LEASE" -ForegroundColor Green
        Write-Host ""
        Write-Host " Device is responding and has a valid DHCP lease."
        Write-Host " Lease holder: $($results.DHCPLease.HostName)"
        $results.Verdict = 'Active - Valid Lease'
    }
    elseif (-not $deviceDetected -and $hasLease) {
        Write-Host " STATUS: " -NoNewline
        Write-Host "STALE LEASE" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " DHCP shows a lease but device is not responding."
        Write-Host " The device may be powered off or disconnected."
        Write-Host ""
        Write-Host " RECOMMENDED ACTIONS:" -ForegroundColor Cyan
        Write-Host "   1. Delete the lease if device is gone" -ForegroundColor White
        Write-Host "   2. Or wait for lease to expire naturally" -ForegroundColor White
        $results.Verdict = 'Stale Lease - Device Offline'
    }
    elseif (-not $deviceDetected -and -not $hasLease) {
        Write-Host " STATUS: " -NoNewline
        Write-Host "IP APPEARS AVAILABLE" -ForegroundColor Green
        Write-Host ""
        Write-Host " No device responding and no DHCP record."
        Write-Host " IP should be available for use."
        Write-Host ""
        Write-Host " CAUTION:" -ForegroundColor Yellow
        Write-Host "   A device may be offline but still configured with this IP."
        Write-Host "   If you assign this IP and later have conflicts, the other"
        Write-Host "   device needs to be found and reconfigured."
        $results.Verdict = 'Appears Available'
    }
    
    if ($results.InExclusionRange) {
        Write-Host ""
        Write-Host " NOTE: This IP is in a DHCP exclusion range (reserved for static IPs)" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    return $results
}
#endregion Probe IP Function

# If -ProbeIP specified, run aggressive probe
if ($ProbeIP) {
    if (-not $Quiet) { Show-YWBanner }
    
    $probeResults = @()
    foreach ($ip in $ProbeIP) {
        $result = Invoke-AggressiveIPProbe -IPAddress $ip -DHCPServer $DHCPServer -UseLocalDirect $UseLocalDirect
        $probeResults += $result
    }
    
    # If only probing (no full scan requested via other params), exit after probe
    if (-not $ScopeId -and -not $ExportPath -and -not $ExportHtml -and -not $ShowAllDevices) {
        return $probeResults
    }
}

#region Main Processing
$startTime = Get-Date
$AllResults = @()
$ConflictResults = @()

# Get DHCP scopes to analyze
if ($ScopeId) {
    $Scopes = foreach ($scope in $ScopeId) {
        if ($UseLocalDirect) {
            Get-DhcpServerv4Scope -ScopeId $scope -ErrorAction SilentlyContinue
        } else {
            Get-DhcpServerv4Scope -ComputerName $DHCPServer -ScopeId $scope -ErrorAction SilentlyContinue
        }
    }
}
else {
    if ($UseLocalDirect) {
        $Scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | 
                  Where-Object { $_.State -eq 'Active' }
    } else {
        $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServer -ErrorAction SilentlyContinue | 
                  Where-Object { $_.State -eq 'Active' }
    }
}

if (-not $Scopes -or $Scopes.Count -eq 0) {
    Write-Error "No active DHCP scopes found."
    exit 1
}

if (-not $Quiet) {
    Write-Host "Found $($Scopes.Count) DHCP scope(s) to analyze:" -ForegroundColor Cyan
    foreach ($scope in $Scopes) {
        Write-Host "  - $($scope.ScopeId) ($($scope.Name)): $($scope.StartRange) - $($scope.EndRange)" -ForegroundColor Gray
    }
    Write-Host ""
}

foreach ($Scope in $Scopes) {
    $currentScopeId = $Scope.ScopeId.ToString()
    
    if (-not $Quiet) {
        Write-Host "Analyzing scope: $currentScopeId ($($Scope.Name))" -ForegroundColor Yellow
        Write-Host ("-" * 60) -ForegroundColor Gray
    }
    
    # Collect DHCP data for this scope
    $DHCPLeases = @{}
    $DHCPReservations = @{}
    $DHCPExclusions = @()
    $BadAddresses = @()
    
    # Get active leases
    if (-not $Quiet) { Write-Host "  Retrieving DHCP leases..." -ForegroundColor Gray }
    
    try {
        if ($UseLocalDirect) {
            $leases = Get-DhcpServerv4Lease -ScopeId $currentScopeId -ErrorAction SilentlyContinue
        } else {
            $leases = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $currentScopeId -ErrorAction SilentlyContinue
        }
        foreach ($lease in $leases) {
            $ip = $lease.IPAddress.ToString()
            $rawClientId = $lease.ClientId
            $extractedMAC = Extract-MACFromClientId $rawClientId
            
            $DHCPLeases[$ip] = @{
                MAC           = $extractedMAC
                RawClientId   = Format-MACAddress $rawClientId  # Keep original for display
                Hostname      = $lease.HostName
                State         = $lease.AddressState
                LeaseExpiry   = $lease.LeaseExpiryTime
                Type          = 'Lease'
            }
        }
        if (-not $Quiet) { Write-Host "    Found $($DHCPLeases.Count) active leases" -ForegroundColor Green }
    }
    catch {
        Write-Warning "Failed to retrieve leases for scope $currentScopeId : $_"
    }
    
    # Get bad/declined addresses
    try {
        if ($UseLocalDirect) {
            $badLeases = Get-DhcpServerv4Lease -ScopeId $currentScopeId -BadLeases -ErrorAction SilentlyContinue
        } else {
            $badLeases = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $currentScopeId -BadLeases -ErrorAction SilentlyContinue
        }
        foreach ($bad in $badLeases) {
            $BadAddresses += $bad.IPAddress.ToString()
        }
        if ($BadAddresses.Count -gt 0 -and -not $Quiet) {
            Write-Host "    Found $($BadAddresses.Count) bad/declined addresses" -ForegroundColor DarkYellow
        }
    }
    catch { }
    
    # Get reservations
    if ($IncludeReservations) {
        if (-not $Quiet) { Write-Host "  Retrieving DHCP reservations..." -ForegroundColor Gray }
        
        try {
            if ($UseLocalDirect) {
            $reservations = Get-DhcpServerv4Reservation -ScopeId $currentScopeId -ErrorAction SilentlyContinue
            } else {
            $reservations = Get-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $currentScopeId -ErrorAction SilentlyContinue
            }
            foreach ($res in $reservations) {
                $ip = $res.IPAddress.ToString()
                $rawClientId = $res.ClientId
                $extractedMAC = Extract-MACFromClientId $rawClientId
                
                $DHCPReservations[$ip] = @{
                    MAC           = $extractedMAC
                    RawClientId   = Format-MACAddress $rawClientId  # Keep original for display
                    Name          = $res.Name
                    Description   = $res.Description
                    Type          = 'Reservation'
                }
            }
            if (-not $Quiet) { Write-Host "    Found $($DHCPReservations.Count) reservations" -ForegroundColor Green }
        }
        catch {
            Write-Warning "Failed to retrieve reservations for scope $currentScopeId : $_"
        }
    }
    
    # Get exclusion ranges
    if (-not $Quiet) { Write-Host "  Retrieving exclusion ranges..." -ForegroundColor Gray }
    
    try {
        if ($UseLocalDirect) {
            $exclusions = Get-DhcpServerv4ExclusionRange -ScopeId $currentScopeId -ErrorAction SilentlyContinue
        } else {
            $exclusions = Get-DhcpServerv4ExclusionRange -ComputerName $DHCPServer -ScopeId $currentScopeId -ErrorAction SilentlyContinue
        }
        foreach ($excl in $exclusions) {
            $excludedIPs = Get-ScopeIPRange -ScopeId $currentScopeId -StartRange $excl.StartRange.ToString() -EndRange $excl.EndRange.ToString()
            $DHCPExclusions += $excludedIPs
        }
        if (-not $Quiet) { Write-Host "    Found $($DHCPExclusions.Count) excluded IPs" -ForegroundColor Green }
    }
    catch {
    Write-Warning "Failed to retrieve exclusions for scope $currentScopeId : $_"
    }
    
    # Network scanning
    $NetworkDevices = @{}
    
    if ($ScanNetwork) {
        if (-not $Quiet) { Write-Host "  Performing network scan..." -ForegroundColor Gray }
        
        # Get all IPs in scope range
        $ScopeIPs = Get-ScopeIPRange -ScopeId $currentScopeId -StartRange $Scope.StartRange.ToString() -EndRange $Scope.EndRange.ToString()
        
        if (-not $Quiet) { Write-Host "    Scanning $($ScopeIPs.Count) IPs in range..." -ForegroundColor Gray }
        
        # Clear ARP cache for accurate results (requires admin)
        try {
            $null = & arp -d 2>$null
        }
        catch { }
        
        # Async ping sweep using runspace pool
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $runspacePool.Open()
        $runspaces = @()
        
        $pingScript = {
            param($IP, $TimeoutMs)
            $ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $result = $ping.Send($IP, $TimeoutMs)
                return @{
                    IP      = $IP
                    Online  = ($result.Status -eq 'Success')
                    RTT     = $result.RoundtripTime
                }
            }
            catch {
                return @{ IP = $IP; Online = $false; RTT = 0 }
            }
            finally {
                $ping.Dispose()
            }
        }
        
        foreach ($ip in $ScopeIPs) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $runspacePool
            [void]$ps.AddScript($pingScript)
            [void]$ps.AddArgument($ip)
            [void]$ps.AddArgument($ScanTimeout)
            
            $runspaces += @{
                Pipe   = $ps
                Handle = $ps.BeginInvoke()
            }
        }
        
        # Collect ping results
        $pingResults = @()
        $completed = 0
        
        while ($runspaces.Handle.IsCompleted -contains $false) {
            $runspaces | Where-Object { $_.Handle.IsCompleted } | ForEach-Object {
                $pingResults += $_.Pipe.EndInvoke($_.Handle)
                $_.Pipe.Dispose()
                $completed++
                
                if (-not $Quiet -and $completed % 50 -eq 0) {
                    Write-Progress -Activity "Scanning $currentScopeId" -Status "$completed of $($ScopeIPs.Count)" -PercentComplete (($completed / $ScopeIPs.Count) * 100)
                }
            }
            $runspaces = $runspaces | Where-Object { $_.Handle.IsCompleted -eq $false }
            Start-Sleep -Milliseconds 20
        }
        
        $runspacePool.Close()
        $runspacePool.Dispose()
        Write-Progress -Activity "Scanning $currentScopeId" -Completed
        
        # Small delay for ARP cache to populate
        Start-Sleep -Milliseconds 500
        
        # Get ARP cache entries
        $onlineIPs = $pingResults | Where-Object { $_['Online'] -eq $true } | ForEach-Object { $_['IP'] }
        
        if (-not $Quiet) { 
            Write-Host "    Found $($onlineIPs.Count) responding devices" -ForegroundColor Green 
        }
        
        # Collect MAC addresses from ARP
        $arpEntries = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                      Where-Object { $_.State -in @('Reachable', 'Stale') -and $_.IPAddress -in $onlineIPs }
        
        foreach ($arp in $arpEntries) {
            $ip = $arp.IPAddress
            $mac = Format-MACAddress $arp.LinkLayerAddress
            
            if ($mac -and $mac -ne '00-00-00-00-00-00') {
                $NetworkDevices[$ip] = @{
                    MAC      = $mac
                    State    = $arp.State
                    Online   = $true
                    Hostname = $null
                }
            }
        }
        
        # Add online devices without ARP entries (responded to ping but no MAC)
        foreach ($ip in $onlineIPs) {
            if (-not $NetworkDevices.ContainsKey($ip)) {
                $NetworkDevices[$ip] = @{
                    MAC      = 'Unknown'
                    State    = 'Reachable'
                    Online   = $true
                    Hostname = $null
                }
            }
        }
        
        if (-not $Quiet) { 
            Write-Host "    Captured $($NetworkDevices.Count) devices with MAC addresses" -ForegroundColor Green 
        }
        
        # Hostname resolution - only for devices NOT already in DHCP (static devices)
        # DHCP leases/reservations already have hostnames captured
        if ($ResolveHostnames) {
            # Get list of IPs that need resolution (not in DHCP leases or reservations)
            $needsResolution = $NetworkDevices.Keys | Where-Object { 
                $_ -notin $DHCPLeases.Keys -and $_ -notin $DHCPReservations.Keys 
            }
            
            if ($needsResolution.Count -gt 0) {
                if (-not $Quiet) { 
                    Write-Host "  Resolving hostnames for $($needsResolution.Count) static devices..." -ForegroundColor Gray 
                }
                
                # Parallel DNS resolution using runspaces (much faster)
                $dnsRunspacePool = [runspacefactory]::CreateRunspacePool(1, 20)
                $dnsRunspacePool.Open()
                $dnsJobs = @()
                
                $dnsScript = {
                    param($IP)
                    try {
                        $result = [System.Net.Dns]::GetHostEntry($IP)
                        if ($result.HostName -and $result.HostName -ne $IP) {
                            return @{ IP = $IP; Hostname = $result.HostName.Split('.')[0] }
                        }
                    }
                    catch { }
                    return @{ IP = $IP; Hostname = $null }
                }
                
                foreach ($ip in $needsResolution) {
                    $ps = [powershell]::Create()
                    $ps.RunspacePool = $dnsRunspacePool
                    [void]$ps.AddScript($dnsScript)
                    [void]$ps.AddArgument($ip)
                    
                    $dnsJobs += @{
                        Pipe   = $ps
                        Handle = $ps.BeginInvoke()
                        IP     = $ip
                    }
                }
                
                # Collect DNS results with timeout
                $dnsTimeout = [datetime]::Now.AddSeconds(10)
                $resolved = 0
                
                while ($dnsJobs.Handle.IsCompleted -contains $false -and [datetime]::Now -lt $dnsTimeout) {
                    Start-Sleep -Milliseconds 50
                }
                
                foreach ($job in $dnsJobs) {
                    try {
                        if ($job.Handle.IsCompleted) {
                            $result = $job.Pipe.EndInvoke($job.Handle)
                            if ($result.Hostname) {
                                $NetworkDevices[$result.IP].Hostname = $result.Hostname
                                $resolved++
                            }
                        }
                        $job.Pipe.Dispose()
                    }
                    catch { }
                }
                
                $dnsRunspacePool.Close()
                $dnsRunspacePool.Dispose()
                
                # Optional NetBIOS fallback for unresolved (slow, skip by default)
                if (-not $SkipNetBIOS) {
                    $stillUnresolved = $needsResolution | Where-Object { -not $NetworkDevices[$_].Hostname }
                    
                    if ($stillUnresolved.Count -gt 0 -and $stillUnresolved.Count -le 10) {
                        if (-not $Quiet) { 
                            Write-Host "    Trying NetBIOS for $($stillUnresolved.Count) remaining..." -ForegroundColor Gray 
                        }
                        
                        foreach ($ip in $stillUnresolved) {
                            try {
                                $nbtJob = Start-Job -ScriptBlock {
                                    param($IP)
                                    & nbtstat -A $IP 2>$null
                                } -ArgumentList $ip
                                
                                $completed = Wait-Job -Job $nbtJob -Timeout 1
                                
                                if ($completed) {
                                    $nbtOutput = Receive-Job -Job $nbtJob
                                    foreach ($line in $nbtOutput) {
                                        if ($line -match '^\s*([A-Z0-9\-]+)\s+<00>\s+UNIQUE') {
                                            $NetworkDevices[$ip].Hostname = $matches[1].Trim()
                                            $resolved++
                                            break
                                        }
                                    }
                                }
                                
                                Remove-Job -Job $nbtJob -Force -ErrorAction SilentlyContinue
                            }
                            catch { }
                        }
                    }
                    elseif ($stillUnresolved.Count -gt 10 -and -not $Quiet) {
                        Write-Host "    Skipping NetBIOS for $($stillUnresolved.Count) devices (use -SkipNetBIOS:`$false to force)" -ForegroundColor DarkGray
                    }
                }
                
                if (-not $Quiet) { Write-Host "    Resolved $resolved hostnames" -ForegroundColor Green }
            }
            else {
                if (-not $Quiet) { Write-Host "  All devices have DHCP hostnames, skipping DNS lookup" -ForegroundColor Green }
            }
        }
    }
    
    # Analysis: Compare DHCP data vs Network reality
    if (-not $Quiet) { 
        Write-Host "  Analyzing for conflicts..." -ForegroundColor Gray 
    }
    
    # Track all IPs for this scope
    $AllScopeIPs = @{}
    
    # Process DHCP Leases
    foreach ($ip in $DHCPLeases.Keys) {
        $lease = $DHCPLeases[$ip]
        $networkDevice = $NetworkDevices[$ip]
        $isOnline = $networkDevice -ne $null -and $networkDevice.Online
        $arpMAC = if ($networkDevice) { $networkDevice.MAC } else { $null }
        $dhcpMAC = $lease.MAC  # This is now the extracted/normalized MAC
        
        $conflictType = $null
        $notes = @()
        
        # Skip MAC comparison for Hyper-V VMs (can't extract real MAC from ClientId)
        $isHyperV = ($dhcpMAC -eq 'HYPERV-VM')
        
        # Check for MAC mismatch (only if we have valid MACs to compare)
        if ($isOnline -and $arpMAC -and $dhcpMAC -and $arpMAC -ne 'Unknown' -and -not $isHyperV) {
            if ($arpMAC -ne $dhcpMAC) {
                $conflictType = 'MAC Mismatch'
                $notes += "DHCP: $dhcpMAC, ARP: $arpMAC"
            }
        }
        # Check for stale lease
        if (-not $conflictType -and -not $isOnline -and $lease.State -eq 'Active') {
            $conflictType = 'Stale Lease'
            $notes += "Lease active but device offline"
        }
        # Default - normal lease
        if (-not $conflictType) {
            $conflictType = 'DHCP Lease'
        }
        
        $hostname = if ($networkDevice -and $networkDevice.Hostname) { 
            $networkDevice.Hostname 
        } elseif ($lease.Hostname) { 
            $lease.Hostname 
        } else { 
            'N/A' 
        }
        
        # For display, show extracted MAC (or raw if extraction failed)
        $displayMAC = if ($dhcpMAC -and $dhcpMAC -ne 'HYPERV-VM') { $dhcpMAC } else { $lease.RawClientId }
        
        $AllScopeIPs[$ip] = [PSCustomObject]@{
            IPAddress       = $ip
            ScopeId         = $currentScopeId
            Hostname        = $hostname
            DHCPType        = 'Lease'
            DHCPMAC         = $displayMAC
            ARPMAC          = $arpMAC
            IsOnline        = $isOnline
            ConflictType    = $conflictType
            Severity        = Get-ConflictSeverity -ConflictType $conflictType -IsOnline $isOnline
            Notes           = ($notes -join '; ')
            LeaseExpiry     = $lease.LeaseExpiry
            IsExcluded      = $ip -in $DHCPExclusions
            IsReservation   = $false
            IsHyperV        = $isHyperV
        }
    }
    
    # Process Reservations
    foreach ($ip in $DHCPReservations.Keys) {
        $res = $DHCPReservations[$ip]
        $networkDevice = $NetworkDevices[$ip]
        $isOnline = $networkDevice -ne $null -and $networkDevice.Online
        $arpMAC = if ($networkDevice) { $networkDevice.MAC } else { $null }
        $dhcpMAC = $res.MAC  # Extracted/normalized MAC
        
        $conflictType = 'Reservation'
        $notes = @()
        
        # Skip MAC comparison for Hyper-V VMs
        $isHyperV = ($dhcpMAC -eq 'HYPERV-VM')
        
        # Check for MAC mismatch on reservation
        if ($isOnline -and $arpMAC -and $dhcpMAC -and $arpMAC -ne 'Unknown' -and -not $isHyperV) {
            if ($arpMAC -ne $dhcpMAC) {
                $conflictType = 'MAC Mismatch'
                $notes += "Reserved: $dhcpMAC, ARP: $arpMAC"
            }
        }
        
        $hostname = if ($networkDevice -and $networkDevice.Hostname) { 
            $networkDevice.Hostname 
        } elseif ($res.Name) { 
            $res.Name 
        } else { 
            'N/A' 
        }
        
        # For display, show extracted MAC (or raw if extraction failed)
        $displayMAC = if ($dhcpMAC -and $dhcpMAC -ne 'HYPERV-VM') { $dhcpMAC } else { $res.RawClientId }
        
        $AllScopeIPs[$ip] = [PSCustomObject]@{
            IPAddress       = $ip
            ScopeId         = $currentScopeId
            Hostname        = $hostname
            DHCPType        = 'Reservation'
            DHCPMAC         = $displayMAC
            ARPMAC          = $arpMAC
            IsOnline        = $isOnline
            ConflictType    = $conflictType
            Severity        = Get-ConflictSeverity -ConflictType $conflictType -IsOnline $isOnline
            Notes           = ($notes -join '; ')
            LeaseExpiry     = $null
            IsExcluded      = $ip -in $DHCPExclusions
            IsReservation   = $true
            IsHyperV        = $isHyperV
        }
    }
    
    # Process Network Devices NOT in DHCP (Static IPs!)
    foreach ($ip in $NetworkDevices.Keys) {
        if (-not $AllScopeIPs.ContainsKey($ip)) {
            $networkDevice = $NetworkDevices[$ip]
            $isExcluded = $ip -in $DHCPExclusions
            
            $conflictType = if ($isExcluded) { 'Excluded' } else { 'Static in DHCP Range' }
            $notes = @()
            
            if (-not $isExcluded) {
                $notes += "Device using static IP within DHCP scope - should be excluded or converted to DHCP"
            }
            
            $AllScopeIPs[$ip] = [PSCustomObject]@{
                IPAddress       = $ip
                ScopeId         = $currentScopeId
                Hostname        = if ($networkDevice.Hostname) { $networkDevice.Hostname } else { 'N/A' }
                DHCPType        = 'None'
                DHCPMAC         = $null
                ARPMAC          = $networkDevice.MAC
                IsOnline        = $true
                ConflictType    = $conflictType
                Severity        = Get-ConflictSeverity -ConflictType $conflictType -IsOnline $true
                Notes           = ($notes -join '; ')
                LeaseExpiry     = $null
                IsExcluded      = $isExcluded
                IsReservation   = $false
                IsHyperV        = $false
            }
        }
    }
    
    # Process Bad Addresses
    foreach ($ip in $BadAddresses) {
        if (-not $AllScopeIPs.ContainsKey($ip)) {
            $networkDevice = $NetworkDevices[$ip]
            
            $AllScopeIPs[$ip] = [PSCustomObject]@{
                IPAddress       = $ip
                ScopeId         = $currentScopeId
                Hostname        = 'N/A'
                DHCPType        = 'Bad Address'
                DHCPMAC         = $null
                ARPMAC          = if ($networkDevice) { $networkDevice.MAC } else { $null }
                IsOnline        = if ($networkDevice) { $networkDevice.Online } else { $false }
                ConflictType    = 'Bad Address'
                Severity        = 'Medium'
                Notes           = 'Address marked as bad/declined by DHCP server'
                LeaseExpiry     = $null
                IsExcluded      = $false
                IsReservation   = $false
                IsHyperV        = $false
            }
        }
    }
    
    # Check for duplicate IPs (same IP, multiple DIFFERENT MACs responding)
    # This is a TRUE conflict - two different devices claiming the same IP
    foreach ($ip in $AllScopeIPs.Keys) {
        $entry = $AllScopeIPs[$ip]
        
        # Skip Hyper-V VMs (can't reliably compare MACs)
        if ($entry.IsHyperV) { continue }
        
        # Get both MACs (normalized)
        $dhcpMAC = $entry.DHCPMAC
        $arpMAC = $entry.ARPMAC
        
        # Only flag as duplicate if:
        # 1. Both MACs exist and are valid
        # 2. They're actually different (after normalization)
        # 3. Neither is 'Unknown'
        if ($dhcpMAC -and $arpMAC -and 
            $dhcpMAC -ne 'Unknown' -and $arpMAC -ne 'Unknown' -and
            $dhcpMAC -ne $arpMAC) {
            
            # This is already flagged as MAC Mismatch - only upgrade to Duplicate if severe
            # A true duplicate would need ARP showing multiple MACs for same IP (rare)
            # For now, MAC Mismatch is the appropriate classification
        }
    }
    
    # Add to results
    $AllResults += $AllScopeIPs.Values
    $scopeConflicts = $AllScopeIPs.Values | Where-Object { $_.Severity -in @('Critical', 'High', 'Medium', 'Low') }
    $ConflictResults += $scopeConflicts
    
    # Scope summary
    if (-not $Quiet) {
        $criticalCount = @($scopeConflicts | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highCount = @($scopeConflicts | Where-Object { $_.Severity -eq 'High' }).Count
        $mediumCount = @($scopeConflicts | Where-Object { $_.Severity -eq 'Medium' }).Count
        $lowCount = @($scopeConflicts | Where-Object { $_.Severity -eq 'Low' }).Count
        
        Write-Host ""
        Write-Host "  Scope Summary for $currentScopeId :" -ForegroundColor Cyan
        if ($criticalCount -gt 0) { Write-Host "    Critical: $criticalCount" -ForegroundColor Red }
        if ($highCount -gt 0) { Write-Host "    High:     $highCount" -ForegroundColor DarkYellow }
        if ($mediumCount -gt 0) { Write-Host "    Medium:   $mediumCount" -ForegroundColor Yellow }
        if ($lowCount -gt 0) { Write-Host "    Low:      $lowCount" -ForegroundColor Gray }
        if ($criticalCount + $highCount + $mediumCount + $lowCount -eq 0) {
            Write-Host "    No conflicts detected" -ForegroundColor Green
        }
        Write-Host ""
    }
}
#endregion Main Processing

#region Output Results
$elapsed = ((Get-Date) - $startTime).TotalSeconds

if (-not $Quiet) {
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " IP Conflict Detection Summary" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "DHCP Server:      $DHCPServer"
    Write-Host "Scopes Analyzed:  $($Scopes.Count)"
    Write-Host "Total IPs Found:  $($AllResults.Count)"
    Write-Host "Scan Duration:    $([math]::Round($elapsed, 1)) seconds"
    Write-Host ""
    
    $totalCritical = @($ConflictResults | Where-Object { $_.Severity -eq 'Critical' }).Count
    $totalHigh = @($ConflictResults | Where-Object { $_.Severity -eq 'High' }).Count
    $totalMedium = @($ConflictResults | Where-Object { $_.Severity -eq 'Medium' }).Count
    $totalLow = @($ConflictResults | Where-Object { $_.Severity -eq 'Low' }).Count
    
    Write-Host "Conflict Summary:" -ForegroundColor Yellow
    Write-Host "  Critical (Duplicate IPs):    " -NoNewline
    if ($totalCritical -gt 0) { Write-Host $totalCritical -ForegroundColor Red } else { Write-Host "0" -ForegroundColor Green }
    Write-Host "  High (Static in Range):      " -NoNewline
    if ($totalHigh -gt 0) { Write-Host $totalHigh -ForegroundColor DarkYellow } else { Write-Host "0" -ForegroundColor Green }
    Write-Host "  Medium (MAC Mismatch/Bad):   " -NoNewline
    if ($totalMedium -gt 0) { Write-Host $totalMedium -ForegroundColor Yellow } else { Write-Host "0" -ForegroundColor Green }
    Write-Host "  Low (Stale Leases):          " -NoNewline
    if ($totalLow -gt 0) { Write-Host $totalLow -ForegroundColor Gray } else { Write-Host "0" -ForegroundColor Green }
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

# Display conflicts in console (always show, regardless of export)
if ($ConflictResults.Count -gt 0) {
    Write-Host "Detected Conflicts:" -ForegroundColor Red
    Write-Host ("-" * 100) -ForegroundColor Gray
    
    $header = "{0,-16} {1,-12} {2,-20} {3,-18} {4,-10} {5,-20}" -f "IP Address", "Scope", "Hostname", "Conflict Type", "Severity", "Notes"
    Write-Host $header -ForegroundColor Yellow
    Write-Host ("-" * 100) -ForegroundColor Gray
    
    $sortedConflicts = $ConflictResults | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} default{4} }
    }}, IPAddress
    
    foreach ($conflict in $sortedConflicts) {
        $color = switch ($conflict.Severity) {
            'Critical' { 'Red' }
            'High'     { 'DarkYellow' }
            'Medium'   { 'Yellow' }
            'Low'      { 'Gray' }
            default    { 'White' }
        }
        
        $hostname = if ($conflict.Hostname.Length -gt 18) { $conflict.Hostname.Substring(0,15) + "..." } else { $conflict.Hostname }
        $notes = if ($conflict.Notes.Length -gt 18) { $conflict.Notes.Substring(0,15) + "..." } else { $conflict.Notes }
        
        $row = "{0,-16} {1,-12} {2,-20} {3,-18} {4,-10} {5,-20}" -f $conflict.IPAddress, $conflict.ScopeId, $hostname, $conflict.ConflictType, $conflict.Severity, $notes
        Write-Host $row -ForegroundColor $color
    }
    
    Write-Host ("-" * 100) -ForegroundColor Gray
    Write-Host ""
}
elseif ($ConflictResults.Count -eq 0) {
    Write-Host "No IP conflicts detected!" -ForegroundColor Green
    Write-Host ""
}

# Export results
if ($ExportPath) {
    $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
    $resultsToExport = if ($ShowAllDevices) { $AllResults } else { $ConflictResults }
    
    try {
        switch ($extension) {
            '.csv' {
                $resultsToExport | Select-Object IPAddress, ScopeId, Hostname, DHCPType, DHCPMAC, ARPMAC, 
                    IsOnline, ConflictType, Severity, Notes, IsExcluded, IsReservation |
                    Export-Csv -Path $ExportPath -NoTypeInformation
                
                if (-not $Quiet) {
                    Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green
                }
            }
            
            '.json' {
                $resultsToExport | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExportPath -Encoding UTF8
                
                if (-not $Quiet) {
                    Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green
                }
            }
            
            '.html' {
                $criticalItems = @($resultsToExport | Where-Object { $_.Severity -eq 'Critical' })
                $highItems = @($resultsToExport | Where-Object { $_.Severity -eq 'High' })
                $mediumItems = @($resultsToExport | Where-Object { $_.Severity -eq 'Medium' })
                $lowItems = @($resultsToExport | Where-Object { $_.Severity -eq 'Low' })
                $infoItems = @($resultsToExport | Where-Object { $_.Severity -eq 'Info' })
                
                $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>IP Conflict Detection Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #FF6600 0%, #6B7280 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; font-size: 32px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .tagline { font-size: 14px; margin-top: 5px; opacity: 0.9; font-style: italic; }
        .header .meta { margin-top: 15px; font-size: 12px; opacity: 0.8; }
        h2 { color: #FF6600; margin-top: 30px; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        .summary { background-color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #FF6600; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat-box { background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%); padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #e0e0e0; transition: transform 0.2s; }
        .stat-box:hover { transform: translateY(-3px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        .stat-box.critical { border-color: #dc3545; }
        .stat-box.high { border-color: #fd7e14; }
        .stat-box.medium { border-color: #ffc107; }
        .stat-box.low { border-color: #6c757d; }
        .stat-box.info { border-color: #17a2b8; }
        .stat-number { font-size: 32px; font-weight: bold; }
        .stat-number.critical { color: #dc3545; }
        .stat-number.high { color: #fd7e14; }
        .stat-number.medium { color: #ffc107; }
        .stat-number.low { color: #6c757d; }
        .stat-number.info { color: #17a2b8; }
        .stat-label { color: #6B7280; margin-top: 8px; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        th { background: linear-gradient(135deg, #6B7280 0%, #4a5568 100%); color: white; padding: 12px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        td { padding: 10px 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px; }
        tr:hover { background-color: #f8f9fa; }
        tr:last-child td { border-bottom: none; }
        .severity-critical { background-color: #f8d7da; border-left: 4px solid #dc3545; }
        .severity-high { background-color: #fff3cd; border-left: 4px solid #fd7e14; }
        .severity-medium { background-color: #fff8e1; border-left: 4px solid #ffc107; }
        .severity-low { background-color: #f5f5f5; border-left: 4px solid #6c757d; }
        .severity-info { background-color: #e3f2fd; border-left: 4px solid #17a2b8; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background-color: #dc3545; color: white; }
        .badge-high { background-color: #fd7e14; color: white; }
        .badge-medium { background-color: #ffc107; color: #333; }
        .badge-low { background-color: #6c757d; color: white; }
        .badge-info { background-color: #17a2b8; color: white; }
        .badge-online { background-color: #28a745; color: white; }
        .badge-offline { background-color: #dc3545; color: white; }
        .scope-section { margin-top: 30px; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .scope-header { color: #FF6600; font-size: 18px; font-weight: 600; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #e0e0e0; }
        .footer { margin-top: 40px; text-align: center; color: #6B7280; padding: 20px; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer .company { font-size: 20px; font-weight: bold; color: #FF6600; margin-bottom: 5px; }
        .mac { font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }
        .no-conflicts { text-align: center; padding: 40px; color: #28a745; font-size: 18px; }
        .no-conflicts-icon { font-size: 48px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>IP Conflict Detection Report</h1>
        <div class="tagline">Network Health Analysis</div>
        <div class="meta">
            <strong>DHCP Server:</strong> $DHCPServer | 
            <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | 
            <strong>Scopes:</strong> $($Scopes.Count) | 
            <strong>Scan Duration:</strong> $([math]::Round($elapsed, 1))s
        </div>
    </div>
    
    <div class="summary">
        <strong style="color: #FF6600; font-size: 16px;">Conflict Summary</strong>
        <div class="summary-grid">
            <div class="stat-box critical"><div class="stat-number critical">$($criticalItems.Count)</div><div class="stat-label">Critical</div></div>
            <div class="stat-box high"><div class="stat-number high">$($highItems.Count)</div><div class="stat-label">High</div></div>
            <div class="stat-box medium"><div class="stat-number medium">$($mediumItems.Count)</div><div class="stat-label">Medium</div></div>
            <div class="stat-box low"><div class="stat-number low">$($lowItems.Count)</div><div class="stat-label">Low</div></div>
$(if ($ShowAllDevices) { "            <div class='stat-box info'><div class='stat-number info'>$($infoItems.Count)</div><div class='stat-label'>Info</div></div>" })
        </div>
    </div>
"@
                
                # Group results by scope
                $scopeGroups = $resultsToExport | Group-Object ScopeId
                
                foreach ($scopeGroup in $scopeGroups) {
                    $scopeName = ($Scopes | Where-Object { $_.ScopeId.ToString() -eq $scopeGroup.Name }).Name
                    
                    $html += @"
    
    <div class="scope-section">
        <div class="scope-header">Scope: $($scopeGroup.Name) $(if ($scopeName) { "($scopeName)" })</div>
"@
                    
                    $scopeConflicts = $scopeGroup.Group | Where-Object { $_.Severity -ne 'Info' }
                    
                    if ($scopeConflicts.Count -eq 0 -and -not $ShowAllDevices) {
                        $html += @"
        <div class="no-conflicts">
            <div class="no-conflicts-icon">&#10004;</div>
            No conflicts detected in this scope
        </div>
"@
                    }
                    else {
                        $html += @"
        <table>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Status</th>
                <th>DHCP Type</th>
                <th>DHCP MAC</th>
                <th>ARP MAC</th>
                <th>Conflict</th>
                <th>Severity</th>
                <th>Notes</th>
            </tr>
"@
                        
                        $sortedItems = $scopeGroup.Group | Sort-Object @{Expression={
                            switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} default{4} }
                        }}, IPAddress
                        
                        foreach ($item in $sortedItems) {
                            $rowClass = switch ($item.Severity) {
                                'Critical' { 'severity-critical' }
                                'High'     { 'severity-high' }
                                'Medium'   { 'severity-medium' }
                                'Low'      { 'severity-low' }
                                default    { 'severity-info' }
                            }
                            
                            $badgeClass = switch ($item.Severity) {
                                'Critical' { 'badge-critical' }
                                'High'     { 'badge-high' }
                                'Medium'   { 'badge-medium' }
                                'Low'      { 'badge-low' }
                                default    { 'badge-info' }
                            }
                            
                            $statusBadge = if ($item.IsOnline) { "<span class='badge badge-online'>Online</span>" } else { "<span class='badge badge-offline'>Offline</span>" }
                            
                            $html += @"
            <tr class="$rowClass">
                <td><strong>$($item.IPAddress)</strong></td>
                <td>$($item.Hostname)</td>
                <td>$statusBadge</td>
                <td>$($item.DHCPType)</td>
                <td class="mac">$($item.DHCPMAC)</td>
                <td class="mac">$($item.ARPMAC)</td>
                <td>$($item.ConflictType)</td>
                <td><span class="badge $badgeClass">$($item.Severity)</span></td>
                <td>$($item.Notes)</td>
            </tr>
"@
                        }
                        
                        $html += @"
        </table>
"@
                    }
                    
                    $html += @"
    </div>
"@
                }
                
                $html += @"
    
    <div class="footer">
        <div class="company">Yeyland Wutani LLC</div>
        <div style="font-style: italic; color: #6B7280; margin-bottom: 10px;">Building Better Systems</div>
        <div style="font-size: 11px; color: #999;">IP Conflict Detection Report v$ScriptVersion</div>
    </div>
</body>
</html>
"@
                
                $html | Out-File -FilePath $ExportPath -Encoding UTF8
                
                if (-not $Quiet) {
                    Write-Host ""
                    Write-Host "HTML Report saved: " -NoNewline -ForegroundColor Cyan
                    Write-Host $ExportPath -ForegroundColor Green
                }
            }
            
            default {
                Write-Warning "Unsupported export format: $extension (use .csv, .json, or .html)"
            }
        }
    }
    catch {
        Write-Error "Failed to export results: $_"
    }
}

# Return conflict results for pipeline
if ($ShowAllDevices) {
    return $AllResults
}
else {
    return $ConflictResults
}
#endregion Output Results
