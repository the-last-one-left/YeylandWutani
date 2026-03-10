<#
.SYNOPSIS
    Network discovery and inventory tool for MSP client networks.

.DESCRIPTION
    Comprehensive network discovery tool that scans IP ranges to identify active devices,
    gather system information, identify device types, and generate detailed inventory reports.
    Designed for MSP client onboarding and network documentation.

    Compatible with PowerShell 5.1+ for maximum Windows Server compatibility.
    Uses runspace pools for fast parallel scanning.

    Features:
    - Automatic local subnet detection (scans all connected networks if no input provided)
    - Multi-subnet discovery (probes candidate gateways for additional networks)
    - Subnet/IP range scanning with parallel processing (~35 common ports)
    - Device type identification (server, workstation, printer, network device, mobile, IoT, container)
    - Domain Controller detection (Kerberos + LDAP port fingerprinting)
    - Operating system detection
    - MAC address via Get-NetNeighbor (reliable) + ARP fallback
    - MAC vendor lookup (local DB + optional macvendors.com API)
    - 150+ vendor OUI database with smart device classification
    - Docker container detection / locally administered MAC identification
    - HTTP title and Server header grabbing
    - SSL/TLS certificate health audit (expiry, issuer, CN)
    - SNMP community probing (sysDescr, sysName, sysLocation)
    - Gateway fingerprinting (FortiGate, SonicWall, pfSense, Ubiquiti, etc.)
    - WMI/CIM remote queries for Windows hosts (OS, RAM, disk, uptime, services)
    - Active Directory enumeration (domain, DCs, users, computers, admins, password policy)
    - Security observation engine (flags risky ports/configs by severity)
    - Public IP / ISP information via ipinfo.io
    - Multi-method hostname resolution (DNS, NetBIOS, DNS Cache)
    - Multiple export formats (CSV, JSON, HTML)
    - Rich HTML report with security, AD, SSL, and WMI sections

.PARAMETER Subnet
    Network subnet(s) to scan in CIDR notation (e.g., "192.168.1.0/24").
    Accepts multiple subnets via comma separation or pipeline.
    If not specified, automatically detects and scans all local subnets.

.PARAMETER IPRange
    IP range to scan using start-end format (e.g., "192.168.1.1-192.168.1.254").

.PARAMETER IPList
    Path to text file containing list of IP addresses (one per line).

.PARAMETER ScanPorts
    Scan common ports to identify services. Default: True

.PARAMETER ScanProfile
    Scan profile: "Quick" (ping only), "Standard" (default), or "Full" (enables all enrichment).
    "Full" auto-enables -EnableWMI, -EnableAD, -EnableSSL, -EnableSNMP,
    -EnableSecurityObs, -EnablePublicIP, -EnableGatewayProbe.

.PARAMETER QuickScan
    Shortcut for -ScanProfile Quick. Ping-only, no port scanning.

.PARAMETER EnableWMI
    Enable WMI/CIM remote queries on discovered Windows hosts.
    Uses current logged-in credentials unless -WMICredential is specified.

.PARAMETER EnableAD
    Enable Active Directory enumeration. Requires RSAT AD module.
    Falls back to anonymous LDAP probe if AD module unavailable.

.PARAMETER EnableSSL
    Enable SSL/TLS certificate health audit on HTTPS/LDAPS/SMTPS ports.
    Flags certificates expiring within 30 days (MEDIUM) or 7 days (HIGH).

.PARAMETER EnableSNMP
    Enable SNMP community probing. Tests community strings and reads
    sysDescr, sysName, sysLocation from responding devices.

.PARAMETER EnableSecurityObs
    Enable security observation engine. Flags risky port exposures and
    configurations by severity (CRITICAL / HIGH / MEDIUM / LOW).

.PARAMETER EnablePublicIP
    Fetch public IP address, ISP/ASN, and location info via ipinfo.io.

.PARAMETER EnableGatewayProbe
    HTTP/SNMP fingerprint the default gateway to identify firewall/router vendor.

.PARAMETER UseMacVendorAPI
    Enable online MAC vendor lookup via macvendors.com API.

.PARAMETER WMICredential
    PSCredential for WMI remote queries. Defaults to current user context.

.PARAMETER SNMPCommunities
    SNMP community strings to test. Default: @("public","private","community","admin").

.PARAMETER ThrottleLimit
    Maximum parallel scanning threads. Default: 100

.PARAMETER Timeout
    Connection timeout in milliseconds per device. Default: 1000

.PARAMETER ExportPath
    Path to export discovery report. Supports CSV, JSON, or HTML formats.

.PARAMETER IncludeOffline
    Include unreachable IP addresses in report as "Offline" entries.

.PARAMETER Quiet
    Suppress progress output. Shows only final summary.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1
    Auto-detect local subnet(s) and scan all connected networks.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -ScanProfile Full -ExportPath "C:\Reports\Network.html"
    Full scan with all enrichment, export rich HTML report.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -EnableSSL -EnableSecurityObs -ExportPath "C:\Reports\Audit.html"
    Standard scan + SSL cert health + security observations.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -EnableAD -EnableWMI -ExportPath "C:\Reports\Inventory.html"
    Standard scan + Active Directory enumeration + WMI deep-dive.

.EXAMPLE
    .\Get-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -QuickScan
    Fast ping-only scan of a specific subnet.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+
    Version: 3.0
#>

[CmdletBinding(DefaultParameterSetName='Subnet')]
param(
    [Parameter(ParameterSetName='Subnet', ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]]$Subnet,

    [Parameter(ParameterSetName='IPRange')]
    [string]$IPRange,

    [Parameter(ParameterSetName='IPList')]
    [ValidateScript({ Test-Path $_ })]
    [string]$IPList,

    [bool]$ScanPorts = $true,

    [ValidateSet('Quick','Standard','Full')]
    [string]$ScanProfile = 'Standard',

    [switch]$QuickScan,
    [switch]$EnableWMI,
    [switch]$EnableAD,
    [switch]$EnableSSL,
    [switch]$EnableSNMP,
    [switch]$EnableSecurityObs,
    [switch]$EnablePublicIP,
    [switch]$EnableGatewayProbe,
    [switch]$UseMacVendorAPI,

    [PSCredential]$WMICredential,

    [string[]]$SNMPCommunities = @('public','private','community','admin'),

    [ValidateRange(1, 500)]
    [int]$ThrottleLimit = 100,

    [ValidateRange(100, 5000)]
    [int]$Timeout = 1000,

    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Export directory does not exist: $parent"
        }
        $true
    })]
    [string]$ExportPath,

    [switch]$IncludeOffline,
    [switch]$Quiet
)

begin {
    $ScriptVersion = "3.0"
    $ScriptName    = "Get-NetworkDiscovery"

    #region Profile / flag resolution
    if ($QuickScan) { $ScanProfile = 'Quick' }
    if ($ScanProfile -eq 'Quick') { $ScanPorts = $false }
    if ($ScanProfile -eq 'Full') {
        $EnableWMI          = $true
        $EnableAD           = $true
        $EnableSSL          = $true
        $EnableSNMP         = $true
        $EnableSecurityObs  = $true
        $EnablePublicIP     = $true
        $EnableGatewayProbe = $true
    }
    #endregion

    #region Banner
    function Show-YWBanner {
        $logo = @(
            "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ ",
            "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|",
            "   \ V /| _| \ V /| |__ / _ \ | .\` | |) |  \ \/\/ /| |_| | | |/ _ \| .\` || | ",
            "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
        )
        $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
        $border  = "=" * 81
        Write-Host ""
        Write-Host $border -ForegroundColor Gray
        foreach ($line in $logo) { Write-Host $line -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host $tagline.PadLeft(62) -ForegroundColor Gray
        Write-Host $border -ForegroundColor Gray
        Write-Host ""
    }
    #endregion

    #region Phase progress helpers
    $script:PhaseNum    = 0
    $script:TotalPhases = 3  # baseline: recon, scan, post-scan
    if ($ScanProfile -ne 'Quick')                 { $script:TotalPhases++ }  # 1b multi-subnet
    if ($ScanPorts -and $ScanProfile -ne 'Quick') { $script:TotalPhases++ }  # 4 service enum
    if ($EnableGatewayProbe)                       { $script:TotalPhases++ }  # 4b gateway
    if ($EnableWMI)                                { $script:TotalPhases++ }  # 5 WMI
    if ($EnableAD)                                 { $script:TotalPhases++ }  # 6 AD
    if ($EnableSecurityObs)                        { $script:TotalPhases++ }  # 7 security

    function Update-PhaseBar {
        param([string]$Name, [string]$Detail = '')
        if ($Quiet) { return }
        $script:PhaseNum++
        $pct    = [math]::Min([int]($script:PhaseNum / $script:TotalPhases * 100), 99)
        $status = "[$($script:PhaseNum)/$($script:TotalPhases)] $Name"
        if ($Detail) { $status += " - $Detail" }
        Write-Progress -Id 0 -Activity "YW Network Discovery v$ScriptVersion" `
                       -Status $status -PercentComplete $pct
    }

    function Write-SubProgress {
        param([string]$Activity, [string]$Status, [int]$Pct)
        if ($Quiet) { return }
        Write-Progress -Id 1 -ParentId 0 -Activity $Activity `
                       -Status $Status -PercentComplete ([math]::Min($Pct, 99))
    }

    function Clear-SubBar {
        if (-not $Quiet) { Write-Progress -Id 1 -Completed -ErrorAction SilentlyContinue }
    }
    #endregion

    #region Port definitions (35 common ports)
    $CommonPorts = @{
        21    = 'FTP'
        22    = 'SSH'
        23    = 'Telnet'
        25    = 'SMTP'
        53    = 'DNS'
        80    = 'HTTP'
        88    = 'Kerberos'
        110   = 'POP3'
        135   = 'RPC'
        139   = 'NetBIOS'
        143   = 'IMAP'
        161   = 'SNMP'
        389   = 'LDAP'
        443   = 'HTTPS'
        445   = 'SMB'
        465   = 'SMTPS'
        514   = 'Syslog'
        587   = 'SMTP-Sub'
        636   = 'LDAPS'
        993   = 'IMAPS'
        995   = 'POP3S'
        1433  = 'MSSQL'
        1723  = 'PPTP'
        3306  = 'MySQL'
        3389  = 'RDP'
        3690  = 'SVN'
        5432  = 'PostgreSQL'
        5900  = 'VNC'
        5985  = 'WinRM-HTTP'
        5986  = 'WinRM-HTTPS'
        6379  = 'Redis'
        8080  = 'HTTP-Alt'
        8443  = 'HTTPS-Alt'
        9100  = 'Printer'
        27017 = 'MongoDB'
    }
    #endregion

    #region MAC vendor database
    $MacVendors = @{
        '00:1B:D5' = 'Cisco|Network|IOS'
        '00:1E:BD' = 'Cisco|Network|IOS'
        '00:24:97' = 'Cisco|Network|IOS'
        '00:0C:85' = 'Cisco|Network|IOS'
        '00:1D:A2' = 'Cisco|Network|IOS'
        '00:26:0A' = 'Cisco|Network|IOS'
        'D4:C9:EF' = 'Aruba Networks|Network|ArubaOS'
        'B4:75:0E' = 'Aruba Networks|Network|ArubaOS'
        '00:0B:86' = 'Aruba Networks|Network|ArubaOS'
        '24:DE:C6' = 'Aruba Networks|Network|ArubaOS'
        '6C:F3:7F' = 'Aruba Networks|Network|ArubaOS'
        '00:1A:1E' = 'WatchGuard|Network|Fireware'
        '00:90:7F' = 'WatchGuard|Network|Fireware'
        'F0:9F:C2' = 'Ubiquiti|Network|EdgeOS'
        '04:18:D6' = 'Ubiquiti|Network|EdgeOS'
        '24:A4:3C' = 'Ubiquiti|Network|EdgeOS'
        '68:D7:9A' = 'Ubiquiti|Network|EdgeOS'
        '00:0F:B5' = 'Netgear|Network|Unknown'
        '00:09:5B' = 'Netgear|Network|Unknown'
        'A0:63:91' = 'Netgear|Network|Unknown'
        '00:0D:88' = 'D-Link|Network|Unknown'
        '00:17:9A' = 'D-Link|Network|Unknown'
        '00:1C:F0' = 'D-Link|Network|Unknown'
        '00:04:76' = '3Com|Network|Unknown'
        '00:50:04' = '3Com|Network|Unknown'
        '00:01:02' = '3Com|Network|Unknown'
        '00:19:06' = 'Fortinet|Network|FortiOS'
        '00:09:0F' = 'Fortinet|Network|FortiOS'
        '70:4C:A5' = 'Fortinet|Network|FortiOS'
        '00:13:C4' = 'TP-Link|Network|Unknown'
        '50:C7:BF' = 'TP-Link|Network|Unknown'
        'F4:F2:6D' = 'TP-Link|Network|Unknown'
        '00:E0:4C' = 'Realtek|Network|Unknown'
        '52:54:00' = 'Realtek|Network|Unknown'
        '00:1F:33' = 'Netgear|Network|Unknown'
        'E0:46:9A' = 'Netgear|Network|Unknown'
        '00:22:6B' = 'Netgear|Network|Unknown'
        '00:0C:76' = 'HP|Printer|Printer'
        '00:14:38' = 'HP|Printer|Printer'
        '00:1E:0B' = 'HP|Printer|Printer'
        '00:21:5A' = 'HP|Printer|Printer'
        '3C:D9:2B' = 'HP|Printer|Printer'
        'B4:99:BA' = 'HP|Printer|Printer'
        'D4:85:64' = 'HP|Printer|Printer'
        '00:00:85' = 'Canon|Printer|Printer'
        '00:1E:8F' = 'Canon|Printer|Printer'
        '9C:E6:E7' = 'Canon|Printer|Printer'
        '00:00:48' = 'Epson|Printer|Printer'
        '00:26:AB' = 'Epson|Printer|Printer'
        '64:EB:8C' = 'Epson|Printer|Printer'
        '00:80:77' = 'Brother|Printer|Printer'
        '00:1B:A9' = 'Brother|Printer|Printer'
        '30:05:5C' = 'Brother|Printer|Printer'
        '00:00:AA' = 'Xerox|Printer|Printer'
        '08:00:03' = 'Xerox|Printer|Printer'
        '00:1B:78' = 'Dell|Computer|Windows'
        '00:14:22' = 'Dell|Computer|Windows'
        'D4:BE:D9' = 'Dell|Computer|Windows'
        '00:1E:4F' = 'Dell|Computer|Windows'
        '00:21:70' = 'Dell|Computer|Windows'
        '00:24:E8' = 'Dell|Computer|Windows'
        '18:03:73' = 'Dell|Computer|Windows'
        'B8:2A:72' = 'Dell|Server|Windows Server'
        'D0:67:E5' = 'Dell|Server|Windows Server'
        '00:50:8B' = 'HP|Computer|Windows'
        '00:1F:29' = 'HP|Computer|Windows'
        '00:23:7D' = 'HP|Computer|Windows'
        '00:26:55' = 'HP|Computer|Windows'
        '2C:27:D7' = 'HP|Server|Windows Server'
        '9C:B6:54' = 'HP|Server|Windows Server'
        '00:1A:6B' = 'Lenovo|Computer|Windows'
        '54:EE:75' = 'Lenovo|Computer|Windows'
        '00:21:CC' = 'Lenovo|Computer|Windows'
        '40:F2:E9' = 'Lenovo|Computer|Windows'
        '00:25:84' = 'Apple|Computer|macOS'
        '00:26:BB' = 'Apple|Computer|macOS'
        '3C:07:54' = 'Apple|Computer|macOS'
        '68:5B:35' = 'Apple|Computer|macOS'
        '98:01:A7' = 'Apple|Computer|macOS'
        'A4:5E:60' = 'Apple|Computer|macOS'
        'BC:92:6B' = 'Apple|Computer|macOS'
        'F0:99:BF' = 'Apple|Computer|macOS'
        '00:23:DF' = 'Apple|Mobile|iOS'
        '10:40:F3' = 'Apple|Mobile|iOS'
        '28:E1:4C' = 'Apple|Mobile|iOS'
        'DC:2B:2A' = 'Apple|Mobile|iOS'
        '00:03:FF' = 'Microsoft|Computer|Windows'
        '00:50:F2' = 'Microsoft|Computer|Windows'
        '7C:ED:8D' = 'Microsoft|Computer|Windows'
        '00:15:5D' = 'Microsoft|Computer|Hyper-V'
        '00:50:56' = 'VMware|Computer|Virtual'
        '00:0C:29' = 'VMware|Computer|Virtual'
        '00:05:69' = 'VMware|Computer|Virtual'
        '00:1C:14' = 'VMware|Computer|Virtual'
        '00:1C:42' = 'Parallels|Computer|Virtual'
        '08:00:27' = 'VirtualBox|Computer|Virtual'
        'DC:A6:32' = 'Raspberry Pi|IoT|Linux'
        'B8:27:EB' = 'Raspberry Pi|IoT|Linux'
        'E4:5F:01' = 'Raspberry Pi|IoT|Linux'
        '28:CD:C1' = 'Raspberry Pi|IoT|Linux'
        '00:12:FB' = 'Samsung|Computer|Unknown'
        '00:1B:98' = 'Samsung|Mobile|Android'
        '34:23:BA' = 'Samsung|Mobile|Android'
        '38:AA:3C' = 'Samsung|Mobile|Android'
        '88:30:8A' = 'Samsung|Mobile|Android'
        '00:1C:62' = 'LG|Mobile|Android'
        '10:68:3F' = 'LG|Mobile|Android'
        '00:26:BA' = 'Motorola|Mobile|Android'
        '48:2C:EA' = 'Motorola|Mobile|Android'
        '00:1B:21' = 'Intel|Computer|Unknown'
        '00:1E:67' = 'Intel|Computer|Unknown'
        '00:23:15' = 'Intel|Computer|Unknown'
        'A0:36:9F' = 'Intel|Computer|Unknown'
        '00:C0:B7' = 'APC|IoT|Embedded'
        '00:11:32' = 'Synology|Server|DSM'
        '00:08:9B' = 'QNAP|Server|QTS'
        '24:5E:BE' = 'QNAP|Server|QTS'
        '74:C2:46' = 'Amazon|IoT|Linux'
        '00:FC:8B' = 'Amazon|IoT|Linux'
        '00:1A:11' = 'Google|IoT|Android'
        'F4:F5:D8' = 'Google|IoT|Android'
        '00:0E:58' = 'Sonos|IoT|Embedded'
        '5C:AA:FD' = 'Sonos|IoT|Embedded'
        '18:B4:30' = 'Nest|IoT|Embedded'
        '64:16:66' = 'Nest|IoT|Embedded'
    }
    #endregion

    #region API cache
    $script:MacVendorCache = [hashtable]::Synchronized(@{})
    $script:LastApiCall    = [DateTime]::MinValue
    $script:ApiCallCount   = 0
    #endregion

    #region Helper: Get-MacVendorFromAPI
    function Get-MacVendorFromAPI {
        param([string]$MacAddress, [string]$MacPrefix, [hashtable]$Cache)
        if ($Cache.ContainsKey($MacPrefix)) { return $Cache[$MacPrefix] }
        $firstOctet = $MacPrefix.Split(':')[0]
        if ($firstOctet -and $firstOctet.Length -eq 2) {
            if ($firstOctet[1] -match '[26AEae]') {
                $val = if ($MacAddress -match '^02-42-') { 'Docker Container' } else { 'Randomized/VM' }
                $Cache[$MacPrefix] = $val; return $val
            }
        }
        try {
            $elapsed = (Get-Date) - $script:LastApiCall
            if ($elapsed.TotalMilliseconds -lt 1100) { Start-Sleep -Milliseconds (1100 - [int]$elapsed.TotalMilliseconds) }
            $resp = Invoke-RestMethod -Uri "https://api.macvendors.com/$($MacAddress.Replace(':','-'))" -Method Get -TimeoutSec 5 -ErrorAction Stop
            $script:LastApiCall = Get-Date; $script:ApiCallCount++
            $Cache[$MacPrefix] = $resp; return $resp
        }
        catch { $Cache[$MacPrefix] = 'Unknown'; return 'Unknown' }
    }
    #endregion

    #region Helper: Get-LocalSubnets
    function Get-LocalSubnets {
        $subnets = @()
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -notmatch '^127\.' -and
                $_.IPAddress -notmatch '^169\.254\.' -and
                $_.PrefixLength -ge 8 -and $_.PrefixLength -le 30
            }
        foreach ($a in $adapters) {
            $ipBytes = [System.Net.IPAddress]::Parse($a.IPAddress).GetAddressBytes()
            [Array]::Reverse($ipBytes)
            $ipInt   = [System.BitConverter]::ToUInt32($ipBytes, 0)
            $mask    = [Convert]::ToUInt32(('1' * $a.PrefixLength + '0' * (32 - $a.PrefixLength)), 2)
            $netInt  = $ipInt -band $mask
            $netBytes = [System.BitConverter]::GetBytes($netInt); [Array]::Reverse($netBytes)
            $cidr = "$([System.Net.IPAddress]::new($netBytes))/$($a.PrefixLength)"
            if ($cidr -notin $subnets) { $subnets += $cidr }
        }
        return $subnets
    }
    #endregion

    #region Helper: Get-DefaultGateway
    function Get-DefaultGateway {
        try {
            $gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                  Sort-Object RouteMetric | Select-Object -First 1
            return $gw.NextHop
        } catch { return $null }
    }
    #endregion

    #region Helper: Get-SubnetIPs
    function Get-SubnetIPs {
        param([string]$CIDR)
        if ($CIDR -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') { throw "Invalid CIDR: $CIDR" }
        $net = $CIDR.Split('/')[0]; $bits = [int]$CIDR.Split('/')[1]
        $ipBytes = [System.Net.IPAddress]::Parse($net).GetAddressBytes(); [Array]::Reverse($ipBytes)
        $ipInt   = [System.BitConverter]::ToUInt32($ipBytes, 0)
        $mask    = [Convert]::ToUInt32(('1' * $bits + '0' * (32 - $bits)), 2)
        $netInt  = $ipInt -band $mask
        $bcast   = $netInt -bor (-bnot $mask)
        $ips     = @()
        for ($i = $netInt + 1; $i -lt $bcast; $i++) {
            $b = [System.BitConverter]::GetBytes($i); [Array]::Reverse($b)
            $ips += [System.Net.IPAddress]::new($b).ToString()
        }
        return $ips
    }
    #endregion

    #region Helper: Invoke-MultiSubnetDiscovery
    function Invoke-MultiSubnetDiscovery {
        param([string[]]$KnownSubnets)
        $candidates = @(
            '192.168.0.1','192.168.1.1','192.168.2.1','192.168.10.1','192.168.100.1',
            '10.0.0.1','10.0.0.254','10.0.1.1','10.1.0.1','10.10.0.1',
            '172.16.0.1','172.16.1.1','172.17.0.1'
        )
        $knownNets = @()
        foreach ($c in $KnownSubnets) {
            try { $knownNets += [System.Net.IPNetwork2]::Parse($c) } catch {}
            # Fallback for PS5 which lacks IPNetwork2
        }
        $ourIPs = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.IPAddress -notmatch '^127\.' }).IPAddress

        $newSubnets = [System.Collections.Generic.List[string]]::new()

        # Parallel probe using runspace
        $probeBlock = {
            param($IP, $TimeoutMs)
            try {
                $t = [System.Net.Sockets.TcpClient]::new()
                $r = $t.BeginConnect($IP, 80, $null, $null)
                $ok = $r.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                try { $t.EndConnect($r) } catch {}
                $t.Close()
                if ($ok) { return $IP }
            } catch {}
            try {
                $p = New-Object System.Net.NetworkInformation.Ping
                $reply = $p.Send($IP, $TimeoutMs)
                $p.Dispose()
                if ($reply.Status -eq 'Success') { return $IP }
            } catch {}
            return $null
        }

        $pool = [runspacefactory]::CreateRunspacePool(1, 20)
        $pool.Open()
        $jobs = @()
        foreach ($ip in $candidates) {
            if ($ip -in $ourIPs) { continue }
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($probeBlock).AddArgument($ip).AddArgument(500)
            $jobs += [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip }
        }
        foreach ($j in $jobs) {
            $result = $j.PS.EndInvoke($j.Handle)
            $j.PS.Dispose()
            if ($result) {
                # Infer /24 subnet from the responding IP
                $parts = $result.Split('.')
                $inferred = "$($parts[0]).$($parts[1]).$($parts[2]).0/24"
                if ($inferred -notin $KnownSubnets -and $inferred -notin $newSubnets) {
                    $newSubnets.Add($inferred)
                }
            }
        }
        $pool.Close(); $pool.Dispose()
        return $newSubnets
    }
    #endregion

    #region Helper: Get-PublicIPInfo
    function Get-PublicIPInfo {
        try {
            $r = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 6 -ErrorAction Stop
            return @{
                PublicIP = $r.ip
                ISP      = $r.org
                City     = $r.city
                Region   = $r.region
                Country  = $r.country
                Hostname = $r.hostname
                Timezone = $r.timezone
            }
        } catch { return @{} }
    }
    #endregion

    #region Helper: Get-HTTPTitleInfo
    function Get-HTTPTitleInfo {
        param([string]$IP, [int]$Port)
        $proto = if ($Port -in @(443, 8443, 636)) { 'https' } else { 'http' }
        $url   = "${proto}://${IP}:${Port}/"
        $result = @{ Title = ''; Server = ''; URL = $url; StatusCode = $null }
        try {
            $orig = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $orig
            $result.StatusCode = [int]$resp.StatusCode
            $result.Server     = $resp.Headers['Server']
            if ($resp.Content -match '(?i)<title[^>]*>([^<]+)</title>') {
                $t = $matches[1].Trim() -replace '\s+', ' '
                $result.Title = if ($t.Length -gt 80) { $t.Substring(0, 77) + '...' } else { $t }
            }
        } catch {
            try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $orig } catch {}
        }
        return $result
    }
    #endregion

    #region Helper: Get-SSLCertInfo
    function Get-SSLCertInfo {
        param([string]$IP, [int]$Port, [int]$TimeoutMs = 5000)
        $result = @{ CommonName = ''; Issuer = ''; ExpiryDate = $null; DaysRemaining = $null; SANs = @(); Error = '' }
        try {
            $tcp  = [System.Net.Sockets.TcpClient]::new()
            $conn = $tcp.BeginConnect($IP, $Port, $null, $null)
            if (-not $conn.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                $tcp.Close(); $result.Error = 'Timeout'; return $result
            }
            try { $tcp.EndConnect($conn) } catch { $tcp.Close(); $result.Error = $_.Exception.Message; return $result }

            $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })
            $ssl.AuthenticateAsClient($IP, $null, [System.Security.Authentication.SslProtocols]::None, $false)

            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            $result.CommonName    = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            $result.Issuer        = $cert.Issuer -replace 'CN=','' -replace ',.*',''
            $result.ExpiryDate    = [datetime]::ParseExact($cert.GetExpirationDateString(), 'M/d/yyyy H:mm:ss', $null)
            $result.DaysRemaining = [int]($result.ExpiryDate - (Get-Date)).TotalDays

            $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
            if ($san) { $result.SANs = ($san.Format($false) -split ', ') | Where-Object { $_ } }

            $ssl.Close(); $tcp.Close()
        } catch {
            $result.Error = ($_.Exception.Message -replace "`n",' ').Substring(0, [math]::Min(120, $_.Exception.Message.Length))
        }
        return $result
    }
    #endregion

    #region Helper: Invoke-SNMPGet
    function Invoke-SNMPGet {
        param([string]$IP, [string]$Community = 'public', [int]$TimeoutMs = 2000)
        $result = @{ SysDescr = ''; SysName = ''; SysLocation = ''; CommunityOK = $false; Error = '' }
        try {
            # Build minimal SNMPv1 GET for sysDescr.0, sysName.0, sysLocation.0
            function _BerLen([int]$n) {
                if ($n -lt 128) { return [byte[]]@($n) }
                return [byte[]]@(0x81, [byte]$n)
            }
            function _BerOid([string]$o) {
                $p = $o.Split('.') | ForEach-Object { [int]$_ }
                $b = [System.Collections.Generic.List[byte]]::new()
                $b.Add([byte](40 * $p[0] + $p[1]))
                for ($i = 2; $i -lt $p.Count; $i++) {
                    $v = $p[$i]
                    if ($v -lt 128) { $b.Add([byte]$v) }
                    else {
                        $enc = [System.Collections.Generic.List[byte]]::new()
                        while ($v -gt 0) { $enc.Insert(0, [byte]($v -band 0x7F)); $v = $v -shr 7 }
                        for ($j = 0; $j -lt $enc.Count - 1; $j++) { $b.Add($enc[$j] -bor 0x80) }
                        $b.Add($enc[$enc.Count - 1])
                    }
                }
                return $b.ToArray()
            }
            function _Varbind([string]$oid) {
                $ob = _BerOid $oid
                $oidTLV = @(0x06) + (_BerLen $ob.Length) + $ob + @(0x05, 0x00)
                return @(0x30) + (_BerLen $oidTLV.Length) + $oidTLV
            }
            $vbl = (_Varbind '1.3.6.1.2.1.1.1.0') + (_Varbind '1.3.6.1.2.1.1.5.0') + (_Varbind '1.3.6.1.2.1.1.6.0')
            $vblTLV = @(0x30) + (_BerLen $vbl.Length) + $vbl
            $pduBody = @(0x02,0x04,0x01,0x02,0x03,0x04,0x02,0x01,0x00,0x02,0x01,0x00) + $vblTLV
            $pdu = @(0xa0) + (_BerLen $pduBody.Length) + $pduBody
            $cb  = [System.Text.Encoding]::ASCII.GetBytes($Community)
            $msg = @(0x02,0x01,0x00) + @(0x04) + (_BerLen $cb.Length) + $cb + $pdu
            $pkt = @(0x30) + (_BerLen $msg.Length) + $msg

            $udp = [System.Net.Sockets.UdpClient]::new()
            $udp.Client.ReceiveTimeout = $TimeoutMs
            $ep  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($IP), 161)
            [void]$udp.Send([byte[]]$pkt, $pkt.Length, $ep)

            $recvEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)
            $resp   = $udp.Receive([ref]$recvEP)
            $udp.Close()

            if ($resp -and $resp.Length -gt 0) {
                $result.CommunityOK = $true
                # Extract OCTET STRING values (tag 0x04) from response
                $strings = [System.Collections.Generic.List[string]]::new()
                $pos = 0
                while ($pos -lt $resp.Length - 1) {
                    if ($resp[$pos] -eq 0x04) {
                        $slen = $resp[$pos + 1]
                        if ($slen -lt 128 -and ($pos + 2 + $slen) -le $resp.Length) {
                            $s = [System.Text.Encoding]::ASCII.GetString($resp, $pos + 2, $slen).Trim()
                            if ($s.Length -gt 2 -and $s -ne $Community -and $s -notmatch '^[\x00-\x1f]+$') {
                                $strings.Add($s)
                            }
                            $pos += 2 + $slen; continue
                        }
                    }
                    $pos++
                }
                if ($strings.Count -ge 1) { $result.SysDescr   = $strings[0] }
                if ($strings.Count -ge 2) { $result.SysName     = $strings[1] }
                if ($strings.Count -ge 3) { $result.SysLocation = $strings[2] }
            }
        } catch [System.Net.Sockets.SocketException] {
            $result.Error = 'Timeout'
        } catch {
            $result.Error = $_.Exception.Message
        }
        return $result
    }
    #endregion

    #region Helper: Invoke-GatewayFingerprint
    $GatewayPatterns = @(
        @{ K=@('fortigate','fortinet');          V='Fortinet';           P='FortiGate' },
        @{ K=@('sonicwall','sonicwall');          V='SonicWall';          P='SonicWall' },
        @{ K=@('pfsense');                        V='Netgate';            P='pfSense' },
        @{ K=@('opnsense');                       V='OPNsense';           P='OPNsense' },
        @{ K=@('meraki');                         V='Cisco Meraki';       P='Meraki' },
        @{ K=@('ubiquiti','unifi','edgeos');       V='Ubiquiti';           P='UniFi/EdgeOS' },
        @{ K=@('watchguard','firebox');            V='WatchGuard';         P='Firebox' },
        @{ K=@('sophos');                         V='Sophos';             P='XG Firewall' },
        @{ K=@('mikrotik','routeros');             V='MikroTik';           P='RouterOS' },
        @{ K=@('draytek','vigor');                V='DrayTek';            P='Vigor' },
        @{ K=@('palo alto','pan-os');             V='Palo Alto Networks'; P='PAN-OS' },
        @{ K=@('cisco');                          V='Cisco';              P='Cisco' }
    )

    function Invoke-GatewayFingerprint {
        param([string]$GatewayIP, [string[]]$Communities = @('public'))
        $gw = @{ IP = $GatewayIP; Vendor = ''; Product = ''; Confidence = ''; Source = ''; SysDescr = '' }
        if (-not $GatewayIP) { return $gw }

        # 1. SNMP sysDescr - highest confidence
        foreach ($c in $Communities) {
            $snmp = Invoke-SNMPGet -IP $GatewayIP -Community $c -TimeoutMs 2000
            if ($snmp.CommunityOK -and $snmp.SysDescr) {
                $gw.SysDescr = $snmp.SysDescr
                $descLow = $snmp.SysDescr.ToLower()
                foreach ($pat in $GatewayPatterns) {
                    foreach ($kw in $pat.K) {
                        if ($descLow -match [regex]::Escape($kw)) {
                            $gw.Vendor = $pat.V; $gw.Product = $pat.P
                            $gw.Confidence = 'High'; $gw.Source = 'SNMP'
                            return $gw
                        }
                    }
                }
                $gw.Confidence = 'Medium'; $gw.Source = 'SNMP (unknown vendor)'
                break
            }
        }

        # 2. HTTP title/server header - medium confidence
        foreach ($port in @(80, 443, 8080, 8443)) {
            $http = Get-HTTPTitleInfo -IP $GatewayIP -Port $port
            if ($http.Title -or $http.Server) {
                $combined = ("$($http.Title) $($http.Server)").ToLower()
                foreach ($pat in $GatewayPatterns) {
                    foreach ($kw in $pat.K) {
                        if ($combined -match [regex]::Escape($kw)) {
                            $gw.Vendor = $pat.V; $gw.Product = $pat.P
                            $gw.Confidence = 'Medium'; $gw.Source = "HTTP:$port"
                            return $gw
                        }
                    }
                }
            }
        }
        return $gw
    }
    #endregion

    #region Helper: Invoke-WMIHostQuery
    function Invoke-WMIHostQuery {
        param([string]$ComputerName, [PSCredential]$Credential = $null)
        $result = @{
            Success = $false; OSName = ''; OSBuild = ''; LastBootTime = $null; UptimeDays = $null
            ComputerName = ''; Domain = ''; Manufacturer = ''; Model = ''; RAM_GB = $null
            SerialNumber = ''; Disks = @(); KeyServices = @(); Error = ''
        }
        $cimParams = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
        if ($Credential) { $cimParams['Credential'] = $Credential }
        try {
            $session = New-CimSession @cimParams -OperationTimeoutSec 15
            $os = Get-CimInstance -CimSession $session Win32_OperatingSystem -ErrorAction Stop
            $result.OSName      = $os.Caption
            $result.OSBuild     = $os.BuildNumber
            $result.LastBootTime = $os.LastBootUpTime
            $result.UptimeDays  = [int]((Get-Date) - $os.LastBootUpTime).TotalDays

            $cs = Get-CimInstance -CimSession $session Win32_ComputerSystem
            $result.ComputerName = $cs.Name
            $result.Domain       = $cs.Domain
            $result.Manufacturer = $cs.Manufacturer -replace 'To Be Filled By O\.E\.M\.', ''
            $result.Model        = $cs.Model
            $result.RAM_GB       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

            $bios = Get-CimInstance -CimSession $session Win32_BIOS
            $result.SerialNumber = $bios.SerialNumber -replace 'To Be Filled By O\.E\.M\.', ''

            $disks = Get-CimInstance -CimSession $session Win32_LogicalDisk -Filter 'DriveType=3'
            $result.Disks = @($disks | ForEach-Object {
                [PSCustomObject]@{
                    Drive    = $_.DeviceID
                    Size_GB  = [math]::Round($_.Size / 1GB, 1)
                    Free_GB  = [math]::Round($_.FreeSpace / 1GB, 1)
                    Free_Pct = if ($_.Size -gt 0) { [math]::Round($_.FreeSpace / $_.Size * 100, 0) } else { 0 }
                }
            })

            $svcNames = 'ADWS','NTDS','DNS','W3SVC','MSSQLSERVER','WinDefend','wuauserv','RemoteRegistry','Schedule','Spooler','TermService'
            $filter   = "Name IN ('$($svcNames -join "','")')"
            $svcs     = Get-CimInstance -CimSession $session Win32_Service -Filter $filter -ErrorAction SilentlyContinue
            $result.KeyServices = @($svcs | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode }
            })

            Remove-CimSession $session -ErrorAction SilentlyContinue
            $result.Success = $true
        } catch {
            $result.Error = ($_.Exception.Message -replace "`n",' ') | Select-Object -First 1
            if ($result.Error.Length -gt 150) { $result.Error = $result.Error.Substring(0,147) + '...' }
        }
        return $result
    }
    #endregion

    #region Helper: Get-ADEnvironmentInfo
    function Get-ADEnvironmentInfo {
        $result = @{
            Available = $false; DomainName = ''; NetBIOSName = ''; FunctionalLevel = ''
            PDCEmulator = ''; DomainControllers = @(); UserCount = $null; ComputerCount = $null
            OSVersions = @{}; DomainAdmins = @(); PasswordPolicy = @{}; OUCount = $null; Error = ''
        }
        # Try AD module first
        $adAvailable = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)
        if ($adAvailable) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $dom = Get-ADDomain -ErrorAction Stop
                $result.Available      = $true
                $result.DomainName     = $dom.DNSRoot
                $result.NetBIOSName    = $dom.NetBIOSName
                $result.FunctionalLevel = $dom.DomainMode.ToString()
                $result.PDCEmulator    = $dom.PDCEmulator

                $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
                $result.DomainControllers = @($dcs | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name; IPAddress = $_.IPv4Address; Site = $_.Site
                        OS = $_.OperatingSystem; IsGC = $_.IsGlobalCatalog; IsRO = $_.IsReadOnly
                    }
                })

                $result.UserCount = @(Get-ADUser -Filter * -ErrorAction SilentlyContinue).Count

                $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem -ErrorAction SilentlyContinue)
                $result.ComputerCount = $computers.Count
                $osGroups = $computers | Where-Object { $_.OperatingSystem } | Group-Object OperatingSystem
                $result.OSVersions = @{}
                foreach ($g in $osGroups) { $result.OSVersions[$g.Name] = $g.Count }

                try {
                    $admins = Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue
                    $result.DomainAdmins = @(($admins | Where-Object { $_.objectClass -eq 'user' } | Select-Object -First 20).Name)
                } catch {}

                try {
                    $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
                    $result.PasswordPolicy = @{
                        MinLength         = $pp.MinPasswordLength
                        ComplexityEnabled = $pp.ComplexityEnabled
                        MaxAgeDays        = $pp.MaxPasswordAge.Days
                        LockoutThreshold  = $pp.LockoutThreshold
                        LockoutDurationMin = $pp.LockoutDuration.Minutes
                    }
                } catch {}

                try { $result.OUCount = @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue).Count } catch {}
            } catch {
                $result.Error = $_.Exception.Message -replace "`n",' '
            }
            return $result
        }

        # LDAP fallback via .NET DirectoryServices (anonymous bind, for non-domain-joined hosts)
        $result.Error = 'AD module unavailable - LDAP probe not attempted (requires RSAT)'
        return $result
    }
    #endregion

    #region Security rules
    $SecurityRules = @(
        @{ Ports=@(21);       Flag='FTP enabled (unencrypted file transfer)';            Severity='MEDIUM' },
        @{ Ports=@(23);       Flag='Telnet enabled (cleartext credentials)';             Severity='HIGH' },
        @{ Ports=@(161);      Flag='SNMP exposed (verify community strings)';            Severity='MEDIUM' },
        @{ Ports=@(137,139);  Flag='NetBIOS exposed on network';                         Severity='LOW' },
        @{ Ports=@(3389);     Flag='RDP exposed to network';                             Severity='MEDIUM' },
        @{ Ports=@(5900);     Flag='VNC exposed (often weak or no authentication)';      Severity='HIGH' },
        @{ Ports=@(1433);     Flag='SQL Server port exposed (1433)';                     Severity='HIGH' },
        @{ Ports=@(3306);     Flag='MySQL exposed (3306)';                               Severity='HIGH' },
        @{ Ports=@(5432);     Flag='PostgreSQL exposed (5432)';                          Severity='HIGH' },
        @{ Ports=@(6379);     Flag='Redis exposed (typically unauthenticated)';          Severity='CRITICAL' },
        @{ Ports=@(27017);    Flag='MongoDB exposed (typically unauthenticated)';        Severity='CRITICAL' },
        @{ Ports=@(9200);     Flag='Elasticsearch exposed';                              Severity='HIGH' },
        @{ Ports=@(5985);     Flag='WinRM HTTP exposed (prefer HTTPS on port 5986)';    Severity='MEDIUM' }
    )
    #endregion

    #region Helper: Get-SecurityObservations
    function Get-SecurityObservations {
        param([object[]]$Devices, [object[]]$SSLResults)
        $allFlags = [System.Collections.Generic.List[object]]::new()
        foreach ($dev in $Devices) {
            $ports = @($dev.OpenPorts)
            $devFlags = [System.Collections.Generic.List[object]]::new()

            foreach ($rule in $SecurityRules) {
                $hit = $false
                foreach ($rp in $rule.Ports) { if ($rp -in $ports) { $hit = $true; break } }
                if ($hit) {
                    $devFlags.Add([PSCustomObject]@{ Flag=$rule.Flag; Severity=$rule.Severity; IP=$dev.IPAddress })
                }
            }

            # High port exposure
            if ($ports.Count -gt 15) {
                $devFlags.Add([PSCustomObject]@{ Flag="High port exposure ($($ports.Count) open ports)"; Severity='MEDIUM'; IP=$dev.IPAddress })
            }

            # WMI-derived observations
            if ($dev.WMIData -and $dev.WMIData.Success) {
                if ($dev.WMIData.UptimeDays -gt 90) {
                    $devFlags.Add([PSCustomObject]@{ Flag="Server not rebooted in $($dev.WMIData.UptimeDays) days"; Severity='LOW'; IP=$dev.IPAddress })
                }
                foreach ($disk in $dev.WMIData.Disks) {
                    if ($disk.Free_Pct -lt 10) {
                        $devFlags.Add([PSCustomObject]@{ Flag="Disk $($disk.Drive) critically low ($($disk.Free_Pct)% free, $($disk.Free_GB) GB)"; Severity='HIGH'; IP=$dev.IPAddress })
                    } elseif ($disk.Free_Pct -lt 20) {
                        $devFlags.Add([PSCustomObject]@{ Flag="Disk $($disk.Drive) low space ($($disk.Free_Pct)% free)"; Severity='MEDIUM'; IP=$dev.IPAddress })
                    }
                }
            }

            if ($devFlags.Count -gt 0) {
                $dev | Add-Member -NotePropertyName SecurityFlags -NotePropertyValue $devFlags -Force
                $allFlags.AddRange($devFlags)
            }
        }

        # SSL expiry flags from SSL results
        if ($SSLResults) {
            foreach ($ssl in $SSLResults) {
                if ($ssl.DaysRemaining -ne $null) {
                    if ($ssl.DaysRemaining -lt 0) {
                        $allFlags.Add([PSCustomObject]@{ Flag="SSL certificate EXPIRED on $($ssl.IP):$($ssl.Port) (CN: $($ssl.CommonName))"; Severity='CRITICAL'; IP=$ssl.IP })
                    } elseif ($ssl.DaysRemaining -le 7) {
                        $allFlags.Add([PSCustomObject]@{ Flag="SSL certificate expiring in $($ssl.DaysRemaining) days on $($ssl.IP):$($ssl.Port)"; Severity='HIGH'; IP=$ssl.IP })
                    } elseif ($ssl.DaysRemaining -le 30) {
                        $allFlags.Add([PSCustomObject]@{ Flag="SSL certificate expiring in $($ssl.DaysRemaining) days on $($ssl.IP):$($ssl.Port)"; Severity='MEDIUM'; IP=$ssl.IP })
                    }
                }
            }
        }
        return $allFlags
    }
    #endregion

    #region Parallel scan scriptblock
    $ScanScriptBlock = {
        param($IP, $DoPortScan, $TimeoutMs, $PortMap, $MacVendorMap)

        $ping = New-Object System.Net.NetworkInformation.Ping
        try   { $reply = $ping.Send($IP, $TimeoutMs); $online = ($reply.Status -eq 'Success') }
        catch { $online = $false }
        finally { $ping.Dispose() }

        if (-not $online) {
            return [PSCustomObject]@{
                IPAddress = $IP; Status = 'Offline'; Hostname = $null; DeviceType = 'Unknown'
                OS = $null; MACAddress = $null; MACPrefix = $null; Vendor = $null
                OpenPorts = @(); Services = @(); IsDomainController = $false; LastSeen = $null
            }
        }

        # DNS hostname
        $hostname = 'N/A'
        if ($DoPortScan) {
            try {
                $dns = [System.Net.Dns]::GetHostEntry($IP)
                if ($dns.HostName -and $dns.HostName -ne $IP) {
                    $hostname = $dns.HostName.Split('.')[0]
                }
            } catch {}
        }

        # MAC via ARP
        $macAddress = 'N/A'; $macPrefix = $null; $vendor = 'Unknown'; $vendorHint = $null
        try {
            $arpOut  = & arp -a 2>$null
            $arpLine = $arpOut | Where-Object { $_ -match "\b$([regex]::Escape($IP))\b" }
            if ($arpLine -and $arpLine -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                $macAddress = $matches[0].ToUpper().Replace(':', '-')
                $macPrefix  = ($macAddress -split '-')[0..2] -join ':'
                if ($MacVendorMap.ContainsKey($macPrefix)) {
                    $parts = $MacVendorMap[$macPrefix] -split '\|'
                    $vendor = $parts[0]
                    if ($parts.Count -ge 3) { $vendorHint = "$($parts[1])|$($parts[2])" }
                }
            }
        } catch {}

        # Port scan
        $openPorts = @(); $services = @()
        if ($DoPortScan) {
            foreach ($port in $PortMap.Keys) {
                try {
                    $tc = New-Object System.Net.Sockets.TcpClient
                    $ar = $tc.BeginConnect($IP, $port, $null, $null)
                    $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                    if ($ok) { try { $tc.EndConnect($ar); $openPorts += $port; $services += $PortMap[$port] } catch {} }
                    $tc.Close(); $tc.Dispose()
                } catch {}
            }
        }

        # DC detection
        $isDC = ($openPorts -contains 88 -and $openPorts -contains 389)

        # Device type
        $deviceType = 'Unknown'; $os = 'Unknown'
        if ($vendorHint) {
            $hp = $vendorHint -split '\|'
            switch ($hp[0]) {
                'Printer'  { $deviceType = 'Printer';        $os = "$vendor Printer" }
                'Network'  { $deviceType = 'Network Device'; $os = if ($hp[1] -ne 'Unknown') { $hp[1] } else { "$vendor Device" } }
                'Server'   { $deviceType = 'Server';         $os = if ($hp[1] -ne 'Unknown') { $hp[1] } else { 'Server' } }
                'Computer' { $deviceType = 'Workstation';    $os = if ($hp[1] -ne 'Unknown') { $hp[1] } else { 'Unknown' } }
                'Mobile'   { $deviceType = 'Mobile Device';  $os = if ($hp[1] -ne 'Unknown') { $hp[1] } else { 'Mobile' } }
                'IoT'      { $deviceType = 'IoT Device';     $os = if ($hp[1] -ne 'Unknown') { $hp[1] } else { $vendor } }
            }
        }
        if ($deviceType -eq 'Unknown' -and $openPorts.Count -gt 0) {
            if ($isDC) {
                $deviceType = 'Server'; $os = 'Windows Server (DC)'
            } elseif ($openPorts -contains 445 -and $openPorts -contains 3389) {
                $deviceType = 'Server'; $os = 'Windows Server'
            } elseif ($openPorts -contains 445 -or $openPorts -contains 139) {
                $deviceType = 'Workstation'; $os = 'Windows'
            } elseif ($openPorts -contains 515 -or $openPorts -contains 631 -or $openPorts -contains 9100) {
                $deviceType = 'Printer'; $os = 'Printer Firmware'
            } elseif ($openPorts -contains 22 -and $vendor -match 'Aruba|WatchGuard|Ubiquiti|Cisco|Netgear|D-Link|Fortinet|TP-Link|MikroTik') {
                $deviceType = 'Network Device'; $os = "$vendor Device"
            } elseif ($openPorts -contains 22 -or ($openPorts -contains 80 -and -not ($openPorts -contains 445))) {
                $deviceType = 'Network Device'
            }
        }

        return [PSCustomObject]@{
            IPAddress          = $IP
            Status             = 'Online'
            Hostname           = $hostname
            DeviceType         = $deviceType
            OS                 = $os
            MACAddress         = $macAddress
            MACPrefix          = $macPrefix
            Vendor             = $vendor
            OpenPorts          = $openPorts
            Services           = ($services | Select-Object -Unique) -join ', '
            IsDomainController = $isDC
            LastSeen           = Get-Date
        }
    }
    #endregion

    $AllResults = @()
    $AllIPs     = @()
    $startTime  = Get-Date

    if (-not $Quiet) {
        Show-YWBanner
        Write-Host "  Network Discovery Tool v$ScriptVersion" -ForegroundColor Cyan
        Write-Host "  Profile: $ScanProfile" -ForegroundColor Gray
        Write-Host ""
    }
}

process {
    #region Phase 1: Network Reconnaissance
    Update-PhaseBar 'Network Reconnaissance'
    if (-not $Quiet) { Write-Host "[Phase 1] Network Reconnaissance..." -ForegroundColor Cyan }

    $defaultGateway = Get-DefaultGateway
    $dnsServers     = @()
    try {
        $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.ServerAddresses } |
                        ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
    } catch {}

    $publicIPInfo = @{}
    if ($EnablePublicIP) {
        if (-not $Quiet) { Write-Host "  Fetching public IP info..." -ForegroundColor Gray }
        $publicIPInfo = Get-PublicIPInfo
        if ($publicIPInfo.PublicIP -and -not $Quiet) {
            Write-Host "  Public IP: $($publicIPInfo.PublicIP)  ISP: $($publicIPInfo.ISP)" -ForegroundColor Gray
        }
    }

    if (-not $Quiet -and $defaultGateway) {
        Write-Host "  Gateway : $defaultGateway" -ForegroundColor Gray
        Write-Host "  DNS     : $($dnsServers -join ', ')" -ForegroundColor Gray
    }
    #endregion

    #region Input: build IP list
    switch ($PSCmdlet.ParameterSetName) {
        'Subnet' {
            if (-not $Subnet -or $Subnet.Count -eq 0) {
                if (-not $Quiet) { Write-Host "`nAuto-detecting local subnets..." -ForegroundColor Yellow }
                $Subnet = Get-LocalSubnets
                if ($Subnet.Count -eq 0) { throw "Could not detect any local subnets. Specify -Subnet." }
                if (-not $Quiet) {
                    Write-Host "  Detected $($Subnet.Count) subnet(s):" -ForegroundColor Green
                    $Subnet | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
                }
            }
            foreach ($net in $Subnet) { $AllIPs += Get-SubnetIPs -CIDR $net }
        }
        'IPRange' {
            if ($IPRange -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})$') {
                for ($i = [int]$matches[2]; $i -le [int]$matches[4]; $i++) { $AllIPs += $matches[1] + $i }
            } else { throw "Invalid IP range format. Use: 192.168.1.1-192.168.1.254" }
        }
        'IPList' {
            $AllIPs = Get-Content $IPList | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }
        }
    }
    if ($AllIPs.Count -eq 0) { throw "No valid IP addresses to scan." }
    #endregion

    #region Phase 1b: Multi-Subnet Discovery
    if ($ScanProfile -ne 'Quick' -and $Subnet) {
        Update-PhaseBar 'Multi-Subnet Discovery' "probing $($Subnet.Count) known subnet(s)"
        if (-not $Quiet) { Write-Host "[Phase 1b] Multi-subnet discovery..." -ForegroundColor Cyan }
        $extraNets = Invoke-MultiSubnetDiscovery -KnownSubnets $Subnet
        if ($extraNets.Count -gt 0) {
            foreach ($en in $extraNets) {
                if (-not $Quiet) { Write-Host "  Found additional subnet: $en" -ForegroundColor Yellow }
                $AllIPs += Get-SubnetIPs -CIDR $en
            }
        } else {
            if (-not $Quiet) { Write-Host "  No additional subnets found." -ForegroundColor Gray }
        }
    }
    #endregion

    #region Phase 2: Parallel Host Discovery + Port Scan
    $scanMode = if ($ScanPorts) { "port scan ($($CommonPorts.Count) ports)" } else { "ping only" }
    Update-PhaseBar 'Host Discovery' "$($AllIPs.Count) IPs | $scanMode | $ThrottleLimit threads"
    if (-not $Quiet) {
        Write-Host "[Phase 2] Scanning $($AllIPs.Count) IPs ($scanMode, $ThrottleLimit threads)..." -ForegroundColor Cyan
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    $runspaces = @()

    foreach ($IP in $AllIPs) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScanScriptBlock).AddArgument($IP).AddArgument($ScanPorts).AddArgument($Timeout).AddArgument($CommonPorts).AddArgument($MacVendors)
        $runspaces += [PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() }
    }

    $completed = 0; $online = 0; $Results = @()
    while ($runspaces.Handle.IsCompleted -contains $false) {
        $runspaces | Where-Object { $_.Handle.IsCompleted } | ForEach-Object {
            $r = $_.Pipe.EndInvoke($_.Handle)
            $Results += $r; $_.Pipe.Dispose(); $completed++
            if ($r.Status -eq 'Online') { $online++ }
            if (-not $Quiet) {
                $pct = [math]::Round($completed / $AllIPs.Count * 100, 1)
                $lastIP = $r.IPAddress
                Write-SubProgress -Activity "Scanning" `
                    -Status "$completed/$($AllIPs.Count) ($pct%) | $online online | last: $lastIP" `
                    -Pct $pct
            }
        }
        $runspaces = $runspaces | Where-Object { -not $_.Handle.IsCompleted }
        Start-Sleep -Milliseconds 50
    }
    # Collect remaining
    $runspaces | ForEach-Object {
        $r = $_.Pipe.EndInvoke($_.Handle); $Results += $r; $_.Pipe.Dispose(); $completed++
        if ($r.Status -eq 'Online') { $online++ }
    }
    $pool.Close(); $pool.Dispose()
    Clear-SubBar
    #endregion

    #region Post-scan: MAC enrichment + NetBIOS (Phase 3)
    Update-PhaseBar 'Post-Scan Enrichment' "MAC | NetBIOS | vendor"
    if (-not $Quiet) { Write-Host "  Enriching MAC addresses via ARP table..." -ForegroundColor Gray }
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' }
        $neighborMap = @{}
        foreach ($n in $neighbors) { $neighborMap[$n.IPAddress] = $n.LinkLayerAddress.ToUpper() }

        foreach ($r in $Results) {
            if ($r.Status -eq 'Online' -and $r.MACAddress -eq 'N/A' -and $neighborMap.ContainsKey($r.IPAddress)) {
                $r.MACAddress = $neighborMap[$r.IPAddress]
                $r.MACPrefix  = ($r.MACAddress -split '-')[0..2] -join ':'
                if ($MacVendors.ContainsKey($r.MACPrefix)) {
                    $parts = $MacVendors[$r.MACPrefix] -split '\|'
                    $r.Vendor = $parts[0]
                }
            }
        }
    } catch {}
    #endregion

    #region Post-scan: MAC Vendor API lookup
    if ($UseMacVendorAPI) {
        $unknownVendors = $Results | Where-Object { $_.Status -eq 'Online' -and $_.MACAddress -ne 'N/A' -and $_.Vendor -eq 'Unknown' -and $_.MACPrefix }
        if ($unknownVendors.Count -gt 0) {
            $prefixToMac = @{}
            $unknownVendors | ForEach-Object { if (-not $prefixToMac.ContainsKey($_.MACPrefix)) { $prefixToMac[$_.MACPrefix] = $_.MACAddress } }
            if (-not $Quiet) { Write-Host "  MAC vendor API: looking up $($prefixToMac.Count) unique prefixes..." -ForegroundColor Gray }
            $macIdx = 0
            foreach ($pfx in $prefixToMac.Keys) {
                $macIdx++
                Write-SubProgress -Activity "MAC Vendor Lookup" `
                    -Status "$macIdx/$($prefixToMac.Count): $pfx" `
                    -Pct ([int]($macIdx / $prefixToMac.Count * 100))
                $v = Get-MacVendorFromAPI -MacAddress $prefixToMac[$pfx] -MacPrefix $pfx -Cache $script:MacVendorCache
                $Results | Where-Object { $_.MACPrefix -eq $pfx } | ForEach-Object { $_.Vendor = $v }
            }
            Clear-SubBar
        }
    }
    #endregion

    #region Post-scan: NetBIOS hostname resolution
    $needNB = @($Results | Where-Object { $_.Status -eq 'Online' -and $_.Hostname -eq 'N/A' -and
                ($_.OpenPorts -contains 445 -or $_.OpenPorts -contains 139 -or $_.OpenPorts -contains 135 -or $_.OpenPorts -contains 3389) })
    if ($needNB.Count -gt 0 -and -not ($ScanProfile -eq 'Quick')) {
        if (-not $Quiet) { Write-Host "  NetBIOS resolution for $($needNB.Count) Windows device(s)..." -ForegroundColor Gray }
        $nbResolved = 0; $nbIdx = 0
        foreach ($dev in $needNB) {
            $nbIdx++
            Write-SubProgress -Activity "NetBIOS Resolution" `
                -Status "$nbIdx/$($needNB.Count): $($dev.IPAddress)" `
                -Pct ([int]($nbIdx / $needNB.Count * 100))
            try {
                $job = Start-Job -ScriptBlock { param($ip) & nbtstat -A $ip 2>$null } -ArgumentList $dev.IPAddress
                $done = Wait-Job $job -Timeout 3
                if ($done) {
                    $out = Receive-Job $job
                    foreach ($line in $out) {
                        if ($line -match '^\s*([A-Z0-9\-]+)\s+<00>\s+UNIQUE') {
                            $nb = $matches[1].Trim()
                            if ($nb.Length -ge 1 -and $nb.Length -le 15) { $dev.Hostname = $nb; $nbResolved++; break }
                        }
                    }
                }
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            } catch {}
        }
        Clear-SubBar
        if (-not $Quiet) { Write-Host "  NetBIOS: resolved $nbResolved hostname(s)." -ForegroundColor Gray }
    }
    #endregion

    # Apply offline filter
    $AllResults = if ($IncludeOffline) { $Results } else { $Results | Where-Object { $_.Status -eq 'Online' } }

    #region Phase 4: Service Enumeration (HTTP titles, SNMP, SSL)
    $sslResults  = [System.Collections.Generic.List[object]]::new()
    $snmpResults = @{}

    if ($ScanPorts -and $ScanProfile -ne 'Quick') {
        $onlineDevices = @($AllResults | Where-Object { $_.Status -eq 'Online' })
        $webPorts      = @(80, 443, 8080, 8443)
        $sslPorts      = @(443, 636, 465, 993, 995, 5986, 8443)

        Update-PhaseBar 'Service Enumeration' "$($onlineDevices.Count) hosts | HTTP | SSL | SNMP"
        if (-not $Quiet) { Write-Host "[Phase 4] Service enumeration ($($onlineDevices.Count) hosts)..." -ForegroundColor Cyan }

        $devCount = 0
        foreach ($dev in $onlineDevices) {
            $devCount++
            if (-not $Quiet) {
                $tasks = @('HTTP')
                if ($EnableSSL)  { $tasks += 'SSL' }
                if ($EnableSNMP -and $dev.OpenPorts -contains 161) { $tasks += 'SNMP' }
                Write-SubProgress -Activity "Service Enumeration" `
                    -Status "$devCount/$($onlineDevices.Count) | $($dev.IPAddress) | $($tasks -join ', ')" `
                    -Pct ([int]($devCount / $onlineDevices.Count * 100))
            }

            # HTTP title grabbing
            $httpTitles = @{}
            foreach ($p in $webPorts) {
                if ($dev.OpenPorts -contains $p) {
                    $info = Get-HTTPTitleInfo -IP $dev.IPAddress -Port $p
                    if ($info.Title -or $info.Server) { $httpTitles[$p] = $info }
                }
            }
            if ($httpTitles.Count -gt 0) { $dev | Add-Member -NotePropertyName HTTPInfo -NotePropertyValue $httpTitles -Force }

            # First HTTP title becomes the display title
            $firstTitle = ($httpTitles.Values | Where-Object { $_.Title } | Select-Object -First 1)
            $dev | Add-Member -NotePropertyName HTTPTitle -NotePropertyValue ($firstTitle.Title) -Force

            # SSL cert check
            if ($EnableSSL) {
                foreach ($p in $sslPorts) {
                    if ($dev.OpenPorts -contains $p) {
                        $cert = Get-SSLCertInfo -IP $dev.IPAddress -Port $p
                        $cert['IP']   = $dev.IPAddress
                        $cert['Port'] = $p
                        $cert['Host'] = if ($dev.Hostname -ne 'N/A') { $dev.Hostname } else { $dev.IPAddress }
                        $sslResults.Add([PSCustomObject]$cert)
                    }
                }
            }

            # SNMP probing
            if ($EnableSNMP -and ($dev.OpenPorts -contains 161)) {
                foreach ($comm in $SNMPCommunities) {
                    $snmp = Invoke-SNMPGet -IP $dev.IPAddress -Community $comm
                    if ($snmp.CommunityOK) {
                        $snmpResults[$dev.IPAddress] = [PSCustomObject]@{
                            Community   = $comm
                            SysDescr    = $snmp.SysDescr
                            SysName     = $snmp.SysName
                            SysLocation = $snmp.SysLocation
                        }
                        $dev | Add-Member -NotePropertyName SNMPInfo -NotePropertyValue $snmpResults[$dev.IPAddress] -Force
                        # Refine OS from sysDescr
                        if ($snmp.SysDescr -and $dev.OS -eq 'Unknown') { $dev.OS = $snmp.SysDescr.Substring(0, [math]::Min(60, $snmp.SysDescr.Length)) }
                        break
                    }
                }
            }
        }
        Clear-SubBar
    }
    #endregion

    #region Gateway fingerprinting
    $gatewayInfo = @{}
    if ($EnableGatewayProbe -and $defaultGateway) {
        Update-PhaseBar 'Gateway Fingerprinting' $defaultGateway
        $gatewayInfo = Invoke-GatewayFingerprint -GatewayIP $defaultGateway -Communities $SNMPCommunities
        if ($gatewayInfo.Vendor -and -not $Quiet) {
            Write-Host "  Gateway: $($gatewayInfo.Vendor) $($gatewayInfo.Product) (confidence: $($gatewayInfo.Confidence))" -ForegroundColor Green
        }
    }
    #endregion

    #region Phase 5: WMI/CIM Deep Dive
    $wmiDevices = @{}
    if ($EnableWMI) {
        $windowsHosts = @($AllResults | Where-Object {
            $_.Status -eq 'Online' -and
            ($_.OpenPorts -contains 445 -or $_.OpenPorts -contains 3389 -or $_.OpenPorts -contains 5985 -or $_.OpenPorts -contains 5986)
        })
        Update-PhaseBar 'WMI / CIM Queries' "$($windowsHosts.Count) Windows host(s)"
        $wmiCount = 0
        foreach ($dev in $windowsHosts) {
            $wmiCount++
            Write-SubProgress -Activity "WMI Queries" `
                -Status "$wmiCount/$($windowsHosts.Count) | $($dev.IPAddress)" `
                -Pct ([int]($wmiCount / [math]::Max($windowsHosts.Count, 1) * 100))
            $wmiResult = Invoke-WMIHostQuery -ComputerName $dev.IPAddress -Credential $WMICredential
            $dev | Add-Member -NotePropertyName WMIData -NotePropertyValue $wmiResult -Force
            if ($wmiResult.Success) {
                $wmiDevices[$dev.IPAddress] = $wmiResult
                if ($wmiResult.ComputerName -and $dev.Hostname -eq 'N/A') { $dev.Hostname = $wmiResult.ComputerName }
                if ($wmiResult.OSName) { $dev.OS = $wmiResult.OSName }
                if (-not $Quiet) { Write-Host "  $($dev.IPAddress): $($wmiResult.OSName) | $($wmiResult.RAM_GB) GB RAM | Uptime: $($wmiResult.UptimeDays)d" -ForegroundColor Gray }
            }
        }
        Clear-SubBar
        if (-not $Quiet) { Write-Host "  WMI: $($wmiDevices.Count) successful out of $($windowsHosts.Count) attempts." -ForegroundColor Green }
    }
    #endregion

    #region Phase 6: Active Directory Enumeration
    $adInfo = @{ Available = $false }
    if ($EnableAD) {
        Update-PhaseBar 'Active Directory Enumeration'
        $adInfo = Get-ADEnvironmentInfo
        if ($adInfo.Available -and -not $Quiet) {
            Write-Host "  Domain : $($adInfo.DomainName) ($($adInfo.FunctionalLevel))" -ForegroundColor Green
            Write-Host "  DCs    : $($adInfo.DomainControllers.Count)  |  Users: $($adInfo.UserCount)  |  Computers: $($adInfo.ComputerCount)" -ForegroundColor Green
        } elseif ($adInfo.Error -and -not $Quiet) {
            Write-Host "  AD: $($adInfo.Error)" -ForegroundColor Yellow
        }
    }
    #endregion

    #region Phase 7: Security Observations
    $allSecurityFlags = [System.Collections.Generic.List[object]]::new()
    if ($EnableSecurityObs) {
        Update-PhaseBar 'Security Observations' "$(@($AllResults | Where-Object Status -eq 'Online').Count) devices"
        $allSecurityFlags = Get-SecurityObservations -Devices @($AllResults | Where-Object { $_.Status -eq 'Online' }) -SSLResults $sslResults

        # Group by severity for summary
        $critCount = @($allSecurityFlags | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
        $highCount = @($allSecurityFlags | Where-Object { $_.Severity -eq 'HIGH' }).Count
        $medCount  = @($allSecurityFlags | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
        $lowCount  = @($allSecurityFlags | Where-Object { $_.Severity -eq 'LOW' }).Count
        if (-not $Quiet) {
            Write-Host "  Findings: CRITICAL=$critCount  HIGH=$highCount  MEDIUM=$medCount  LOW=$lowCount" -ForegroundColor $(if ($critCount -gt 0) { 'Red' } elseif ($highCount -gt 0) { 'Yellow' } else { 'Green' })
        }
    }
    #endregion
}

end {
    # Dismiss all progress bars before writing summary output
    if (-not $Quiet) {
        Write-Progress -Id 1 -Completed -ErrorAction SilentlyContinue
        Write-Progress -Id 0 -Activity "YW Network Discovery" -Completed -ErrorAction SilentlyContinue
    }

    $onlineCount  = @($AllResults | Where-Object { $_.Status -eq 'Online' }).Count
    $elapsed      = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

    if (-not $Quiet) {
        $hostnameResolved = @($AllResults | Where-Object { $_.Status -eq 'Online' -and $_.Hostname -and $_.Hostname -ne 'N/A' }).Count
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host " Network Discovery Summary" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "Total IPs Scanned:    $($AllIPs.Count)"
        Write-Host "Online Devices:       " -NoNewline; Write-Host "$onlineCount" -ForegroundColor Green
        Write-Host "Hostnames Resolved:   $hostnameResolved of $onlineCount"
        Write-Host "Scan Duration:        $elapsed seconds"

        if ($EnableSecurityObs) {
            $c = @($allSecurityFlags | Where-Object Severity -eq 'CRITICAL').Count
            $h = @($allSecurityFlags | Where-Object Severity -eq 'HIGH').Count
            $m = @($allSecurityFlags | Where-Object Severity -eq 'MEDIUM').Count
            Write-Host "Security Findings:    " -NoNewline
            Write-Host "CRITICAL:$c  HIGH:$h  MEDIUM:$m" -ForegroundColor $(if ($c -gt 0) { 'Red' } elseif ($h -gt 0) { 'Yellow' } else { 'Cyan' })
        }
        if ($EnableSSL) {
            $expiring = @($sslResults | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -le 30 }).Count
            Write-Host "SSL Certs Checked:    $(@($sslResults).Count) | Expiring <=30d: $expiring"
        }
        if ($EnableAD -and $adInfo.Available) {
            Write-Host "AD Domain:            $($adInfo.DomainName) | Users: $($adInfo.UserCount) | Computers: $($adInfo.ComputerCount)"
        }

        $dtypes = $AllResults | Where-Object Status -eq 'Online' | Group-Object DeviceType | Sort-Object Count -Descending
        if ($dtypes) {
            Write-Host "`nDevice Types:"
            foreach ($t in $dtypes) { Write-Host "  $($t.Name): $($t.Count)" -ForegroundColor Gray }
        }
        Write-Host "================================================================`n" -ForegroundColor Cyan

        # Top devices console table
        $onlineDevices = @($AllResults | Where-Object { $_.Status -eq 'Online' })
        if ($onlineDevices.Count -gt 0 -and -not $ExportPath) {
            $top10 = $onlineDevices | Sort-Object { @($_.OpenPorts).Count } -Descending | Select-Object -First 10
            $hdr = "{0,-16} {1,-22} {2,-18} {3,-20} {4}" -f "IP Address","Hostname","Device Type","Vendor","Services"
            Write-Host "Top 10 Devices by Services:" -ForegroundColor Cyan
            Write-Host ("-" * 100) -ForegroundColor Gray
            Write-Host $hdr -ForegroundColor Yellow
            Write-Host ("-" * 100) -ForegroundColor Gray
            foreach ($d in $top10) {
                $color = switch ($d.DeviceType) {
                    'Server'         { 'Blue' }
                    'Workstation'    { 'Green' }
                    'Printer'        { 'Yellow' }
                    'Network Device' { 'DarkYellow' }
                    'Mobile Device'  { 'Magenta' }
                    'IoT Device'     { 'Red' }
                    'Container'      { 'Cyan' }
                    default          { 'White' }
                }
                $hn  = if ($d.Hostname.Length -gt 20) { $d.Hostname.Substring(0,17)+'...' } else { $d.Hostname }
                $dt  = if ($d.DeviceType.Length -gt 16) { $d.DeviceType.Substring(0,13)+'...' } else { $d.DeviceType }
                $vnd = if ($d.Vendor.Length -gt 18) { $d.Vendor.Substring(0,15)+'...' } else { $d.Vendor }
                $svc = if ($d.Services.Length -gt 30) { $d.Services.Substring(0,27)+'...' } else { $d.Services }
                Write-Host ("{0,-16} {1,-22} {2,-18} {3,-20} {4}" -f $d.IPAddress, $hn, $dt, $vnd, $svc) -ForegroundColor $color
            }
            Write-Host ("-" * 100) -ForegroundColor Gray
            if ($onlineDevices.Count -gt 10) { Write-Host "  ...and $($onlineDevices.Count - 10) more. Use -ExportPath for full report." -ForegroundColor Gray }
            Write-Host ""
        }
    }

    #region Export
    if ($ExportPath) {
        $ext = [System.IO.Path]::GetExtension($ExportPath).ToLower()
        try {
            switch ($ext) {
                '.csv' {
                    $AllResults | Select-Object IPAddress,Status,Hostname,DeviceType,OS,MACAddress,Vendor,Services,HTTPTitle,IsDomainController,LastSeen |
                        Export-Csv -Path $ExportPath -NoTypeInformation
                    if (-not $Quiet) { Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green }
                }
                '.json' {
                    $AllResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Encoding UTF8
                    if (-not $Quiet) { Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green }
                }
                '.html' {
                    $onlineDevices = @($AllResults | Where-Object { $_.Status -eq 'Online' })
                    $scanDate      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    $runningUser   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

                    # Severity counts
                    $critC = @($allSecurityFlags | Where-Object Severity -eq 'CRITICAL').Count
                    $highC = @($allSecurityFlags | Where-Object Severity -eq 'HIGH').Count
                    $medC  = @($allSecurityFlags | Where-Object Severity -eq 'MEDIUM').Count
                    $lowC  = @($allSecurityFlags | Where-Object Severity -eq 'LOW').Count
                    $totalIssues = $critC + $highC + $medC + $lowC

                    # SSL counts
                    $sslCount    = @($sslResults).Count
                    $sslExpCount = @($sslResults | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -le 30 }).Count

                    # Device type counts
                    $serverCount      = @($onlineDevices | Where-Object DeviceType -in @('Server')).Count
                    $workstationCount = @($onlineDevices | Where-Object DeviceType -eq 'Workstation').Count
                    $dcCount          = @($onlineDevices | Where-Object IsDomainController).Count
                    $networkCount     = @($onlineDevices | Where-Object DeviceType -eq 'Network Device').Count
                    $printerCount     = @($onlineDevices | Where-Object DeviceType -eq 'Printer').Count

                    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Discovery Report - $scanDate</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f0f2f5;color:#333;font-size:13px}
  .page{max-width:1400px;margin:0 auto;padding:20px}
  .header{background:linear-gradient(135deg,#FF6600 0%,#cc4400 60%,#1a1a2e 100%);color:#fff;padding:32px 36px;border-radius:12px;margin-bottom:24px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
  .header h1{font-size:28px;font-weight:700;letter-spacing:.5px}
  .header .sub{margin-top:8px;opacity:.85;font-size:13px}
  .header .meta{margin-top:14px;opacity:.75;font-size:11px;display:flex;gap:24px;flex-wrap:wrap}
  .header .meta span{background:rgba(255,255,255,.15);padding:3px 10px;border-radius:20px}
  h2{color:#FF6600;font-size:16px;font-weight:600;margin:28px 0 12px;padding-bottom:6px;border-bottom:2px solid #e8e8e8}
  h3{font-size:13px;font-weight:600;color:#555;margin-bottom:8px}
  .card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px;margin-bottom:24px}
  .card{background:#fff;border-radius:10px;padding:18px 14px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.07);border-top:4px solid #ddd;transition:transform .15s}
  .card:hover{transform:translateY(-3px);box-shadow:0 4px 16px rgba(0,0,0,.12)}
  .card .num{font-size:32px;font-weight:700;line-height:1}
  .card .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:#888;margin-top:6px}
  .card.orange{border-top-color:#FF6600}.card.orange .num{color:#FF6600}
  .card.blue{border-top-color:#2563eb}.card.blue .num{color:#2563eb}
  .card.green{border-top-color:#16a34a}.card.green .num{color:#16a34a}
  .card.red{border-top-color:#dc2626}.card.red .num{color:#dc2626}
  .card.purple{border-top-color:#7c3aed}.card.purple .num{color:#7c3aed}
  .card.gray{border-top-color:#6b7280}.card.gray .num{color:#6b7280}
  .card.yellow{border-top-color:#d97706}.card.yellow .num{color:#d97706}
  .panel{background:#fff;border-radius:10px;padding:20px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.07)}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{background:#f8f9fa;padding:9px 12px;text-align:left;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#666;border-bottom:2px solid #e5e7eb;white-space:nowrap}
  td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
  tr:hover td{background:#fafafa}
  tr:last-child td{border-bottom:none}
  .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600;white-space:nowrap}
  .badge-critical{background:#fef2f2;color:#dc2626;border:1px solid #fca5a5}
  .badge-high{background:#fff7ed;color:#ea580c;border:1px solid #fed7aa}
  .badge-medium{background:#fefce8;color:#ca8a04;border:1px solid #fde68a}
  .badge-low{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0}
  .badge-info{background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe}
  .badge-ok{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0}
  .badge-warn{background:#fefce8;color:#ca8a04;border:1px solid #fde68a}
  .badge-danger{background:#fef2f2;color:#dc2626;border:1px solid #fca5a5}
  .sev-block{margin-bottom:16px}
  .sev-header{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;padding:4px 10px;border-radius:6px;display:inline-block}
  .sev-critical .sev-header{background:#fef2f2;color:#dc2626}
  .sev-high .sev-header{background:#fff7ed;color:#ea580c}
  .sev-medium .sev-header{background:#fefce8;color:#ca8a04}
  .sev-low .sev-header{background:#f0fdf4;color:#16a34a}
  .flag-row{padding:5px 10px;border-left:3px solid #e5e7eb;margin:3px 0;font-size:12px;background:#fafafa;border-radius:0 4px 4px 0}
  .flag-row .flag-ip{font-size:10px;color:#888;margin-left:8px;font-family:monospace}
  .sev-critical .flag-row{border-left-color:#dc2626;background:#fef9f9}
  .sev-high .flag-row{border-left-color:#ea580c;background:#fffaf7}
  .sev-medium .flag-row{border-left-color:#ca8a04;background:#fffef5}
  .sev-low .flag-row{border-left-color:#16a34a;background:#f9fdf9}
  .dc-row{background:#eff6ff!important}
  a{color:#FF6600;text-decoration:none}a:hover{text-decoration:underline}
  .icon{margin-right:4px}
  .pubip-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}
  .pubip-item{background:#f8f9fa;border-radius:6px;padding:10px 14px}
  .pubip-item .k{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:.5px}
  .pubip-item .v{font-size:14px;font-weight:600;color:#333;margin-top:2px}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px}
  @media(max-width:700px){.two-col{grid-template-columns:1fr}}
  .footer{margin-top:40px;text-align:center;padding:20px;background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.07)}
  .footer .company{font-size:18px;font-weight:700;color:#FF6600}
  .footer .tagline{color:#888;font-size:12px;margin-top:4px;font-style:italic}
</style>
</head>
<body>
<div class="page">

<div class="header">
  <h1>&#128225; Network Discovery Report</h1>
  <div class="sub">Comprehensive Network Infrastructure Analysis</div>
  <div class="meta">
    <span>&#128197; $scanDate</span>
    <span>&#128100; $runningUser</span>
    <span>&#128268; $($AllIPs.Count) IPs scanned</span>
    <span>&#9201; ${elapsed}s</span>
    <span>&#128295; Profile: $ScanProfile</span>
  </div>
</div>

<h2>&#128200; Executive Summary</h2>
<div class="card-grid">
  <div class="card orange"><div class="num">$onlineCount</div><div class="lbl">Online Devices</div></div>
  <div class="card blue"><div class="num">$serverCount</div><div class="lbl">Servers</div></div>
  <div class="card green"><div class="num">$workstationCount</div><div class="lbl">Workstations</div></div>
  <div class="card purple"><div class="num">$networkCount</div><div class="lbl">Network Devices</div></div>
  <div class="card gray"><div class="num">$printerCount</div><div class="lbl">Printers</div></div>
  <div class="card $(if($dcCount -gt 0){'blue'}else{'gray'})"><div class="num">$dcCount</div><div class="lbl">Domain Controllers</div></div>
  <div class="card $(if($totalIssues -gt 0){'red'}else{'green'})"><div class="num">$totalIssues</div><div class="lbl">Security Findings</div></div>
  <div class="card $(if($sslExpCount -gt 0){'yellow'}else{'green'})"><div class="num">$sslExpCount</div><div class="lbl">SSL Expiring &lt;=30d</div></div>
</div>
"@

                    # Public IP section
                    if ($publicIPInfo.PublicIP) {
                        $html += @"
<h2>&#127760; Public IP / ISP Information</h2>
<div class="panel">
  <div class="pubip-grid">
    <div class="pubip-item"><div class="k">Public IP</div><div class="v">$($publicIPInfo.PublicIP)</div></div>
    <div class="pubip-item"><div class="k">ISP / ASN</div><div class="v">$($publicIPInfo.ISP)</div></div>
    <div class="pubip-item"><div class="k">Location</div><div class="v">$($publicIPInfo.City), $($publicIPInfo.Region), $($publicIPInfo.Country)</div></div>
    <div class="pubip-item"><div class="k">Reverse DNS</div><div class="v">$(if($publicIPInfo.Hostname){$publicIPInfo.Hostname}else{'(none)'})</div></div>
    <div class="pubip-item"><div class="k">Timezone</div><div class="v">$($publicIPInfo.Timezone)</div></div>
  </div>
</div>
"@
                    }

                    # Gateway section
                    if ($gatewayInfo.IP) {
                        $gwVendorStr = if ($gatewayInfo.Vendor) { "$($gatewayInfo.Vendor) $($gatewayInfo.Product)" } else { "Unknown" }
                        $gwSrc = if ($gatewayInfo.Confidence) { " <span class='badge badge-info'>$($gatewayInfo.Confidence) via $($gatewayInfo.Source)</span>" } else { "" }
                        $html += @"
<h2>&#128657; Gateway / Firewall</h2>
<div class="panel">
  <table><tr>
    <th>IP</th><th>Identified As</th><th>Confidence / Source</th><th>SNMP sysDescr</th>
  </tr><tr>
    <td><strong>$($gatewayInfo.IP)</strong></td>
    <td>$gwVendorStr</td>
    <td>$(if($gatewayInfo.Confidence){"<span class='badge badge-info'>$($gatewayInfo.Confidence) via $($gatewayInfo.Source)</span>"}else{"-"})</td>
    <td style="font-family:monospace;font-size:11px;max-width:400px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">$(if($gatewayInfo.SysDescr){[System.Web.HttpUtility]::HtmlEncode($gatewayInfo.SysDescr)}else{"-"})</td>
  </tr></table>
</div>
"@
                    }

                    # Active Directory section
                    if ($adInfo.Available) {
                        $html += "<h2>&#127970; Active Directory</h2><div class='panel'><div class='two-col'>"
                        $html += "<div><h3>Domain Information</h3><table>"
                        $html += "<tr><td><strong>DNS Name</strong></td><td>$($adInfo.DomainName)</td></tr>"
                        $html += "<tr><td><strong>NetBIOS Name</strong></td><td>$($adInfo.NetBIOSName)</td></tr>"
                        $html += "<tr><td><strong>Functional Level</strong></td><td>$($adInfo.FunctionalLevel)</td></tr>"
                        $html += "<tr><td><strong>PDC Emulator</strong></td><td>$($adInfo.PDCEmulator)</td></tr>"
                        $html += "<tr><td><strong>Total Users</strong></td><td>$($adInfo.UserCount)</td></tr>"
                        $html += "<tr><td><strong>Total Computers</strong></td><td>$($adInfo.ComputerCount)</td></tr>"
                        $html += "<tr><td><strong>OUs</strong></td><td>$($adInfo.OUCount)</td></tr>"
                        if ($adInfo.PasswordPolicy.MinLength -ne $null) {
                            $html += "<tr><td><strong>Pwd Min Length</strong></td><td>$($adInfo.PasswordPolicy.MinLength)</td></tr>"
                            $html += "<tr><td><strong>Pwd Complexity</strong></td><td>$(if($adInfo.PasswordPolicy.ComplexityEnabled){'Enabled'}else{'<span style=color:red>Disabled</span>'})</td></tr>"
                            $html += "<tr><td><strong>Max Pwd Age</strong></td><td>$($adInfo.PasswordPolicy.MaxAgeDays) days</td></tr>"
                            $html += "<tr><td><strong>Lockout Threshold</strong></td><td>$(if($adInfo.PasswordPolicy.LockoutThreshold -eq 0){'<span style=color:red>No lockout</span>'}else{$adInfo.PasswordPolicy.LockoutThreshold})</td></tr>"
                        }
                        $html += "</table></div>"

                        $html += "<div><h3>Domain Controllers</h3><table><tr><th>Name</th><th>IP</th><th>Site</th><th>OS</th><th>GC</th></tr>"
                        foreach ($dc in $adInfo.DomainControllers) {
                            $html += "<tr><td><strong>$($dc.Name)</strong></td><td>$($dc.IPAddress)</td><td>$($dc.Site)</td><td>$($dc.OS)</td><td>$(if($dc.IsGC){'&#10003;'}else{'-'})</td></tr>"
                        }
                        $html += "</table>"

                        if ($adInfo.OSVersions.Count -gt 0) {
                            $html += "<h3 style='margin-top:14px'>Computer OS Distribution</h3><table><tr><th>Operating System</th><th>Count</th></tr>"
                            foreach ($osKey in ($adInfo.OSVersions.Keys | Sort-Object)) {
                                $html += "<tr><td>$osKey</td><td>$($adInfo.OSVersions[$osKey])</td></tr>"
                            }
                            $html += "</table>"
                        }

                        if ($adInfo.DomainAdmins.Count -gt 0) {
                            $html += "<h3 style='margin-top:14px'>Domain Admins ($($adInfo.DomainAdmins.Count))</h3>"
                            $html += "<div style='font-family:monospace;font-size:11px;background:#f8f9fa;padding:8px;border-radius:4px;line-height:1.8'>"
                            $html += ($adInfo.DomainAdmins -join "<br>")
                            $html += "</div>"
                        }
                        $html += "</div></div></div>"
                    }

                    # Security Observations section
                    if ($EnableSecurityObs -and $allSecurityFlags.Count -gt 0) {
                        $html += "<h2>&#9888; Security Observations</h2><div class='panel'>"
                        foreach ($sev in @('CRITICAL','HIGH','MEDIUM','LOW')) {
                            $sevFlags = @($allSecurityFlags | Where-Object { $_.Severity -eq $sev })
                            if ($sevFlags.Count -eq 0) { continue }
                            $sevClass = $sev.ToLower()
                            $html += "<div class='sev-block sev-$sevClass'>"
                            $html += "<div class='sev-header'>$sev ($($sevFlags.Count))</div>"
                            # Group by flag text
                            $grouped = $sevFlags | Group-Object Flag
                            foreach ($g in $grouped) {
                                $ips = ($g.Group.IP | Select-Object -Unique) -join ', '
                                $html += "<div class='flag-row'>$($g.Name) <span class='flag-ip'>[$ips]</span></div>"
                            }
                            $html += "</div>"
                        }
                        $html += "</div>"
                    } elseif ($EnableSecurityObs) {
                        $html += "<h2>&#9888; Security Observations</h2><div class='panel' style='color:#16a34a;font-weight:600'>&#10003; No security issues detected.</div>"
                    }

                    # SSL Certificate Health section
                    if ($EnableSSL -and $sslResults.Count -gt 0) {
                        $html += "<h2>&#128274; SSL/TLS Certificate Health</h2><div class='panel'>"
                        $html += "<table><tr><th>Host</th><th>IP</th><th>Port</th><th>Common Name</th><th>Issuer</th><th>Expires</th><th>Days Left</th><th>Status</th></tr>"
                        foreach ($cert in ($sslResults | Sort-Object { $_.DaysRemaining })) {
                            if ($cert.Error -and -not $cert.CommonName) { continue }
                            $expStr  = if ($cert.ExpiryDate)    { $cert.ExpiryDate.ToString('yyyy-MM-dd') } else { 'N/A' }
                            $daysStr = if ($cert.DaysRemaining -ne $null) { $cert.DaysRemaining } else { 'N/A' }
                            $badge   = if ($cert.DaysRemaining -eq $null) { '' }
                                       elseif ($cert.DaysRemaining -lt 0)  { "<span class='badge badge-danger'>EXPIRED</span>" }
                                       elseif ($cert.DaysRemaining -le 7)  { "<span class='badge badge-danger'>CRITICAL</span>" }
                                       elseif ($cert.DaysRemaining -le 30) { "<span class='badge badge-warn'>EXPIRING</span>" }
                                       else                                { "<span class='badge badge-ok'>OK</span>" }
                            $html += "<tr><td>$($cert.Host)</td><td>$($cert.IP)</td><td>$($cert.Port)</td><td>$($cert.CommonName)</td><td>$($cert.Issuer)</td><td>$expStr</td><td>$daysStr</td><td>$badge</td></tr>"
                        }
                        $html += "</table></div>"
                    }

                    # WMI Insights section
                    if ($EnableWMI -and $wmiDevices.Count -gt 0) {
                        $html += "<h2>&#128187; WMI Host Insights</h2><div class='panel'>"
                        $html += "<table><tr><th>Host</th><th>IP</th><th>OS</th><th>RAM</th><th>Uptime</th><th>Serial</th><th>Disk Status</th><th>Key Services</th></tr>"
                        foreach ($dev in ($AllResults | Where-Object { $_.WMIData -and $_.WMIData.Success })) {
                            $w = $dev.WMIData
                            $diskStr = ($w.Disks | ForEach-Object {
                                $col = if ($_.Free_Pct -lt 10) { 'style=color:red' } elseif ($_.Free_Pct -lt 20) { 'style=color:orange' } else { '' }
                                "<span $col>$($_.Drive) $($_.Free_GB)GB/$($_.Size_GB)GB ($($_.Free_Pct)%)</span>"
                            }) -join ' '
                            $svcStr = ($w.KeyServices | Where-Object { $_.State -eq 'Running' } | ForEach-Object { $_.Name }) -join ', '
                            $uptimeBadge = if ($w.UptimeDays -gt 90) { "<span class='badge badge-warn'>$($w.UptimeDays)d</span>" } else { "$($w.UptimeDays)d" }
                            $html += "<tr><td><strong>$(if($dev.Hostname -ne 'N/A'){$dev.Hostname}else{$dev.IPAddress})</strong></td><td>$($dev.IPAddress)</td><td>$($w.OSName)</td><td>$($w.RAM_GB) GB</td><td>$uptimeBadge</td><td style='font-size:10px;font-family:monospace'>$($w.SerialNumber)</td><td style='font-size:11px'>$diskStr</td><td style='font-size:10px'>$svcStr</td></tr>"
                        }
                        $html += "</table></div>"
                    }

                    # Device Inventory table
                    $html += "<h2>&#128203; Device Inventory</h2><div class='panel'>"
                    $html += "<table><tr><th>IP Address</th><th>Hostname</th><th>Type</th><th>OS</th><th>MAC / Vendor</th><th>HTTP Title</th><th>Services</th><th>Flags</th></tr>"

                    foreach ($dev in ($onlineDevices | Sort-Object {
                        $o = $_.IPAddress.Split('.')
                        [int]$o[0]*16777216 + [int]$o[1]*65536 + [int]$o[2]*256 + [int]$o[3]
                    })) {
                        $rowStyle = ''
                        $devFlags = @($dev.SecurityFlags)
                        if (@($devFlags | Where-Object Severity -eq 'CRITICAL').Count -gt 0) { $rowStyle = 'background:#fef9f9' }
                        elseif (@($devFlags | Where-Object Severity -eq 'HIGH').Count -gt 0) { $rowStyle = 'background:#fffaf5' }

                        $icon = switch ($dev.DeviceType) {
                            'Server'         { '&#9632;' }
                            'Workstation'    { '&#9675;' }
                            'Printer'        { '&#9643;' }
                            'Network Device' { '&#9654;' }
                            'Mobile Device'  { '&#9670;' }
                            'IoT Device'     { '&#9670;' }
                            'Container'      { '&#9663;' }
                            default          { '&#9661;' }
                        }
                        $dcBadge = if ($dev.IsDomainController) { " <span class='badge badge-info'>DC</span>" } else { '' }

                        $macStr = if ($dev.MACAddress -ne 'N/A') { "$($dev.MACAddress)<br><span style='font-size:10px;color:#888'>$($dev.Vendor)</span>" } else { "<span style='color:#aaa'>N/A</span>" }

                        # Service links
                        $svcLinks = @()
                        foreach ($svc in ($dev.Services -split ', ')) {
                            $link = switch -Regex ($svc) {
                                '^HTTP$'     { "<a href='http://$($dev.IPAddress)' target='_blank'>HTTP</a>" }
                                '^HTTPS$'    { "<a href='https://$($dev.IPAddress)' target='_blank'>HTTPS</a>" }
                                '^HTTP-Alt$' { "<a href='http://$($dev.IPAddress):8080' target='_blank'>HTTP-Alt</a>" }
                                'HTTPS-Alt'  { "<a href='https://$($dev.IPAddress):8443' target='_blank'>HTTPS-Alt</a>" }
                                default      { $svc }
                            }
                            $svcLinks += $link
                        }
                        $svcStr = $svcLinks -join ', '

                        $flagStr = ''
                        if ($devFlags.Count -gt 0) {
                            $maxSev = if (@($devFlags | Where-Object Severity -eq 'CRITICAL').Count -gt 0) { 'CRITICAL' }
                                      elseif (@($devFlags | Where-Object Severity -eq 'HIGH').Count -gt 0) { 'HIGH' }
                                      elseif (@($devFlags | Where-Object Severity -eq 'MEDIUM').Count -gt 0) { 'MEDIUM' }
                                      else { 'LOW' }
                            $sevClass = switch ($maxSev) { 'CRITICAL'{'badge-critical'}'HIGH'{'badge-high'}'MEDIUM'{'badge-medium'}default{'badge-low'}}
                            $flagStr = "<span class='badge $sevClass'>$($devFlags.Count) issue$(if($devFlags.Count -ne 1){'s'})</span>"
                        }

                        $html += "<tr style='$rowStyle'><td><strong>$($dev.IPAddress)</strong></td>"
                        $html += "<td>$($dev.Hostname)$dcBadge</td>"
                        $html += "<td>$icon $($dev.DeviceType)</td>"
                        $html += "<td>$($dev.OS)</td>"
                        $html += "<td style='font-size:11px'>$macStr</td>"
                        $html += "<td style='font-size:11px;color:#555'>$(if($dev.HTTPTitle){$dev.HTTPTitle}else{'-'})</td>"
                        $html += "<td style='font-size:11px'>$svcStr</td>"
                        $html += "<td>$flagStr</td></tr>"
                    }
                    $html += "</table></div>"

                    $html += @"
<div class="footer">
  <div class="company">Yeyland Wutani LLC</div>
  <div class="tagline">Building Better Systems</div>
  <div style="font-size:10px;color:#bbb;margin-top:6px">Network Discovery Report v$ScriptVersion &bull; Generated $scanDate</div>
</div>

</div>
</body>
</html>
"@
                    $html | Out-File -FilePath $ExportPath -Encoding UTF8
                    if (-not $Quiet) { Write-Host "Results exported to HTML: $ExportPath" -ForegroundColor Green }
                }
                default {
                    Write-Warning "Unsupported export format: $ext (use .csv, .json, or .html)"
                }
            }
        } catch {
            Write-Error "Failed to export results: $_"
        }
    }
    #endregion

    if (-not $Quiet) { Write-Host "Network discovery complete.`n" -ForegroundColor Cyan }

    # Return results to pipeline
    return $AllResults
}
