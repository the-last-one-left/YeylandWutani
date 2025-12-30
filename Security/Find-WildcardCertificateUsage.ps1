<#
.SYNOPSIS
    Comprehensive Wildcard Certificate Usage Discovery Tool v1.1
    
.DESCRIPTION
    MSP-focused tool for discovering everywhere a wildcard (or any) SSL certificate is used
    across Windows servers. Essential for certificate renewals and compliance auditing.
    
    Discovery Methods:
    - Certificate Store Enumeration: Scans LocalMachine\My store on remote servers
    - IIS Bindings: Identifies which websites use the certificate
    - RDP Configuration: Checks Remote Desktop certificate assignments
    - SSL Port Probing: Directly connects to common SSL ports to identify certificates
    - Service Bindings: Checks HTTP.SYS SSL bindings
    
    Supports searching by:
    - Certificate Thumbprint (exact match across all servers)
    - Subject Pattern (e.g., *.contoso.com)
    - Friendly Name
    
    Supports target specification:
    - Individual hostnames or IPs
    - CIDR notation (e.g., 192.168.1.0/24)
    - IP ranges (e.g., 192.168.1.1-50)
    - Automatic AD discovery
    
.PARAMETER Thumbprint
    The certificate thumbprint to search for. This is the most reliable method as
    the same wildcard certificate will have identical thumbprints everywhere.
    
.PARAMETER SubjectPattern
    Subject pattern to match (supports wildcards). Example: "*.contoso.com"
    
.PARAMETER FriendlyName
    Certificate friendly name to search for (partial match supported).
    
.PARAMETER ComputerName
    Array of computer names, IPs, CIDR ranges, or IP ranges to scan.
    Supports: hostnames, IPs, CIDR (192.168.1.0/24), ranges (192.168.1.1-50)
    If not specified, queries AD for Windows Servers.
    
.PARAMETER OUSearchBase
    Limit AD computer query to specific OU. Example: "OU=Servers,DC=contoso,DC=com"
    
.PARAMETER IncludeClients
    Include Windows client computers in the scan (normally only servers are scanned).
    
.PARAMETER ScanPorts
    Array of ports to probe for SSL certificates. Default: 443, 3389, 636, 8443, 8080
    
.PARAMETER SkipPortScan
    Skip the SSL port probing phase (faster, but may miss some certificate usage).
    
.PARAMETER SkipRemoting
    Only use SSL port probing (when PowerShell remoting is not available).
    
.PARAMETER OutputPath
    Directory path for output files. Defaults to current directory.
    
.PARAMETER Credential
    PSCredential for remote access. Uses current user context if not specified.
    
.PARAMETER TimeoutSeconds
    Connection timeout for port probing. Default: 5 seconds.
    
.PARAMETER ThrottleLimit
    Maximum concurrent remote connections. Default: 32.

.EXAMPLE
    .\Find-WildcardCertificateUsage.ps1 -Thumbprint "A1B2C3D4E5F6..."
    Find all servers using a certificate with the specified thumbprint
    
.EXAMPLE
    .\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*.contoso.com" -ComputerName "192.168.1.0/24"
    Scan entire /24 subnet for certificates matching the subject pattern

.EXAMPLE
    .\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*.contoso.com" -ComputerName "10.0.0.1-20"
    Scan IP range 10.0.0.1 through 10.0.0.20

.EXAMPLE
    .\Find-WildcardCertificateUsage.ps1 -Thumbprint "A1B2C3D4..." -ComputerName (Get-Content servers.txt)
    Search specific servers from a list
    
.EXAMPLE
    .\Find-WildcardCertificateUsage.ps1 -SubjectPattern "*wildcard*" -SkipRemoting -ScanPorts 443,8443
    Port-only scan when remoting is unavailable

.NOTES
    Author: Yeyland Wutani LLC
    Version: 1.1
    Website: https://github.com/YeylandWutani
    
    Requirements:
    - PowerShell 5.1 or later
    - Admin rights for certificate store access
    - PowerShell Remoting enabled on target servers (for full discovery)
    - Active Directory PowerShell module (for automatic server discovery)
    
    The same wildcard certificate will have the same thumbprint across all servers,
    making thumbprint-based searching the most reliable method.
#>

[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(ParameterSetName = 'Thumbprint', Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$Thumbprint,
    
    [Parameter(ParameterSetName = 'Subject', Mandatory = $true)]
    [string]$SubjectPattern,
    
    [Parameter(ParameterSetName = 'FriendlyName', Mandatory = $true)]
    [string]$FriendlyName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory = $false)]
    [string]$OUSearchBase,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeClients,
    
    [Parameter(Mandatory = $false)]
    [int[]]$ScanPorts = @(443, 3389, 636, 8443, 8080),
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPortScan,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipRemoting,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$TimeoutSeconds = 5,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 32
)

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Continue'
$Script:StartTime = Get-Date
$Script:Version = "1.1"

# Branding colors (HTML)
$Script:BrandOrange = "#FF6600"
$Script:BrandGrey = "#6B7280"
$Script:BrandDarkGrey = "#374151"
$Script:BrandLightGrey = "#F3F4F6"

# Console colors (for Write-Host)
$Script:ConsoleAccent = "DarkYellow"
$Script:ConsoleHighlight = "White"
$Script:ConsoleMuted = "Gray"

# Results collections
$Script:CertificateInstances = [System.Collections.ArrayList]::new()
$Script:IISBindings = [System.Collections.ArrayList]::new()
$Script:RDPCertificates = [System.Collections.ArrayList]::new()
$Script:HTTPSysBindings = [System.Collections.ArrayList]::new()
$Script:PortScanResults = [System.Collections.ArrayList]::new()
$Script:ScanErrors = [System.Collections.ArrayList]::new()
$Script:ScannedComputers = [System.Collections.ArrayList]::new()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $prefix = switch ($Type) {
        'Info'    { "[*]" }
        'Success' { "[+]" }
        'Warning' { "[!]" }
        'Error'   { "[-]" }
    }
    
    $color = switch ($Type) {
        'Info'    { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Expand-CIDRNotation {
    param([string]$CIDR)
    
    # Check if it's CIDR notation
    if ($CIDR -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') {
        return $null  # Not CIDR
    }
    
    $ipAddress = $matches[1]
    $prefixLength = [int]$matches[2]
    
    if ($prefixLength -lt 16 -or $prefixLength -gt 30) {
        Write-StatusMessage "CIDR prefix /$prefixLength not supported (use /16 to /30)" -Type Warning
        return @()
    }
    
    try {
        $ipBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
        
        $hostBits = 32 - $prefixLength
        $numHosts = [Math]::Pow(2, $hostBits) - 2  # Exclude network and broadcast
        
        if ($numHosts -gt 65534) {
            Write-StatusMessage "Subnet too large (max /16 = 65534 hosts)" -Type Warning
            return @()
        }
        
        $mask = [uint32]([Math]::Pow(2, 32) - 1) -shl $hostBits
        $networkInt = $ipInt -band $mask
        
        $ips = [System.Collections.ArrayList]::new()
        
        Write-StatusMessage "Expanding CIDR $CIDR to $([int]$numHosts) addresses..."
        
        # Start from network + 1, end before broadcast
        for ($i = 1; $i -le $numHosts; $i++) {
            $currentInt = $networkInt + $i
            $bytes = [BitConverter]::GetBytes([uint32]$currentInt)
            [Array]::Reverse($bytes)
            $ip = [System.Net.IPAddress]::new($bytes)
            [void]$ips.Add($ip.ToString())
        }
        
        return $ips.ToArray()
    }
    catch {
        Write-StatusMessage "Failed to parse CIDR: $($_.Exception.Message)" -Type Error
        return @()
    }
}

function Expand-IPRange {
    param([string]$Range)
    
    # Check for range notation: 192.168.1.1-50
    if ($Range -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$') {
        $baseOctets = $matches[1]
        $startLast = [int]$matches[2]
        $endLast = [int]$matches[3]
        
        if ($startLast -gt $endLast -or $endLast -gt 254 -or $startLast -lt 1) {
            Write-StatusMessage "Invalid IP range: $Range" -Type Warning
            return @()
        }
        
        $count = $endLast - $startLast + 1
        Write-StatusMessage "Expanding range $Range to $count addresses..."
        
        $ips = @()
        for ($i = $startLast; $i -le $endLast; $i++) {
            $ips += "$baseOctets.$i"
        }
        return $ips
    }
    
    return $null  # Not a range
}

function Get-TargetComputers {
    param(
        [string[]]$ComputerName,
        [string]$OUSearchBase,
        [switch]$IncludeClients
    )
    
    if ($ComputerName) {
        # Expand any CIDR notation or IP ranges
        $expandedList = [System.Collections.ArrayList]::new()
        
        foreach ($entry in $ComputerName) {
            # Try CIDR expansion
            $cidrResult = Expand-CIDRNotation -CIDR $entry
            if ($cidrResult -ne $null) {
                foreach ($ip in $cidrResult) {
                    [void]$expandedList.Add($ip)
                }
                continue
            }
            
            # Try IP range expansion
            $rangeResult = Expand-IPRange -Range $entry
            if ($rangeResult -ne $null) {
                foreach ($ip in $rangeResult) {
                    [void]$expandedList.Add($ip)
                }
                continue
            }
            
            # Not CIDR or range, add as-is
            [void]$expandedList.Add($entry)
        }
        
        Write-StatusMessage "Target list: $($expandedList.Count) addresses"
        return $expandedList.ToArray()
    }
    
    Write-StatusMessage "Querying Active Directory for Windows computers..."
    
    try {
        $adParams = @{}
        
        if ($IncludeClients) {
            $adParams['LDAPFilter'] = "(operatingSystem=*Windows*)"
        } else {
            $adParams['LDAPFilter'] = "(operatingSystem=*Windows Server*)"
        }
        
        if ($OUSearchBase) {
            $adParams['SearchBase'] = $OUSearchBase
        }
        
        $computers = Get-ADComputer @adParams -Properties OperatingSystem, DNSHostName |
            Where-Object { $_.Enabled -eq $true } |
            Select-Object -ExpandProperty DNSHostName
        
        Write-StatusMessage "Found $($computers.Count) computers in Active Directory" -Type Success
        return $computers
    }
    catch {
        Write-StatusMessage "Failed to query AD: $($_.Exception.Message)" -Type Error
        Write-StatusMessage "Provide computers via -ComputerName parameter" -Type Warning
        return @()
    }
}

function Test-ComputerReachable {
    param([string]$ComputerName)
    
    try {
        $result = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $result
    }
    catch {
        return $false
    }
}

function Get-SSLCertificateFromPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$Timeout = 5000
    )
    
    $result = @{
        ComputerName = $ComputerName
        Port = $Port
        Success = $false
        Certificate = $null
        Error = $null
    }
    
    $tcpClient = $null
    $sslStream = $null
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        $waitHandle = $connectResult.AsyncWaitHandle
        
        if (-not $waitHandle.WaitOne($Timeout, $false)) {
            $tcpClient.Close()
            $result.Error = "Connection timeout"
            return $result
        }
        
        $tcpClient.EndConnect($connectResult)
        
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            { param($sender, $certificate, $chain, $sslPolicyErrors) return $true }
        )
        
        $sslStream.AuthenticateAsClient($ComputerName)
        
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
        
        $result.Success = $true
        $result.Certificate = @{
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            FriendlyName = $cert.FriendlyName
            DnsNameList = ($cert.DnsNameList | ForEach-Object { $_.Unicode }) -join ', '
            SerialNumber = $cert.SerialNumber
        }
        
        $sslStream.Close()
        $tcpClient.Close()
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($sslStream) { try { $sslStream.Dispose() } catch {} }
        if ($tcpClient) { try { $tcpClient.Dispose() } catch {} }
    }
    
    return $result
}

# ============================================================================
# DISCOVERY FUNCTIONS
# ============================================================================

function Invoke-CertificateStoreDiscovery {
    param(
        [string[]]$Computers,
        [string]$Thumbprint,
        [string]$SubjectPattern,
        [string]$FriendlyName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$ThrottleLimit
    )
    
    Write-StatusMessage "Scanning certificate stores on $($Computers.Count) computers..."
    
    $scriptBlock = {
        param($Thumbprint, $SubjectPattern, $FriendlyName)
        
        $results = @{
            ComputerName = $env:COMPUTERNAME
            Certificates = @()
            IISBindings = @()
            RDPCertificate = $null
            HTTPSysBindings = @()
            Error = $null
        }
        
        try {
            # Get certificates from Personal store
            $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
            
            foreach ($cert in $certs) {
                $match = $false
                
                if ($Thumbprint -and $cert.Thumbprint -eq $Thumbprint) {
                    $match = $true
                }
                elseif ($SubjectPattern -and $cert.Subject -like "*$SubjectPattern*") {
                    $match = $true
                }
                elseif ($FriendlyName -and $cert.FriendlyName -like "*$FriendlyName*") {
                    $match = $true
                }
                
                if ($match) {
                    $dnsNames = @()
                    try {
                        $dnsNames = $cert.DnsNameList | ForEach-Object { $_.Unicode }
                    } catch {}
                    
                    $results.Certificates += @{
                        Thumbprint = $cert.Thumbprint
                        Subject = $cert.Subject
                        Issuer = $cert.Issuer
                        FriendlyName = $cert.FriendlyName
                        NotBefore = $cert.NotBefore
                        NotAfter = $cert.NotAfter
                        DnsNameList = $dnsNames -join ', '
                        HasPrivateKey = $cert.HasPrivateKey
                        SerialNumber = $cert.SerialNumber
                    }
                }
            }
            
            # Check IIS bindings if WebAdministration is available
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
                
                foreach ($site in $sites) {
                    foreach ($binding in $site.Bindings.Collection) {
                        if ($binding.protocol -eq 'https') {
                            $certHash = $binding.certificateHash
                            if ($certHash) {
                                $matchBinding = $false
                                if ($Thumbprint -and $certHash -eq $Thumbprint) {
                                    $matchBinding = $true
                                }
                                elseif ($SubjectPattern -or $FriendlyName) {
                                    $boundCert = Get-ChildItem -Path "Cert:\LocalMachine\$($binding.certificateStoreName)\$certHash" -ErrorAction SilentlyContinue
                                    if ($boundCert) {
                                        if ($SubjectPattern -and $boundCert.Subject -like "*$SubjectPattern*") {
                                            $matchBinding = $true
                                        }
                                        elseif ($FriendlyName -and $boundCert.FriendlyName -like "*$FriendlyName*") {
                                            $matchBinding = $true
                                        }
                                    }
                                }
                                
                                if ($matchBinding) {
                                    $results.IISBindings += @{
                                        SiteName = $site.Name
                                        SiteID = $site.ID
                                        BindingInfo = $binding.bindingInformation
                                        CertificateHash = $certHash
                                        CertificateStore = $binding.certificateStoreName
                                        SslFlags = $binding.sslFlags
                                    }
                                }
                            }
                        }
                    }
                }
            } catch { }
            
            # Check RDP certificate
            try {
                $rdpSetting = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace "root\cimv2\terminalservices" -Filter "TerminalName='RDP-tcp'" -ErrorAction SilentlyContinue
                if ($rdpSetting -and $rdpSetting.SSLCertificateSHA1Hash) {
                    $rdpThumbprint = $rdpSetting.SSLCertificateSHA1Hash
                    $matchRDP = $false
                    
                    if ($Thumbprint -and $rdpThumbprint -eq $Thumbprint) {
                        $matchRDP = $true
                    }
                    elseif ($SubjectPattern -or $FriendlyName) {
                        $rdpCert = Get-ChildItem -Path "Cert:\LocalMachine\My\$rdpThumbprint" -ErrorAction SilentlyContinue
                        if ($rdpCert) {
                            if ($SubjectPattern -and $rdpCert.Subject -like "*$SubjectPattern*") {
                                $matchRDP = $true
                            }
                            elseif ($FriendlyName -and $rdpCert.FriendlyName -like "*$FriendlyName*") {
                                $matchRDP = $true
                            }
                        }
                    }
                    
                    if ($matchRDP) {
                        $results.RDPCertificate = @{
                            Thumbprint = $rdpThumbprint
                            TerminalName = $rdpSetting.TerminalName
                        }
                    }
                }
            } catch { }
            
            # Check HTTP.SYS SSL bindings
            try {
                $netshOutput = netsh http show sslcert 2>&1
                $currentBinding = @{}
                
                foreach ($line in $netshOutput) {
                    if ($line -match "^\s*IP:port\s*:\s*(.+)$") {
                        if ($currentBinding.Count -gt 0) {
                            $results.HTTPSysBindings += $currentBinding
                        }
                        $currentBinding = @{ IPPort = $matches[1].Trim() }
                    }
                    elseif ($line -match "^\s*Hostname:port\s*:\s*(.+)$") {
                        if ($currentBinding.Count -gt 0) {
                            $results.HTTPSysBindings += $currentBinding
                        }
                        $currentBinding = @{ HostnamePort = $matches[1].Trim() }
                    }
                    elseif ($line -match "^\s*Certificate Hash\s*:\s*(.+)$") {
                        $hash = $matches[1].Trim()
                        $currentBinding['CertificateHash'] = $hash
                        
                        $matchHTTPSys = $false
                        if ($Thumbprint -and $hash -eq $Thumbprint) {
                            $matchHTTPSys = $true
                        }
                        elseif ($SubjectPattern -or $FriendlyName) {
                            $httpCert = Get-ChildItem -Path "Cert:\LocalMachine\My\$hash" -ErrorAction SilentlyContinue
                            if ($httpCert) {
                                if ($SubjectPattern -and $httpCert.Subject -like "*$SubjectPattern*") {
                                    $matchHTTPSys = $true
                                }
                                elseif ($FriendlyName -and $httpCert.FriendlyName -like "*$FriendlyName*") {
                                    $matchHTTPSys = $true
                                }
                            }
                        }
                        $currentBinding['Match'] = $matchHTTPSys
                    }
                    elseif ($line -match "^\s*Application ID\s*:\s*(.+)$") {
                        $currentBinding['ApplicationID'] = $matches[1].Trim()
                    }
                }
                
                if ($currentBinding.Count -gt 0) {
                    $results.HTTPSysBindings += $currentBinding
                }
                
                $results.HTTPSysBindings = $results.HTTPSysBindings | Where-Object { $_.Match -eq $true }
            } catch { }
            
        }
        catch {
            $results.Error = $_.Exception.Message
        }
        
        return $results
    }
    
    $invokeParams = @{
        ComputerName = $Computers
        ScriptBlock = $scriptBlock
        ArgumentList = @($Thumbprint, $SubjectPattern, $FriendlyName)
        ErrorAction = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    
    if ($Credential) {
        $invokeParams['Credential'] = $Credential
    }
    
    $remoteResults = Invoke-Command @invokeParams
    
    foreach ($result in $remoteResults) {
        [void]$Script:ScannedComputers.Add($result.ComputerName)
        
        foreach ($cert in $result.Certificates) {
            [void]$Script:CertificateInstances.Add([PSCustomObject]@{
                ComputerName = $result.ComputerName
                Thumbprint = $cert.Thumbprint
                Subject = $cert.Subject
                Issuer = $cert.Issuer
                FriendlyName = $cert.FriendlyName
                NotBefore = $cert.NotBefore
                NotAfter = $cert.NotAfter
                DnsNameList = $cert.DnsNameList
                HasPrivateKey = $cert.HasPrivateKey
                SerialNumber = $cert.SerialNumber
            })
        }
        
        foreach ($binding in $result.IISBindings) {
            [void]$Script:IISBindings.Add([PSCustomObject]@{
                ComputerName = $result.ComputerName
                SiteName = $binding.SiteName
                SiteID = $binding.SiteID
                BindingInfo = $binding.BindingInfo
                CertificateHash = $binding.CertificateHash
                CertificateStore = $binding.CertificateStore
                SslFlags = $binding.SslFlags
            })
        }
        
        if ($result.RDPCertificate) {
            [void]$Script:RDPCertificates.Add([PSCustomObject]@{
                ComputerName = $result.ComputerName
                Thumbprint = $result.RDPCertificate.Thumbprint
                TerminalName = $result.RDPCertificate.TerminalName
            })
        }
        
        foreach ($httpBinding in $result.HTTPSysBindings) {
            [void]$Script:HTTPSysBindings.Add([PSCustomObject]@{
                ComputerName = $result.ComputerName
                Endpoint = if ($httpBinding.IPPort) { $httpBinding.IPPort } else { $httpBinding.HostnamePort }
                CertificateHash = $httpBinding.CertificateHash
                ApplicationID = $httpBinding.ApplicationID
            })
        }
        
        if ($result.Error) {
            [void]$Script:ScanErrors.Add([PSCustomObject]@{
                ComputerName = $result.ComputerName
                Phase = "Remote Discovery"
                Error = $result.Error
            })
        }
    }
    
    # Handle connection errors
    if ($remoteErrors) {
        foreach ($err in $remoteErrors) {
            if ($err.TargetObject) {
                [void]$Script:ScanErrors.Add([PSCustomObject]@{
                    ComputerName = $err.TargetObject
                    Phase = "Remote Connection"
                    Error = $err.Exception.Message
                })
            }
        }
    }
}

function Invoke-SSLPortScanning {
    param(
        [string[]]$Computers,
        [int[]]$Ports,
        [string]$Thumbprint,
        [string]$SubjectPattern,
        [string]$FriendlyName,
        [int]$Timeout
    )
    
    $totalScans = $Computers.Count * $Ports.Count
    Write-StatusMessage "Probing $totalScans SSL endpoints ($($Computers.Count) hosts x $($Ports.Count) ports)..."
    
    $scanCounter = 0
    
    foreach ($computer in $Computers) {
        foreach ($port in $Ports) {
            $scanCounter++
            $pct = [math]::Round(($scanCounter / $totalScans) * 100, 0)
            Write-Progress -Activity "SSL Port Scanning" -Status "$computer`:$port ($scanCounter of $totalScans)" -PercentComplete $pct
            
            $scanResult = Get-SSLCertificateFromPort -ComputerName $computer -Port $port -Timeout ($Timeout * 1000)
            
            if ($scanResult.Success -and $scanResult.Certificate) {
                $cert = $scanResult.Certificate
                $match = $false
                
                if ($Thumbprint -and $cert.Thumbprint -eq $Thumbprint) {
                    $match = $true
                }
                elseif ($SubjectPattern -and $cert.Subject -like "*$SubjectPattern*") {
                    $match = $true
                }
                elseif ($FriendlyName -and $cert.FriendlyName -like "*$FriendlyName*") {
                    $match = $true
                }
                
                if ($match) {
                    [void]$Script:PortScanResults.Add([PSCustomObject]@{
                        ComputerName = $computer
                        Port = $port
                        Thumbprint = $cert.Thumbprint
                        Subject = $cert.Subject
                        Issuer = $cert.Issuer
                        NotAfter = $cert.NotAfter
                        DnsNameList = $cert.DnsNameList
                    })
                }
            }
        }
    }
    
    Write-Progress -Activity "SSL Port Scanning" -Completed
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

function New-HTMLReport {
    param([string]$OutputPath)
    
    $searchCriteria = if ($Thumbprint) { "Thumbprint: $Thumbprint" }
                      elseif ($SubjectPattern) { "Subject Pattern: $SubjectPattern" }
                      else { "Friendly Name: $FriendlyName" }
    
    $totalFound = $Script:CertificateInstances.Count + $Script:PortScanResults.Count
    $iisCount = $Script:IISBindings.Count
    $rdpCount = $Script:RDPCertificates.Count
    $httpSysCount = $Script:HTTPSysBindings.Count
    $errorCount = $Script:ScanErrors.Count
    
    $duration = (Get-Date) - $Script:StartTime
    $durationStr = "{0:mm}m {0:ss}s" -f $duration
    
    $html = New-Object System.Text.StringBuilder
    
    [void]$html.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wildcard Certificate Usage Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .header { background: linear-gradient(135deg, $($Script:BrandOrange) 0%, #cc5200 100%); color: white; padding: 30px 40px; }
        .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 5px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .summary-card .value { font-size: 36px; font-weight: 700; color: $($Script:BrandOrange); }
        .summary-card .label { font-size: 14px; color: $($Script:BrandGrey); margin-top: 5px; }
        .section { background: white; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .section-header { background: $($Script:BrandDarkGrey); color: white; padding: 15px 20px; font-size: 16px; font-weight: 600; }
        .section-content { padding: 20px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: $($Script:BrandLightGrey); color: $($Script:BrandDarkGrey); text-align: left; padding: 12px; font-weight: 600; border-bottom: 2px solid #ddd; }
        td { padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
        tr:hover { background: #fafafa; }
        .status-ok { color: #059669; }
        .status-warn { color: #d97706; }
        .status-error { color: #dc2626; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 10px; }
        .badge-iis { background: #dbeafe; color: #1d4ed8; }
        .badge-rdp { background: #fce7f3; color: #be185d; }
        .badge-httpsys { background: #e0e7ff; color: #4338ca; }
        .badge-port { background: #d1fae5; color: #065f46; }
        .thumbprint { font-family: 'Consolas', monospace; font-size: 11px; word-break: break-all; }
        .footer { text-align: center; padding: 20px; color: $($Script:BrandGrey); font-size: 12px; }
        .search-criteria { background: $($Script:BrandLightGrey); border-left: 4px solid $($Script:BrandOrange); padding: 15px 20px; margin-bottom: 20px; border-radius: 0 8px 8px 0; }
        .no-data { color: $($Script:BrandGrey); font-style: italic; padding: 20px; text-align: center; }
        .expiry-warning { background: #fef3c7; }
        .expiry-critical { background: #fee2e2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Wildcard Certificate Usage Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Duration: $durationStr | Yeyland Wutani LLC</p>
    </div>
    
    <div class="container">
        <div class="search-criteria">
            <strong>Search Criteria:</strong> $searchCriteria
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">$($Script:ScannedComputers.Count)</div>
                <div class="label">Computers Scanned</div>
            </div>
            <div class="summary-card">
                <div class="value">$totalFound</div>
                <div class="label">Certificate Instances</div>
            </div>
            <div class="summary-card">
                <div class="value">$iisCount</div>
                <div class="label">IIS Bindings</div>
            </div>
            <div class="summary-card">
                <div class="value">$rdpCount</div>
                <div class="label">RDP Services</div>
            </div>
            <div class="summary-card">
                <div class="value">$httpSysCount</div>
                <div class="label">HTTP.SYS Bindings</div>
            </div>
            <div class="summary-card">
                <div class="value">$errorCount</div>
                <div class="label">Scan Errors</div>
            </div>
        </div>
"@)

    # Certificate Instances Section
    [void]$html.AppendLine('<div class="section">')
    [void]$html.AppendLine('<div class="section-header">Certificate Store Instances</div>')
    [void]$html.AppendLine('<div class="section-content">')
    
    if ($Script:CertificateInstances.Count -gt 0) {
        [void]$html.AppendLine('<table>')
        [void]$html.AppendLine('<thead><tr><th>Computer</th><th>Subject</th><th>Thumbprint</th><th>Expires</th><th>Has Key</th><th>DNS Names</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')
        
        foreach ($cert in $Script:CertificateInstances) {
            $expiryClass = ""
            $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
            if ($daysUntilExpiry -lt 0) { $expiryClass = "expiry-critical" }
            elseif ($daysUntilExpiry -lt 30) { $expiryClass = "expiry-warning" }
            
            $keyStatus = if ($cert.HasPrivateKey) { '<span class="status-ok">Yes</span>' } else { '<span class="status-error">No</span>' }
            
            [void]$html.AppendLine("<tr class=`"$expiryClass`">")
            [void]$html.AppendLine("<td>$($cert.ComputerName)</td>")
            [void]$html.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($cert.Subject))</td>")
            [void]$html.AppendLine("<td class=`"thumbprint`">$($cert.Thumbprint)</td>")
            [void]$html.AppendLine("<td>$($cert.NotAfter.ToString('yyyy-MM-dd'))</td>")
            [void]$html.AppendLine("<td>$keyStatus</td>")
            [void]$html.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($cert.DnsNameList))</td>")
            [void]$html.AppendLine("</tr>")
        }
        
        [void]$html.AppendLine('</tbody></table>')
    } else {
        [void]$html.AppendLine('<div class="no-data">No certificate instances found in certificate stores</div>')
    }
    
    [void]$html.AppendLine('</div></div>')

    # IIS Bindings Section
    [void]$html.AppendLine('<div class="section">')
    [void]$html.AppendLine('<div class="section-header">IIS Website Bindings<span class="badge badge-iis">IIS</span></div>')
    [void]$html.AppendLine('<div class="section-content">')
    
    if ($Script:IISBindings.Count -gt 0) {
        [void]$html.AppendLine('<table>')
        [void]$html.AppendLine('<thead><tr><th>Computer</th><th>Site Name</th><th>Site ID</th><th>Binding</th><th>Certificate Hash</th><th>Store</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')
        
        foreach ($binding in $Script:IISBindings) {
            [void]$html.AppendLine("<tr>")
            [void]$html.AppendLine("<td>$($binding.ComputerName)</td>")
            [void]$html.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($binding.SiteName))</td>")
            [void]$html.AppendLine("<td>$($binding.SiteID)</td>")
            [void]$html.AppendLine("<td>$($binding.BindingInfo)</td>")
            [void]$html.AppendLine("<td class=`"thumbprint`">$($binding.CertificateHash)</td>")
            [void]$html.AppendLine("<td>$($binding.CertificateStore)</td>")
            [void]$html.AppendLine("</tr>")
        }
        
        [void]$html.AppendLine('</tbody></table>')
    } else {
        [void]$html.AppendLine('<div class="no-data">No IIS bindings found using the specified certificate</div>')
    }
    
    [void]$html.AppendLine('</div></div>')

    # RDP Certificates Section
    [void]$html.AppendLine('<div class="section">')
    [void]$html.AppendLine('<div class="section-header">Remote Desktop Certificate Assignments<span class="badge badge-rdp">RDP</span></div>')
    [void]$html.AppendLine('<div class="section-content">')
    
    if ($Script:RDPCertificates.Count -gt 0) {
        [void]$html.AppendLine('<table>')
        [void]$html.AppendLine('<thead><tr><th>Computer</th><th>Terminal Name</th><th>Certificate Thumbprint</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')
        
        foreach ($rdp in $Script:RDPCertificates) {
            [void]$html.AppendLine("<tr>")
            [void]$html.AppendLine("<td>$($rdp.ComputerName)</td>")
            [void]$html.AppendLine("<td>$($rdp.TerminalName)</td>")
            [void]$html.AppendLine("<td class=`"thumbprint`">$($rdp.Thumbprint)</td>")
            [void]$html.AppendLine("</tr>")
        }
        
        [void]$html.AppendLine('</tbody></table>')
    } else {
        [void]$html.AppendLine('<div class="no-data">No RDP services found using the specified certificate</div>')
    }
    
    [void]$html.AppendLine('</div></div>')

    # HTTP.SYS Bindings Section
    [void]$html.AppendLine('<div class="section">')
    [void]$html.AppendLine('<div class="section-header">HTTP.SYS SSL Bindings<span class="badge badge-httpsys">HTTP.SYS</span></div>')
    [void]$html.AppendLine('<div class="section-content">')
    
    if ($Script:HTTPSysBindings.Count -gt 0) {
        [void]$html.AppendLine('<table>')
        [void]$html.AppendLine('<thead><tr><th>Computer</th><th>Endpoint</th><th>Certificate Hash</th><th>Application ID</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')
        
        foreach ($binding in $Script:HTTPSysBindings) {
            [void]$html.AppendLine("<tr>")
            [void]$html.AppendLine("<td>$($binding.ComputerName)</td>")
            [void]$html.AppendLine("<td>$($binding.Endpoint)</td>")
            [void]$html.AppendLine("<td class=`"thumbprint`">$($binding.CertificateHash)</td>")
            [void]$html.AppendLine("<td>$($binding.ApplicationID)</td>")
            [void]$html.AppendLine("</tr>")
        }
        
        [void]$html.AppendLine('</tbody></table>')
    } else {
        [void]$html.AppendLine('<div class="no-data">No HTTP.SYS bindings found using the specified certificate</div>')
    }
    
    [void]$html.AppendLine('</div></div>')

    # Port Scan Results Section
    if ($Script:PortScanResults.Count -gt 0) {
        [void]$html.AppendLine('<div class="section">')
        [void]$html.AppendLine('<div class="section-header">SSL Port Scan Results<span class="badge badge-port">Port Scan</span></div>')
        [void]$html.AppendLine('<div class="section-content">')
        [void]$html.AppendLine('<table>')
        [void]$html.AppendLine('<thead><tr><th>Computer</th><th>Port</th><th>Subject</th><th>Thumbprint</th><th>Expires</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')
        
        foreach ($result in $Script:PortScanResults) {
            $expiryClass = ""
            if ($result.NotAfter) {
                $daysUntilExpiry = ($result.NotAfter - (Get-Date)).Days
                if ($daysUntilExpiry -lt 0) { $expiryClass = "expiry-critical" }
                elseif ($daysUntilExpiry -lt 30) { $expiryClass = "expiry-warning" }
            }
            
            [void]$html.AppendLine("<tr class=`"$expiryClass`">")
            [void]$html.AppendLine("<td>$($result.ComputerName)</td>")
            [void]$html.AppendLine("<td>$($result.Port)</td>")
            [void]$html.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($result.Subject))</td>")
            [void]$html.AppendLine("<td class=`"thumbprint`">$($result.Thumbprint)</td>")
            [void]$html.AppendLine("<td>$(if ($result.NotAfter) { $result.NotAfter.ToString('yyyy-MM-dd') } else { 'N/A' })</td>")
            [void]$html.AppendLine("</tr>")
        }
        
        [void]$html.AppendLine('</tbody></table>')
        [void]$html.AppendLine('</div></div>')
    }

    # Errors Section
    if ($Script:ScanErrors.Count -gt 0) {
        [void]$html.AppendLine('<div class="section">')
        [void]$html.AppendLine('<div class="section-header">Scan Errors</div>')
        [void]$html.AppendLine('<div class="section-content">')
        [void]$html.AppendLine('<table>')
        [void]$html.AppendLine('<thead><tr><th>Computer</th><th>Phase</th><th>Error</th></tr></thead>')
        [void]$html.AppendLine('<tbody>')
        
        foreach ($err in $Script:ScanErrors) {
            [void]$html.AppendLine("<tr>")
            [void]$html.AppendLine("<td>$($err.ComputerName)</td>")
            [void]$html.AppendLine("<td>$($err.Phase)</td>")
            [void]$html.AppendLine("<td class=`"status-error`">$([System.Web.HttpUtility]::HtmlEncode($err.Error))</td>")
            [void]$html.AppendLine("</tr>")
        }
        
        [void]$html.AppendLine('</tbody></table>')
        [void]$html.AppendLine('</div></div>')
    }

    [void]$html.AppendLine(@"
    </div>
    
    <div class="footer">
        <p>Yeyland Wutani LLC - Building Better Systems</p>
        <p>Find-WildcardCertificateUsage v$($Script:Version)</p>
    </div>
</body>
</html>
"@)

    return $html.ToString()
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Add System.Web for HTML encoding
Add-Type -AssemblyName System.Web

#region Banner
function Show-YWBanner {
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
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
#endregion Banner

Show-YWBanner
Write-Host "  Wildcard Certificate Usage Discovery" -ForegroundColor Cyan
Write-Host ""

# Determine search criteria display
$searchDisplay = if ($Thumbprint) { "Thumbprint: $Thumbprint" }
                 elseif ($SubjectPattern) { "Subject: $SubjectPattern" }
                 else { "Friendly Name: $FriendlyName" }
Write-StatusMessage "Search Criteria: $searchDisplay"
Write-Host ""

# Get target computers
$targetComputers = Get-TargetComputers -ComputerName $ComputerName -OUSearchBase $OUSearchBase -IncludeClients:$IncludeClients

if ($targetComputers.Count -eq 0) {
    Write-StatusMessage "No target computers found. Exiting." -Type Error
    exit 1
}

# Phase 1: Test connectivity
Write-StatusMessage "Testing connectivity to $($targetComputers.Count) targets..."
$reachableComputers = [System.Collections.ArrayList]::new()
$unreachableCount = 0

$counter = 0
foreach ($computer in $targetComputers) {
    $counter++
    $pct = [math]::Round(($counter / $targetComputers.Count) * 100, 0)
    Write-Progress -Activity "Testing Connectivity" -Status "$computer ($counter of $($targetComputers.Count))" -PercentComplete $pct
    
    if (Test-ComputerReachable -ComputerName $computer) {
        [void]$reachableComputers.Add($computer)
    } else {
        $unreachableCount++
        [void]$Script:ScanErrors.Add([PSCustomObject]@{
            ComputerName = $computer
            Phase = "Connectivity"
            Error = "Host unreachable"
        })
    }
}
Write-Progress -Activity "Testing Connectivity" -Completed

Write-StatusMessage "$($reachableComputers.Count) targets reachable, $unreachableCount unreachable" -Type $(if ($reachableComputers.Count -gt 0) { 'Success' } else { 'Warning' })

if ($reachableComputers.Count -eq 0) {
    Write-StatusMessage "No reachable computers. Exiting." -Type Error
    exit 1
}

# Phase 2: Remote Certificate Store Discovery (unless skipped)
if (-not $SkipRemoting) {
    Write-Host ""
    Invoke-CertificateStoreDiscovery -Computers $reachableComputers -Thumbprint $Thumbprint -SubjectPattern $SubjectPattern -FriendlyName $FriendlyName -Credential $Credential -ThrottleLimit $ThrottleLimit
    Write-StatusMessage "Certificate store scan complete" -Type Success
    Write-StatusMessage "  - Certificate Instances: $($Script:CertificateInstances.Count)"
    Write-StatusMessage "  - IIS Bindings: $($Script:IISBindings.Count)"
    Write-StatusMessage "  - RDP Certificates: $($Script:RDPCertificates.Count)"
    Write-StatusMessage "  - HTTP.SYS Bindings: $($Script:HTTPSysBindings.Count)"
}

# Phase 3: SSL Port Scanning (unless skipped)
if (-not $SkipPortScan) {
    Write-Host ""
    Invoke-SSLPortScanning -Computers $reachableComputers -Ports $ScanPorts -Thumbprint $Thumbprint -SubjectPattern $SubjectPattern -FriendlyName $FriendlyName -Timeout $TimeoutSeconds
    Write-StatusMessage "Port scan complete: $($Script:PortScanResults.Count) matching certificates found" -Type Success
}

# Phase 4: Generate Reports
Write-Host ""
Write-StatusMessage "Generating reports..."

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$baseFileName = "CertificateUsage_$timestamp"

# Create output directory if needed
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Export CSV files
if ($Script:CertificateInstances.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "$baseFileName`_Instances.csv"
    $Script:CertificateInstances | Export-Csv -Path $csvPath -NoTypeInformation
    Write-StatusMessage "Exported certificate instances to: $csvPath" -Type Success
}

if ($Script:IISBindings.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "$baseFileName`_IISBindings.csv"
    $Script:IISBindings | Export-Csv -Path $csvPath -NoTypeInformation
    Write-StatusMessage "Exported IIS bindings to: $csvPath" -Type Success
}

if ($Script:RDPCertificates.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "$baseFileName`_RDP.csv"
    $Script:RDPCertificates | Export-Csv -Path $csvPath -NoTypeInformation
    Write-StatusMessage "Exported RDP certificates to: $csvPath" -Type Success
}

if ($Script:PortScanResults.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "$baseFileName`_PortScan.csv"
    $Script:PortScanResults | Export-Csv -Path $csvPath -NoTypeInformation
    Write-StatusMessage "Exported port scan results to: $csvPath" -Type Success
}

# Generate HTML report
$htmlContent = New-HTMLReport -OutputPath $OutputPath
$htmlPath = Join-Path $OutputPath "$baseFileName.html"
$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8

Write-StatusMessage "HTML report saved to: $htmlPath" -Type Success

# Summary
$duration = (Get-Date) - $Script:StartTime
Write-Host ""
Write-Host "============================================================" -ForegroundColor $Script:ConsoleAccent
Write-Host "  SCAN COMPLETE" -ForegroundColor $Script:ConsoleHighlight
Write-Host "============================================================" -ForegroundColor $Script:ConsoleAccent
Write-Host "  Duration: $("{0:mm}m {0:ss}s" -f $duration)" -ForegroundColor Gray
Write-Host "  Computers Scanned: $($Script:ScannedComputers.Count)" -ForegroundColor Gray
Write-Host "  Certificate Instances: $($Script:CertificateInstances.Count)" -ForegroundColor $(if ($Script:CertificateInstances.Count -gt 0) { 'Green' } else { 'Gray' })
Write-Host "  IIS Bindings: $($Script:IISBindings.Count)" -ForegroundColor $(if ($Script:IISBindings.Count -gt 0) { 'Green' } else { 'Gray' })
Write-Host "  RDP Services: $($Script:RDPCertificates.Count)" -ForegroundColor $(if ($Script:RDPCertificates.Count -gt 0) { 'Green' } else { 'Gray' })
Write-Host "  HTTP.SYS Bindings: $($Script:HTTPSysBindings.Count)" -ForegroundColor $(if ($Script:HTTPSysBindings.Count -gt 0) { 'Green' } else { 'Gray' })
Write-Host "  Port Scan Matches: $($Script:PortScanResults.Count)" -ForegroundColor $(if ($Script:PortScanResults.Count -gt 0) { 'Green' } else { 'Gray' })
Write-Host "  Errors: $($Script:ScanErrors.Count)" -ForegroundColor $(if ($Script:ScanErrors.Count -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host "============================================================" -ForegroundColor $Script:ConsoleAccent
Write-Host ""

# Open HTML report
if (Test-Path $htmlPath) {
    Write-StatusMessage "Opening report in browser..."
    Start-Process $htmlPath
}
