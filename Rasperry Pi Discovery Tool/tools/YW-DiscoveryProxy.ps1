<#
.SYNOPSIS
    Yeyland Wutani LLC — Discovery Proxy for credentialed network scanning.

.DESCRIPTION
    Run this script on a Domain Controller as Domain Admin BEFORE starting a
    YW Pi network scan. The proxy:

      1. Writes a self-expiring DNS TXT record:
             _yw-discovery.<domain>  TXT  "ywp-v1|token=<TOKEN>|port=<PORT>"
         The Pi discovers this record automatically — no manual key entry needed.

      2. Starts a local HTTP API that accepts authenticated queries from the Pi:
             /computers       All AD computer objects
             /users           All AD user objects
             /groups          Privileged group memberships
             /password-policy Domain password & lockout policy
             /dhcp            Full DHCP lease table (if DHCP role present)
             /dns             DNS zone records (if DNS Server role present)
             /gpos            Group Policy objects
             /hardware        CIM hardware inventory for servers (CPU/RAM/disk/serial)
             /done            Pi signals scan complete; proxy shuts down cleanly

      3. Locks to the first IP that successfully authenticates (the Pi).

      4. Self-terminates when the Pi sends /done or when the timeout expires.
         The DNS TXT record is always removed on exit.

.PARAMETER Port
    TCP port for the HTTP listener. Default: 8734.

.PARAMETER TimeoutMinutes
    Auto-shutdown after this many minutes. Default: 45.

.PARAMETER Domain
    AD domain FQDN. Defaults to the current user's domain ($env:USERDNSDOMAIN).

.EXAMPLE
    # Run on a Domain Controller as Domain Admin:
    .\YW-DiscoveryProxy.ps1

    # Custom port / timeout:
    .\YW-DiscoveryProxy.ps1 -Port 9000 -TimeoutMinutes 30
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [int]    $Port           = 8734,
    [int]    $TimeoutMinutes = 45,
    [string] $Domain         = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colour helpers ─────────────────────────────────────────────────────────────

function Write-Banner {
    $bar = "=" * 62
    Write-Host ""
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host "    YEYLAND WUTANI LLC  //  Network Discovery Proxy" -ForegroundColor Cyan
    Write-Host "    Credentialed AD enrichment for Pi network scans" -ForegroundColor DarkGray
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-KV([string]$Key, [string]$Value, [string]$Color = "White") {
    Write-Host ("    {0,-18}" -f "${Key}:") -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

function Write-Req([string]$Method, [string]$Path, [string]$Detail) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    Write-Host ("  [{0}]  {1,-5}  {2,-30}  {3}" -f $ts, $Method, $Path, $Detail) `
        -ForegroundColor DarkCyan
}

# ── Module checks ──────────────────────────────────────────────────────────────

function Test-Mod([string]$Name) {
    return [bool](Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
}

$ADAvailable  = Test-Mod "ActiveDirectory"
$DNSAvailable = Test-Mod "DnsServer"

if (-not $ADAvailable) {
    Write-Host "`n  [ERROR] ActiveDirectory module not available." -ForegroundColor Red
    Write-Host "          Run this script on a Domain Controller.`n" -ForegroundColor Red
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop
if ($DNSAvailable) {
    Import-Module DnsServer -ErrorAction SilentlyContinue
}

# ── Token generation ───────────────────────────────────────────────────────────

$TokenBytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(24)
$Token      = [Convert]::ToBase64String($TokenBytes) `
              -replace '\+', '-' -replace '/', '_' -replace '=', ''

# ── DNS TXT record management ──────────────────────────────────────────────────

$TxtLabel   = "_yw-discovery"
$TxtValue   = "ywp-v1|token=$Token|port=$Port"
$DnsCleanOk = $false

function Register-ProxyTxt {
    if (-not $DNSAvailable) {
        Write-KV "DNS TXT" "SKIPPED (DnsServer module unavailable)" "Yellow"
        return
    }
    try {
        # Remove any stale record silently
        Remove-DnsServerResourceRecord -ZoneName $Domain -Name $TxtLabel `
            -RRType "TXT" -Force -ErrorAction SilentlyContinue | Out-Null

        Add-DnsServerResourceRecord `
            -ZoneName $Domain -Name $TxtLabel -Txt `
            -DescriptiveText $TxtValue `
            -TimeToLive (New-TimeSpan -Minutes $TimeoutMinutes) `
            -ErrorAction Stop | Out-Null

        Write-KV "DNS TXT" "${TxtLabel}.${Domain}  (auto-discovery)" "Green"
    }
    catch {
        Write-KV "DNS TXT" "FAILED: $_" "Yellow"
        Write-Host "         Pi will still connect if pointed at this DC directly." `
            -ForegroundColor DarkGray
    }
}

function Remove-ProxyTxt {
    if ($script:DnsCleanOk -or -not $DNSAvailable) { return }
    try {
        Remove-DnsServerResourceRecord -ZoneName $Domain -Name $TxtLabel `
            -RRType "TXT" -Force -ErrorAction SilentlyContinue | Out-Null
        $script:DnsCleanOk = $true
    }
    catch { }
}

# ── Hardware inventory via CIM ─────────────────────────────────────────────────

function Get-ServerHardware([string[]]$ComputerNames) {
    $out = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($name in $ComputerNames) {
        $hw = @{ computer_name = $name; wmi_accessible = $false; wmi_error = $null }

        try {
            # System / model / RAM
            $cs = Get-CimInstance -ComputerName $name -ClassName Win32_ComputerSystem `
                      -OperationTimeoutSec 15 -ErrorAction Stop
            $hw.manufacturer       = $cs.Manufacturer
            $hw.model              = $cs.Model
            $hw.total_ram_gb       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            $hw.domain             = $cs.Domain
            $hw.virtual_machine    = ($cs.Model -match 'Virtual|VMware|Hyper-V|KVM|QEMU|Xen')
            $hw.hypervisor_present = [bool]$cs.HypervisorPresent

            # CPU
            $procs = @(Get-CimInstance -ComputerName $name -ClassName Win32_Processor `
                           -OperationTimeoutSec 15 -ErrorAction Stop)
            if ($procs.Count -gt 0) {
                $hw.cpu_name          = ($procs[0].Name -replace '\s+', ' ').Trim()
                $hw.cpu_socket_count  = $procs.Count
                $hw.cpu_cores_total   = ($procs | Measure-Object NumberOfCores -Sum).Sum
                $hw.cpu_logical_total = ($procs | Measure-Object NumberOfLogicalProcessors -Sum).Sum
                $hw.cpu_speed_mhz     = $procs[0].MaxClockSpeed
            }

            # RAM DIMMs
            $dimms = @(Get-CimInstance -ComputerName $name -ClassName Win32_PhysicalMemory `
                           -OperationTimeoutSec 10 -ErrorAction SilentlyContinue)
            if ($dimms.Count -gt 0) {
                $hw.ram_dimm_count   = $dimms.Count
                $hw.ram_dimm_gb_each = [math]::Round(($dimms[0].Capacity / 1GB), 0)
                $hw.ram_speed_mhz    = $dimms[0].Speed
                $hw.ram_type         = switch ($dimms[0].MemoryType) {
                    24 { "DDR3" } 26 { "DDR4" } 34 { "DDR5" } default { "DDR" }
                }
            }

            # Disks — try Storage module (accurate SSD/HDD), fall back to WMI
            $disks = @()
            try {
                $sess = New-CimSession -ComputerName $name -OperationTimeoutSec 10
                $pd   = @(Get-PhysicalDisk -CimSession $sess -ErrorAction Stop)
                $disks = @($pd | ForEach-Object {
                    @{
                        model      = $_.FriendlyName
                        size_gb    = [math]::Round($_.Size / 1GB, 0)
                        media_type = $_.MediaType   # SSD / HDD / Unspecified
                        bus_type   = $_.BusType.ToString()
                        health     = $_.HealthStatus.ToString()
                    }
                })
                Remove-CimSession $sess -ErrorAction SilentlyContinue
            }
            catch {
                $wmiDisks = @(Get-CimInstance -ComputerName $name -ClassName Win32_DiskDrive `
                                  -OperationTimeoutSec 10 -ErrorAction SilentlyContinue)
                $disks = @($wmiDisks | ForEach-Object {
                    @{
                        model      = $_.Model
                        size_gb    = if ($_.Size) { [math]::Round($_.Size / 1GB, 0) } else { 0 }
                        media_type = if ($_.Model -match 'SSD|Solid State') { 'SSD' } else { 'HDD' }
                        serial     = $_.SerialNumber
                    }
                })
            }
            $hw.disks          = $disks
            $hw.disk_count     = $disks.Count
            $hw.disk_total_gb  = ($disks | Measure-Object size_gb -Sum).Sum

            # BIOS / firmware (serial number critical for warranty lookup)
            $bios = Get-CimInstance -ComputerName $name -ClassName Win32_BIOS `
                        -OperationTimeoutSec 10 -ErrorAction SilentlyContinue
            if ($bios) {
                $hw.bios_serial       = $bios.SerialNumber
                $hw.bios_version      = $bios.SMBIOSBIOSVersion
                $hw.bios_manufacturer = $bios.Manufacturer
                $hw.bios_release_date = if ($bios.ReleaseDate) {
                    $bios.ReleaseDate.ToString("yyyy-MM-dd")
                } else { $null }
            }

            # OS / uptime
            $os = Get-CimInstance -ComputerName $name -ClassName Win32_OperatingSystem `
                      -OperationTimeoutSec 10 -ErrorAction SilentlyContinue
            if ($os) {
                $hw.os_caption   = $os.Caption
                $hw.os_build     = $os.BuildNumber
                $hw.os_arch      = $os.OSArchitecture
                $hw.last_boot    = if ($os.LastBootUpTime)  { $os.LastBootUpTime.ToString("o")  } else { $null }
                $hw.install_date = if ($os.InstallDate)     { $os.InstallDate.ToString("o")     } else { $null }
                $hw.uptime_days  = if ($os.LastBootUpTime) {
                    [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
                } else { $null }
            }

            # Network adapters
            $nics = @(Get-CimInstance -ComputerName $name -ClassName Win32_NetworkAdapter `
                          -Filter "PhysicalAdapter=True" -OperationTimeoutSec 10 `
                          -ErrorAction SilentlyContinue)
            $hw.nics = @($nics | ForEach-Object {
                @{
                    name       = $_.Name
                    mac        = $_.MACAddress
                    speed_mbps = if ($_.Speed -and $_.Speed -gt 0) {
                        [math]::Round($_.Speed / 1MB, 0)
                    } else { $null }
                    enabled    = $_.NetEnabled
                }
            })
            $hw.nic_count = $hw.nics.Count

            $hw.wmi_accessible = $true
            Write-Host ("          [{0}]  hardware OK" -f $name) -ForegroundColor DarkGreen
        }
        catch {
            $hw.wmi_error = $_.Exception.Message
            Write-Host ("          [{0}]  WMI unreachable: {1}" -f $name, $_.Exception.Message) `
                -ForegroundColor DarkYellow
        }

        [void]$out.Add($hw)
    }

    return , @($out)
}

# ── AD query helpers ───────────────────────────────────────────────────────────

function Get-ComputersData {
    $props = @(
        "Name", "DNSHostName", "IPv4Address", "OperatingSystem", "OperatingSystemVersion",
        "LastLogonDate", "Enabled", "DistinguishedName", "Description",
        "ServicePrincipalNames", "WhenCreated", "WhenChanged", "Location", "ManagedBy"
    )
    return @(Get-ADComputer -Filter * -Properties $props | Select-Object $props)
}

function Get-UsersData {
    $props = @(
        "SamAccountName", "DisplayName", "GivenName", "Surname", "EmailAddress",
        "Title", "Department", "Company", "Manager", "TelephoneNumber",
        "LastLogonDate", "Enabled", "PasswordLastSet", "PasswordNeverExpires",
        "PasswordExpired", "LockedOut", "BadLogonCount", "CannotChangePassword",
        "WhenCreated", "WhenChanged", "DistinguishedName", "MemberOf",
        "Description", "ServicePrincipalNames", "UserPrincipalName"
    )
    return @(Get-ADUser -Filter * -Properties $props | Select-Object $props)
}

function Get-GroupsData {
    $targets = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Backup Operators", "Server Operators",
        "Remote Desktop Users", "DnsAdmins", "Group Policy Creator Owners",
        "DHCP Administrators"
    )
    $result = @{}
    foreach ($g in $targets) {
        try {
            $members = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue |
                Where-Object { $_.objectClass -eq "user" } |
                Select-Object SamAccountName, Name, DistinguishedName)
            $result[$g] = $members
        }
        catch { $result[$g] = @() }
    }
    return $result
}

function Get-DhcpData {
    try {
        $scopes  = @(Get-DhcpServerv4Scope -ErrorAction Stop)
        $leases  = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($scope in $scopes) {
            foreach ($l in @(Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)) {
                [void]$leases.Add(@{
                    ip            = $l.IPAddress.ToString()
                    mac           = $l.ClientId
                    hostname      = $l.HostName
                    scope         = $scope.ScopeId.ToString()
                    address_state = $l.AddressState.ToString()
                    lease_expires = if ($l.LeaseExpiryTime) { $l.LeaseExpiryTime.ToString("o") } else { $null }
                })
            }
        }
        return @{ available = $true; leases = @($leases); scope_count = $scopes.Count }
    }
    catch {
        return @{ available = $false; error = $_.Exception.Message }
    }
}

function Get-DnsData {
    if (-not $DNSAvailable) { return @{ available = $false; reason = "DnsServer module unavailable" } }
    try {
        $zones  = @(Get-DnsServerZone -ErrorAction Stop |
            Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne "TrustAnchors" })
        $result = @($zones | ForEach-Object {
            $z = $_
            $recs = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordType -in @("A","AAAA","CNAME","MX","PTR","SRV","NS") } |
                ForEach-Object {
                    @{
                        name   = $_.HostName
                        type   = $_.RecordType
                        data   = $_.RecordData.IPv4Address.ToString()    -replace '^$', '' `
                               + $_.RecordData.IPv6Address?.ToString()   `
                               + $_.RecordData.HostNameAlias             `
                               + $_.RecordData.MailExchange              `
                               + $_.RecordData.DomainName
                        ttl    = $_.TimeToLive.TotalSeconds
                    }
                })
            @{
                zone_name    = $z.ZoneName
                zone_type    = $z.ZoneType.ToString()
                is_reverse   = $z.IsReverseLookupZone
                record_count = $recs.Count
                records      = $recs
            }
        })
        return @{ available = $true; zones = $result }
    }
    catch {
        return @{ available = $false; error = $_.Exception.Message }
    }
}

function Get-GposData {
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpos = @(Get-GPO -All -ErrorAction Stop | Select-Object `
            DisplayName, Id, GpoStatus, CreationTime, ModificationTime,
            @{ N = "ComputerEnabled"; E = { $_.Computer.Enabled } },
            @{ N = "UserEnabled";     E = { $_.User.Enabled     } })
        return @{ available = $true; gpos = $gpos; count = $gpos.Count }
    }
    catch {
        return @{ available = $false; error = $_.Exception.Message }
    }
}

function Get-PasswordPolicyData {
    $d = Get-ADDefaultDomainPasswordPolicy
    $pol = @{
        min_password_length                = $d.MinPasswordLength
        max_password_age_days              = $d.MaxPasswordAge.Days
        min_password_age_days              = $d.MinPasswordAge.Days
        password_history_count             = $d.PasswordHistoryCount
        complexity_enabled                 = $d.ComplexityEnabled
        reversible_encryption              = $d.ReversibleEncryptionEnabled
        lockout_threshold                  = $d.LockoutThreshold
        lockout_duration_minutes           = $d.LockoutDuration.TotalMinutes
        lockout_observation_window_minutes = $d.LockoutObservationWindow.TotalMinutes
    }
    try {
        $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue |
            Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge,
                          ComplexityEnabled, LockoutThreshold)
        $pol.fine_grained_policies = $fgpp
    }
    catch { $pol.fine_grained_policies = @() }
    return $pol
}

function Get-DomainData {
    $dom = Get-ADDomain
    $fst = Get-ADForest
    $dcs = @(Get-ADDomainController -Filter * |
        Select-Object Name, IPv4Address, OperatingSystem, IsGlobalCatalog, IsReadOnly, Site)
    return @{
        domain_name             = $dom.DNSRoot
        netbios_name            = $dom.NetBIOSName
        domain_mode             = $dom.DomainMode.ToString()
        forest_mode             = $fst.ForestMode.ToString()
        domain_controller_count = $dcs.Count
        domain_controllers      = $dcs
        forest_name             = $fst.Name
        pdc_emulator            = $dom.PDCEmulator
        rid_master              = $dom.RIDMaster
        sites                   = @($fst.Sites)
    }
}

# ── HTTP listener helpers ──────────────────────────────────────────────────────

$RequestCount = 0
$LockedToIP   = $null

function Send-Json($Context, $Data, [int]$StatusCode = 200) {
    $json  = $Data | ConvertTo-Json -Depth 20 -Compress -WarningAction SilentlyContinue
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $r     = $Context.Response
    $r.StatusCode       = $StatusCode
    $r.ContentType      = "application/json; charset=utf-8"
    $r.ContentLength64  = $bytes.LongLength
    $r.OutputStream.Write($bytes, 0, $bytes.Length)
    $r.OutputStream.Close()
}

function Handle-Request($Context) {
    $req      = $Context.Request
    $clientIP = $req.RemoteEndPoint.Address.ToString()
    $path     = $req.Url.AbsolutePath.ToLower().TrimEnd('/')
    $method   = $req.HttpMethod.ToUpper()
    $script:RequestCount++

    # Bearer token auth
    $auth  = $req.Headers["Authorization"] ?? ""
    $given = if ($auth -match '^Bearer\s+(.+)$') { $Matches[1].Trim() } else { "" }

    if ($given -ne $Token) {
        Write-Host ("  [REJECT]  {0}  bad-token  from {1}" -f $path, $clientIP) -ForegroundColor Red
        Send-Json $Context @{ error = "Unauthorized" } 401
        return $false
    }

    # Lock to first authenticated IP
    if ($null -eq $script:LockedToIP) {
        $script:LockedToIP = $clientIP
        Write-Host ("  [LOCKED]  Proxy locked to $clientIP") -ForegroundColor Green
    }
    elseif ($clientIP -ne $script:LockedToIP) {
        Send-Json $Context @{ error = "Locked to another client" } 403
        return $false
    }

    switch -Regex ($path) {

        "^/ping$" {
            Write-Req $method "/ping" "domain info"
            $info = Get-DomainData
            $info.proxy_version = "ywp-v1"
            $info.expires       = $Deadline.ToString("o")
            Send-Json $Context $info
        }

        "^/computers$" {
            Write-Host "  [REQ]   GET  /computers ..." -ForegroundColor DarkCyan -NoNewline
            $data = Get-ComputersData
            Write-Host ("  {0} records" -f $data.Count) -ForegroundColor Cyan
            Send-Json $Context $data
        }

        "^/users$" {
            Write-Host "  [REQ]   GET  /users ..." -ForegroundColor DarkCyan -NoNewline
            $data = Get-UsersData
            Write-Host ("  {0} records" -f $data.Count) -ForegroundColor Cyan
            Send-Json $Context $data
        }

        "^/groups$" {
            Write-Req $method "/groups" "privileged group memberships"
            Send-Json $Context (Get-GroupsData)
        }

        "^/password-policy$" {
            Write-Req $method "/password-policy" ""
            Send-Json $Context (Get-PasswordPolicyData)
        }

        "^/dhcp$" {
            Write-Req $method "/dhcp" "lease table"
            Send-Json $Context (Get-DhcpData)
        }

        "^/dns$" {
            Write-Req $method "/dns" "zone records"
            Send-Json $Context (Get-DnsData)
        }

        "^/gpos$" {
            Write-Req $method "/gpos" ""
            Send-Json $Context (Get-GposData)
        }

        "^/hardware$" {
            $qs = [System.Web.HttpUtility]::ParseQueryString($req.Url.Query)
            if ($qs["targets"]) {
                $targets = @($qs["targets"] -split ',')
            }
            else {
                $targets = @(Get-ADComputer -Filter { OperatingSystem -like "*Server*" } |
                    Select-Object -ExpandProperty Name)
            }
            Write-Host ("  [REQ]   GET  /hardware  ({0} server(s))..." -f $targets.Count) `
                -ForegroundColor DarkCyan
            $hwData = Get-ServerHardware -ComputerNames $targets
            Send-Json $Context @{ servers = $hwData; count = $hwData.Count }
        }

        "^/done$" {
            Write-Req $method "/done" "Pi signaled scan complete"
            Send-Json $Context @{ status = "goodbye"; requests_served = $script:RequestCount }
            return $true   # Signal main loop to exit
        }

        default {
            Send-Json $Context @{ error = "Unknown endpoint: $path" } 404
        }
    }

    return $false
}

# ── Main ───────────────────────────────────────────────────────────────────────

Write-Banner

$DcHostname = $env:COMPUTERNAME
$DcIP       = (Get-NetIPAddress -AddressFamily IPv4 |
               Where-Object {
                   $_.IPAddress -notmatch '^127\.' -and
                   $_.PrefixOrigin -notin @('WellKnown', 'Manual') -or
                   $_.InterfaceAlias -match 'Ethernet|LAN'
               } |
               Sort-Object PrefixLength |
               Select-Object -First 1 -ExpandProperty IPAddress)

if (-not $DcIP) {
    $DcIP = (Get-NetIPAddress -AddressFamily IPv4 |
             Where-Object { $_.IPAddress -notmatch '^127\.' } |
             Select-Object -First 1 -ExpandProperty IPAddress)
}

Register-ProxyTxt

$Deadline = (Get-Date).AddMinutes($TimeoutMinutes)

Write-KV "Domain"   $Domain
Write-KV "DC"       "$DcHostname  ($DcIP)"
Write-KV "Port"     $Port
Write-KV "Expires"  ($Deadline.ToString("HH:mm:ss") + "  ($TimeoutMinutes min)") "Yellow"
Write-KV "Status"   "Waiting for Pi to auto-discover and connect..." "Green"
Write-Host ""
Write-Host "  (Pi discovers this proxy automatically via DNS TXT — no manual steps needed.)" `
    -ForegroundColor DarkGray
Write-Host ""

# Start listener
$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add("http://+:${Port}/")

try {
    $Listener.Start()
}
catch {
    Write-Host "  [ERROR] Cannot bind to port ${Port}: $_" -ForegroundColor Red
    Write-Host "          If this is a permission error, run once as admin:" -ForegroundColor DarkGray
    Write-Host "          netsh http add urlacl url=http://+:${Port}/ user=Everyone" -ForegroundColor DarkGray
    exit 1
}

$ShouldExit = $false

try {
    while (-not $ShouldExit -and (Get-Date) -lt $Deadline) {
        # Poll every 2s so we can check the timeout without blocking forever
        $async   = $Listener.BeginGetContext($null, $null)
        $arrived = $async.AsyncWaitHandle.WaitOne(2000)

        if (-not $arrived) { continue }

        $ctx = $Listener.EndGetContext($async)
        try {
            $ShouldExit = Handle-Request $ctx
        }
        catch {
            Write-Host ("  [ERR]  Request handler: $_") -ForegroundColor Red
            try { $ctx.Response.Abort() } catch { }
        }
    }

    if ((Get-Date) -ge $Deadline) {
        Write-Host "`n  [TIMEOUT]  Proxy expired after $TimeoutMinutes minutes." -ForegroundColor Yellow
    }
}
finally {
    $Listener.Stop()
    $Listener.Close()
    Remove-ProxyTxt

    Write-Host ""
    Write-Host ("  Requests served : {0}" -f $RequestCount) -ForegroundColor DarkGray
    Write-Host ("  DNS TXT removed : {0}" -f $script:DnsCleanOk) -ForegroundColor DarkGray
    Write-Host "  Proxy stopped cleanly.`n" -ForegroundColor DarkGray
}
