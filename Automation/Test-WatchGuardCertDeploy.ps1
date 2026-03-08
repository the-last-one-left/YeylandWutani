#Requires -Version 5.1
<#
.SYNOPSIS
    WatchGuard Firebox certificate deployment probe + import test.

.DESCRIPTION
    Phase 1 (read-only):  Connects via SSH, dumps firmware version, current
                          certificate list, and active web-server-cert.
    Phase 2 (import):     Spins up a temporary in-process FTP server, pushes a
                          PFX to the Firebox via CLI, verifies the cert appears
                          in 'show certificate', then optionally activates it as
                          the Firebox web-server-cert.

    Note: IKEv2 Mobile VPN cert assignment is not supported via CLI on Fireware
    v12.10+. That step requires manual configuration in the Fireware Web UI.

    All raw SSH output is written to the console so you can see exactly what
    the parser will need to handle in the real implementation.

.NOTES
    Requires:  Install-Module Posh-SSH  (will prompt to install if missing)
    Tested on: Fireware v12.x, SSH port 4118
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $FireboxHost,
    [Parameter()] [int]    $FireboxPort   = 4118,
    [Parameter()] [string] $LocalIP,       # IP the Firebox can reach this machine on
    [Parameter()] [int]    $FtpPort        = 2121,  # non-privileged; no admin required
    [Parameter()] [string] $PfxPath,
    [Parameter()] [System.Security.SecureString] $PfxPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
function Write-Step   { param([string]$Msg) Write-Host "`n[STEP] $Msg" -ForegroundColor Cyan }
function Write-Ok     { param([string]$Msg) Write-Host "  [OK] $Msg"   -ForegroundColor Green }
function Write-Warn   { param([string]$Msg) Write-Host "  [!!] $Msg"   -ForegroundColor Yellow }
function Write-Raw    { param([string]$Label,[string]$Data)
    Write-Host "`n--- $Label ---" -ForegroundColor DarkGray
    Write-Host $Data -ForegroundColor Gray
    Write-Host "---" -ForegroundColor DarkGray
}

function Read-SecurePlain {
    param([System.Security.SecureString]$Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# --------------------------------------------------------------------------- #
# 1. Check / install Posh-SSH
# --------------------------------------------------------------------------- #
Write-Step "Checking for Posh-SSH module"
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Warn "Posh-SSH not found."
    $ans = Read-Host "Install Posh-SSH now? [Y/n]"
    if ($ans -match '^[Nn]') { throw "Posh-SSH is required. Aborting." }
    Install-Module -Name Posh-SSH -Scope CurrentUser -Force -AllowClobber
}
Import-Module Posh-SSH -ErrorAction Stop
Write-Ok "Posh-SSH $(( Get-Module Posh-SSH ).Version) loaded"

# --------------------------------------------------------------------------- #
# 2. Gather parameters
# --------------------------------------------------------------------------- #
Write-Step "Gathering connection parameters"

if (-not $FireboxHost) {
    $FireboxHost = Read-Host "Firebox hostname or IP"
}

if (-not $LocalIP) {
    # Auto-detect: pick the first non-loopback IPv4 that is in the same /24
    # (rough heuristic; user can override)
    $detected = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Sort-Object InterfaceIndex |
        Select-Object -First 1).IPAddress
    Write-Host "  Detected local IP: $detected"
    $input = Read-Host "  Local IP the Firebox can reach this machine on [$detected]"
    $LocalIP = if ($input.Trim()) { $input.Trim() } else { $detected }
}

$Credential = Get-Credential -Message "SSH credentials for $FireboxHost"

# --------------------------------------------------------------------------- #
# 3. SSH probe (read-only)
# --------------------------------------------------------------------------- #
Write-Step "Phase 1 - SSH read-only probe (port $FireboxPort)"

$session = New-SSHSession -ComputerName $FireboxHost -Port $FireboxPort `
               -Credential $Credential -AcceptKey -ErrorAction Stop
$stream  = New-SSHShellStream -SSHSession $session

# Helper: send a command, wait for prompt, return output
function Invoke-WgCommand {
    param([string]$Cmd, [int]$TimeoutMs = 4000)
    $stream.WriteLine($Cmd)
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    $buf = ''
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
        $chunk = $stream.Read()
        if ($chunk) { $buf += $chunk }
        # WatchGuard prompts end with '> ' in main or '(config)> '
        if ($buf -match '>\s*$') { break }
    }
    return $buf
}

# Consume login banner / initial prompt - firmware version lives HERE, not in show version
Start-Sleep -Milliseconds 1500
$banner = $stream.Read()
Write-Raw "Login banner" $banner

# 'show version' is NOT a valid WatchGuard CLI command - parse version from banner
$fwVersion = if ($banner -match 'Fireware\s+(?:OS\s+)?[Vv]ersion\s+([\d\.]+)') { $Matches[1] } else { 'unknown' }
Write-Ok "Firmware: $fwVersion"

# show certificate can be slow (369 certs!) - give it extra time
$certOut = Invoke-WgCommand 'show certificate' -TimeoutMs 15000
$wsOut   = Invoke-WgCommand 'show web-server-cert'

Write-Raw "show certificate"     $certOut
Write-Raw "show web-server-cert" $wsOut

# Parse current web-server-cert state
# Output is either:
#   ---Default Certificate signed by Firebox
#   ---Third-party Certificate: <name>  (ID: <number>)
if ($wsOut -match 'Default') {
    Write-Ok "Current web-server-cert: Default (self-signed)"
} elseif ($wsOut -match 'Third.party') {
    Write-Ok "Current web-server-cert: Third-party (already customized)"
} else {
    Write-Warn "Could not parse web-server-cert state - review output above"
}

# Snapshot numeric cert IDs that exist BEFORE import (for before/after diff)
# Format: lines where first non-space token is a 5-digit integer
$certIdsBefore = [System.Collections.Generic.HashSet[string]]::new()
foreach ($line in ($certOut -split "`n")) {
    if ($line -match '^\s*(\d{5,})\s') { [void]$certIdsBefore.Add($Matches[1]) }
}
Write-Ok "Numeric cert IDs found before import: $($certIdsBefore.Count)  ($($certIdsBefore -join ', '))"

# --------------------------------------------------------------------------- #
# 4. Ask whether to proceed with import
# --------------------------------------------------------------------------- #
Write-Host ""
$proceed = Read-Host "Phase 1 complete. Proceed with import test? [Y/n]"
if ($proceed -match '^[Nn]') {
    $session | Remove-SSHSession | Out-Null
    Write-Host "Session closed. Exiting." -ForegroundColor Yellow
    exit 0
}

# --------------------------------------------------------------------------- #
# 5. PFX file
# --------------------------------------------------------------------------- #
Write-Step "Phase 2 - import test"

if (-not $PfxPath) {
    $PfxPath = Read-Host "Full path to PFX certificate file"
}
if (-not (Test-Path $PfxPath)) { throw "PFX file not found: $PfxPath" }
$PfxFile = Get-Item $PfxPath

if (-not $PfxPassword) {
    $PfxPassword = Read-Host "PFX password" -AsSecureString
}
$PfxPlain = Read-SecurePlain $PfxPassword

# --------------------------------------------------------------------------- #
# 6. Spin up minimal in-process FTP server (passive mode)
# --------------------------------------------------------------------------- #
Write-Step "Starting temporary FTP server on $LocalIP`:$FtpPort"

$ftpUser = 'wgtest'
$ftpPass = [System.Guid]::NewGuid().ToString('N').Substring(0,12)  # random each run

# All FTP server state lives in a runspace so it doesn't block the main thread
$rsData = [hashtable]::Synchronized(@{
    FilePath = $PfxFile.FullName
    User     = $ftpUser
    Password = $ftpPass
    Port     = $FtpPort
    LocalIP  = $LocalIP
    Log      = [System.Collections.Generic.List[string]]::new()
    Ready    = $false
    Error    = $null
})

$ftpScript = {
    param($d)
    try {
        $ctl = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $d.Port)
        $ctl.Start()
        $d.Ready = $true
        $d.Log.Add("FTP listening on :$($d.Port)")

        $client = $ctl.AcceptTcpClient()
        $ns     = $client.GetStream()
        $rd     = [System.IO.StreamReader]::new($ns)
        $wr     = [System.IO.StreamWriter]::new($ns); $wr.AutoFlush = $true
        $wr.WriteLine('220 wgtest-ftp ready')
        $d.Log.Add("Client connected")

        $dataListener = $null

        while ($true) {
            $line = $rd.ReadLine()
            if ($null -eq $line) { break }
            $d.Log.Add(">> $line")
            $parts = $line -split ' ',2
            $cmd   = $parts[0].ToUpper()
            $arg   = if ($parts.Count -gt 1) { $parts[1] } else { '' }

            switch ($cmd) {
                'USER' {
                    if ($arg -eq $d.User) { $wr.WriteLine('331 Password required') }
                    else                  { $wr.WriteLine('530 Bad user') }
                }
                'PASS' {
                    if ($arg -eq $d.Password) { $wr.WriteLine('230 OK') }
                    else                      { $wr.WriteLine('530 Bad pass') }
                }
                'SYST' { $wr.WriteLine('215 UNIX Type: L8') }
                'FEAT' { $wr.WriteLine("211-Features:`r`nPASV`r`n211 End") }
                'OPTS' { $wr.WriteLine('200 OK') }
                'PWD'  { $wr.WriteLine('257 "/" is cwd') }
                'CWD'  { $wr.WriteLine('250 OK') }
                'TYPE' { $wr.WriteLine('200 Type set') }
                'PASV' {
                    $dataListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 0)
                    $dataListener.Start()
                    $dp = ($dataListener.LocalEndpoint).Port
                    $ipParts = $d.LocalIP -split '\.'
                    $p1 = [math]::Floor($dp / 256); $p2 = $dp % 256
                    $wr.WriteLine("227 Entering Passive Mode ($($ipParts -join ','),$p1,$p2)")
                    $d.Log.Add("<< PASV port $dp")
                }
                'LIST' {
                    $fname = [System.IO.Path]::GetFileName($d.FilePath)
                    $sz    = (Get-Item $d.FilePath).Length
                    $wr.WriteLine('150 Here comes the listing')
                    $dc = $dataListener.AcceptTcpClient()
                    $ds = $dc.GetStream()
                    $dw = [System.IO.StreamWriter]::new($ds); $dw.AutoFlush = $true
                    $dw.WriteLine("-rw-r--r-- 1 wg wg $sz Jan 01 00:00 $fname")
                    $dw.Close(); $dc.Close(); $dataListener.Stop(); $dataListener = $null
                    $wr.WriteLine('226 Transfer complete')
                }
                'NLST' {
                    $fname = [System.IO.Path]::GetFileName($d.FilePath)
                    $wr.WriteLine('150 Here comes the listing')
                    $dc = $dataListener.AcceptTcpClient()
                    $ds = $dc.GetStream()
                    $dw = [System.IO.StreamWriter]::new($ds); $dw.AutoFlush = $true
                    $dw.WriteLine($fname)
                    $dw.Close(); $dc.Close(); $dataListener.Stop(); $dataListener = $null
                    $wr.WriteLine('226 Transfer complete')
                }
                'RETR' {
                    $d.Log.Add("Sending file: $($d.FilePath)")
                    $wr.WriteLine('150 Opening data connection')
                    $dc    = $dataListener.AcceptTcpClient()
                    $ds    = $dc.GetStream()
                    $bytes = [System.IO.File]::ReadAllBytes($d.FilePath)
                    $ds.Write($bytes, 0, $bytes.Length)
                    $ds.Close(); $dc.Close(); $dataListener.Stop(); $dataListener = $null
                    $d.Log.Add("File sent ($($bytes.Length) bytes)")
                    $wr.WriteLine('226 Transfer complete')
                    # One-shot server - file delivered, we're done
                    break
                }
                'QUIT' { $wr.WriteLine('221 Bye'); break }
                default { $wr.WriteLine("500 Unknown: $cmd") }
            }
        }
        $client.Close(); $ctl.Stop()
        $d.Log.Add("FTP server closed")
    }
    catch {
        $d.Error = $_.Exception.Message
        $d.Log.Add("ERROR: $($_.Exception.Message)")
    }
}

$rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
$rs.Open()
$rs.SessionStateProxy.SetVariable('d', $rsData)
$ps = [System.Management.Automation.PowerShell]::Create()
$ps.Runspace = $rs
[void]$ps.AddScript($ftpScript).AddArgument($rsData)
$ftpHandle = $ps.BeginInvoke()

# Wait for server to be ready (up to 5s)
$t0 = [datetime]::UtcNow
while (-not $rsData.Ready -and ([datetime]::UtcNow - $t0).TotalSeconds -lt 5) {
    Start-Sleep -Milliseconds 100
}
if (-not $rsData.Ready) { throw "FTP server failed to start" }
Write-Ok "FTP server ready  user=$ftpUser  pass=$ftpPass"

# --------------------------------------------------------------------------- #
# 7. Import certificate via CLI
# --------------------------------------------------------------------------- #
$PfxFileName = $PfxFile.Name
$ftpUrl      = "ftp://${ftpUser}:${ftpPass}@${LocalIP}:${FtpPort}/${PfxFileName}"

Write-Step "Importing certificate via CLI"
Write-Host "  FTP URL: $ftpUrl" -ForegroundColor DarkGray
Write-Host "  Command: import certificate general-usage from <url> <pass>" -ForegroundColor DarkGray

$importCmd = "import certificate general-usage from $ftpUrl $PfxPlain"
$importOut = Invoke-WgCommand $importCmd -TimeoutMs 30000  # give it 30s
Write-Raw "import certificate output" $importOut

# Detect known error conditions
if ($importOut -match 'Edit Mode') {
    Write-Warn "EDIT MODE CONFLICT: Another admin session is holding Edit Mode."
    Write-Warn "Close WatchGuard System Manager / Policy Manager on all other machines, then retry."
    Write-Warn "The session holding Edit Mode is shown in the error above (look for the IP address)."
    $session | Remove-SSHSession | Out-Null
    exit 1
}
if ($importOut -match '%Error') {
    Write-Warn "Import command returned an error - see raw output above."
}

# --------------------------------------------------------------------------- #
# 8. Verify cert appears in 'show certificate'
# --------------------------------------------------------------------------- #
Write-Step "Verifying import"
Start-Sleep -Milliseconds 1000
$certOut2 = Invoke-WgCommand 'show certificate' -TimeoutMs 15000
Write-Raw "show certificate (after import)" $certOut2

# Find new numeric cert IDs by diffing before/after
$newCertId = $null
foreach ($line in ($certOut2 -split "`n")) {
    if ($line -match '^\s*(\d{5,})\s') {
        $candidate = $Matches[1]
        if (-not $certIdsBefore.Contains($candidate)) {
            $newCertId = $candidate
            Write-Ok "New cert ID (appeared after import): $newCertId"
            Write-Ok "  Line: $($line.Trim())"
            break
        }
    }
}
if (-not $newCertId) {
    Write-Warn "No new numeric cert ID found after import."
    Write-Warn "The cert may have been imported with a name-based ID (hash) rather than a numeric one,"
    Write-Warn "or the import may have failed. Review the import output and the cert list above."
}

# --------------------------------------------------------------------------- #
# 9. Optional: activate as web-server-cert
# --------------------------------------------------------------------------- #
if ($newCertId) {
    Write-Host ""
    $activate = Read-Host "Activate cert $newCertId as the Firebox web-server-cert? [y/N]"
    if ($activate -match '^[Yy]') {
        Write-Step "Activating web-server-cert"

        $cfgOut  = Invoke-WgCommand 'configure'
        Write-Raw "configure mode" $cfgOut

        $wsSetOut = Invoke-WgCommand "web-server-cert third-party $newCertId"
        Write-Raw "web-server-cert third-party $newCertId" $wsSetOut

        $exitOut  = Invoke-WgCommand 'exit'
        Write-Raw "exit (back to main mode)" $exitOut

        # Confirm
        $wsOut2 = Invoke-WgCommand 'show web-server-cert'
        Write-Raw "show web-server-cert (after)" $wsOut2
        Write-Ok "Done - review output above to confirm activation"
    }
}

# --------------------------------------------------------------------------- #
# 10. FTP server log + cleanup
# --------------------------------------------------------------------------- #
Write-Step "FTP server log"
foreach ($entry in $rsData.Log) { Write-Host "  $entry" -ForegroundColor DarkGray }
if ($rsData.Error) { Write-Warn "FTP error: $($rsData.Error)" }

# --------------------------------------------------------------------------- #
# 11. Cleanup
# --------------------------------------------------------------------------- #
Write-Step "Cleanup"
$session | Remove-SSHSession | Out-Null
Write-Ok "SSH session closed"

try { $ps.EndInvoke($ftpHandle) } catch { }
$ps.Dispose(); $rs.Close(); $rs.Dispose()
Write-Ok "FTP server runspace disposed"

Write-Host "`n[DONE] Test complete." -ForegroundColor Green
