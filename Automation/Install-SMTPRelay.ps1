#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Yeyland Wutani SMTP Relay - Single-File Installer
    Installs the SMTP Relay as a Windows service.

.DESCRIPTION
    Self-contained installer that:
    1. Checks prerequisites (PowerShell version, port availability)
    2. Optionally creates the Entra ID app registration with Mail.Send
    3. Generates the configuration file
    4. Extracts embedded relay script and uninstaller
    5. Downloads NSSM (Non-Sucking Service Manager) for service hosting
    6. Creates the "SMTP Relay" Windows service
    7. Configures firewall rules
    8. Starts the service and runs a connectivity test

.PARAMETER InstallPath
    Installation directory. Default: C:\SMTPRelay

.PARAMETER SmtpPort
    SMTP listen port. Default: 25

.PARAMETER SkipAppRegistration
    Skip Entra app registration (use if already created).

.EXAMPLE
    .\Install-SMTPRelay.ps1
    .\Install-SMTPRelay.ps1 -InstallPath "D:\Services\SMTPRelay" -SmtpPort 2525

.NOTES
    Yeyland Wutani LLC - Building Better Systems
    Version: 1.0.0
    All components embedded - no additional files required.
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "SMTP Relay",
    [string]$AppName,
    [string]$InstallPath,
    [int]$SmtpPort = 25,
    [switch]$SkipAppRegistration
)

# Derive defaults from ServiceName if not explicitly provided
if (-not $AppName) { $AppName = $ServiceName }
# Create safe path name from service name (remove spaces, special chars)
$SafeServiceName = $ServiceName -replace '[^a-zA-Z0-9]', ''
if (-not $InstallPath) { $InstallPath = "C:\$SafeServiceName" }

$ErrorActionPreference = "Stop"
# $ServiceName is now a parameter (default: "Yeyland Wutani SMTP Relay")
$NssmVersion = "2.24"
$ScriptVersion = "1.0.0"

# ============================================================================
# EMBEDDED SCRIPTS
# ============================================================================

$EmbeddedRelayScript = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Yeyland Wutani SMTP Relay - SMTP to Microsoft 365 Graph API relay service.

.DESCRIPTION
    Listens for inbound SMTP connections from devices (scanners, printers,
    LOB apps, monitoring systems) and relays messages to Microsoft 365
    through the Graph API using an Entra ID app registration.

    Designed to run as a Windows service via NSSM.

    Architecture:
      Device -> SMTP (port 25) -> This Script -> OAuth2 -> Graph API -> M365

.NOTES
    Yeyland Wutani LLC - Building Better Systems
    Service Name: SMTP Relay
#>

param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "config.json")
)

$ErrorActionPreference = "Stop"
$script:ServiceRunning = $true

# ============================================================================
# REGION: Helper Functions (PowerShell 5.1 Compatibility)
# ============================================================================

function Coalesce {
    # Returns the first non-null/non-empty value (replaces ?? operator)
    param([object]$Value, [object]$Default)
    if ($null -ne $Value -and $Value -ne "") { return $Value }
    return $Default
}

# ============================================================================
# REGION: Configuration
# ============================================================================

function Import-RelayConfig {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path. Run Install-SMTPRelay.ps1 first."
    }

    $config = Get-Content $Path -Raw | ConvertFrom-Json

    # Validate required fields
    $required = @("TenantId", "ClientId", "ClientSecret", "SendAsAddress")
    foreach ($field in $required) {
        if ([string]::IsNullOrWhiteSpace($config.$field) -or $config.$field -match '^YOUR-') {
            throw "Configuration field '$field' is not set. Edit $Path and restart the service."
        }
    }

    return $config
}

# ============================================================================
# REGION: Logging
# ============================================================================

$script:LogLevels = @{ DEBUG = 0; INFO = 1; WARN = 2; ERROR = 3 }

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("DEBUG","INFO","WARN","ERROR")][string]$Level = "INFO",
        [string]$SessionId
    )

    $configLevel = Coalesce $script:Config.LogLevel "INFO"
    if ($script:LogLevels[$Level] -lt $script:LogLevels[$configLevel]) { return }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $prefix = if ($SessionId) { "[$ts] [$Level] [$SessionId]" } else { "[$ts] [$Level]" }
    $line = "$prefix $Message"

    # Console output (visible in NSSM logs and debug sessions)
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "DEBUG" { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line }
    }

    # File output
    try {
        $logDir = Coalesce $script:Config.LogDirectory (Join-Path $PSScriptRoot "Logs")
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $logPrefix = (Coalesce $script:Config.ServiceName "YW SMTP Relay") -replace '[^a-zA-Z0-9]', ''
        $logFile = Join-Path $logDir ("{0}_{1}.log" -f $logPrefix, (Get-Date -Format "yyyyMMdd"))
        [System.IO.File]::AppendAllText($logFile, "$line`r`n")
    }
    catch { }
}

function Invoke-LogCleanup {
    try {
        $logDir = Coalesce $script:Config.LogDirectory (Join-Path $PSScriptRoot "Logs")
        $retention = Coalesce $script:Config.LogRetentionDays 30
        $cutoff = (Get-Date).AddDays(-$retention)
        $logPrefix = (Coalesce $script:Config.ServiceName "YW SMTP Relay") -replace '[^a-zA-Z0-9]', ''
        Get-ChildItem -Path $logDir -Filter "$($logPrefix)_*.log" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Log cleanup complete (removed files older than $retention days)" -Level DEBUG
    }
    catch { Write-Log "Log cleanup error: $_" -Level WARN }
}

function Test-SecretExpiryReminder {
    <#
    .SYNOPSIS
        Checks if the client secret is expiring soon and sends a one-time reminder email.
        Called at service startup. Only sends ONE reminder (no spam).
    #>
    try {
        # Check if reminder is configured
        if (-not $script:Config.ReminderEmail -or [string]::IsNullOrWhiteSpace($script:Config.ReminderEmail)) {
            Write-Log "Secret expiry reminder not configured (no ReminderEmail)" -Level DEBUG
            return
        }

        # Check if reminder was already sent
        if ($script:Config.ReminderSent -eq $true) {
            Write-Log "Secret expiry reminder already sent - skipping" -Level DEBUG
            return
        }

        # Check if we have an expiry date
        $expiryDateStr = $script:Config.ClientSecretExpiry
        if (-not $expiryDateStr) {
            Write-Log "No ClientSecretExpiry configured - cannot check expiry" -Level DEBUG
            return
        }

        # Parse expiry date
        try {
            $expiryDate = [datetime]::Parse($expiryDateStr)
        }
        catch {
            Write-Log "Could not parse ClientSecretExpiry '$expiryDateStr': $_" -Level WARN
            return
        }

        # Check if we're within 1 month of expiry
        $reminderDate = $expiryDate.AddMonths(-1)
        $today = Get-Date

        if ($today -lt $reminderDate) {
            $daysUntilReminder = ($reminderDate - $today).Days
            Write-Log "Secret expiry reminder will be sent in $daysUntilReminder days (expiry: $($expiryDate.ToString('yyyy-MM-dd')))" -Level DEBUG
            return
        }

        # Time to send the reminder!
        Write-Log "Client secret expiring soon - sending reminder email to $($script:Config.ReminderEmail)" -Level INFO

        $daysUntilExpiry = [Math]::Max(0, ($expiryDate - $today).Days)
        $svcName = Coalesce $script:Config.ServiceName "SMTP Relay"
        $serverName = $env:COMPUTERNAME

        $subject = "[ACTION REQUIRED] $svcName - Client Secret Expiring in $daysUntilExpiry days"
        $body = @"
ATTENTION: Client Secret Expiration Warning

The client secret for your $svcName service is expiring soon.

Server:          $serverName
Service:         $svcName
Expiry Date:     $($expiryDate.ToString('yyyy-MM-dd'))
Days Remaining:  $daysUntilExpiry

ACTION REQUIRED:
1. Log into the Azure Portal (portal.azure.com)
2. Navigate to Entra ID > App registrations
3. Find the app: $svcName
4. Go to Certificates & secrets
5. Create a new client secret
6. Update the config.json file on $serverName with the new secret
7. Restart the $svcName service

Config file location: $(Join-Path $PSScriptRoot 'config.json')

This is a one-time reminder. You will not receive this alert again.

--
$svcName Automated Alert
Yeyland Wutani LLC - Building Better Systems
"@

        # Send the reminder using Graph API (reusing existing token infrastructure)
        $token = Get-GraphToken

        $message = @{
            subject = $subject
            body = @{
                contentType = "text"
                content = $body
            }
            toRecipients = @(
                @{ emailAddress = @{ address = $script:Config.ReminderEmail } }
            )
        }

        $payload = @{
            message = $message
            saveToSentItems = $false
        } | ConvertTo-Json -Depth 10 -Compress

        $sender = $script:Config.SendAsAddress
        $uri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($sender))/sendMail"

        $headers = @{
            Authorization = "Bearer $token"
            "Content-Type" = "application/json; charset=utf-8"
        }

        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -ErrorAction Stop
        Write-Log "Secret expiry reminder sent successfully to $($script:Config.ReminderEmail)" -Level INFO

        # Mark reminder as sent (update config file to persist this)
        $script:Config.ReminderSent = $true
        try {
            $configFilePath = Join-Path $PSScriptRoot "config.json"
            $script:Config | ConvertTo-Json -Depth 3 | Set-Content $configFilePath -Encoding UTF8
            Write-Log "Reminder flag saved to config - will not send again" -Level DEBUG
        }
        catch {
            Write-Log "Could not save reminder flag to config: $_" -Level WARN
        }
    }
    catch {
        Write-Log "Secret expiry reminder check failed: $_" -Level WARN
        # Don't fail the service startup for reminder issues
    }
}


# ============================================================================

function Test-SmtpAuth {
    <#
    .SYNOPSIS
        Validates SMTP authentication credentials.
        Returns $true if valid, $false otherwise.
    #>
    param(
        [string]$Username,
        [string]$Password
    )
    
    # Check if auth is configured
    if (-not $script:Config.SmtpAuthEnabled) {
        return $true  # Auth not required
    }
    
    $configUser = $script:Config.SmtpAuthUsername
    $configPass = $script:Config.SmtpAuthPassword
    
    if ([string]::IsNullOrWhiteSpace($configUser) -or [string]::IsNullOrWhiteSpace($configPass)) {
        Write-Log "SMTP Auth enabled but no credentials configured - denying" -Level WARN
        return $false
    }
    
    # Simple string comparison (case-sensitive for password, case-insensitive for username)
    $userMatch = $Username -ieq $configUser
    $passMatch = $Password -ceq $configPass
    
    return ($userMatch -and $passMatch)
}

function Test-SmtpAuthRequired {
    <#
    .SYNOPSIS
        Returns $true if SMTP authentication is required for this relay.
    #>
    return ($script:Config.SmtpAuthEnabled -eq $true)
}

# REGION: IP Access Control
# ============================================================================

function Test-IpAllowed {
    param([string]$ClientIp)

    # Normalize IPv6-mapped IPv4 (::ffff:x.x.x.x -> x.x.x.x)
    if ($ClientIp -match '^::ffff:(\d+\.\d+\.\d+\.\d+)$') { $ClientIp = $Matches[1] }

    # Always allow localhost connections (127.0.0.1, ::1, and loopback variants)
    $localhostPatterns = @('127.0.0.1', '::1', 'localhost')
    if ($ClientIp -in $localhostPatterns -or $ClientIp -match '^127\.') {
        return $true
    }

    $allowList = $script:Config.AllowedClients
    if (-not $allowList -or $allowList.Count -eq 0) { return $true }

    foreach ($entry in $allowList) {
        if ($entry -match '/') {
            # CIDR match
            try {
                $parts = $entry -split '/'
                $networkIp = [System.Net.IPAddress]::Parse($parts[0])
                $maskBits = [int]$parts[1]
                $clientAddr = [System.Net.IPAddress]::Parse($ClientIp)

                $netBytes = $networkIp.GetAddressBytes()
                $cliBytes = $clientAddr.GetAddressBytes()

                # Only compare IPv4 to IPv4
                if ($netBytes.Length -ne $cliBytes.Length) { continue }
                if ($netBytes.Length -ne 4) { continue }  # Skip IPv6 for now

                # Convert to UInt32 (big-endian network byte order)
                [Array]::Reverse($netBytes)
                [Array]::Reverse($cliBytes)

                # Use BitConverter for proper unsigned handling
                $netInt = [BitConverter]::ToUInt32($netBytes, 0)
                $cliInt = [BitConverter]::ToUInt32($cliBytes, 0)

                # Calculate subnet mask properly for PS 5.1
                # Avoid signed integer overflow by using Math.Pow
                if ($maskBits -eq 0) {
                    $mask = [uint32]0
                }
                elseif ($maskBits -eq 32) {
                    $mask = [uint32]::MaxValue
                }
                else {
                    # Calculate mask: /24 = 0xFFFFFF00 (4294967040)
                    # Formula: 2^32 - 2^(32-maskBits)
                    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $maskBits))
                }

                if (($netInt -band $mask) -eq ($cliInt -band $mask)) {
                    return $true
                }
            }
            catch {
                Write-Log "ACL parse error for '$entry': $_" -Level WARN
                continue
            }
        }
        else {
            # Exact IP match
            if ($ClientIp -eq $entry) { return $true }
        }
    }

    return $false
}

# ============================================================================
# REGION: OAuth2 Token Management
# ============================================================================

$script:TokenCache = @{ AccessToken = $null; ExpiresAt = [datetime]::MinValue }

function Get-GraphToken {
    # Return cached token if still valid (5 min buffer)
    if ($script:TokenCache.AccessToken -and $script:TokenCache.ExpiresAt -gt (Get-Date).AddMinutes(5)) {
        Write-Log "Using cached token (expires $($script:TokenCache.ExpiresAt))" -Level DEBUG
        return $script:TokenCache.AccessToken
    }

    Write-Log "Acquiring new Graph API access token..." -Level INFO

    $tokenUrl = "https://login.microsoftonline.com/$($script:Config.TenantId)/oauth2/v2.0/token"

    $body = @{
        client_id     = $script:Config.ClientId
        client_secret = $script:Config.ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $script:TokenCache.AccessToken = $response.access_token
        $script:TokenCache.ExpiresAt = (Get-Date).AddSeconds($response.expires_in - 60)
        Write-Log "Token acquired (expires $($script:TokenCache.ExpiresAt))" -Level INFO
        return $response.access_token
    }
    catch {
        Write-Log "Token acquisition FAILED: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# ============================================================================
# REGION: Graph API Send
# ============================================================================

function Send-GraphMail {
    param(
        [string]$From,
        [string[]]$To,
        [string[]]$Cc,
        [string[]]$Bcc,
        [string]$Subject,
        [string]$Body,
        [string]$BodyType = "text",
        [array]$Attachments,
        [string]$SessionId
    )

    $token = Get-GraphToken

    # Determine sender
    $sender = if ($script:Config.ForceSendAs -eq $true) {
        $script:Config.SendAsAddress
    } else {
        if ($From) { $From } else { $script:Config.SendAsAddress }
    }

    # Build message payload
    $message = @{
        subject      = Coalesce $Subject "(No Subject)"
        body         = @{
            contentType = if ($BodyType -eq "html") { "html" } else { "text" }
            content     = Coalesce $Body ""
        }
        toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    }

    if ($Cc -and $Cc.Count -gt 0) {
        $message.ccRecipients = @($Cc | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    }
    if ($Bcc -and $Bcc.Count -gt 0) {
        $message.bccRecipients = @($Bcc | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    }

    # Attachments
    if ($Attachments -and $Attachments.Count -gt 0) {
        $message.attachments = @($Attachments | ForEach-Object {
            @{
                "@odata.type" = "#microsoft.graph.fileAttachment"
                name          = $_.Name
                contentType   = $_.ContentType
                contentBytes  = $_.Base64
            }
        })
    }

    $payload = @{
        message         = $message
        saveToSentItems = if ($script:Config.SaveToSentItems) { $true } else { $false }
    } | ConvertTo-Json -Depth 10 -Compress

    $uri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($sender))/sendMail"

    Write-Log "Sending via Graph: From=[$sender] To=[$($To -join ', ')] Subject=[$Subject]" -Level INFO -SessionId $SessionId

    try {
        $headers = @{
            Authorization  = "Bearer $token"
            "Content-Type" = "application/json; charset=utf-8"
        }
        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -ErrorAction Stop
        Write-Log "Message sent successfully" -Level INFO -SessionId $SessionId
        return $true
    }
    catch {
        $errDetail = $_.Exception.Message
        $statusCode = ""

        # Try to get the actual Graph error response
        if ($_.Exception.Response) {
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $errStream = $_.Exception.Response.GetResponseStream()
                $errReader = [System.IO.StreamReader]::new($errStream)
                $errBody = $errReader.ReadToEnd()
                $errReader.Dispose()

                $graphErr = $errBody | ConvertFrom-Json
                $errDetail = "HTTP $statusCode - $($graphErr.error.code): $($graphErr.error.message)"
            } catch { }
        }
        elseif ($_.ErrorDetails.Message) {
            try {
                $graphErr = $_.ErrorDetails.Message | ConvertFrom-Json
                $errDetail = "$($graphErr.error.code): $($graphErr.error.message)"
            } catch { }
        }

        Write-Log "Graph API FAILED: $errDetail" -Level ERROR -SessionId $SessionId
        return $false
    }
}

# ============================================================================
# REGION: MIME Parsing
# ============================================================================

function ConvertFrom-MimeMessage {
    <#
    .SYNOPSIS
        Parses raw SMTP DATA content into structured components.
        Handles plain text, HTML, multipart MIME, and attachments.
    #>
    param(
        [string]$RawData,
        [string[]]$EnvelopeTo,
        [string]$EnvelopeFrom
    )

    $result = @{
        From        = $EnvelopeFrom
        To          = @()
        Cc          = @()
        Bcc         = @()
        Subject     = ""
        Body        = ""
        BodyType    = "text"
        Attachments = @()
    }

    # Split headers from body at first blank line
    $headerEnd = -1
    $lines = $RawData -split "`r`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -eq "" -or $lines[$i] -match '^\s*$') {
            $headerEnd = $i
            break
        }
    }

    if ($headerEnd -lt 0) {
        $result.Body = $RawData
        $result.To = $EnvelopeTo
        return $result
    }

    $headerLines = $lines[0..($headerEnd - 1)]
    $bodyContent = ($lines[($headerEnd + 1)..($lines.Count - 1)]) -join "`r`n"

    # Parse headers (unfold continuation lines)
    $headers = @{}
    $currentHeader = ""
    $currentValue = ""
    foreach ($line in $headerLines) {
        if ($line -match '^\s+(.*)$' -and $currentHeader) {
            # Continuation line
            $currentValue += " " + $Matches[1].Trim()
        }
        else {
            if ($currentHeader) { $headers[$currentHeader] = $currentValue }
            if ($line -match '^([^:]+):\s*(.*)$') {
                $currentHeader = $Matches[1].Trim()
                $currentValue = $Matches[2].Trim()
            }
        }
    }
    if ($currentHeader) { $headers[$currentHeader] = $currentValue }

    # Extract addresses from headers
    $emailRegex = [regex]'[\w\.\-\+]+@[\w\.\-]+'

    if ($headers["From"]) {
        $fromMatch = $emailRegex.Match($headers["From"])
        if ($fromMatch.Success) { $result.From = $fromMatch.Value }
    }
    if ($headers["To"]) {
        $result.To = @($emailRegex.Matches($headers["To"]) | ForEach-Object { $_.Value })
    }
    if ($headers["Cc"]) {
        $result.Cc = @($emailRegex.Matches($headers["Cc"]) | ForEach-Object { $_.Value })
    }
    if ($headers["Subject"]) {
        $result.Subject = Decode-MimeHeader $headers["Subject"]
    }

    # Fall back to envelope recipients
    if ($result.To.Count -eq 0) { $result.To = $EnvelopeTo }

    # Determine BCC (in envelope but not in headers)
    $headerAddrs = @($result.To) + @($result.Cc) | ForEach-Object { $_.ToLower() }
    $result.Bcc = @($EnvelopeTo | Where-Object { $_.ToLower() -notin $headerAddrs })

    # Parse body based on content type
    $contentType = $headers["Content-Type"]
    $transferEncoding = $headers["Content-Transfer-Encoding"]

    if ($contentType -match 'multipart/' -and $contentType -match 'boundary="?([^";]+)"?') {
        $boundary = $Matches[1]
        Parse-MimeParts -RawBody $bodyContent -Boundary $boundary -Result $result
    }
    else {
        $result.Body = Decode-MimeBody -Content $bodyContent -Encoding $transferEncoding -ContentType $contentType
        if ($contentType -match 'text/html') { $result.BodyType = "html" }
    }

    return $result
}

function Decode-MimeHeader {
    param([string]$Value)
    # RFC 2047 encoded-word: =?charset?B/Q?encoded?=
    return [regex]::Replace($Value, '=\?([^?]+)\?([BbQq])\?([^?]+)\?=', {
        param($m)
        try {
            $charset = [System.Text.Encoding]::GetEncoding($m.Groups[1].Value)
            if ($m.Groups[2].Value.ToUpper() -eq 'B') {
                return $charset.GetString([Convert]::FromBase64String($m.Groups[3].Value))
            }
            else {
                $text = $m.Groups[3].Value -replace '_', ' '
                $text = [regex]::Replace($text, '=([0-9A-Fa-f]{2})', { [char][Convert]::ToInt32($args[0].Groups[1].Value, 16) })
                return $text
            }
        }
        catch { return $m.Value }
    })
}

function Decode-MimeBody {
    param([string]$Content, [string]$Encoding, [string]$ContentType)

    $encodingVal = Coalesce $Encoding ""

    switch ($encodingVal.Trim().ToLower()) {
        "base64" {
            try {
                $bytes = [Convert]::FromBase64String(($Content -replace '\s', ''))
                $charset = "utf-8"
                if ($ContentType -match 'charset="?([^";]+)"?') { $charset = $Matches[1] }
                return [System.Text.Encoding]::GetEncoding($charset).GetString($bytes)
            }
            catch { return $Content }
        }
        "quoted-printable" {
            $decoded = $Content -replace '=\r?\n', ''
            $decoded = [regex]::Replace($decoded, '=([0-9A-Fa-f]{2})', { [char][Convert]::ToInt32($args[0].Groups[1].Value, 16) })
            return $decoded
        }
        default { return $Content }
    }
}

function Parse-MimeParts {
    param([string]$RawBody, [string]$Boundary, [hashtable]$Result)

    $parts = $RawBody -split "--$([regex]::Escape($Boundary))"

    foreach ($part in $parts) {
        $part = $part.Trim("`r`n")
        if (-not $part -or $part -eq '--') { continue }

        # Split part header from part body
        $partLines = $part -split "`r`n"
        $blankIdx = -1
        for ($i = 0; $i -lt $partLines.Count; $i++) {
            if ($partLines[$i] -match '^\s*$') { $blankIdx = $i; break }
        }
        if ($blankIdx -lt 0) { continue }

        $partHeaderLines = $partLines[0..($blankIdx - 1)]
        $partBody = ($partLines[($blankIdx + 1)..($partLines.Count - 1)]) -join "`r`n"

        # Parse part headers
        $partHeaders = @{}
        $ch = ""; $cv = ""
        foreach ($line in $partHeaderLines) {
            if ($line -match '^\s+(.*)$' -and $ch) { $cv += " " + $Matches[1].Trim() }
            else {
                if ($ch) { $partHeaders[$ch] = $cv }
                if ($line -match '^([^:]+):\s*(.*)$') { $ch = $Matches[1].Trim(); $cv = $Matches[2].Trim() }
            }
        }
        if ($ch) { $partHeaders[$ch] = $cv }

        $pct = Coalesce $partHeaders["Content-Type"] ""
        $pcd = Coalesce $partHeaders["Content-Disposition"] ""
        $pte = Coalesce $partHeaders["Content-Transfer-Encoding"] ""

        # Recurse into nested multipart
        if ($pct -match 'multipart/' -and $pct -match 'boundary="?([^";]+)"?') {
            Parse-MimeParts -RawBody $partBody -Boundary $Matches[1] -Result $Result
            continue
        }

        # Attachment detection
        if ($pcd -match 'attachment' -or ($pcd -match 'filename' -and $pct -notmatch 'text/')) {
            $filename = "attachment.bin"
            if ($pcd -match 'filename="?([^";]+)"?') { $filename = $Matches[1] }
            elseif ($pct -match 'name="?([^";]+)"?') { $filename = $Matches[1] }

            $mimeType = "application/octet-stream"
            if ($pct -match '^([^;]+)') { $mimeType = $Matches[1].Trim() }

            if ($pte.Trim().ToLower() -eq "base64") {
                $b64 = ($partBody -replace '\s', '')
            }
            else {
                $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($partBody))
            }

            $Result.Attachments += @{
                Name        = $filename
                ContentType = $mimeType
                Base64      = $b64
            }
            continue
        }

        # Body content (prefer HTML)
        if ($pct -match 'text/html' -and $Result.BodyType -ne "html") {
            $Result.Body = Decode-MimeBody -Content $partBody -Encoding $pte -ContentType $pct
            $Result.BodyType = "html"
        }
        elseif ($pct -match 'text/plain' -and -not $Result.Body) {
            $Result.Body = Decode-MimeBody -Content $partBody -Encoding $pte -ContentType $pct
            $Result.BodyType = "text"
        }
    }
}

# ============================================================================
# REGION: SMTP Protocol Handler
# ============================================================================

function Start-SmtpSession {
    <#
    .SYNOPSIS
        Handles a single SMTP client session. Implements the SMTP protocol
        state machine and relays accepted messages through Graph API.
    #>
    param([System.Net.Sockets.TcpClient]$Client)

    $sessionId = [guid]::NewGuid().ToString("N").Substring(0, 8)
    $script:authenticated = $false  # Track SMTP AUTH state for this session
    $clientEp = $Client.Client.RemoteEndPoint -as [System.Net.IPEndPoint]
    $clientIp = if ($clientEp) { $clientEp.Address.ToString() } else { "unknown" }

    # Normalize IPv6-mapped IPv4
    if ($clientIp -match '^::ffff:(\d+\.\d+\.\d+\.\d+)$') { $clientIp = $Matches[1] }

    Write-Log "Connection from $clientIp" -Level INFO -SessionId $sessionId

    # IP ACL check
    if (-not (Test-IpAllowed $clientIp)) {
        Write-Log "REJECTED - IP not in allowlist: $clientIp" -Level WARN -SessionId $sessionId
        try {
            $stream = $Client.GetStream()
            $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
            $writer.AutoFlush = $true
            $writer.WriteLine("554 5.7.1 Access denied")
            $writer.Dispose()
        } catch { }
        $Client.Close()
        return
    }

    $stream = $null
    $reader = $null
    $writer = $null

    try {
        $stream = $Client.GetStream()

        # Set timeouts
        $timeoutSec = Coalesce $script:Config.SessionTimeoutSec 60
        $stream.ReadTimeout = $timeoutSec * 1000
        $stream.WriteTimeout = 30000

        # Use ASCII encoding - SMTP standard (no BOM issues)
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
        $writer.AutoFlush = $true
        $writer.NewLine = "`r`n"

        # Session state
        $mailFrom = ""
        $rcptTo = [System.Collections.Generic.List[string]]::new()
        $hostname = $env:COMPUTERNAME

        # Send SMTP greeting immediately
        Write-Log "Sending greeting..." -Level DEBUG -SessionId $sessionId
        $svcName = Coalesce $script:Config.ServiceName "SMTP Relay"
        $writer.WriteLine("220 $hostname $svcName Service Ready")
        Write-Log "S: 220 $hostname $svcName Service Ready" -Level DEBUG -SessionId $sessionId

        # Command loop
        while ($Client.Connected -and $script:ServiceRunning) {
            $line = $null
            try {
                $line = $reader.ReadLine()
            }
            catch [System.IO.IOException] {
                Write-Log "Read timeout or connection closed" -Level DEBUG -SessionId $sessionId
                break
            }

            if ($null -eq $line) {
                Write-Log "Client disconnected (null read)" -Level DEBUG -SessionId $sessionId
                break
            }

            $line = $line.Trim()
            if ($line -eq "") { continue }  # Ignore blank lines

            Write-Log "C: $line" -Level DEBUG -SessionId $sessionId

            # Extract command (first word)
            $cmd = ($line -split '\s', 2)[0].ToUpper()

            switch -Regex ($cmd) {
                '^(EHLO|HELO)$' {
                    $mailFrom = ""; $rcptTo.Clear()
                    if ($cmd -eq "EHLO") {
                        $maxSize = Coalesce $script:Config.MaxMessageSizeBytes 36700160
                        $writer.WriteLine("250-$hostname Hello")
                        $writer.WriteLine("250-SIZE $maxSize")
                        $writer.WriteLine("250-8BITMIME")
                        $writer.WriteLine("250-PIPELINING")
                        $writer.WriteLine("250-ENHANCEDSTATUSCODES")
                        # Advertise AUTH if enabled
                        if (Test-SmtpAuthRequired) {
                            $writer.WriteLine("250-AUTH PLAIN LOGIN")
                        }
                        $writer.WriteLine("250 OK")
                        Write-Log "S: 250 EHLO response sent" -Level DEBUG -SessionId $sessionId
                    }
                    else {
                        $writer.WriteLine("250 $hostname Hello")
                        Write-Log "S: 250 HELO response sent" -Level DEBUG -SessionId $sessionId
                    }
                }
                # AUTH command handler
                '^AUTH$' {
                    if (-not (Test-SmtpAuthRequired)) {
                        $writer.WriteLine("503 5.5.1 AUTH not available")
                        Write-Log "AUTH attempted but not enabled" -Level DEBUG -SessionId $sessionId
                        break
                    }
                    
                    Write-Log "AUTH command received: $line" -Level DEBUG -SessionId $sessionId
                    
                    $authMethod = ""
                    # -match is case-insensitive by default, so this matches LOGIN/login/Login/PLAIN/plain/Plain
                    if ($line -match 'AUTH\s+(PLAIN|LOGIN)(?:\s+(.*))?') {
                        $authMethod = $Matches[1].ToUpper()
                        $initialResponse = if ($Matches[2]) { $Matches[2] } else { "" }
                    }
                    
                    Write-Log "Parsed AUTH method: $authMethod, has initial response: $(if ($initialResponse) { 'YES' } else { 'NO' })" -Level DEBUG -SessionId $sessionId
                    
                    if (-not $authMethod) {
                        $writer.WriteLine("504 5.5.4 Unrecognized authentication type")
                        Write-Log "Could not parse AUTH method from: $line" -Level WARN -SessionId $sessionId
                        continue
                    }
                    
                    switch ($authMethod) {
                        "PLAIN" {
                            # AUTH PLAIN can have credentials inline or prompted
                            Write-Log "AUTH PLAIN initiated" -Level DEBUG -SessionId $sessionId
                            
                            if ($initialResponse) {
                                $authData = $initialResponse
                                Write-Log "AUTH PLAIN with initial response (length: $($authData.Length))" -Level DEBUG -SessionId $sessionId
                            } else {
                                $writer.WriteLine("334 ")  # Empty challenge for PLAIN
                                $authData = $reader.ReadLine()
                                Write-Log "AUTH PLAIN response received (length: $($authData.Length))" -Level DEBUG -SessionId $sessionId
                            }
                            
                            try {
                                # PLAIN format: base64(\0username\0password)
                                $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($authData))
                                $parts = $decoded -split "\0"
                                # Parts: [0]=authzid (often empty), [1]=username, [2]=password
                                $authUser = if ($parts.Count -ge 2) { $parts[1] } else { "" }
                                $authPass = if ($parts.Count -ge 3) { $parts[2] } else { "" }
                                
                                Write-Log "AUTH PLAIN decoded: username=[$authUser], password length=$($authPass.Length), parts=$($parts.Count)" -Level DEBUG -SessionId $sessionId
                                
                                if (Test-SmtpAuth -Username $authUser -Password $authPass) {
                                    $script:authenticated = $true
                                    $writer.WriteLine("235 2.7.0 Authentication successful")
                                    Write-Log "AUTH PLAIN successful for user: $authUser" -Level INFO -SessionId $sessionId
                                } else {
                                    $writer.WriteLine("535 5.7.8 Authentication credentials invalid")
                                    Write-Log "AUTH PLAIN failed for user: [$authUser] - expected username in config: [$($script:Config.SmtpAuthUsername)]" -Level WARN -SessionId $sessionId
                                }
                            } catch {
                                $writer.WriteLine("501 5.5.4 Invalid AUTH PLAIN data")
                                Write-Log "AUTH PLAIN decode error: $_" -Level WARN -SessionId $sessionId
                            }
                        }
                        "LOGIN" {
                            # AUTH LOGIN supports two modes per RFC 4954:
                            # Mode 1: AUTH LOGIN
                            #         S: 334 VXNlcm5hbWU6  (Username:)
                            #         C: <username-base64>
                            #         S: 334 UGFzc3dvcmQ6  (Password:)
                            #         C: <password-base64>
                            #
                            # Mode 2: AUTH LOGIN <username-base64>
                            #         S: 334 UGFzc3dvcmQ6  (Password:)
                            #         C: <password-base64>
                            #
                            # We support both modes
                            
                            Write-Log "AUTH LOGIN initiated (initial response: $(if ($initialResponse) { 'YES (length: ' + $initialResponse.Length + ')' } else { 'NO' }))" -Level DEBUG -SessionId $sessionId
                            
                            # Get username (either from initial response or prompt for it)
                            if ($initialResponse) {
                                $userB64 = $initialResponse
                                Write-Log "Username provided in AUTH command (base64 length: $($userB64.Length))" -Level DEBUG -SessionId $sessionId
                            } else {
                                $writer.WriteLine("334 VXNlcm5hbWU6")  # "Username:" in base64
                                $userB64 = $reader.ReadLine()
                                Write-Log "Username prompted and received (base64 length: $($userB64.Length))" -Level DEBUG -SessionId $sessionId
                            }
                            
                            # Always prompt for password
                            $writer.WriteLine("334 UGFzc3dvcmQ6")  # "Password:" in base64
                            $passB64 = $reader.ReadLine()
                            Write-Log "Password received (base64 length: $($passB64.Length))" -Level DEBUG -SessionId $sessionId
                            
                            try {
                                $authUser = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userB64))
                                $authPass = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($passB64))
                                
                                Write-Log "Decoded username: [$authUser], password length: $($authPass.Length)" -Level DEBUG -SessionId $sessionId
                                
                                if (Test-SmtpAuth -Username $authUser -Password $authPass) {
                                    $script:authenticated = $true
                                    $writer.WriteLine("235 2.7.0 Authentication successful")
                                    Write-Log "AUTH LOGIN successful for user: $authUser" -Level INFO -SessionId $sessionId
                                } else {
                                    $writer.WriteLine("535 5.7.8 Authentication credentials invalid")
                                    Write-Log "AUTH LOGIN failed for user: [$authUser] - expected username in config: [$($script:Config.SmtpAuthUsername)]" -Level WARN -SessionId $sessionId
                                }
                            } catch {
                                $writer.WriteLine("501 5.5.4 Invalid AUTH LOGIN data")
                                Write-Log "AUTH LOGIN decode error: $_" -Level WARN -SessionId $sessionId
                            }
                        }
                        default {
                            $writer.WriteLine("504 5.5.4 Unrecognized authentication type")
                            Write-Log "Unknown AUTH method attempted: $authMethod" -Level WARN -SessionId $sessionId
                        }
                    }
                    # Don't fall through to other cases
                    continue
                }



                '^MAIL$' {
                    # Check if authentication is required but not completed
                    if ((Test-SmtpAuthRequired) -and -not $script:authenticated) {
                        $writer.WriteLine("530 5.7.0 Authentication required")
                        Write-Log "MAIL FROM rejected - authentication required" -Level WARN -SessionId $sessionId
                        break
                    }
                    # MAIL FROM:<address> [SIZE=xxx]
                    $mailFrom = ""
                    if ($line -match '<([^>]*)>') { $mailFrom = $Matches[1] }
                    elseif ($line -match 'FROM:\s*(\S+)') { $mailFrom = $Matches[1] }
                    $rcptTo.Clear()
                    $writer.WriteLine("250 2.1.0 Sender OK")
                    Write-Log "MAIL FROM: $mailFrom" -Level DEBUG -SessionId $sessionId
                }

                '^RCPT$' {
                    # RCPT TO:<address>
                    $addr = ""
                    if ($line -match '<([^>]+)>') { $addr = $Matches[1] }
                    elseif ($line -match 'TO:\s*(\S+)') { $addr = $Matches[1] }

                    if (-not $addr -or $addr -notmatch '@') {
                        $writer.WriteLine("501 5.1.3 Invalid recipient address")
                        Write-Log "Invalid RCPT rejected: $addr" -Level DEBUG -SessionId $sessionId
                        continue
                    }

                    $maxRcpt = Coalesce $script:Config.MaxRecipients 500
                    if ($rcptTo.Count -ge $maxRcpt) {
                        $writer.WriteLine("452 4.5.3 Too many recipients")
                        continue
                    }

                    $rcptTo.Add($addr)
                    $writer.WriteLine("250 2.1.5 Recipient OK")
                    Write-Log "RCPT TO: $addr (total: $($rcptTo.Count))" -Level DEBUG -SessionId $sessionId
                }

                '^DATA$' {
                    if ($rcptTo.Count -eq 0) {
                        $writer.WriteLine("503 5.5.1 Need RCPT TO first")
                        continue
                    }

                    $writer.WriteLine("354 Start mail input; end with <CRLF>.<CRLF>")
                    Write-Log "S: 354 - awaiting message data" -Level DEBUG -SessionId $sessionId

                    # Read message data until lone "." on a line
                    $dataBuilder = [System.Text.StringBuilder]::new()
                    while ($true) {
                        $dataLine = $reader.ReadLine()
                        if ($null -eq $dataLine) { break }
                        if ($dataLine -eq ".") { break }

                        # Undo dot-stuffing (RFC 5321 S4.5.2)
                        if ($dataLine.StartsWith("..")) { $dataLine = $dataLine.Substring(1) }
                        [void]$dataBuilder.AppendLine($dataLine)
                    }

                    $rawData = $dataBuilder.ToString()
                    Write-Log "DATA received ($($rawData.Length) bytes, $($rcptTo.Count) recipients)" -Level INFO -SessionId $sessionId

                    # Parse and relay
                    try {
                        $parsed = ConvertFrom-MimeMessage -RawData $rawData -EnvelopeTo $rcptTo.ToArray() -EnvelopeFrom $mailFrom

                        $sendResult = Send-GraphMail `
                            -From $parsed.From `
                            -To $parsed.To `
                            -Cc $parsed.Cc `
                            -Bcc $parsed.Bcc `
                            -Subject $parsed.Subject `
                            -Body $parsed.Body `
                            -BodyType $parsed.BodyType `
                            -Attachments $parsed.Attachments `
                            -SessionId $sessionId

                        if ($sendResult) {
                            $writer.WriteLine("250 2.0.0 Message accepted for delivery")
                            Write-Log "Message relayed successfully" -Level INFO -SessionId $sessionId
                        }
                        else {
                            $writer.WriteLine("451 4.7.0 Temporary relay failure - try again later")
                            Write-Log "Relay failed - told client to retry" -Level ERROR -SessionId $sessionId
                        }
                    }
                    catch {
                        Write-Log "Message processing error: $_" -Level ERROR -SessionId $sessionId
                        $writer.WriteLine("451 4.3.0 Internal relay error")
                    }

                    # Reset for next message in same session
                    $mailFrom = ""; $rcptTo.Clear()
                }

                '^RSET$' {
                    $mailFrom = ""; $rcptTo.Clear()
                    $writer.WriteLine("250 2.0.0 Reset OK")
                    Write-Log "S: 250 Reset OK" -Level DEBUG -SessionId $sessionId
                }

                '^NOOP$' {
                    $writer.WriteLine("250 2.0.0 OK")
                }

                '^VRFY$' {
                    $writer.WriteLine("252 2.5.2 Cannot verify user, but will accept")
                }

                '^QUIT$' {
                    $writer.WriteLine("221 2.0.0 $hostname closing connection")
                    Write-Log "Client sent QUIT - closing" -Level DEBUG -SessionId $sessionId
                    break
                }

                '^STARTTLS$' {
                    # TLS not supported - tell client plainly
                    $writer.WriteLine("454 4.7.0 TLS not available")
                    Write-Log "STARTTLS rejected (not supported)" -Level DEBUG -SessionId $sessionId
                }

                default {
                    $writer.WriteLine("502 5.5.2 Command not recognized")
                    Write-Log "Unknown command: $cmd" -Level DEBUG -SessionId $sessionId
                }
            }
        }
    }
    catch [System.IO.IOException] {
        $innerMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Log "Connection lost: $innerMsg" -Level WARN -SessionId $sessionId
    }
    catch {
        Write-Log "Session error: $($_.Exception.GetType().Name): $($_.Exception.Message)" -Level ERROR -SessionId $sessionId
        Write-Log "Stack: $($_.ScriptStackTrace)" -Level DEBUG -SessionId $sessionId
    }
    finally {
        try { if ($reader) { $reader.Dispose() } } catch { }
        try { if ($writer) { $writer.Dispose() } } catch { }
        try { if ($stream) { $stream.Dispose() } } catch { }
        try { $Client.Close() } catch { }
        Write-Log "Session closed for $clientIp" -Level INFO -SessionId $sessionId
    }
}

# ============================================================================
# REGION: SMTP Listener (Main Loop)
# ============================================================================

function Start-SmtpListener {
    $port = Coalesce $script:Config.SmtpPort 25
    $bindAddr = if ($script:Config.ListenAddress) {
        [System.Net.IPAddress]::Parse($script:Config.ListenAddress)
    } else {
        [System.Net.IPAddress]::Any
    }

    $listener = [System.Net.Sockets.TcpListener]::new($bindAddr, $port)
    $listener.Server.SetSocketOption(
        [System.Net.Sockets.SocketOptionLevel]::Socket,
        [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)

    try {
        $listener.Start()
        Write-Log "=== Yeyland Wutani SMTP Relay started on ${bindAddr}:${port} ===" -Level INFO
        Write-Log "Relay address: $($script:Config.SendAsAddress)" -Level INFO
        Write-Log "SMTP Auth: $(if ($script:Config.SmtpAuthEnabled) { "ENABLED (username: $($script:Config.SmtpAuthUsername))" } else { "DISABLED" })" -Level INFO
        Write-Log "Allowed clients: $(if ($script:Config.AllowedClients.Count -gt 0) { $script:Config.AllowedClients -join ', ' } else { 'ALL (no ACL)' })" -Level INFO

        # Register shutdown handler
        $script:Listener = $listener
        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            $script:ServiceRunning = $false
            if ($script:Listener) { $script:Listener.Stop() }
        } | Out-Null

        # Pre-validate token on startup
        try {
            $null = Get-GraphToken
            Write-Log "Graph API token validation: OK" -Level INFO
        }
        catch {
            Write-Log "WARNING: Initial token acquisition failed - messages will fail until resolved: $_" -Level ERROR
        }

        # Clean old logs on startup
        Invoke-LogCleanup

        # Check for secret expiry and send reminder if needed
        Test-SecretExpiryReminder


        # Main accept loop
        while ($script:ServiceRunning) {
            try {
                if (-not $listener.Pending()) {
                    Start-Sleep -Milliseconds 100
                    continue
                }

                $client = $listener.AcceptTcpClient()

                # Synchronous session handling (sufficient for relay workloads)
                Start-SmtpSession -Client $client
            }
            catch [System.Net.Sockets.SocketException] {
                if ($script:ServiceRunning) {
                    Write-Log "Socket error: $($_.Exception.Message)" -Level WARN
                }
            }
            catch {
                if ($script:ServiceRunning) {
                    Write-Log "Accept error: $_" -Level ERROR
                    Start-Sleep -Seconds 1  # Prevent tight error loops
                }
            }
        }
    }
    finally {
        Write-Log "=== Yeyland Wutani SMTP Relay shutting down ===" -Level INFO
        try { $listener.Stop() } catch { }
    }
}

# ============================================================================
# REGION: Service Entry Point
# ============================================================================

try {
    Write-Host "=========================================="
    Write-Host " Yeyland Wutani SMTP Relay"
    Write-Host " SMTP to Microsoft 365 Graph API"
    Write-Host " Yeyland Wutani LLC - Building Better Systems"
    Write-Host "=========================================="
    Write-Host ""

    # Load config
    $script:Config = Import-RelayConfig -Path $ConfigPath
    Write-Log "Configuration loaded from $ConfigPath" -Level INFO

    # Start the SMTP listener (blocks until service stop)
    Start-SmtpListener
}
catch {
    Write-Host "FATAL: $_" -ForegroundColor Red
    try { Write-Log "FATAL: $_" -Level ERROR } catch { }
    exit 1
}
'@

$EmbeddedUninstallScript = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the SMTP Relay service and optionally removes all files.

.PARAMETER InstallPath
    Installation directory. Default: C:\SMTPRelay

.PARAMETER KeepLogs
    If specified, preserves the Logs directory.

.PARAMETER KeepConfig
    If specified, preserves config.json (useful for reinstalls).

.NOTES
    Yeyland Wutani LLC - Building Better Systems
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "SMTP Relay",
    [string]$InstallPath,
    [switch]$KeepLogs,
    [switch]$KeepConfig
)

$ErrorActionPreference = "Stop"
# Derive InstallPath from ServiceName if not provided
$SafeServiceName = $ServiceName -replace '[^a-zA-Z0-9]', ''
if (-not $InstallPath) { $InstallPath = "C:\$SafeServiceName" }

Write-Host ""
Write-Host "  Yeyland Wutani SMTP Relay - Uninstaller" -ForegroundColor DarkYellow
Write-Host "  ========================================" -ForegroundColor DarkYellow
Write-Host ""

# Confirm
$confirm = Read-Host "This will stop and remove the '$ServiceName' service. Continue? (y/N)"
if ($confirm -notmatch '^[Yy]') { exit 0 }

# Stop service
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  Stopping service..." -NoNewline
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Write-Host " Done" -ForegroundColor Green
}

# Remove service via NSSM
$nssmExe = Join-Path $InstallPath "nssm.exe"
if (Test-Path $nssmExe) {
    Write-Host "  Removing service via NSSM..." -NoNewline
    & $nssmExe remove $ServiceName confirm 2>$null
    Write-Host " Done" -ForegroundColor Green
}
else {
    Write-Host "  Removing service via sc.exe..." -NoNewline
    sc.exe delete $ServiceName 2>$null
    Write-Host " Done" -ForegroundColor Green
}

# Remove firewall rules
Write-Host "  Removing firewall rules..." -NoNewline
Get-NetFirewallRule -DisplayName "$ServiceName*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host " Done" -ForegroundColor Green

# Remove files
if (Test-Path $InstallPath) {
    Write-Host "  Removing installation files..."

    if ($KeepLogs -or $KeepConfig) {
        # Selective removal
        Get-ChildItem -Path $InstallPath -File | ForEach-Object {
            if ($KeepConfig -and $_.Name -eq "config.json") { return }
            Remove-Item $_.FullName -Force
        }
        if (-not $KeepLogs) {
            $logDir = Join-Path $InstallPath "Logs"
            if (Test-Path $logDir) { Remove-Item $logDir -Recurse -Force }
        }
        Write-Host "  Files removed (preserved: $(if ($KeepConfig) { 'config' })$(if ($KeepLogs) { ' logs' }))" -ForegroundColor Green
    }
    else {
        Remove-Item -Path $InstallPath -Recurse -Force
        Write-Host "  Installation directory removed: $InstallPath" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "  Uninstall complete." -ForegroundColor Green
Write-Host ""
'@

# ============================================================================
# Helper Functions
# ============================================================================

function Show-YWBanner {
    <#
    .SYNOPSIS
        Displays the Yeyland Wutani ASCII banner with brand colors.
    #>
    $banner = @"
  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ 
  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|
   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | 
    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|
                                                                             
                        B U I L D I N G   B E T T E R   S Y S T E M S
"@
    Write-Host ""
    Write-Host $banner -ForegroundColor DarkYellow
    Write-Host ""
}

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    Write-Host "  $Text" -ForegroundColor DarkYellow
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    Write-Host ""
}

function Write-Step {
    param([int]$Number, [int]$Total, [string]$Text)
    Write-Host "[$Number/$Total] $Text" -ForegroundColor White
}

function Write-Ok {
    param([string]$Text)
    Write-Host "  [OK] $Text" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Text)
    Write-Host "  [FAIL] $Text" -ForegroundColor Red
}

function Write-Info {
    param([string]$Text)
    Write-Host "  $Text" -ForegroundColor Gray
}

function Read-SecurePrompt {
    param([string]$Prompt, [string]$Default)
    $userInput = Read-Host -Prompt "$Prompt$(if ($Default) { " [$Default]" })"
    if ([string]::IsNullOrWhiteSpace($userInput) -and $Default) { return $Default }
    return $userInput
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    $suffix = if ($Default) { "(Y/n)" } else { "(y/N)" }
    $userInput = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($userInput)) { return $Default }
    return $userInput -match '^[Yy]'
}

function Test-GraphSenderAddress {
    <#
    .SYNOPSIS
        Validates that a sender address exists in Microsoft 365 using Graph API.
        Uses client credentials (app-only auth) to verify the address.
    #>
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$EmailAddress
    )

    try {
        # Acquire token using client credentials
        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $tokenBody = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "client_credentials"
        }
        
        $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $accessToken = $tokenResponse.access_token
        
        # Query Graph API to check if user exists
        $headers = @{
            Authorization  = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }
        
        # Try to get user by userPrincipalName or mail attribute
        $encodedEmail = [uri]::EscapeDataString($EmailAddress)
        
        # First try: exact UPN match
        $userUrl = "https://graph.microsoft.com/v1.0/users/$encodedEmail"
        try {
            $user = Invoke-RestMethod -Uri $userUrl -Headers $headers -Method GET -ErrorAction Stop
            return @{
                Success = $true
                DisplayName = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                Mail = $user.mail
                Message = "Address validated: $($user.displayName) ($($user.userPrincipalName))"
            }
        }
        catch {
            # User not found by UPN, try searching by mail attribute
            $searchUrl = "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$EmailAddress' or proxyAddresses/any(p:p eq 'smtp:$EmailAddress')"
            try {
                $searchResult = Invoke-RestMethod -Uri $searchUrl -Headers $headers -Method GET -ErrorAction Stop
                if ($searchResult.value -and $searchResult.value.Count -gt 0) {
                    $user = $searchResult.value[0]
                    return @{
                        Success = $true
                        DisplayName = $user.displayName
                        UserPrincipalName = $user.userPrincipalName
                        Mail = $user.mail
                        Message = "Address validated: $($user.displayName) ($($user.userPrincipalName))"
                    }
                }
            }
            catch { }
        }
        
        return @{
            Success = $false
            Message = "Address '$EmailAddress' not found in Microsoft 365 tenant. Ensure this is a valid user, shared mailbox, or distribution list in your organization."
        }
    }
    catch {
        # Token acquisition failed - likely invalid credentials
        $errMsg = $_.Exception.Message
        if ($errMsg -match "AADSTS7000215|invalid_client") {
            return @{
                Success = $false
                Message = "Invalid client credentials. Cannot validate address."
            }
        }
        return @{
            Success = $false
            Message = "Could not validate address: $errMsg"
        }
    }
}

# ============================================================================
# Service Name Prompt
# ============================================================================

# Show current defaults
Write-Host ""
Write-Host "  Service Configuration" -ForegroundColor DarkYellow
Write-Host "  =====================" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Current service name: $ServiceName" -ForegroundColor White
Write-Host "  This will determine the Windows service name and install folder."
Write-Host ""

$customName = Read-Host "  Press ENTER to keep [$ServiceName], or type a new name"
if (-not [string]::IsNullOrWhiteSpace($customName)) {
    $ServiceName = $customName.Trim()
    # Re-derive paths from new service name
    $SafeServiceName = $ServiceName -replace '[^a-zA-Z0-9]', ''
    $InstallPath = "C:\$SafeServiceName"
    $AppName = $ServiceName
    Write-Host ""
    Write-Host "  Updated: Service='$ServiceName', Path='$InstallPath'" -ForegroundColor Green
}
Write-Host ""

# ============================================================================
# Banner
# ============================================================================

Clear-Host
Show-YWBanner

Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
Write-Host "  ║                                                          ║" -ForegroundColor DarkYellow
Write-Host "  ║        Yeyland Wutani SMTP Relay - Installer             ║" -ForegroundColor DarkYellow
Write-Host "  ║                                                          ║" -ForegroundColor DarkYellow
Write-Host "  ║   SMTP to Microsoft 365 via Graph API                    ║" -ForegroundColor DarkYellow
Write-Host "  ║   Yeyland Wutani LLC - Building Better Systems           ║" -ForegroundColor DarkYellow
Write-Host "  ║                                                          ║" -ForegroundColor DarkYellow
Write-Host "  ║   Version: $ScriptVersion                                        ║" -ForegroundColor DarkYellow
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Install path:  $InstallPath"
Write-Host "  SMTP port:     $SmtpPort"
Write-Host "  Service name:  $ServiceName"
Write-Host ""

# ============================================================================
# Existing Installation Detection
# ============================================================================

$existingInstallDetected = $false
$existingConfig = $null
$existingServiceStatus = $null

# Check for existing service
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    $existingInstallDetected = $true
    $existingServiceStatus = $existingService.Status
}

# Check for existing install folder and config
$existingConfigPath = Join-Path $InstallPath "config.json"
if (Test-Path $InstallPath) {
    $existingInstallDetected = $true
    if (Test-Path $existingConfigPath) {
        try {
            $existingConfig = Get-Content $existingConfigPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Host "  [WARN] Could not read existing config.json" -ForegroundColor Yellow
        }
    }
}

if ($existingInstallDetected) {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║         EXISTING INSTALLATION DETECTED                   ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    if ($existingService) {
        Write-Host "  Service:    $ServiceName" -ForegroundColor White
        Write-Host "  Status:     $existingServiceStatus" -ForegroundColor $(if ($existingServiceStatus -eq 'Running') { 'Green' } else { 'Yellow' })
    }
    if (Test-Path $InstallPath) {
        Write-Host "  Location:   $InstallPath" -ForegroundColor White
    }
    if ($existingConfig) {
        Write-Host "  Tenant:     $($existingConfig.TenantId)" -ForegroundColor Gray
        Write-Host "  Send-As:    $($existingConfig.SendAsAddress)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  What would you like to do?" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "    [U] Upgrade    - Update scripts, preserve configuration" -ForegroundColor White
    Write-Host "    [R] Uninstall  - Remove service and all files" -ForegroundColor White
    Write-Host "    [F] Fresh      - Remove everything and start fresh" -ForegroundColor White
    Write-Host "    [C] Cancel     - Exit without changes" -ForegroundColor White
    Write-Host ""
    
    $choice = ""
    while ($choice -notmatch '^[URFCurfc]$') {
        $choice = Read-Host "  Select option (U/R/F/C)"
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "C" }
    }
    
    switch ($choice.ToUpper()) {
        "U" {
            Write-Host ""
            Write-Host "  Upgrading existing installation..." -ForegroundColor DarkYellow
            Write-Host ""
            
            if ($existingService -and $existingService.Status -eq 'Running') {
                Write-Host "  Stopping service..." -NoNewline
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Write-Host " Done" -ForegroundColor Green
            }
            
            $script:UpgradeMode = $true
            $script:PreservedConfig = $existingConfig
            
            Write-Host "  Configuration will be preserved." -ForegroundColor Green
            Write-Host ""
        }
        "R" {
            Write-Host ""
            Write-Host "  Running uninstaller..." -ForegroundColor DarkYellow
            Write-Host ""
            
            $uninstallScriptPath = Join-Path $env:TEMP "Uninstall-YWSMTPRelay-Temp.ps1"
            Set-Content -Path $uninstallScriptPath -Value $EmbeddedUninstallScript -Encoding UTF8
            & $uninstallScriptPath -ServiceName $ServiceName -InstallPath $InstallPath
            Remove-Item $uninstallScriptPath -Force -ErrorAction SilentlyContinue
            
            Write-Host ""
            Write-Host "  Uninstall complete. Exiting installer." -ForegroundColor Green
            exit 0
        }
        "F" {
            Write-Host ""
            Write-Host "  Preparing for fresh installation..." -ForegroundColor DarkYellow
            
            if ($existingService) {
                Write-Host "  Stopping and removing existing service..." -NoNewline
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                $nssmPath = Join-Path $InstallPath "nssm.exe"
                if (Test-Path $nssmPath) {
                    & $nssmPath remove $ServiceName confirm 2>$null
                }
                else {
                    sc.exe delete $ServiceName 2>$null
                }
                Start-Sleep -Seconds 1
                Write-Host " Done" -ForegroundColor Green
            }
            
            if (Test-Path $InstallPath) {
                Write-Host "  Removing existing files..." -NoNewline
                Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
                Write-Host " Done" -ForegroundColor Green
            }
            
            Write-Host "  Removing firewall rules..." -NoNewline
            $fwRuleName = "$ServiceName (TCP $SmtpPort)"
            Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
            Write-Host " Done" -ForegroundColor Green
            
            Write-Host ""
            Write-Host "  Ready for fresh installation." -ForegroundColor Green
            Write-Host ""
        }
        "C" {
            Write-Host ""
            Write-Host "  Installation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
}


$totalSteps = 7
if (-not (Read-YesNo "Continue with installation?")) { exit 0 }

# ============================================================================
# Step 1: Prerequisites
# ============================================================================

Write-Header "Step 1: Prerequisites Check"
Write-Step 1 $totalSteps "Checking prerequisites..."

# PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 7) {
    Write-Ok "PowerShell $psVersion (pwsh)"
    $psExe = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
}
elseif ($psVersion.Major -ge 5) {
    Write-Ok "PowerShell $psVersion (Windows PowerShell)"
    $psExe = (Get-Command powershell -ErrorAction SilentlyContinue).Source
}
else {
    Write-Fail "PowerShell 5.1+ required (found $psVersion)"
    exit 1
}

# Check if port is available
$portInUse = Get-NetTCPConnection -LocalPort $SmtpPort -State Listen -ErrorAction SilentlyContinue
if ($portInUse) {
    $process = Get-Process -Id $portInUse[0].OwningProcess -ErrorAction SilentlyContinue
    Write-Fail "Port $SmtpPort is already in use by $($process.ProcessName) (PID: $($portInUse[0].OwningProcess))"
    Write-Info "Stop the conflicting service or choose a different port with -SmtpPort"

    # Check for common conflicts
    $smtpSvc = Get-Service -Name "SMTPSVC" -ErrorAction SilentlyContinue
    if ($smtpSvc -and $smtpSvc.Status -eq "Running") {
        Write-Host ""
        Write-Host "  IIS SMTP Service is running. To disable it:" -ForegroundColor Yellow
        Write-Host "    Stop-Service SMTPSVC; Set-Service SMTPSVC -StartupType Disabled" -ForegroundColor Yellow
    }

    if (-not (Read-YesNo "Continue anyway?")) { exit 1 }
}
else {
    Write-Ok "Port $SmtpPort is available"
}

# Check for existing installation (skip if already handled in upgrade mode)
if (-not $script:UpgradeMode) {
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "  [WARN] Service '$ServiceName' already exists (Status: $($existingService.Status))" -ForegroundColor Yellow
        if (Read-YesNo "  Stop and remove existing service before reinstalling?") {
            Write-Info "Stopping service..."
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2

            # Remove via NSSM if available, otherwise sc.exe
            $existingNssm = Join-Path $InstallPath "nssm.exe"
            if (Test-Path $existingNssm) {
                & $existingNssm remove $ServiceName confirm 2>$null
            }
            else {
                sc.exe delete $ServiceName 2>$null
            }
            Start-Sleep -Seconds 1
            Write-Ok "Existing service removed"
        }
        else {
            Write-Fail "Cannot install over existing service"
            exit 1
        }
    }
}
else {
    Write-Ok "Upgrade mode - existing service will be updated"
}

# Internet connectivity (needed for NSSM download and app registration)
Write-Host "  Checking internet connectivity..." -NoNewline
try {
    $null = Invoke-WebRequest -Uri "https://graph.microsoft.com" -Method HEAD -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
}
catch {
    Write-Host " WARN - Graph API unreachable" -ForegroundColor Yellow
    Write-Info "Service will fail to relay until connectivity is restored"
}

# ============================================================================
# Step 2: Entra ID App Registration
# ============================================================================

Write-Header "Step 2: Entra ID App Registration"
Write-Step 2 $totalSteps "Configuring Graph API authentication..."

$tenantId = ""
$clientId = ""
$clientSecret = ""
$clientSecretExpiry = ""

# In upgrade mode, use preserved config values
if ($script:UpgradeMode -and $script:PreservedConfig) {
    Write-Ok "Upgrade mode - using existing credentials from config.json"
    $tenantId = $script:PreservedConfig.TenantId
    $clientId = $script:PreservedConfig.ClientId
    $clientSecret = $script:PreservedConfig.ClientSecret
    $clientSecretExpiry = $script:PreservedConfig.ClientSecretExpiry
    Write-Info "  Tenant ID: $tenantId"
    Write-Info "  Client ID: $clientId"
    Write-Info "  Client Secret: ****[preserved]****"
}
elseif (-not $SkipAppRegistration -and (Read-YesNo "Create a new Entra app registration now?" $true)) {
    # Check for Microsoft.Graph module
    $graphModule = Get-Module -Name "Microsoft.Graph.Applications" -ListAvailable -ErrorAction SilentlyContinue
    if (-not $graphModule) {
        Write-Info "Microsoft.Graph module not found. Installing..."
        try {
            Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
            Write-Ok "Microsoft.Graph.Applications module installed"
        }
        catch {
            Write-Fail "Could not install Microsoft.Graph module: $_"
            Write-Info "Install manually: Install-Module Microsoft.Graph -Scope CurrentUser"
            Write-Info "Or skip this step with -SkipAppRegistration and provide details manually"
            if (-not (Read-YesNo "Continue with manual configuration instead?")) { exit 1 }
            $SkipAppRegistration = $true
        }
    }

    if (-not $SkipAppRegistration) {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop

        Write-Host ""
        Write-Host "  A browser window will open for authentication." -ForegroundColor Yellow
        Write-Host "  Sign in with a Global Admin or Application Administrator account." -ForegroundColor Yellow
        Write-Host ""
        Pause

        try {
            Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome -ErrorAction Stop
            $ctx = Get-MgContext
            $tenantId = $ctx.TenantId
            Write-Ok "Connected to tenant: $tenantId"
        }
        catch {
            Write-Fail "Graph connection failed: $_"
            if (-not (Read-YesNo "Continue with manual configuration?")) { exit 1 }
            $SkipAppRegistration = $true
        }
    }

    if (-not $SkipAppRegistration) {
        $appDisplayName = Read-SecurePrompt "  App display name" $AppName

        # Check for existing app
        $existingApp = Get-MgApplication -Filter "displayName eq '$appDisplayName'" -ErrorAction SilentlyContinue
        if ($existingApp) {
            Write-Host "  App '$appDisplayName' already exists (Client ID: $($existingApp.AppId))" -ForegroundColor Yellow
            if (Read-YesNo "  Use existing app and create a new secret?") {
                $app = $existingApp
                $clientId = $app.AppId
            }
            else {
                $appDisplayName = Read-SecurePrompt "  Enter a different name" "SMTP Relay - $(Get-Date -Format 'MMdd')"
            }
        }

        if (-not $clientId) {
            Write-Info "Creating app registration: $appDisplayName"

            # Well-known IDs
            $graphAppId = "00000003-0000-0000-c000-000000000000"
            $mailSendRoleId = "b633e1c5-b582-4048-a93e-9f11b44c7e96"

            $appParams = @{
                DisplayName            = $appDisplayName
                SignInAudience         = "AzureADMyOrg"
                RequiredResourceAccess = @(
                    @{
                        ResourceAppId  = $graphAppId
                        ResourceAccess = @(
                            @{ Id = $mailSendRoleId; Type = "Role" }
                        )
                    }
                )
                Notes = "Yeyland Wutani SMTP Relay - relays SMTP from on-prem devices through Graph API. Supports user mailboxes, shared mailboxes, and distribution lists. Managed by Yeyland Wutani LLC."
            }

            $app = New-MgApplication @appParams
            $clientId = $app.AppId
            Write-Ok "App registration created: $clientId"

            # Create service principal
            $sp = New-MgServicePrincipal -AppId $app.AppId
            Write-Ok "Service principal created"

            # Grant admin consent
            Write-Info "Granting admin consent for Mail.Send..."
            try {
                $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter @{
                    PrincipalId = $sp.Id
                    ResourceId  = $graphSp.Id
                    AppRoleId   = $mailSendRoleId
                } | Out-Null
                Write-Ok "Admin consent granted for Mail.Send"
            }
            catch {
                Write-Host "  [WARN] Auto-consent failed: $_" -ForegroundColor Yellow
                Write-Info "An admin must grant consent manually in the Entra portal:"
                Write-Info "  App registrations -> $appDisplayName -> API permissions -> Grant admin consent"
            }
        }

        # Create client secret
        Write-Info "Creating client secret..."
        $secretMonths = [int](Read-SecurePrompt "  Secret expiry (months)" "24")
        $secretParams = @{
            PasswordCredential = @{
                DisplayName = "YW-SMTPRelay-Install-$(Get-Date -Format 'yyyyMMdd')"
                EndDateTime = (Get-Date).AddMonths($secretMonths)
            }
        }
        $secret = Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $secretParams
        $clientSecret = $secret.SecretText
        $clientSecretExpiry = $secret.EndDateTime.ToString('yyyy-MM-dd')
        Write-Ok "Client secret created (expires $clientSecretExpiry)"

        Write-Host ""
        Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │  SAVE THESE VALUES - Secret cannot be retrieved  │" -ForegroundColor Yellow
        Write-Host "  │  again after this installer completes.           │" -ForegroundColor Yellow
        Write-Host "  │                                                  │" -ForegroundColor Yellow
        Write-Host "  │  Tenant ID:     $tenantId  │" -ForegroundColor Yellow
        Write-Host "  │  Client ID:     $clientId  │" -ForegroundColor Yellow
        Write-Host "  │  Client Secret: $($clientSecret.Substring(0, [Math]::Min(20, $clientSecret.Length)))...                       │" -ForegroundColor Yellow
        Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Yellow

        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

# Manual entry if app registration was skipped
if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
    Write-Host ""
    Write-Host "  Enter your Entra app registration details:" -ForegroundColor Yellow
    if (-not $tenantId) { $tenantId = Read-Host "  Tenant ID" }
    if (-not $clientId) { $clientId = Read-Host "  Client ID (Application ID)" }
    if (-not $clientSecret) { $clientSecret = Read-Host "  Client Secret" }
}

# ============================================================================
# Step 3: Relay Configuration
# ============================================================================

Write-Header "Step 3: Relay Configuration"
Write-Step 3 $totalSteps "Configuring relay behavior..."

Write-Host ""
Write-Host "  IMPORTANT - TLS/ENCRYPTION INFORMATION:" -ForegroundColor Yellow
Write-Host "  ========================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  This relay operates as follows:" -ForegroundColor Gray
Write-Host "    Device -> SMTP (plaintext) -> Relay Server" -ForegroundColor Gray
Write-Host "    Relay Server -> HTTPS (encrypted) -> Microsoft 365" -ForegroundColor Gray
Write-Host ""
Write-Host "  STARTTLS/TLS is NOT supported for incoming SMTP connections." -ForegroundColor Yellow
Write-Host "  This is normal for internal relays and legacy devices." -ForegroundColor Gray
Write-Host ""
Write-Host "  Security considerations:" -ForegroundColor White
Write-Host "    ✓ Use IP-based ACLs to restrict which devices can relay" -ForegroundColor Green
Write-Host "    ✓ Optional: Use SMTP AUTH for additional security" -ForegroundColor Green
Write-Host "    ✓ Relay-to-M365 traffic is always encrypted (HTTPS)" -ForegroundColor Green
Write-Host "    ✓ Deploy relay on trusted internal network only" -ForegroundColor Green
Write-Host ""
Pause
Write-Host ""

# In upgrade mode, use preserved send-as configuration
if ($script:UpgradeMode -and $script:PreservedConfig) {
    Write-Ok "Upgrade mode - using existing relay configuration"
    $sendAsAddress = $script:PreservedConfig.SendAsAddress
    $forceSendAs = $script:PreservedConfig.ForceSendAs
    $SmtpAuthEnabled = $script:PreservedConfig.SmtpAuthEnabled
    $SmtpAuthUsername = $script:PreservedConfig.SmtpAuthUsername
    $SmtpAuthPassword = $script:PreservedConfig.SmtpAuthPassword
    $reminderEmail = $script:PreservedConfig.ReminderEmail
    $allowedClients = $script:PreservedConfig.AllowedClients
    Write-Info "  Send-As: $sendAsAddress"
    Write-Info "  Force Send-As: $forceSendAs"
    Write-Host ""
    
    # Skip to Step 4 (file extraction)
}
else {
    Write-Host "  Enter the email address to send from. This can be:" -ForegroundColor Yellow
    Write-Host "    - A user mailbox" -ForegroundColor Gray
    Write-Host "    - A shared mailbox (does NOT require a license)" -ForegroundColor Gray
    Write-Host "    - Any valid address in an accepted domain" -ForegroundColor Gray
    Write-Host ""

    do {
        $sendAsAddress = Read-Host "  Send-as address (e.g. relay@contoso.com)"
        if ($sendAsAddress -notmatch '@') {
            Write-Host '  Invalid email address. Must contain @' -ForegroundColor Red
        }
    } while ($sendAsAddress -notmatch '@')
    
    # Validate the sender address exists in Microsoft 365
    Write-Host "  Validating address in Microsoft 365..." -NoNewline
    $validation = Test-GraphSenderAddress -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret -EmailAddress $sendAsAddress
    
    if ($validation.Success) {
        Write-Host " OK" -ForegroundColor Green
        Write-Info $validation.Message
    } else {
        Write-Host " SKIPPED" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  VALIDATION NOTE:" -ForegroundColor Yellow
        Write-Host "  The address could not be validated, but this is expected for:" -ForegroundColor Gray
        Write-Host "    - Shared mailboxes (most common)" -ForegroundColor Gray
        Write-Host "    - Distribution lists" -ForegroundColor Gray
        Write-Host "    - Mail contacts" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  WHY: The app has 'Mail.Send' permission (sufficient to send email)" -ForegroundColor Gray
        Write-Host "       but lacks 'User.Read.All' permission (needed to validate mailboxes)." -ForegroundColor Gray
        Write-Host ""
        Write-Host "  This is normal and recommended - Mail.Send is all you need!" -ForegroundColor Green
        Write-Host "  The relay will work fine as long as '$sendAsAddress' exists in M365." -ForegroundColor Green
        Write-Host ""
        if (-not (Read-YesNo "  Continue with '$sendAsAddress'?" $true)) {
            $sendAsAddress = Read-Host "  Enter a different send-as address"
            while ($sendAsAddress -notmatch '@') {
                Write-Host '  Invalid email address. Must contain @' -ForegroundColor Red
                $sendAsAddress = Read-Host "  Send-as address"
            }
        }
    }
    
    $forceSendAs = Read-YesNo "  Force all messages to send as $sendAsAddress (recommended)?" $true
    
    # SMTP Authentication
    Write-Host ""
    Write-Host "  SMTP AUTHENTICATION" -ForegroundColor DarkYellow
    Write-Host "  Basic username/password authentication for SMTP clients."
    Write-Host "  Enable this if your devices support SMTP AUTH and you want"
    Write-Host "  an extra layer of security beyond IP-based access control."
    Write-Host ""
    
    $enableSmtpAuth = Read-YesNo "Enable SMTP authentication?" $false
    $SmtpAuthEnabled = $false
    $SmtpAuthUsername = ""
    $SmtpAuthPassword = ""
    
    if ($enableSmtpAuth) {
        $SmtpAuthEnabled = $true
        
        # Get username
        do {
            $SmtpAuthUsername = Read-Host "  SMTP Auth Username"
            if ([string]::IsNullOrWhiteSpace($SmtpAuthUsername)) {
                Write-Host "  [!] Username cannot be empty" -ForegroundColor Yellow
            }
        } while ([string]::IsNullOrWhiteSpace($SmtpAuthUsername))
        
        # Get password
        do {
            $SmtpAuthPassword = Read-Host "  SMTP Auth Password"
            if ([string]::IsNullOrWhiteSpace($SmtpAuthPassword)) {
                Write-Host "  [!] Password cannot be empty" -ForegroundColor Yellow
            }
        } while ([string]::IsNullOrWhiteSpace($SmtpAuthPassword))
        
        Write-Ok "SMTP authentication configured"
        Write-Info "    Username: $SmtpAuthUsername"
        Write-Info "    Clients will need to authenticate before sending mail"
    } else {
        Write-Info "SMTP authentication disabled"
    }
    
    # Client Secret Expiry Reminder
    Write-Host ""
    Write-Host "  CLIENT SECRET EXPIRY REMINDER" -ForegroundColor Yellow
    Write-Host "  Your client secret will expire. Would you like an email reminder" -ForegroundColor Yellow
    Write-Host "  sent 1 month before expiration?" -ForegroundColor Yellow
    Write-Host ""
    
    # Try to get the expiry date from the secret we just created
    $secretExpiryDate = $clientSecretExpiry
    if ($secretExpiryDate) {
        Write-Host "  Secret expires: $secretExpiryDate" -ForegroundColor Gray
    }
    
    $enableReminder = Read-YesNo "  Enable expiry reminder email?" $true
    $reminderEmail = ""
    
    if ($enableReminder) {
        $reminderEmail = Read-Host "  Email address for reminder alerts"
        while ($reminderEmail -and $reminderEmail -notmatch '@') {
            Write-Host '  Invalid email address. Must contain @' -ForegroundColor Red
            $reminderEmail = Read-Host "  Email address for reminder alerts"
        }
        
        # If we don't have the expiry date (manual app entry), ask for it
        if (-not $secretExpiryDate) {
            Write-Host ""
            Write-Host "  When does your client secret expire?" -ForegroundColor Yellow
            Write-Host "  (Check Azure Portal > App registrations > Certificates & secrets)" -ForegroundColor Gray
            $secretExpiryInput = Read-Host "  Secret expiry date (YYYY-MM-DD, or press Enter to skip)"
            if ($secretExpiryInput -match '^\d{4}-\d{2}-\d{2}$') {
                $secretExpiryDate = $secretExpiryInput
            } elseif ($secretExpiryInput) {
                Write-Host "  Invalid date format. Reminder will not be configured." -ForegroundColor Yellow
                $reminderEmail = ""
            }
        }
        
        if ($reminderEmail -and $secretExpiryDate) {
            $reminderDateObj = [datetime]::Parse($secretExpiryDate).AddMonths(-1)
            Write-Ok "Reminder configured: Email will be sent around $($reminderDateObj.ToString('yyyy-MM-dd'))"
        }
    }
    
    # IP Access Control
    Write-Host ""
    Write-Host "  IP Access Control - which devices can relay through this server?" -ForegroundColor Yellow
    Write-Host "  Enter IP addresses or CIDR ranges, comma-separated." -ForegroundColor Yellow
    Write-Host "  Common defaults: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1" -ForegroundColor Yellow
    $aclInput = Read-SecurePrompt "  Allowed clients" "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1"
    $allowedClients = @($aclInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Build configuration object (used for both new installs and upgrades)
$config = [ordered]@{
    # Service Identity
    ServiceName          = $ServiceName

    # Entra ID / Authentication
    TenantId             = $tenantId
    ClientId             = $clientId
    ClientSecret         = $clientSecret

    # Relay Behavior
    SendAsAddress        = $sendAsAddress
    ForceSendAs          = $forceSendAs
    SaveToSentItems      = $false

    # SMTP Listener
    SmtpPort             = $SmtpPort
    ListenAddress        = "0.0.0.0"
    MaxMessageSizeBytes  = 36700160     # 35 MB
    SessionTimeoutSec    = 60
    MaxRecipients        = 500

    # Access Control
    AllowedClients       = $allowedClients

    # Secret Expiry Reminder
    ClientSecretExpiry   = $secretExpiryDate
    ReminderEmail        = $reminderEmail
    ReminderSent         = $false

    # SMTP Authentication
    SmtpAuthEnabled      = $SmtpAuthEnabled
    SmtpAuthUsername     = $SmtpAuthUsername
    SmtpAuthPassword     = $SmtpAuthPassword

    # Logging
    LogDirectory         = Join-Path $InstallPath "Logs"
    LogRetentionDays     = 30
    LogLevel             = "INFO"
}

Write-Ok "Configuration built"

# ============================================================================
# Step 4: Create Installation Directory & Extract Files
# ============================================================================

Write-Header "Step 4: Install Files"
Write-Step 4 $totalSteps "Creating installation directory and extracting files..."

# Create directories
foreach ($dir in @($InstallPath, (Join-Path $InstallPath "Logs"))) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Write-Info "Created: $dir"
    }
}

# Extract the embedded relay script
$relayScriptName = "$SafeServiceName.ps1"
$relayScriptPath = Join-Path $InstallPath $relayScriptName
$EmbeddedRelayScript | Set-Content -Path $relayScriptPath -Encoding UTF8 -Force
Write-Ok "Relay script extracted to $relayScriptPath"

# Extract the embedded uninstall script
$uninstallScriptName = "Uninstall-$SafeServiceName.ps1"
$uninstallScriptPath = Join-Path $InstallPath $uninstallScriptName
$EmbeddedUninstallScript | Set-Content -Path $uninstallScriptPath -Encoding UTF8 -Force
Write-Ok "Uninstaller extracted to $uninstallScriptPath"

# Write configuration
$configPath = Join-Path $InstallPath "config.json"
$config | ConvertTo-Json -Depth 3 | Set-Content $configPath -Encoding UTF8
Write-Ok "Configuration written to $configPath"

# Protect config file (contains client secret) - restrict to Administrators and SYSTEM
try {
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false) # Remove inheritance
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

    # SYSTEM - Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.AddAccessRule($systemRule)

    # Administrators - Full Control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)

    Set-Acl $configPath $acl
    Write-Ok "Config file permissions locked to SYSTEM and Administrators"
}
catch {
    Write-Host "  [WARN] Could not restrict config file permissions: $_" -ForegroundColor Yellow
}

# ============================================================================
# Step 5: Download & Install NSSM
# ============================================================================

Write-Header "Step 5: Service Manager (NSSM)"
Write-Step 5 $totalSteps "Setting up NSSM..."

$nssmExe = Join-Path $InstallPath "nssm.exe"

if (Test-Path $nssmExe) {
    Write-Ok "NSSM already present at $nssmExe"
}
else {
    $nssmUrl = "https://nssm.cc/release/nssm-$NssmVersion.zip"
    $nssmZip = Join-Path $env:TEMP "nssm-$NssmVersion.zip"
    $nssmExtract = Join-Path $env:TEMP "nssm-$NssmVersion"

    Write-Info "Downloading NSSM $NssmVersion..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $maxRetries = 3
    $retryDelaySeconds = 5
    $downloadSuccess = $false
    
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            if ($attempt -gt 1) {
                Write-Host "    Retry attempt $attempt of $maxRetries..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryDelaySeconds
                # Exponential backoff: double the delay for next attempt
                $retryDelaySeconds = $retryDelaySeconds * 2
            }
            Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            $downloadSuccess = $true
            Write-Ok "NSSM downloaded"
            break
        }
        catch {
            Write-Host "    [WARN] Download attempt $attempt failed: $_" -ForegroundColor Yellow
            if ($attempt -eq $maxRetries) {
                Write-Host ""
                Write-Host "  NSSM could not be downloaded after $maxRetries attempts." -ForegroundColor Yellow
                Write-Host "  The nssm.cc website may be experiencing issues." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  Download it manually from: https://nssm.cc/download" -ForegroundColor Yellow
                Write-Host "  Place nssm.exe (64-bit) in: $InstallPath" -ForegroundColor Yellow
                Write-Host ""

                if (-not (Read-YesNo "Have you placed nssm.exe in $InstallPath`?")) {
                    Write-Fail "NSSM is required to run as a Windows service"
                    exit 1
                }

                if (-not (Test-Path $nssmExe)) {
                    Write-Fail "nssm.exe not found at $nssmExe"
                    exit 1
                }
            }
        }
    }

    if (Test-Path $nssmZip) {
        Write-Info "Extracting..."
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

        # Find the 64-bit exe
        $nssmSrc = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" |
            Where-Object { $_.DirectoryName -match 'win64' } |
            Select-Object -First 1

        if (-not $nssmSrc) {
            # Fall back to any nssm.exe found
            $nssmSrc = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" | Select-Object -First 1
        }

        if ($nssmSrc) {
            Copy-Item -Path $nssmSrc.FullName -Destination $nssmExe -Force
            Write-Ok "NSSM installed to $nssmExe"
        }
        else {
            Write-Fail "Could not find nssm.exe in downloaded archive"
            exit 1
        }

        # Cleanup
        Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
        Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# Step 6: Create Windows Service
# ============================================================================

Write-Header "Step 6: Windows Service"
Write-Step 6 $totalSteps "Creating '$ServiceName' service..."

$scriptPath = Join-Path $InstallPath "$SafeServiceName.ps1"

# Check if service already exists (upgrade mode)
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existingSvc -and $script:UpgradeMode) {
    Write-Info "Service already exists - updating configuration..."
    
    # Update the service command line to point to new script
    & $nssmExe set $ServiceName Application $psExe 2>$null | Out-Null
    & $nssmExe set $ServiceName AppParameters "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`"" 2>$null | Out-Null
    
    Write-Ok "Service configuration updated"
}
elseif ($existingSvc) {
    Write-Fail "Service '$ServiceName' already exists and not in upgrade mode"
    Write-Info "This shouldn't happen - the installer should have detected the existing service earlier."
    Write-Info "Try running the installer again and choosing 'Fresh' or 'Uninstall' first."
    exit 1
}
else {
    # Fresh install - create new service
    & $nssmExe install $ServiceName $psExe "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "NSSM service installation failed (exit code: $LASTEXITCODE)"
        exit 1
    }
    Write-Ok "Service installed"
}

# Configure service parameters (applies to both new and existing services)
$nssmSettings = @{
    "DisplayName"                  = $ServiceName
    "Description"                  = "Relays SMTP email from devices to Microsoft 365 via Graph API. Yeyland Wutani LLC - Building Better Systems."
    "Start"                        = "SERVICE_AUTO_START"
    "AppDirectory"                 = $InstallPath
    "AppStdout"                    = Join-Path $InstallPath "Logs\service-stdout.log"
    "AppStderr"                    = Join-Path $InstallPath "Logs\service-stderr.log"
    "AppStdoutCreationDisposition" = "4"         # Append
    "AppStderrCreationDisposition" = "4"         # Append
    "AppRotateFiles"               = "1"
    "AppRotateSeconds"             = "86400"
    "AppRotateBytes"               = "10485760"  # 10 MB
    "AppRestartDelay"              = "5000"      # 5 sec restart delay on crash
}

foreach ($key in $nssmSettings.Keys) {
    & $nssmExe set $ServiceName $key $nssmSettings[$key] 2>$null | Out-Null
}

# AppExit requires TWO separate arguments (subparameter + action)
& $nssmExe set $ServiceName AppExit Default Restart 2>$null | Out-Null

# Set service recovery options via sc.exe (restart on failure)
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

if ($script:UpgradeMode) {
    Write-Ok "Service updated (auto-start, auto-restart on failure)"
} else {
    Write-Ok "Service configured (auto-start, auto-restart on failure)"
}

# ============================================================================
# Step 7: Firewall & Startup
# ============================================================================

Write-Header "Step 7: Firewall & Startup"
Write-Step 7 $totalSteps "Final configuration..."

# Firewall rule
$fwRuleName = "$ServiceName (TCP $SmtpPort)"
$existingFw = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
if (-not $existingFw) {
    New-NetFirewallRule -DisplayName $fwRuleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $SmtpPort `
        -Profile Domain,Private `
        -Description "$ServiceName - allows inbound SMTP from devices" | Out-Null
    Write-Ok "Firewall rule created: $fwRuleName"
}
else {
    Write-Ok "Firewall rule already exists"
}

# Start the service
if ($script:UpgradeMode) {
    Write-Info "Restarting service..."
    try {
        Restart-Service -Name $ServiceName -Force -ErrorAction Stop
        Start-Sleep -Seconds 3

        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq "Running") {
            Write-Ok "Service restarted successfully"
        }
        else {
            Write-Fail "Service status: $($svc.Status)"
            Write-Info "Check logs at: $(Join-Path $InstallPath 'Logs')"
        }
    }
    catch {
        Write-Fail "Service failed to restart: $_"
        Write-Info "Check logs at: $(Join-Path $InstallPath 'Logs')"
        Write-Info "Try manually: Restart-Service '$ServiceName'"
    }
} else {
    Write-Info "Starting service..."
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3

        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq "Running") {
            Write-Ok "Service is running"
        }
        else {
            Write-Fail "Service status: $($svc.Status)"
            Write-Info "Check logs at: $(Join-Path $InstallPath 'Logs')"
        }
    }
    catch {
        Write-Fail "Service failed to start: $_"
        Write-Info "Check logs at: $(Join-Path $InstallPath 'Logs')"
        Write-Info "Common issues:"
        Write-Info "  - Invalid Entra credentials in config.json"
        Write-Info "  - Port $SmtpPort already in use"
        Write-Info "  - PowerShell execution policy blocking the script"
    }
}

# Quick SMTP test
Write-Host ""
Write-Info "Running quick SMTP connectivity test..."
try {
    Start-Sleep -Seconds 2
    $tcpTest = New-Object System.Net.Sockets.TcpClient
    $tcpTest.Connect("127.0.0.1", $SmtpPort)
    $stream = $tcpTest.GetStream()
    $reader = [System.IO.StreamReader]::new($stream)
    $banner = $reader.ReadLine()
    $reader.Dispose()
    $stream.Dispose()
    $tcpTest.Close()

    if ($banner -match '^220') {
        Write-Ok "SMTP banner received: $banner"
    }
    else {
        Write-Host "  [WARN] Unexpected response: $banner" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Could not connect to SMTP on port ${SmtpPort}: $_" -ForegroundColor Yellow
    Write-Info "Service may still be starting up. Check logs for details."
}

# ============================================================================
# Installation Complete
# ============================================================================

Write-Host ""
if ($script:UpgradeMode) {
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║                                                          ║" -ForegroundColor Green
    Write-Host "  ║          Upgrade Complete!                               ║" -ForegroundColor Green
    Write-Host "  ║                                                          ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
} else {
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║                                                          ║" -ForegroundColor Green
    Write-Host "  ║          Installation Complete!                          ║" -ForegroundColor Green
    Write-Host "  ║                                                          ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Service Name:     $ServiceName"
Write-Host "  Install Path:     $InstallPath"
Write-Host "  SMTP Port:        $SmtpPort"
Write-Host "  Send-As Address:  $sendAsAddress"

if ($script:UpgradeMode) {
    Write-Host ""
    Write-Host "  UPGRADE NOTES:" -ForegroundColor DarkYellow
    Write-Host "    ✓ Scripts updated to latest version" -ForegroundColor Green
    Write-Host "    ✓ Configuration preserved from previous install" -ForegroundColor Green
    Write-Host "    ✓ Service updated and restarted" -ForegroundColor Green
    Write-Host "    ✓ Logs retained" -ForegroundColor Green
}

if ($reminderEmail -and $secretExpiryDate) {
    Write-Host ""
    Write-Host "  SECRET EXPIRY REMINDER:" -ForegroundColor Yellow
    Write-Host "    Alert Email:    $reminderEmail"
    Write-Host "    Secret Expires: $secretExpiryDate"
    $reminderDateDisplay = [datetime]::Parse($secretExpiryDate).AddMonths(-1).ToString('yyyy-MM-dd')
    Write-Host "    Reminder Date:  $reminderDateDisplay (approx)"
}
Write-Host "  Config File:      $configPath"
Write-Host "  Log Directory:    $(Join-Path $InstallPath 'Logs')"
Write-Host ""
Write-Host "  DEVICE CONFIGURATION:" -ForegroundColor Yellow
Write-Host "    SMTP Server:  $($env:COMPUTERNAME) (or this server's IP)"
Write-Host "    SMTP Port:    $SmtpPort"
if ($SmtpAuthEnabled) {
    Write-Host "    Auth:         Required (AUTH PLAIN/LOGIN)"
    Write-Host "                  Username: $SmtpAuthUsername"
} else {
    Write-Host "    Auth:         None required"
}
Write-Host "    TLS/SSL:      Not supported (plaintext only)"
Write-Host "    STARTTLS:     Not supported"
Write-Host "    From Address: Anything (overridden to $sendAsAddress)"
Write-Host ""
Write-Host "    Note: Relay-to-M365 traffic is encrypted via HTTPS (Graph API)" -ForegroundColor Gray
Write-Host ""
Write-Host "  MANAGEMENT COMMANDS:" -ForegroundColor Yellow
Write-Host "    Status:    Get-Service '$ServiceName'"
Write-Host "    Restart:   Restart-Service '$ServiceName'"
Write-Host "    Logs:      Get-Content '$(Join-Path $InstallPath 'Logs')\YWSMTPRelay_$(Get-Date -Format 'yyyyMMdd').log' -Tail 50"
Write-Host "    Config:    notepad '$configPath'"
Write-Host "    Uninstall: $(Join-Path $InstallPath "Uninstall-$SafeServiceName.ps1")"
Write-Host ""
Write-Host "  TROUBLESHOOTING:" -ForegroundColor Yellow
Write-Host "    For detailed AUTH debugging, edit config.json and change:"
Write-Host "    'LogLevel': 'INFO' -> 'LogLevel': 'DEBUG'"
Write-Host "    Then restart the service to see detailed authentication logs."
Write-Host ""
Write-Host "  SEND A TEST:" -ForegroundColor Yellow
Write-Host "    Send-MailMessage -SmtpServer $($env:COMPUTERNAME) -Port $SmtpPort ``"
Write-Host "      -From 'test@contoso.com' -To 'you@contoso.com' ``"
Write-Host "      -Subject 'Yeyland Wutani SMTP Relay Test' -Body 'It works!'"
Write-Host ""

if ($clientId) {
    Write-Host "  IMPORTANT - APPLICATION ACCESS POLICY:" -ForegroundColor Red
    Write-Host "  By default the app can send as ANY mailbox in the tenant." -ForegroundColor Red
    Write-Host "  Restrict it to the relay mailbox only:" -ForegroundColor Red
    Write-Host ""
    Write-Host "    # In Exchange Online PowerShell:" -ForegroundColor Yellow
    Write-Host "    New-ApplicationAccessPolicy ``" -ForegroundColor Yellow
    Write-Host "      -AppId '$clientId' ``" -ForegroundColor Yellow
    Write-Host "      -PolicyScopeGroupId '$sendAsAddress' ``" -ForegroundColor Yellow
    Write-Host "      -AccessRight RestrictAccess ``" -ForegroundColor Yellow
    Write-Host "      -Description 'Restrict SMTP Relay to relay mailbox only'" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  NEED TLS/STARTTLS SUPPORT?" -ForegroundColor Yellow
Write-Host "  TLS is not currently implemented. For most internal relay scenarios," -ForegroundColor Gray
Write-Host "  this is acceptable since the relay-to-M365 leg uses HTTPS encryption." -ForegroundColor Gray
Write-Host "  If you require TLS for device-to-relay connections, contact Yeyland" -ForegroundColor Gray
Write-Host "  Wutani for a custom implementation." -ForegroundColor Gray
Write-Host ""

# ============================================================================
# Documentation Summary (Copy-Paste Ready)
# ============================================================================

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
Write-Host "  ║       DOCUMENTATION SUMMARY (Copy/Paste Ready)           ║" -ForegroundColor DarkYellow
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Press [D] to display copyable documentation, or any other key to exit." -ForegroundColor Yellow
$docChoice = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character

if ($docChoice -ieq 'D') {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "SMTP RELAY INSTALLATION DOCUMENTATION"
    Write-Host ("=" * 70)
    Write-Host ""
    Write-Host "Installation Date:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "Installed By:         $env:USERNAME"
    Write-Host ""
    Write-Host "--- SERVER DETAILS ---"
    Write-Host "Server Name:          $env:COMPUTERNAME"
    Write-Host "Server IP(s):         $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -ExpandProperty IPAddress) -join ', ')"
    Write-Host "Operating System:     $((Get-CimInstance Win32_OperatingSystem).Caption)"
    Write-Host "PowerShell Version:   $($PSVersionTable.PSVersion.ToString())"
    Write-Host ""
    Write-Host "--- SERVICE CONFIGURATION ---"
    Write-Host "Service Name:         $ServiceName"
    Write-Host "Service Status:       $((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status)"
    Write-Host "Install Path:         $InstallPath"
    Write-Host "Config File:          $configPath"
    Write-Host "Log Directory:        $(Join-Path $InstallPath 'Logs')"
    Write-Host ""
    Write-Host "--- SMTP SETTINGS ---"
    Write-Host "SMTP Port:            $SmtpPort"
    Write-Host "Firewall Rule:        $ServiceName (Port $SmtpPort/TCP)"
    if ($SmtpAuthEnabled) {
        Write-Host "Authentication:       Enabled (AUTH PLAIN/LOGIN)"
        Write-Host "Auth Username:        $SmtpAuthUsername"
        Write-Host "Auth Password:        [CONFIGURED - NOT DISPLAYED]"
    } else {
        Write-Host "Authentication:       Disabled (open relay from allowed IPs)"
    }
    Write-Host "TLS/STARTTLS:         Not supported (plaintext SMTP only)"
    Write-Host ""
    Write-Host "--- ENCRYPTION ARCHITECTURE ---"
    Write-Host "Device -> Relay:      Plaintext SMTP (internal network)"
    Write-Host "Relay -> M365:        HTTPS/TLS (Graph API - always encrypted)"
    Write-Host ""
    Write-Host "--- ENTRA ID / MICROSOFT 365 ---"
    Write-Host "Tenant ID:            $tenantId"
    Write-Host "Application Name:     $AppName"
    Write-Host "Application (Client) ID: $clientId"
    Write-Host "Client Secret:        [CONFIGURED - NOT DISPLAYED]"
    if ($secretExpiryDate) {
        Write-Host "Secret Expiry Date:   $secretExpiryDate"
    }
    Write-Host "API Permission:       Mail.Send (Application)"
    Write-Host ""
    Write-Host "--- EMAIL CONFIGURATION ---"
    Write-Host "Send-As Address:      $sendAsAddress"
    Write-Host "Force Send-As:        $(if ($forceSendAs) { 'Yes (all mail sent from this address)' } else { 'No (original From address used when valid)' })"
    Write-Host "Save to Sent Items:   $(if ($config.SaveToSentItems) { 'Yes' } else { 'No' })"
    if ($reminderEmail) {
        Write-Host "Reminder Email:       $reminderEmail"
    }
    Write-Host ""
    Write-Host "--- DEVICE CONFIGURATION (for printers/scanners/apps) ---"
    Write-Host "SMTP Server:          $env:COMPUTERNAME"
    Write-Host "SMTP Port:            $SmtpPort"
    if ($SmtpAuthEnabled) {
        Write-Host "Username:             $SmtpAuthUsername"
        Write-Host "Password:             [Use the password configured above]"
    } else {
        Write-Host "Username:             [Not required]"
        Write-Host "Password:             [Not required]"
    }
    Write-Host "Encryption:           None / Disabled"
    Write-Host "STARTTLS:             Disabled"
    Write-Host "TLS/SSL:              Disabled"
    Write-Host "From Address:         [Any - will be overwritten to $sendAsAddress]"
    Write-Host ""
    Write-Host "Note: This is a plaintext relay. The Relay->M365 connection uses HTTPS."
    Write-Host ""
    Write-Host "--- MANAGEMENT COMMANDS ---"
    Write-Host "Check Status:         Get-Service '$ServiceName'"
    Write-Host "Start Service:        Start-Service '$ServiceName'"
    Write-Host "Stop Service:         Stop-Service '$ServiceName'"
    Write-Host "Restart Service:      Restart-Service '$ServiceName'"
    Write-Host "View Today's Log:     Get-Content '$(Join-Path $InstallPath 'Logs')\$($ServiceName -replace '[^a-zA-Z0-9]','')_$(Get-Date -Format 'yyyyMMdd').log' -Tail 100"
    Write-Host "Edit Config:          notepad '$configPath'"
    Write-Host "Uninstall:            & '$(Join-Path $InstallPath "Uninstall-$SafeServiceName.ps1")'"
    Write-Host ""
    Write-Host "--- TROUBLESHOOTING ---"
    Write-Host "Enable DEBUG logging: Edit config.json, change 'LogLevel': 'INFO' to 'LogLevel': 'DEBUG'"
    Write-Host "                      Restart service after changing. Shows detailed AUTH transaction logs."
    Write-Host ""
    Write-Host "--- TEST COMMAND ---"
    Write-Host "Send-MailMessage -SmtpServer $env:COMPUTERNAME -Port $SmtpPort ``"
    Write-Host "  -From 'test@test.com' -To 'youraddress@domain.com' ``"
    Write-Host "  -Subject 'SMTP Relay Test' -Body 'Test message from SMTP relay'"
    Write-Host ""
    if ($clientId) {
        Write-Host "--- SECURITY RECOMMENDATION ---"
        Write-Host "Restrict the Entra app to only send as the relay mailbox:"
        Write-Host ""
        Write-Host "New-ApplicationAccessPolicy ``"
        Write-Host "  -AppId '$clientId' ``"
        Write-Host "  -PolicyScopeGroupId '$sendAsAddress' ``"
        Write-Host "  -AccessRight RestrictAccess ``"
        Write-Host "  -Description 'Restrict $ServiceName to relay mailbox only'"
        Write-Host ""
    }
    Write-Host ("=" * 70)
    Write-Host ""
    Write-Host "  TIP: Select all text above (Ctrl+A in terminal) or scroll up to copy." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
