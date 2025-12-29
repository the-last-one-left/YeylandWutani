<#
.SYNOPSIS
    Tests SMTP configuration for MFP devices, applications, and servers.

.DESCRIPTION
    Comprehensive SMTP testing tool for validating email relay settings before 
    configuring multi-function printers, scanners, and line-of-business applications.
    
    Supports:
    - Port connectivity testing (25, 587, 465)
    - Microsoft 365 SMTP AUTH client submission
    - Microsoft 365 SMTP Relay (connector-based)
    - Microsoft 365 Direct Send
    - Microsoft Graph API (modern authentication)
    - Google Workspace SMTP (smtp.gmail.com)
    - Google Workspace SMTP Relay (smtp-relay.gmail.com)
    - Generic SMTP server testing
    
    Includes common pitfall detection and remediation guidance.

.PARAMETER Provider
    Email provider: Microsoft365, GoogleWorkspace, or Generic

.PARAMETER Method
    Connection method based on provider:
    - Microsoft365: SmtpAuth, SmtpRelay, DirectSend, GraphApi
    - GoogleWorkspace: SmtpAuth, SmtpRelay, Restricted
    - Generic: Standard

.PARAMETER SmtpServer
    SMTP server address (auto-populated based on provider/method if not specified)

.PARAMETER Port
    SMTP port (auto-populated based on method if not specified)

.PARAMETER FromAddress
    Sender email address

.PARAMETER ToAddress
    Recipient email address for test message

.PARAMETER Credential
    PSCredential for SMTP authentication

.PARAMETER AppPassword
    App password for Google Workspace (use instead of regular password)

.PARAMETER TenantId
    Azure AD tenant ID for Graph API authentication

.PARAMETER ClientId
    Azure AD application client ID for Graph API

.PARAMETER ClientSecret
    Azure AD application client secret for Graph API

.PARAMETER Domain
    Email domain (used to construct MX record for relay/direct send)

.PARAMETER UseTls
    Force TLS connection (default: true for ports 587/465)

.PARAMETER SkipPortTest
    Skip initial port connectivity tests

.PARAMETER Interactive
    Run in interactive guided mode

.PARAMETER GenerateReport
    Generate HTML report with test results

.PARAMETER ReportPath
    Path for HTML report output

.EXAMPLE
    Test-SMTPConfiguration -Interactive
    Runs the tool in interactive guided mode

.EXAMPLE
    Test-SMTPConfiguration -Provider Microsoft365 -Method SmtpAuth -FromAddress "scanner@contoso.com" -ToAddress "admin@contoso.com" -Credential (Get-Credential)
    Tests Microsoft 365 SMTP AUTH client submission

.EXAMPLE
    Test-SMTPConfiguration -Provider GoogleWorkspace -Method SmtpAuth -FromAddress "scanner@company.com" -ToAddress "admin@company.com" -AppPassword "xxxx xxxx xxxx xxxx"
    Tests Google Workspace with app password

.NOTES
    Author:         Yeyland Wutani LLC
    Version:        1.2.0
    Created:        2024-12-29
    Updated:        2024-12-29
    
    Changelog:
    - 1.2.0: Fixed TLS/STARTTLS detection, proper AUTH capability check after TLS upgrade
    - 1.1.0: Improved Graph API error handling, pre-flight auth validation
    
    IMPORTANT NOTES:
    
    Microsoft 365 SMTP AUTH Requirements:
    - SMTP AUTH must be enabled on the mailbox (disabled by default since 2020)
    - Security defaults must be disabled OR Conditional Access must exclude the mailbox
    - MFA users need app passwords OR use Graph API instead
    - Requires TLS 1.2 or higher
    - Basic auth deprecation: March 2026 (use Graph API for future-proofing)
    
    Google Workspace Requirements:
    - Less secure apps deprecated May 1, 2025
    - App passwords required for accounts with 2FA
    - SMTP relay requires admin configuration in Google Admin Console
    
    Port Information:
    - Port 25:  Often blocked by ISPs, used for relay/direct send
    - Port 587: STARTTLS, standard submission port
    - Port 465: Implicit TLS/SSL
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Direct')]
    [ValidateSet('Microsoft365', 'GoogleWorkspace', 'Generic')]
    [string]$Provider,

    [Parameter(ParameterSetName = 'Direct')]
    [ValidateSet('SmtpAuth', 'SmtpRelay', 'DirectSend', 'GraphApi', 'Restricted', 'Standard')]
    [string]$Method,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$SmtpServer,

    [Parameter(ParameterSetName = 'Direct')]
    [ValidateSet(25, 465, 587)]
    [int]$Port,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$FromAddress,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$ToAddress,

    [Parameter(ParameterSetName = 'Direct')]
    [PSCredential]$Credential,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$AppPassword,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$Domain,

    [Parameter(ParameterSetName = 'Direct')]
    [bool]$UseTls = $true,

    [Parameter(ParameterSetName = 'Direct')]
    [switch]$SkipPortTest,

    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive,

    [Parameter()]
    [switch]$GenerateReport,

    [Parameter()]
    [string]$ReportPath
)

#region Script Variables
$script:Version = "1.2.0"
$script:TestResults = [System.Collections.ArrayList]::new()
$script:Warnings = [System.Collections.ArrayList]::new()
$script:Recommendations = [System.Collections.ArrayList]::new()
$script:GraphToken = $null

# Yeyland Wutani Branding
$script:BrandOrange = "#FF6600"
$script:BrandGrey = "#6B7280"
$script:CompanyName = "Yeyland Wutani LLC"
$script:Tagline = "Building Better Systems"
#endregion

#region Helper Functions
function Show-Banner {
    $banner = @"

=================================================================================
  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ 
  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|
   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | 
    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|

                        B U I L D I N G   B E T T E R   S Y S T E M S
=================================================================================
          SMTP Configuration Tester v$($script:Version) - MFP/Device Validation
=================================================================================

"@
    Write-Host $banner -ForegroundColor DarkYellow
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $prefix = switch ($Level) {
        'Info'    { "[*]"; $color = "Cyan" }
        'Success' { "[+]"; $color = "Green" }
        'Warning' { "[!]"; $color = "Yellow" }
        'Error'   { "[-]"; $color = "Red" }
    }
    
    Write-Host "$timestamp $prefix " -ForegroundColor Gray -NoNewline
    Write-Host $Message -ForegroundColor $color
}

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Category,
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Skipped')]
        [string]$Status,
        [string]$Details,
        [string]$Recommendation
    )
    
    $null = $script:TestResults.Add([PSCustomObject]@{
        Timestamp      = Get-Date
        TestName       = $TestName
        Category       = $Category
        Status         = $Status
        Details        = $Details
        Recommendation = $Recommendation
    })
    
    $level = switch ($Status) {
        'Pass'    { 'Success' }
        'Fail'    { 'Error' }
        'Warning' { 'Warning' }
        default   { 'Info' }
    }
    
    Write-Log -Message "$TestName : $Details" -Level $level
    
    if ($Recommendation -and $Status -in @('Fail', 'Warning')) {
        $null = $script:Recommendations.Add($Recommendation)
    }
}

function Test-PortConnectivity {
    param(
        [string]$Server,
        [int]$Port,
        [int]$TimeoutMs = 5000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($Server, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle
        
        if (-not $waitHandle.WaitOne($TimeoutMs, $false)) {
            $tcpClient.Close()
            return @{
                Success = $false
                Error   = "Connection timed out after $($TimeoutMs)ms"
            }
        }
        
        $tcpClient.EndConnect($asyncResult)
        $connected = $tcpClient.Connected
        $tcpClient.Close()
        
        return @{
            Success = $connected
            Error   = $null
        }
    }
    catch {
        return @{
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}

function Test-TlsSupport {
    param(
        [string]$Server,
        [int]$Port
    )
    
    $results = @{
        Tls10 = $false
        Tls11 = $false
        Tls12 = $false
        Tls13 = $false
    }
    
    $protocols = @{
        'Tls10' = [System.Net.SecurityProtocolType]::Tls
        'Tls11' = [System.Net.SecurityProtocolType]::Tls11
        'Tls12' = [System.Net.SecurityProtocolType]::Tls12
    }
    
    # TLS 1.3 only available in newer .NET versions
    if ([Enum]::GetNames([System.Net.SecurityProtocolType]) -contains 'Tls13') {
        $protocols['Tls13'] = [System.Net.SecurityProtocolType]::Tls13
    }
    
    foreach ($proto in $protocols.Keys) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($Server, $Port)
            
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
            $sslStream.AuthenticateAsClient($Server, $null, $protocols[$proto], $false)
            
            $results[$proto] = $true
            $sslStream.Close()
            $tcpClient.Close()
        }
        catch {
            # Protocol not supported
        }
    }
    
    return $results
}

function Get-MxRecord {
    param([string]$Domain)
    
    try {
        $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop
        return $mxRecords | Sort-Object Preference | Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Get-M365MxEndpoint {
    param([string]$Domain)
    
    # Construct the expected M365 MX endpoint format
    $cleanDomain = $Domain.Replace('.', '-')
    return "$cleanDomain.mail.protection.outlook.com"
}

function Send-SmtpTestEmail {
    param(
        [string]$Server,
        [int]$Port,
        [string]$From,
        [string]$To,
        [PSCredential]$Credential,
        [bool]$UseSsl,
        [string]$Subject = "SMTP Test - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    )
    
    $body = @"
This is an automated SMTP test email sent by the Yeyland Wutani SMTP Configuration Tester.

Test Details:
- Server: $Server
- Port: $Port
- From: $From
- To: $To
- Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
- Computer: $env:COMPUTERNAME

If you received this email, the SMTP configuration is working correctly.

--
$script:CompanyName
$script:Tagline
"@
    
    try {
        $mailParams = @{
            SmtpServer = $Server
            Port       = $Port
            From       = $From
            To         = $To
            Subject    = $Subject
            Body       = $body
            UseSsl     = $UseSsl
        }
        
        if ($Credential) {
            $mailParams['Credential'] = $Credential
        }
        
        # Suppress the deprecation warning for Send-MailMessage
        $WarningPreference = 'SilentlyContinue'
        Send-MailMessage @mailParams -ErrorAction Stop
        $WarningPreference = 'Continue'
        
        return @{
            Success = $true
            Error   = $null
        }
    }
    catch {
        return @{
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}

function Send-GraphApiEmail {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$From,
        [string]$To,
        [string]$Subject = "SMTP Test via Graph API - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    )
    
    $bodyContent = @"
This is an automated test email sent via Microsoft Graph API by the Yeyland Wutani SMTP Configuration Tester.

Test Details:
- Method: Microsoft Graph API
- From: $From
- To: $To
- Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
- Computer: $env:COMPUTERNAME

If you received this email, the Graph API configuration is working correctly.

--
$script:CompanyName
$script:Tagline
"@
    
    # Step 1: Get access token (reuse if already acquired)
    $accessToken = $null
    
    if ($script:GraphToken) {
        Write-Log -Message "Using pre-acquired access token..." -Level Info
        $accessToken = $script:GraphToken
    }
    else {
        Write-Log -Message "Authenticating with Azure AD..." -Level Info
        
        try {
            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $tokenBody = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "https://graph.microsoft.com/.default"
            }
            
            $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $tokenBody -ErrorAction Stop
            $accessToken = $tokenResponse.access_token
            
            if (-not $accessToken) {
                return @{
                    Success = $false
                    Error   = "Token response received but access_token was empty"
                }
            }
            
            Write-Log -Message "Authentication successful, token acquired" -Level Success
        }
        catch {
            $authError = "Authentication failed: "
            
            if ($_.ErrorDetails.Message) {
                try {
                    $errorJson = $_.ErrorDetails.Message | ConvertFrom-Json
                    $authError += "$($errorJson.error): $($errorJson.error_description)"
                }
                catch {
                    $authError += $_.ErrorDetails.Message
                }
            }
            elseif ($_.Exception.Response) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                $authError += $responseBody
            }
            else {
                $authError += $_.Exception.Message
            }
            
            return @{
                Success = $false
                Error   = $authError
            }
        }
    }
    
    # Step 2: Send email via Graph API
    Write-Log -Message "Sending email via Graph API..." -Level Info
    
    try {
        # Construct email message
        $emailMessage = @{
            message = @{
                subject = $Subject
                body    = @{
                    contentType = "Text"
                    content     = $bodyContent
                }
                toRecipients = @(
                    @{
                        emailAddress = @{
                            address = $To
                        }
                    }
                )
            }
            saveToSentItems = $true
        }
        
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type"  = "application/json"
        }
        
        $sendMailUri = "https://graph.microsoft.com/v1.0/users/$From/sendMail"
        $jsonBody = $emailMessage | ConvertTo-Json -Depth 10 -Compress
        
        Write-Log -Message "Calling: POST $sendMailUri" -Level Info
        
        $response = Invoke-RestMethod -Uri $sendMailUri -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
        
        return @{
            Success = $true
            Error   = $null
        }
    }
    catch {
        $sendError = ""
        
        # Try multiple methods to extract the error
        if ($_.ErrorDetails.Message) {
            try {
                $errorJson = $_.ErrorDetails.Message | ConvertFrom-Json
                $sendError = "$($errorJson.error.code): $($errorJson.error.message)"
            }
            catch {
                $sendError = $_.ErrorDetails.Message
            }
        }
        elseif ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $responseBody = $reader.ReadToEnd()
                $reader.Close()
                $stream.Close()
                
                try {
                    $errorJson = $responseBody | ConvertFrom-Json
                    $sendError = "$($errorJson.error.code): $($errorJson.error.message)"
                }
                catch {
                    $sendError = $responseBody
                }
            }
            catch {
                $sendError = "HTTP $($_.Exception.Response.StatusCode.value__): $($_.Exception.Response.StatusDescription)"
            }
        }
        else {
            $sendError = $_.Exception.Message
        }
        
        # If still empty, try the full exception
        if ([string]::IsNullOrWhiteSpace($sendError)) {
            $sendError = $_.ToString()
        }
        
        # Common error translations
        if ($sendError -match "ErrorAccessDenied|Access is denied") {
            $sendError += " [Likely cause: Mail.Send application permission not granted or not admin-consented]"
        }
        elseif ($sendError -match "ResourceNotFound|does not exist") {
            $sendError += " [Likely cause: The From address mailbox does not exist or app lacks access]"
        }
        elseif ($sendError -match "InvalidAuthenticationToken") {
            $sendError += " [Likely cause: Token expired or invalid credentials]"
        }
        
        return @{
            Success = $false
            Error   = $sendError
        }
    }
}

function Test-SmtpAuthentication {
    param(
        [string]$Server,
        [int]$Port,
        [PSCredential]$Credential,
        [bool]$UseTls
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = 10000
        $tcpClient.SendTimeout = 10000
        $tcpClient.Connect($Server, $Port)
        
        $stream = $tcpClient.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        
        # Read banner
        $banner = $reader.ReadLine()
        
        # Send EHLO
        $writer.WriteLine("EHLO $env:COMPUTERNAME")
        Start-Sleep -Milliseconds 500
        
        $capabilities = @()
        while ($stream.DataAvailable) {
            $line = $reader.ReadLine()
            $capabilities += $line
        }
        
        $supportsAuth = $capabilities | Where-Object { $_ -match 'AUTH' }
        $supportsStartTls = $capabilities | Where-Object { $_ -match 'STARTTLS' }
        
        # If STARTTLS is supported and we're on port 587, try to upgrade and check AUTH again
        $postStartTlsAuth = $false
        $tlsUpgradeSuccess = $false
        
        if ($supportsStartTls -and $Port -eq 587) {
            try {
                $writer.WriteLine("STARTTLS")
                Start-Sleep -Milliseconds 500
                $startTlsResponse = $reader.ReadLine()
                
                if ($startTlsResponse -match "^220") {
                    # Upgrade to TLS
                    $sslStream = New-Object System.Net.Security.SslStream($stream, $false)
                    $sslStream.AuthenticateAsClient($Server)
                    $tlsUpgradeSuccess = $true
                    
                    # Create new reader/writer on SSL stream
                    $reader = New-Object System.IO.StreamReader($sslStream)
                    $writer = New-Object System.IO.StreamWriter($sslStream)
                    $writer.AutoFlush = $true
                    
                    # Send EHLO again after TLS
                    $writer.WriteLine("EHLO $env:COMPUTERNAME")
                    Start-Sleep -Milliseconds 500
                    
                    $tlsCapabilities = @()
                    while ($sslStream.CanRead) {
                        try {
                            $line = $reader.ReadLine()
                            if ($null -eq $line) { break }
                            $tlsCapabilities += $line
                            if ($line -match "^250 ") { break }  # Last capability line
                        }
                        catch { break }
                    }
                    
                    $postStartTlsAuth = $tlsCapabilities | Where-Object { $_ -match 'AUTH' }
                    
                    # Update capabilities with post-TLS capabilities
                    if ($tlsCapabilities.Count -gt 0) {
                        $capabilities = $tlsCapabilities
                        $supportsAuth = $postStartTlsAuth
                    }
                }
            }
            catch {
                # STARTTLS upgrade failed, continue with plain connection info
            }
        }
        
        # Cleanup
        try { $writer.WriteLine("QUIT") } catch { }
        try { $reader.Close() } catch { }
        try { $writer.Close() } catch { }
        try { $tcpClient.Close() } catch { }
        
        return @{
            Success            = $true
            Banner             = $banner
            SupportsAuth       = ($null -ne $supportsAuth)
            SupportsStartTls   = ($null -ne $supportsStartTls)
            TlsUpgradeSuccess  = $tlsUpgradeSuccess
            PostTlsAuth        = ($null -ne $postStartTlsAuth)
            Capabilities       = $capabilities
        }
    }
    catch {
        return @{
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}

function Get-SmtpServerSettings {
    param(
        [string]$Provider,
        [string]$Method,
        [string]$Domain
    )
    
    $settings = @{
        Server      = $null
        Port        = $null
        UseTls      = $true
        RequiresAuth = $true
        Notes       = @()
    }
    
    switch ($Provider) {
        'Microsoft365' {
            switch ($Method) {
                'SmtpAuth' {
                    $settings.Server = "smtp.office365.com"
                    $settings.Port = 587
                    $settings.UseTls = $true
                    $settings.RequiresAuth = $true
                    $settings.Notes += "Requires SMTP AUTH enabled on mailbox"
                    $settings.Notes += "Security defaults must be disabled or excluded"
                    $settings.Notes += "Basic auth deprecated March 2026"
                }
                'SmtpRelay' {
                    $settings.Server = Get-M365MxEndpoint -Domain $Domain
                    $settings.Port = 25
                    $settings.UseTls = $true
                    $settings.RequiresAuth = $false
                    $settings.Notes += "Requires inbound connector in Exchange Online"
                    $settings.Notes += "IP address must be added to connector"
                    $settings.Notes += "Add IP to SPF record for deliverability"
                }
                'DirectSend' {
                    $settings.Server = Get-M365MxEndpoint -Domain $Domain
                    $settings.Port = 25
                    $settings.UseTls = $false
                    $settings.RequiresAuth = $false
                    $settings.Notes += "Can only send to internal recipients"
                    $settings.Notes += "No authentication required"
                    $settings.Notes += "From address must be in accepted domain"
                }
                'GraphApi' {
                    $settings.Server = "graph.microsoft.com"
                    $settings.Port = 443
                    $settings.UseTls = $true
                    $settings.RequiresAuth = $true
                    $settings.Notes += "Requires Azure AD app registration"
                    $settings.Notes += "Needs Mail.Send application permission"
                    $settings.Notes += "Modern auth - future-proof solution"
                }
            }
        }
        'GoogleWorkspace' {
            switch ($Method) {
                'SmtpAuth' {
                    $settings.Server = "smtp.gmail.com"
                    $settings.Port = 587
                    $settings.UseTls = $true
                    $settings.RequiresAuth = $true
                    $settings.Notes += "Requires app password if 2FA enabled"
                    $settings.Notes += "Less secure apps deprecated May 2025"
                    $settings.Notes += "2000 messages/day limit"
                }
                'SmtpRelay' {
                    $settings.Server = "smtp-relay.gmail.com"
                    $settings.Port = 587
                    $settings.UseTls = $true
                    $settings.RequiresAuth = $true
                    $settings.Notes += "Requires Google Admin Console configuration"
                    $settings.Notes += "IP whitelist or SMTP auth required"
                    $settings.Notes += "10,000 messages/day limit"
                }
                'Restricted' {
                    $settings.Server = "aspmx.l.google.com"
                    $settings.Port = 25
                    $settings.UseTls = $false
                    $settings.RequiresAuth = $false
                    $settings.Notes += "Can only send to Gmail/Workspace recipients"
                    $settings.Notes += "IP must be allowlisted in Admin Console"
                    $settings.Notes += "No authentication required"
                }
            }
        }
    }
    
    return $settings
}
#endregion

#region Interactive Mode Functions
function Show-Menu {
    param(
        [string]$Title,
        [string[]]$Options,
        [string]$Prompt = "Select an option"
    )
    
    Write-Host "`n$Title" -ForegroundColor DarkYellow
    Write-Host ("-" * $Title.Length) -ForegroundColor Gray
    
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "  [$($i + 1)] " -ForegroundColor Cyan -NoNewline
        Write-Host $Options[$i] -ForegroundColor White
    }
    
    Write-Host ""
    do {
        $selection = Read-Host $Prompt
        $valid = $selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $Options.Count
        if (-not $valid) {
            Write-Host "Invalid selection. Please enter a number between 1 and $($Options.Count)" -ForegroundColor Red
        }
    } while (-not $valid)
    
    return [int]$selection
}

function Read-SecureInput {
    param(
        [string]$Prompt,
        [switch]$AsPlainText
    )
    
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    
    if ($AsPlainText) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    
    return $secure
}

function Start-InteractiveMode {
    Show-Banner
    
    Write-Host "This tool will help you test SMTP configuration for MFP devices," -ForegroundColor White
    Write-Host "scanners, and applications before deployment." -ForegroundColor White
    Write-Host ""
    
    # Step 1: Provider Selection
    $providerOptions = @(
        "Microsoft 365 / Office 365",
        "Google Workspace (G Suite)",
        "Generic SMTP Server",
        "Port Connectivity Test Only"
    )
    
    $providerChoice = Show-Menu -Title "Select Email Provider" -Options $providerOptions
    
    $config = @{
        Provider    = $null
        Method      = $null
        Server      = $null
        Port        = $null
        From        = $null
        To          = $null
        Credential  = $null
        Domain      = $null
        TenantId    = $null
        ClientId    = $null
        ClientSecret = $null
        UseTls      = $true
    }
    
    switch ($providerChoice) {
        1 { # Microsoft 365
            $config.Provider = 'Microsoft365'
            
            $m365Options = @(
                "SMTP AUTH Client Submission (smtp.office365.com:587) - Requires licensed mailbox",
                "SMTP Relay (MX endpoint:25) - Requires connector, IP-based auth",
                "Direct Send (MX endpoint:25) - Internal recipients only",
                "Graph API (Modern Auth) - Recommended for new implementations"
            )
            
            $methodChoice = Show-Menu -Title "Select Microsoft 365 Method" -Options $m365Options
            
            $config.Method = switch ($methodChoice) {
                1 { 'SmtpAuth' }
                2 { 'SmtpRelay' }
                3 { 'DirectSend' }
                4 { 'GraphApi' }
            }
            
            # Get domain for MX lookup
            Write-Host "`nEnter your email domain (e.g., contoso.com):" -ForegroundColor Cyan
            $config.Domain = Read-Host "Domain"
            
            if ($config.Method -eq 'GraphApi') {
                Write-Host "`nGraph API requires an Azure AD App Registration with Mail.Send permission." -ForegroundColor Yellow
                Write-Host "Enter the following details from your app registration:" -ForegroundColor White
                
                $config.TenantId = Read-Host "Tenant ID"
                $config.ClientId = Read-Host "Client ID (Application ID)"
                $config.ClientSecret = Read-SecureInput -Prompt "Client Secret" -AsPlainText
            }
            elseif ($config.Method -eq 'SmtpAuth') {
                Write-Host "`nEnter credentials for SMTP authentication:" -ForegroundColor Cyan
                $username = Read-Host "Username (full email address)"
                $password = Read-SecureInput -Prompt "Password (or app password)"
                $config.Credential = New-Object PSCredential($username, $password)
            }
        }
        
        2 { # Google Workspace
            $config.Provider = 'GoogleWorkspace'
            
            $googleOptions = @(
                "SMTP Auth (smtp.gmail.com:587) - Standard, requires app password with 2FA",
                "SMTP Relay (smtp-relay.gmail.com:587) - Admin configured, higher limits",
                "Restricted Server (aspmx.l.google.com:25) - Gmail/Workspace recipients only"
            )
            
            $methodChoice = Show-Menu -Title "Select Google Workspace Method" -Options $googleOptions
            
            $config.Method = switch ($methodChoice) {
                1 { 'SmtpAuth' }
                2 { 'SmtpRelay' }
                3 { 'Restricted' }
            }
            
            Write-Host "`nEnter your Google Workspace domain (e.g., company.com):" -ForegroundColor Cyan
            $config.Domain = Read-Host "Domain"
            
            if ($config.Method -in @('SmtpAuth', 'SmtpRelay')) {
                Write-Host "`nEnter credentials for SMTP authentication:" -ForegroundColor Cyan
                Write-Host "(Use App Password if 2FA is enabled - generate at myaccount.google.com)" -ForegroundColor Yellow
                $username = Read-Host "Username (full email address)"
                $password = Read-SecureInput -Prompt "Password or App Password"
                $config.Credential = New-Object PSCredential($username, $password)
            }
        }
        
        3 { # Generic SMTP
            $config.Provider = 'Generic'
            $config.Method = 'Standard'
            
            Write-Host "`nEnter SMTP server details:" -ForegroundColor Cyan
            $config.Server = Read-Host "SMTP Server Address"
            $config.Port = [int](Read-Host "Port (25, 465, or 587)")
            
            $authChoice = Show-Menu -Title "Authentication Required?" -Options @("Yes", "No")
            if ($authChoice -eq 1) {
                $username = Read-Host "Username"
                $password = Read-SecureInput -Prompt "Password"
                $config.Credential = New-Object PSCredential($username, $password)
            }
            
            $tlsChoice = Show-Menu -Title "Use TLS/SSL?" -Options @("Yes (Recommended)", "No")
            $config.UseTls = ($tlsChoice -eq 1)
        }
        
        4 { # Port Test Only
            Write-Host "`nEnter server to test port connectivity:" -ForegroundColor Cyan
            $testServer = Read-Host "Server Address"
            
            Write-Host "`n" -NoNewline
            Write-Log -Message "Testing port connectivity to $testServer" -Level Info
            Write-Host ""
            
            $ports = @(25, 465, 587)
            foreach ($p in $ports) {
                $result = Test-PortConnectivity -Server $testServer -Port $p
                if ($result.Success) {
                    Add-TestResult -TestName "Port $p" -Category "Connectivity" -Status "Pass" -Details "Port $p is open and reachable"
                }
                else {
                    Add-TestResult -TestName "Port $p" -Category "Connectivity" -Status "Fail" -Details "Port $p is blocked or unreachable: $($result.Error)" -Recommendation "Check firewall rules or contact ISP if port 25 is blocked"
                }
            }
            
            return
        }
    }
    
    # Get From/To addresses
    if ($config.Provider -ne 'Generic' -or $config.Method -ne 'PortOnly') {
        Write-Host "`nEnter email addresses for test:" -ForegroundColor Cyan
        $config.From = Read-Host "From Address"
        $config.To = Read-Host "To Address"
    }
    
    # Get server settings based on provider/method
    if (-not $config.Server) {
        $serverSettings = Get-SmtpServerSettings -Provider $config.Provider -Method $config.Method -Domain $config.Domain
        $config.Server = $serverSettings.Server
        $config.Port = $serverSettings.Port
        $config.UseTls = $serverSettings.UseTls
        
        Write-Host "`nServer Settings:" -ForegroundColor DarkYellow
        Write-Host "  Server: $($config.Server)" -ForegroundColor White
        Write-Host "  Port:   $($config.Port)" -ForegroundColor White
        Write-Host "  TLS:    $($config.UseTls)" -ForegroundColor White
        
        if ($serverSettings.Notes.Count -gt 0) {
            Write-Host "`nImportant Notes:" -ForegroundColor Yellow
            foreach ($note in $serverSettings.Notes) {
                Write-Host "  - $note" -ForegroundColor White
            }
        }
    }
    
    # Confirm and run tests
    Write-Host "`n"
    $confirmChoice = Show-Menu -Title "Ready to run tests?" -Options @("Yes, run all tests", "Cancel")
    
    if ($confirmChoice -eq 2) {
        Write-Host "`nTest cancelled." -ForegroundColor Yellow
        return
    }
    
    # Run the tests
    Write-Host "`n"
    Start-SmtpTests -Config $config
}
#endregion

#region Main Test Functions
function Start-SmtpTests {
    param([hashtable]$Config)
    
    Write-Log -Message "Starting SMTP Configuration Tests" -Level Info
    Write-Host ""
    
    # Test 1: Port Connectivity
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host " PHASE 1: Port Connectivity Tests" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor Gray
    
    if ($Config.Method -ne 'GraphApi') {
        $portResult = Test-PortConnectivity -Server $Config.Server -Port $Config.Port
        
        if ($portResult.Success) {
            Add-TestResult -TestName "Port $($Config.Port) Connectivity" -Category "Network" -Status "Pass" -Details "Successfully connected to $($Config.Server):$($Config.Port)"
        }
        else {
            Add-TestResult -TestName "Port $($Config.Port) Connectivity" -Category "Network" -Status "Fail" -Details "Failed to connect: $($portResult.Error)" -Recommendation "Check firewall rules, verify server address, or contact ISP if port 25 is blocked"
            
            if ($Config.Port -eq 25) {
                $null = $script:Warnings.Add("Port 25 is commonly blocked by ISPs and cloud providers. Consider using port 587 with SMTP AUTH instead.")
            }
            
            # Don't continue if we can't connect
            Write-Host ""
            Write-Log -Message "Cannot proceed without port connectivity. Please resolve network issues first." -Level Error
            return
        }
        
        # Additional port tests
        $additionalPorts = @(25, 465, 587) | Where-Object { $_ -ne $Config.Port }
        foreach ($port in $additionalPorts) {
            $result = Test-PortConnectivity -Server $Config.Server -Port $port -TimeoutMs 3000
            $status = if ($result.Success) { "Pass" } else { "Info" }
            $details = if ($result.Success) { "Port $port is also available" } else { "Port $port not reachable (may not be needed)" }
            Add-TestResult -TestName "Port $port (Alternate)" -Category "Network" -Status $status -Details $details
        }
    }
    else {
        # Graph API - test HTTPS connectivity to required endpoints
        Add-TestResult -TestName "Graph API Endpoint" -Category "Network" -Status "Info" -Details "Graph API uses HTTPS (443) - testing connectivity..."
        
        $graphEndpoints = @(
            @{ Name = "Azure AD Login"; Url = "login.microsoftonline.com"; Port = 443 }
            @{ Name = "Microsoft Graph"; Url = "graph.microsoft.com"; Port = 443 }
        )
        
        foreach ($endpoint in $graphEndpoints) {
            $result = Test-PortConnectivity -Server $endpoint.Url -Port $endpoint.Port
            if ($result.Success) {
                Add-TestResult -TestName "$($endpoint.Name) Connectivity" -Category "Network" -Status "Pass" -Details "Connected to $($endpoint.Url):$($endpoint.Port)"
            }
            else {
                Add-TestResult -TestName "$($endpoint.Name) Connectivity" -Category "Network" -Status "Fail" -Details "Cannot reach $($endpoint.Url): $($result.Error)" -Recommendation "Check firewall/proxy settings - Graph API requires HTTPS access to Microsoft endpoints"
            }
        }
        
        # Test authentication before email send
        Write-Host ""
        Write-Log -Message "Testing Graph API authentication..." -Level Info
        
        try {
            $tokenEndpoint = "https://login.microsoftonline.com/$($Config.TenantId)/oauth2/v2.0/token"
            $tokenBody = @{
                grant_type    = "client_credentials"
                client_id     = $Config.ClientId
                client_secret = $Config.ClientSecret
                scope         = "https://graph.microsoft.com/.default"
            }
            
            $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $tokenBody -ErrorAction Stop
            
            if ($tokenResponse.access_token) {
                Add-TestResult -TestName "Azure AD Authentication" -Category "Auth" -Status "Pass" -Details "Successfully acquired access token (expires in $($tokenResponse.expires_in)s)"
                
                # Store token for later use
                $script:GraphToken = $tokenResponse.access_token
                
                # Check if we have Mail.Send permission by examining token (optional)
                try {
                    $tokenParts = $tokenResponse.access_token.Split('.')
                    if ($tokenParts.Count -ge 2) {
                        # Decode JWT payload (base64url)
                        $payload = $tokenParts[1]
                        $payload = $payload.Replace('-', '+').Replace('_', '/')
                        switch ($payload.Length % 4) {
                            2 { $payload += '==' }
                            3 { $payload += '=' }
                        }
                        $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
                        
                        if ($decodedPayload.roles -contains 'Mail.Send') {
                            Add-TestResult -TestName "Mail.Send Permission" -Category "Auth" -Status "Pass" -Details "Token includes Mail.Send application permission"
                        }
                        else {
                            $rolesFound = if ($decodedPayload.roles) { $decodedPayload.roles -join ', ' } else { 'None' }
                            Add-TestResult -TestName "Mail.Send Permission" -Category "Auth" -Status "Warning" -Details "Mail.Send not found in token roles. Found: $rolesFound" -Recommendation "Add Mail.Send application permission in Azure AD and grant admin consent"
                        }
                    }
                }
                catch {
                    Add-TestResult -TestName "Permission Check" -Category "Auth" -Status "Info" -Details "Could not decode token to verify permissions (will test during send)"
                }
            }
            else {
                Add-TestResult -TestName "Azure AD Authentication" -Category "Auth" -Status "Fail" -Details "Token response received but no access_token present"
            }
        }
        catch {
            $authError = ""
            if ($_.ErrorDetails.Message) {
                try {
                    $errorJson = $_.ErrorDetails.Message | ConvertFrom-Json
                    $authError = "$($errorJson.error): $($errorJson.error_description)"
                }
                catch {
                    $authError = $_.ErrorDetails.Message
                }
            }
            else {
                $authError = $_.Exception.Message
            }
            
            Add-TestResult -TestName "Azure AD Authentication" -Category "Auth" -Status "Fail" -Details "Authentication failed: $authError" -Recommendation "Verify Tenant ID, Client ID, and Client Secret are correct"
            
            Write-Host ""
            Write-Log -Message "Cannot proceed without valid authentication. Please check Azure AD app registration." -Level Error
            
            Show-TestSummary -Config $Config
            return
        }
    }
    
    # Test 2: TLS Support
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host " PHASE 2: TLS/Security Tests" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor Gray
    
    if ($Config.Method -ne 'GraphApi') {
        # Port 587 uses STARTTLS (upgrade), Port 465 uses implicit TLS
        if ($Config.Port -eq 587) {
            # TLS will be tested during SMTP capability check via STARTTLS
            Add-TestResult -TestName "TLS Mode" -Category "Security" -Status "Info" -Details "Port 587 uses STARTTLS - TLS upgrade will be tested during SMTP phase"
        }
        elseif ($Config.Port -eq 465) {
            # Direct TLS connection
            $tlsResults = Test-TlsSupport -Server $Config.Server -Port $Config.Port
            
            if ($tlsResults.Tls12 -or $tlsResults.Tls13) {
                $supportedVersions = @()
                if ($tlsResults.Tls12) { $supportedVersions += "TLS 1.2" }
                if ($tlsResults.Tls13) { $supportedVersions += "TLS 1.3" }
                
                Add-TestResult -TestName "TLS Support" -Category "Security" -Status "Pass" -Details "Server supports: $($supportedVersions -join ', ')"
            }
            else {
                Add-TestResult -TestName "TLS Support" -Category "Security" -Status "Warning" -Details "Could not verify TLS 1.2+ support on port 465" -Recommendation "Microsoft 365 requires TLS 1.2 or higher. Verify device supports modern TLS."
            }
            
            if ($tlsResults.Tls10 -or $tlsResults.Tls11) {
                Add-TestResult -TestName "Legacy TLS" -Category "Security" -Status "Warning" -Details "Server still accepts TLS 1.0/1.1 (deprecated)" -Recommendation "Consider disabling TLS 1.0/1.1 for security"
            }
        }
        elseif ($Config.Port -eq 25) {
            Add-TestResult -TestName "TLS Mode" -Category "Security" -Status "Info" -Details "Port 25 may use opportunistic STARTTLS or no encryption"
        }
    }
    
    # Test 3: SMTP Capabilities
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host " PHASE 3: SMTP Capability Tests" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor Gray
    
    if ($Config.Method -notin @('GraphApi', 'DirectSend', 'Restricted')) {
        $smtpCaps = Test-SmtpAuthentication -Server $Config.Server -Port $Config.Port -Credential $Config.Credential -UseTls $Config.UseTls
        
        if ($smtpCaps.Success) {
            Add-TestResult -TestName "SMTP Banner" -Category "SMTP" -Status "Info" -Details $smtpCaps.Banner
            
            if ($smtpCaps.SupportsStartTls) {
                Add-TestResult -TestName "STARTTLS Support" -Category "SMTP" -Status "Pass" -Details "Server supports STARTTLS encryption upgrade"
                
                if ($smtpCaps.TlsUpgradeSuccess) {
                    Add-TestResult -TestName "TLS Upgrade" -Category "Security" -Status "Pass" -Details "Successfully upgraded connection to TLS"
                }
            }
            
            # Check AUTH - consider post-STARTTLS if applicable
            if ($smtpCaps.SupportsAuth) {
                if ($smtpCaps.PostTlsAuth) {
                    Add-TestResult -TestName "AUTH Support" -Category "SMTP" -Status "Pass" -Details "Server advertises AUTH after STARTTLS (secure configuration)"
                }
                else {
                    Add-TestResult -TestName "AUTH Support" -Category "SMTP" -Status "Pass" -Details "Server advertises AUTH capability"
                }
            }
            elseif ($smtpCaps.SupportsStartTls -and -not $smtpCaps.TlsUpgradeSuccess) {
                # Server has STARTTLS but we couldn't upgrade to check AUTH
                Add-TestResult -TestName "AUTH Support" -Category "SMTP" -Status "Info" -Details "AUTH typically available after STARTTLS (M365 standard behavior)"
            }
            else {
                Add-TestResult -TestName "AUTH Support" -Category "SMTP" -Status "Warning" -Details "Server does not advertise AUTH" -Recommendation "Server may require STARTTLS before advertising AUTH, or authentication is not supported"
            }
        }
        else {
            Add-TestResult -TestName "SMTP Capabilities" -Category "SMTP" -Status "Warning" -Details "Could not enumerate capabilities: $($smtpCaps.Error)"
        }
    }
    
    # Test 4: DNS/MX Validation
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host " PHASE 4: DNS Validation" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor Gray
    
    if ($Config.Domain) {
        $mx = Get-MxRecord -Domain $Config.Domain
        if ($mx) {
            Add-TestResult -TestName "MX Record" -Category "DNS" -Status "Pass" -Details "MX: $($mx.NameExchange) (Priority: $($mx.Preference))"
            
            # Check if MX matches expected endpoint
            if ($Config.Provider -eq 'Microsoft365' -and $Config.Method -in @('SmtpRelay', 'DirectSend')) {
                $expectedMx = Get-M365MxEndpoint -Domain $Config.Domain
                if ($mx.NameExchange -like "*mail.protection.outlook.com*") {
                    Add-TestResult -TestName "M365 MX Validation" -Category "DNS" -Status "Pass" -Details "Domain uses Microsoft 365 for email"
                }
                else {
                    Add-TestResult -TestName "M365 MX Validation" -Category "DNS" -Status "Warning" -Details "MX does not point to Microsoft 365" -Recommendation "SMTP Relay/Direct Send requires mail to flow through M365"
                }
            }
        }
        else {
            Add-TestResult -TestName "MX Record" -Category "DNS" -Status "Warning" -Details "Could not resolve MX record for $($Config.Domain)"
        }
    }
    
    # Test 5: Send Test Email
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host " PHASE 5: Email Delivery Test" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor Gray
    
    $sendChoice = Show-Menu -Title "Send a test email?" -Options @("Yes", "No (skip)")
    
    if ($sendChoice -eq 1) {
        Write-Log -Message "Attempting to send test email..." -Level Info
        
        $sendResult = $null
        
        if ($Config.Method -eq 'GraphApi') {
            $sendResult = Send-GraphApiEmail -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret -From $Config.From -To $Config.To
        }
        else {
            # Build credential if we have username/password
            $cred = $Config.Credential
            
            $sendResult = Send-SmtpTestEmail -Server $Config.Server -Port $Config.Port -From $Config.From -To $Config.To -Credential $cred -UseSsl $Config.UseTls
        }
        
        if ($sendResult.Success) {
            Add-TestResult -TestName "Email Delivery" -Category "Delivery" -Status "Pass" -Details "Test email sent successfully to $($Config.To)"
        }
        else {
            Add-TestResult -TestName "Email Delivery" -Category "Delivery" -Status "Fail" -Details "Failed to send: $($sendResult.Error)"
            
            # Add specific recommendations based on error
            $errorLower = $sendResult.Error.ToLower()
            
            if ($errorLower -match "authentication|credential|password|535") {
                $null = $script:Recommendations.Add("Authentication failed. For M365: Verify SMTP AUTH is enabled on mailbox. For Google: Use App Password if 2FA enabled.")
            }
            
            if ($errorLower -match "5.7.60|sender") {
                $null = $script:Recommendations.Add("Sender address rejected. Ensure the From address matches the authenticated user or is an authorized alias.")
            }
            
            if ($errorLower -match "5.7.57|security default") {
                $null = $script:Recommendations.Add("Security defaults are blocking basic auth. Disable security defaults or use Conditional Access to exclude this account.")
            }
            
            if ($errorLower -match "relay|5.7.1") {
                $null = $script:Recommendations.Add("Relay denied. For M365 SMTP Relay: Verify connector is configured and IP is authorized.")
            }
            
            if ($errorLower -match "erroraccessdenied|mail.send") {
                $null = $script:Recommendations.Add("Graph API access denied. Verify Mail.Send application permission is granted and admin consented.")
            }
        }
    }
    else {
        Add-TestResult -TestName "Email Delivery" -Category "Delivery" -Status "Skipped" -Details "User chose to skip email delivery test"
    }
    
    # Display Summary
    Show-TestSummary -Config $Config
    
    # Generate Report if requested
    if ($GenerateReport -or (Show-Menu -Title "Generate HTML Report?" -Options @("Yes", "No")) -eq 1) {
        $reportFile = if ($ReportPath) { $ReportPath } else { "SMTP-Test-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html" }
        Export-HtmlReport -Path $reportFile -Config $Config
        Write-Log -Message "Report saved to: $reportFile" -Level Success
    }
}

function Show-TestSummary {
    param([hashtable]$Config)
    
    Write-Host "`n"
    Write-Host "=" * 60 -ForegroundColor DarkYellow
    Write-Host " TEST SUMMARY" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor DarkYellow
    
    $passed = ($script:TestResults | Where-Object { $_.Status -eq 'Pass' }).Count
    $failed = ($script:TestResults | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnings = ($script:TestResults | Where-Object { $_.Status -eq 'Warning' }).Count
    
    Write-Host ""
    Write-Host "  Results: " -NoNewline -ForegroundColor White
    Write-Host "$passed Passed" -ForegroundColor Green -NoNewline
    Write-Host " | " -ForegroundColor Gray -NoNewline
    Write-Host "$failed Failed" -ForegroundColor Red -NoNewline
    Write-Host " | " -ForegroundColor Gray -NoNewline
    Write-Host "$warnings Warnings" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "  Configuration Tested:" -ForegroundColor White
    Write-Host "    Provider:  $($Config.Provider)" -ForegroundColor Gray
    Write-Host "    Method:    $($Config.Method)" -ForegroundColor Gray
    Write-Host "    Server:    $($Config.Server)" -ForegroundColor Gray
    Write-Host "    Port:      $($Config.Port)" -ForegroundColor Gray
    
    if ($script:Recommendations.Count -gt 0) {
        Write-Host ""
        Write-Host "  Recommendations:" -ForegroundColor Yellow
        $script:Recommendations | Select-Object -Unique | ForEach-Object {
            Write-Host "    - $_" -ForegroundColor White
        }
    }
    
    # MFP Configuration Summary
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkYellow
    Write-Host " MFP/DEVICE CONFIGURATION" -ForegroundColor DarkYellow
    Write-Host "=" * 60 -ForegroundColor DarkYellow
    
    if ($failed -eq 0) {
        Write-Host ""
        Write-Host "  Use these settings in your device:" -ForegroundColor Green
        Write-Host ""
        Write-Host "    SMTP Server:     $($Config.Server)" -ForegroundColor White
        Write-Host "    Port:            $($Config.Port)" -ForegroundColor White
        Write-Host "    Encryption:      $(if ($Config.UseTls) { 'TLS/STARTTLS' } else { 'None' })" -ForegroundColor White
        
        if ($Config.Credential) {
            Write-Host "    Authentication:  Required" -ForegroundColor White
            Write-Host "    Username:        $($Config.Credential.UserName)" -ForegroundColor White
            Write-Host "    Password:        (as configured)" -ForegroundColor White
        }
        elseif ($Config.Method -eq 'GraphApi') {
            Write-Host "    Authentication:  Graph API (not applicable to MFP)" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Note: Graph API is for applications, not MFP devices." -ForegroundColor Yellow
            Write-Host "  For MFP, use SMTP AUTH or SMTP Relay instead." -ForegroundColor Yellow
        }
        else {
            Write-Host "    Authentication:  None (IP-based)" -ForegroundColor White
        }
        
        Write-Host "    From Address:    $($Config.From)" -ForegroundColor White
    }
    else {
        Write-Host ""
        Write-Host "  Configuration issues detected. Please resolve before configuring device." -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Gray
    Write-Host ""
}

function Export-HtmlReport {
    param(
        [string]$Path,
        [hashtable]$Config
    )
    
    $passed = ($script:TestResults | Where-Object { $_.Status -eq 'Pass' }).Count
    $failed = ($script:TestResults | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnings = ($script:TestResults | Where-Object { $_.Status -eq 'Warning' }).Count
    $total = $script:TestResults.Count
    
    $statusColor = if ($failed -gt 0) { "#DC2626" } elseif ($warnings -gt 0) { "#D97706" } else { "#059669" }
    $statusText = if ($failed -gt 0) { "Issues Detected" } elseif ($warnings -gt 0) { "Warnings" } else { "All Tests Passed" }
    
    $testRowsHtml = ""
    foreach ($test in $script:TestResults) {
        $rowColor = switch ($test.Status) {
            'Pass'    { "#059669" }
            'Fail'    { "#DC2626" }
            'Warning' { "#D97706" }
            'Info'    { "#6B7280" }
            'Skipped' { "#9CA3AF" }
        }
        
        $testRowsHtml += @"
        <tr>
            <td>$($test.TestName)</td>
            <td>$($test.Category)</td>
            <td style="color: $rowColor; font-weight: 600;">$($test.Status)</td>
            <td>$($test.Details)</td>
            <td>$(if ($test.Recommendation) { $test.Recommendation } else { '-' })</td>
        </tr>
"@
    }
    
    $recommendationsHtml = ""
    if ($script:Recommendations.Count -gt 0) {
        $recommendationsHtml = @"
    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
"@
        $script:Recommendations | Select-Object -Unique | ForEach-Object {
            $recommendationsHtml += "            <li>$_</li>`n"
        }
        $recommendationsHtml += @"
        </ul>
    </div>
"@
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMTP Configuration Test Report</title>
    <style>
        :root {
            --brand-orange: $($script:BrandOrange);
            --brand-grey: $($script:BrandGrey);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #F3F4F6;
            color: #1F2937;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, var(--brand-orange) 0%, #CC5200 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .header h1 {
            font-size: 1.75rem;
            margin-bottom: 0.5rem;
        }
        
        .header .tagline {
            opacity: 0.9;
            font-size: 0.9rem;
            letter-spacing: 2px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .summary-card.status {
            border-left: 4px solid $statusColor;
        }
        
        .summary-card h3 {
            color: var(--brand-grey);
            font-size: 0.875rem;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .summary-card .value.status {
            color: $statusColor;
        }
        
        .config-section, .results-section, .recommendations, .mfp-config {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        h2 {
            color: var(--brand-orange);
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #E5E7EB;
        }
        
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .config-item {
            padding: 0.75rem;
            background: #F9FAFB;
            border-radius: 4px;
        }
        
        .config-item label {
            display: block;
            font-size: 0.75rem;
            color: var(--brand-grey);
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }
        
        .config-item span {
            font-weight: 600;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #E5E7EB;
        }
        
        th {
            background: #F9FAFB;
            font-weight: 600;
            color: var(--brand-grey);
            font-size: 0.875rem;
        }
        
        tr:hover {
            background: #F9FAFB;
        }
        
        .recommendations ul {
            list-style: none;
            padding: 0;
        }
        
        .recommendations li {
            padding: 0.75rem;
            background: #FEF3C7;
            border-left: 3px solid #D97706;
            margin-bottom: 0.5rem;
            border-radius: 0 4px 4px 0;
        }
        
        .mfp-config .config-display {
            background: #F0FDF4;
            border: 1px solid #BBF7D0;
            border-radius: 4px;
            padding: 1rem;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        
        .mfp-config .config-display div {
            margin-bottom: 0.25rem;
        }
        
        .mfp-config .config-display .label {
            color: var(--brand-grey);
            display: inline-block;
            width: 150px;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--brand-grey);
            font-size: 0.875rem;
        }
        
        .footer a {
            color: var(--brand-orange);
            text-decoration: none;
        }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            th, td { padding: 0.5rem; font-size: 0.875rem; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>SMTP Configuration Test Report</h1>
        <div class="tagline">$($script:CompanyName) - $($script:Tagline)</div>
    </div>
    
    <div class="container">
        <div class="summary-grid">
            <div class="summary-card status">
                <h3>Overall Status</h3>
                <div class="value status">$statusText</div>
            </div>
            <div class="summary-card">
                <h3>Tests Passed</h3>
                <div class="value" style="color: #059669;">$passed / $total</div>
            </div>
            <div class="summary-card">
                <h3>Warnings</h3>
                <div class="value" style="color: #D97706;">$warnings</div>
            </div>
            <div class="summary-card">
                <h3>Failed</h3>
                <div class="value" style="color: #DC2626;">$failed</div>
            </div>
        </div>
        
        <div class="config-section">
            <h2>Test Configuration</h2>
            <div class="config-grid">
                <div class="config-item">
                    <label>Provider</label>
                    <span>$($Config.Provider)</span>
                </div>
                <div class="config-item">
                    <label>Method</label>
                    <span>$($Config.Method)</span>
                </div>
                <div class="config-item">
                    <label>Server</label>
                    <span>$($Config.Server)</span>
                </div>
                <div class="config-item">
                    <label>Port</label>
                    <span>$($Config.Port)</span>
                </div>
                <div class="config-item">
                    <label>TLS Enabled</label>
                    <span>$($Config.UseTls)</span>
                </div>
                <div class="config-item">
                    <label>Test Date</label>
                    <span>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
                </div>
                <div class="config-item">
                    <label>From Address</label>
                    <span>$($Config.From)</span>
                </div>
                <div class="config-item">
                    <label>To Address</label>
                    <span>$($Config.To)</span>
                </div>
            </div>
        </div>
        
        <div class="results-section">
            <h2>Test Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Test Name</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Details</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    $testRowsHtml
                </tbody>
            </table>
        </div>
        
        $recommendationsHtml
        
        <div class="mfp-config">
            <h2>MFP/Device Configuration Settings</h2>
            <div class="config-display">
                <div><span class="label">SMTP Server:</span> $($Config.Server)</div>
                <div><span class="label">Port:</span> $($Config.Port)</div>
                <div><span class="label">Encryption:</span> $(if ($Config.UseTls) { 'TLS/STARTTLS' } else { 'None' })</div>
                <div><span class="label">Authentication:</span> $(if ($Config.Credential) { 'Required' } else { 'None (IP-based)' })</div>
                $(if ($Config.Credential) { "<div><span class='label'>Username:</span> $($Config.Credential.UserName)</div>" })
                <div><span class="label">From Address:</span> $($Config.From)</div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by <a href="#">$($script:CompanyName)</a> SMTP Configuration Tester v$($script:Version)</p>
        <p>$($script:Tagline)</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $Path -Encoding UTF8
}
#endregion

#region Main Execution
# Determine execution mode
if ($PSCmdlet.ParameterSetName -eq 'Interactive' -or $Interactive -or -not $Provider) {
    Start-InteractiveMode
}
else {
    # Direct parameter mode
    Show-Banner
    
    $config = @{
        Provider     = $Provider
        Method       = $Method
        Server       = $SmtpServer
        Port         = $Port
        From         = $FromAddress
        To           = $ToAddress
        Credential   = $Credential
        Domain       = $Domain
        TenantId     = $TenantId
        ClientId     = $ClientId
        ClientSecret = $ClientSecret
        UseTls       = $UseTls
    }
    
    # Auto-populate server settings if not provided
    if (-not $config.Server -or -not $config.Port) {
        $serverSettings = Get-SmtpServerSettings -Provider $Provider -Method $Method -Domain $Domain
        if (-not $config.Server) { $config.Server = $serverSettings.Server }
        if (-not $config.Port) { $config.Port = $serverSettings.Port }
        $config.UseTls = $serverSettings.UseTls
    }
    
    # Handle app password for Google
    if ($AppPassword -and $Provider -eq 'GoogleWorkspace') {
        $securePassword = ConvertTo-SecureString $AppPassword -AsPlainText -Force
        $config.Credential = New-Object PSCredential($FromAddress, $securePassword)
    }
    
    Start-SmtpTests -Config $config
}
#endregion
