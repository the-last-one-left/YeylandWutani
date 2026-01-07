<#
.SYNOPSIS
    Monitors system availability and reports online systems via Microsoft Graph API email.

.DESCRIPTION
    Scheduled task-ready monitoring script for domain environments. Monitors specified
    systems for online status and collects detailed information when online, including:
    - Open TCP ports (common services)
    - Device type and OS information
    - Last logged-on user
    - System hardware details
    - Network configuration

    When online systems are detected, sends comprehensive report via Microsoft Graph API.
    Designed for security monitoring, asset tracking, and compliance reporting.

.PARAMETER ComputerName
    Hostname(s) or IP address(es) of systems to monitor.
    Supports comma-separated list or pipeline input.

.PARAMETER TenantId
    Microsoft 365 Tenant ID for Graph API authentication.
    Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

.PARAMETER ClientId
    Azure App Registration Client ID (Application ID).
    Requires Mail.Send API permission.

.PARAMETER ClientSecret
    Azure App Registration Client Secret value.
    Store securely and pass as secure string when possible.

.PARAMETER EmailTo
    Recipient email address(es) for online system alerts.
    Supports multiple addresses comma-separated.

.PARAMETER EmailFrom
    Sender email address. Must be valid mailbox in tenant.
    Requires appropriate Graph API permissions.

.PARAMETER PortsToScan
    TCP ports to scan when system is online.
    Default: Common ports (RDP, SMB, HTTP, HTTPS, WinRM, etc.)

.PARAMETER ScanTimeout
    Timeout in milliseconds for port scanning. Default: 1000ms

.PARAMETER IncludeOfflineSystems
    Include offline systems in the report.
    Default: Only reports systems that are online.

.PARAMETER ExportPath
    Optional path to export detailed results (JSON or CSV format).

.PARAMETER AlertLogPath
    Path to JSON file tracking when alerts were last sent for each system.
    Default: $env:ProgramData\SystemMonitor\AlertLog.json
    Prevents duplicate alerts for same system within 24 hours.

.PARAMETER UseSecureString
    Indicates ClientSecret parameter is provided as SecureString.

.EXAMPLE
    .\Invoke-SystemOnlineMonitor.ps1 -ComputerName "WORKSTATION01","WORKSTATION02" `
        -TenantId "12345678-1234-1234-1234-123456789012" `
        -ClientId "abcdef12-3456-7890-abcd-ef1234567890" `
        -ClientSecret "your_client_secret_here" `
        -EmailTo "security@contoso.com" `
        -EmailFrom "monitoring@contoso.com"

    Monitor two workstations and email results if they come online.

.EXAMPLE
    Get-Content "C:\MonitorList.txt" | .\Invoke-SystemOnlineMonitor.ps1 `
        -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
        -EmailTo "alerts@contoso.com" -EmailFrom "monitor@contoso.com" `
        -ExportPath "C:\Logs\OnlineReport.json"

    Monitor systems from file, send Graph API email, and export detailed JSON report.

.EXAMPLE
    $params = @{
        ComputerName  = "LAPTOP-STOLEN","LAPTOP-MISSING"
        TenantId      = "12345678-1234-1234-1234-123456789012"
        ClientId      = "abcdef12-3456-7890-abcd-ef1234567890"
        ClientSecret  = "secret_value"
        EmailTo       = "security-team@contoso.com","manager@contoso.com"
        EmailFrom     = "security-alerts@contoso.com"
        PortsToScan   = @(22,80,443,3389,5985,5986)
    }
    .\Invoke-SystemOnlineMonitor.ps1 @params

    Monitor specific systems with custom port list using splatting.

.EXAMPLE
    # Create scheduled task to run every 15 minutes
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Invoke-SystemOnlineMonitor.ps1" -ComputerName "TARGET-PC" -TenantId "..." -ClientId "..." -ClientSecret "..." -EmailTo "alerts@company.com" -EmailFrom "monitor@company.com"'

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName "Monitor-StolenLaptop" -Action $action -Trigger $trigger -Principal $principal

    Schedule automated monitoring every 15 minutes.

.NOTES
    Author: Yeyland Wutani LLC
    Website: https://github.com/YeylandWutani
    Requires: PowerShell 5.1+, Network access to monitored systems

    GRAPH API SETUP:
    1. Register Azure App in Entra ID (Azure AD)
    2. Add API Permission: Microsoft Graph > Application > Mail.Send
    3. Grant admin consent for the permission
    4. Create client secret and note the value
    5. Note Application (client) ID and Directory (tenant) ID

    SECURITY CONSIDERATIONS:
    - Store credentials securely (Azure Key Vault, encrypted files, etc.)
    - Use least-privilege Graph API permissions
    - Restrict script access to authorized personnel only
    - Consider using Managed Identity for Azure-hosted automation
    - Audit email recipients regularly

    SCHEDULED TASK RECOMMENDATIONS:
    - Run as SYSTEM or dedicated service account with domain read access
    - Set execution policy appropriately
    - Log output to file for troubleshooting
    - Test email delivery before production deployment
    - Consider rate limiting for large system lists

    COMMON USE CASES:
    - Missing/stolen device detection
    - Unauthorized system monitoring
    - Asset inventory automation
    - Compliance reporting (online systems only)
    - Security incident response
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('CN', 'Hostname', 'Computer', 'System')]
    [string[]]$ComputerName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8,9}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8,9}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [string]$ClientSecret,

    [Parameter(Mandatory)]
    [ValidatePattern('^[\w\.-]+@[\w\.-]+\.\w+$')]
    [string[]]$EmailTo,

    [Parameter(Mandatory)]
    [ValidatePattern('^[\w\.-]+@[\w\.-]+\.\w+$')]
    [string]$EmailFrom,

    [int[]]$PortsToScan = @(
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        135,   # RPC
        139,   # NetBIOS
        443,   # HTTPS
        445,   # SMB
        1433,  # MSSQL
        3306,  # MySQL
        3389,  # RDP
        5985,  # WinRM HTTP
        5986,  # WinRM HTTPS
        8080   # HTTP Alt
    ),

    [ValidateRange(100, 5000)]
    [int]$ScanTimeout = 1000,

    [switch]$IncludeOfflineSystems,

    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Export directory does not exist: $parent"
        }
        $true
    })]
    [string]$ExportPath,

    [string]$AlertLogPath = "$env:ProgramData\SystemMonitor\AlertLog.json",

    [switch]$UseSecureString
)

begin {
    # Script metadata
    $ScriptVersion = "1.0"
    $ScriptName = "Invoke-SystemOnlineMonitor"

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
    Write-Host "  System Online Monitor with Graph API Reporting" -ForegroundColor Cyan
    Write-Host ""

    Write-Verbose "[$ScriptName v$ScriptVersion] - Starting system monitoring"
    Write-Verbose "Monitoring $($ComputerName.Count) system(s)"
    Write-Verbose "Port scan timeout: $ScanTimeout ms"

    # Initialize results collection
    $AllResults = @()
    $OnlineSystems = @()

    #region Functions

    # Function to load alert log
    function Get-AlertLog {
        param([string]$LogPath)

        try {
            if (Test-Path $LogPath) {
                $logContent = Get-Content $LogPath -Raw | ConvertFrom-Json
                Write-Verbose "Loaded alert log with $($logContent.Count) entries"
                return $logContent
            }
            else {
                Write-Verbose "No existing alert log found. Creating new log."
                return @()
            }
        }
        catch {
            Write-Warning "Failed to load alert log: $_"
            return @()
        }
    }

    # Function to save alert log
    function Save-AlertLog {
        param(
            [string]$LogPath,
            [array]$LogData
        )

        try {
            $logDir = Split-Path $LogPath -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                Write-Verbose "Created alert log directory: $logDir"
            }

            $LogData | ConvertTo-Json -Depth 5 | Out-File -FilePath $LogPath -Encoding UTF8
            Write-Verbose "Saved alert log with $($LogData.Count) entries"
        }
        catch {
            Write-Warning "Failed to save alert log: $_"
        }
    }

    # Function to check if alert should be sent
    function Test-ShouldSendAlert {
        param(
            [string]$ComputerName,
            [array]$AlertLog
        )

        $today = (Get-Date).Date
        $lastAlert = $AlertLog | Where-Object { $_.ComputerName -eq $ComputerName } | Select-Object -First 1

        if (-not $lastAlert) {
            Write-Verbose "No previous alert found for $ComputerName"
            return $true
        }

        $lastAlertDate = [DateTime]::Parse($lastAlert.LastAlertDate).Date

        if ($lastAlertDate -lt $today) {
            Write-Verbose "Last alert for $ComputerName was on $lastAlertDate (sending new alert)"
            return $true
        }
        else {
            Write-Verbose "Alert already sent for $ComputerName today ($lastAlertDate)"
            return $false
        }
    }

    # Function to update alert log
    function Update-AlertLog {
        param(
            [string]$ComputerName,
            [array]$AlertLog
        )

        $existingEntry = $AlertLog | Where-Object { $_.ComputerName -eq $ComputerName }

        if ($existingEntry) {
            # Update existing entry
            $existingEntry.LastAlertDate = Get-Date -Format "o"
            $existingEntry.AlertCount++
        }
        else {
            # Add new entry
            $AlertLog += [PSCustomObject]@{
                ComputerName  = $ComputerName
                LastAlertDate = Get-Date -Format "o"
                AlertCount    = 1
            }
        }

        return $AlertLog
    }

    # Function to get Graph API access token
    function Get-GraphAccessToken {
        param(
            [string]$TenantId,
            [string]$ClientId,
            [string]$ClientSecret
        )

        try {
            Write-Verbose "Acquiring Graph API access token..."

            $body = @{
                grant_type    = "client_credentials"
                scope         = "https://graph.microsoft.com/.default"
                client_id     = $ClientId
                client_secret = $ClientSecret
            }

            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

            $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded"

            Write-Verbose "Successfully acquired access token"
            return $response.access_token
        }
        catch {
            Write-Error "Failed to acquire Graph API access token: $_"
            throw
        }
    }

    # Function to send email via Graph API
    function Send-GraphEmail {
        param(
            [string]$AccessToken,
            [string]$From,
            [string[]]$To,
            [string]$Subject,
            [string]$Body,
            [switch]$IsHtml
        )

        try {
            Write-Verbose "Sending email via Graph API..."

            $recipients = @()
            foreach ($recipient in $To) {
                $recipients += @{
                    emailAddress = @{
                        address = $recipient
                    }
                }
            }

            $contentType = if ($IsHtml) { "HTML" } else { "Text" }

            $emailMessage = @{
                message = @{
                    subject      = $Subject
                    body         = @{
                        contentType = $contentType
                        content     = $Body
                    }
                    toRecipients = $recipients
                }
                saveToSentItems = $false
            }

            $jsonBody = $emailMessage | ConvertTo-Json -Depth 10

            $headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type"  = "application/json"
            }

            $sendMailEndpoint = "https://graph.microsoft.com/v1.0/users/$From/sendMail"

            Invoke-RestMethod -Method Post -Uri $sendMailEndpoint -Headers $headers -Body $jsonBody

            Write-Verbose "Email sent successfully to $($To -join ', ')"
            return $true
        }
        catch {
            Write-Error "Failed to send email via Graph API: $_"
            Write-Error "Error details: $($_.Exception.Message)"
            if ($_.ErrorDetails.Message) {
                Write-Error "API Error: $($_.ErrorDetails.Message)"
            }
            return $false
        }
    }

    # Function to test system online status
    function Test-SystemOnline {
        param([string]$ComputerName)

        try {
            $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue
            return $pingResult
        }
        catch {
            return $false
        }
    }

    # Function to scan TCP port
    function Test-TCPPort {
        param(
            [string]$ComputerName,
            [int]$Port,
            [int]$Timeout
        )

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

            if ($wait) {
                try {
                    $tcpClient.EndConnect($connect)
                    $result = $true
                }
                catch {
                    $result = $false
                }
            }
            else {
                $result = $false
            }

            $tcpClient.Close()
            return $result
        }
        catch {
            return $false
        }
    }

    # Function to get open ports
    function Get-OpenPorts {
        param(
            [string]$ComputerName,
            [int[]]$Ports,
            [int]$Timeout
        )

        $openPorts = @()

        foreach ($port in $Ports) {
            if (Test-TCPPort -ComputerName $ComputerName -Port $port -Timeout $Timeout) {
                $openPorts += $port
            }
        }

        return $openPorts
    }

    # Function to get system details
    function Get-SystemDetails {
        param([string]$ComputerName)

        $details = @{
            OSInfo           = $null
            ComputerSystem   = $null
            LastUser         = $null
            IPAddresses      = @()
            MACAddresses     = @()
            Domain           = $null
            Manufacturer     = $null
            Model            = $null
            SerialNumber     = $null
            BIOSVersion      = $null
            TotalMemoryGB    = $null
            ProcessorName    = $null
            LastBootTime     = $null
            UptimeDays       = $null
            ADInfo           = $null
            LastLogon        = $null
            ADDescription    = $null
            ADLocation       = $null
        }

        # Try Active Directory first (most reliable in domain environment)
        try {
            Write-Verbose "Attempting to retrieve AD info for $ComputerName..."

            # Check if AD module is available
            if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
                $adComputer = Get-ADComputer -Identity $ComputerName -Properties * -ErrorAction Stop

                if ($adComputer) {
                    Write-Verbose "Successfully retrieved AD information"

                    # Operating System from AD
                    $details.OSInfo = $adComputer.OperatingSystem
                    if ($adComputer.OperatingSystemVersion) {
                        $details.OSInfo += " ($($adComputer.OperatingSystemVersion))"
                    }

                    # Last logon
                    if ($adComputer.LastLogonDate) {
                        $details.LastLogon = $adComputer.LastLogonDate
                        $daysSinceLogon = ((Get-Date) - $adComputer.LastLogonDate).Days
                        $details.ADInfo = "Last seen: $($adComputer.LastLogonDate) ($daysSinceLogon days ago)"
                    }

                    # Domain
                    $details.Domain = $adComputer.DNSHostName

                    # Description and Location from AD
                    $details.ADDescription = $adComputer.Description
                    $details.ADLocation = $adComputer.Location

                    # Try to get last logged on user from AD (if available)
                    if ($adComputer.ManagedBy) {
                        $details.LastUser = $adComputer.ManagedBy
                    }

                    # Get IP from DNS if available
                    if ($adComputer.IPv4Address) {
                        $details.IPAddresses += $adComputer.IPv4Address
                    }
                }
            }
            else {
                Write-Warning "Active Directory module not available. Install RSAT tools for better results."
            }
        }
        catch {
            Write-Warning "Could not retrieve AD info for $ComputerName : $($_.Exception.Message)"
        }

        try {
            # Operating System info
            try {
                Write-Verbose "Attempting to retrieve OS info from $ComputerName via CIM..."
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
                if ($os) {
                    $details.OSInfo = "$($os.Caption) $($os.Version)"
                    $details.LastBootTime = $os.LastBootUpTime
                    $uptime = (Get-Date) - $os.LastBootUpTime
                    $details.UptimeDays = [math]::Round($uptime.TotalDays, 2)
                    $details.TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                    Write-Verbose "Successfully retrieved OS info via CIM"
                }
            }
            catch {
                Write-Warning "CIM query failed for OS info on $ComputerName : $($_.Exception.Message)"
                # Try WMI as fallback
                try {
                    Write-Verbose "Attempting fallback to WMI..."
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
                    if ($os) {
                        $details.OSInfo = "$($os.Caption) $($os.Version)"
                        $details.LastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
                        $uptime = (Get-Date) - $details.LastBootTime
                        $details.UptimeDays = [math]::Round($uptime.TotalDays, 2)
                        $details.TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                        Write-Verbose "Successfully retrieved OS info via WMI"
                    }
                }
                catch {
                    Write-Warning "WMI fallback also failed for OS info: $($_.Exception.Message)"
                }
            }

            # Computer System info
            try {
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($cs) {
                    $details.ComputerSystem = $cs.Model
                    $details.Domain = $cs.Domain
                    $details.Manufacturer = $cs.Manufacturer
                    $details.Model = $cs.Model

                    # Get last logged on user
                    if ($cs.UserName) {
                        $details.LastUser = $cs.UserName
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve Computer System info for $ComputerName"
            }

            # BIOS info
            try {
                $bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($bios) {
                    $details.SerialNumber = $bios.SerialNumber
                    $details.BIOSVersion = $bios.SMBIOSBIOSVersion
                }
            }
            catch {
                Write-Verbose "Could not retrieve BIOS info for $ComputerName"
            }

            # Processor info
            try {
                $cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerName -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($cpu) {
                    $details.ProcessorName = $cpu.Name
                }
            }
            catch {
                Write-Verbose "Could not retrieve Processor info for $ComputerName"
            }

            # Network adapters
            try {
                $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction SilentlyContinue |
                           Where-Object { $_.IPEnabled -eq $true }

                foreach ($adapter in $adapters) {
                    if ($adapter.IPAddress) {
                        $details.IPAddresses += $adapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
                    }
                    if ($adapter.MACAddress) {
                        $details.MACAddresses += $adapter.MACAddress
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve Network info for $ComputerName"
            }
        }
        catch {
            Write-Warning "Error retrieving system details for $ComputerName : $_"
        }

        return $details
    }

    # Function to get port service name
    function Get-PortServiceName {
        param([int]$Port)

        $portMap = @{
            21   = "FTP"
            22   = "SSH"
            23   = "Telnet"
            25   = "SMTP"
            53   = "DNS"
            80   = "HTTP"
            135  = "RPC"
            139  = "NetBIOS"
            443  = "HTTPS"
            445  = "SMB"
            1433 = "MSSQL"
            3306 = "MySQL"
            3389 = "RDP"
            5985 = "WinRM-HTTP"
            5986 = "WinRM-HTTPS"
            8080 = "HTTP-Alt"
        }

        if ($portMap.ContainsKey($Port)) {
            return "$($portMap[$Port]) ($Port)"
        }
        else {
            return "Port $Port"
        }
    }

    #endregion Functions
}

process {
    foreach ($Computer in $ComputerName) {
        Write-Progress -Activity "System Online Monitor" -Status "Checking $Computer" -PercentComplete 0

        Write-Verbose "Testing connectivity to $Computer..."
        $isOnline = Test-SystemOnline -ComputerName $Computer

        if ($isOnline) {
            Write-Host "[ONLINE] $Computer" -ForegroundColor Green

            Write-Progress -Activity "System Online Monitor" -Status "Scanning ports - $Computer" -PercentComplete 30
            Write-Verbose "System is ONLINE. Scanning ports..."

            $openPorts = Get-OpenPorts -ComputerName $Computer -Ports $PortsToScan -Timeout $ScanTimeout

            Write-Progress -Activity "System Online Monitor" -Status "Gathering details - $Computer" -PercentComplete 60
            Write-Verbose "Gathering system details..."

            $systemDetails = Get-SystemDetails -ComputerName $Computer

            $result = [PSCustomObject]@{
                ComputerName   = $Computer
                Status         = "Online"
                Timestamp      = Get-Date
                OpenPorts      = $openPorts
                OpenPortCount  = $openPorts.Count
                OSInfo         = $systemDetails.OSInfo
                Manufacturer   = $systemDetails.Manufacturer
                Model          = $systemDetails.Model
                SerialNumber   = $systemDetails.SerialNumber
                BIOSVersion    = $systemDetails.BIOSVersion
                ProcessorName  = $systemDetails.ProcessorName
                TotalMemoryGB  = $systemDetails.TotalMemoryGB
                LastUser       = $systemDetails.LastUser
                IPAddresses    = $systemDetails.IPAddresses -join ', '
                MACAddresses   = $systemDetails.MACAddresses -join ', '
                Domain         = $systemDetails.Domain
                LastBootTime   = $systemDetails.LastBootTime
                UptimeDays     = $systemDetails.UptimeDays
                ADInfo         = $systemDetails.ADInfo
                LastLogon      = $systemDetails.LastLogon
                ADDescription  = $systemDetails.ADDescription
                ADLocation     = $systemDetails.ADLocation
            }

            $OnlineSystems += $result
            $AllResults += $result

            # Display summary
            Write-Host "  OS: $($systemDetails.OSInfo)" -ForegroundColor Gray
            if ($systemDetails.ADInfo) {
                Write-Host "  AD Info: $($systemDetails.ADInfo)" -ForegroundColor Gray
            }
            if ($systemDetails.ADDescription) {
                Write-Host "  Description: $($systemDetails.ADDescription)" -ForegroundColor Gray
            }
            if ($systemDetails.ADLocation) {
                Write-Host "  Location: $($systemDetails.ADLocation)" -ForegroundColor Gray
            }
            Write-Host "  Model: $($systemDetails.Manufacturer) $($systemDetails.Model)" -ForegroundColor Gray
            Write-Host "  Serial: $($systemDetails.SerialNumber)" -ForegroundColor Gray
            Write-Host "  Last User: $($systemDetails.LastUser)" -ForegroundColor Gray
            Write-Host "  IP Addresses: $($systemDetails.IPAddresses -join ', ')" -ForegroundColor Gray
            Write-Host "  Open Ports: $($openPorts.Count)" -ForegroundColor Yellow

            if ($openPorts.Count -gt 0) {
                foreach ($port in $openPorts) {
                    $serviceName = Get-PortServiceName -Port $port
                    Write-Host "    - $serviceName" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "[OFFLINE] $Computer" -ForegroundColor Red

            if ($IncludeOfflineSystems) {
                $result = [PSCustomObject]@{
                    ComputerName   = $Computer
                    Status         = "Offline"
                    Timestamp      = Get-Date
                    OpenPorts      = @()
                    OpenPortCount  = 0
                    OSInfo         = $null
                    Manufacturer   = $null
                    Model          = $null
                    SerialNumber   = $null
                    BIOSVersion    = $null
                    ProcessorName  = $null
                    TotalMemoryGB  = $null
                    LastUser       = $null
                    IPAddresses    = $null
                    MACAddresses   = $null
                    Domain         = $null
                    LastBootTime   = $null
                    UptimeDays     = $null
                }

                $AllResults += $result
            }
        }

        Write-Progress -Activity "System Online Monitor" -Completed
    }
}

end {
    Write-Host "`n===============================================================" -ForegroundColor Cyan
    Write-Host " Monitoring Summary" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "Total Systems Monitored: $($ComputerName.Count)"
    Write-Host "Online Systems: " -NoNewline
    Write-Host "$($OnlineSystems.Count)" -ForegroundColor Green
    Write-Host "Offline Systems: " -NoNewline
    Write-Host "$($ComputerName.Count - $OnlineSystems.Count)" -ForegroundColor Red
    Write-Host "===============================================================`n" -ForegroundColor Cyan

    # Export results if requested
    if ($ExportPath -and $AllResults.Count -gt 0) {
        $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()

        try {
            switch ($extension) {
                '.json' {
                    $AllResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Encoding UTF8
                    Write-Host "Results exported to JSON: $ExportPath" -ForegroundColor Green
                }

                '.csv' {
                    $AllResults | Export-Csv -Path $ExportPath -NoTypeInformation
                    Write-Host "Results exported to CSV: $ExportPath" -ForegroundColor Green
                }

                default {
                    Write-Warning "Unsupported export format: $extension (use .json or .csv)"
                }
            }
        }
        catch {
            Write-Error "Failed to export results: $_"
        }
    }

    # Send email if online systems detected
    if ($OnlineSystems.Count -gt 0) {
        # Load alert log
        Write-Verbose "Loading alert log from: $AlertLogPath"
        $alertLog = Get-AlertLog -LogPath $AlertLogPath

        # Filter systems that need alerts (haven't been alerted today)
        $systemsToAlert = @()
        $systemsAlreadyAlerted = @()

        foreach ($system in $OnlineSystems) {
            if (Test-ShouldSendAlert -ComputerName $system.ComputerName -AlertLog $alertLog) {
                $systemsToAlert += $system
                Write-Host "  Will send alert for: $($system.ComputerName)" -ForegroundColor Green
            }
            else {
                $systemsAlreadyAlerted += $system
                Write-Host "  Skipping alert for: $($system.ComputerName) (already alerted today)" -ForegroundColor Yellow
            }
        }

        if ($systemsToAlert.Count -eq 0) {
            Write-Host "`nAll online systems were already alerted today. No email will be sent." -ForegroundColor Yellow
        }
        else {
            Write-Host "`nSending alert for $($systemsToAlert.Count) system(s)..." -ForegroundColor Yellow

            try {
                # Acquire access token
            $accessToken = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

                # Build HTML email body
                $emailSubject = "System Online Alert - $($systemsToAlert.Count) System(s) Detected Online"

            $htmlBody = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #FF6600; border-bottom: 3px solid #6B7280; padding-bottom: 10px; }
        h2 { color: #6B7280; margin-top: 25px; }
        .summary { background-color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .system-card { background-color: white; padding: 20px; border-radius: 5px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #28a745; }
        .info-grid { display: grid; grid-template-columns: 200px 1fr; gap: 10px; margin: 10px 0; }
        .info-label { font-weight: bold; color: #6B7280; }
        .info-value { color: #333; }
        .ports-section { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .port-item { background-color: white; padding: 8px 12px; border-radius: 3px; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #ddd; }
        .alert-box { background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #6B7280; font-size: 12px; }
        .timestamp { color: #6B7280; font-size: 14px; }
    </style>
</head>
<body>
    <h1>System Online Detection Report</h1>

    <div class="summary">
        <strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Systems Monitored:</strong> $($ComputerName.Count)<br>
        <strong>Systems Online:</strong> <span style="color: #28a745; font-weight: bold;">$($OnlineSystems.Count)</span><br>
        <strong>Systems Offline:</strong> <span style="color: #dc3545; font-weight: bold;">$($ComputerName.Count - $OnlineSystems.Count)</span><br>
        <strong>New Alerts:</strong> <span style="color: #ffc107; font-weight: bold;">$($systemsToAlert.Count)</span>
    </div>

    <div class="alert-box">
        <strong>⚠ Alert:</strong> The following system(s) have been detected online for the first time today.
    </div>
"@

            foreach ($system in $systemsToAlert) {
                $portsList = ""
                if ($system.OpenPorts.Count -gt 0) {
                    foreach ($port in $system.OpenPorts) {
                        $serviceName = Get-PortServiceName -Port $port
                        $portsList += "<span class='port-item'>$serviceName</span>"
                    }
                }
                else {
                    $portsList = "<em>No open ports detected from scan list</em>"
                }

                $htmlBody += @"
    <div class="system-card">
        <h2>$($system.ComputerName)</h2>
        <div class="timestamp">Detected: $($system.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</div>

        <div class="info-grid">
            <div class="info-label">Operating System:</div>
            <div class="info-value">$($system.OSInfo)</div>

            <div class="info-label">Manufacturer:</div>
            <div class="info-value">$($system.Manufacturer)</div>

            <div class="info-label">Model:</div>
            <div class="info-value">$($system.Model)</div>

            <div class="info-label">Serial Number:</div>
            <div class="info-value">$($system.SerialNumber)</div>

            <div class="info-label">BIOS Version:</div>
            <div class="info-value">$($system.BIOSVersion)</div>

            <div class="info-label">Processor:</div>
            <div class="info-value">$($system.ProcessorName)</div>

            <div class="info-label">Total Memory:</div>
            <div class="info-value">$($system.TotalMemoryGB) GB</div>

            <div class="info-label">Last Logged User:</div>
            <div class="info-value">$($system.LastUser)</div>

            <div class="info-label">IP Address(es):</div>
            <div class="info-value">$($system.IPAddresses)</div>

            <div class="info-label">MAC Address(es):</div>
            <div class="info-value">$($system.MACAddresses)</div>

            <div class="info-label">Domain:</div>
            <div class="info-value">$($system.Domain)</div>

            <div class="info-label">Last AD Logon:</div>
            <div class="info-value">$($system.LastLogon)</div>

            <div class="info-label">AD Description:</div>
            <div class="info-value">$($system.ADDescription)</div>

            <div class="info-label">AD Location:</div>
            <div class="info-value">$($system.ADLocation)</div>

            <div class="info-label">Last Boot Time:</div>
            <div class="info-value">$($system.LastBootTime)</div>

            <div class="info-label">Uptime:</div>
            <div class="info-value">$($system.UptimeDays) days</div>
        </div>

        <div class="ports-section">
            <strong>Open Ports Detected ($($system.OpenPortCount)):</strong><br><br>
            $portsList
        </div>
    </div>
"@
            }

            $htmlBody += @"
    <div class="footer">
        <strong>Yeyland Wutani LLC</strong><br>
        Building Better Systems<br>
        System Online Monitoring Report<br>
        <em>This is an automated report generated by Invoke-SystemOnlineMonitor.ps1</em>
    </div>
</body>
</html>
"@

                # Send email via Graph API
                $emailSent = Send-GraphEmail -AccessToken $accessToken -From $EmailFrom -To $EmailTo -Subject $emailSubject -Body $htmlBody -IsHtml

                if ($emailSent) {
                    Write-Host "Email report sent successfully to: $($EmailTo -join ', ')" -ForegroundColor Green

                    # Update alert log for all systems that were alerted
                    Write-Verbose "Updating alert log..."
                    foreach ($system in $systemsToAlert) {
                        $alertLog = Update-AlertLog -ComputerName $system.ComputerName -AlertLog $alertLog
                    }

                    # Save updated alert log
                    Save-AlertLog -LogPath $AlertLogPath -LogData $alertLog
                    Write-Host "Alert log updated. $($systemsToAlert.Count) system(s) marked as alerted." -ForegroundColor Green
                }
                else {
                    Write-Error "Failed to send email report"
                }
            }
            catch {
                Write-Error "Error sending Graph API email: $_"
            }
        }
    }
    else {
        Write-Host "`nNo online systems detected. No email will be sent." -ForegroundColor Yellow
    }

    Write-Verbose "System monitoring completed. Processed $($ComputerName.Count) system(s)."
}
