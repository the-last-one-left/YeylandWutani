#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Automated Let's Encrypt Certificate Renewal v1.4.0

.DESCRIPTION
    Automates the full Let's Encrypt certificate lifecycle using the ACME protocol
    via the Posh-ACME module. Designed for MSP environments where customers are
    transitioning to 90-day (and soon 47-day) certificate renewals.

    When run interactively, presents a guided menu for first-time setup. Subsequent
    renewals run fully unattended as SYSTEM via a Windows Scheduled Task.

    Capabilities:
    - Interactive guided menu: one-time, scheduled task, remove task, update task
    - New certificate issuance via HTTP-01 or DNS-01 challenge validation
    - Automatic IIS challenge response configuration (HTTP-01)
    - DNS-01 validation via 30+ providers (Azure, Cloudflare, GoDaddy, Route53, etc.)
    - Manual DNS mode for providers without API integration
    - Wildcard certificate support (requires DNS-01)
    - Multi-domain (SAN) certificate support
    - Deployment targets: IIS, RD Gateway (TSGateway), PFX export, WatchGuard Firebox
    - WatchGuard Firebox web-server-cert deployment via SSH + ephemeral FTP pipeline
    - RD Gateway certificate binding via RDS PowerShell drive or WMI fallback
    - PFX export mode for non-IIS servers (Apache, nginx, load balancers)
    - Certificate renewal when approaching expiry threshold (default: 30 days)
    - Automatic IIS binding updates (when IIS output mode is selected)
    - Scheduled task installation for fully unattended operation (runs as SYSTEM)
    - Shared Posh-ACME data directory (ProgramData) so SYSTEM and user share cert cache
    - DPAPI/LocalMachine credential encryption for DNS plugin, Firebox SSH, and email
    - Optional email reporting via Microsoft 365 Graph API or SMTP (success/failure/update)
    - Automatic cleanup of expired Let's Encrypt certificates from the Windows cert store
    - Let's Encrypt staging environment support for testing
    - Contact email registration for expiry notifications from Let's Encrypt

    Challenge Types:
      HTTP-01 (default): Proves domain control by serving a token file over HTTP.
        Requires port 80 open to the internet. Cannot issue wildcard certificates.

      DNS-01: Proves domain control by creating a TXT record in DNS.
        Supports wildcard certificates (*.contoso.com). Does not require port 80.
        Can be fully automated with a DNS provider plugin, or done manually.

    Workflow:
      1. Shows interactive menu (one-shot, install task, or remove task)
      2. Asks where to deploy the certificate (IIS or PFX export)
      3. Ensures Posh-ACME module is available (installs if needed)
      4. Configures the ACME server (staging or production)
      5. Sets up challenge infrastructure (IIS vdir for HTTP-01, or DNS plugin for DNS-01)
      6. Requests or renews the certificate via ACME protocol
      7. Imports to IIS cert store and updates bindings, OR exports as PFX
      8. Cleans up challenge infrastructure

.PARAMETER DomainName
    Primary domain name for the certificate. This becomes the certificate's
    Common Name (CN). Example: "www.contoso.com"

.PARAMETER AdditionalDomains
    Additional Subject Alternative Names (SANs) to include on the certificate.
    Example: @("mail.contoso.com", "portal.contoso.com")

.PARAMETER ContactEmail
    Email address registered with Let's Encrypt for expiry notifications and
    account recovery. Required for first-time registration.

.PARAMETER ChallengeType
    ACME challenge type to use for domain validation. Default: "Http".
    - Http:      HTTP-01 challenge. Serves a token file via IIS on port 80.
                 Simple and works for most setups. Cannot issue wildcard certs.
    - Dns:       DNS-01 challenge using a Posh-ACME DNS plugin for automatic
                 TXT record management. Required for wildcard certificates.
                 Specify the plugin with -DnsPlugin and credentials with -DnsPluginArgs.
    - DnsManual: DNS-01 challenge with manual TXT record creation. The script
                 will pause and display the TXT record value for you to create.
                 Not suitable for automated/scheduled renewals.

.PARAMETER DnsPlugin
    The Posh-ACME DNS plugin name for automated DNS-01 challenges.
    Common plugins: Azure, AzureDns, Cloudflare, GoDaddy, Route53, Namecheap,
    DOcean (DigitalOcean), Hetzner, OVH, Porkbun, DuckDNS, Dynu, Linode, Gandi.
    Run 'Get-PAPlugin' after installing Posh-ACME to see all available plugins.
    Run 'Get-PAPlugin <PluginName> -Params' to see required parameters for a plugin.

.PARAMETER DnsPluginArgs
    Hashtable of arguments for the DNS plugin. Each plugin requires different
    credentials/parameters. See examples below and Posh-ACME documentation.

    Common examples:
    - Cloudflare: @{ CFToken = (Read-Host -AsSecureString) }
    - Azure DNS:  @{ AZSubscriptionId = 'xxx'; AZAccessToken = 'xxx' }
    - Route53:    @{ R53AccessKey = 'xxx'; R53SecretKey = (Read-Host -AsSecureString) }
    - GoDaddy:    @{ GDKey = 'xxx'; GDSecret = (Read-Host -AsSecureString) }

.PARAMETER DnsSleep
    Seconds to wait for DNS propagation after creating TXT records. Default: 120.
    Increase this if validation fails due to slow DNS propagation.

.PARAMETER RenewalDays
    Number of days before certificate expiry to trigger renewal. Default: 30.
    With 90-day certificates, 30 days gives you a 60-day window where the cert
    is valid and a 30-day renewal window.

.PARAMETER Staging
    Use the Let's Encrypt staging environment. Certificates issued will NOT be
    trusted by browsers but this avoids rate limits during testing.

.PARAMETER ForceRenewal
    Force certificate renewal regardless of the current certificate's expiry date.
    Useful after revocation or when changing domain names.

.PARAMETER InstallScheduledTask
    Creates a Windows Scheduled Task that runs this script daily to check for
    and perform certificate renewals automatically.

.PARAMETER TaskTime
    Time of day to run the scheduled task. Default: "03:00" (3:00 AM).
    Choose a time with low traffic to minimize any brief disruption.

.PARAMETER PfxOutputPath
    Directory to export the PFX certificate file to. When specified on a non-IIS
    server, the certificate is exported as a PFX file instead of being imported
    to the Windows certificate store. When IIS is not detected, the script will
    automatically prompt to export to a folder if this parameter is not set.
    The PFX file and its password are saved to the specified directory.

.PARAMETER CertStorePath
    Certificate store location. Default: "Cert:\LocalMachine\WebHosting"
    Falls back to "Cert:\LocalMachine\My" if WebHosting store is unavailable.

.PARAMETER RemoveScheduledTask
    Removes the previously installed scheduled task.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" -Staging
    Issues a staging certificate for testing. Validate everything works before going live.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com"
    Issues a production Let's Encrypt certificate and binds it to matching IIS sites.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "contoso.com" -AdditionalDomains @("www.contoso.com","mail.contoso.com") -ContactEmail "admin@contoso.com"
    Issues a multi-domain (SAN) certificate.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" -InstallScheduledTask
    Issues a certificate and installs a daily scheduled task for automatic renewal.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "www.contoso.com" -ContactEmail "admin@contoso.com" -ForceRenewal
    Forces renewal even if the current certificate has not reached the renewal threshold.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "*.contoso.com" -ContactEmail "admin@contoso.com" -ChallengeType Dns -DnsPlugin Cloudflare -DnsPluginArgs @{ CFToken = (Read-Host 'Cloudflare API Token' -AsSecureString) }
    Issues a wildcard certificate using Cloudflare DNS for automated DNS-01 validation.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "*.contoso.com" -AdditionalDomains @("contoso.com") -ContactEmail "admin@contoso.com" -ChallengeType Dns -DnsPlugin AzureDns -DnsPluginArgs @{ AZSubscriptionId = 'your-sub-id'; AZAccessToken = 'your-token' }
    Issues a wildcard + apex domain certificate using Azure DNS.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "*.contoso.com" -ContactEmail "admin@contoso.com" -ChallengeType DnsManual
    Issues a wildcard certificate with manual DNS TXT record creation. The script will
    pause and tell you what TXT record to create, then wait for you to confirm.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "*.contoso.com" -ContactEmail "admin@contoso.com" -ChallengeType Dns -DnsPlugin Route53 -DnsPluginArgs @{ R53AccessKey = 'AKIA...'; R53SecretKey = (Read-Host 'AWS Secret' -AsSecureString) } -InstallScheduledTask
    Issues a wildcard cert via Route53 and installs a scheduled task for auto-renewal.

.EXAMPLE
    .\Invoke-LetsEncryptRenewal.ps1 -DomainName "app.contoso.com" -ContactEmail "admin@contoso.com" -ChallengeType Dns -DnsPlugin Cloudflare -DnsPluginArgs @{ CFToken = (Read-Host -AsSecureString) } -PfxOutputPath "C:\Certs"
    Issues a certificate on a non-IIS server and exports the PFX file to C:\Certs.
    Useful for servers running Apache, nginx, or other non-IIS web servers.

.NOTES
    Yeyland Wutani LLC - Building Better Systems
    Version: 1.4.0

    Prerequisites:
    - Windows Server 2016+ (IIS required for HTTP-01 and auto-binding; optional for DNS-01 with PFX export)
    - For HTTP-01: IIS installed and port 80 reachable from the internet
    - For DNS-01: DNS provider API credentials (or ability to create TXT records manually)
    - PowerShell 5.1+ (PowerShell 7+ recommended)
    - Administrative privileges
    - Internet connectivity to Let's Encrypt ACME endpoints

    The script uses Posh-ACME (https://github.com/rmbolger/Posh-ACME) which is
    installed automatically from the PowerShell Gallery if not present.

    Rate Limits (production):
    - 50 certificates per registered domain per week
    - 5 duplicate certificates per week
    - 300 new orders per account per 3 hours
    Use -Staging to avoid hitting these during testing.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Renew')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter()]
    [string[]]$AdditionalDomains,

    [Parameter(Mandatory)]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$ContactEmail,

    [Parameter()]
    [ValidateSet('Http', 'Dns', 'DnsManual')]
    [string]$ChallengeType = 'Http',

    [Parameter()]
    [string]$DnsPlugin,

    [Parameter()]
    [hashtable]$DnsPluginArgs,

    [Parameter()]
    [ValidateRange(30, 600)]
    [int]$DnsSleep = 120,

    [Parameter()]
    [ValidateRange(7, 60)]
    [int]$RenewalDays = 30,

    [Parameter()]
    [switch]$Staging,

    [Parameter()]
    [switch]$ForceRenewal,

    [Parameter(ParameterSetName = 'InstallTask')]
    [switch]$InstallScheduledTask,

    [Parameter(ParameterSetName = 'InstallTask')]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$TaskTime = "03:00",

    [Parameter()]
    [string]$PfxOutputPath,

    [Parameter()]
    [ValidateSet('IIS', 'RDGateway', 'PFX', 'WatchGuard')]
    [string]$DeployMode,

    # ---- WatchGuard Firebox deployment parameters ----

    [Parameter()]
    [string]$FireboxHost,

    [Parameter()]
    [int]$FireboxSshPort = 4118,

    [Parameter()]
    [string]$FireboxLocalIP,   # IP the Firebox can reach this machine on (for FTP callback)

    [Parameter()]
    [int]$FireboxFtpPort = 2121,   # Non-privileged port; no admin required

    # ---- Email reporting parameters ----

    [Parameter()]
    [switch]$SendReport,   # Enable email status reports (settings loaded from email_config.json)

    [Parameter()]
    [string]$EmailBodyNote,   # Custom text appended to report email body (supports !!contact@co.com!! ConnectWise routing tags)

    [Parameter()]
    [string]$EmailSubjectNote,   # Text appended to the report email subject line

    [Parameter()]
    [string]$CertStorePath = "Cert:\LocalMachine\WebHosting",

    [Parameter(ParameterSetName = 'RemoveTask')]
    [switch]$RemoveScheduledTask
)

$ErrorActionPreference = "Stop"
$script:OutputMode     = if ($DeployMode) { $DeployMode } elseif ($PfxOutputPath) { 'PFX' } else { 'IIS' }
$script:RDGAvailable   = $false
$script:FireboxHost    = $FireboxHost
$script:FireboxSshPort = $FireboxSshPort
$script:FireboxLocalIP = $FireboxLocalIP
$script:FireboxFtpPort = $FireboxFtpPort
$script:SkipCertOrder  = $false
$script:WgCredential   = $null
$script:SendReport       = $SendReport.IsPresent
$script:EmailBodyNote    = $EmailBodyNote
$script:EmailSubjectNote = $EmailSubjectNote
$script:ReportSent       = $false
$script:ChallengeType  = $ChallengeType
$script:DnsPlugin      = $DnsPlugin
$script:DnsPluginArgs  = $DnsPluginArgs
$script:PfxOutputPath  = $PfxOutputPath
$script:CertStorePath  = $CertStorePath
$script:ReportData     = @{
    Status        = 'None'    # 'Success' | 'Failed' | 'Skipped' | 'Updated' | 'None'
    Domain        = $DomainName
    Mode          = ''
    NewExpiry     = ''
    CurrentExpiry = ''
    Thumbprint    = ''
    Message       = ''
    StartTime     = Get-Date
}
$ScriptVersion = "1.4.0"
$TaskName = "LetsEncrypt Certificate Renewal - $DomainName"
$LogDir = Join-Path $env:ProgramData "YeylandWutani\LetsEncrypt"
$LogFile = Join-Path $LogDir "renewal_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$lockFile = Join-Path $LogDir ".renewal.lock"
$ChallengeSiteName = "LetsEncrypt-Challenge-$($DomainName -replace '\.', '-')"

# ============================================================================
# LOGGING
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $logEntry

    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Host "  [ERROR] $Message" -ForegroundColor Red }
        'Success' { Write-Host "  [OK] $Message" -ForegroundColor Green }
        default   { Write-Host "  [INFO] $Message" -ForegroundColor Cyan }
    }
}

function Write-Banner {
    $border = "=" * 81
    Write-Host ""
    Write-Host $border -ForegroundColor Gray
    Write-Host '  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ ' -ForegroundColor DarkYellow
    Write-Host '  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|' -ForegroundColor DarkYellow
    Write-Host '   \ V /| _| \ V /| |__ / _ \ | .` | |) |  \ \/\/ /| |_| | | |/ _ \| .` || | ' -ForegroundColor DarkYellow
    Write-Host '    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|' -ForegroundColor DarkYellow
    Write-Host '' -ForegroundColor Green
    Write-Host '                      B U I L D I N G   B E T T E R   S Y S T E M S' -ForegroundColor Green
    Write-Host $border -ForegroundColor Gray
    Write-Host "  Let's Encrypt Certificate Manager v$ScriptVersion" -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

function Test-IISAvailable {
    # Check W3SVC service first - works on both Server and Workstation editions
    $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($w3svc) { return $true }

    # Check IIS via Windows Feature (Server editions only - requires ServerManager module)
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo -and $osInfo.Caption -match 'Server') {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        if ($iisFeature -and $iisFeature.InstallState -eq 'Installed') { return $true }
    }

    return $false
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

function Show-InteractiveMenu {
    Write-Host "  What would you like to do?" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Request/renew a certificate (one-time)" -ForegroundColor Cyan
    Write-Host "  [2] Request/renew and install scheduled task for auto-renewal" -ForegroundColor Cyan
    Write-Host "  [3] Remove existing scheduled task" -ForegroundColor Cyan
    Write-Host "  [4] Update existing scheduled task (refresh credentials / reconfigure)" -ForegroundColor Cyan
    Write-Host "  [5] Exit" -ForegroundColor Cyan
    Write-Host ""

    do {
        $choice = Read-Host "  Select option [1-5]"
    } while ($choice -notin @('1', '2', '3', '4', '5'))

    return $choice
}

function Test-RDGatewayAvailable {
    # Check for the TSGateway service
    if (-not (Get-Service -Name TSGateway -ErrorAction SilentlyContinue)) { return $false }

    # Verify the WMI class is accessible (not present on non-RDG servers even if service exists)
    $gwSettings = Get-CimInstance -Namespace root/CIMV2/TerminalServices `
        -ClassName Win32_TSGatewayServerSettings -ErrorAction SilentlyContinue
    return ($null -ne $gwSettings)
}

function Get-RDGatewayCurrentCert {
    # Returns the X509Certificate2 currently bound to RD Gateway, or $null
    try {
        $gwSettings = Get-CimInstance -Namespace root/CIMV2/TerminalServices `
            -ClassName Win32_TSGatewayServerSettings -ErrorAction Stop
        if (-not $gwSettings.CertHash -or $gwSettings.CertHash.Count -eq 0) { return $null }

        $thumbprint = [System.BitConverter]::ToString($gwSettings.CertHash).Replace('-', '')
        return (Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue)
    }
    catch {
        Write-Log "Could not retrieve current RD Gateway certificate: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Install-RDGatewayCertificate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    # Validate TSGateway is present on this machine at deploy time.
    # The menu always shows RDGateway as an option, so catch misconfigured runs here.
    if (-not (Get-Service -Name TSGateway -ErrorAction SilentlyContinue)) {
        throw "RD Gateway deployment selected but the TSGateway service was not found on this machine. This script must run on the RD Gateway server itself. Ensure the Remote Desktop Gateway role service is installed before running."
    }

    $thumbprint = $Certificate.Thumbprint
    Write-Log "Binding certificate to RD Gateway (thumbprint: $thumbprint)"

    $bound = $false

    # Method 1: RDS PowerShell drive (Windows Server 2016+)
    try {
        if (-not (Get-PSDrive -Name RDS -ErrorAction SilentlyContinue)) {
            Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue
        }
        $rdsPath = 'RDS:\GatewayServer\SSLCertificate\Thumbprint'
        if (Test-Path $rdsPath -ErrorAction SilentlyContinue) {
            Set-Item -Path $rdsPath -Value $thumbprint -ErrorAction Stop
            $bound = $true
            Write-Log "RD Gateway certificate set via RDS PowerShell drive" -Level Success
        }
    }
    catch {
        Write-Log "RDS drive method failed ($($_.Exception.Message)) - falling back to WMI" -Level Warning
    }

    # Method 2: WMI/CIM (works on 2012 R2+ and as a fallback on newer)
    if (-not $bound) {
        $certObj     = Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop
        $certHash    = $certObj.GetCertHash()
        $gwSettings  = Get-CimInstance -Namespace root/CIMV2/TerminalServices `
            -ClassName Win32_TSGatewayServerSettings -ErrorAction Stop
        $result = Invoke-CimMethod -InputObject $gwSettings -MethodName SetCertificate `
            -Arguments @{ CertHash = $certHash }

        if ($result.ReturnValue -ne 0) {
            throw "Win32_TSGatewayServerSettings.SetCertificate returned error code $($result.ReturnValue)"
        }
        $bound = $true
        Write-Log "RD Gateway certificate set via WMI" -Level Success
    }

    # Restart TSGateway to apply - this drops active RD Gateway sessions
    Write-Log "Restarting TSGateway service to apply certificate (active gateway sessions will be dropped)..." -Level Warning
    Restart-Service -Name TSGateway -Force -ErrorAction Stop
    Write-Log "TSGateway service restarted" -Level Success
}

function Show-CertificateOutputMenu {
    # Detect available local services
    $script:IISAvailable = Test-IISAvailable
    $script:RDGAvailable = Test-RDGatewayAvailable

    if ($script:IISAvailable) {
        if (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
        }
        else {
            Write-Log "WebAdministration module not found. IIS binding management will be unavailable." -Level Warning
            $script:IISAvailable = $false
        }
    }

    # If DeployMode or PfxOutputPath were provided on the command line, skip the menu
    if ($DeployMode -or $PfxOutputPath) {
        if ($PfxOutputPath) { $script:OutputMode = 'PFX' }
        # $script:OutputMode already set from $DeployMode at script start

        if ($script:OutputMode -eq 'RDGateway') {
            $script:CertStorePath = 'Cert:\LocalMachine\My'
        }
        Write-Log "Certificate output: $script:OutputMode$(if ($PfxOutputPath) { " -> $PfxOutputPath" })" -Level Info
        return
    }

    # Build menu options dynamically.
    # IIS is only shown when detected (requires WebAdministration module).
    # RD Gateway, PFX, and WatchGuard are always available — they are shown
    # unconditionally, with a note when TSGateway is not detected locally.
    $menuOptions = [System.Collections.Generic.List[hashtable]]::new()
    if ($script:IISAvailable) {
        $menuOptions.Add(@{ Label = 'Import to IIS certificate store and update site bindings'; Mode = 'IIS' })
    }
    $rdgLabel = if ($script:RDGAvailable) {
        'Bind to RD Gateway (TSGateway) - updates the gateway SSL certificate'
    } else {
        'Bind to RD Gateway (TSGateway) - [TSGateway not detected on this machine]'
    }
    $menuOptions.Add(@{ Label = $rdgLabel; Mode = 'RDGateway' })
    $menuOptions.Add(@{ Label = 'Export as PFX file to a folder (for any web server / load balancer)'; Mode = 'PFX' })
    $menuOptions.Add(@{ Label = 'Deploy to WatchGuard Firebox (web-server-cert via SSH + FTP)'; Mode = 'WatchGuard' })

    Write-Host ""
    Write-Host "  How should the certificate be deployed?" -ForegroundColor White
    Write-Host ""
    if (-not $script:IISAvailable) {
        Write-Host "  IIS not detected - IIS binding option is unavailable on this server." -ForegroundColor Yellow
        Write-Host ""
    }
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        Write-Host "  [$($i+1)] $($menuOptions[$i].Label)" -ForegroundColor Cyan
    }
    Write-Host ""

    $maxChoice = $menuOptions.Count
    $validChoices = 1..$maxChoice | ForEach-Object { "$_" }
    do {
        $outputChoice = Read-Host "  Select output [1-$maxChoice]"
    } while ($outputChoice -notin $validChoices)

    $chosen = $menuOptions[[int]$outputChoice - 1]
    $script:OutputMode = $chosen.Mode

    switch ($script:OutputMode) {
        'PFX' {
            $script:PfxOutputPath = Read-Host "  Enter folder path to export PFX to (e.g. C:\Certs)"
            if ([string]::IsNullOrWhiteSpace($script:PfxOutputPath)) {
                throw "A folder path is required for PFX export."
            }
            Write-Log "Certificate output: PFX export to $PfxOutputPath" -Level Info
        }
        'RDGateway' {
            # RD Gateway requires the cert in Cert:\LocalMachine\My
            $script:CertStorePath = 'Cert:\LocalMachine\My'

            # Check the existing RD Gateway cert hostname against the requested domain
            $currentGWCert = Get-RDGatewayCurrentCert
            if ($currentGWCert) {
                Write-Log "Current RD Gateway certificate: Subject=$($currentGWCert.Subject)  Expires=$($currentGWCert.NotAfter.ToString('yyyy-MM-dd'))" -Level Info

                $gwCN = if ($currentGWCert.Subject -match 'CN=([^,]+)') { $Matches[1] } else { '' }
                $reqBase = $DomainName.TrimStart('*').TrimStart('.')
                $gwBase  = $gwCN.TrimStart('*').TrimStart('.')

                if ($gwBase -and $reqBase -ne $gwBase) {
                    Write-Log "WARNING: Requested domain '$DomainName' differs from current RD Gateway cert hostname '$gwCN'. RDP clients connecting to '$gwBase' will need a matching cert." -Level Warning
                    Write-Host ""
                    Write-Host "  Current gateway cert: $gwCN" -ForegroundColor Yellow
                    Write-Host "  Requested domain:     $DomainName" -ForegroundColor Yellow
                    Write-Host "  These do not match. Clients connecting to '$gwBase' may get certificate warnings." -ForegroundColor Yellow
                    Write-Host ""
                    $confirm = Read-Host "  Continue anyway? [y/N]"
                    if ($confirm -notmatch '^[Yy]') {
                        throw "Aborted by user - domain mismatch for RD Gateway certificate."
                    }
                }
            }
            else {
                Write-Log "No existing RD Gateway certificate found (or cert is not in Cert:\LocalMachine\My). Proceeding." -Level Warning
            }

            Write-Log "Certificate output: RD Gateway binding (Cert:\LocalMachine\My + TSGateway service restart)" -Level Info
        }
        'IIS' {
            Write-Log "Certificate output: IIS certificate store + binding update" -Level Info
        }
        'WatchGuard' {
            # Gather Firebox connection details interactively if not provided
            if (-not $script:FireboxHost) {
                Write-Host ""
                $script:FireboxHost = Read-Host "  Firebox hostname or IP"
                if ([string]::IsNullOrWhiteSpace($script:FireboxHost)) {
                    throw "Firebox hostname or IP is required for WatchGuard deployment."
                }
            }

            Write-Host "  SSH port [$($script:FireboxSshPort)]:" -ForegroundColor Gray -NoNewline
            $sshIn = Read-Host " "
            if (-not [string]::IsNullOrWhiteSpace($sshIn)) { $script:FireboxSshPort = [int]$sshIn }

            if (-not $script:FireboxLocalIP) {
                $detected = (Get-NetIPAddress -AddressFamily IPv4 |
                    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
                    Sort-Object InterfaceIndex | Select-Object -First 1).IPAddress
                Write-Host "  This machine's IP (Firebox will FTP back to this) [$detected]:" -ForegroundColor Gray -NoNewline
                $localIpIn = Read-Host " "
                $script:FireboxLocalIP = if ($localIpIn.Trim()) { $localIpIn.Trim() } else { $detected }
            }

            Write-Host "  FTP port (used for cert transfer) [$($script:FireboxFtpPort)]:" -ForegroundColor Gray -NoNewline
            $ftpIn = Read-Host " "
            if (-not [string]::IsNullOrWhiteSpace($ftpIn)) { $script:FireboxFtpPort = [int]$ftpIn }

            Write-Log "Certificate output: WatchGuard Firebox $($script:FireboxHost):$($script:FireboxSshPort) (SSH+FTP deploy)" -Level Info
        }
    }
}

function Show-ChallengeTypeMenu {
    # Only show the menu in interactive mode - when parameters are passed directly, respect them
    if (-not $script:isInteractive) { return }

    # Check for wildcards - they require DNS
    $allCheckDomains = @($DomainName) + @($AdditionalDomains | Where-Object { $_ })
    $hasWildcard = $allCheckDomains | Where-Object { $_ -like '*`**' }

    if ($hasWildcard) {
        Write-Host ""
        Write-Host "  Wildcard domain detected - DNS-01 validation is required." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] DNS-01 with plugin (automated via DNS provider API)" -ForegroundColor Cyan
        Write-Host "  [2] DNS-01 manual (you create TXT records when prompted)" -ForegroundColor Cyan
        Write-Host ""

        do {
            $chalChoice = Read-Host "  Select challenge type [1-2]"
        } while ($chalChoice -notin @('1', '2'))

        if ($chalChoice -eq '1') {
            $script:ChallengeType = 'Dns'
            if (-not $DnsPlugin) {
                Write-Host ""
                Write-Host "  Common DNS plugins: AzureDns, Cloudflare, GoDaddy, Route53, Namecheap, OVH" -ForegroundColor Gray
                Write-Host "  Full list: run 'Get-PAPlugin' after Posh-ACME is installed" -ForegroundColor Gray
                Write-Host ""
                $script:DnsPlugin = Read-Host "  Enter DNS plugin name"
                if ([string]::IsNullOrWhiteSpace($script:DnsPlugin)) {
                    throw "A DNS plugin name is required for DNS-01 automated validation."
                }
            }
        }
        else {
            $script:ChallengeType = 'DnsManual'
        }
    }
    else {
        Write-Host ""
        Write-Host "  How should domain ownership be validated?" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1] HTTP-01  - Serve a challenge file via IIS on port 80 (requires public IIS)" -ForegroundColor Cyan
        Write-Host "  [2] DNS-01   - Create a DNS TXT record via provider API (automated)" -ForegroundColor Cyan
        Write-Host "  [3] DNS-01   - Create a DNS TXT record manually (you will be prompted)" -ForegroundColor Cyan
        Write-Host ""

        do {
            $chalChoice = Read-Host "  Select challenge type [1-3]"
        } while ($chalChoice -notin @('1', '2', '3'))

        switch ($chalChoice) {
            '1' { $script:ChallengeType = 'Http' }
            '2' {
                $script:ChallengeType = 'Dns'
                if (-not $DnsPlugin) {
                    Write-Host ""
                    Write-Host "  Common DNS plugins: AzureDns, Cloudflare, GoDaddy, Route53, Namecheap, OVH" -ForegroundColor Gray
                    Write-Host "  Full list: run 'Get-PAPlugin' after Posh-ACME is installed" -ForegroundColor Gray
                    Write-Host ""
                    $script:DnsPlugin = Read-Host "  Enter DNS plugin name"
                    if ([string]::IsNullOrWhiteSpace($script:DnsPlugin)) {
                        throw "A DNS plugin name is required for DNS-01 automated validation."
                    }
                }
            }
            '3' { $script:ChallengeType = 'DnsManual' }
        }
    }

    Write-Log "Challenge type: $ChallengeType"
}

function Show-EmailReportMenu {
    <#
    .SYNOPSIS
        Interactively configures optional email reporting for certificate renewal runs.
        Settings are DPAPI/LocalMachine-encrypted in email_config.json so the
        scheduled task (running as SYSTEM) can send reports without prompting.
    #>
    if (-not $script:isInteractive) { return }

    Write-Host ""
    Write-Host "  -- Email Reporting --------------------------------------------------------" -ForegroundColor DarkGray

    # Offer to keep / update / disable existing config
    $existing = Get-EmailConfig
    if ($existing -and $existing.Enabled) {
        Write-Host "  Email reporting is already configured:" -ForegroundColor Green
        Write-Host "    Method:    $($existing.Method)" -ForegroundColor Gray
        Write-Host "    Sender:    $($existing.Sender)" -ForegroundColor Gray
        Write-Host "    Recipient: $($existing.Recipient)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [K] Keep existing settings (default)" -ForegroundColor Cyan
        Write-Host "  [U] Update / reconfigure" -ForegroundColor Cyan
        Write-Host "  [D] Disable email reporting" -ForegroundColor Cyan
        Write-Host ""
        $action = Read-Host "  Choice [K/u/d]"

        if ($action -match '^[Dd]') {
            # Just flip the Enabled flag in-place without re-encrypting secrets
            $cfgFile = Join-Path $LogDir "email_config.json"
            $raw = Get-Content $cfgFile -Raw | ConvertFrom-Json
            $raw.Enabled = $false
            $raw | ConvertTo-Json | Set-Content -Path $cfgFile -Encoding UTF8
            $script:SendReport = $false
            Write-Log "Email reporting disabled" -Level Info
            return
        }
        if ($action -notmatch '^[Uu]') {
            # Keep — load saved notes into script scope so Send-RenewalReport picks them up
            $script:SendReport = $true
            if ($existing.SubjectNote) { $script:EmailSubjectNote = $existing.SubjectNote }
            if ($existing.BodyNote)    { $script:EmailBodyNote    = $existing.BodyNote }
            Write-Log "Email reporting: keeping existing config ($($existing.Method) -> $($existing.Recipient))" -Level Info
            return
        }
        # Fall through to reconfigure
        Write-Host ""
    }
    else {
        $enable = Read-Host "  Configure email reports for this renewal run (and future scheduled runs)? [y/N]"
        if ($enable -notmatch '^[Yy]') {
            $script:SendReport = $false
            return
        }
    }

    # ---- Choose method ----
    Write-Host ""
    Write-Host "  [1] Microsoft 365 Graph API  (OAuth2 app credentials - recommended for M365 environments)" -ForegroundColor Cyan
    Write-Host "  [2] SMTP  (any mail server with username/password - Office 365, Gmail, etc.)" -ForegroundColor Cyan
    Write-Host ""
    do { $methodChoice = Read-Host "  Select method [1-2]" } while ($methodChoice -notin @('1', '2'))

    $config = @{
        Enabled   = $true
        Method    = if ($methodChoice -eq '1') { 'Graph' } else { 'SMTP' }
        Sender    = ''
        Recipient = ''
    }

    Write-Host ""
    $config.Recipient = Read-Host "  Send reports TO (recipient email)"
    if ([string]::IsNullOrWhiteSpace($config.Recipient)) { throw "Recipient email is required." }

    if ($config.Method -eq 'Graph') {
        Write-Host ""
        Write-Host "  -- Microsoft 365 Graph API --------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Prerequisites:" -ForegroundColor Gray
        Write-Host "    1. Azure Portal -> Azure AD -> App registrations -> New registration" -ForegroundColor Gray
        Write-Host "    2. API permissions -> Add -> Microsoft Graph -> Application -> Mail.Send" -ForegroundColor Gray
        Write-Host "    3. Grant admin consent for Mail.Send" -ForegroundColor Gray
        Write-Host "    4. Certificates & secrets -> New client secret -> copy the VALUE (not ID)" -ForegroundColor Gray
        Write-Host "    5. The sender must be a licensed M365 user or shared mailbox" -ForegroundColor Gray
        Write-Host ""
        $config.TenantId = Read-Host "  Azure Tenant (Directory) ID"
        $config.ClientId = Read-Host "  App Registration (Client) ID"
        $cssSS = Read-Host "  Client Secret VALUE" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cssSS)
        try   { $config.ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $config.Sender = Read-Host "  FROM address (licensed M365 mailbox, e.g. alerts@contoso.com)"
    }
    else {
        Write-Host ""
        Write-Host "  -- SMTP Settings ------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Common configs:" -ForegroundColor Gray
        Write-Host "    Office 365:  smtp.office365.com  port 587  (STARTTLS)" -ForegroundColor Gray
        Write-Host "    Gmail:       smtp.gmail.com       port 587  (use App Password if 2FA enabled)" -ForegroundColor Gray
        Write-Host ""
        $config.SmtpServer   = Read-Host "  SMTP server"
        $smtpPortIn = Read-Host "  SMTP port [587]"
        $config.SmtpPort     = if ($smtpPortIn.Trim()) { [int]$smtpPortIn } else { 587 }
        $config.SmtpUsername = Read-Host "  SMTP username"
        $smtpPassSS = Read-Host "  SMTP password" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($smtpPassSS)
        try   { $config.SmtpPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $config.Sender = Read-Host "  FROM address (e.g. noreply@contoso.com)"
    }

    Write-Host ""
    Write-Host "  -- Email Customization (optional) ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Subject note: text appended to every report subject line." -ForegroundColor Gray
    Write-Host "    Example: 'Contoso Ltd'  ->  '[YW] Let's Encrypt - domain - Success - Contoso Ltd'" -ForegroundColor Gray
    $subjectNoteIn = Read-Host "  Subject note [leave blank to skip]"
    $config.SubjectNote = $subjectNoteIn.Trim()

    Write-Host ""
    Write-Host "  Body note: text added as a Notes row in every report email." -ForegroundColor Gray
    Write-Host "  Supports ConnectWise routing tags, e.g. !!contact@company.com!! Company Name" -ForegroundColor Gray
    $bodyNoteIn = Read-Host "  Body note [leave blank to skip]"
    $config.BodyNote = $bodyNoteIn.Trim()

    if ($config.SubjectNote) { $script:EmailSubjectNote = $config.SubjectNote }
    if ($config.BodyNote)    { $script:EmailBodyNote    = $config.BodyNote }

    Save-EmailConfig -Config $config
    $script:SendReport = $true
    Write-Log "Email reporting configured: $($config.Method) -> $($config.Recipient)" -Level Success

    # Offer a test send
    Write-Host ""
    $testNow = Read-Host "  Send a test email now to verify settings? [y/N]"
    if ($testNow -match '^[Yy]') {
        $savedCfg = Get-EmailConfig
        try {
            $testSubj = "[YW] Let's Encrypt - Test Email ($DomainName)"
            $testBody = @"
<html><body style="font-family:Arial,sans-serif;padding:20px;color:#333">
<div style="max-width:560px;margin:0 auto">
  <div style="background:#FF6600;padding:16px 20px;border-radius:6px 6px 0 0">
    <span style="color:#fff;font-size:17px;font-weight:bold">Yeyland Wutani LLC</span>
    <span style="color:#ffe0c0;font-size:12px;margin-left:8px">Building Better Systems</span>
  </div>
  <div style="background:#fff;padding:20px;border:1px solid #ddd;border-top:none">
    <p style="font-size:16px;font-weight:bold;color:#28a745;margin:0 0 12px">&#10003; Test Email Successful</p>
    <p>Email reporting is correctly configured for <strong>$DomainName</strong>.</p>
    <p style="color:#666;font-size:13px">You will receive a report like this after each certificate renewal attempt.</p>
  </div>
  <div style="background:#f8f8f8;padding:10px 20px;border:1px solid #ddd;border-top:none;border-radius:0 0 6px 6px;font-size:11px;color:#999">
    Let's Encrypt Certificate Manager v$ScriptVersion &bull; Yeyland Wutani LLC
  </div>
</div></body></html>
"@
            switch ($savedCfg.Method) {
                'Graph' { Send-GraphEmail -Config $savedCfg -Subject $testSubj -HtmlBody $testBody }
                'SMTP'  { Send-SmtpEmail  -Config $savedCfg -Subject $testSubj -HtmlBody $testBody }
            }
            Write-Host "  Test email sent successfully!" -ForegroundColor Green
            Write-Log "Test email sent to $($savedCfg.Recipient)" -Level Success
        }
        catch {
            $detail = $_.Exception.Message
            if ($_.ErrorDetails.Message) {
                try { $body = $_.ErrorDetails.Message | ConvertFrom-Json; $detail += " - $($body.error.message)" } catch {}
            }
            Write-Host "  Test email failed: $detail" -ForegroundColor Red
            Write-Host "  Check your credentials and try again (menu option 4 -> reconfigure email)." -ForegroundColor Yellow
            Write-Log "Test email failed: $detail" -Level Warning
        }
    }
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."

    # Check internet connectivity to Let's Encrypt
    $acmeEndpoint = if ($Staging) { "acme-staging-v02.api.letsencrypt.org" } else { "acme-v02.api.letsencrypt.org" }
    $acmeUrl = "https://$acmeEndpoint/directory"

    # Detect this server's public IP for logging
    $publicIP = $null
    foreach ($ipSvc in @('https://api.ipify.org', 'https://icanhazip.com')) {
        try {
            $publicIP = (Invoke-RestMethod -Uri $ipSvc -TimeoutSec 5 -ErrorAction Stop).Trim()
            break
        } catch { continue }
    }
    if ($publicIP) { Write-Log "Server public IP: $publicIP" -Level Info }
    else { Write-Log "Could not determine server public IP (not fatal)" -Level Warning }

    # Test actual HTTPS connectivity to the ACME directory endpoint (avoids split-DNS issues)
    try {
        $null = Invoke-WebRequest -Uri $acmeUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
    }
    catch {
        throw "Cannot reach $acmeUrl. Check internet connectivity and firewall rules. Error: $($_.Exception.Message)"
    }
    Write-Log "ACME endpoint reachable ($acmeEndpoint)" -Level Success

    # Challenge-type-specific checks
    if ($ChallengeType -eq 'Http') {
        # HTTP-01 requires IIS for serving the challenge file
        if (-not $script:IISAvailable) {
            Write-Host ""
            Write-Host "  HTTP-01 challenge requires IIS to serve the challenge file, but IIS is not available." -ForegroundColor Yellow
            Write-Host "  You can switch to DNS-01 validation instead." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [1] DNS-01 with plugin (automated via DNS provider API)" -ForegroundColor Cyan
            Write-Host "  [2] DNS-01 manual (you create TXT records when prompted)" -ForegroundColor Cyan
            Write-Host ""

            do {
                $fallbackChoice = Read-Host "  Select challenge type [1-2]"
            } while ($fallbackChoice -notin @('1', '2'))

            if ($fallbackChoice -eq '1') {
                $script:ChallengeType = 'Dns'
                if (-not $DnsPlugin) {
                    Write-Host ""
                    Write-Host "  Common DNS plugins: AzureDns, Cloudflare, GoDaddy, Route53, Namecheap, OVH" -ForegroundColor Gray
                    Write-Host "  Full list: run 'Get-PAPlugin' after Posh-ACME is installed" -ForegroundColor Gray
                    Write-Host ""
                    $script:DnsPlugin = Read-Host "  Enter DNS plugin name"
                    if ([string]::IsNullOrWhiteSpace($script:DnsPlugin)) {
                        throw "A DNS plugin name is required for DNS-01 automated validation."
                    }
                }
                Write-Log "Switched to DNS-01 plugin challenge (IIS not available for HTTP-01)" -Level Info
            }
            else {
                $script:ChallengeType = 'DnsManual'
                Write-Log "Switched to DNS-01 manual challenge (IIS not available for HTTP-01)" -Level Info
            }
        }
        else {
            # Check port 80 listener (needed for HTTP-01 challenge)
            $port80 = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
            if (-not $port80) {
                Write-Log "No listener on port 80. IIS must be running and listening on port 80 for HTTP-01 challenges." -Level Warning
            }

            # Wildcard domains require DNS-01
            $allCheckDomains = @($DomainName) + @($AdditionalDomains | Where-Object { $_ })
            $hasWildcard = $allCheckDomains | Where-Object { $_ -like '*`**' }
            if ($hasWildcard) {
                throw "Wildcard certificates (e.g. *.contoso.com) require DNS-01 validation. Use -ChallengeType Dns or -ChallengeType DnsManual."
            }
        }
    }

    # Re-check after potential fallback from HTTP to DNS
    if ($script:ChallengeType -eq 'Dns') {
        if (-not $script:DnsPlugin) {
            if ($script:isInteractive) {
                Write-Host ""
                Write-Host "  Common DNS plugins: AzureDns, Cloudflare, GoDaddy, Route53, Namecheap, OVH" -ForegroundColor Gray
                Write-Host "  Full list: run 'Get-PAPlugin' after Posh-ACME is installed" -ForegroundColor Gray
                Write-Host ""
                $script:DnsPlugin = Read-Host "  Enter DNS plugin name"
                if ([string]::IsNullOrWhiteSpace($script:DnsPlugin)) {
                    throw "A DNS plugin name is required for DNS-01 automated validation."
                }
            }
            else {
                throw "DNS-01 challenge requires -DnsPlugin parameter. Run 'Get-PAPlugin' to see available plugins, or use -ChallengeType DnsManual for manual TXT record creation."
            }
        }
        Write-Log "DNS-01 challenge mode: plugin=$($script:DnsPlugin), propagation wait=${DnsSleep}s" -Level Info
    }
    elseif ($script:ChallengeType -eq 'DnsManual') {
        Write-Log "DNS-01 manual mode: you will be prompted to create TXT records during validation" -Level Warning
        Write-Log "Manual DNS mode is NOT suitable for unattended scheduled task renewals" -Level Warning
    }

    # Validate PfxOutputPath if specified
    if ($PfxOutputPath) {
        if (-not (Test-Path $PfxOutputPath)) {
            New-Item -ItemType Directory -Path $PfxOutputPath -Force | Out-Null
            Write-Log "Created PFX output directory: $PfxOutputPath" -Level Info
        }
    }

    # Verify certificate store path exists or fall back (IIS and RDGateway modes use the cert store)
    if ($script:OutputMode -in @('IIS', 'RDGateway')) {
        if ($script:CertStorePath -eq "Cert:\LocalMachine\WebHosting") {
            try {
                $null = Get-ChildItem $CertStorePath -ErrorAction Stop
            }
            catch {
                $script:CertStorePath = "Cert:\LocalMachine\My"
                Write-Log "WebHosting store unavailable, falling back to LocalMachine\My" -Level Warning
            }
        }
        Write-Log "Certificate store: $($script:CertStorePath)" -Level Info
    }
}

# ============================================================================
# POSH-ACME MODULE MANAGEMENT
# ============================================================================

function Install-PoshAcmeModule {
    # Pin Posh-ACME's data directory to a shared system path BEFORE loading the module.
    # By default Posh-ACME stores accounts, orders, and certs in $env:LOCALAPPDATA,
    # which differs between the interactive user and the SYSTEM account that runs the
    # scheduled task.  Without this, SYSTEM finds no cached cert, creates a new ACME
    # account, and re-issues a fresh certificate on every task run.
    $paHome = Join-Path $env:ProgramData "YeylandWutani\PoshAcme"
    if (-not (Test-Path $paHome)) {
        New-Item -ItemType Directory -Path $paHome -Force | Out-Null
    }
    $env:POSHACME_HOME = $paHome
    Write-Log "Posh-ACME data directory: $paHome"

    if (Get-Module -ListAvailable -Name Posh-ACME) {
        Write-Log "Posh-ACME module is already installed" -Level Success
        Import-Module Posh-ACME -Force
        return
    }

    Write-Log "Installing Posh-ACME module from PowerShell Gallery..."

    # Ensure NuGet provider is available
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget -or $nuget.Version -lt [version]"2.8.5.201") {
        Write-Log "Installing NuGet package provider..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
    }

    # Trust PSGallery if needed
    $repo = Get-PSRepository -Name PSGallery
    if ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    Install-Module -Name Posh-ACME -Scope AllUsers -Force -AllowClobber
    Import-Module Posh-ACME -Force
    Write-Log "Posh-ACME module installed and loaded" -Level Success
}

# ============================================================================
# WATCHGUARD FIREBOX DEPLOYMENT
# Deploys a Posh-ACME certificate to a locally-managed WatchGuard Firebox
# via SSH (port 4118) + ephemeral in-process FTP server for cert transfer.
# Supports: web-server-cert (Fireware Web UI SSL certificate)
# Note: IKEv2 Mobile VPN cert assignment via CLI is not available on
#       Fireware v12.10+ - that requires manual configuration in the Web UI.
# ============================================================================

function Install-PoshSshModule {
    if (Get-Module -ListAvailable -Name Posh-SSH) {
        Write-Log "Posh-SSH module is already installed" -Level Success
        Import-Module Posh-SSH -Force
        return
    }

    Write-Log "Installing Posh-SSH module from PowerShell Gallery..."

    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget -or $nuget.Version -lt [version]"2.8.5.201") {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
    }

    $repo = Get-PSRepository -Name PSGallery
    if ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    Install-Module -Name Posh-SSH -Scope AllUsers -Force -AllowClobber
    Import-Module Posh-SSH -Force
    Write-Log "Posh-SSH module installed and loaded" -Level Success
}

function Invoke-FireboxCommand {
    <#
    .SYNOPSIS
        Sends a CLI command to a WatchGuard Firebox over an SSH shell stream
        and waits for the prompt to return, then returns the buffered output.
    #>
    param(
        $Stream,
        [string]$Cmd,
        [int]$TimeoutMs = 4000
    )
    $Stream.WriteLine($Cmd)
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    $buf = ''
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
        $chunk = $Stream.Read()
        if ($chunk) { $buf += $chunk }
        # WatchGuard prompts: "WG> " (main) or "WG(config)> " (config mode)
        if ($buf -match 'WG[^>]*>\s*$') { break }
    }
    return $buf
}

function Save-FireboxCredentials {
    <#
    .SYNOPSIS
        Saves Firebox connection parameters and SSH credentials to a
        DPAPI/LocalMachine-encrypted JSON file so the scheduled task
        (running as SYSTEM) can connect without interactive prompts.
    #>
    param([System.Management.Automation.PSCredential]$Credential)

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    $credFile = Join-Path $LogDir "firebox_creds.json"

    # Encrypt username
    $encUser = [Convert]::ToBase64String(
        [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::UTF8.GetBytes($Credential.UserName),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )

    # Decrypt SecureString to plain, encrypt with DPAPI, zero out plain
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    try   { $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $encPass = [Convert]::ToBase64String(
        [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::UTF8.GetBytes($plainPass),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    $plainPass = $null

    $store = @{
        FireboxHost    = $script:FireboxHost
        FireboxSshPort = $script:FireboxSshPort
        FireboxLocalIP = $script:FireboxLocalIP
        FireboxFtpPort = $script:FireboxFtpPort
        SavedAt        = (Get-Date -Format 'o')
        Username       = $encUser
        Password       = $encPass
    }

    $store | ConvertTo-Json | Set-Content -Path $credFile -Encoding UTF8

    # Restrict file to Administrators and SYSTEM only
    try {
        $acl = Get-Acl -Path $credFile
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')))
        Set-Acl -Path $credFile -AclObject $acl
    }
    catch {
        Write-Log "Could not restrict firebox_creds.json permissions (non-fatal): $($_.Exception.Message)" -Level Warning
    }

    Write-Log "Firebox credentials saved (DPAPI/LocalMachine): $credFile" -Level Info
}

function Get-FireboxCredentials {
    <#
    .SYNOPSIS
        Loads and decrypts saved Firebox credentials. Also restores
        connection parameters (host, ports) that were not provided on the
        command line.
    #>
    $credFile = Join-Path $LogDir "firebox_creds.json"
    if (-not (Test-Path $credFile)) { return $null }

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    try {
        $store = Get-Content -Path $credFile -Raw | ConvertFrom-Json

        # Restore connection params into script scope from saved file
        # (command-line params take priority if already set)
        if (-not $script:FireboxHost    -and $store.FireboxHost)    { $script:FireboxHost    = $store.FireboxHost }
        if (-not $script:FireboxLocalIP -and $store.FireboxLocalIP) { $script:FireboxLocalIP = $store.FireboxLocalIP }
        if ($store.FireboxSshPort) { $script:FireboxSshPort = $store.FireboxSshPort }
        if ($store.FireboxFtpPort) { $script:FireboxFtpPort = $store.FireboxFtpPort }

        $username = [System.Text.Encoding]::UTF8.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [Convert]::FromBase64String($store.Username), $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        $passPlain = [System.Text.Encoding]::UTF8.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [Convert]::FromBase64String($store.Password), $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        $ss = New-Object System.Security.SecureString
        foreach ($c in $passPlain.ToCharArray()) { $ss.AppendChar($c) }
        $ss.MakeReadOnly()
        $passPlain = $null

        $cred = New-Object System.Management.Automation.PSCredential($username, $ss)
        Write-Log "Loaded saved Firebox credentials for $username @ $($script:FireboxHost) (saved $($store.SavedAt))" -Level Info
        return $cred
    }
    catch {
        Write-Log "Failed to load saved Firebox credentials: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Get-FireboxCredentialsInteractive {
    <#
    .SYNOPSIS
        Prompts the operator for Firebox SSH credentials, offering to reuse
        any previously saved credentials. Returns a PSCredential.
    #>
    Write-Host ""
    Write-Host "  -- Firebox SSH Credentials -----------------------------------------------" -ForegroundColor DarkGray

    # Offer to reuse saved credentials
    $saved = Get-FireboxCredentials
    if ($saved) {
        $credFile = Join-Path $LogDir "firebox_creds.json"
        $savedDate = (Get-Content $credFile -Raw | ConvertFrom-Json).SavedAt
        Write-Host "  Found saved credentials for '$($saved.UserName)' (saved $savedDate)" -ForegroundColor Green
        $reuse = Read-Host "  Use saved credentials? [Y/n]"
        if ($reuse -eq '' -or $reuse -match '^[Yy]') {
            return $saved
        }
        Write-Host ""
    }

    return (Get-Credential -Message "Firebox SSH credentials for $($script:FireboxHost)")
}

function Deploy-WatchGuardCert {
    <#
    .SYNOPSIS
        Deploys a Posh-ACME certificate to a WatchGuard Firebox as the
        Firebox web-server-cert (the SSL certificate used by the Firebox Web UI
        and authentication portal).

    .DESCRIPTION
        1. Connects to the Firebox via SSH (Posh-SSH, default port 4118)
        2. Snapshots the current certificate list to detect the new cert after import
        3. Spins up an ephemeral in-process FTP server so the Firebox can pull the PFX
        4. Runs: import certificate general-usage from ftp://... <pfx-password>
        5. Diffs the certificate list to find the newly imported cert ID
        6. Enters config mode and runs: web-server-cert third-party <id>
        7. Confirms the activation and logs the result
    #>
    param(
        $PACertificate,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Log "WatchGuard deployment: $($script:FireboxHost):$($script:FireboxSshPort) | FTP callback: $($script:FireboxLocalIP):$($script:FireboxFtpPort)"

    # ------------------------------------------------------------------ #
    # Resolve PFX path and password from Posh-ACME certificate object
    # ------------------------------------------------------------------ #
    $pfxPath = $PACertificate.PfxFullChain
    if (-not $pfxPath -or -not (Test-Path $pfxPath)) { $pfxPath = $PACertificate.PfxFile }
    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
        throw "PFX file not found in Posh-ACME output. Certificate may not have been issued."
    }

    $pfxPlain = $PACertificate.PfxPass
    if ($pfxPlain -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxPlain)
        try   { $pfxPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    if ([string]::IsNullOrEmpty($pfxPlain)) { $pfxPlain = 'poshacme' }

    $pfxFile = Get-Item $pfxPath

    # ------------------------------------------------------------------ #
    # SSH connection
    # ------------------------------------------------------------------ #
    Write-Log "Connecting to Firebox via SSH..."
    $session = New-SSHSession -ComputerName $script:FireboxHost -Port $script:FireboxSshPort `
                   -Credential $Credential -AcceptKey -ErrorAction Stop
    $stream  = New-SSHShellStream -SSHSession $session

    $rs = $null; $ps = $null
    $fwRuleName = "YW-LetsEncrypt-FTP-Temp-$($script:FireboxFtpPort)"
    $fwDataRuleName = "YW-LetsEncrypt-FTP-Data-Temp-$($script:FireboxFtpPort)"
    $dataPort = $script:FireboxFtpPort + 1

    try {
        # Open temporary firewall rules for FTP control and data ports
        New-NetFirewallRule -DisplayName $fwRuleName -Direction Inbound -Protocol TCP `
            -LocalPort $script:FireboxFtpPort -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName $fwDataRuleName -Direction Inbound -Protocol TCP `
            -LocalPort $dataPort -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Temporary firewall rules created for FTP ports $($script:FireboxFtpPort) and $dataPort" -Level Info
        # Consume login banner - firmware version is in the banner (show version is not a valid command)
        Start-Sleep -Milliseconds 1500
        $banner = $stream.Read()
        $fwVersion = if ($banner -match 'Fireware\s+(?:OS\s+)?[Vv]ersion\s+([\d\.]+)') { $Matches[1] } else { 'unknown' }
        Write-Log "Firebox firmware: $fwVersion" -Level Success

        # Snapshot cert IDs before import (give show certificate extra time - can list 300+ certs)
        Write-Log "Reading current certificate list..."
        $certOut = Invoke-FireboxCommand -Stream $stream -Cmd 'show certificate' -TimeoutMs 15000
        $wsOut   = Invoke-FireboxCommand -Stream $stream -Cmd 'show web-server-cert'

        $currentWs = if ($wsOut -match 'Default') { 'Default (self-signed)' }
                     elseif ($wsOut -match 'Third.party') { 'Third-party (already customized)' }
                     else { 'Unknown' }
        Write-Log "Current web-server-cert: $currentWs" -Level Info

        $certIdsBefore = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($line in ($certOut -split "`n")) {
            if ($line -match '^\s*(\d{5,})\s') { [void]$certIdsBefore.Add($Matches[1]) }
        }
        Write-Log "Certificate IDs before import: $($certIdsBefore.Count)"

        # ---------------------------------------------------------------- #
        # Spin up minimal in-process FTP server (passive mode, one-shot)
        # The Firebox pulls the PFX file from this server during import.
        # ---------------------------------------------------------------- #
        Write-Log "Starting ephemeral FTP server on $($script:FireboxLocalIP):$($script:FireboxFtpPort)..."

        $ftpUser = 'wgcert'
        $ftpPass = [System.Guid]::NewGuid().ToString('N').Substring(0, 12)   # random each run

        $rsData = [hashtable]::Synchronized(@{
            FilePath = $pfxFile.FullName
            User     = $ftpUser
            Password = $ftpPass
            Port     = $script:FireboxFtpPort
            DataPort = $dataPort
            LocalIP  = $script:FireboxLocalIP
            Log      = [System.Collections.Generic.List[string]]::new()
            Ready    = $false
            Done     = $false
            Error    = $null
        })

        $ftpScript = {
            param($d)
            try {
                $ctl = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $d.Port)
                $ctl.Start()
                $d.Ready = $true
                $d.Log.Add("Listening on :$($d.Port)")

                $client = $ctl.AcceptTcpClient()
                $ns     = $client.GetStream()
                $rd     = [System.IO.StreamReader]::new($ns)
                $wr     = [System.IO.StreamWriter]::new($ns); $wr.AutoFlush = $true
                $wr.WriteLine('220 wgcert ready')
                $d.Log.Add("Client connected")

                $dataListener = $null
                $done = $false

                while (-not $done) {
                    $line = $rd.ReadLine()
                    if ($null -eq $line) { break }
                    $d.Log.Add(">> $line")
                    $parts = $line -split ' ', 2
                    $cmd   = $parts[0].ToUpper()
                    $arg   = if ($parts.Count -gt 1) { $parts[1] } else { '' }

                    switch ($cmd) {
                        'USER' { if ($arg -eq $d.User) { $wr.WriteLine('331 Password required') } else { $wr.WriteLine('530 Bad user') } }
                        'PASS' { if ($arg -eq $d.Password) { $wr.WriteLine('230 OK') } else { $wr.WriteLine('530 Bad pass') } }
                        'SYST' { $wr.WriteLine('215 UNIX Type: L8') }
                        'FEAT' { $wr.WriteLine("211-Features:`r`nPASV`r`n211 End") }
                        'OPTS' { $wr.WriteLine('200 OK') }
                        'PWD'  { $wr.WriteLine('257 "/" is cwd') }
                        'CWD'  { $wr.WriteLine('250 OK') }
                        'TYPE' { $wr.WriteLine('200 Type set') }
                        'PASV' {
                            $dataListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $d.DataPort)
                            $dataListener.Start()
                            $dp      = ($dataListener.LocalEndpoint).Port
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
                            $d.Log.Add("Sending: $($d.FilePath)")
                            $wr.WriteLine('150 Opening data connection')
                            $dc    = $dataListener.AcceptTcpClient()
                            $ds    = $dc.GetStream()
                            $bytes = [System.IO.File]::ReadAllBytes($d.FilePath)
                            $ds.Write($bytes, 0, $bytes.Length)
                            $ds.Close(); $dc.Close(); $dataListener.Stop(); $dataListener = $null
                            $d.Log.Add("Sent $($bytes.Length) bytes")
                            $wr.WriteLine('226 Transfer complete')
                            $done = $true   # one-shot: file delivered, exit the while loop
                        }
                        'QUIT' { $wr.WriteLine('221 Bye'); $done = $true }
                        default { $wr.WriteLine("500 Unknown: $cmd") }
                    }
                }
                $d.Done = $true
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
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript($ftpScript).AddArgument($rsData)
        $ftpHandle = $ps.BeginInvoke()

        # Wait up to 5 s for the FTP server to be ready
        $t0 = [datetime]::UtcNow
        while (-not $rsData.Ready -and ([datetime]::UtcNow - $t0).TotalSeconds -lt 5) {
            Start-Sleep -Milliseconds 100
        }
        if (-not $rsData.Ready) { throw "FTP server failed to start within 5 seconds." }
        Write-Log "FTP server ready" -Level Success

        # ---------------------------------------------------------------- #
        # Import certificate via Firebox CLI
        # ---------------------------------------------------------------- #
        $pfxFileName = $pfxFile.Name
        $ftpUrl      = "ftp://${ftpUser}:${ftpPass}@$($script:FireboxLocalIP):$($script:FireboxFtpPort)/${pfxFileName}"

        Write-Log "Importing certificate (may take up to 30 s)..."
        $importCmd = "import certificate general-usage from $ftpUrl $pfxPlain"
        $importOut = Invoke-FireboxCommand -Stream $stream -Cmd $importCmd -TimeoutMs 30000

        Write-Log "Import response: $($importOut.Trim() -replace '\s+', ' ')"

        if ($importOut -match 'Edit Mode') {
            throw "EDIT MODE CONFLICT: Another admin session is holding Edit Mode on the Firebox. Close WatchGuard System Manager / Policy Manager on all other machines, then retry."
        }
        if ($importOut -match '%Error') {
            Write-Log "Import command returned a CLI error - review response above" -Level Warning
        }

        # ---------------------------------------------------------------- #
        # Verify: diff cert list before/after to find the new cert ID
        # ---------------------------------------------------------------- #
        Write-Log "Verifying import..."
        Start-Sleep -Milliseconds 1000
        $certOut2 = Invoke-FireboxCommand -Stream $stream -Cmd 'show certificate' -TimeoutMs 15000

        $newCertId = $null
        foreach ($line in ($certOut2 -split "`n")) {
            if ($line -match '^\s*(\d{5,})\s') {
                $candidate = $Matches[1]
                if (-not $certIdsBefore.Contains($candidate)) {
                    $newCertId = $candidate
                    Write-Log "New certificate ID: $newCertId" -Level Success
                    break
                }
            }
        }

        if (-not $newCertId) {
            throw "Certificate import could not be verified. No new certificate ID appeared in 'show certificate'. " +
                  "Check for Edit Mode conflicts, FTP connectivity, and PFX password."
        }

        # ---------------------------------------------------------------- #
        # Activate as web-server-cert (enter config mode, set, exit)
        # ---------------------------------------------------------------- #
        Write-Log "Activating certificate ID $newCertId as Firebox web-server-cert..."
        $null = Invoke-FireboxCommand -Stream $stream -Cmd 'configure'
        $wsSetOut = Invoke-FireboxCommand -Stream $stream -Cmd "web-server-cert third-party $newCertId"
        $null = Invoke-FireboxCommand -Stream $stream -Cmd 'exit'

        # Verify activation
        $wsOut2 = Invoke-FireboxCommand -Stream $stream -Cmd 'show web-server-cert'
        if ($wsOut2 -match 'Third.party') {
            Write-Log "web-server-cert set successfully to third-party certificate $newCertId" -Level Success
        }
        else {
            Write-Log "web-server-cert activation result: $($wsOut2.Trim() -replace '\s+',' ')" -Level Warning
        }

        # Log FTP server activity
        foreach ($entry in $rsData.Log) { Write-Log "FTP: $entry" }
        if ($rsData.Error) { Write-Log "FTP error: $($rsData.Error)" -Level Warning }

        Write-Log "WatchGuard Firebox certificate deployment complete" -Level Success
    }
    finally {
        # Always clean up SSH session, FTP runspace, and firewall rules
        if ($stream) {
            try { $stream.Close() } catch { }
        }
        if ($session) {
            try { $session | Remove-SSHSession | Out-Null } catch { }
        }
        if ($ps -and $ftpHandle) {
            try { $ps.EndInvoke($ftpHandle) } catch { }
            try { $ps.Dispose() } catch { }
        }
        if ($rs) {
            try { $rs.Close(); $rs.Dispose() } catch { }
        }
        # Remove temporary firewall rules
        Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName $fwDataRuleName -ErrorAction SilentlyContinue
        Write-Log "Temporary FTP firewall rules removed" -Level Info
    }
}

# ============================================================================
# EMAIL REPORTING
# Optional status emails after each renewal run.
# Supports Microsoft 365 Graph API (OAuth2 client credentials) and SMTP.
# All secrets are DPAPI/LocalMachine-encrypted in email_config.json so the
# scheduled task (running as SYSTEM) can send reports without prompting.
# ============================================================================

function Save-EmailConfig {
    param([hashtable]$Config)

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    $storeSubjectNote = [string]$Config.SubjectNote
    $storeBodyNote    = [string]$Config.BodyNote

    $store = [ordered]@{
        Enabled     = $Config.Enabled
        Method      = $Config.Method
        Sender      = $Config.Sender
        Recipient   = $Config.Recipient
        SubjectNote = $storeSubjectNote
        BodyNote    = $storeBodyNote
        SavedAt     = (Get-Date -Format 'o')
    }

    if ($Config.Method -eq 'SMTP') {
        $store.SmtpServer   = $Config.SmtpServer
        $store.SmtpPort     = $Config.SmtpPort
        $store.SmtpUsername = $Config.SmtpUsername
        $store.SmtpPasswordEnc = [Convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::UTF8.GetBytes($Config.SmtpPassword),
                $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }

    if ($Config.Method -eq 'Graph') {
        $store.TenantId = $Config.TenantId
        $store.ClientId = $Config.ClientId
        $store.ClientSecretEnc = [Convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::UTF8.GetBytes($Config.ClientSecret),
                $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }

    $cfgFile = Join-Path $LogDir "email_config.json"
    $store | ConvertTo-Json -Depth 10 | Set-Content -Path $cfgFile -Encoding UTF8

    try {
        $acl = Get-Acl -Path $cfgFile
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')))
        Set-Acl -Path $cfgFile -AclObject $acl
    }
    catch {
        Write-Log "Could not restrict email_config.json permissions (non-fatal): $($_.Exception.Message)" -Level Warning
    }

    Write-Log "Email config saved (DPAPI/LocalMachine): $cfgFile" -Level Info
}

function Get-EmailConfig {
    $cfgFile = Join-Path $LogDir "email_config.json"
    if (-not (Test-Path $cfgFile)) { return $null }
    try {
        return (Get-Content -Path $cfgFile -Raw | ConvertFrom-Json)
    }
    catch {
        Write-Log "Failed to load email config: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Send-GraphEmail {
    param($Config, [string]$Subject, [string]$HtmlBody)

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    # Decrypt client secret
    $secret = [System.Text.Encoding]::UTF8.GetString(
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            [Convert]::FromBase64String($Config.ClientSecretEnc), $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )

    # Acquire access token via client credentials flow
    $tokenResp = Invoke-RestMethod -Method Post -ErrorAction Stop `
        -Uri "https://login.microsoftonline.com/$($Config.TenantId)/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            grant_type    = 'client_credentials'
            client_id     = $Config.ClientId
            client_secret = $secret
            scope         = 'https://graph.microsoft.com/.default'
        }
    $secret = $null
    $token  = $tokenResp.access_token

    # Build and send message
    $payload = @{
        message = @{
            subject = $Subject
            body    = @{ contentType = 'HTML'; content = $HtmlBody }
            toRecipients = @(@{ emailAddress = @{ address = $Config.Recipient } })
        }
    }

    Invoke-RestMethod -Method Post -ErrorAction Stop `
        -Uri "https://graph.microsoft.com/v1.0/users/$($Config.Sender)/sendMail" `
        -Headers @{ Authorization = "Bearer $token" } `
        -ContentType 'application/json' `
        -Body ($payload | ConvertTo-Json -Depth 10) | Out-Null

    $token = $null
}

function Send-SmtpEmail {
    param($Config, [string]$Subject, [string]$HtmlBody)

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    # Decrypt password
    $passPlain = [System.Text.Encoding]::UTF8.GetString(
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            [Convert]::FromBase64String($Config.SmtpPasswordEnc), $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )

    $mail = New-Object System.Net.Mail.MailMessage
    $mail.From    = $Config.Sender
    $mail.To.Add($Config.Recipient)
    $mail.Subject = $Subject
    $mail.Body    = $HtmlBody
    $mail.IsBodyHtml = $true

    $smtp = New-Object System.Net.Mail.SmtpClient($Config.SmtpServer, $Config.SmtpPort)
    $smtp.EnableSsl    = $true
    $smtp.Credentials  = New-Object System.Net.NetworkCredential($Config.SmtpUsername, $passPlain)
    $passPlain = $null

    try   { $smtp.Send($mail) }
    finally { $smtp.Dispose(); $mail.Dispose() }
}

function Send-RenewalReport {
    if ($script:ReportSent) { return }

    $config = Get-EmailConfig
    if (-not $config -or -not $config.Enabled) { return }

    $status    = $script:ReportData.Status
    $domain    = $script:ReportData.Domain
    $mode      = if ($script:ReportData.Mode) { $script:ReportData.Mode } else { $script:OutputMode }
    $startTime = $script:ReportData.StartTime
    $message   = $script:ReportData.Message

    # Colour and icon per status
    $statusColor = switch ($status) {
        'Success' { '#28a745' }
        'Failed'  { '#dc3545' }
        'Skipped' { '#6c757d' }
        'Updated' { '#0d6efd' }
        default   { '#6c757d' }
    }
    $statusIcon = switch ($status) {
        'Success' { '&#10003;' }
        'Failed'  { '&#10007;' }
        'Skipped' { '&#8212;' }
        'Updated' { '&#8635;' }
        default   { '' }
    }
    $statusLabel = switch ($status) {
        'Success' { 'Certificate Renewed Successfully' }
        'Failed'  { 'Renewal Failed' }
        'Skipped' { 'No Renewal Needed' }
        'Updated' { 'Scheduled Task Updated' }
        default   { $status }
    }

    # Notes: parameter override wins, then config, then empty
    $subjectNote = [string]$script:EmailSubjectNote
    if (-not $subjectNote) { $subjectNote = [string]$config.SubjectNote }
    $bodyNote = [string]$script:EmailBodyNote
    if (-not $bodyNote) { $bodyNote = [string]$config.BodyNote }

    # Subject line
    $subject = "[YW] Let's Encrypt - $domain - $status"
    if ($subjectNote) { $subject += " - $subjectNote" }

    # Build detail rows
    $tdL = "style=`"padding:9px 4px;color:#666;font-size:13px;white-space:nowrap;vertical-align:top`""
    $tdR = "style=`"padding:9px 4px;font-size:13px;word-break:break-all`""

    $safeMsg = if ($message) {
        ($message -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;').Trim() -replace "`n", '<br>'
    } else { '' }

    $rows  = "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Domain</td><td $tdR><strong>$domain</strong></td></tr>`n"
    $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Deploy Mode</td><td $tdR>$mode</td></tr>`n"
    if ($mode -eq 'WatchGuard' -and $script:FireboxHost) {
        $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Firebox</td><td $tdR>$($script:FireboxHost):$($script:FireboxSshPort)</td></tr>`n"
    }
    if ($script:ReportData.NewExpiry) {
        $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>New Expiry</td><td $tdR><strong>$($script:ReportData.NewExpiry)</strong></td></tr>`n"
    }
    if ($script:ReportData.CurrentExpiry) {
        $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Cert Expiry</td><td $tdR>$($script:ReportData.CurrentExpiry)</td></tr>`n"
    }
    if ($script:ReportData.Thumbprint) {
        $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Thumbprint</td><td $tdR><code style=`"font-size:11px`">$($script:ReportData.Thumbprint)</code></td></tr>`n"
    }
    if ($safeMsg) {
        $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Details</td><td $tdR style=`"color:$statusColor`">$safeMsg</td></tr>`n"
    }
    $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Started</td><td $tdR>$($startTime.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>`n"
    $rows += "<tr style=`"border-bottom:1px solid #f0f0f0`"><td $tdL>Log File</td><td $tdR style=`"font-size:11px;color:#888`">$LogFile</td></tr>`n"
    if ($bodyNote) {
        $safeNote = ($bodyNote -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;').Trim() -replace "`n", '<br>'
        $rows += "<tr><td $tdL>Notes</td><td $tdR style=`"color:#555`">$safeNote</td></tr>`n"
    }

    # HTML email body
    $html = @"
<!DOCTYPE html>
<html><body style="margin:0;padding:20px;background:#f0f0f0;font-family:Arial,Helvetica,sans-serif">
<div style="max-width:600px;margin:0 auto">
  <div style="background:#FF6600;padding:18px 24px;border-radius:6px 6px 0 0">
    <span style="color:#fff;font-size:19px;font-weight:bold">Yeyland Wutani LLC</span>
    <span style="color:#ffe0c0;font-size:12px;margin-left:10px">Building Better Systems</span>
  </div>
  <div style="background:#fff;padding:24px;border:1px solid #ddd;border-top:none">
    <p style="font-size:16px;font-weight:bold;margin:0 0 16px;color:#222">Let's Encrypt Certificate Report</p>
    <div style="background:$statusColor;color:#fff;padding:11px 16px;border-radius:4px;margin-bottom:20px;font-size:15px;font-weight:bold">
      $statusIcon&nbsp; $statusLabel
    </div>
    <table style="width:100%;border-collapse:collapse">
      $rows
    </table>
  </div>
  <div style="background:#f8f8f8;padding:10px 24px;border:1px solid #ddd;border-top:none;border-radius:0 0 6px 6px;font-size:11px;color:#999;text-align:center">
    Let's Encrypt Certificate Manager v$ScriptVersion &bull; Yeyland Wutani LLC &bull; Automated Certificate Renewal
  </div>
</div>
</body></html>
"@

    try {
        switch ($config.Method) {
            'Graph' { Send-GraphEmail -Config $config -Subject $subject -HtmlBody $html }
            'SMTP'  { Send-SmtpEmail  -Config $config -Subject $subject -HtmlBody $html }
        }
        Write-Log "Renewal report sent to $($config.Recipient) via $($config.Method)" -Level Success
        $script:ReportSent = $true
    }
    catch {
        Write-Log "Failed to send renewal report: $($_.Exception.Message)" -Level Warning
    }
}

# ============================================================================
# IIS CHALLENGE CONFIGURATION
# ============================================================================

function New-AcmeChallengeConfig {
    param([string]$ChallengePath)

    Write-Log "Configuring IIS for HTTP-01 challenge response..."

    # Create the challenge directory
    if (-not (Test-Path $ChallengePath)) {
        New-Item -ItemType Directory -Path $ChallengePath -Force | Out-Null
    }

    # Create web.config to allow extensionless files and static content serving
    $webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
    <handlers>
      <clear />
      <add name="StaticFile" path="*" verb="GET" modules="StaticFileModule"
           resourceType="Either" requireAccess="Read" />
    </handlers>
    <validation validateIntegratedModeConfiguration="false" />
  </system.webServer>
</configuration>
"@
    $webConfig | Set-Content -Path (Join-Path $ChallengePath "web.config") -Encoding UTF8
    Write-Log "Challenge directory created: $ChallengePath" -Level Success
}

function Add-ChallengeVirtualDirectory {
    param(
        [string]$SiteName,
        [string]$ChallengePath
    )

    $vdirPath = "IIS:\Sites\$SiteName\.well-known\acme-challenge"
    $wellKnownPath = "IIS:\Sites\$SiteName\.well-known"

    # Create .well-known application/virtual directory if it doesn't exist
    if (-not (Test-Path $wellKnownPath)) {
        $wellKnownPhysical = Join-Path (Split-Path $ChallengePath -Parent) ".well-known"
        if (-not (Test-Path $wellKnownPhysical)) {
            New-Item -ItemType Directory -Path $wellKnownPhysical -Force | Out-Null
        }
        New-WebVirtualDirectory -Site $SiteName -Name ".well-known" -PhysicalPath $wellKnownPhysical -ErrorAction SilentlyContinue | Out-Null
    }

    # Create acme-challenge virtual directory
    if (-not (Test-Path $vdirPath)) {
        New-WebVirtualDirectory -Site $SiteName -Name ".well-known/acme-challenge" -PhysicalPath $ChallengePath -ErrorAction SilentlyContinue | Out-Null
    }

    Write-Log "Challenge virtual directory added to site: $SiteName" -Level Success
}

function Remove-ChallengeVirtualDirectory {
    param([string]$SiteName)

    $vdirPath = "IIS:\Sites\$SiteName\.well-known\acme-challenge"
    if (Test-Path $vdirPath) {
        Remove-Item $vdirPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Challenge virtual directory removed from site: $SiteName"
    }
}

# ============================================================================
# CERTIFICATE OPERATIONS
# ============================================================================

function Get-CurrentCertificate {
    param([string[]]$Domains)

    $primaryDomain = $Domains[0]

    # Search for existing certificates matching the domain
    $certs = Get-ChildItem $script:CertStorePath -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -match [regex]::Escape($primaryDomain) -or
        ($_.DnsNameList -and ($_.DnsNameList.Unicode -contains $primaryDomain))
    } | Sort-Object NotAfter -Descending

    if ($certs) {
        $cert = $certs[0]
        Write-Log "Found existing certificate: Subject=$($cert.Subject), Expires=$($cert.NotAfter), Thumbprint=$($cert.Thumbprint)"
        return $cert
    }

    Write-Log "No existing certificate found for $primaryDomain" -Level Info
    return $null
}

function Test-CertificateNeedsRenewal {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if (-not $Certificate) { return $true }

    $daysUntilExpiry = ($Certificate.NotAfter - (Get-Date)).Days
    Write-Log "Certificate expires in $daysUntilExpiry days (threshold: $RenewalDays days)"

    if ($daysUntilExpiry -le $RenewalDays) {
        Write-Log "Certificate is within renewal window" -Level Warning
        return $true
    }

    Write-Log "Certificate does not need renewal yet" -Level Success
    return $false
}

function Invoke-AcmeCertificateOrder {
    param([string[]]$Domains)

    # Set the ACME server
    $server = if ($Staging) { "LE_STAGE" } else { "LE_PROD" }
    Set-PAServer $server
    Write-Log "ACME server set to: $server"

    # Check for existing account or create new one
    $account = Get-PAAccount -ErrorAction SilentlyContinue
    if (-not $account) {
        Write-Log "Creating new ACME account with contact: $ContactEmail"
        $account = New-PAAccount -AcceptTOS -Contact $ContactEmail
        Write-Log "ACME account created: $($account.id)" -Level Success
    }
    else {
        Write-Log "Using existing ACME account: $($account.id)"
    }

    Write-Log "Requesting certificate for: $($Domains -join ', ')"

    # Build challenge parameters based on challenge type
    switch ($script:ChallengeType) {
        'Http' {
            $certParams = Build-HttpChallengeParams -Domains $Domains
        }
        'Dns' {
            $certParams = Build-DnsChallengeParams -Domains $Domains
        }
        'DnsManual' {
            $certParams = Build-DnsManualChallengeParams -Domains $Domains
        }
    }

    $maxAttempts = 2
    $lastError = $null
    $matchedSites = @()

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            # For HTTP-01, set up IIS challenge infrastructure
            if ($script:ChallengeType -eq 'Http') {
                $challengeDir = Join-Path $env:ProgramData "YeylandWutani\LetsEncrypt\challenges"
                New-AcmeChallengeConfig -ChallengePath $challengeDir
                $matchedSites = Add-ChallengeToMatchingSites -Domains $Domains -ChallengePath $challengeDir
            }

            # Pre-check: if Posh-ACME has a cached order for this domain with no
            # AuthURLs, the order is stale (LE already expired or removed those
            # authorizations). Remove it now so New-PACertificate creates a fresh
            # order. Posh-ACME swallows the internal Get-PAAuthorization exception
            # and returns $null, so we cannot detect this reliably in the catch block.
            if ($script:ChallengeType -in @('Dns', 'DnsManual')) {
                try {
                    $existingOrder = Get-PAOrder -MainDomain $Domains[0] -ErrorAction SilentlyContinue
                    if ($existingOrder -and
                        $existingOrder.status -in @('pending', 'processing') -and
                        (-not $existingOrder.AuthURLs -or $existingOrder.AuthURLs.Count -eq 0)) {
                        Write-Log "Stale ACME order detected (status=$($existingOrder.status), AuthURLs empty) - removing before attempt $attempt so a fresh order is created..." -Level Warning
                        Remove-StaleAcmeOrder -Domains $Domains
                    }
                }
                catch { }
            }

            if ($script:ChallengeType -eq 'Dns') {
                Write-Host ""
                Write-Host "  `u{231B} DNS propagation wait (~${DnsSleep}s) - do not interrupt..." -ForegroundColor Yellow
                Write-Host ""
                Write-Log "Submitting certificate order - Posh-ACME will create a DNS TXT record then wait ${DnsSleep}s for propagation before asking Let's Encrypt to verify. This is normal; please wait..." -Level Info
            }

            $paCert = New-PACertificate @certParams

            if (-not $paCert) {
                $errorHint = switch ($script:ChallengeType) {
                    'Http'      { "Check that port 80 is accessible from the internet and DNS points to this server." }
                    'Dns'       { "Check DNS plugin credentials and that the plugin can create TXT records in your DNS zone." }
                    'DnsManual' { "Check that TXT records were created correctly and had time to propagate." }
                }
                throw "Certificate order failed. $errorHint"
            }

            $envLabel = if ($Staging) { "STAGING " } else { "" }
            Write-Log "${envLabel}Certificate obtained successfully!" -Level Success
            Write-Log "  Thumbprint: $($paCert.Thumbprint)"
            Write-Log "  Expires: $($paCert.NotAfter)"

            # Persist DNS plugin credentials after every successful issuance so scheduled
            # task renewals (running as SYSTEM) can load them without prompting.
            if ($script:ChallengeType -eq 'Dns' -and $script:DnsPlugin -and $script:DnsPluginArgs) {
                Save-PluginCredentials -Plugin $script:DnsPlugin -PluginArgs $script:DnsPluginArgs
            }

            return $paCert
        }
        catch {
            $lastError = $_

            # Provide specific guidance for common ACME errors
            $msg = $_.Exception.Message
            if ($msg -match 'rateLimited') {
                Write-Log "RATE LIMITED: Let's Encrypt rate limit reached. Wait at least 1 hour before retrying. Use -Staging for testing." -Level Error
            }
            elseif ($msg -match 'unauthorized|Incorrect TXT') {
                Write-Log "AUTHORIZATION FAILED: The challenge response was rejected. For DNS-01, verify your API credentials and that the TXT record was created in the correct zone." -Level Error
            }
            elseif ($msg -match 'AuthURLs|No such authorization|Authorization not found') {
                Write-Log "Stale ACME order detected - the cached authorization has expired on Let's Encrypt's server. Removing the stale order so the next attempt creates a fresh one..." -Level Warning
                Remove-StaleAcmeOrder -Domains $Domains
            }

            if ($attempt -lt $maxAttempts) {
                $wait = 60 * $attempt
                Write-Log "Certificate order attempt $attempt failed: $($_.Exception.Message). Retrying in ${wait}s..." -Level Warning
                Start-Sleep -Seconds $wait
            }
        }
        finally {
            # Clean up HTTP-01 challenge virtual directories
            foreach ($siteName in $matchedSites) {
                Remove-ChallengeVirtualDirectory -SiteName $siteName
            }
            $matchedSites = @()
        }
    }

    throw $lastError
}

function Build-HttpChallengeParams {
    param([string[]]$Domains)

    $challengeDir = Join-Path $env:ProgramData "YeylandWutani\LetsEncrypt\challenges"

    return @{
        Domain     = $Domains
        AcceptTOS  = $true
        Contact    = $ContactEmail
        Plugin     = 'WebRoot'
        PluginArgs = @{ WRPath = $challengeDir }
        Force      = $ForceRenewal.IsPresent
        Verbose    = $false
    }
}

# ============================================================================
# CREDENTIAL MANAGEMENT
# Credentials are encrypted with DPAPI LocalMachine scope so that the
# scheduled task (running as SYSTEM) can decrypt them on renewal without
# any interactive prompt.
# ============================================================================

function Save-PluginCredentials {
    param(
        [string]$Plugin,
        [hashtable]$PluginArgs
    )

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    $credFile = Join-Path $LogDir "plugin_creds.json"

    $store = @{
        Plugin  = $Plugin
        SavedAt = (Get-Date -Format 'o')
        Args    = @{}
    }

    foreach ($key in $PluginArgs.Keys) {
        $val = $PluginArgs[$key]
        $isSecure = $val -is [System.Security.SecureString]

        if ($isSecure) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($val)
            try   { $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
            $plain = $null
        }
        else {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$val)
        }

        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
            $bytes, $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )

        $entryType = if ($isSecure) { 'SecureString' } else { 'String' }
        $store.Args[$key] = @{
            Type  = $entryType
            Value = [Convert]::ToBase64String($encrypted)
        }
    }

    $store | ConvertTo-Json -Depth 10 | Set-Content -Path $credFile -Encoding UTF8

    # Restrict file access to Administrators and SYSTEM only
    try {
        $acl = Get-Acl -Path $credFile
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')))
        Set-Acl -Path $credFile -AclObject $acl
    }
    catch {
        Write-Log "Could not restrict credential file permissions (non-fatal): $($_.Exception.Message)" -Level Warning
    }

    Write-Log "DNS plugin credentials saved (DPAPI/LocalMachine): $credFile" -Level Info
}

function Get-PluginCredentials {
    $credFile = Join-Path $LogDir "plugin_creds.json"
    if (-not (Test-Path $credFile)) { return $null }

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    try {
        $store = Get-Content -Path $credFile -Raw | ConvertFrom-Json

        if ($store.Plugin -ne $script:DnsPlugin) {
            Write-Log "Saved credentials are for plugin '$($store.Plugin)' but current plugin is '$($script:DnsPlugin)' - skipping" -Level Warning
            return $null
        }

        $result = @{}
        foreach ($key in $store.Args.PSObject.Properties.Name) {
            $entry   = $store.Args.$key
            $bytes   = [Convert]::FromBase64String($entry.Value)
            $plain   = [System.Text.Encoding]::UTF8.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $bytes, $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )

            if ($entry.Type -eq 'SecureString') {
                $ss = New-Object System.Security.SecureString
                foreach ($c in $plain.ToCharArray()) { $ss.AppendChar($c) }
                $ss.MakeReadOnly()
                $result[$key] = $ss
            }
            else {
                $result[$key] = $plain
            }
        }

        Write-Log "Loaded saved DNS plugin credentials for $($script:DnsPlugin) (saved $($store.SavedAt))" -Level Info
        return $result
    }
    catch {
        Write-Log "Failed to load saved plugin credentials: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Get-DnsPluginArgsInteractive {
    param([string]$Plugin)

    Write-Host ""
    Write-Host "  -- DNS Provider Credentials -----------------------------------------------" -ForegroundColor DarkGray

    # Check for a previously saved credential first
    $saved = Get-PluginCredentials
    if ($saved) {
        $credFile = Join-Path $LogDir "plugin_creds.json"
        $savedDate = (Get-Content $credFile -Raw | ConvertFrom-Json).SavedAt
        Write-Host "  Found saved credentials for $Plugin (saved $savedDate)" -ForegroundColor Green
        $reuse = Read-Host "  Use saved credentials? [Y/n]"
        if ($reuse -eq '' -or $reuse -match '^[Yy]') {
            return $saved
        }
        Write-Host ""
    }

    switch ($Plugin.ToLower()) {
        'cloudflare' {
            Write-Host "  Cloudflare API Token required." -ForegroundColor White
            Write-Host ""
            Write-Host "  How to get it:" -ForegroundColor Gray
            Write-Host "    1. Log in at dash.cloudflare.com" -ForegroundColor Gray
            Write-Host "    2. Click your profile icon (top right) -> My Profile" -ForegroundColor Gray
            Write-Host "    3. Go to the 'API Tokens' tab" -ForegroundColor Gray
            Write-Host "    4. Click 'Create Token' -> use the 'Edit zone DNS' template" -ForegroundColor Gray
            Write-Host "    5. Scope it to your specific zone (e.g. specificoffice.com)" -ForegroundColor Gray
            Write-Host "    6. Click 'Continue to summary' -> 'Create Token'" -ForegroundColor Gray
            Write-Host "    7. Copy the token - it is only shown once" -ForegroundColor Yellow
            Write-Host ""
            $token = Read-Host "  Paste your Cloudflare API Token" -AsSecureString
            return @{ CFToken = $token }
        }
        'godaddy' {
            Write-Host "  GoDaddy API Key and Secret required." -ForegroundColor White
            Write-Host ""
            Write-Host "  How to get them:" -ForegroundColor Gray
            Write-Host "    1. Go to developer.godaddy.com -> Keys" -ForegroundColor Gray
            Write-Host "    2. Create a Production key (not OTE/test)" -ForegroundColor Gray
            Write-Host "    3. Copy both the Key and Secret - Secret is only shown once" -ForegroundColor Yellow
            Write-Host ""
            $key    = Read-Host "  GoDaddy API Key"
            $secret = Read-Host "  GoDaddy API Secret" -AsSecureString
            return @{ GDKey = $key; GDSecret = $secret }
        }
        'route53' {
            Write-Host "  AWS Route53 credentials required (IAM user with Route53 permissions)." -ForegroundColor White
            Write-Host ""
            Write-Host "  How to get them:" -ForegroundColor Gray
            Write-Host "    1. In AWS Console, go to IAM -> Users -> Create user" -ForegroundColor Gray
            Write-Host "    2. Attach the 'AmazonRoute53FullAccess' policy (or a custom scoped policy)" -ForegroundColor Gray
            Write-Host "    3. Go to the user -> Security credentials -> Create access key" -ForegroundColor Gray
            Write-Host "    4. Copy the Access Key ID and Secret Access Key" -ForegroundColor Yellow
            Write-Host ""
            $accessKey = Read-Host "  AWS Access Key ID"
            $secretKey = Read-Host "  AWS Secret Access Key" -AsSecureString
            return @{ R53AccessKey = $accessKey; R53SecretKey = $secretKey }
        }
        'azuredns' {
            Write-Host "  Azure DNS credentials required (Service Principal with DNS Zone Contributor role)." -ForegroundColor White
            Write-Host ""
            Write-Host "  How to get them:" -ForegroundColor Gray
            Write-Host "    1. In Azure Portal, go to Azure Active Directory -> App registrations -> New registration" -ForegroundColor Gray
            Write-Host "    2. Note the Application (client) ID and Directory (tenant) ID" -ForegroundColor Gray
            Write-Host "    3. Under Certificates and secrets, create a new client secret - copy it now" -ForegroundColor Gray
            Write-Host "    4. Go to your DNS Zone -> Access control (IAM) -> Add role assignment" -ForegroundColor Gray
            Write-Host "    5. Assign 'DNS Zone Contributor' to the app registration you created" -ForegroundColor Gray
            Write-Host "    6. Also need your Azure Subscription ID (found in Subscriptions)" -ForegroundColor Gray
            Write-Host ""
            $subId    = Read-Host "  Azure Subscription ID"
            $tenantId = Read-Host "  Azure Tenant (Directory) ID"
            $appId    = Read-Host "  App Registration Client ID"
            $secret   = Read-Host "  Client Secret" -AsSecureString
            return @{
                AZSubscriptionId         = $subId
                AZTenantId               = $tenantId
                AZAppUsername            = $appId
                AZAppPasswordCredential  = $secret
            }
        }
        'namecheap' {
            Write-Host "  Namecheap API credentials required." -ForegroundColor White
            Write-Host ""
            Write-Host "  How to get them:" -ForegroundColor Gray
            Write-Host "    1. Log in at namecheap.com -> Profile -> Tools" -ForegroundColor Gray
            Write-Host "    2. Scroll to 'Business and Dev Tools' -> Enable API access" -ForegroundColor Gray
            Write-Host "    3. Whitelist this server's public IP address in the API section" -ForegroundColor Yellow
            Write-Host "    4. Your API key is shown on that same page" -ForegroundColor Gray
            Write-Host ""
            $username = Read-Host "  Namecheap username"
            $apiKey   = Read-Host "  Namecheap API key" -AsSecureString
            return @{ NCUsername = $username; NCApiKey = $apiKey }
        }
        default {
            Write-Host "  Plugin '$Plugin' requires credentials." -ForegroundColor White
            Write-Host "  Run 'Get-PAPlugin $Plugin -Param' in PowerShell to see required parameters." -ForegroundColor Gray
            Write-Host "  You will be prompted for individual values by Posh-ACME during certificate issuance." -ForegroundColor Gray
            Write-Host ""
            return $null  # Let Posh-ACME prompt natively
        }
    }
}

function Build-DnsChallengeParams {
    param([string[]]$Domains)

    Write-Log "Using DNS-01 challenge with plugin: $($script:DnsPlugin)"

    # Validate the plugin exists in Posh-ACME (only in interactive mode to avoid overhead on scheduled runs)
    if ($script:isInteractive) {
        $availablePlugins = $null
        try {
            $availablePlugins = Get-PAPlugin -ErrorAction Stop
        }
        catch {
            Write-Log "Could not enumerate DNS plugins (non-fatal, will attempt to use '$($script:DnsPlugin)' directly)" -Level Warning
        }
        if ($availablePlugins -and $script:DnsPlugin -notin $availablePlugins.Name) {
            $pluginList = ($availablePlugins.Name | Sort-Object) -join ', '
            throw "DNS plugin '$($script:DnsPlugin)' not found. Available plugins: $pluginList"
        }
    }

    # Resolve plugin credentials:
    #   1. Use args passed on the command line
    #   2. If interactive (menu-driven run), prompt the user with provider instructions
    #   3. If non-interactive (scheduled task), load from the DPAPI-encrypted credential store
    $resolvedPluginArgs = $script:DnsPluginArgs
    if (-not $resolvedPluginArgs) {
        if ($script:isInteractive) {
            $resolvedPluginArgs = Get-DnsPluginArgsInteractive -Plugin $script:DnsPlugin
        }
        else {
            $resolvedPluginArgs = Get-PluginCredentials
            if (-not $resolvedPluginArgs) {
                throw "No DNS plugin credentials found. Run the script interactively with -InstallScheduledTask to save credentials for unattended renewal."
            }
        }
    }

    # Persist back to script scope so Install-RenewalTask can save them
    if ($resolvedPluginArgs) {
        $script:DnsPluginArgs = $resolvedPluginArgs
    }

    $certParams = @{
        Domain     = $Domains
        AcceptTOS  = $true
        Contact    = $ContactEmail
        Plugin     = $script:DnsPlugin
        Force      = $ForceRenewal.IsPresent
        DnsSleep   = $DnsSleep
        Verbose    = $false
    }

    if ($resolvedPluginArgs) {
        $certParams['PluginArgs'] = $resolvedPluginArgs
    }

    return $certParams
}

function Build-DnsManualChallengeParams {
    param([string[]]$Domains)

    Write-Log "Using DNS-01 manual challenge mode"
    Write-Log "You will need to create DNS TXT records when prompted" -Level Warning

    return @{
        Domain     = $Domains
        AcceptTOS  = $true
        Contact    = $ContactEmail
        Plugin     = 'Manual'
        PluginArgs = @{ ManualNonInteractive = $false }
        Force      = $ForceRenewal.IsPresent
        DnsSleep   = $DnsSleep
        Verbose    = $false
    }
}

function Remove-StaleAcmeOrder {
    param([string[]]$Domains)

    $mainDomain = $Domains[0]
    Write-Log "Removing stale ACME order for: $mainDomain" -Level Info

    # Posh-ACME 4.x provides Remove-PAOrder
    try {
        if (Get-Command Remove-PAOrder -ErrorAction SilentlyContinue) {
            Remove-PAOrder -MainDomain $mainDomain -Force -ErrorAction Stop
            Write-Log "Stale order removed via Remove-PAOrder" -Level Info
            return
        }
    }
    catch {
        Write-Log "Remove-PAOrder failed ($($_.Exception.Message)) - falling back to filesystem cleanup" -Level Warning
    }

    # Fallback: find and delete the order.json + directory from Posh-ACME's data store
    $acmeHome = if ($env:POSH_ACME_HOME) { $env:POSH_ACME_HOME } else {
        Join-Path $env:ProgramData 'Posh-ACME'
    }
    if (-not (Test-Path $acmeHome)) { return }

    Get-ChildItem -Path $acmeHome -Recurse -Filter 'order.json' -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $orderData = Get-Content $_.FullName -Raw | ConvertFrom-Json
                if ($orderData.MainDomain -eq $mainDomain) {
                    Remove-Item -Path $_.DirectoryName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed stale order directory: $($_.DirectoryName)" -Level Info
                }
            }
            catch { }
        }
}

function Add-ChallengeToMatchingSites {
    param(
        [string[]]$Domains,
        [string]$ChallengePath
    )

    $sites = Get-ChildItem "IIS:\Sites" -ErrorAction SilentlyContinue
    $matchedSites = @()
    foreach ($site in $sites) {
        $bindings = Get-WebBinding -Name $site.Name -ErrorAction SilentlyContinue
        foreach ($binding in $bindings) {
            $bindingInfo = $binding.bindingInformation
            $hostHeader = ($bindingInfo -split ':')[-1]
            if ($hostHeader -in $Domains -or [string]::IsNullOrEmpty($hostHeader)) {
                if ($site.Name -notin $matchedSites) {
                    $matchedSites += $site.Name
                    Add-ChallengeVirtualDirectory -SiteName $site.Name -ChallengePath $ChallengePath
                }
            }
        }
    }

    if ($matchedSites.Count -eq 0) {
        Write-Log "No IIS sites found with bindings matching the requested domains. Adding challenge directory to Default Web Site." -Level Warning
        if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) {
            Add-ChallengeVirtualDirectory -SiteName "Default Web Site" -ChallengePath $ChallengePath
            $matchedSites += "Default Web Site"
        }
        else {
            throw "No suitable IIS site found to serve ACME challenges. Create a site with an HTTP binding for $($Domains[0]) first."
        }
    }

    return $matchedSites
}

function Import-CertificateToStore {
    param($PACertificate)

    Write-Log "Importing certificate to store: $($script:CertStorePath)"

    $pfxPath = $PACertificate.PfxFullChain
    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
        $pfxPath = $PACertificate.PfxFile
    }

    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
        throw "PFX file not found in Posh-ACME output. Certificate may not have been issued."
    }

    # Posh-ACME uses an empty string as default PFX password
    $pfxPass = $PACertificate.PfxPass
    if ([string]::IsNullOrEmpty($pfxPass)) {
        $pfxPass = "poshacme"
    }
    $securePass = ConvertTo-SecureString -String $pfxPass -Force -AsPlainText

    # Import to the target certificate store
    $importedCert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $script:CertStorePath -Password $securePass -Exportable

    Write-Log "Certificate imported: Thumbprint=$($importedCert.Thumbprint)" -Level Success
    return $importedCert
}

function Export-PfxToFolder {
    param($PACertificate)

    Write-Log "Exporting certificate as PFX to: $PfxOutputPath"

    # Locate the PFX file from Posh-ACME output
    $pfxPath = $PACertificate.PfxFullChain
    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
        $pfxPath = $PACertificate.PfxFile
    }
    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
        throw "PFX file not found in Posh-ACME output. Certificate may not have been issued."
    }

    # Build output file names
    $safeDomain = $DomainName -replace '\*', 'wildcard' -replace '[^a-zA-Z0-9\-\.]', '_'
    $timestamp = Get-Date -Format 'yyyyMMdd'
    $pfxFileName = "${safeDomain}_${timestamp}.pfx"
    $destPfx = Join-Path $PfxOutputPath $pfxFileName

    # Copy the PFX file
    Copy-Item -Path $pfxPath -Destination $destPfx -Force
    Write-Log "PFX file exported: $destPfx" -Level Success

    # Also copy the individual cert and key files if available
    $certFile = $PACertificate.CertFile
    $keyFile = $PACertificate.KeyFile
    $chainFile = $PACertificate.ChainFile

    if ($certFile -and (Test-Path $certFile)) {
        $destCert = Join-Path $PfxOutputPath "${safeDomain}_${timestamp}.cer"
        Copy-Item -Path $certFile -Destination $destCert -Force
        Write-Log "Certificate file exported: $destCert" -Level Success
    }
    if ($keyFile -and (Test-Path $keyFile)) {
        $destKey = Join-Path $PfxOutputPath "${safeDomain}_${timestamp}.key"
        Copy-Item -Path $keyFile -Destination $destKey -Force
        Write-Log "Private key file exported: $destKey" -Level Success
    }
    if ($chainFile -and (Test-Path $chainFile)) {
        $destChain = Join-Path $PfxOutputPath "${safeDomain}_${timestamp}_chain.cer"
        Copy-Item -Path $chainFile -Destination $destChain -Force
        Write-Log "Chain file exported: $destChain" -Level Success
    }

    # Remove old password files for this domain before writing the new one
    Get-ChildItem -Path $PfxOutputPath -Filter "${safeDomain}_*_password.txt" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "${safeDomain}_${timestamp}_password.txt" } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # Save the PFX password to a file
    $pfxPass = $PACertificate.PfxPass
    if ($pfxPass -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxPass)
        try   { $pfxPass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    if ([string]::IsNullOrEmpty($pfxPass)) {
        $pfxPass = "poshacme"
    }
    $passFile = Join-Path $PfxOutputPath "${safeDomain}_${timestamp}_password.txt"
    $pfxPass | Set-Content -Path $passFile -Encoding UTF8
    Write-Log "PFX password saved: $passFile" -Level Info

    # Restrict password file permissions to Administrators only
    $acl = Get-Acl $passFile
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $passFile -AclObject $acl
    Write-Log "Password file permissions restricted to Administrators and SYSTEM" -Level Info

    return $destPfx
}

# ============================================================================
# IIS BINDING MANAGEMENT
# ============================================================================

function Update-IISBindings {
    param(
        [string]$NewThumbprint,
        [string]$OldThumbprint,
        [string[]]$Domains
    )

    Write-Log "Updating IIS bindings..."

    $sites = Get-ChildItem "IIS:\Sites"
    $updatedCount = 0

    foreach ($site in $sites) {
        $bindings = Get-WebBinding -Name $site.Name -Protocol "https" -ErrorAction SilentlyContinue

        foreach ($binding in $bindings) {
            $bindingInfo = $binding.bindingInformation
            $hostHeader = ($bindingInfo -split ':')[-1]
            $shouldUpdate = $false

            # Update if the binding matches one of our domains
            if ($hostHeader -in $Domains) {
                $shouldUpdate = $true
            }

            # Also update if the binding is using the old certificate
            if ($OldThumbprint) {
                $sslBinding = Get-ChildItem "IIS:\SslBindings" -ErrorAction SilentlyContinue | Where-Object {
                    $_.Thumbprint -eq $OldThumbprint
                }
                if ($sslBinding) {
                    $shouldUpdate = $true
                }
            }

            if ($shouldUpdate) {
                try {
                    $binding.AddSslCertificate($NewThumbprint, $CertStorePath -replace 'Cert:\\LocalMachine\\', '')
                    $updatedCount++
                    Write-Log "Updated binding: $($site.Name) - $bindingInfo" -Level Success
                }
                catch {
                    Write-Log "Failed to update binding $($site.Name) - $bindingInfo : $_" -Level Error
                }
            }
        }
    }

    # Handle SSL bindings directly (IP-based bindings without host headers)
    if ($OldThumbprint) {
        $sslBindings = Get-ChildItem "IIS:\SslBindings" -ErrorAction SilentlyContinue | Where-Object {
            $_.Thumbprint -eq $OldThumbprint
        }
        foreach ($ssl in $sslBindings) {
            try {
                $ssl | Remove-Item -Force
                $ipPort = "$($ssl.IPAddress):$($ssl.Port)"
                New-Item -Path "IIS:\SslBindings\$ipPort" -Thumbprint $NewThumbprint -SSLFlags 0 -ErrorAction Stop | Out-Null
                $updatedCount++
                Write-Log "Updated SSL binding: $ipPort" -Level Success
            }
            catch {
                Write-Log "Failed to update SSL binding: $_" -Level Error
            }
        }
    }

    if ($updatedCount -eq 0) {
        Write-Log "No IIS bindings were updated. You may need to manually create HTTPS bindings for your sites." -Level Warning
        Write-Log "Use IIS Manager to add an HTTPS binding with the new certificate (Thumbprint: $NewThumbprint)" -Level Info
    }
    else {
        Write-Log "Updated $updatedCount IIS binding(s)" -Level Success
    }
}

function Remove-OldCertificate {
    param(
        [string]$OldThumbprint,
        [string]$NewThumbprint
    )

    if (-not $OldThumbprint -or $OldThumbprint -eq $NewThumbprint) { return }

    # Check if old cert is still bound to RD Gateway
    if ($script:OutputMode -eq 'RDGateway') {
        $gwCert = Get-RDGatewayCurrentCert
        if ($gwCert -and $gwCert.Thumbprint -eq $OldThumbprint) {
            Write-Log "Old cert $OldThumbprint is still bound to RD Gateway - keeping" -Level Warning
            return
        }
    }

    # Only remove old cert if it's no longer bound to any IIS site
    $stillInUse = $false
    if ($script:IISAvailable) {
        $stillInUse = Get-ChildItem "IIS:\SslBindings" -ErrorAction SilentlyContinue | Where-Object {
            $_.Thumbprint -eq $OldThumbprint
        }
    }

    if (-not $stillInUse) {
        $oldCert = Get-ChildItem $script:CertStorePath -ErrorAction SilentlyContinue | Where-Object {
            $_.Thumbprint -eq $OldThumbprint
        }
        if ($oldCert) {
            $oldCert | Remove-Item -Force
            Write-Log "Removed old certificate: $OldThumbprint" -Level Info
        }
    }
    else {
        Write-Log "Old certificate $OldThumbprint is still in use on other bindings, keeping it" -Level Warning
    }
}

function Remove-ExpiredLetsEncryptCerts {
    <#
    .SYNOPSIS
        Sweeps the Windows certificate stores for expired Let's Encrypt certificates
        that are no longer bound to any IIS site and removes them.
    .NOTES
        Searches both Cert:\LocalMachine\WebHosting and Cert:\LocalMachine\My.
        Any thumbprint currently assigned to an IIS SSL binding is always protected,
        even if the certificate itself has expired (belt-and-suspenders safety).
        Let's Encrypt certificates are identified by Issuer matching "Let.s Encrypt",
        which covers all current and historical LE intermediates (R3, R10, R11, E5,
        E6, and the legacy "Let's Encrypt Authority X3" series).
    #>
    param(
        # Additional thumbprints to protect regardless of expiry (e.g. cert just issued).
        [string[]]$ProtectThumbprints = @()
    )

    Write-Log "Scanning for expired Let's Encrypt certificates to clean up..."

    # Collect thumbprints currently assigned to IIS SSL bindings (must not remove these).
    $activeThumbs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    if ($script:IISAvailable) {
        $bindings = Get-ChildItem "IIS:\SslBindings" -ErrorAction SilentlyContinue
        foreach ($b in $bindings) {
            if ($b.Thumbprint) { [void]$activeThumbs.Add($b.Thumbprint) }
        }
    }

    # Also protect any caller-supplied thumbprints.
    foreach ($t in $ProtectThumbprints) {
        if ($t) { [void]$activeThumbs.Add($t) }
    }

    # Sweep both stores - certs may accumulate in either depending on deployment history.
    $stores = @('Cert:\LocalMachine\WebHosting', 'Cert:\LocalMachine\My')
    $now    = Get-Date
    $removed = 0
    $skipped = 0

    foreach ($store in $stores) {
        if (-not (Test-Path $store -ErrorAction SilentlyContinue)) { continue }

        $expired = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object {
            $_.Issuer -match "Let.s Encrypt" -and $_.NotAfter -lt $now
        }

        foreach ($cert in $expired) {
            if ($activeThumbs.Contains($cert.Thumbprint)) {
                # Expired but still bound - leave it; IIS would break without it.
                $msg = "Skipping expired LE cert still in active IIS binding: $($cert.Thumbprint) | Subject: $($cert.Subject) | Expired: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
                Write-Log $msg -Level Warning
                $skipped++
                continue
            }

            try {
                $cert | Remove-Item -Force -ErrorAction Stop
                $msg = "Removed expired LE cert: $($cert.Thumbprint) | Subject: $($cert.Subject) | Expired: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
                Write-Log $msg -Level Info
                $removed++
            }
            catch {
                Write-Log "Could not remove expired LE cert $($cert.Thumbprint): $($_.Exception.Message)" -Level Warning
            }
        }
    }

    if ($removed -gt 0 -or $skipped -gt 0) {
        $level = if ($removed -gt 0) { 'Success' } else { 'Info' }
        Write-Log "Expired LE cert cleanup: $removed removed, $skipped skipped (still bound)" -Level $level
    }
    else {
        Write-Log "No expired Let's Encrypt certificates found in store"
    }
}

# ============================================================================
# SCHEDULED TASK MANAGEMENT
# ============================================================================

function Install-RenewalTask {
    Write-Log "Installing scheduled task: $TaskName"

    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        throw "Cannot determine script path for scheduled task. Run the script from a file, not interactively."
    }

    # Build the argument list (mirror current parameters, minus the task switches)
    $argParts = @(
        "-NoProfile"
        "-ExecutionPolicy Bypass"
        "-File `"$scriptPath`""
        "-DomainName `"$DomainName`""
        "-ContactEmail `"$ContactEmail`""
        "-RenewalDays $RenewalDays"
    )
    if ($AdditionalDomains) {
        $domainList = ($AdditionalDomains | ForEach-Object { "`"$_`"" }) -join ','
        $argParts += "-AdditionalDomains @($domainList)"
    }
    if ($ChallengeType -ne 'Http') {
        $argParts += "-ChallengeType $ChallengeType"
    }
    if ($script:DnsPlugin) {
        $argParts += "-DnsPlugin `"$($script:DnsPlugin)`""
    }
    if ($DnsSleep -ne 120) {
        $argParts += "-DnsSleep $DnsSleep"
    }
    if ($PfxOutputPath) {
        $argParts += "-PfxOutputPath `"$PfxOutputPath`""
    }
    # Persist the chosen deployment mode so the scheduled task uses the same target
    $argParts += "-DeployMode $script:OutputMode"

    # WatchGuard connection parameters (credentials are in DPAPI-encrypted firebox_creds.json)
    if ($script:OutputMode -eq 'WatchGuard') {
        if ($script:FireboxHost)                   { $argParts += "-FireboxHost `"$script:FireboxHost`"" }
        if ($script:FireboxSshPort -ne 4118)       { $argParts += "-FireboxSshPort $script:FireboxSshPort" }
        if ($script:FireboxLocalIP)                { $argParts += "-FireboxLocalIP `"$script:FireboxLocalIP`"" }
        if ($script:FireboxFtpPort -ne 2121)       { $argParts += "-FireboxFtpPort $script:FireboxFtpPort" }
    }

    if ($Staging) { $argParts += "-Staging" }
    if ($script:CertStorePath -ne "Cert:\LocalMachine\WebHosting") {
        $argParts += "-CertStorePath `"$($script:CertStorePath)`""
    }

    # Warn about DnsManual mode with scheduled tasks
    if ($script:ChallengeType -eq 'DnsManual') {
        Write-Log "WARNING: DnsManual challenge type requires interactive input and is NOT compatible with scheduled tasks!" -Level Warning
        Write-Log "Consider switching to -ChallengeType Dns with a -DnsPlugin for automated renewals" -Level Warning
    }

    # DNS plugin credentials are saved to a DPAPI/LocalMachine-encrypted file during cert
    # issuance and loaded automatically by the scheduled task (running as SYSTEM).
    if ($script:DnsPlugin) {
        $credFile = Join-Path $LogDir "plugin_creds.json"
        if (Test-Path $credFile) {
            Write-Log "DNS plugin credentials on file: $credFile (DPAPI/LocalMachine encrypted)" -Level Info
        }
        else {
            Write-Log "WARNING: No saved DNS plugin credentials found. The scheduled task will fail on renewal unless credentials are saved first by running this script interactively." -Level Warning
        }
    }

    # WatchGuard SSH credentials are saved to a DPAPI/LocalMachine-encrypted file.
    if ($script:OutputMode -eq 'WatchGuard') {
        $fbCredFile = Join-Path $LogDir "firebox_creds.json"
        if (Test-Path $fbCredFile) {
            Write-Log "Firebox credentials on file: $fbCredFile (DPAPI/LocalMachine encrypted)" -Level Info
        }
        else {
            Write-Log "WARNING: No saved Firebox credentials found. The scheduled task will fail unless credentials are saved first by running this script interactively." -Level Warning
        }
    }

    # Email reporting
    if ($script:SendReport) {
        $argParts += "-SendReport"
        $emailCfgFile = Join-Path $LogDir "email_config.json"
        if (Test-Path $emailCfgFile) {
            $emailCfg = Get-EmailConfig
            Write-Log "Email reporting on file: $emailCfgFile ($($emailCfg.Method) -> $($emailCfg.Recipient))" -Level Info
        }
        else {
            Write-Log "WARNING: -SendReport specified but no email_config.json found. Configure email reporting interactively first." -Level Warning
        }
    }
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument ($argParts -join ' ')

    $trigger = New-ScheduledTaskTrigger -Daily -At $TaskTime

    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -DontStopOnIdleEnd `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 15) `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1)

    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # Remove existing task if present
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Removed existing scheduled task"
    }

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Automatically renews Let's Encrypt certificate for $DomainName. Managed by Yeyland Wutani LLC." `
        -Force | Out-Null

    Write-Log "Scheduled task installed: runs daily at $TaskTime as SYSTEM" -Level Success
}

function Uninstall-RenewalTask {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Scheduled task removed: $TaskName" -Level Success
    }
    else {
        Write-Log "Scheduled task not found: $TaskName" -Level Warning
    }
}

# ============================================================================
# LOG MAINTENANCE
# ============================================================================

function Remove-OldLogs {
    $maxLogAge = 90
    $cutoff = (Get-Date).AddDays(-$maxLogAge)
    $oldLogs = Get-ChildItem -Path $LogDir -Filter "renewal_*.log" -ErrorAction SilentlyContinue |
        Where-Object {
            if ($_.Name -match 'renewal_(\d{8})_') {
                try {
                    [datetime]::ParseExact($Matches[1], 'yyyyMMdd', $null) -lt $cutoff
                } catch { $false }
            } else {
                $_.CreationTime -lt $cutoff
            }
        }

    foreach ($log in $oldLogs) {
        Remove-Item $log.FullName -Force -ErrorAction SilentlyContinue
    }

    if ($oldLogs.Count -gt 0) {
        Write-Log "Cleaned up $($oldLogs.Count) old log file(s)"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Enter-RenewalLock {
    if (Test-Path $lockFile) {
        $lockAge = (Get-Date) - (Get-Item $lockFile).LastWriteTime
        if ($lockAge.TotalHours -lt 2) {
            throw "Another renewal process is running (lock file age: $($lockAge.TotalMinutes.ToString('0')) min). Remove $lockFile manually if this is stale."
        }
        Write-Log "Stale lock file found (age: $($lockAge.TotalHours.ToString('0.0'))h) - removing" -Level Warning
    }
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    Set-Content -Path $lockFile -Value "$PID $(Get-Date -Format 'o')" -Force
}

function Exit-RenewalLock {
    Remove-Item -Path $lockFile -Force -ErrorAction SilentlyContinue
}

try {
    Write-Banner

    # Handle scheduled task removal (direct parameter mode)
    if ($RemoveScheduledTask) {
        $script:ReportData.Status = 'None'
        Uninstall-RenewalTask
        return
    }

    # Acquire lock to prevent concurrent runs
    Enter-RenewalLock

    # Track whether we should install the scheduled task
    $shouldInstallTask = $InstallScheduledTask.IsPresent

    # Determine if we're running interactively (no task switches pre-selected)
    $script:isInteractive = -not $shouldInstallTask -and [Environment]::UserInteractive
    $isInteractive = $script:isInteractive

    # Show interactive menu when running interactively without task flags
    if ($isInteractive -and -not $RemoveScheduledTask) {
        $menuChoice = Show-InteractiveMenu

        switch ($menuChoice) {
            '1' {
                # One-shot: proceed with renewal, no scheduled task
                Write-Log "Mode: One-time certificate request/renewal"
            }
            '2' {
                # Renew + install scheduled task
                $shouldInstallTask = $true
                Write-Log "Mode: Request/renewal + scheduled task installation"
            }
            '3' {
                Uninstall-RenewalTask
                return
            }
            '4' {
                # Update existing scheduled task: recollect credentials / reconfigure, no cert order
                $shouldInstallTask = $true
                $script:SkipCertOrder = $true
                Write-Log "Mode: Update existing scheduled task (credentials / configuration refresh)"

                $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                if ($existing) {
                    Write-Host ""
                    Write-Host "  Found existing task: $TaskName" -ForegroundColor Green
                    Write-Host "  Current action: $($existing.Actions[0].Arguments)" -ForegroundColor Gray
                    Write-Host ""
                }
                else {
                    Write-Host ""
                    Write-Host "  No existing task found for: $TaskName" -ForegroundColor Yellow
                    Write-Host "  A new scheduled task will be created." -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            '5' {
                $script:ReportData.Status = 'None'
                Write-Host "  Exiting." -ForegroundColor Gray
                return
            }
        }
    }

    # Ask about certificate output (IIS import vs PFX export)
    Show-CertificateOutputMenu

    # Ask about challenge type (HTTP-01, DNS-01, or DNS manual)
    Show-ChallengeTypeMenu

    # Ask about email reporting (interactive only; non-interactive uses -SendReport flag + saved config)
    Show-EmailReportMenu

    # Sync script-scoped variables back to local scope after all interactive decisions
    $ChallengeType = $script:ChallengeType
    $DnsPlugin     = $script:DnsPlugin
    $DnsPluginArgs = $script:DnsPluginArgs
    $PfxOutputPath = $script:PfxOutputPath
    $CertStorePath = $script:CertStorePath

    # Capture final output mode for report
    $script:ReportData.Mode = $script:OutputMode

    # Show run summary
    Write-Host ""
    Write-Host "  -----------------------------------------------------------" -ForegroundColor Gray
    Write-Host "  Domain:    $DomainName" -ForegroundColor White
    Write-Host "  Mode:      $(if ($Staging) { 'STAGING (test)' } else { 'PRODUCTION' })" -ForegroundColor White
    Write-Host "  Challenge: $(switch ($script:ChallengeType) { 'Http' { 'HTTP-01 (IIS webroot)' } 'Dns' { "DNS-01 (plugin: $($script:DnsPlugin))" } 'DnsManual' { 'DNS-01 (manual TXT record)' } })" -ForegroundColor White
    Write-Host "  Output:    $(switch ($script:OutputMode) { 'PFX' { "PFX export to $($script:PfxOutputPath)" } 'RDGateway' { 'RD Gateway (TSGateway) certificate binding' } 'WatchGuard' { "WatchGuard Firebox $($script:FireboxHost):$($script:FireboxSshPort) (web-server-cert)" } default { 'IIS cert store + binding update' } })" -ForegroundColor White
    Write-Host "  Threshold: $RenewalDays days before expiry" -ForegroundColor White
    Write-Host "  -----------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""

    # Build the full domain list
    $allDomains = @($DomainName)
    if ($AdditionalDomains) {
        $allDomains += $AdditionalDomains
    }
    Write-Log "Target domains: $($allDomains -join ', ')"

    # Run prerequisite checks
    Test-Prerequisites

    # Confirm production issuance interactively (rate limits apply)
    if ($script:isInteractive -and -not $Staging -and -not $script:SkipCertOrder) {
        Write-Host ""
        $confirm = Read-Host "  Issue a PRODUCTION certificate for $($allDomains -join ', ')? [y/N]"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "  Aborted." -ForegroundColor Yellow
            $script:ReportData.Status = 'None'
            return
        }
    }

    # Install Posh-ACME if needed
    Install-PoshAcmeModule

    # ---- WatchGuard: install Posh-SSH and collect/save SSH credentials ----
    if ($script:OutputMode -eq 'WatchGuard') {
        Install-PoshSshModule

        if ($script:isInteractive) {
            $script:WgCredential = Get-FireboxCredentialsInteractive
            # Save credentials to DPAPI-encrypted file for scheduled-task use
            Save-FireboxCredentials -Credential $script:WgCredential
        }
        else {
            $script:WgCredential = Get-FireboxCredentials
            if (-not $script:WgCredential) {
                throw "No saved Firebox credentials found. Run this script interactively once (menu option 1, 2, or 4) to save credentials for unattended renewal."
            }
        }
    }

    # ---- Update-task-only mode: skip cert order, just save config and reinstall task ----
    if ($script:SkipCertOrder) {
        Write-Log "Update task mode: skipping certificate order, reinstalling task only" -Level Info

        $script:ReportData.Status  = 'Updated'
        $script:ReportData.Message = "Scheduled task configuration refreshed. No certificate order was performed."
        if ($shouldInstallTask) { Install-RenewalTask }

        Write-Host ""
        Write-Host "  ============================================================" -ForegroundColor Green
        Write-Host "  Scheduled task updated successfully!" -ForegroundColor Green
        if ($script:OutputMode -eq 'WatchGuard') {
            Write-Host "  Firebox:    $($script:FireboxHost):$($script:FireboxSshPort)" -ForegroundColor Green
            Write-Host "  Credentials saved (DPAPI/LocalMachine encrypted)" -ForegroundColor Green
        }
        Write-Host "  Task name:  $TaskName" -ForegroundColor Green
        Write-Host "  ============================================================" -ForegroundColor Green
        Write-Host ""
        return
    }

    # Clean old logs
    Remove-OldLogs

    # Sweep expired Let's Encrypt certificates from the Windows certificate store.
    # Only runs after an actual renewal, or once a week to avoid unnecessary overhead.
    $lastSweepFile = Join-Path $LogDir ".last_cert_sweep"
    $shouldSweep = $false
    if (-not (Test-Path $lastSweepFile)) {
        $shouldSweep = $true
    } else {
        $lastSweep = (Get-Item $lastSweepFile).LastWriteTime
        $shouldSweep = ((Get-Date) - $lastSweep).TotalDays -ge 7
    }

    # Determine if the current certificate needs renewal (this may set $shouldSweep below).
    # IIS / RDGateway:  check the Windows certificate store.
    # WatchGuard / PFX: check the Posh-ACME local cert cache (shared system path set by
    #                   Install-PoshAcmeModule) so the renewal threshold is respected
    #                   even when the cert is not imported into the Windows store.
    $currentCert = $null
    $oldThumbprint = $null
    if ($script:OutputMode -in @('IIS', 'RDGateway')) {
        $currentCert = Get-CurrentCertificate -Domains $allDomains
        $oldThumbprint = if ($currentCert) { $currentCert.Thumbprint } else { $null }
    }
    else {
        # WatchGuard / PFX: load the cert from Posh-ACME's shared cache so that
        # Test-CertificateNeedsRenewal can decide whether to skip this run.
        # Set-PAServer is safe to call here (idempotent); it will be called again
        # inside Invoke-AcmeCertificateOrder if renewal proceeds.
        try {
            $paServer = if ($Staging) { "LE_STAGE" } else { "LE_PROD" }
            $null = Set-PAServer $paServer -ErrorAction Stop
            $paCached = Get-PACertificate -MainDomain $DomainName -ErrorAction SilentlyContinue
            if ($paCached -and $paCached.CertFile -and (Test-Path $paCached.CertFile -ErrorAction SilentlyContinue)) {
                $currentCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($paCached.CertFile)
                Write-Log "Posh-ACME cached cert: Subject=$($currentCert.Subject), Expires=$($currentCert.NotAfter.ToString('yyyy-MM-dd')), Thumbprint=$($currentCert.Thumbprint)"
            }
            else {
                Write-Log "No cached Posh-ACME certificate found for $DomainName - will request a new one" -Level Info
            }
        }
        catch {
            Write-Log "Could not read Posh-ACME cert cache: $($_.Exception.Message). Proceeding with renewal." -Level Warning
        }
    }

    # Decide whether to renew
    $needsRenewal = $ForceRenewal -or (Test-CertificateNeedsRenewal -Certificate $currentCert)

    if (-not $needsRenewal) {
        Write-Log "Certificate is still valid and outside the renewal window. No action needed." -Level Success

        # Run periodic cert sweep even when no renewal is needed
        if ($shouldSweep) {
            Remove-ExpiredLetsEncryptCerts
            Set-Content -Path $lastSweepFile -Value (Get-Date -Format 'o')
        }

        $script:ReportData.Status = 'Skipped'
        if ($currentCert) {
            $script:ReportData.CurrentExpiry = $currentCert.NotAfter.ToString('yyyy-MM-dd')
            $script:ReportData.Thumbprint    = $currentCert.Thumbprint
            $script:ReportData.Message = "Certificate is still valid. Expires $($currentCert.NotAfter.ToString('yyyy-MM-dd')). Renewal threshold: $RenewalDays days."
        }

        if ($shouldInstallTask) { Install-RenewalTask }

        Write-Host ""
        Write-Host "  No renewal needed. Certificate expires $($currentCert.NotAfter)" -ForegroundColor Green
        Write-Host ""
        return
    }

    # Always sweep after a renewal
    $shouldSweep = $true

    # Perform the certificate order/renewal
    if ($PSCmdlet.ShouldProcess($DomainName, "Request/renew Let's Encrypt certificate")) {
        $paCert = Invoke-AcmeCertificateOrder -Domains $allDomains

        # Sweep expired LE certs after successful renewal
        if ($shouldSweep) {
            $protectThumbs = @($paCert.Thumbprint)
            Remove-ExpiredLetsEncryptCerts -ProtectThumbprints $protectThumbs
            Set-Content -Path $lastSweepFile -Value (Get-Date -Format 'o')
        }

        $stagingNote = if ($Staging) {
            "`n  NOTE: This is a STAGING certificate (not browser-trusted).`n  Run again without -Staging for a production certificate."
        } else { '' }

        switch ($script:OutputMode) {

            'PFX' {
                $exportedPfx = Export-PfxToFolder -PACertificate $paCert

                $script:ReportData.Status    = 'Success'
                $script:ReportData.NewExpiry = $paCert.NotAfter.ToString('yyyy-MM-dd')
                $script:ReportData.Message   = "PFX exported to $exportedPfx"

                if ($shouldInstallTask) { Install-RenewalTask }

                Write-Host ""
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host "  Certificate issued and exported!" -ForegroundColor Green
                Write-Host "  PFX File:   $exportedPfx" -ForegroundColor Green
                Write-Host "  Expires:    $($paCert.NotAfter)" -ForegroundColor Green
                Write-Host "  Output Dir: $PfxOutputPath" -ForegroundColor Green
                if ($stagingNote) { Write-Host $stagingNote -ForegroundColor Yellow }
                Write-Host ""
                Write-Host "  Import the PFX into your web server or load balancer." -ForegroundColor Cyan
                Write-Host "  Password is saved alongside the PFX file (restricted to Admins)." -ForegroundColor Cyan
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host ""
            }

            'RDGateway' {
                # Import cert to Cert:\LocalMachine\My (CertStorePath was set in menu)
                $newCert = Import-CertificateToStore -PACertificate $paCert

                # Bind to RD Gateway and restart TSGateway service
                Install-RDGatewayCertificate -Certificate $newCert

                # Remove old cert if it's no longer needed elsewhere
                Remove-OldCertificate -OldThumbprint $oldThumbprint -NewThumbprint $newCert.Thumbprint

                $script:ReportData.Status     = 'Success'
                $script:ReportData.NewExpiry  = $newCert.NotAfter.ToString('yyyy-MM-dd')
                $script:ReportData.Thumbprint = $newCert.Thumbprint
                $script:ReportData.Message    = "TSGateway service restarted. Active RD Gateway sessions were dropped."

                if ($shouldInstallTask) { Install-RenewalTask }

                Write-Host ""
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host "  RD Gateway certificate updated!" -ForegroundColor Green
                Write-Host "  Thumbprint: $($newCert.Thumbprint)" -ForegroundColor Green
                Write-Host "  Expires:    $($newCert.NotAfter)" -ForegroundColor Green
                Write-Host "  Store:      Cert:\LocalMachine\My" -ForegroundColor Green
                if ($stagingNote) { Write-Host $stagingNote -ForegroundColor Yellow }
                Write-Host ""
                Write-Host "  TSGateway service was restarted. Active RD Gateway sessions were dropped." -ForegroundColor Yellow
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host ""
            }

            'WatchGuard' {
                # Deploy the certificate to the Firebox via SSH + ephemeral FTP
                Deploy-WatchGuardCert -PACertificate $paCert -Credential $script:WgCredential

                $script:ReportData.Status    = 'Success'
                $script:ReportData.NewExpiry = $paCert.NotAfter.ToString('yyyy-MM-dd')
                $script:ReportData.Message   = "Deployed to WatchGuard Firebox $($script:FireboxHost). web-server-cert updated."

                if ($shouldInstallTask) { Install-RenewalTask }

                Write-Host ""
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host "  WatchGuard Firebox certificate deployment complete!" -ForegroundColor Green
                Write-Host "  Firebox:    $($script:FireboxHost):$($script:FireboxSshPort)" -ForegroundColor Green
                Write-Host "  Expires:    $($paCert.NotAfter)" -ForegroundColor Green
                if ($stagingNote) { Write-Host $stagingNote -ForegroundColor Yellow }
                Write-Host ""
                Write-Host "  The Firebox web-server-cert has been updated." -ForegroundColor Cyan
                Write-Host "  Browsers connecting to the Firebox Web UI will now trust the new cert." -ForegroundColor Cyan
                Write-Host "  NOTE: IKEv2 Mobile VPN cert requires manual update in the Web UI" -ForegroundColor Yellow
                Write-Host "        (Fireware v12.10+ does not support IKEv2 cert assignment via CLI)." -ForegroundColor Yellow
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host ""
            }

            default {
                # IIS path: import to store and update bindings
                $newCert = Import-CertificateToStore -PACertificate $paCert

                Update-IISBindings -NewThumbprint $newCert.Thumbprint -OldThumbprint $oldThumbprint -Domains $allDomains

                Remove-OldCertificate -OldThumbprint $oldThumbprint -NewThumbprint $newCert.Thumbprint

                $script:ReportData.Status     = 'Success'
                $script:ReportData.NewExpiry  = $newCert.NotAfter.ToString('yyyy-MM-dd')
                $script:ReportData.Thumbprint = $newCert.Thumbprint

                if ($shouldInstallTask) { Install-RenewalTask }

                Write-Host ""
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host "  Certificate renewal complete!" -ForegroundColor Green
                Write-Host "  Thumbprint: $($newCert.Thumbprint)" -ForegroundColor Green
                Write-Host "  Expires:    $($newCert.NotAfter)" -ForegroundColor Green
                if ($stagingNote) { Write-Host $stagingNote -ForegroundColor Yellow }
                Write-Host "  ============================================================" -ForegroundColor Green
                Write-Host ""
            }
        }

        Write-Log "Renewal process completed successfully" -Level Success
        Write-Log "Log file: $LogFile"
    }
}
catch {
    Exit-RenewalLock
    $script:ReportData.Status  = 'Failed'
    $script:ReportData.Message = $_.Exception.Message

    Write-Log "FATAL: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Write-Log "Full log: $LogFile" -Level Error
    throw
}
finally {
    Exit-RenewalLock
    # Send renewal report on action-worthy exits only: Success, Failed, Updated.
    # 'Skipped' (cert not yet due) fires on every daily task run and would be very chatty.
    # 'None' means an early exit (remove task, exit menu) where no report is warranted.
    $reportableStatuses = @('Success', 'Failed', 'Updated')
    if ($script:SendReport -and $script:ReportData.Status -in $reportableStatuses -and -not $script:ReportSent) {
        try {
            Send-RenewalReport
        }
        catch {
            Write-Log "Report send failed in finally block: $($_.Exception.Message)" -Level Warning
        }
    }
}
