#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Automated Let's Encrypt Certificate Renewal v1.3

.DESCRIPTION
    Automates the full Let's Encrypt certificate lifecycle using the ACME protocol
    via the Posh-ACME module. Designed for MSP environments where customers are
    transitioning to 90-day (and soon 47-day) certificate renewals.

    When run interactively, presents a menu to choose between one-time issuance,
    scheduled auto-renewal, or task removal. Works with or without IIS - when IIS
    is present, you choose whether to import to IIS or export as PFX.

    Capabilities:
    - Interactive menu for guided one-shot or scheduled operation
    - New certificate issuance via HTTP-01 or DNS-01 challenge validation
    - Automatic IIS challenge response configuration (HTTP-01)
    - DNS-01 validation via 30+ providers (Azure, Cloudflare, GoDaddy, Route53, etc.)
    - Manual DNS mode for providers without API integration
    - Wildcard certificate support (requires DNS-01)
    - PFX export mode for non-IIS servers (Apache, nginx, load balancers)
    - Certificate renewal when approaching expiry threshold
    - Automatic IIS binding updates (when IIS output mode is selected)
    - Scheduled task installation for fully unattended operation
    - Let's Encrypt staging environment support for testing
    - Multi-domain (SAN) certificate support
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
    Run 'Get-PAPlugin -List' after installing Posh-ACME to see all available plugins.
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
    Version: 1.3.0

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
    [string]$CertStorePath = "Cert:\LocalMachine\WebHosting",

    [Parameter(ParameterSetName = 'RemoveTask')]
    [switch]$RemoveScheduledTask
)

$ErrorActionPreference = "Stop"
$ScriptVersion = "1.3.0"
$TaskName = "LetsEncrypt Certificate Renewal - $DomainName"
$LogDir = Join-Path $env:ProgramData "YeylandWutani\LetsEncrypt"
$LogFile = Join-Path $LogDir "renewal_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
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
    # Check IIS via Windows Feature
    $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
    if ($iisFeature -and $iisFeature.InstallState -eq 'Installed') { return $true }

    # Fallback: check W3SVC service (works on workstation OS)
    $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($w3svc) { return $true }

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
    Write-Host "  [4] Exit" -ForegroundColor Cyan
    Write-Host ""

    do {
        $choice = Read-Host "  Select option [1-4]"
    } while ($choice -notin @('1', '2', '3', '4'))

    return $choice
}

function Show-CertificateOutputMenu {
    # Always ask about certificate output - IIS may be present but not the target
    $script:IISAvailable = Test-IISAvailable
    $iisLoaded = $false

    if ($script:IISAvailable) {
        # Try to load WebAdministration
        if (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            $iisLoaded = $true
        }
        else {
            Write-Log "WebAdministration module not found. IIS binding management will be unavailable." -Level Warning
            $script:IISAvailable = $false
        }
    }

    # If PfxOutputPath was already provided on the command line, skip the menu
    if ($PfxOutputPath) {
        Write-Log "Certificate output: PFX export to $PfxOutputPath" -Level Info
        return
    }

    Write-Host ""
    Write-Host "  How should the certificate be deployed?" -ForegroundColor White
    Write-Host ""
    if ($script:IISAvailable) {
        Write-Host "  [1] Import to IIS certificate store and update site bindings" -ForegroundColor Cyan
        Write-Host "  [2] Export as PFX file to a folder (for any web server / load balancer)" -ForegroundColor Cyan
    }
    else {
        Write-Host "  IIS is not installed on this server." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Export as PFX file to a folder (for any web server / load balancer)" -ForegroundColor Cyan
    }
    Write-Host ""

    if ($script:IISAvailable) {
        do {
            $outputChoice = Read-Host "  Select output [1-2]"
        } while ($outputChoice -notin @('1', '2'))

        if ($outputChoice -eq '2') {
            $script:PfxOutputPath = Read-Host "  Enter folder path to export PFX to (e.g. C:\Certs)"
            if ([string]::IsNullOrWhiteSpace($script:PfxOutputPath)) {
                throw "A folder path is required for PFX export."
            }
            Write-Log "Certificate output: PFX export to $PfxOutputPath" -Level Info
        }
        else {
            Write-Log "Certificate output: IIS certificate store + binding update" -Level Info
        }
    }
    else {
        $script:PfxOutputPath = Read-Host "  Enter folder path to export PFX to (e.g. C:\Certs)"
        if ([string]::IsNullOrWhiteSpace($script:PfxOutputPath)) {
            throw "A PFX output path is required when IIS is not installed. Re-run with -PfxOutputPath <folder>."
        }
        Write-Log "Certificate output: PFX export to $PfxOutputPath" -Level Info
    }
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."

    # Check internet connectivity to Let's Encrypt
    $acmeEndpoint = if ($Staging) { "acme-staging-v02.api.letsencrypt.org" } else { "acme-v02.api.letsencrypt.org" }
    $connectTest = Test-NetConnection -ComputerName $acmeEndpoint -Port 443 -WarningAction SilentlyContinue
    if (-not $connectTest.TcpTestSucceeded) {
        throw "Cannot reach $acmeEndpoint on port 443. Check internet connectivity and firewall rules."
    }
    Write-Log "ACME endpoint reachable ($acmeEndpoint)" -Level Success

    # Challenge-type-specific checks
    if ($ChallengeType -eq 'Http') {
        # HTTP-01 requires IIS
        if (-not $script:IISAvailable) {
            throw "HTTP-01 challenge requires IIS. Either install IIS, or use -ChallengeType Dns / -ChallengeType DnsManual for DNS-01 validation (no IIS needed)."
        }

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
    elseif ($ChallengeType -eq 'Dns') {
        if (-not $DnsPlugin) {
            throw "DNS-01 challenge requires -DnsPlugin parameter. Run 'Get-PAPlugin -List' to see available plugins, or use -ChallengeType DnsManual for manual TXT record creation."
        }
        Write-Log "DNS-01 challenge mode: plugin=$DnsPlugin, propagation wait=${DnsSleep}s" -Level Info
    }
    elseif ($ChallengeType -eq 'DnsManual') {
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

    # Verify certificate store path exists or fall back (only relevant for IIS output mode)
    if ($script:IISAvailable -and -not $PfxOutputPath) {
        if ($CertStorePath -eq "Cert:\LocalMachine\WebHosting") {
            try {
                $null = Get-ChildItem $CertStorePath -ErrorAction Stop
            }
            catch {
                $script:CertStorePath = "Cert:\LocalMachine\My"
                Write-Log "WebHosting store unavailable, falling back to LocalMachine\My" -Level Warning
            }
        }
        Write-Log "Certificate store: $CertStorePath" -Level Info
    }
}

# ============================================================================
# POSH-ACME MODULE MANAGEMENT
# ============================================================================

function Install-PoshAcmeModule {
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
    $certs = Get-ChildItem $CertStorePath -ErrorAction SilentlyContinue | Where-Object {
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
    switch ($ChallengeType) {
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

    $matchedSites = @()
    try {
        # For HTTP-01, set up IIS challenge infrastructure
        if ($ChallengeType -eq 'Http') {
            $challengeDir = Join-Path $env:ProgramData "YeylandWutani\LetsEncrypt\challenges"
            New-AcmeChallengeConfig -ChallengePath $challengeDir
            $matchedSites = Add-ChallengeToMatchingSites -Domains $Domains -ChallengePath $challengeDir
        }

        $paCert = New-PACertificate @certParams

        if (-not $paCert) {
            $errorHint = switch ($ChallengeType) {
                'Http'      { "Check that port 80 is accessible from the internet and DNS points to this server." }
                'Dns'       { "Check DNS plugin credentials and that the plugin can create TXT records in your DNS zone." }
                'DnsManual' { "Check that TXT records were created correctly and had time to propagate." }
            }
            throw "Certificate order failed. $errorHint"
        }

        Write-Log "Certificate obtained successfully!" -Level Success
        Write-Log "  Thumbprint: $($paCert.Thumbprint)"
        Write-Log "  Expires: $($paCert.NotAfter)"

        return $paCert
    }
    finally {
        # Clean up HTTP-01 challenge virtual directories
        foreach ($siteName in $matchedSites) {
            Remove-ChallengeVirtualDirectory -SiteName $siteName
        }
    }
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

function Build-DnsChallengeParams {
    param([string[]]$Domains)

    Write-Log "Using DNS-01 challenge with plugin: $DnsPlugin"

    # Validate the plugin exists in Posh-ACME
    $availablePlugins = Get-PAPlugin -List -ErrorAction SilentlyContinue
    if ($availablePlugins -and $DnsPlugin -notin $availablePlugins.Name) {
        $pluginList = ($availablePlugins.Name | Sort-Object) -join ', '
        throw "DNS plugin '$DnsPlugin' not found. Available plugins: $pluginList"
    }

    $certParams = @{
        Domain     = $Domains
        AcceptTOS  = $true
        Contact    = $ContactEmail
        Plugin     = $DnsPlugin
        Force      = $ForceRenewal.IsPresent
        DnsSleep   = $DnsSleep
        Verbose    = $false
    }

    if ($DnsPluginArgs) {
        $certParams['PluginArgs'] = $DnsPluginArgs
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

    Write-Log "Importing certificate to store: $CertStorePath"

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
    $importedCert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $CertStorePath -Password $securePass -Exportable

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

    # Save the PFX password to a file
    $pfxPass = $PACertificate.PfxPass
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

    # Only remove old cert if it's no longer bound anywhere
    $stillInUse = Get-ChildItem "IIS:\SslBindings" -ErrorAction SilentlyContinue | Where-Object {
        $_.Thumbprint -eq $OldThumbprint
    }

    if (-not $stillInUse) {
        $oldCert = Get-ChildItem $CertStorePath -ErrorAction SilentlyContinue | Where-Object {
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
    if ($DnsPlugin) {
        $argParts += "-DnsPlugin `"$DnsPlugin`""
    }
    if ($DnsSleep -ne 120) {
        $argParts += "-DnsSleep $DnsSleep"
    }
    if ($PfxOutputPath) {
        $argParts += "-PfxOutputPath `"$PfxOutputPath`""
    }
    if ($Staging) { $argParts += "-Staging" }
    if ($CertStorePath -ne "Cert:\LocalMachine\WebHosting") {
        $argParts += "-CertStorePath `"$CertStorePath`""
    }

    # Warn about DnsManual mode with scheduled tasks
    if ($ChallengeType -eq 'DnsManual') {
        Write-Log "WARNING: DnsManual challenge type requires interactive input and is NOT compatible with scheduled tasks!" -Level Warning
        Write-Log "Consider switching to -ChallengeType Dns with a -DnsPlugin for automated renewals" -Level Warning
    }

    # Note: DnsPluginArgs containing SecureString values will NOT survive serialization
    # to a scheduled task. For scheduled tasks, use environment variables or a credential
    # file that the DNS plugin supports. See Posh-ACME docs for plugin-specific guidance.
    if ($DnsPluginArgs) {
        Write-Log "Note: DNS plugin credentials are stored by Posh-ACME in the ACME account profile and will be reused on renewal" -Level Info
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
        Where-Object { $_.LastWriteTime -lt $cutoff }

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

try {
    Write-Banner

    # Handle scheduled task removal (direct parameter mode)
    if ($RemoveScheduledTask) {
        Uninstall-RenewalTask
        return
    }

    # Track whether we should install the scheduled task
    $shouldInstallTask = $InstallScheduledTask.IsPresent

    # Determine if we're running interactively (no task switches pre-selected)
    $isInteractive = -not $shouldInstallTask -and [Environment]::UserInteractive

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
                Write-Host "  Exiting." -ForegroundColor Gray
                return
            }
        }
    }

    # Ask about certificate output (IIS import vs PFX export)
    Show-CertificateOutputMenu

    # Show run summary
    Write-Host ""
    Write-Host "  -----------------------------------------------------------" -ForegroundColor Gray
    Write-Host "  Domain:    $DomainName" -ForegroundColor White
    Write-Host "  Mode:      $(if ($Staging) { 'STAGING (test)' } else { 'PRODUCTION' })" -ForegroundColor White
    Write-Host "  Challenge: $(switch ($ChallengeType) { 'Http' { 'HTTP-01 (IIS webroot)' } 'Dns' { "DNS-01 (plugin: $DnsPlugin)" } 'DnsManual' { 'DNS-01 (manual TXT record)' } })" -ForegroundColor White
    Write-Host "  Output:    $(if ($PfxOutputPath) { "PFX export to $PfxOutputPath" } else { 'IIS cert store + binding update' })" -ForegroundColor White
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

    # Install Posh-ACME if needed
    Install-PoshAcmeModule

    # Clean old logs
    Remove-OldLogs

    # Check current certificate status (only in cert store when doing IIS output)
    $currentCert = $null
    $oldThumbprint = $null
    if ($script:IISAvailable -and -not $PfxOutputPath) {
        $currentCert = Get-CurrentCertificate -Domains $allDomains
        $oldThumbprint = if ($currentCert) { $currentCert.Thumbprint } else { $null }
    }

    # Decide whether to renew
    $needsRenewal = $ForceRenewal -or (Test-CertificateNeedsRenewal -Certificate $currentCert)

    if (-not $needsRenewal) {
        Write-Log "Certificate is still valid and outside the renewal window. No action needed." -Level Success

        if ($shouldInstallTask) {
            Install-RenewalTask
        }

        Write-Host ""
        Write-Host "  No renewal needed. Certificate expires $($currentCert.NotAfter)" -ForegroundColor Green
        Write-Host ""
        return
    }

    # Perform the certificate order/renewal
    if ($PSCmdlet.ShouldProcess($DomainName, "Request/renew Let's Encrypt certificate")) {
        $paCert = Invoke-AcmeCertificateOrder -Domains $allDomains

        if ($PfxOutputPath) {
            # PFX export path
            $exportedPfx = Export-PfxToFolder -PACertificate $paCert

            # Install scheduled task if requested
            if ($shouldInstallTask) {
                Install-RenewalTask
            }

            Write-Host ""
            Write-Host "  ============================================================" -ForegroundColor Green
            Write-Host "  Certificate issued and exported!" -ForegroundColor Green
            Write-Host "  PFX File:   $exportedPfx" -ForegroundColor Green
            Write-Host "  Expires:    $($paCert.NotAfter)" -ForegroundColor Green
            Write-Host "  Output Dir: $PfxOutputPath" -ForegroundColor Green
            if ($Staging) {
                Write-Host ""
                Write-Host "  NOTE: This is a STAGING certificate (not browser-trusted)." -ForegroundColor Yellow
                Write-Host "  Run again without -Staging for a production certificate." -ForegroundColor Yellow
            }
            Write-Host ""
            Write-Host "  Import the PFX into your web server or load balancer." -ForegroundColor Cyan
            Write-Host "  Password is saved alongside the PFX file (restricted to Admins)." -ForegroundColor Cyan
            Write-Host "  ============================================================" -ForegroundColor Green
            Write-Host ""
        }
        else {
            # IIS path: import to store and update bindings
            $newCert = Import-CertificateToStore -PACertificate $paCert

            # Update IIS bindings
            Update-IISBindings -NewThumbprint $newCert.Thumbprint -OldThumbprint $oldThumbprint -Domains $allDomains

            # Remove old certificate if safe to do so
            Remove-OldCertificate -OldThumbprint $oldThumbprint -NewThumbprint $newCert.Thumbprint

            # Install scheduled task if requested
            if ($shouldInstallTask) {
                Install-RenewalTask
            }

            Write-Host ""
            Write-Host "  ============================================================" -ForegroundColor Green
            Write-Host "  Certificate renewal complete!" -ForegroundColor Green
            Write-Host "  Thumbprint: $($newCert.Thumbprint)" -ForegroundColor Green
            Write-Host "  Expires:    $($newCert.NotAfter)" -ForegroundColor Green
            if ($Staging) {
                Write-Host ""
                Write-Host "  NOTE: This is a STAGING certificate (not browser-trusted)." -ForegroundColor Yellow
                Write-Host "  Run again without -Staging for a production certificate." -ForegroundColor Yellow
            }
            Write-Host "  ============================================================" -ForegroundColor Green
            Write-Host ""
        }

        Write-Log "Renewal process completed successfully" -Level Success
        Write-Log "Log file: $LogFile"
    }
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Write-Log "Full log: $LogFile" -Level Error
    throw
}
