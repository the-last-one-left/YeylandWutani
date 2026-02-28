#Requires -Version 5.1
<#
.SYNOPSIS
    Microsoft 365 SAML Domain Federation Wizard.

.DESCRIPTION
    Interactive wizard to federate Microsoft 365 custom domains to a SAML 2.0
    identity provider. Supports WatchGuard AuthPoint, Okta, ADFS, and any
    standards-compliant SAML 2.0 IdP.

    Wizard capabilities:
      - SAML provider configuration with built-in templates (WatchGuard AuthPoint, Okta, ADFS, Generic)
      - Multi-domain selection from verified tenant domains
      - Admin account lockout prevention (UPN safety check before federation)
      - Pre-flight review with full confirmation before any changes
      - Post-federation verification
      - Federation status report for all tenant domains
      - Revert federated domain(s) back to managed authentication

.NOTES
    Author:     Yeyland Wutani - Building Better Systems
    Requires:   Microsoft.Graph PowerShell SDK (wizard will offer to install)
    Permissions: Global Administrator or Privileged Role Administrator
    Version:    2.0  (Graph API - replaces deprecated MSOnline/MSOL)

    CRITICAL SAFETY NOTE:
    If your admin account UPN uses a domain you intend to federate (e.g. admin@contoso.com
    and you are federating contoso.com), you WILL be locked out after federation unless
    you first change your UPN to the *.onmicrosoft.com fallback domain.
    This wizard will detect this condition and help you resolve it safely.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region -- Globals -------------------------------------------------------------
$script:Connected     = $false
$script:TenantDomains = @()
$script:OnMicrosoftDomain = ''
$script:AdminUpn      = ''
$script:SelectedDomains = @()
$script:SamlConfig    = $null
$script:LogLines      = [System.Collections.Generic.List[string]]::new()
#endregion

#region -- UI Helpers ----------------------------------------------------------
function Show-YWBanner {
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ ",
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|",
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | ",
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

function Write-Step   { param([string]$Msg) Write-Host "  [*] $Msg" -ForegroundColor DarkYellow }
function Write-OK     { param([string]$Msg) Write-Host "  [+] $Msg" -ForegroundColor Green }
function Write-Warn   { param([string]$Msg) Write-Host "  [!] $Msg" -ForegroundColor Yellow }
function Write-Fail   { param([string]$Msg) Write-Host "  [X] $Msg" -ForegroundColor Red }
function Write-Info   { param([string]$Msg) Write-Host "      $Msg" -ForegroundColor Gray }

function Write-Section {
    param([string]$Title)
    $pad = "-" * [Math]::Max(0, 77 - $Title.Length)
    Write-Host ""
    Write-Host "  -- $Title $pad" -ForegroundColor DarkYellow
    Write-Host ""
}

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $script:LogLines.Add("[$ts] $Msg")
}

function Read-MenuChoice {
    param([string]$Prompt = "Choice", [string[]]$Valid)
    do {
        $choice = (Read-Host "`n  $Prompt").Trim()
    } while ($Valid -and $choice -notin $Valid)
    return $choice
}

function Confirm-Dangerous {
    param([string]$Action)
    Write-Host ""
    Write-Warn "You are about to: $Action"
    Write-Host "  Type " -NoNewline -ForegroundColor Gray
    Write-Host "CONFIRM" -NoNewline -ForegroundColor Yellow
    Write-Host " to proceed, or press Enter to cancel." -ForegroundColor Gray
    $ans = (Read-Host "  >>>").Trim()
    return ($ans -eq 'CONFIRM')
}

function Pause-ForUser {
    Write-Host ""
    Read-Host "  Press Enter to continue" | Out-Null
}

function Confirm-YesNo {
    # Returns $true for yes/y, $false for no/n.
    # $Default: 'yes' or 'no' - returned when user presses Enter with no input.
    param([string]$Prompt, [string]$Default = '')
    $hint = switch ($Default.ToLower()) {
        'yes' { ' (Y/n)' }
        'no'  { ' (y/N)' }
        default { ' (y/n)' }
    }
    do {
        $raw = (Read-Host "  $Prompt$hint").Trim().ToLower()
        if (-not $raw -and $Default) { $raw = $Default.ToLower() }
    } while ($raw -notin 'y','yes','n','no')
    return $raw -in 'y','yes'
}
#endregion

#region -- Prerequisites -------------------------------------------------------
function Test-AndInstallMgraph {
    Write-Section "Prerequisites"

    $needed = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Users'
    )

    $allPresent = $true
    foreach ($modName in $needed) {
        $mod = Get-Module -Name $modName -ListAvailable | Select-Object -First 1
        if ($mod) {
            Write-OK "$modName (v$($mod.Version))"
            Import-Module $modName -ErrorAction SilentlyContinue
        } else {
            Write-Warn "$modName - NOT installed"
            $allPresent = $false
        }
    }

    if ($allPresent) { return $true }

    Write-Host ""
    Write-Info "The Microsoft.Graph PowerShell SDK is required for domain federation."
    Write-Info "This installs three submodules (~10-30 MB) from the PowerShell Gallery."
    if (-not (Confirm-YesNo "Install Microsoft.Graph modules for CurrentUser now")) {
        Write-Fail "Cannot continue without Microsoft.Graph modules."
        return $false
    }

    foreach ($modName in $needed) {
        if (Get-Module -Name $modName -ListAvailable) { continue }
        try {
            Write-Step "Installing $modName ..."
            Install-Module $modName -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            Import-Module $modName
            Write-OK "$modName installed."
        } catch {
            Write-Fail "Failed to install $modName : $_"
            Write-Info "Try manually: Install-Module $modName -Scope CurrentUser"
            return $false
        }
    }
    return $true
}
#endregion

#region -- M365 Connection -----------------------------------------------------
function Connect-ToM365 {
    Write-Section "Connect to Microsoft 365"

    if ($script:Connected) {
        Write-OK "Already connected."
        Write-Info "Tenant:    $script:OnMicrosoftDomain"
        Write-Info "Admin UPN: $script:AdminUpn"
        if (-not (Confirm-YesNo "Reconnect (clears token cache and re-authenticates)")) { return $true }
    }

    # Disconnect first, then use -ContextScope Process so MSAL never reads from its
    # persistent disk cache. This guarantees a fresh browser auth and a token that
    # actually contains the scopes we requested - not a silently-reused stale token.
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Info "A browser window will open for Microsoft authentication."
    Write-Info "Sign in with a Global Administrator account."
    Write-Info "When the browser prompts, click ACCEPT to consent to the requested permissions."
    Write-Info "Requested: Domain-InternalFederation.ReadWrite.All, Domain.ReadWrite.All,"
    Write-Info "           User.ReadWrite.All, RoleManagement.Read.Directory"
    Write-Host ""

    try {
        Connect-MgGraph -Scopes "Domain-InternalFederation.ReadWrite.All","Domain.ReadWrite.All",`
            "User.ReadWrite.All","RoleManagement.Read.Directory" `
            -NoWelcome -ContextScope Process -ErrorAction Stop
    } catch {
        Write-Fail "Connection failed: $_"
        Write-Warn "If the browser did not open, try running PowerShell as Administrator."
        Pause-ForUser
        return $false
    }

    # Gather tenant details via Graph
    try {
        $domains = Get-MgDomain -ErrorAction Stop
        if (-not $domains) { throw "Get-MgDomain returned no results. Check your permissions." }
        $script:TenantDomains     = $domains
        $onMSObj = $domains |
            Where-Object { $_.Id -like '*.onmicrosoft.com' -and $_.Id -notlike '*.mail.onmicrosoft.com' } |
            Select-Object -First 1
        $script:OnMicrosoftDomain = if ($onMSObj) { $onMSObj.Id } else { '' }
        $script:Connected = $true
    } catch {
        Write-Fail "Authenticated but could not retrieve tenant domain data: $_"
        Write-Warn "Possible causes:"
        Write-Info "  - Account lacks Global Administrator or Domain.ReadWrite.All permission"
        Write-Info "  - Conditional Access policy blocked the Graph API scope"
        Write-Info "  - Try disconnecting (Disconnect-MgGraph) and reconnecting"
        $script:Connected = $false
        Pause-ForUser
        return $false
    }

    Write-OK "Connected to Microsoft 365 via Graph API."
    Write-Info "Tenant fallback domain: $script:OnMicrosoftDomain"
    Write-Host ""

    # ── Live permission probe - verify Domain.ReadWrite.All actually works ───
    # Get-MgContext).Scopes only returns what was *requested*, not what Entra
    # actually put in the token. Probe the real federation API instead.
    $ctx         = Get-MgContext
    $detectedUpn = if ($ctx) { $ctx.Account } else { '' }

    # ── Live permission probe against a verified custom domain ───────────────
    # The .onmicrosoft.com domain has no federationConfiguration endpoint (it can
    # never be federated), so probe a real custom domain instead. A 200 (even an
    # empty collection) proves Domain.ReadWrite.All is in the token. A 403 does not.
    Write-Info "Verifying Domain-InternalFederation.ReadWrite.All permission against live API..."
    $probeDomain = $script:TenantDomains |
        Where-Object { $_.Id -notlike '*.onmicrosoft.com' -and $_.IsVerified -eq $true } |
        Select-Object -First 1

    if ($probeDomain) {
        try {
            $probeUri = "https://graph.microsoft.com/v1.0/domains/$($probeDomain.Id)/federationConfiguration"
            Invoke-MgGraphRequest -Method GET -Uri $probeUri -ErrorAction Stop | Out-Null
            Write-OK "Domain federation permissions confirmed (probed: $($probeDomain.Id))."
        } catch {
            $probeErr = "$_"
            if ($probeErr -match '403|Forbidden|Authorization_RequestDenied|Insufficient') {
                Write-Host ""
                Write-Warn "PERMISSION TEST FAILED: token does not have effective Domain-InternalFederation.ReadWrite.All."
                Write-Warn "Federation will fail with 403. Resolve before proceeding."
                Write-Host ""
                Write-Info "Most common causes:"
                Write-Host "  1. Browser consent prompt dismissed without clicking Accept" -ForegroundColor Yellow
                Write-Host "  2. Admin consent not granted for 'Microsoft Graph Command Line Tools'" -ForegroundColor Yellow
                Write-Host "  3. Account is not a Global Admin or Domain Name Administrator" -ForegroundColor Yellow
                Write-Host "  4. Conditional Access policy blocking this scope" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "To grant admin consent:"
                Write-Info "  Entra ID -> Enterprise Applications ->"
                Write-Info "  'Microsoft Graph Command Line Tools' -> Permissions ->"
                Write-Info "  Grant admin consent for [your tenant]"
                Write-Host ""
                Write-Info "Then use option [1] to reconnect."
            } elseif ($probeErr -match '404|ResourceNotFound|Request_ResourceNotFound') {
                # 404 means the API processed the request (auth OK) but the domain
                # has no federation config yet - this is the expected state.
                # A 403 would fire before any resource lookup, so 404 = permission confirmed.
                Write-OK "Domain federation permissions confirmed ($($probeDomain.Id) - not yet federated)."
            } else {
                Write-Warn "Permission probe inconclusive (unexpected error): $probeErr"
                Write-Info "Proceeding - federation will confirm permissions at apply time."
            }
        }
    } else {
        Write-Info "No verified custom domains found to probe permissions against."
        Write-Info "Permission will be confirmed when federation is applied."
    }

    Write-Warn "Safety check: confirm the admin UPN you signed in with."
    Write-Info "This detects if your account would be locked out by federation."
    $hint = if ($detectedUpn) { " [$detectedUpn]" } else { " (e.g. admin@contoso.com)" }
    $entered = (Read-Host "  Your admin UPN$hint").Trim().ToLower()
    $script:AdminUpn = if ($entered) { $entered } elseif ($detectedUpn) { $detectedUpn.ToLower() } else { '' }

    Write-Log "Connected to M365 via Graph. Tenant: $script:OnMicrosoftDomain  Admin: $script:AdminUpn"
    Write-OK "Session active. Admin: $script:AdminUpn"
    Pause-ForUser
    return $true
}
#endregion

#region -- SAML Metadata XML Parser -------------------------------------------
function Import-SamlMetadataValues {
    <#
    .SYNOPSIS
        Parses a SAML 2.0 IdP metadata XML string and extracts values for M365 federation.
    .OUTPUTS
        Hashtable with keys: IssuerUri, PassiveSignInUri, SignOutUri, SigningCertificate
        Returns $null if the XML cannot be parsed.
    #>
    param([string]$XmlContent)

    $result = @{}

    try {
        $xml = [System.Xml.XmlDocument]::new()
        $xml.LoadXml($XmlContent)
    } catch {
        Write-Fail "  Cannot parse XML: $_"
        return $null
    }

    # ── Entity ID → IssuerUri ────────────────────────────────────────────────
    # Handles namespace prefixes (md:, saml:, etc.) via local-name()
    $entityNode = $xml.SelectSingleNode('//*[local-name()="EntityDescriptor"]')
    if ($entityNode) {
        $entityId = $entityNode.GetAttribute('entityID')
        if ($entityId) { $result['IssuerUri'] = $entityId }
    }

    # ── SSO URL (prefer HTTP-Redirect, fall back to HTTP-POST) ───────────────
    $ssoNodes    = $xml.SelectNodes('//*[local-name()="SingleSignOnService"]')
    $ssoRedirect = $null
    $ssoPost     = $null
    foreach ($n in $ssoNodes) {
        $binding  = $n.GetAttribute('Binding')
        $location = $n.GetAttribute('Location')
        if ($binding -like '*HTTP-Redirect' -and $location) { $ssoRedirect = $location }
        elseif ($binding -like '*HTTP-POST' -and $location) { $ssoPost = $location }
    }
    $ssoUrl = if ($ssoRedirect) { $ssoRedirect } elseif ($ssoPost) { $ssoPost } else { $null }
    if ($ssoUrl) { $result['PassiveSignInUri'] = $ssoUrl }

    # ── Sign-out URL (prefer HTTP-Redirect) ───────────────────────────────────
    $sloNodes    = $xml.SelectNodes('//*[local-name()="SingleLogoutService"]')
    $sloLocation = $null
    foreach ($n in $sloNodes) {
        $binding  = $n.GetAttribute('Binding')
        $location = $n.GetAttribute('Location')
        if ($binding -like '*HTTP-Redirect' -and $location) { $sloLocation = $location; break }
    }
    if (-not $sloLocation -and $sloNodes -and $sloNodes.Count -gt 0) {
        $sloLocation = $sloNodes[0].GetAttribute('Location')
    }
    if ($sloLocation) { $result['SignOutUri'] = $sloLocation }

    # ── Signing certificate ───────────────────────────────────────────────────
    # Prefer KeyDescriptor[@use='signing'] to avoid picking up encryption certs
    $signingCert = $null
    $sigKDs = $xml.SelectNodes('//*[local-name()="KeyDescriptor"][@use="signing"]')
    foreach ($kd in $sigKDs) {
        $x509Node = $kd.SelectSingleNode('.//*[local-name()="X509Certificate"]')
        if ($x509Node -and $x509Node.InnerText.Trim()) {
            $signingCert = $x509Node.InnerText -replace '\s', ''
            break
        }
    }
    if (-not $signingCert) {
        # Fall back to first X509Certificate in the document
        $anyX509 = $xml.SelectSingleNode('//*[local-name()="X509Certificate"]')
        if ($anyX509 -and $anyX509.InnerText.Trim()) {
            $signingCert = $anyX509.InnerText -replace '\s', ''
        }
    }
    if ($signingCert) { $result['SigningCertificate'] = $signingCert }

    return $result
}

function Invoke-ImportMetadataUI {
    <#
    .SYNOPSIS
        Interactive prompt to load a SAML metadata XML from a file or URL.
        Merges parsed values into the provided config hashtable.
        Returns $true if values were imported, $false otherwise.
    #>
    param([hashtable]$Cfg)

    Write-Host ""
    Write-Host "  -- Import from SAML Metadata XML (optional) -----------------------------------" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Info "  Load values automatically from your IdP's SAML metadata XML."
    Write-Info "  This fills Entity ID, SSO URL, Sign-out URL, and Certificate in one step."
    Write-Host ""
    Write-Host "    [F]  Load from a local metadata file" -ForegroundColor White
    Write-Host "    [U]  Fetch from a metadata URL" -ForegroundColor White
    Write-Host "         (ADFS: https://[server]/FederationMetadata/2007-06/FederationMetadata.xml)" -ForegroundColor DarkGray
    Write-Host "    [S]  Skip - enter values manually" -ForegroundColor Gray
    Write-Host ""

    $metaChoice = (Read-Host "  Choice").Trim().ToUpper()
    if ($metaChoice -notin 'F','FILE','U','URL') { return $false }

    $metaXml = $null

    if ($metaChoice -in 'F','FILE') {
        $metaPath = $null
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $dlg                  = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.Title            = 'Select SAML Metadata XML'
            $dlg.Filter           = 'XML files (*.xml)|*.xml|All files (*.*)|*.*'
            $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $dlg.CheckFileExists  = $true
            Write-Info "  Opening file picker..."
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $metaPath = $dlg.FileName
                Write-Info "  Selected: $metaPath"
            } else {
                Write-Warn "  File selection cancelled."
                return $false
            }
        } catch {
            $metaPath = (Read-Host "  Metadata XML file path").Trim().Trim('"')
            if (-not $metaPath) { Write-Warn "  No path entered."; return $false }
        }

        if (-not (Test-Path $metaPath)) {
            Write-Fail "  File not found: $metaPath"
            return $false
        }
        try {
            $metaXml = [System.IO.File]::ReadAllText($metaPath, [System.Text.Encoding]::UTF8)
        } catch {
            Write-Fail "  Could not read file: $_"
            return $false
        }

    } elseif ($metaChoice -in 'U','URL') {
        $metaUrl = (Read-Host "  Metadata URL").Trim()
        if (-not $metaUrl) { Write-Warn "  No URL entered."; return $false }
        Write-Info "  Fetching metadata..."
        try {
            $resp    = Invoke-WebRequest -Uri $metaUrl -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
            $metaXml = $resp.Content
            Write-OK "  Downloaded ($($metaXml.Length) bytes)."
        } catch {
            Write-Fail "  Failed to fetch URL: $_"
            return $false
        }
    }

    if (-not $metaXml) { return $false }

    Write-Info "  Parsing metadata XML..."
    $parsed = Import-SamlMetadataValues -XmlContent $metaXml
    if (-not $parsed -or $parsed.Count -eq 0) {
        Write-Warn "  No recognizable SAML values found in the XML."
        return $false
    }

    # ── Show summary table ───────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  +- Values extracted from metadata ----------------------------------------+" -ForegroundColor Green
    $fieldLabels = [ordered]@{
        'Issuer URI'   = 'IssuerUri'
        'SSO URL'      = 'PassiveSignInUri'
        'Sign-out URL' = 'SignOutUri'
        'Certificate'  = 'SigningCertificate'
    }
    $importedCount = 0
    foreach ($label in $fieldLabels.Keys) {
        $key = $fieldLabels[$label]
        $val = $parsed[$key]
        if ($val) {
            $display = if ($key -eq 'SigningCertificate') {
                "$($val.Length) chars (base64)"
            } else {
                $val.Substring(0, [Math]::Min(62, $val.Length))
            }
            Write-Host "  |  $($label.PadRight(14)): $($display.PadRight(56)) |" -ForegroundColor Green
            $Cfg[$key] = $val
            $importedCount++
        } else {
            Write-Host "  |  $($label.PadRight(14)): (not found in metadata)$((' ' * 34)) |" -ForegroundColor DarkYellow
        }
    }
    Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""

    if ($importedCount -gt 0) {
        Write-OK "  Imported $importedCount field(s). Review each below - press Enter to accept."
    } else {
        Write-Warn "  No fields could be extracted from this metadata."
        return $false
    }

    return $true
}
#endregion

#region -- SAML Provider Configuration ----------------------------------------
function Get-SamlConfigFromUser {
    param([hashtable]$Template = $null)

    $cfg = if ($Template) { $Template.Clone() } else {
        @{
            ProviderName                    = ''
            IssuerUri                       = ''
            PassiveSignInUri                = ''
            ActiveSignInUri                 = ''
            SignOutUri                      = ''
            SigningCertificate              = ''
            PreferredAuthenticationProtocol = 'saml'
            FederatedIdpMfaBehavior         = 'enforceMfaByFederatedIdp'
            DisplayName                     = ''
        }
    }

    # ── Provider-specific before-you-start guidance ──────────────────────────
    $providerName = $cfg['ProviderName']
    switch -Wildcard ($providerName) {

        'WatchGuard AuthPoint' {
            Write-Host ""
            Write-Host "  +- WatchGuard AuthPoint - Where to find your SAML values ---------------+" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  EASIEST: Download the metadata XML and use [F] at the next prompt     |" -ForegroundColor Cyan
            Write-Host "  |  to auto-fill all values (Entity ID, SSO/SLO URLs, certificate).       |" -ForegroundColor Cyan
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  1. Log in to WatchGuard Cloud: https://www.watchguard.com/wgrd-cloud  |" -ForegroundColor DarkYellow
            Write-Host "  |  2. Navigate to: Configure -> AuthPoint -> Resources                   |" -ForegroundColor DarkYellow
            Write-Host "  |  3. Open your Office 365 SAML Resource (or create one)                 |" -ForegroundColor DarkYellow
            Write-Host "  |  4. Next to the AuthPoint certificate: click menu -> Download Metadata  |" -ForegroundColor DarkYellow
            Write-Host "  |     OR click the resource menu -> Download Metadata                    |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Values and their expected formats:                                    |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Entity ID (Issuer URI):                                               |" -ForegroundColor DarkYellow
            Write-Host "  |    https://sp.authpoint.[region].cloud.watchguard.com/[AccountID]      |" -ForegroundColor DarkYellow
            Write-Host "  |    Regions: us1, us2, eu1, eu2, au1 (match your WatchGuard Cloud login)|" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  SSO URL (PassiveSignInUri):                                           |" -ForegroundColor DarkYellow
            Write-Host "  |    https://sp.authpoint.[region].cloud.watchguard.com/saml/            |" -ForegroundColor DarkYellow
            Write-Host "  |      [AccountID]/sso/spinit                                            |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Sign-Out URL (SignOutUri):                                            |" -ForegroundColor DarkYellow
            Write-Host "  |    https://sp.authpoint.[region].cloud.watchguard.com/saml/            |" -ForegroundColor DarkYellow
            Write-Host "  |      [AccountID]/slo/spinit                                            |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Certificate: Copy the base64 text from the 'X.509 Certificate'        |" -ForegroundColor DarkYellow
            Write-Host "  |    field on the SAML resource page. Do NOT include the                 |" -ForegroundColor DarkYellow
            Write-Host "  |    -----BEGIN/END CERTIFICATE----- lines.                              |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Full guide: https://www.watchguard.com/help/docs/help-center/en-US/   |" -ForegroundColor DarkYellow
            Write-Host "  |    Content/Integration-Guides/AuthPoint/Office365-AuthPoint.html       |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor DarkYellow
        }

        'Okta' {
            Write-Host ""
            Write-Host "  +- Okta - Where to find your SAML values --------------------------------+" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  EASIEST: Download IdP metadata XML and use [F] at the next prompt     |" -ForegroundColor Cyan
            Write-Host "  |  to auto-fill all values (Entity ID, SSO URL, certificate).            |" -ForegroundColor Cyan
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  1. Log in to Okta Admin Console                                       |" -ForegroundColor DarkYellow
            Write-Host "  |  2. Navigate to: Applications -> Applications -> [your M365 app]       |" -ForegroundColor DarkYellow
            Write-Host "  |  3. Click the 'Sign On' tab                                            |" -ForegroundColor DarkYellow
            Write-Host "  |  4. Click 'Identity Provider metadata' link to download the XML file   |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Entity ID (Issuer URI):                                               |" -ForegroundColor DarkYellow
            Write-Host "  |    http://www.okta.com/[appInstanceId]                                 |" -ForegroundColor DarkYellow
            Write-Host "  |    (shown as 'Identity Provider Issuer' in SAML setup instructions)    |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  SSO URL (PassiveSignInUri):                                           |" -ForegroundColor DarkYellow
            Write-Host "  |    https://[yourorg].okta.com/app/[appname]/[appId]/sso/saml           |" -ForegroundColor DarkYellow
            Write-Host "  |    (shown as 'Identity Provider Single Sign-On URL')                   |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Certificate: Click 'Download certificate' on the Sign On tab.         |" -ForegroundColor DarkYellow
            Write-Host "  |    Open the .cert file in Notepad, copy only the base64 content.       |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Okta SAML docs: https://help.okta.com/en-us/content/topics/apps/      |" -ForegroundColor DarkYellow
            Write-Host "  |    apps_app_integration_wizard_saml.htm                                |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor DarkYellow
        }

        'Active Directory Federation Services (ADFS)' {
            Write-Host ""
            Write-Host "  +- ADFS - Where to find your SAML / WS-Fed values -----------------------+" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  EASIEST: Use [U] at the next prompt and paste this URL:               |" -ForegroundColor Cyan
            Write-Host "  |    https://[adfs-server]/FederationMetadata/2007-06/                   |" -ForegroundColor Cyan
            Write-Host "  |      FederationMetadata.xml                                            |" -ForegroundColor Cyan
            Write-Host "  |  This auto-fills Entity ID, SSO URL, and signing certificate.          |" -ForegroundColor Cyan
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Open ADFS Management on your federation server:                       |" -ForegroundColor DarkYellow
            Write-Host "  |    Server Manager -> Tools -> AD FS Management                         |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Entity ID (Issuer URI) - Federation Service Identifier:               |" -ForegroundColor DarkYellow
            Write-Host "  |    AD FS Management -> Service -> Edit Federation Service Properties   |" -ForegroundColor DarkYellow
            Write-Host "  |    Format: http://[adfs-server]/adfs/services/trust                    |" -ForegroundColor DarkYellow
            Write-Host "  |    OR retrieve via PS: (Get-AdfsProperties).Identifier                 |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Passive (browser) SSO URL:                                            |" -ForegroundColor DarkYellow
            Write-Host "  |    https://[adfs-server]/adfs/ls/                                      |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Active (WS-Trust) endpoint - for legacy non-browser clients:          |" -ForegroundColor DarkYellow
            Write-Host "  |    https://[adfs-server]/adfs/services/trust/2005/usernamemixed        |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Sign-out URL:                                                         |" -ForegroundColor DarkYellow
            Write-Host "  |    https://[adfs-server]/adfs/ls/?wa=wsignout1.0                       |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Token-signing certificate:                                            |" -ForegroundColor DarkYellow
            Write-Host "  |    AD FS Management -> Service -> Certificates ->                      |" -ForegroundColor DarkYellow
            Write-Host "  |    Token-signing cert -> right-click -> View Certificate ->             |" -ForegroundColor DarkYellow
            Write-Host "  |    Details -> Copy to File -> Base-64 encoded X.509 (.CER)             |" -ForegroundColor DarkYellow
            Write-Host "  |    Then use the FILE option below to load it.                          |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  ADFS federation guide:                                                |" -ForegroundColor DarkYellow
            Write-Host "  |    https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/    |" -ForegroundColor DarkYellow
            Write-Host "  |    how-to-connect-fed-management                                       |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor DarkYellow
        }

        default {
            Write-Host ""
            Write-Host "  +- Generic SAML 2.0 - Where to find your values -------------------------+" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  EASIEST: If your IdP provides a metadata XML file or URL, use [F]     |" -ForegroundColor Cyan
            Write-Host "  |  or [U] at the next prompt to auto-fill all values.                    |" -ForegroundColor Cyan
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  In your IdP's admin portal, look for:                                 |" -ForegroundColor DarkYellow
            Write-Host "  |    'SAML Metadata', 'Federation Metadata', or 'IdP Metadata'           |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  If your IdP provides a metadata XML URL or file, the values you       |" -ForegroundColor DarkYellow
            Write-Host "  |  need are inside it as these XML attributes/elements:                  |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Entity ID:     <EntityDescriptor entityID='...'>                      |" -ForegroundColor DarkYellow
            Write-Host "  |  SSO URL:       <SingleSignOnService Location='...'                    |" -ForegroundColor DarkYellow
            Write-Host "  |                   Binding='...HTTP-Redirect'>                          |" -ForegroundColor DarkYellow
            Write-Host "  |  Sign-Out URL:  <SingleLogoutService Location='...'>                   |" -ForegroundColor DarkYellow
            Write-Host "  |  Certificate:  <X509Certificate>...base64 data...</X509Certificate>    |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  |  Microsoft Graph federation docs:                                      |" -ForegroundColor DarkYellow
            Write-Host "  |    https://learn.microsoft.com/en-us/graph/api/resources/              |" -ForegroundColor DarkYellow
            Write-Host "  |    internaldomainfederation                                            |" -ForegroundColor DarkYellow
            Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
            Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor DarkYellow
        }
    }

    Write-Host ""
    # ── Metadata XML import (fills cfg before per-field prompts) ─────────────
    Invoke-ImportMetadataUI -Cfg $cfg | Out-Null

    Write-Host ""
    Write-Info "Press Enter on any field to keep the existing value shown in [brackets]."
    Write-Host ""

    # ── Input validators (return error string on failure, $null on pass) ─────
    $validateUri = {
        param([string]$v)
        $uri = $null
        if (-not [System.Uri]::TryCreate($v, [System.UriKind]::Absolute, [ref]$uri)) {
            return "Not a valid URI. Expected format: https://idp.example.com/path"
        }
        if ($uri.Scheme -notin 'http', 'https') {
            return "URI scheme must be http or https (found: '$($uri.Scheme)')"
        }
        return $null
    }

    $validateHttpsUrl = {
        param([string]$v)
        $uri = $null
        if (-not [System.Uri]::TryCreate($v, [System.UriKind]::Absolute, [ref]$uri)) {
            return "Not a valid URL. Expected format: https://idp.example.com/path"
        }
        if ($uri.Scheme -notin 'http', 'https') {
            return "URL must use https (found: '$($uri.Scheme)')"
        }
        if ($uri.Scheme -eq 'http') {
            Write-Host "    [!] Warning: URL uses http:// - SAML endpoints should use https://" -ForegroundColor Yellow
        }
        return $null
    }

    # ── Nested prompt helper ─────────────────────────────────────────────────
    function Prompt-Field {
        param(
            [string]$Label,
            [string]$Key,
            [string]$Hint          = '',
            [string]$Format        = '',
            [bool]  $Required      = $true,
            [scriptblock]$Validator = $null
        )
        $current = $cfg[$Key]
        $display = if ($current) { " [$current]" } else { '' }
        Write-Host ""
        if ($Hint)   { Write-Info "  $Hint" }
        if ($Format) { Write-Host "    Format: $Format" -ForegroundColor DarkYellow }
        while ($true) {
            $val = (Read-Host "  $Label$display").Trim()
            if (-not $val -and $current) { $val = $current }
            if ($Required -and -not $val) {
                Write-Host "    [!] This field is required." -ForegroundColor Yellow
                continue
            }
            if ($val -and $Validator) {
                $errMsg = & $Validator $val
                if ($errMsg) {
                    Write-Host "    [X] $errMsg" -ForegroundColor Red
                    continue
                }
            }
            break
        }
        $cfg[$Key] = $val
    }

    # ── Provider-specific field hints and format examples ────────────────────
    switch -Wildcard ($providerName) {

        'WatchGuard AuthPoint' {
            Prompt-Field "Provider name"      'ProviderName'    `
                -Hint "Descriptive name for this federation config" `
                -Format "e.g. WatchGuard AuthPoint"

            Prompt-Field "Entity ID (Issuer URI)" 'IssuerUri'   `
                -Hint "Found on the AuthPoint SAML resource page" `
                -Format "https://sp.authpoint.[region].cloud.watchguard.com/[AccountID]" `
                -Validator $validateUri

            Prompt-Field "SSO URL"            'PassiveSignInUri' `
                -Hint "The sign-in (SSO) URL from the AuthPoint SAML resource" `
                -Format "https://sp.authpoint.[region].cloud.watchguard.com/saml/[AccountID]/sso/spinit" `
                -Validator $validateHttpsUrl

            Prompt-Field "Sign-Out URL"       'SignOutUri'       `
                -Hint "The sign-out (SLO) URL from the AuthPoint SAML resource" `
                -Format "https://sp.authpoint.[region].cloud.watchguard.com/saml/[AccountID]/slo/spinit" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "WS-Trust endpoint"  'ActiveSignInUri'  `
                -Hint "Leave blank - AuthPoint does not publish a WS-Trust endpoint" `
                -Format "(leave blank)" `
                -Required $false

            Prompt-Field "Display name"       'DisplayName'      `
                -Hint "Text shown on the Microsoft sign-in page (optional)" `
                -Format "e.g. Sign in with WatchGuard AuthPoint" `
                -Required $false
        }

        'Okta' {
            Prompt-Field "Provider name"      'ProviderName'    `
                -Hint "Descriptive name for this federation config" `
                -Format "e.g. Okta"

            Prompt-Field "Entity ID (Issuer URI)" 'IssuerUri'   `
                -Hint "Shown as 'Identity Provider Issuer' in Okta SAML setup instructions" `
                -Format "http://www.okta.com/[exkXXXXXXXXX]" `
                -Validator $validateUri

            Prompt-Field "SSO URL"            'PassiveSignInUri' `
                -Hint "Shown as 'Identity Provider Single Sign-On URL' in Okta SAML setup instructions" `
                -Format "https://[yourorg].okta.com/app/[appname]/[appId]/sso/saml" `
                -Validator $validateHttpsUrl

            Prompt-Field "Sign-Out URL"       'SignOutUri'       `
                -Hint "Optional - from Okta SAML setup instructions if SLO is configured" `
                -Format "https://[yourorg].okta.com/app/[appId]/slo/saml" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "WS-Trust endpoint"  'ActiveSignInUri'  `
                -Hint "Leave blank unless Okta WS-Trust is specifically enabled for this app" `
                -Format "(leave blank for most Okta deployments)" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "Display name"       'DisplayName'      `
                -Hint "Text shown on the Microsoft sign-in page (optional)" `
                -Format "e.g. Sign in with Okta" `
                -Required $false
        }

        'Active Directory Federation Services (ADFS)' {
            Prompt-Field "Provider name"      'ProviderName'    `
                -Hint "Descriptive name for this federation config" `
                -Format "e.g. Contoso ADFS"

            Prompt-Field "Entity ID (Issuer URI)" 'IssuerUri'   `
                -Hint "Federation Service Identifier - from AD FS Management -> Service Properties" `
                -Format "http://[adfs-server]/adfs/services/trust" `
                -Validator $validateUri

            Prompt-Field "SSO URL (Passive)"  'PassiveSignInUri' `
                -Hint "Browser-based sign-in endpoint (WS-Fed / SAML HTTP-Redirect)" `
                -Format "https://[adfs-server]/adfs/ls/" `
                -Validator $validateHttpsUrl

            Prompt-Field "Sign-Out URL"       'SignOutUri'       `
                -Hint "WS-Fed sign-out endpoint" `
                -Format "https://[adfs-server]/adfs/ls/?wa=wsignout1.0" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "WS-Trust endpoint (Active)" 'ActiveSignInUri' `
                -Hint "For Outlook / legacy clients that use basic auth over WS-Trust" `
                -Format "https://[adfs-server]/adfs/services/trust/2005/usernamemixed" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "Display name"       'DisplayName'      `
                -Hint "Text shown on the Microsoft sign-in page (optional)" `
                -Format "e.g. Corporate SSO" `
                -Required $false
        }

        default {
            Prompt-Field "Provider name"      'ProviderName'    `
                -Hint "Descriptive name for this IdP" `
                -Format "e.g. Contoso IdP"

            Prompt-Field "Entity ID (Issuer URI)" 'IssuerUri'   `
                -Hint "Unique URI identifying the IdP - from SAML metadata EntityDescriptor entityID attribute" `
                -Format "URI or URL - exact value from IdP metadata" `
                -Validator $validateUri

            Prompt-Field "SSO URL"            'PassiveSignInUri' `
                -Hint "HTTP-Redirect or HTTP-POST SingleSignOnService Location from IdP metadata" `
                -Format "https://[idp-server]/saml/sso  (exact value from IdP metadata)" `
                -Validator $validateHttpsUrl

            Prompt-Field "Sign-Out URL"       'SignOutUri'       `
                -Hint "SingleLogoutService Location from IdP metadata (optional)" `
                -Format "https://[idp-server]/saml/slo" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "WS-Trust endpoint"  'ActiveSignInUri'  `
                -Hint "Only needed for non-browser clients. Leave blank if not supported by this IdP." `
                -Format "(leave blank unless explicitly documented by IdP)" `
                -Required $false -Validator $validateHttpsUrl

            Prompt-Field "Display name"       'DisplayName'      `
                -Hint "Text shown on the Microsoft sign-in page (optional)" `
                -Format "e.g. Sign in with [Company] SSO" `
                -Required $false
        }
    }

    # ── Signing certificate ──────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  -- Signing Certificate -------------------------------------------------------" -ForegroundColor DarkYellow
    Write-Host ""

    if ($cfg['SigningCertificate']) {
        Write-OK "  Certificate already loaded (from metadata XML import or previous entry)."
        Write-Info "  Press Enter at the prompt below to confirm it, or paste a new one to replace."
        Write-Host ""
    }

    switch -Wildcard ($providerName) {
        'WatchGuard AuthPoint' {
            Write-Info "  Preferred: download the AuthPoint SAML metadata XML and copy the text"
            Write-Info "    inside the <X509Certificate>...</X509Certificate> element - no headers."
            Write-Info "  Alternative: Configure -> AuthPoint -> Resources -> [your resource]"
            Write-Info "    scroll to 'X.509 Certificate' and copy the base64 text block shown there."
        }
        'Okta' {
            Write-Info "  Preferred: from Okta's IdP metadata XML, copy the <X509Certificate> value - no headers."
            Write-Info "  Alternative: Applications -> [app] -> Sign On tab -> 'Download certificate'"
            Write-Info "    (.cert file is PEM format - this wizard will strip the BEGIN/END lines automatically)."
        }
        'Active Directory Federation Services (ADFS)' {
            Write-Info "  Option 1 (easiest): open https://[adfs-server]/federationmetadata/2007-06/"
            Write-Info "    federationmetadata.xml and copy the <X509Certificate> value - no headers."
            Write-Info "  Option 2: ADFS Management -> Service -> Certificates -> Token-signing certificate"
            Write-Info "    -> right-click -> View Certificate -> Details -> Copy to File."
            Write-Info "    Use FILE below and select the exported .cer - both Base-64 and DER binary"
            Write-Info "    formats are supported."
        }
        default {
            Write-Info "  Preferred: from your IdP's SAML metadata XML, copy the text inside"
            Write-Info "    <X509Certificate>...</X509Certificate> - this is raw base64, no headers needed."
            Write-Info "  Alternative: download the signing certificate file and use the FILE option below."
        }
    }

    Write-Host ""
    Write-Info "  Three ways to enter the certificate:"
    Write-Info "    1. Paste raw base64 directly (from <X509Certificate> in IdP metadata XML)"
    Write-Info "    2. Paste PEM text (-----BEGIN CERTIFICATE----- lines will be stripped)"
    Write-Info "    3. Type FILE to open a file picker (.cer / .pem / .crt - PEM and DER binary supported)"
    Write-Info "    Type SKIP to leave blank and continue (federation will fail without a certificate)."
    Write-Host ""

    # ── Helper: detect and reject clearly wrong PEM types (defined once outside loop)
    function Test-WrongPemType {
        param([string]$text)
        if ($text -match '-----BEGIN.*PRIVATE KEY-----') {
            Write-Fail "  This is a PRIVATE KEY - federation needs the public signing certificate, not the key."
            return $true
        }
        if ($text -match '-----BEGIN PKCS7-----' -or $text -match '-----BEGIN CMS-----') {
            Write-Fail "  This is a PKCS#7/CMS bundle - extract the single signing certificate from your IdP portal."
            return $true
        }
        if ($text -match '-----BEGIN.*PUBLIC KEY-----' -and $text -notmatch '-----BEGIN CERTIFICATE-----') {
            Write-Fail "  This is a raw public key, not an X.509 certificate. Get the signing certificate from your IdP."
            return $true
        }
        return $false
    }

    $certInput = ''
    $certDone  = $false
    while (-not $certDone) {
        $certCurrent = if ($cfg['SigningCertificate']) { " [existing - $($cfg['SigningCertificate'].Length) chars, Enter to keep]" } else { '' }
        $certRaw     = (Read-Host "  Certificate$certCurrent").Trim()

        # Keep existing - re-validate before accepting
        if (-not $certRaw -and $cfg['SigningCertificate']) {
            $existingInput = $cfg['SigningCertificate']
            $existingOk    = $false
            try {
                $existingBytes = [System.Convert]::FromBase64String($existingInput)
                if ($existingBytes.Count -lt 300) {
                    Write-Warn "  Existing certificate is only $($existingBytes.Count) decoded bytes - too short to be valid."
                    Write-Warn "  Real signing certificates decode to at least 300+ bytes (typically 1000-3000+)."
                    if (Confirm-YesNo "  Keep this certificate anyway" -Default 'no') { $existingOk = $true }
                } else {
                    try {
                        $x509ex     = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($existingBytes)
                        $daysLeftEx = ($x509ex.NotAfter - (Get-Date)).Days
                        Write-OK   "  Existing cert: $($x509ex.Subject)"
                        Write-Info "  Thumbprint   : $($x509ex.Thumbprint)"
                        if ($daysLeftEx -lt 0) {
                            Write-Fail "  EXPIRED $([Math]::Abs($daysLeftEx)) day(s) ago ($($x509ex.NotAfter.ToString('yyyy-MM-dd'))) - update the cert in your IdP."
                        } elseif ($daysLeftEx -lt 30) {
                            Write-Warn "  Expires in $daysLeftEx day(s) ($($x509ex.NotAfter.ToString('yyyy-MM-dd'))) - renew immediately."
                        } else {
                            Write-OK  "  Valid until $($x509ex.NotAfter.ToString('yyyy-MM-dd')) ($daysLeftEx days remaining)"
                        }
                        $existingOk = $true
                    } catch {
                        Write-Warn "  Existing certificate could not be verified as X.509."
                        if (Confirm-YesNo "  Keep anyway" -Default 'no') { $existingOk = $true }
                    }
                }
            } catch {
                Write-Fail "  Existing certificate is not valid base64 - must be re-entered."
                $cfg['SigningCertificate'] = ''
                # fall through to re-prompt
            }
            if ($existingOk) {
                Write-Info "  Keeping existing certificate."
                $certInput = $existingInput
                $certDone  = $true
            }
            continue
        }

        # Skip (no existing either)
        if (-not $certRaw) {
            Write-Warn "  No certificate provided - federation will likely fail."
            $certDone = $true
            continue
        }

        # Escape hatch - SKIP / Q / QUIT / BACK / CANCEL all exit the loop cleanly
        if ($certRaw -in 'skip','q','quit','exit','back','cancel') {
            if ($cfg['SigningCertificate']) {
                Write-Info "  Keeping existing certificate."
                $certInput = $cfg['SigningCertificate']
            } else {
                Write-Warn "  Certificate skipped - federation will fail without a signing certificate."
                $certInput = ''
            }
            $certDone = $true
            continue
        }

        # FILE path - open Windows file picker, fall back to manual entry if GUI unavailable
        if ($certRaw -ieq 'FILE') {
            $certPath = ''
            try {
                Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
                $dialog                  = New-Object System.Windows.Forms.OpenFileDialog
                $dialog.Title            = 'Select IdP Signing Certificate'
                $dialog.Filter           = 'Certificate files (*.cer;*.crt;*.pem;*.cert;*.p7b)|*.cer;*.crt;*.pem;*.cert;*.p7b|All files (*.*)|*.*'
                $dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
                $dialog.CheckFileExists  = $true
                Write-Info "  Opening file picker..."
                if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $certPath = $dialog.FileName
                    Write-Info "  Selected: $certPath"
                } else {
                    Write-Warn "  File selection cancelled."
                    continue
                }
            } catch {
                # No GUI available (headless / SSH) - fall back to typed path
                Write-Info "  (File picker unavailable - enter path manually)"
                $certPath = (Read-Host "  Certificate file path").Trim().Trim('"')
                if (-not $certPath) {
                    Write-Warn "  No path entered."
                    continue
                }
            }

            if (-not (Test-Path $certPath)) {
                Write-Fail "  File not found: $certPath"
                continue
            }
            $rawBytes = [System.IO.File]::ReadAllBytes($certPath)
            # DER binary: starts with 0x30 (ASN.1 SEQUENCE) and no printable PEM text
            if ($rawBytes.Count -gt 2 -and $rawBytes[0] -eq 0x30 -and $rawBytes[1] -ne 0x2D) {
                $certInput = [System.Convert]::ToBase64String($rawBytes)
                Write-OK   "  Format: DER binary"
                Write-Info "  Converted: base64-encoded $($rawBytes.Count) bytes -> single-line base64 for Graph API"
            } else {
                $fileText = [System.Text.Encoding]::UTF8.GetString($rawBytes)
                if (Test-WrongPemType $fileText) { continue }
                $hasPemHeaders = $fileText -match '-----BEGIN'
                $certInput = $fileText `
                    -replace '-----BEGIN[^-]*-----', '' `
                    -replace '-----END[^-]*-----',   '' `
                    -replace '\s', ''
                if ($hasPemHeaders) {
                    Write-OK   "  Format: PEM (with headers)"
                    Write-Info "  Converted: headers stripped, line breaks removed -> single-line base64 for Graph API"
                } else {
                    Write-OK   "  Format: base64 text file"
                    Write-Info "  Converted: whitespace removed -> single-line base64 for Graph API"
                }
            }
        } else {
            # Pasted value - detect format, warn on wrong types, normalise and report
            if (Test-WrongPemType $certRaw) { continue }

            $hasPemHeaders   = $certRaw -match '-----BEGIN'
            $hasLineWrapping = $certRaw -match '[\r\n]'

            $certInput = $certRaw `
                -replace '-----BEGIN[^-]*-----', '' `
                -replace '-----END[^-]*-----',   '' `
                -replace '\s', ''

            if ($hasPemHeaders) {
                Write-OK   "  Format: PEM (with headers)"
                Write-Info "  Converted: headers stripped, line breaks removed -> single-line base64 for Graph API"
            } elseif ($hasLineWrapping) {
                Write-OK   "  Format: line-wrapped base64"
                Write-Info "  Converted: line breaks removed -> single-line base64 for Graph API"
            }
            # else: already single-line raw base64 - no message needed
        }

        # ── Validate base64 ───────────────────────────────────────────────────
        $certBytes = $null
        try {
            $certBytes = [System.Convert]::FromBase64String($certInput)
        } catch {
            Write-Fail "  Not valid base64 - check you copied only the certificate data."
            Write-Info "  No BEGIN/END header lines, no spaces, no extra characters."
            continue  # re-prompt
        }

        # Sanity-check length - real X.509 certs decode to at least ~300 bytes (typically 1000-3000+)
        if ($certBytes.Count -lt 300) {
            Write-Fail "  Decoded to only $($certBytes.Count) bytes - too short to be a valid certificate."
            Write-Info "  Real signing certificates are typically 1000-3000+ bytes when decoded."
            continue  # re-prompt
        }

        # ── Try X.509 parse ───────────────────────────────────────────────────
        try {
            $x509     = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
            $daysLeft = ($x509.NotAfter - (Get-Date)).Days
            Write-OK   "  Subject    : $($x509.Subject)"
            Write-Info "  Thumbprint : $($x509.Thumbprint)"
            if ($daysLeft -lt 0) {
                Write-Fail "  EXPIRED $([Math]::Abs($daysLeft)) day(s) ago ($($x509.NotAfter.ToString('yyyy-MM-dd'))) - update the cert in your IdP before federating."
            } elseif ($daysLeft -lt 30) {
                Write-Warn "  Expires in $daysLeft day(s) ($($x509.NotAfter.ToString('yyyy-MM-dd'))) - renew immediately."
            } elseif ($daysLeft -lt 90) {
                Write-Warn "  Expires in $daysLeft day(s) ($($x509.NotAfter.ToString('yyyy-MM-dd'))) - plan renewal."
            } else {
                Write-OK  "  Valid until $($x509.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days remaining)"
            }
            $certDone = $true
        } catch {
            # Valid base64 and correct length but not a parseable X.509 DER cert.
            # This can happen with some non-standard encodings; let the user decide.
            Write-Warn "  Decoded from base64 ($($certBytes.Count) bytes) but could not verify as X.509."
            Write-Info "  Make sure you copied the signing certificate, not a private key or CA bundle."
            if (Confirm-YesNo "  Accept this certificate data anyway" -Default 'no') {
                $certDone = $true
            }
            # else loop back and re-prompt
        }
    }
    $cfg['SigningCertificate'] = $certInput

    # ── MFA behavior ─────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  -- MFA Behavior --------------------------------------------------------------" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Info "  How should Microsoft 365 / Entra ID handle MFA claims from this IdP?"
    Write-Host ""

    $mfaCurrent = $cfg['FederatedIdpMfaBehavior']
    $mfaLabels  = @{
        '1' = 'enforceMfaByFederatedIdp'
        '2' = 'acceptIfMfaDoneByFederatedIdp'
        '3' = 'rejectMfaByFederatedIdp'
    }
    $mfaDescriptions = @{
        'enforceMfaByFederatedIdp'         = 'IdP is the MFA authority. Entra trusts IdP MFA claims completely.'
        'acceptIfMfaDoneByFederatedIdp'    = 'Accept MFA if IdP performed it, but Entra may also enforce its own MFA policy.'
        'rejectMfaByFederatedIdp'          = 'Ignore IdP MFA entirely. Entra Conditional Access handles all MFA challenges.'
    }

    # Show current selection and label recommendations
    $mfaRec = switch -Wildcard ($providerName) {
        'WatchGuard AuthPoint' { '1' }
        'Okta'                 { '2' }
        default                { '2' }
    }
    foreach ($k in '1','2','3') {
        $label = $mfaLabels[$k]
        $desc  = $mfaDescriptions[$label]
        $rec   = if ($k -eq $mfaRec) { ' <-- recommended for this IdP' } else { '' }
        $mark  = if ($mfaCurrent -eq $label) { '*' } else { ' ' }
        Write-Host "    [$k]$mark $label" -ForegroundColor White
        Write-Host "         $desc$rec" -ForegroundColor Gray
        Write-Host ""
    }

    $mfaChoice = Read-MenuChoice "MFA behavior" -Valid @('1','2','3')
    $cfg['FederatedIdpMfaBehavior'] = $mfaLabels[$mfaChoice]

    return $cfg
}

function Show-SamlProviderMenu {
    Write-Section "Configure SAML Provider"

    $templates = @{
        '1' = @{
            ProviderName                    = 'WatchGuard AuthPoint'
            DisplayName                     = 'WatchGuard AuthPoint'
            PreferredAuthenticationProtocol = 'saml'
            FederatedIdpMfaBehavior         = 'enforceMfaByFederatedIdp'
            IssuerUri                       = ''
            PassiveSignInUri                = ''
            ActiveSignInUri                 = ''
            SignOutUri                      = ''
            SigningCertificate              = ''
        }
        '2' = @{
            ProviderName                    = 'Okta'
            DisplayName                     = 'Okta'
            PreferredAuthenticationProtocol = 'saml'
            FederatedIdpMfaBehavior         = 'acceptIfMfaDoneByFederatedIdp'
            IssuerUri                       = ''
            PassiveSignInUri                = ''
            ActiveSignInUri                 = ''
            SignOutUri                      = ''
            SigningCertificate              = ''
        }
        '3' = @{
            ProviderName                    = 'Active Directory Federation Services (ADFS)'
            DisplayName                     = 'Corporate SSO'
            PreferredAuthenticationProtocol = 'wsFed'
            FederatedIdpMfaBehavior         = 'acceptIfMfaDoneByFederatedIdp'
            IssuerUri                       = ''
            PassiveSignInUri                = ''
            ActiveSignInUri                 = ''
            SignOutUri                      = ''
            SigningCertificate              = ''
        }
        '4' = @{
            ProviderName                    = 'Generic SAML 2.0 IdP'
            DisplayName                     = ''
            PreferredAuthenticationProtocol = 'saml'
            FederatedIdpMfaBehavior         = 'acceptIfMfaDoneByFederatedIdp'
            IssuerUri                       = ''
            PassiveSignInUri                = ''
            ActiveSignInUri                 = ''
            SignOutUri                      = ''
            SigningCertificate              = ''
        }
    }

    Write-Host "  Select your SAML Identity Provider:" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    [1]  WatchGuard AuthPoint" -ForegroundColor White
    Write-Host "    [2]  Okta" -ForegroundColor White
    Write-Host "    [3]  Active Directory Federation Services (ADFS)" -ForegroundColor White
    Write-Host "    [4]  Generic SAML 2.0 (manual entry)" -ForegroundColor White
    Write-Host "    [B]  Back to main menu" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-MenuChoice "Select provider" -Valid @('1','2','3','4','B','b')
    if ($choice -in 'B','b') { return }

    $template = $templates[$choice]

    if ($choice -eq '1') {
        Write-Host ""
        Write-Host "  +- WatchGuard AuthPoint - Setup Guide ---------------------------------+" -ForegroundColor DarkYellow
        Write-Host "  |                                                                       |" -ForegroundColor DarkYellow
        Write-Host "  |  In your AuthPoint portal, navigate to:                               |" -ForegroundColor DarkYellow
        Write-Host "  |    Resources -> SAML Authentication -> Add Resource -> Office 365        |" -ForegroundColor DarkYellow
        Write-Host "  |                                                                       |" -ForegroundColor DarkYellow
        Write-Host "  |  You will need the following values from AuthPoint SAML metadata:     |" -ForegroundColor DarkYellow
        Write-Host "  |    * Entity ID (Issuer URI)                                           |" -ForegroundColor DarkYellow
        Write-Host "  |    * Sign-On URL (SSO / Passive logon URL)                            |" -ForegroundColor DarkYellow
        Write-Host "  |    * Sign-Out URL (logout URL)                                        |" -ForegroundColor DarkYellow
        Write-Host "  |    * X.509 Signing Certificate                                        |" -ForegroundColor DarkYellow
        Write-Host "  |                                                                       |" -ForegroundColor DarkYellow
        Write-Host "  |  Reference: watchguard.com -> Help -> Integration Guides -> AuthPoint    |" -ForegroundColor DarkYellow
        Write-Host "  |             -> Office 365 and AuthPoint                                |" -ForegroundColor DarkYellow
        Write-Host "  |                                                                       |" -ForegroundColor DarkYellow
        Write-Host "  +-----------------------------------------------------------------------+" -ForegroundColor DarkYellow
    }

    if ($choice -eq '3') {
        Write-Host ""
        Write-Warn "ADFS uses WS-Federation protocol. Ensure PreferredAuthProtocol stays as WsFed."
        Write-Info "ADFS federation endpoints are typically:"
        Write-Info "  Passive:  https://<adfs-server>/adfs/ls/"
        Write-Info "  Active:   https://<adfs-server>/adfs/services/trust/2005/usernamemixed"
        Write-Info "  Issuer:   http://<adfs-server>/adfs/services/trust"
    }

    $script:SamlConfig = Get-SamlConfigFromUser -Template $template
    Write-Log "SAML provider configured: $($script:SamlConfig.ProviderName)"
    Write-OK "SAML provider configuration saved: $($script:SamlConfig.ProviderName)"
}

function Show-SamlConfigSummary {
    if (-not $script:SamlConfig) {
        Write-Warn "No SAML provider configured yet."
        return
    }
    $c = $script:SamlConfig
    Write-Section "Current SAML Configuration"
    Write-Info "Provider Name  : $($c.ProviderName)"
    Write-Info "Display Name   : $($c.DisplayName)"
    Write-Info "Issuer URI     : $($c.IssuerUri)"
    Write-Info "SSO URL        : $($c.PassiveSignInUri)"
    Write-Info "Sign-Out URL   : $($c.SignOutUri)"
    Write-Info "WS-Trust URL   : $(if ($c.ActiveSignInUri) { $c.ActiveSignInUri } else { '(not set)' })"
    Write-Info "Protocol       : $($c.PreferredAuthenticationProtocol)"
    Write-Info "MFA Behavior   : $($c.FederatedIdpMfaBehavior)"
    $certLen = if ($c.SigningCertificate) { "$($c.SigningCertificate.Length) chars" } else { "NOT SET" }
    Write-Info "Certificate    : $certLen"
}
#endregion

#region -- Domain Selection ----------------------------------------------------
function Show-DomainSelectionMenu {
    if (-not $script:Connected) {
        Write-Warn "Not connected to Microsoft 365. Please connect first."
        Pause-ForUser
        return
    }

    Write-Section "Select Domains to Federate"

    # Refresh domain list
    try {
        $script:TenantDomains = Get-MgDomain -ErrorAction Stop
    } catch {
        Write-Fail "Failed to retrieve domains: $_"
        Pause-ForUser
        return
    }

    # Only show verified, non-onmicrosoft domains as candidates
    $candidates = $script:TenantDomains | Where-Object {
        $_.IsVerified -eq $true -and
        $_.Id -notlike '*.onmicrosoft.com'
    } | Sort-Object Id

    if (-not $candidates) {
        Write-Warn "No verified custom domains found in this tenant."
        Write-Info "Ensure your domains are verified in Microsoft 365 admin center first."
        Pause-ForUser
        return
    }

    Write-Host "  Verified custom domains in tenant:" -ForegroundColor Gray
    Write-Host ""

    $i = 1
    $indexMap = @{}
    foreach ($d in $candidates) {
        $authType   = $d.AuthenticationType
        $authColor  = if ($authType -eq 'Federated') { 'Cyan' } elseif ($authType -eq 'Managed') { 'Green' } else { 'Gray' }
        $selected   = if ($d.Id -in $script:SelectedDomains) { '*' } else { ' ' }
        $defaultTag = if ($d.IsDefault) { '  [DEFAULT - cannot federate]' } else { '' }
        $nameColor  = if ($d.IsDefault) { 'Yellow' } else { 'White' }
        Write-Host "    [$i] $($selected) " -NoNewline -ForegroundColor White
        Write-Host "$($d.Id.PadRight(45))$defaultTag" -NoNewline -ForegroundColor $nameColor
        Write-Host "  [$authType]" -ForegroundColor $authColor
        $indexMap["$i"] = $d.Id
        $i++
    }

    Write-Host ""
    Write-Host "  Currently selected: " -NoNewline -ForegroundColor Gray
    if ($script:SelectedDomains.Count -gt 0) {
        Write-Host ($script:SelectedDomains -join ', ') -ForegroundColor DarkYellow
    } else {
        Write-Host "(none)" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Info "Enter domain numbers to toggle selection (comma-separated, e.g. 1,3,4)."
    Write-Info "Type ALL to select all custom domains, or CLEAR to deselect all."
    Write-Info "Type DONE when finished, or BACK to cancel."
    Write-Host ""

    $userSelection = (Read-Host "  Selection").Trim().ToUpper()

    switch ($userSelection) {
        'DONE' { return }
        'BACK' { return }
        'CLEAR' {
            $script:SelectedDomains = @()
            Write-OK "Selection cleared."
        }
        'ALL' {
            $nonDefault = @($candidates | Where-Object { -not $_.IsDefault } | ForEach-Object { $_.Id })
            $skipped    = @($candidates | Where-Object { $_.IsDefault })
            $script:SelectedDomains = $nonDefault
            Write-OK "Selected $($nonDefault.Count) domain(s)."
            foreach ($sd in $skipped) {
                Write-Warn "Skipped $($sd.Id) - it is the DEFAULT domain and cannot be federated."
                Write-Info "  Use option [5] Change Default Domain to designate a different domain as default first."
            }
        }
        default {
            $nums = $userSelection -split ',' |
                ForEach-Object { $_.Trim() } |
                Where-Object   { $_ -ne '' }
            foreach ($n in $nums) {
                if ($indexMap.ContainsKey($n)) {
                    $domName = $indexMap[$n]
                    $domObj  = $candidates | Where-Object { $_.Id -eq $domName } | Select-Object -First 1
                    if (-not $domObj) { Write-Warn "Could not look up domain for selection $n."; continue }
                    if ($domObj.IsDefault) {
                        Write-Warn "$domName is the DEFAULT domain and cannot be federated."
                        Write-Info "  Microsoft 365 requires at least one non-federated default domain."
                        Write-Info "  Use option [5] Change Default Domain to set a different domain as default first."
                    } elseif ($domName -in $script:SelectedDomains) {
                        $script:SelectedDomains = @($script:SelectedDomains | Where-Object { $_ -ne $domName })
                        Write-Info "Deselected: $domName"
                    } else {
                        $script:SelectedDomains += $domName
                        Write-Info "Selected:   $domName"
                    }
                } else {
                    Write-Warn "Invalid number: $n"
                }
            }
        }
    }

    Write-Log "Domain selection updated: $($script:SelectedDomains -join ', ')"
    Pause-ForUser
}
#endregion

#region -- Admin UPN Safety Check ---------------------------------------------
function Invoke-AdminUPNSafetyCheck {
    Write-Section "Admin Account Safety Check"

    if (-not $script:Connected) {
        Write-Warn "Not connected to Microsoft 365. Please connect first."
        Pause-ForUser
        return
    }
    if ($script:SelectedDomains.Count -eq 0) {
        Write-Warn "No domains selected yet. Select domains first."
        Pause-ForUser
        return
    }
    if (-not $script:AdminUpn) {
        Write-Warn "Admin UPN not set. Reconnect to M365 to provide your admin UPN."
        Pause-ForUser
        return
    }

    $adminDomain = $script:AdminUpn.Split('@')[-1].ToLower()
    $atRisk = $adminDomain -in ($script:SelectedDomains | ForEach-Object { $_.ToLower() })

    Write-Info "Your admin account : $script:AdminUpn"
    Write-Info "Account domain     : $adminDomain"
    Write-Info "Domains to federate: $($script:SelectedDomains -join ', ')"
    Write-Host ""

    # -- Global Administrator listing (visibility / reporting) ────────────────
    Write-Step "Retrieving Global Administrator accounts..."
    $gaTemplateId = '62e90394-69f5-4237-9190-012177145e10'  # well-known GA role template ID
    $gaRole       = $null
    try {
        # Try filtered query first (faster); fall back to listing all roles
        $gaRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$gaTemplateId'" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $gaRole) {
            $gaRole = Get-MgDirectoryRole -ErrorAction Stop |
                Where-Object { $_.RoleTemplateId -eq $gaTemplateId } |
                Select-Object -First 1
        }
    } catch {
        $gaRole = $null
    }

    $atRiskAdmins = @()
    if ($gaRole) {
        try {
            $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop

            # Resolve each member to a user object (skip service principals / groups)
            $gaUsers = foreach ($m in $gaMembers) {
                $odt = $m.AdditionalProperties['@odata.type']
                if ($odt -and $odt -ne '#microsoft.graph.user') { continue }
                try {
                    Get-MgUser -UserId $m.Id -Property 'DisplayName,UserPrincipalName,AccountEnabled' -ErrorAction Stop
                } catch { $null }
            }
            $gaUsers = @($gaUsers | Where-Object { $_ } | Sort-Object UserPrincipalName)

            Write-Host ""
            Write-Host "  -- Global Administrators ($($gaUsers.Count) account(s)) ----------------------------" -ForegroundColor DarkYellow
            Write-Host ""
            Write-Host ("    " + "Display Name".PadRight(30) + "UPN".PadRight(44) + "Status") -ForegroundColor Gray
            Write-Host ("    " + "-" * 82) -ForegroundColor Gray

            foreach ($u in $gaUsers) {
                $upn     = $u.UserPrincipalName
                $upnDom  = $upn.Split('@')[-1].ToLower()
                $risk    = ($script:SelectedDomains.Count -gt 0) -and
                           ($upnDom -in ($script:SelectedDomains | ForEach-Object { $_.ToLower() }))
                $enabled = if ($u.AccountEnabled) { 'Enabled' } else { 'Disabled' }

                $dn     = if ($u.DisplayName.Length -gt 28) { $u.DisplayName.Substring(0,27) + '~' } else { $u.DisplayName }
                $upnStr = if ($upn.Length -gt 42)           { $upn.Substring(0,41) + '~' }           else { $upn }

                $nameCol = $dn.PadRight(30)
                $upnCol  = $upnStr.PadRight(44)

                if ($risk) {
                    Write-Host "    $nameCol$upnCol$enabled  [LOCKOUT RISK]" -ForegroundColor Red
                    $atRiskAdmins += $upn
                } elseif (-not $u.AccountEnabled) {
                    Write-Host "    $nameCol$upnCol$enabled" -ForegroundColor DarkGray
                } else {
                    Write-Host "    $nameCol$upnCol$enabled" -ForegroundColor White
                }
            }

            Write-Host ""
            if ($script:SelectedDomains.Count -gt 0) {
                if ($atRiskAdmins.Count -gt 0) {
                    Write-Warn "$($atRiskAdmins.Count) admin account(s) above are on domains being federated and will be locked out."
                } else {
                    Write-OK "No Global Admin accounts are on domains being federated."
                }
            }
            Write-Log "Global Admins: $($gaUsers.Count) total. At-risk: $(if ($atRiskAdmins.Count -gt 0) { $atRiskAdmins -join ', ' } else { 'none' })"
        } catch {
            Write-Warn "Could not retrieve Global Administrator members: $_"
            Write-Info "The RoleManagement.Read.Directory scope may not have been consented."
            Write-Info "Reconnect (option 1) to re-consent and try again."
        }
    } else {
        Write-Warn "Could not locate the Global Administrator role in this tenant."
        Write-Info "Reconnect (option 1) to re-consent the RoleManagement.Read.Directory scope."
    }

    Write-Host ""
    # ── per-admin lockout check for the currently signed-in account ───────────

    if (-not $atRisk) {
        Write-OK "Your admin account domain is NOT in the list of domains to federate."
        Write-OK "No lockout risk detected. You are safe to proceed."
        Pause-ForUser
        return
    }

    Write-Host ""
    Write-Host "  +======================================================================+" -ForegroundColor Red
    Write-Host "  |  WARNING: ADMIN LOCKOUT RISK DETECTED                               |" -ForegroundColor Red
    Write-Host "  +======================================================================+" -ForegroundColor Red
    Write-Host "  |                                                                      |" -ForegroundColor Red
    Write-Host "  |  Your admin account ($($script:AdminUpn.PadRight(40))) |" -ForegroundColor Red
    Write-Host "  |  uses the domain [$adminDomain] which is in your                  |" -ForegroundColor Red
    Write-Host "  |  federation list. After federation, logins to Microsoft 365 for     |" -ForegroundColor Red
    Write-Host "  |  this domain will redirect to your SAML IdP.                        |" -ForegroundColor Red
    Write-Host "  |                                                                      |" -ForegroundColor Red
    Write-Host "  |  IF the IdP is not yet configured correctly, you will be LOCKED      |" -ForegroundColor Red
    Write-Host "  |  OUT of your admin account.                                          |" -ForegroundColor Red
    Write-Host "  |                                                                      |" -ForegroundColor Red
    Write-Host "  |  RECOMMENDED: Change your admin UPN to the .onmicrosoft.com domain   |" -ForegroundColor Red
    Write-Host "  |  BEFORE federating. Use a UPN like:                                  |" -ForegroundColor Red
    Write-Host "  |    admin@$($script:OnMicrosoftDomain.PadRight(54)) |" -ForegroundColor Red
    Write-Host "  |                                                                      |" -ForegroundColor Red
    Write-Host "  +======================================================================+" -ForegroundColor Red
    Write-Host ""

    if (-not (Confirm-YesNo "Change your UPN to @$($script:OnMicrosoftDomain) now")) {
        Write-Warn "UPN change skipped. Proceeding without this safety measure is risky."
        Write-Warn "You may proceed, but ensure your SAML IdP is fully configured before applying."
        Write-Log "Safety check: UPN change DECLINED for $script:AdminUpn"
        Pause-ForUser
        return
    }

    # Build the new UPN
    $localPart    = $script:AdminUpn.Split('@')[0]
    $newUpn       = "$localPart@$($script:OnMicrosoftDomain)"

    Write-Host ""
    Write-Info "Current UPN : $script:AdminUpn"
    Write-Info "New UPN     : $newUpn"
    Write-Host ""
    Write-Warn "This will change your admin account UPN. Your current session will continue,"
    Write-Warn "but future logins must use $newUpn."
    Write-Host ""

    if (-not (Confirm-Dangerous "Change UPN from $script:AdminUpn to $newUpn")) {
        Write-Warn "UPN change cancelled."
        Pause-ForUser
        return
    }

    try {
        Update-MgUser -UserId $script:AdminUpn -UserPrincipalName $newUpn -ErrorAction Stop
        Write-OK "UPN changed successfully."
        Write-OK "New admin UPN: $newUpn"
        Write-Log "UPN changed: $script:AdminUpn -> $newUpn"
        $script:AdminUpn = $newUpn
        Write-Warn "IMPORTANT: Your next login to Microsoft 365 must use: $newUpn"
    } catch {
        Write-Fail "Failed to change UPN: $_"
        Write-Info "You may need to change the UPN manually in the Microsoft 365 admin center."
        Write-Log "UPN change FAILED for $script:AdminUpn : $_"
    }

    Pause-ForUser
}
#endregion

#region -- Pre-Flight Review ---------------------------------------------------
function Show-PreFlightReview {
    Write-Section "Pre-Flight Review"

    $errors = @()

    if (-not $script:Connected)               { $errors += "Not connected to Microsoft 365" }
    if ($script:SelectedDomains.Count -eq 0)  { $errors += "No domains selected" }
    if (-not $script:SamlConfig)              { $errors += "SAML provider not configured" }

    # Live probe for Domain.ReadWrite.All using a selected/custom domain
    # (.onmicrosoft.com has no federationConfiguration endpoint - must use a real custom domain)
    if ($script:Connected) {
        $pfProbeDomain = $null
        # Prefer one of the domains we're about to federate; fall back to any verified custom domain
        if ($script:SelectedDomains.Count -gt 0) {
            $pfProbeDomain = $script:SelectedDomains[0]
        } else {
            $pfProbeDomain = ($script:TenantDomains |
                Where-Object { $_.Id -notlike '*.onmicrosoft.com' -and $_.IsVerified -eq $true } |
                Select-Object -First 1).Id
        }
        if ($pfProbeDomain) {
            try {
                $pfProbeUri = "https://graph.microsoft.com/v1.0/domains/$pfProbeDomain/federationConfiguration"
                Invoke-MgGraphRequest -Method GET -Uri $pfProbeUri -ErrorAction Stop | Out-Null
            } catch {
                $pfProbeErr = "$_"
                if ($pfProbeErr -match '403|Forbidden|Authorization_RequestDenied|Insufficient') {
                    # 403 = permission genuinely denied
                    $errors += "Domain-InternalFederation.ReadWrite.All permission denied (403 on probe). Use option [1] to reconnect and accept the consent prompt. If this persists, grant admin consent in Entra ID: Enterprise Applications -> 'Microsoft Graph Command Line Tools' -> Permissions -> Grant admin consent."
                }
                # 404/Request_ResourceNotFound = domain exists, no federation config yet = permission OK
                # Any other error is not treated as a permission failure
            }
        }
    }
    if ($script:SamlConfig -and -not $script:SamlConfig.IssuerUri)          { $errors += "SAML Issuer URI is empty" }
    if ($script:SamlConfig -and -not $script:SamlConfig.PassiveSignInUri)   { $errors += "SAML SSO URL (PassiveSignInUri) is empty" }
    if ($script:SamlConfig -and -not $script:SamlConfig.SigningCertificate) {
        $errors += "Signing certificate is empty"
    } elseif ($script:SamlConfig -and $script:SamlConfig.SigningCertificate) {
        # Validate the stored cert is plausible before attempting federation
        try {
            $pfCertBytes = [System.Convert]::FromBase64String($script:SamlConfig.SigningCertificate)
            if ($pfCertBytes.Count -lt 300) {
                $errors += "Signing certificate decodes to only $($pfCertBytes.Count) bytes - too short to be valid. Re-enter the certificate in SAML Provider setup (option [2])."
            } else {
                try {
                    [void][System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfCertBytes)
                } catch {
                    $errors += "Signing certificate is not a valid X.509 certificate. Re-enter it in SAML Provider setup (option [2])."
                }
            }
        } catch {
            $errors += "Signing certificate is not valid base64. Re-enter it in SAML Provider setup (option [2])."
        }
    }

    # Default domain check - M365 will reject federation of the tenant default domain
    if ($script:Connected -and $script:SelectedDomains.Count -gt 0) {
        $defaultInSelection = $script:TenantDomains | Where-Object {
            $_.IsDefault -and ($_.Id -in $script:SelectedDomains)
        }
        foreach ($dd in $defaultInSelection) {
            $errors += "Domain '$($dd.Id)' is the tenant DEFAULT domain - Microsoft 365 does not allow federating it. Use 'Change Default Domain' (option [5]) to assign a different default first."
        }
    }

    if ($errors.Count -gt 0) {
        Write-Host "  The following issues must be resolved before applying federation:" -ForegroundColor Red
        Write-Host ""
        foreach ($e in $errors) { Write-Fail $e }
        Pause-ForUser
        return $false
    }

    $c = $script:SamlConfig
    Write-Host "  +- Federation Plan -----------------------------------------------------+" -ForegroundColor DarkYellow
    Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
    Write-Host "  |  SAML Provider : $($c.ProviderName.PadRight(55)) |" -ForegroundColor DarkYellow
    Write-Host "  |  Protocol      : $($c.PreferredAuthenticationProtocol.PadRight(55)) |" -ForegroundColor DarkYellow
    $issuerDisplay = if ($c.IssuerUri) { $c.IssuerUri.Substring(0,[Math]::Min(55,$c.IssuerUri.Length)) } else { '(not set)' }
    $ssoDisplay    = if ($c.PassiveSignInUri) { $c.PassiveSignInUri.Substring(0,[Math]::Min(55,$c.PassiveSignInUri.Length)) } else { '(not set)' }
    $certDisplay   = if ($c.SigningCertificate) { "$($c.SigningCertificate.Length) chars (base64)" } else { '(not set)' }
    Write-Host "  |  Issuer URI    : $($issuerDisplay.PadRight(55)) |" -ForegroundColor DarkYellow
    Write-Host "  |  SSO URL       : $($ssoDisplay.PadRight(55)) |" -ForegroundColor DarkYellow
    Write-Host "  |  Certificate   : $($certDisplay.PadRight(55)) |" -ForegroundColor DarkYellow
    Write-Host "  |  MFA Behavior  : $($c.FederatedIdpMfaBehavior.PadRight(55)) |" -ForegroundColor DarkYellow
    Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
    Write-Host "  |  Domains to federate:                                                  |" -ForegroundColor DarkYellow
    foreach ($d in $script:SelectedDomains) {
        Write-Host "  |    * $($d.PadRight(68)) |" -ForegroundColor White
    }
    Write-Host "  |                                                                        |" -ForegroundColor DarkYellow
    Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor DarkYellow

    Write-Host ""
    Write-Warn "After federation, all sign-ins for the above domains will be redirected"
    Write-Warn "to your SAML provider. Ensure the IdP is fully configured before proceeding."
    Write-Host ""

    # Re-run lockout check silently
    $adminDomain = $script:AdminUpn.Split('@')[-1].ToLower()
    $atRisk = $adminDomain -in ($script:SelectedDomains | ForEach-Object { $_.ToLower() })
    if ($atRisk) {
        Write-Host ""
        Write-Fail "LOCKOUT RISK: Your admin account ($script:AdminUpn) is on a domain being federated!"
        Write-Fail "Run the Admin Safety Check from the menu before applying federation."
        Write-Host ""
        Pause-ForUser
        return $false
    }

    return $true
}
#endregion

#region -- Apply Federation ----------------------------------------------------
function Invoke-ApplyFederation {
    Write-Section "Apply Domain Federation"

    $ready = Show-PreFlightReview
    if (-not $ready) { return }

    if (-not (Confirm-Dangerous "federate $($script:SelectedDomains.Count) domain(s) to $($script:SamlConfig.ProviderName)")) {
        Write-Warn "Federation cancelled."
        Pause-ForUser
        return
    }

    $c = $script:SamlConfig
    $succeeded = @()
    $failed    = @()

    Write-Host ""
    foreach ($domain in $script:SelectedDomains) {
        Write-Step "Federating $domain ..."

        try {
            # If a federation config already exists for this domain, remove it first
            $existing = Get-MgDomainFederationConfiguration -DomainId $domain -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Info "  Existing federation config found - replacing..."
                Remove-MgDomainFederationConfiguration -DomainId $domain `
                    -InternalDomainFederationId $existing.Id -ErrorAction Stop
            }

            $params = @{
                DomainId                        = $domain
                IssuerUri                       = $c.IssuerUri
                PassiveSignInUri                = $c.PassiveSignInUri
                SignOutUri                      = $c.SignOutUri
                SigningCertificate              = $c.SigningCertificate
                PreferredAuthenticationProtocol = $c.PreferredAuthenticationProtocol
                FederatedIdpMfaBehavior         = $c.FederatedIdpMfaBehavior
            }
            if ($c.DisplayName)      { $params['DisplayName']      = $c.DisplayName }
            if ($c.ActiveSignInUri)  { $params['ActiveSignInUri']  = $c.ActiveSignInUri }

            New-MgDomainFederationConfiguration @params -ErrorAction Stop | Out-Null
            Write-OK "  $domain federated successfully."
            $succeeded += $domain
            Write-Log "FEDERATED: $domain  Provider: $($c.ProviderName)"
        } catch {
            $errStr = "$_"
            Write-Fail "  $domain failed: $errStr"
            $failed += $domain
            Write-Log "FEDERATION FAILED: $domain  Error: $errStr"

            # Provide targeted guidance for the most common failure modes
            if ($errStr -match '403|Forbidden|Insufficient privileges|Authorization_RequestDenied') {
                Write-Host ""
                Write-Warn "  403 Forbidden - the signed-in account lacks permission. Common causes:"
                Write-Host "    1. Account is not a Global Administrator or Domain Name Administrator" -ForegroundColor Yellow
                Write-Host "    2. 'Domain-InternalFederation.ReadWrite.All' scope not admin-consented for this session" -ForegroundColor Yellow
                Write-Host "    3. A cached token (without this scope) is being reused" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "  Resolution steps:"
                Write-Info "    a. Ensure the account is a Global Admin in Entra ID"
                Write-Info "    b. Use option [1] to reconnect - accept the permissions prompt"
                Write-Info "    c. If that fails, clear the token cache first:"
                Write-Info "       Run in a separate PS window: Disconnect-MgGraph"
                Write-Info "       Then use option [1] here to reconnect"
                Write-Host ""
            } elseif ($errStr -match '400|BadRequest|Invalid value') {
                Write-Host ""
                Write-Warn "  400 Bad Request - one or more values were rejected by Microsoft."
                Write-Info "  Use option [2] to review and correct your SAML provider settings."
                Write-Host ""
            }
        }
    }

    Write-Host ""
    Write-Host "  -- Results $("-" * 68)" -ForegroundColor DarkYellow
    Write-Host ""
    if ($succeeded.Count -gt 0) {
        Write-OK "Successfully federated ($($succeeded.Count)): $($succeeded -join ', ')"
    }
    if ($failed.Count -gt 0) {
        Write-Fail "Failed ($($failed.Count)): $($failed -join ', ')"
        if ($failed.Count -eq $succeeded.Count + $failed.Count) {
            # All failed - suggest checking connection
            Write-Info "All domains failed. If you see 403 errors above, reconnect with option [1]."
        }
    }

    Pause-ForUser
}
#endregion

#region -- Federation Status ---------------------------------------------------
function Show-FederationStatus {
    Write-Section "Domain Federation Status"

    if (-not $script:Connected) {
        Write-Warn "Not connected to Microsoft 365. Please connect first."
        Pause-ForUser
        return
    }

    try {
        $domains = Get-MgDomain -ErrorAction Stop | Sort-Object Id
    } catch {
        Write-Fail "Failed to retrieve domains: $_"
        Pause-ForUser
        return
    }

    Write-Host ("  " + "Domain".PadRight(45) + "Auth".PadRight(12) + "Verified".PadRight(10) + "Default") -ForegroundColor Gray
    Write-Host ("  " + "-" * 75) -ForegroundColor Gray

    foreach ($d in $domains) {
        $authColor   = if ($d.AuthenticationType -eq 'Federated') { 'Cyan' } elseif ($d.AuthenticationType -eq 'Managed') { 'Green' } else { 'Gray' }
        $verifyColor = if ($d.IsVerified) { 'Green' } else { 'Yellow' }
        $verifyTxt   = if ($d.IsVerified) { 'Verified' } else { 'Unverified' }
        $defaultMark = if ($d.IsDefault) { '  [DEFAULT]' } else { '' }

        Write-Host "  $($d.Id.PadRight(45))" -NoNewline -ForegroundColor White
        Write-Host "$($d.AuthenticationType.PadRight(12))" -NoNewline -ForegroundColor $authColor
        Write-Host "$($verifyTxt.PadRight(10))" -NoNewline -ForegroundColor $verifyColor
        Write-Host $defaultMark -ForegroundColor DarkYellow
    }

    # Show federation config details for federated domains
    $federated = $domains | Where-Object { $_.AuthenticationType -eq 'Federated' }
    if ($federated) {
        Write-Host ""
        Write-Host "  -- Federation Details $("-" * 57)" -ForegroundColor DarkYellow
        foreach ($fd in $federated) {
            try {
                $cfg = Get-MgDomainFederationConfiguration -DomainId $fd.Id -ErrorAction Stop
                Write-Host ""
                Write-Host "  $($fd.Id)" -ForegroundColor Cyan
                Write-Info "    Issuer URI    : $($cfg.IssuerUri)"
                Write-Info "    SSO URL       : $($cfg.PassiveSignInUri)"
                Write-Info "    Sign-Out URL  : $($cfg.SignOutUri)"
                Write-Info "    Protocol      : $($cfg.PreferredAuthenticationProtocol)"
                Write-Info "    MFA Behavior  : $($cfg.FederatedIdpMfaBehavior)"
                Write-Info "    Display Name  : $($cfg.DisplayName)"
            } catch {
                Write-Warn "  Could not retrieve details for $($fd.Id): $_"
            }
        }
    }

    Pause-ForUser
}
#endregion

#region -- Revert to Managed ---------------------------------------------------
function Invoke-RevertToManaged {
    Write-Section "Revert Domain(s) to Managed Authentication"

    if (-not $script:Connected) {
        Write-Warn "Not connected to Microsoft 365. Please connect first."
        Pause-ForUser
        return
    }

    Write-Warn "This removes SAML federation. Users will authenticate directly with Microsoft 365."
    Write-Warn "Password hash sync / SSPR must be in place or users may lose access."
    Write-Host ""

    try {
        $fedDomains = Get-MgDomain -ErrorAction Stop |
            Where-Object { $_.AuthenticationType -eq 'Federated' -and $_.Id -notlike '*.onmicrosoft.com' } |
            Sort-Object Id
    } catch {
        Write-Fail "Failed to retrieve domains: $_"
        Pause-ForUser
        return
    }

    if (-not $fedDomains) {
        Write-Info "No federated custom domains found in this tenant."
        Pause-ForUser
        return
    }

    Write-Host "  Federated domains available to revert:" -ForegroundColor Gray
    Write-Host ""

    $i = 1
    $indexMap = @{}
    foreach ($d in $fedDomains) {
        Write-Host "    [$i]  $($d.Id)" -ForegroundColor Cyan
        $indexMap["$i"] = $d.Id
        $i++
    }

    Write-Host ""
    $userInput = (Read-Host "  Enter domain number(s) to revert (comma-separated), ALL, or BACK").Trim().ToUpper()

    if ($userInput -eq 'BACK') { return }

    $toRevert = @()
    if ($userInput -eq 'ALL') {
        $toRevert = @($fedDomains | ForEach-Object { $_.Id })
    } else {
        foreach ($n in ($userInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })) {
            if ($indexMap.ContainsKey($n)) { $toRevert += $indexMap[$n] }
            else { Write-Warn "Invalid selection: $n" }
        }
    }

    if ($toRevert.Count -eq 0) {
        Write-Warn "No domains selected to revert."
        Pause-ForUser
        return
    }

    Write-Host ""
    Write-Info "Domains to revert to Managed: $($toRevert -join ', ')"
    Write-Host ""

    if (-not (Confirm-Dangerous "revert $($toRevert.Count) domain(s) to managed authentication")) {
        Write-Warn "Revert cancelled."
        Pause-ForUser
        return
    }

    foreach ($domain in $toRevert) {
        Write-Step "Reverting $domain to Managed..."
        try {
            $cfg = Get-MgDomainFederationConfiguration -DomainId $domain -ErrorAction Stop
            Remove-MgDomainFederationConfiguration -DomainId $domain `
                -InternalDomainFederationId $cfg.Id -ErrorAction Stop
            Write-OK "$domain is now Managed."
            Write-Log "REVERTED TO MANAGED: $domain"
        } catch {
            Write-Fail "Failed to revert $domain : $_"
            Write-Log "REVERT FAILED: $domain  Error: $_"
        }
    }

    Pause-ForUser
}
#endregion

#region -- Change Default Domain -----------------------------------------------
function Invoke-ChangeDefaultDomain {
    Write-Section "Change Default Domain"

    if (-not $script:Connected) {
        Write-Warn "Not connected to Microsoft 365. Please connect first."
        Pause-ForUser
        return
    }

    # Refresh domain list
    try {
        $script:TenantDomains = Get-MgDomain -ErrorAction Stop
    } catch {
        Write-Fail "Failed to retrieve domains: $_"
        Pause-ForUser
        return
    }

    $currentDefault = $script:TenantDomains | Where-Object { $_.IsDefault } | Select-Object -First 1

    Write-Host ""
    Write-Info "Microsoft 365 does not allow federating the tenant default domain."
    Write-Info "The default domain is used when assigning UPNs to new users."
    Write-Info "To federate your current default, first designate another domain as default."
    Write-Host ""
    Write-Host "  Current default domain: " -NoNewline -ForegroundColor Gray
    if ($currentDefault) {
        Write-Host $currentDefault.Id -ForegroundColor Yellow
    } else {
        Write-Host "(none detected)" -ForegroundColor DarkYellow
    }
    Write-Host ""

    # Eligible candidates: verified, not the current default, not already federated, not .mail.onmicrosoft.com
    # Include the .onmicrosoft.com domain as a safe fallback (it can never be federated so it is always safe as default)
    $eligible = $script:TenantDomains | Where-Object {
        $_.IsVerified -eq $true -and
        $_.IsDefault  -eq $false -and
        $_.Id -notlike '*.mail.onmicrosoft.com'
    } | Sort-Object {
        # Sort: non-onmicrosoft custom managed domains first, then onmicrosoft fallbacks
        if ($_.Id -notlike '*.onmicrosoft.com' -and $_.AuthenticationType -ne 'Federated') { 0 }
        elseif ($_.Id -like '*.onmicrosoft.com') { 2 }
        else { 1 }
    }, Id

    if (-not $eligible) {
        Write-Warn "No eligible domains found to set as the new default."
        Write-Info "You need at least one other verified domain in the tenant."
        Pause-ForUser
        return
    }

    Write-Host "  Available domains to set as new default:" -ForegroundColor Gray
    Write-Host ""

    $i = 1
    $indexMap = @{}
    foreach ($d in $eligible) {
        $tag = ''
        $col = 'White'
        if ($d.Id -like '*.onmicrosoft.com') {
            $tag = '  [onmicrosoft - safe fallback, can never be federated]'
            $col = 'Cyan'
        } elseif ($d.AuthenticationType -eq 'Federated') {
            $tag = '  [FEDERATED - not recommended as default]'
            $col = 'Gray'
        }
        Write-Host "    [$i]  " -NoNewline -ForegroundColor White
        Write-Host "$($d.Id)$tag" -ForegroundColor $col
        $indexMap["$i"] = $d.Id
        $i++
    }

    Write-Host ""
    Write-Host "    [B]  Back" -ForegroundColor Gray
    Write-Host ""

    $validChoices = (@(1..($i - 1)) | ForEach-Object { "$_" }) + @('B', 'b')
    $choice = Read-MenuChoice "Select new default domain" -Valid $validChoices
    if ($choice -in 'B', 'b') { return }

    $newDefault = $indexMap[$choice]
    $newDefaultObj = $eligible | Where-Object { $_.Id -eq $newDefault } | Select-Object -First 1

    if (-not $newDefaultObj) {
        Write-Fail "Could not look up domain object for '$newDefault'. Please try again."
        Pause-ForUser
        return
    }

    Write-Host ""
    Write-Info "Current default : $(if ($currentDefault) { $currentDefault.Id } else { '(none)' })"
    Write-Info "New default     : $newDefault"
    Write-Host ""

    if ($newDefaultObj.AuthenticationType -eq 'Federated') {
        Write-Warn "Note: '$newDefault' is currently Federated. Setting a federated domain as the"
        Write-Warn "default means new users will have UPNs on a federated domain. This is unusual."
        if (-not (Confirm-YesNo "Proceed anyway" -Default 'no')) {
            Write-Warn "Operation cancelled."
            Pause-ForUser
            return
        }
    } else {
        Write-Warn "Existing user UPNs are NOT changed - only new user defaults are affected."
        if (-not (Confirm-YesNo "Set '$newDefault' as the new default domain" -Default 'no')) {
            Write-Warn "Operation cancelled."
            Pause-ForUser
            return
        }
    }

    try {
        Update-MgDomain -DomainId $newDefault -BodyParameter @{ isDefault = $true } -ErrorAction Stop
        $prevDefault = if ($currentDefault) { $currentDefault.Id } else { '(unknown)' }
        Write-OK "Default domain changed to: $newDefault"
        Write-OK "'$prevDefault' is no longer the default and can now be federated."
        Write-Log "Default domain changed: $prevDefault -> $newDefault"

        # Refresh globals
        $script:TenantDomains = Get-MgDomain -ErrorAction Stop
        $onMSObj = $script:TenantDomains |
            Where-Object { $_.Id -like '*.onmicrosoft.com' -and $_.Id -notlike '*.mail.onmicrosoft.com' } |
            Select-Object -First 1
        $script:OnMicrosoftDomain = if ($onMSObj) { $onMSObj.Id } else { '' }
    } catch {
        Write-Fail "Failed to change default domain: $_"
        Write-Info "You may need to change this manually:"
        Write-Info "  Microsoft 365 Admin Center -> Settings -> Domains -> [$newDefault] -> Set as default"
        Write-Log "Default domain change FAILED: $newDefault  Error: $_"
    }

    Pause-ForUser
}
#endregion

#region -- Session Log ---------------------------------------------------------
function Show-SessionLog {
    Write-Section "Session Activity Log"
    if ($script:LogLines.Count -eq 0) {
        Write-Info "No actions recorded in this session."
    } else {
        foreach ($line in $script:LogLines) {
            Write-Host "  $line" -ForegroundColor Gray
        }
    }
    Pause-ForUser
}

function Export-SessionLog {
    Write-Section "Export Session Log"
    $defaultPath = Join-Path $env:USERPROFILE "Desktop\M365-Federation-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $path = (Read-Host "  Export path [$defaultPath]").Trim()
    if (-not $path) { $path = $defaultPath }
    try {
        $script:LogLines | Set-Content -Path $path -Encoding UTF8
        Write-OK "Log exported to: $path"
    } catch {
        Write-Fail "Export failed: $_"
    }
    Pause-ForUser
}
#endregion

#region -- Main Menu -----------------------------------------------------------
function Show-StatusBar {
    $connStatus  = if ($script:Connected)                { "[CONNECTED: $script:OnMicrosoftDomain]" } else { "[NOT CONNECTED]" }
    $domStatus   = if ($script:SelectedDomains.Count -gt 0) { "[$($script:SelectedDomains.Count) domain(s) selected]" } else { "[no domains selected]" }
    $samlStatus  = if ($script:SamlConfig)               { "[IdP: $($script:SamlConfig.ProviderName)]" } else { "[SAML not configured]" }
    $connColor   = if ($script:Connected)                { 'Green' } else { 'Red' }
    $domColor    = if ($script:SelectedDomains.Count -gt 0) { 'DarkYellow' } else { 'Gray' }
    $samlColor   = if ($script:SamlConfig)               { 'DarkYellow' } else { 'Gray' }

    Write-Host "  " -NoNewline
    Write-Host $connStatus  -NoNewline -ForegroundColor $connColor
    Write-Host "  " -NoNewline
    Write-Host $domStatus   -NoNewline -ForegroundColor $domColor
    Write-Host "  " -NoNewline
    Write-Host $samlStatus  -ForegroundColor $samlColor
    Write-Host ""
}

function Show-MainMenu {
    while ($true) {
        Clear-Host
        Show-YWBanner
        Write-Host "  Microsoft 365 SAML Domain Federation Wizard" -ForegroundColor White
        Write-Host ""
        Show-StatusBar

        Write-Host "  -- Setup ----------------------------------------------------------------" -ForegroundColor DarkYellow
        Write-Host "    [1]  Connect to Microsoft 365" -ForegroundColor White
        Write-Host "    [2]  Configure SAML Provider" -ForegroundColor White
        Write-Host "    [3]  Select Domains to Federate" -ForegroundColor White
        Write-Host "    [4]  Admin Account Safety Check" -ForegroundColor White
        Write-Host "    [5]  Change Default Domain" -ForegroundColor White
        Write-Host ""
        Write-Host "  -- Actions --------------------------------------------------------------" -ForegroundColor DarkYellow
        Write-Host "    [6]  Review and Apply Federation" -ForegroundColor White
        Write-Host "    [7]  View Current Federation Status" -ForegroundColor White
        Write-Host "    [8]  Revert Domain(s) to Managed Auth" -ForegroundColor White
        Write-Host ""
        Write-Host "  -- Utilities ------------------------------------------------------------" -ForegroundColor DarkYellow
        Write-Host "    [9]  View SAML Configuration Summary" -ForegroundColor White
        Write-Host "    [0]  View Session Log" -ForegroundColor White
        Write-Host "    [L]  Export Session Log to File" -ForegroundColor White
        Write-Host "    [Q]  Quit" -ForegroundColor Gray
        Write-Host ""

        $choice = Read-MenuChoice "Select option"

        switch ($choice.ToUpper()) {
            '1' { Connect-ToM365 | Out-Null }
            '2' { Show-SamlProviderMenu }
            '3' { Show-DomainSelectionMenu }
            '4' { Invoke-AdminUPNSafetyCheck }
            '5' { Invoke-ChangeDefaultDomain }
            '6' { Invoke-ApplyFederation }
            '7' { Show-FederationStatus }
            '8' { Invoke-RevertToManaged }
            '9' { Show-SamlConfigSummary; Pause-ForUser }
            '0' { Show-SessionLog }
            'L' { Export-SessionLog }
            'Q' {
                Write-Host ""
                Write-Host "  Exiting. " -NoNewline -ForegroundColor Gray
                Write-Host "Yeyland Wutani LLC - Building Better Systems" -ForegroundColor DarkYellow
                Write-Host ""
                return
            }
            default {
                Write-Warn "Invalid selection. Please choose a menu option."
                Start-Sleep -Seconds 1
            }
        }
    }
}
#endregion

#region -- Entry Point ---------------------------------------------------------
Clear-Host
Show-YWBanner

Write-Host "  Microsoft 365 SAML Domain Federation Wizard" -ForegroundColor White
Write-Host "  Yeyland Wutani LLC - IT Consulting and Cybersecurity" -ForegroundColor Gray
Write-Host ""
Write-Info "This wizard federates Microsoft 365 custom domains to a SAML 2.0 IdP."
Write-Info "Supported providers: WatchGuard AuthPoint, Okta, ADFS, and any SAML 2.0 IdP."
Write-Host ""
Write-Warn "Run this script as a user with Global Administrator rights in the target tenant."
Write-Host ""
Start-Sleep -Milliseconds 500

if (-not (Test-AndInstallMgraph)) {
    Write-Host ""
    Write-Fail "Cannot continue. Install the Microsoft.Graph modules and re-run."
    exit 1
}

Write-Log "Session started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  User: $env:USERNAME  Host: $env:COMPUTERNAME"

Show-MainMenu
#endregion
