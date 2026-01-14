<#
.SYNOPSIS
    Comprehensive SharePoint Online Security and Usage Report Tool v3.3
    
.DESCRIPTION
    MSP-friendly reporting tool using Microsoft Graph SDK and SPO Management Shell.
    No app registrations required - uses delegated permissions with interactive sign-in.
    
    Generates detailed reports on SharePoint Online including:
    - All SharePoint sites with storage metrics and sharing settings (OneDrive excluded by default)
    - Site permissions for ALL site types (Team Sites, Communication Sites, Classic Sites, etc.)
    - External sharing settings (tenant-level and per-site)
    - Deep library analysis (external sharing links, unique permissions, folder size distribution)
    - Visual charts for storage and sharing distribution
    - Exports to CSV files and branded HTML report
    
    FOCUS: Designed for security audits - automatically excludes OneDrive personal sites
    to focus on shared Team Sites, Communication Sites, and Document Libraries where
    organizational data is stored and collaboration happens.
    
.PARAMETER TenantName
    The SharePoint Online tenant name (e.g., 'contoso' for contoso.sharepoint.com)
    
.PARAMETER OutputPath
    Directory path for output files. Defaults to current directory
    
.PARAMETER IncludeLibraryDeepDive
    Switch to enable detailed library analysis including sharing links, unique permissions, and folder sizes
    WARNING: This significantly increases execution time for large tenants
    
.PARAMETER SiteUrlFilter
    Optional - Process only sites matching this URL pattern. Supports wildcards (e.g., '*project*')
    
.PARAMETER IncludeOneDrive
    Switch to INCLUDE OneDrive for Business sites in the report.
    By default, OneDrive sites are EXCLUDED to focus on shared Team Sites and reduce scan time.
    OneDrive sites are personal storage and typically not the focus of security audits.
    
.PARAMETER MaxSites
    Maximum number of sites to process. Useful for testing. Default is 0 (unlimited)
    
.PARAMETER SkipTenantSettings
    Skip tenant-level settings collection (useful if you only have site-level access)

.PARAMETER MaxScanDepth
    Maximum folder depth to scan for permissions, sharing links, and sizes.
    Range: 1-10. Default: 3
    - Lower values (1-2): Faster, less thorough
    - Higher values (5-10): Slower, more comprehensive

.EXAMPLE
    .\Get-SPOSecurityReport.ps1 -TenantName "contoso"
    Basic report of all Team Sites (OneDrive excluded by default)
    
.EXAMPLE
    .\Get-SPOSecurityReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive -OutputPath "C:\Reports"
    Full deep-dive report including library-level sharing links and folder sizes

.EXAMPLE
    .\Get-SPOSecurityReport.ps1 -TenantName "contoso" -IncludeOneDrive
    Include OneDrive for Business sites in the scan (excluded by default)

.NOTES
    Author: Yeyland Wutani LLC
    Version: 3.3
    Website: https://github.com/YeylandWutani
    
    Key Features:
    - OneDrive excluded by default (use -IncludeOneDrive to include)
    - Site permissions for ALL site types via Get-SPOSiteGroup
    - EXPANDS SharePoint groups to show actual members
    - Identifies Site Admins, Owners, Members, and Visitors
    - External user detection and flagging
    - Visual charts for sharing and storage analysis
    
    Required Modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Sites
    - Microsoft.Graph.Users  
    - Microsoft.Graph.Groups
    - Microsoft.Online.SharePoint.PowerShell
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Tenant name (e.g., 'contoso' for contoso.sharepoint.com)")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false, HelpMessage = "Enable deep library analysis")]
    [switch]$IncludeLibraryDeepDive,
    
    [Parameter(Mandatory = $false)]
    [string]$SiteUrlFilter = "*",
    
    [Parameter(Mandatory = $false, HelpMessage = "Include OneDrive sites (excluded by default)")]
    [switch]$IncludeOneDrive,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxSites = 0,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipTenantSettings,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum folder depth to scan (1-10, default: 3)")]
    [ValidateRange(1, 10)]
    [int]$MaxScanDepth = 3
)

#region Script Configuration
$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

# Yeyland Wutani LLC branding
$Script:Branding = @{
    PrimaryOrange = "#FF6600"
    Grey          = "#6B7280"
    White         = "#FFFFFF"
    Black         = "#1F2937"
    LightOrange   = "#FFF3E6"
    DarkOrange    = "#CC5200"
    Tagline       = "Building Better Systems"
    CompanyName   = "Yeyland Wutani LLC"
}

# Chart colors for visualizations (orange-first palette)
$Script:ChartColors = @(
    "#FF6600", "#CC5200", "#28a745", "#ffc107", "#dc3545", 
    "#6B7280", "#20c997", "#fd7e14", "#4B5563", "#17a2b8",
    "#e83e8c", "#374151", "#7952b3", "#F97316", "#51cf66"
)

# URLs and timestamps
$Script:TenantUrl = "https://$TenantName.sharepoint.com"
$Script:AdminUrl = "https://$TenantName-admin.sharepoint.com"
$Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"

# Data collections
$Script:Data = @{
    TenantSettings    = $null
    Sites             = [System.Collections.Generic.List[PSObject]]::new()
    SiteMembers       = [System.Collections.Generic.List[PSObject]]::new()
    ExternalSharing   = [System.Collections.Generic.List[PSObject]]::new()
    Libraries         = [System.Collections.Generic.List[PSObject]]::new()
    SharingLinks      = [System.Collections.Generic.List[PSObject]]::new()
    UniquePermissions = [System.Collections.Generic.List[PSObject]]::new()
    FolderSizes       = [System.Collections.Generic.List[PSObject]]::new()
    Errors            = [System.Collections.Generic.List[PSObject]]::new()
}

# Microsoft Graph scopes
$Script:GraphScopes = @(
    "Sites.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All"
)

# Template ID to friendly name mapping
$Script:TemplateNames = @{
    "SPSPERS#10"              = "OneDrive"
    "SPSPERS#12"              = "OneDrive"
    "GROUP#0"                 = "Team Site"
    "STS#3"                   = "Team Site (No Group)"
    "STS#0"                   = "Team Site (Classic)"
    "SITEPAGEPUBLISHING#0"    = "Communication Site"
    "SRCHCEN#0"               = "Search Center"
    "SPSMSITEHOST#0"          = "OneDrive Host"
    "POINTPUBLISHINGHUB#0"    = "Hub Site"
    "POINTPUBLISHINGTOPIC#0"  = "Topic Site"
    "EHS#1"                   = "Team Site (Classic)"
    "TEAMCHANNEL#0"           = "Teams Private Channel"
    "TEAMCHANNEL#1"           = "Teams Shared Channel"
    "APPCATALOG#0"            = "App Catalog"
    "BDR#0"                   = "Document Center"
    "DEV#0"                   = "Developer Site"
    "PROJECTSITE#0"           = "Project Site"
    "COMMUNITY#0"             = "Community Site"
    "COMMUNITYPORTAL#0"       = "Community Portal"
    "BLANKINTERNET#0"         = "Publishing Site"
    "ENTERWIKI#0"             = "Enterprise Wiki"
    "OFFILE#1"                = "Records Center"
    "PWA#0"                   = "Project Web App"
    "VISPRUS#0"               = "Visio Process Repository"
}

# System libraries to exclude
$Script:SystemLibraries = @(
    "Preservation Hold Library", "Site Assets", "Style Library",
    "FormServerTemplates", "Form Templates", "Site Collection Documents",
    "Site Collection Images", "Translation Packages", "Images",
    "Pages", "Videos", "Settings", "Organization Logos", "AppPages",
    "_catalogs", "Solution Gallery", "Theme Gallery", "Web Part Gallery",
    "Master Page Gallery", "Converted Forms", "Customized Reports",
    "Site Template Media", "User Photos"
)

$Script:SystemLibraryPatterns = @("PersistedManagedNavigation*", "_*", "DO_NOT_DELETE*")
#endregion

#region Logging Functions
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("Info", "Warning", "Error", "Success", "Debug")][string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{ Info = "Cyan"; Warning = "Yellow"; Error = "Red"; Success = "Green"; Debug = "Gray" }
    $symbols = @{ Info = "[*]"; Warning = "[!]"; Error = "[X]"; Success = "[+]"; Debug = "[-]" }
    
    Write-Host "$timestamp " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($symbols[$Level]) " -NoNewline -ForegroundColor $colors[$Level]
    Write-Host $Message -ForegroundColor $colors[$Level]
}

function Add-Error {
    param([string]$Operation, [string]$Target, [string]$ErrorMessage)
    $Script:Data.Errors.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operation = $Operation
        Target    = $Target
        Error     = $ErrorMessage
    })
}
#endregion

#region Utility Functions
function Convert-BytesToReadable {
    param([long]$Bytes)
    if ($null -eq $Bytes -or $Bytes -eq 0) { return "0 Bytes" }
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes Bytes"
}

function Get-FriendlyTemplateName {
    param([string]$TemplateId)
    if ([string]::IsNullOrWhiteSpace($TemplateId)) { return "Unknown" }
    if ($Script:TemplateNames.ContainsKey($TemplateId)) { return $Script:TemplateNames[$TemplateId] }
    $baseTemplate = $TemplateId -replace '#\d+$', ''
    foreach ($key in $Script:TemplateNames.Keys) {
        if ($key -like "$baseTemplate*") { return $Script:TemplateNames[$key] }
    }
    return $TemplateId
}

function Get-SharingCapabilityText {
    param([string]$Capability)
    $descriptions = @{
        "Disabled"                          = "Disabled"
        "ExternalUserSharingOnly"           = "Guests (sign-in required)"
        "ExternalUserAndGuestSharing"       = "Anyone (anonymous links)"
        "ExistingExternalUserSharingOnly"   = "Existing guests only"
    }
    if ($descriptions.ContainsKey($Capability)) { return $descriptions[$Capability] }
    return $Capability
}

function Get-DefaultLinkTypeText {
    param([string]$LinkType)
    $types = @{ "None" = "Organization default"; "AnonymousAccess" = "Anyone with link"; "Internal" = "Organization only"; "Direct" = "Specific people" }
    if ($types.ContainsKey($LinkType)) { return $types[$LinkType] }
    return $LinkType
}

function Test-IsOneDriveSite {
    param([string]$Url)
    return $Url -match "-my\.sharepoint\.com" -or $Url -match "/personal/"
}

function Test-IsSystemLibrary {
    param([string]$LibraryName)
    if ([string]::IsNullOrWhiteSpace($LibraryName)) { return $true }
    if ($Script:SystemLibraries -contains $LibraryName) { return $true }
    foreach ($pattern in $Script:SystemLibraryPatterns) {
        if ($LibraryName -like $pattern) { return $true }
    }
    return $false
}

function Get-CleanSiteName {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return "" }
    if ($Url -match "/personal/([^/]+)") { return $Matches[1] }
    if ($Url -match "/sites/([^/]+)") { return $Matches[1] }
    if ($Url -match "/portals/([^/]+)") { return $Matches[1] }
    if ($Url -match "sharepoint\.com/?$") { return "Root" }
    try {
        $uri = [System.Uri]$Url
        $segments = @($uri.Segments | Where-Object { $_ -ne "/" })
        if ($segments.Count -gt 0) {
            $lastSegment = [string]$segments[-1]
            return $lastSegment.TrimEnd('/')
        }
    } catch {}
    return $Url
}

function Get-HtmlSafeString {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}
#endregion

#region Module Management
function Install-RequiredModules {
    $modules = @(
        @{ Name = "Microsoft.Graph.Authentication"; MinVersion = "2.0.0" },
        @{ Name = "Microsoft.Graph.Sites"; MinVersion = "2.0.0" },
        @{ Name = "Microsoft.Graph.Users"; MinVersion = "2.0.0" },
        @{ Name = "Microsoft.Graph.Groups"; MinVersion = "2.0.0" },
        @{ Name = "Microsoft.Online.SharePoint.PowerShell"; MinVersion = "16.0.0" }
    )
    
    $missing = @()
    foreach ($module in $modules) {
        Write-Log "Checking module: $($module.Name)..." -Level Debug
        $installed = Get-Module -ListAvailable -Name $module.Name | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $installed -or $installed.Version -lt [Version]$module.MinVersion) { $missing += $module }
    }
    
    if ($missing.Count -gt 0) {
        Write-Log "Missing or outdated modules detected:" -Level Warning
        foreach ($m in $missing) { Write-Log "  - $($m.Name) (requires v$($m.MinVersion)+)" -Level Warning }
        $install = Read-Host "Install/update missing modules? (Y/N)"
        if ($install -eq 'Y') {
            foreach ($m in $missing) {
                Write-Log "Installing $($m.Name)..." -Level Info
                try {
                    Install-Module -Name $m.Name -MinimumVersion $m.MinVersion -Scope CurrentUser -Force -AllowClobber
                    Write-Log "Installed $($m.Name)" -Level Success
                } catch {
                    Write-Log "Failed to install $($m.Name): $_" -Level Error
                    return $false
                }
            }
        } else {
            Write-Log "Cannot continue without required modules" -Level Error
            return $false
        }
    }
    
    Write-Log "Loading modules..." -Level Info
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Sites -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Groups -ErrorAction Stop
        Import-Module Microsoft.Online.SharePoint.PowerShell -DisableNameChecking -ErrorAction Stop
        Write-Log "All modules loaded successfully" -Level Success
        return $true
    } catch {
        Write-Log "Failed to import modules: $_" -Level Error
        return $false
    }
}
#endregion

#region Connection Functions
function Connect-Services {
    Write-Log "Connecting to Microsoft Graph (delegated auth)..." -Level Info
    Write-Log "Sign in with a Global/SharePoint Admin account" -Level Info
    
    try {
        Connect-MgGraph -Scopes $Script:GraphScopes -NoWelcome
        $context = Get-MgContext
        Write-Log "Connected to Graph as: $($context.Account)" -Level Success
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $_" -Level Error
        throw
    }
    
    if (-not $SkipTenantSettings) {
        Write-Log "Connecting to SharePoint Online Admin Center..." -Level Info
        try {
            Connect-SPOService -Url $Script:AdminUrl
            Write-Log "Connected to SPO Admin Center" -Level Success
        } catch {
            Write-Log "Failed to connect to SPO Admin: $_" -Level Error
            Write-Log "Tenant settings will be skipped." -Level Warning
            $Script:SkipTenantSettings = $true
        }
    }
}

function Disconnect-Services {
    Write-Log "Disconnecting from services..." -Level Info
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch {}
}
#endregion

#region Data Collection Functions
function Get-TenantSharingSettings {
    if ($SkipTenantSettings) {
        Write-Log "Skipping tenant settings collection" -Level Warning
        return
    }
    
    Write-Log "Collecting tenant-level settings..." -Level Info
    
    try {
        $tenant = Get-SPOTenant
        $Script:Data.TenantSettings = [PSCustomObject]@{
            SharingCapability                    = $tenant.SharingCapability
            SharingCapabilityDescription         = Get-SharingCapabilityText $tenant.SharingCapability
            OneDriveSharingCapability            = $tenant.OneDriveSharingCapability
            DefaultSharingLinkType               = $tenant.DefaultSharingLinkType
            DefaultLinkPermission                = $tenant.DefaultLinkPermission
            RequireAnonymousLinksExpireInDays    = $tenant.RequireAnonymousLinksExpireInDays
            SharingDomainRestrictionMode         = $tenant.SharingDomainRestrictionMode
            SharingAllowedDomainList             = $tenant.SharingAllowedDomainList
            SharingBlockedDomainList             = $tenant.SharingBlockedDomainList
            PreventExternalUsersFromResharing    = $tenant.PreventExternalUsersFromResharing
            ExternalUserExpirationRequired       = $tenant.ExternalUserExpirationRequired
            ExternalUserExpireInDays             = $tenant.ExternalUserExpireInDays
            StorageQuota                         = $tenant.StorageQuota
            StorageQuotaAllocated                = $tenant.StorageQuotaAllocated
            StorageQuotaReadable                 = Convert-BytesToReadable ($tenant.StorageQuota * 1MB)
            StorageQuotaAllocatedReadable        = Convert-BytesToReadable ($tenant.StorageQuotaAllocated * 1MB)
            LegacyAuthProtocolsEnabled           = $tenant.LegacyAuthProtocolsEnabled
        }
        Write-Log "Tenant settings collected successfully" -Level Success
    } catch {
        Write-Log "Error collecting tenant settings: $_" -Level Error
        Add-Error -Operation "Get-TenantSettings" -Target $Script:AdminUrl -ErrorMessage $_.Exception.Message
    }
}

function Get-AllSharePointSites {
    Write-Log "Enumerating SharePoint sites..." -Level Info
    
    try {
        # Get sites - include personal sites only if IncludeOneDrive is specified
        # Must explicitly convert switch to bool for -IncludePersonalSite parameter
        $includePersonal = $IncludeOneDrive.IsPresent
        $spoSites = Get-SPOSite -Limit All -IncludePersonalSite:$includePersonal
        if ($SiteUrlFilter -ne "*") { $spoSites = $spoSites | Where-Object { $_.Url -like $SiteUrlFilter } }
        
        # Filter out OneDrive sites unless explicitly included
        if (-not $IncludeOneDrive) { 
            $spoSites = $spoSites | Where-Object { -not (Test-IsOneDriveSite $_.Url) }
            Write-Log "OneDrive sites excluded (use -IncludeOneDrive to include)" -Level Info
        }
        
        if ($MaxSites -gt 0) { $spoSites = $spoSites | Select-Object -First $MaxSites }
        
        $totalSites = ($spoSites | Measure-Object).Count
        Write-Log "Found $totalSites sites to process" -Level Success
        return $spoSites
    } catch {
        Write-Log "Error enumerating sites: $_" -Level Error
        Add-Error -Operation "Get-AllSites" -Target $Script:TenantUrl -ErrorMessage $_.Exception.Message
        return @()
    }
}

function Get-SiteDetailsFromGraph {
    param([Parameter(Mandatory = $true)][string]$SiteUrl)
    try {
        $uri = [System.Uri]$SiteUrl
        $hostName = $uri.Host
        $sitePath = $uri.AbsolutePath.TrimEnd('/')
        $graphSite = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/${hostName}:${sitePath}" -ErrorAction Stop
        return $graphSite
    } catch { return $null }
}

function Get-SPOSiteUsers {
    <#
    .SYNOPSIS
        Retrieves all users with permissions on a SharePoint site using SPO Management Shell
        Works for ALL site types (Team Sites, Communication Sites, Classic Sites, etc.)
        Expands SharePoint groups (Owners, Members, Visitors) to show actual members
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SiteUrl,
        [Parameter(Mandatory = $true)][string]$SiteTitle
    )
    
    $ownerCount = 0
    $memberCount = 0
    $visitorCount = 0
    
    # Track users we've already added to avoid duplicates
    # Store role hierarchy to keep only highest role
    $processedUsers = @{}
    $roleHierarchy = @{
        "Site Admin" = 1
        "Owner" = 2
        "Member" = 3
        "Visitor" = 4
        "Direct Access" = 5
        "Broad Access" = 6
    }
    
    # Helper function to add a user entry
    function Add-UserEntry {
        param(
            [string]$DisplayName,
            [string]$Email,
            [string]$Role,
            [bool]$IsSiteAdmin,
            [string]$GroupMembership,
            [bool]$IsExternal,
            [string]$LoginName
        )
        
        # Create unique key to prevent duplicates - use LoginName only (case-insensitive)
        # Keep only the highest priority role (Site Admin > Owner > Member > Visitor > Direct Access)
        $userKey = $LoginName.ToLower()
        if ($processedUsers.ContainsKey($userKey)) {
            $existingRole = $processedUsers[$userKey]
            $existingPriority = $roleHierarchy[$existingRole]
            $newPriority = $roleHierarchy[$Role]

            # User already exists - keep existing higher priority role
            return $false
        }
        $processedUsers[$userKey] = $Role
        
        $Script:Data.SiteMembers.Add([PSCustomObject]@{
            SiteUrl       = $SiteUrl
            SiteTitle     = $SiteTitle
            MemberName    = $DisplayName
            Email         = $Email
            Role          = $Role
            IsSiteAdmin   = $IsSiteAdmin
            Groups        = $GroupMembership
            IsExternal    = $IsExternal
            LoginName     = $LoginName
        })
        return $true
    }
    
    # Helper function to extract email from login name
    function Get-EmailFromLoginName {
        param([string]$LoginName)
        
        if ([string]::IsNullOrWhiteSpace($LoginName)) { return "" }
        
        # Check for standard email in claim
        if ($LoginName -match "\|([^|]+@[^|]+)$") {
            return $Matches[1]
        }
        # External user format
        elseif ($LoginName -like "*#ext#*") {
            return $LoginName -replace ".*_", "" -replace "#ext#.*", "" -replace "_", "@"
        }
        # Already an email
        elseif ($LoginName -match "@") {
            return $LoginName
        }
        return $LoginName
    }
    
    # Helper function to check if a user entry is a SharePoint group
    function Test-IsSharePointGroup {
        param($User, [string]$SiteName)
        
        # Check if the LoginName looks like a group GUID (not an email)
        if ($User.LoginName -match "^[a-f0-9-]{36}(_o)?$") { return $true }
        
        # Check if DisplayName matches site group patterns
        if ($User.DisplayName -match "^.+ (Owners|Members|Visitors)$") { return $true }
        
        # Check specific site name patterns
        $cleanSiteName = $SiteName -replace "[^a-zA-Z0-9]", ""
        if ($User.DisplayName -match "^$cleanSiteName (Owners|Members|Visitors)$") { return $true }
        
        return $false
    }
    
    try {
        Write-Log "  Enumerating site groups and members..." -Level Debug

        # Get ALL users/groups first (includes nested group objects)
        $allSiteUsers = Get-SPOUser -Site $SiteUrl -Limit All -ErrorAction Stop
        Write-Log "  Retrieved $($allSiteUsers.Count) total users/groups from site" -Level Debug

        # Build a lookup map of LoginName -> User object for nested group resolution
        $userByLoginName = @{}
        foreach ($u in $allSiteUsers) {
            if (-not [string]::IsNullOrWhiteSpace($u.LoginName)) {
                $userByLoginName[$u.LoginName] = $u
            }
        }
        Write-Log "  Built lookup map with $($userByLoginName.Count) entries" -Level Debug

        # First, get all SharePoint groups for the site and expand their members
        try {
            $siteGroups = Get-SPOSiteGroup -Site $SiteUrl -Limit 200 -ErrorAction Stop

            Write-Log "  Found $($siteGroups.Count) site groups" -Level Debug

            # Sort groups by priority: Owners first, then Members, then Visitors
            # This ensures users get their highest role assigned
            $siteGroups = $siteGroups | Sort-Object {
                if ($_.Title -match "Owner") { return 1 }
                elseif ($_.Title -match "Member") { return 2 }
                else { return 3 }
            }

            foreach ($group in $siteGroups) {
                # Skip system/empty groups
                if ([string]::IsNullOrWhiteSpace($group.Title)) { continue }
                
                # Determine role based on group name
                $groupRole = "Visitor"
                if ($group.Title -match "Owner" -or $group.Roles -contains "Full Control") {
                    $groupRole = "Owner"
                } elseif ($group.Title -match "Member" -or $group.Roles -contains "Edit" -or $group.Roles -contains "Contribute") {
                    $groupRole = "Member"
                }
                
                # Get the actual members of this group
                try {
                    $groupDetail = Get-SPOSiteGroup -Site $SiteUrl -Group $group.Title -ErrorAction Stop
                    $groupUsers = $groupDetail.Users

                    if ($groupUsers -and $groupUsers.Count -gt 0) {
                        foreach ($memberLogin in $groupUsers) {
                            # Skip system accounts
                            if ([string]::IsNullOrWhiteSpace($memberLogin)) { continue }
                            if ($memberLogin -like "*spocrwl*") { continue }
                            if ($memberLogin -like "*app@sharepoint*") { continue }
                            if ($memberLogin -like "SHAREPOINT\*") { continue }
                            if ($memberLogin -like "c:0(.s|true*") { continue }
                            if ($memberLogin -like "c:0-.f|rolemanager|*") { continue }

                            # Handle nested group GUIDs - these are likely Entra ID groups
                            if ($memberLogin -match "^[a-f0-9-]{36}(_o)?$") {
                                Write-Log "    Found nested group GUID in '$($group.Title)': $memberLogin" -Level Debug

                                # Extract the actual GUID (remove _o suffix if present)
                                $guidOnly = $memberLogin -replace "_o$", ""

                                # Try to get the group from Microsoft Graph using REST API (more compatible)
                                try {
                                    # Use Invoke-MgGraphRequest for better compatibility
                                    $graphGroup = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$guidOnly" -ErrorAction Stop

                                    # Get transitive members (includes nested group members)
                                    try {
                                        $transitiveUri = "https://graph.microsoft.com/v1.0/groups/$guidOnly/transitiveMembers"
                                        $graphMembers = Invoke-MgGraphRequest -Method GET -Uri $transitiveUri -ErrorAction Stop
                                        $members = $graphMembers.value

                                        foreach ($member in $members) {
                                            # Only process users (not nested groups or other types)
                                            if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                                                $email = $member.userPrincipalName
                                                $displayName = $member.displayName

                                                if ([string]::IsNullOrWhiteSpace($displayName)) {
                                                    $displayName = $email
                                                }

                                                $isExternal = $email -like "*#EXT#*"

                                                if (Add-UserEntry -DisplayName $displayName -Email $email -Role $groupRole `
                                                    -IsSiteAdmin $false -GroupMembership $group.Title `
                                                    -IsExternal $isExternal -LoginName $email) {
                                                    switch ($groupRole) {
                                                        "Owner" { $ownerCount++ }
                                                        "Member" { $memberCount++ }
                                                        default { $visitorCount++ }
                                                    }
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-Log "        Could not get members of Entra ID group: $($_.Exception.Message)" -Level Debug
                                    }
                                } catch {
                                    Write-Log "      Could not resolve GUID as Entra ID group: $($_.Exception.Message)" -Level Debug

                                    # Fallback: Try SPO method
                                    if ($userByLoginName.ContainsKey($memberLogin)) {
                                        $nestedGroupObj = $userByLoginName[$memberLogin]
                                        Write-Log "      Fallback: Found in SPO as '$($nestedGroupObj.DisplayName)'" -Level Debug
                                        try {
                                            $nestedDetail = Get-SPOSiteGroup -Site $SiteUrl -Group $nestedGroupObj.DisplayName -ErrorAction Stop
                                            foreach ($nestedMember in $nestedDetail.Users) {
                                                if ([string]::IsNullOrWhiteSpace($nestedMember)) { continue }
                                                if ($nestedMember -like "*spocrwl*" -or $nestedMember -like "*app@sharepoint*" -or
                                                    $nestedMember -like "SHAREPOINT\*" -or $nestedMember -like "c:0-.f|rolemanager|*") { continue }
                                                if ($nestedMember -match "^[a-f0-9-]{36}(_o)?$") {
                                                    Write-Log "        Skipping double-nested GUID: $nestedMember" -Level Debug
                                                    continue
                                                }
                                                if ($nestedMember -eq "Everyone" -or $nestedMember -like "*spo-grid-all-users/*") { continue }

                                                $email = Get-EmailFromLoginName -LoginName $nestedMember
                                                $displayName = $email
                                                if ($email -match "^([^@]+)@") {
                                                    $namePart = $Matches[1]
                                                    if ($namePart -match "^([a-zA-Z]+)\.([a-zA-Z]+)$") {
                                                        $displayName = "$($Matches[1].Substring(0,1).ToUpper())$($Matches[1].Substring(1)) $($Matches[2].Substring(0,1).ToUpper())$($Matches[2].Substring(1))"
                                                    }
                                                }
                                                $isExternal = $nestedMember -like "*#ext#*"

                                                if (Add-UserEntry -DisplayName $displayName -Email $email -Role $groupRole `
                                                    -IsSiteAdmin $false -GroupMembership $group.Title `
                                                    -IsExternal $isExternal -LoginName $nestedMember) {
                                                    switch ($groupRole) {
                                                        "Owner" { $ownerCount++ }
                                                        "Member" { $memberCount++ }
                                                        default { $visitorCount++ }
                                                    }
                                                }
                                            }
                                        } catch {
                                            Write-Log "        Could not expand nested group '$($nestedGroupObj.DisplayName)': $($_.Exception.Message)" -Level Debug
                                        }
                                    } else {
                                        Write-Log "      GUID not found in lookup map: $memberLogin" -Level Warning
                                    }
                                }
                                continue
                            }

                            # Handle Everyone groups - add as special warning entries
                            if ($memberLogin -eq "Everyone" -or $memberLogin -eq "Everyone except external users" -or $memberLogin -like "*spo-grid-all-users/*") {
                                $everyoneLabel = if ($memberLogin -eq "Everyone") { "[!] Everyone (All Users Including External)" } else { "[!] Everyone Except External Users" }
                                if (Add-UserEntry -DisplayName $everyoneLabel -Email "All tenant users" -Role "Broad Access" `
                                    -IsSiteAdmin $false -GroupMembership $group.Title `
                                    -IsExternal $false -LoginName $memberLogin) {
                                    $visitorCount++
                                }
                                continue
                            }
                            
                            # Extract email and display name from login
                            $email = Get-EmailFromLoginName -LoginName $memberLogin
                            
                            # Create display name from email or login
                            $displayName = $email
                            if ($email -match "^([^@]+)@") {
                                # Try to make a friendly name from email
                                $namePart = $Matches[1]
                                if ($namePart -match "^([a-zA-Z]+)\.([a-zA-Z]+)$") {
                                    $displayName = "$($Matches[1].Substring(0,1).ToUpper())$($Matches[1].Substring(1)) $($Matches[2].Substring(0,1).ToUpper())$($Matches[2].Substring(1))"
                                } elseif ($namePart -match "^([a-zA-Z]+)([a-zA-Z]+)$" -and $namePart.Length -gt 3) {
                                    $displayName = $namePart.Substring(0,1).ToUpper() + $namePart.Substring(1)
                                }
                            }
                            
                            $isExternal = $memberLogin -like "*#ext#*"
                            
                            if (Add-UserEntry -DisplayName $displayName -Email $email -Role $groupRole `
                                -IsSiteAdmin $false -GroupMembership $group.Title `
                                -IsExternal $isExternal -LoginName $memberLogin) {
                                
                                switch ($groupRole) {
                                    "Owner" { $ownerCount++ }
                                    "Member" { $memberCount++ }
                                    default { $visitorCount++ }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "    Could not expand group '$($group.Title)': $($_.Exception.Message)" -Level Debug
                }
            }
        } catch {
            Write-Log "  Could not enumerate site groups: $($_.Exception.Message)" -Level Debug
        }
        
        # Also get direct users (Site Admins and users with direct permissions)
        try {
            $siteUsers = Get-SPOUser -Site $SiteUrl -Limit All -ErrorAction Stop
            
            # Get site name for group detection
            $siteName = Get-CleanSiteName -Url $SiteUrl
            
            foreach ($user in $siteUsers) {
                # Skip system accounts and empty entries
                if ([string]::IsNullOrWhiteSpace($user.LoginName)) { continue }
                if ($user.LoginName -like "*spocrwl*") { continue }
                if ($user.LoginName -like "*app@sharepoint*") { continue }
                if ($user.LoginName -like "SHAREPOINT\*") { continue }
                if ($user.LoginName -like "*\spsearch") { continue }
                if ($user.LoginName -like "NT Service\*") { continue }
                if ($user.LoginName -like "NT AUTHORITY\*") { continue }

                # Skip if this is a SharePoint group (we already expanded those above)
                if (Test-IsSharePointGroup -User $user -SiteName $siteName) {
                    continue
                }
                
                # Also skip entries that look like group GUIDs
                if ($user.LoginName -match "^[a-f0-9-]{36}(_o)?$") { continue }
                
                # Site Admins are important - always include them
                if ($user.IsSiteAdmin) {
                    $displayName = $user.DisplayName
                    if ([string]::IsNullOrWhiteSpace($displayName)) {
                        $displayName = Get-EmailFromLoginName -LoginName $user.LoginName
                    }
                    
                    $email = Get-EmailFromLoginName -LoginName $user.LoginName
                    $isExternal = $user.LoginName -like "*#ext#*"
                    
                    if (Add-UserEntry -DisplayName $displayName -Email $email -Role "Site Admin" `
                        -IsSiteAdmin $true -GroupMembership ($user.Groups -join "; ") `
                        -IsExternal $isExternal -LoginName $user.LoginName) {
                        $ownerCount++
                    }
                }
                # Include users with direct permissions who weren't already added via groups
                # The Add-UserEntry function will automatically skip users we already processed
                else {
                    $displayName = $user.DisplayName
                    if ([string]::IsNullOrWhiteSpace($displayName)) {
                        $displayName = Get-EmailFromLoginName -LoginName $user.LoginName
                    }

                    $email = Get-EmailFromLoginName -LoginName $user.LoginName
                    $isExternal = $user.LoginName -like "*#ext#*"

                    # Check if this is an "Everyone" group by DisplayName or LoginName
                    if ($displayName -eq "Everyone" -or $user.LoginName -eq "Everyone" -or $user.LoginName -like "c:0(.s|true*") {
                        # Add as Broad Access warning instead of Direct Access
                        if (Add-UserEntry -DisplayName "[!] Everyone (All Users Including External)" -Email "All tenant users" -Role "Broad Access" `
                            -IsSiteAdmin $false -GroupMembership "Direct Permission" `
                            -IsExternal $false -LoginName $user.LoginName) {
                            $visitorCount++
                        }
                    }
                    elseif ($displayName -eq "Everyone except external users" -or $user.LoginName -eq "Everyone except external users" -or $user.LoginName -like "c:0-.f|rolemanager|spo-grid-all-users/*") {
                        # Add as Broad Access warning instead of Direct Access
                        if (Add-UserEntry -DisplayName "[!] Everyone Except External Users" -Email "All internal users" -Role "Broad Access" `
                            -IsSiteAdmin $false -GroupMembership "Direct Permission" `
                            -IsExternal $false -LoginName $user.LoginName) {
                            $visitorCount++
                        }
                    }
                    else {
                        # Try to add as Direct Access - will be skipped if already added via group
                        if (Add-UserEntry -DisplayName $displayName -Email $email -Role "Direct Access" `
                            -IsSiteAdmin $false -GroupMembership "Direct Permission" `
                            -IsExternal $isExternal -LoginName $user.LoginName) {
                            $visitorCount++
                        }
                    }
                }
            }
        } catch {
            # Access denied is common for restricted sites
            if ($_.Exception.Message -notmatch "Access is denied|E_ACCESSDENIED") {
                Write-Log "  Could not enumerate direct users: $($_.Exception.Message)" -Level Debug
            }
        }
        
        Write-Log "  Found $ownerCount owners, $memberCount members, $visitorCount visitors" -Level Debug
        
    } catch {
        # Access denied is common for restricted sites - don't treat as error
        if ($_.Exception.Message -match "Access is denied|E_ACCESSDENIED") {
            Write-Log "  Site has restricted permissions (access denied)" -Level Debug
        } else {
            Write-Log "  Could not enumerate site users: $($_.Exception.Message)" -Level Debug
            Add-Error -Operation "Get-SPOSiteUsers" -Target $SiteUrl -ErrorMessage $_.Exception.Message
        }
    }
    
    return @{ OwnerCount = $ownerCount; MemberCount = $memberCount; VisitorCount = $visitorCount }
}

function Get-LibrarySecurityScan {
    param(
        [string]$SiteId, [string]$DriveId, [string]$SiteUrl, [string]$LibraryName
    )
    
    $sharingLinks = [System.Collections.Generic.List[PSObject]]::new()
    $uniquePermissions = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        # Try the optimized method first (with $expand)
        $nextLink = "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/root/children?`$select=id,name,webUrl,folder,file,size&`$expand=permissions"
        
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $useExpandMethod = $true
        }
        catch {
            # If $expand fails, fall back to separate permission calls
            Write-Log "    Library doesn't support permissions expansion, using fallback method" -Level Debug
            $useExpandMethod = $false
            $nextLink = "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/root/children?`$select=id,name,webUrl,folder,file,size"
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
        }
        
        while ($true) {
            foreach ($item in $response.value) {
                $permissions = $null
                
                if ($useExpandMethod -and $item.permissions) {
                    $permissions = $item.permissions
                }
                elseif (-not $useExpandMethod) {
                    # Get permissions separately
                    try {
                        $permResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/items/$($item.id)/permissions" -ErrorAction Stop
                        $permissions = $permResponse.value
                    }
                    catch {
                        # Item doesn't support permissions - skip
                        continue
                    }
                }
                
                if ($permissions) {
                    # Process sharing links
                    foreach ($perm in $permissions) {
                        if ($perm.link) {
                            $linkScope = $perm.link.scope
                            $sharingLinks.Add([PSCustomObject]@{
                                SiteUrl        = $SiteUrl
                                SiteName       = Get-CleanSiteName $SiteUrl
                                LibraryName    = $LibraryName
                                ItemName       = $item.name
                                ItemPath       = $item.name
                                ItemUrl        = $item.webUrl
                                ItemType       = if ($item.folder) { "Folder" } else { "File" }
                                LinkType       = $perm.link.type
                                LinkScope      = $linkScope
                                IsExternal     = $linkScope -in @("anonymous", "users")
                                ExpirationDate = $perm.expirationDateTime
                                HasPassword    = $perm.hasPassword
                            })
                        }
                    }
                    
                    # Process unique permissions
                    $uniquePerms = $permissions | Where-Object { $null -eq $_.inheritedFrom }
                    if ($uniquePerms.Count -gt 0) {
                        $permDetails = foreach ($perm in $uniquePerms) {
                            $grantedTo = "Unknown"
                            if ($perm.grantedToV2.user) { $grantedTo = $perm.grantedToV2.user.displayName }
                            elseif ($perm.grantedToV2.group) { $grantedTo = $perm.grantedToV2.group.displayName }
                            elseif ($perm.grantedToV2.siteUser) { $grantedTo = $perm.grantedToV2.siteUser.displayName }
                            elseif ($perm.link) { $grantedTo = "Sharing Link ($($perm.link.scope))" }
                            "$grantedTo [$($perm.roles -join ',')]"
                        }
                        
                        $uniquePermissions.Add([PSCustomObject]@{
                            SiteUrl         = $SiteUrl
                            SiteName        = Get-CleanSiteName $SiteUrl
                            LibraryName     = $LibraryName
                            ItemName        = $item.name
                            ItemUrl         = $item.webUrl
                            ItemType        = if ($item.folder) { "Folder" } else { "File" }
                            UniquePermCount = $uniquePerms.Count
                            Permissions     = $permDetails -join "; "
                        })
                    }
                }
                
                # Recurse into folders
                if ($item.folder -and $item.folder.childCount -gt 0 -and $MaxScanDepth -gt 0) {
                    $childResults = Get-FolderSecurityScanRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $item.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $item.name -Depth 1 -MaxDepth $MaxScanDepth
                    foreach ($link in $childResults.SharingLinks) { $sharingLinks.Add($link) }
                    foreach ($perm in $childResults.UniquePermissions) { $uniquePermissions.Add($perm) }
                }
            }
            
            # Check for pagination
            if ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -ErrorAction Stop
            }
            else {
                break
            }
        }
    }
    catch {
        Write-Log "    Error scanning library: $($_.Exception.Message)" -Level Warning
        Add-Error -Operation "Get-LibrarySecurityScan" -Target "$SiteUrl/$LibraryName" -ErrorMessage $_.Exception.Message
    }
    
    return @{
        SharingLinks      = $sharingLinks
        UniquePermissions = $uniquePermissions
    }
}

function Get-FolderSecurityScanRecursive {
    <#
    .SYNOPSIS
        COMBINED recursive scan for both sharing links and unique permissions
    #>
    param([string]$SiteId, [string]$DriveId, [string]$FolderId, [string]$SiteUrl, [string]$LibraryName, [string]$ParentPath, [int]$Depth = 0, [int]$MaxDepth = 3)
    
    $sharingLinks = [System.Collections.Generic.List[PSObject]]::new()
    $uniquePermissions = [System.Collections.Generic.List[PSObject]]::new()
    
    if ($Depth -ge $MaxDepth) { 
        return @{ SharingLinks = $sharingLinks; UniquePermissions = $uniquePermissions }
    }
    
    try {
        # Single API call with expanded permissions
        $children = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/items/$FolderId/children?`$select=id,name,webUrl,folder,file,size&`$expand=permissions(`$select=id,link,roles,grantedToV2,inheritedFrom)" -ErrorAction Stop
        
        foreach ($item in $children.value) {
            $itemPath = "$ParentPath/$($item.name)"
            
            if ($item.permissions) {
                # Process sharing links
                foreach ($perm in $item.permissions) {
                    if ($perm.link) {
                        $sharingLinks.Add([PSCustomObject]@{
                            SiteUrl        = $SiteUrl
                            SiteName       = Get-CleanSiteName $SiteUrl
                            LibraryName    = $LibraryName
                            ItemName       = $item.name
                            ItemPath       = $itemPath
                            ItemUrl        = $item.webUrl
                            ItemType       = if ($item.folder) { "Folder" } else { "File" }
                            LinkType       = $perm.link.type
                            LinkScope      = $perm.link.scope
                            IsExternal     = $perm.link.scope -in @("anonymous", "users")
                            ExpirationDate = $perm.expirationDateTime
                            HasPassword    = $perm.hasPassword
                        })
                    }
                }
                
                # Process unique permissions
                $uniquePerms = $item.permissions | Where-Object { $null -eq $_.inheritedFrom }
                if ($uniquePerms.Count -gt 0) {
                    $permDetails = foreach ($perm in $uniquePerms) {
                        $grantedTo = "Unknown"
                        if ($perm.grantedToV2.user) { $grantedTo = $perm.grantedToV2.user.displayName }
                        elseif ($perm.grantedToV2.group) { $grantedTo = $perm.grantedToV2.group.displayName }
                        elseif ($perm.link) { $grantedTo = "Sharing Link ($($perm.link.scope))" }
                        "$grantedTo [$($perm.roles -join ',')]"
                    }
                    
                    $uniquePermissions.Add([PSCustomObject]@{
                        SiteUrl         = $SiteUrl
                        SiteName        = Get-CleanSiteName $SiteUrl
                        LibraryName     = $LibraryName
                        ItemName        = $item.name
                        ItemPath        = $itemPath
                        ItemUrl         = $item.webUrl
                        ItemType        = if ($item.folder) { "Folder" } else { "File" }
                        UniquePermCount = $uniquePerms.Count
                        Permissions     = $permDetails -join "; "
                    })
                }
            }
            
            # Continue recursion for folders
            if ($item.folder -and $item.folder.childCount -gt 0) {
                $childResults = Get-FolderSecurityScanRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $item.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $itemPath -Depth ($Depth + 1) -MaxDepth $MaxDepth
                foreach ($link in $childResults.SharingLinks) { $sharingLinks.Add($link) }
                foreach ($perm in $childResults.UniquePermissions) { $uniquePermissions.Add($perm) }
            }
        }
    } catch {}
    
    return @{
        SharingLinks      = $sharingLinks
        UniquePermissions = $uniquePermissions
    }
}

function Get-LibrarySharingLinks {
    <#
    .SYNOPSIS
        OPTIMIZED: Uses $expand=permissions to get items WITH permissions in single API call
        Reduces API calls from N+1 to just 1 per folder level
    #>
    param(
        [string]$SiteId, [string]$DriveId, [string]$SiteUrl, [string]$LibraryName
    )
    
    $sharingLinks = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        # Get root children WITH permissions expanded - single API call!
        $nextLink = "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/root/children?`$select=id,name,webUrl,folder,file,size&`$expand=permissions"
        
        while ($nextLink) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            
            foreach ($item in $response.value) {
                # Process permissions directly from expanded data - no extra API call needed!
                if ($item.permissions) {
                    foreach ($perm in $item.permissions) {
                        if ($perm.link) {
                            $linkScope = $perm.link.scope
                            $sharingLinks.Add([PSCustomObject]@{
                                SiteUrl        = $SiteUrl
                                SiteName       = Get-CleanSiteName $SiteUrl
                                LibraryName    = $LibraryName
                                ItemName       = $item.name
                                ItemPath       = $item.name
                                ItemUrl        = $item.webUrl
                                ItemType       = if ($item.folder) { "Folder" } else { "File" }
                                LinkType       = $perm.link.type
                                LinkScope      = $linkScope
                                IsExternal     = $linkScope -in @("anonymous", "users")
                                ExpirationDate = $perm.expirationDateTime
                                HasPassword    = $perm.hasPassword
                            })
                        }
                    }
                }
                
                # Recurse into folders (with depth limit)
                if ($item.folder -and $item.folder.childCount -gt 0) {
                    $folderLinks = Get-FolderSharingLinksRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $item.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $item.name -Depth 1 -MaxDepth $MaxScanDepth
                    foreach ($link in $folderLinks) { $sharingLinks.Add($link) }
                }
            }
            $nextLink = $response.'@odata.nextLink'
        }
    } catch {
        Add-Error -Operation "Get-LibrarySharingLinks" -Target "$SiteUrl/$LibraryName" -ErrorMessage $_.Exception.Message
    }
    
    return $sharingLinks
}

function Get-FolderSharingLinksRecursive {
    <#
    .SYNOPSIS
        OPTIMIZED: Uses $expand=permissions, reduced depth, early termination
    #>
    param([string]$SiteId, [string]$DriveId, [string]$FolderId, [string]$SiteUrl, [string]$LibraryName, [string]$ParentPath, [int]$Depth = 0, [int]$MaxDepth = 3)
    
    if ($Depth -ge $MaxDepth) { return @() }
    $sharingLinks = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        # Single API call with expanded permissions
        $children = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/items/$FolderId/children?`$select=id,name,webUrl,folder,file,size&`$expand=permissions" -ErrorAction Stop
        
        foreach ($item in $children.value) {
            $itemPath = "$ParentPath/$($item.name)"
            
            # Process permissions from expanded data
            if ($item.permissions) {
                foreach ($perm in $item.permissions) {
                    if ($perm.link) {
                        $sharingLinks.Add([PSCustomObject]@{
                            SiteUrl        = $SiteUrl
                            SiteName       = Get-CleanSiteName $SiteUrl
                            LibraryName    = $LibraryName
                            ItemName       = $item.name
                            ItemPath       = $itemPath
                            ItemUrl        = $item.webUrl
                            ItemType       = if ($item.folder) { "Folder" } else { "File" }
                            LinkType       = $perm.link.type
                            LinkScope      = $perm.link.scope
                            IsExternal     = $perm.link.scope -in @("anonymous", "users")
                            ExpirationDate = $perm.expirationDateTime
                            HasPassword    = $perm.hasPassword
                        })
                    }
                }
            }
            
            # Continue recursion for folders
            if ($item.folder -and $item.folder.childCount -gt 0) {
                $folderLinks = Get-FolderSharingLinksRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $item.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $itemPath -Depth ($Depth + 1) -MaxDepth $MaxDepth
                foreach ($link in $folderLinks) { $sharingLinks.Add($link) }
            }
        }
    } catch {}
    
    return $sharingLinks
}

function Get-LibraryFolderSizes {
    <#
    .SYNOPSIS
        Gets folder size distribution - already optimized, folder info comes with children call
    #>
    param([string]$SiteId, [string]$DriveId, [string]$SiteUrl, [string]$LibraryName)
    
    $folderData = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        $rootInfo = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/root?`$select=id,name,size,folder,webUrl" -ErrorAction Stop
        
        if ($rootInfo.size -gt 0 -or ($rootInfo.folder -and $rootInfo.folder.childCount -gt 0)) {
            $folderData.Add([PSCustomObject]@{
                SiteUrl      = $SiteUrl
                SiteName     = Get-CleanSiteName $SiteUrl
                LibraryName  = $LibraryName
                FolderPath   = "/"
                FolderName   = $LibraryName
                SizeBytes    = $rootInfo.size
                SizeReadable = Convert-BytesToReadable $rootInfo.size
                ItemCount    = $rootInfo.folder.childCount
                Depth        = 0
            })
        }
        
        $children = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/root/children?`$select=id,name,size,folder,webUrl" -ErrorAction Stop
        
        foreach ($child in $children.value) {
            if ($child.folder -and ($child.size -gt 0 -or $child.folder.childCount -gt 0)) {
                $childData = Get-FolderSizeRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $child.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath "" -FolderName $child.name -Size $child.size -ChildCount $child.folder.childCount -Depth 1 -MaxScanDepth $MaxScanDepth
                foreach ($folder in $childData) { $folderData.Add($folder) }
            }
        }
    } catch {
        Add-Error -Operation "Get-LibraryFolderSizes" -Target "$SiteUrl/$LibraryName" -ErrorMessage $_.Exception.Message
    }
    
    return $folderData
}

function Get-FolderSizeRecursive {
    <#
    .SYNOPSIS
        Recursively collects folder sizes - depth limited to 2 for performance
    #>
    param([string]$SiteId, [string]$DriveId, [string]$FolderId, [string]$SiteUrl, [string]$LibraryName, [string]$ParentPath, [string]$FolderName, [long]$Size, [int]$ChildCount, [int]$Depth, [int]$MaxScanDepth = 3)
    
    $folderData = [System.Collections.Generic.List[PSObject]]::new()
    $currentPath = if ($ParentPath) { "$ParentPath/$FolderName" } else { $FolderName }
    
    if ($Size -gt 0 -or $ChildCount -gt 0) {
        $folderData.Add([PSCustomObject]@{
            SiteUrl      = $SiteUrl
            SiteName     = Get-CleanSiteName $SiteUrl
            LibraryName  = $LibraryName
            FolderPath   = $currentPath
            FolderName   = $FolderName
            SizeBytes    = $Size
            SizeReadable = Convert-BytesToReadable $Size
            ItemCount    = $ChildCount
            Depth        = $Depth
        })
    }
    
    # Use configurable depth limit
    if ($Depth -lt $MaxScanDepth) {
        try {
            $children = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/items/$FolderId/children?`$select=id,name,size,folder,webUrl" -ErrorAction Stop
            foreach ($child in $children.value) {
                if ($child.folder -and ($child.size -gt 0 -or $child.folder.childCount -gt 0)) {
                     $childData = Get-FolderSizeRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $child.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $currentPath -FolderName $child.name -Size $child.size -ChildCount $child.folder.childCount -Depth ($Depth + 1) -MaxScanDepth $MaxScanDepth
                    foreach ($folder in $childData) { $folderData.Add($folder) }
                }
            }
        } catch {}
    }
    
    return $folderData
}

function Get-ItemsWithUniquePermissions {
    <#
    .SYNOPSIS
        OPTIMIZED: Uses $expand=permissions to find items with unique permissions in single call
    #>
    param([string]$SiteId, [string]$DriveId, [string]$SiteUrl, [string]$LibraryName)
    
    $uniquePermItems = [System.Collections.Generic.List[PSObject]]::new()
    
    try {
        # Single API call with expanded permissions
        $items = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/root/children?`$select=id,name,webUrl,folder,file&`$expand=permissions" -ErrorAction Stop
        
        foreach ($item in $items.value) {
            # Check permissions from expanded data
            if ($item.permissions) {
                $uniquePerms = $item.permissions | Where-Object { $null -eq $_.inheritedFrom }
                
                if ($uniquePerms.Count -gt 0) {
                    $permDetails = foreach ($perm in $uniquePerms) {
                        $grantedTo = "Unknown"
                        if ($perm.grantedToV2.user) { $grantedTo = $perm.grantedToV2.user.displayName }
                        elseif ($perm.grantedToV2.group) { $grantedTo = $perm.grantedToV2.group.displayName }
                        elseif ($perm.grantedToV2.siteUser) { $grantedTo = $perm.grantedToV2.siteUser.displayName }
                        elseif ($perm.link) { $grantedTo = "Sharing Link ($($perm.link.scope))" }
                        "$grantedTo [$($perm.roles -join ',')]"
                    }
                    
                    $uniquePermItems.Add([PSCustomObject]@{
                        SiteUrl         = $SiteUrl
                        SiteName        = Get-CleanSiteName $SiteUrl
                        LibraryName     = $LibraryName
                        ItemName        = $item.name
                        ItemUrl         = $item.webUrl
                        ItemType        = if ($item.folder) { "Folder" } else { "File" }
                        UniquePermCount = $uniquePerms.Count
                        Permissions     = $permDetails -join "; "
                    })
                }
            }
            
            # Recurse into folders
            if ($item.folder) {
               $childItems = Get-UniquePermissionsRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $item.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $item.name -Depth 1 -MaxDepth $MaxScanDepth
                foreach ($childItem in $childItems) { $uniquePermItems.Add($childItem) }
            }
        }
    } catch {
        Add-Error -Operation "Get-UniquePermissions" -Target "$SiteUrl/$LibraryName" -ErrorMessage $_.Exception.Message
    }
    
    return $uniquePermItems
}

function Get-UniquePermissionsRecursive {
    param(
        [string]$SiteId,
        [string]$DriveId,
        [string]$FolderId,
        [string]$SiteUrl,
        [string]$LibraryName,
        [string]$ParentPath,
        [int]$Depth,
        [int]$MaxDepth = 3
    )

    if ($Depth -ge $MaxDepth) { return @() }
    $uniquePermItems = [System.Collections.Generic.List[PSObject]]::new()

    try {
        # Single API call with expanded permissions
        $uri = "https://graph.microsoft.com/v1.0/sites/$SiteId/drives/$DriveId/items/$FolderId/children?`$select=id,name,webUrl,folder,file&`$expand=permissions"
        $children = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop

        foreach ($item in $children.value) {
            $itemPath = "$ParentPath/$($item.name)"

            # Process permissions from expanded data
            if ($item.permissions) {
                $uniquePerms = $item.permissions | Where-Object { $null -eq $_.inheritedFrom }
                if ($uniquePerms.Count -gt 0) {
                    $permDetails = foreach ($perm in $uniquePerms) {
                        $grantedTo = "Unknown"
                        if ($perm.grantedToV2.user) { $grantedTo = $perm.grantedToV2.user.displayName }
                        elseif ($perm.grantedToV2.group) { $grantedTo = $perm.grantedToV2.group.displayName }
                        elseif ($perm.link) { $grantedTo = "Sharing Link ($($perm.link.scope))" }
                        "$grantedTo [$($perm.roles -join ',')]"
                    }
                    $uniquePermItems.Add([PSCustomObject]@{
                        SiteUrl         = $SiteUrl
                        SiteName        = Get-CleanSiteName $SiteUrl
                        LibraryName     = $LibraryName
                        ItemName        = $item.name
                        ItemPath        = $itemPath
                        ItemUrl         = $item.webUrl
                        ItemType        = if ($item.folder) { "Folder" } else { "File" }
                        UniquePermCount = $uniquePerms.Count
                        Permissions     = $permDetails -join "; "
                    })
                }
            }
            if ($item.folder) {
                $childItems = Get-UniquePermissionsRecursive -SiteId $SiteId -DriveId $DriveId -FolderId $item.id -SiteUrl $SiteUrl -LibraryName $LibraryName -ParentPath $itemPath -Depth ($Depth + 1) -MaxDepth $MaxDepth
                foreach ($childItem in $childItems) { $uniquePermItems.Add($childItem) }
            }
        }
    } catch {
        # Log or ignore errors
    }
    return $uniquePermItems
}

function Process-Site {
    param($SPOSite, [int]$Index, [int]$Total)
    
    $siteUrl = $SPOSite.Url
    Write-Progress -Activity "Processing Sites" -Status "Site $Index of $Total" -CurrentOperation $siteUrl -PercentComplete (($Index / $Total) * 100)
    Write-Log "Processing: $siteUrl" -Level Info
    
    $graphSite = Get-SiteDetailsFromGraph -SiteUrl $siteUrl
    
    $siteTitle = $SPOSite.Title
    if ([string]::IsNullOrWhiteSpace($siteTitle)) { $siteTitle = Get-CleanSiteName $siteUrl }
    
    $ownerDisplay = $SPOSite.Owner
    if ([string]::IsNullOrWhiteSpace($ownerDisplay)) { $ownerDisplay = "-" }
    
    $siteType = Get-FriendlyTemplateName $SPOSite.Template
    $isOneDrive = Test-IsOneDriveSite $siteUrl
    $isTeamSite = $SPOSite.Template -like "GROUP#*"
    $groupCounts = @{ OwnerCount = 0; MemberCount = 0; VisitorCount = 0 }
    
    # Get site users for ALL non-OneDrive sites (this works for all site types)
    if (-not $isOneDrive) {
        Write-Log "  Getting site users..." -Level Debug
        $groupCounts = Get-SPOSiteUsers -SiteUrl $siteUrl -SiteTitle $siteTitle
    }
    
    $siteRecord = [PSCustomObject]@{
        Title                  = $siteTitle
        Url                    = $siteUrl
        SiteType               = $siteType
        Template               = $SPOSite.Template
        StorageUsageMB         = $SPOSite.StorageUsageCurrent
        StorageUsageReadable   = Convert-BytesToReadable ($SPOSite.StorageUsageCurrent * 1MB)
        StorageQuotaMB         = $SPOSite.StorageQuota
        StorageQuotaReadable   = Convert-BytesToReadable ($SPOSite.StorageQuota * 1MB)
        StoragePercentUsed     = if ($SPOSite.StorageQuota -gt 0) { [math]::Round(($SPOSite.StorageUsageCurrent / $SPOSite.StorageQuota) * 100, 2) } else { 0 }
        Owner                  = $ownerDisplay
        OwnerCount             = $groupCounts.OwnerCount
        MemberCount            = $groupCounts.MemberCount
        VisitorCount           = $groupCounts.VisitorCount
        SharingCapability      = $SPOSite.SharingCapability
        SharingCapabilityDesc  = Get-SharingCapabilityText $SPOSite.SharingCapability
        IsHubSite              = $SPOSite.IsHubSite
        LastModifiedDateTime   = $SPOSite.LastContentModifiedDate
        LockState              = $SPOSite.LockState
    }
    
    $Script:Data.Sites.Add($siteRecord)
    
    $Script:Data.ExternalSharing.Add([PSCustomObject]@{
        SiteUrl                      = $siteUrl
        SiteTitle                    = $siteTitle
        SharingCapability            = $SPOSite.SharingCapability
        SharingCapabilityDescription = Get-SharingCapabilityText $SPOSite.SharingCapability
        DefaultSharingLinkType       = $SPOSite.DefaultSharingLinkType
        DefaultLinkPermission        = $SPOSite.DefaultLinkPermission
    })
    
    # Deep dive into libraries if requested
    # OPTIMIZATIONS: Skip small libraries (<1MB), skip system sites, combine permission checks
    if ($IncludeLibraryDeepDive -and $graphSite -and $graphSite.id) {
        # Skip deep dive for certain site types that rarely have shared content
        $skipTemplates = @("SRCHCEN#0", "SPSMSITEHOST#0", "APPCATALOG#0", "PWA#0")
        if ($SPOSite.Template -in $skipTemplates) {
            Write-Log "  Skipping deep dive (system site type)" -Level Debug
        } else {
            Write-Log "  Performing library deep dive..." -Level Debug
            
            try {
                $drives = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$($graphSite.id)/drives?`$select=id,name,driveType,quota,webUrl" -ErrorAction Stop
                
                foreach ($drive in $drives.value) {
                    if (Test-IsSystemLibrary $drive.name) { continue }
                    
					# Get library size and handle missing quota information properly
                    $librarySizeBytes = 0
                    if ($drive.quota -and $null -ne $drive.quota.used) {
                        $librarySizeBytes = $drive.quota.used
                    }
                    $librarySizeMB = if ($librarySizeBytes -gt 0) { $librarySizeBytes / 1MB } else { 0 }

                    $Script:Data.Libraries.Add([PSCustomObject]@{
                        SiteUrl     = $siteUrl
                        SiteTitle   = $siteTitle
                        LibraryName = $drive.name
                        DriveType   = $drive.driveType
                        QuotaUsed   = Convert-BytesToReadable $librarySizeBytes
                        WebUrl      = $drive.webUrl
                    })

                    # Only skip if quota info exists AND library is confirmed < 1MB
                    # If quota is unavailable (0 or null), still scan it - don't assume it's empty!
                    if ($librarySizeBytes -gt 0 -and $librarySizeMB -lt 1) {
                        Write-Log "    Skipping: $($drive.name) (< 1MB)" -Level Debug
                        continue
                    }

                    # Log appropriately based on whether we have quota info
                    if ($librarySizeBytes -eq 0) {
                        Write-Log "    Analyzing: $($drive.name) (quota info unavailable - scanning anyway)" -Level Debug
                    } else {
                        Write-Log "    Analyzing: $($drive.name) ($(Convert-BytesToReadable $librarySizeBytes))" -Level Debug
                    }

                    
                    # Combined pass: Get sharing links AND unique permissions in one scan
                    $scanResults = Get-LibrarySecurityScan -SiteId $graphSite.id -DriveId $drive.id -SiteUrl $siteUrl -LibraryName $drive.name
                    foreach ($link in $scanResults.SharingLinks) { $Script:Data.SharingLinks.Add($link) }
                    foreach ($perm in $scanResults.UniquePermissions) { $Script:Data.UniquePermissions.Add($perm) }
                    
                    # Folder sizes (separate - doesn't need permissions)
                    $folderSizes = Get-LibraryFolderSizes -SiteId $graphSite.id -DriveId $drive.id -SiteUrl $siteUrl -LibraryName $drive.name
                    foreach ($folder in $folderSizes) { $Script:Data.FolderSizes.Add($folder) }
                }
            } catch {
                Add-Error -Operation "Library-DeepDive" -Target $siteUrl -ErrorMessage $_.Exception.Message
            }
        }
    }
}
#endregion

#region Export Functions
function Export-ToCsv {
    Write-Log "Exporting data to CSV files..." -Level Info
    $csvFiles = @()
    
    if ($Script:Data.Sites.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Sites_$Script:Timestamp.csv"
        $Script:Data.Sites | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.SiteMembers.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_SiteMembers_$Script:Timestamp.csv"
        $Script:Data.SiteMembers | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.ExternalSharing.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_ExternalSharingSettings_$Script:Timestamp.csv"
        $Script:Data.ExternalSharing | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.Libraries.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Libraries_$Script:Timestamp.csv"
        $Script:Data.Libraries | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.SharingLinks.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_SharingLinks_$Script:Timestamp.csv"
        $Script:Data.SharingLinks | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.UniquePermissions.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_UniquePermissions_$Script:Timestamp.csv"
        $Script:Data.UniquePermissions | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.FolderSizes.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_FolderSizes_$Script:Timestamp.csv"
        $Script:Data.FolderSizes | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }
    
    if ($Script:Data.Errors.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Errors_$Script:Timestamp.csv"
        $Script:Data.Errors | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Warning
    }
    
    return $csvFiles
}

function Export-ToHtml {
	# ======================================================================
    # CALCULATE SUMMARY STATISTICS
    # ======================================================================
    $totalSites = $Script:Data.Sites.Count
    $totalStorage = ($Script:Data.Sites | Measure-Object -Property StorageUsageMB -Sum).Sum

    # External sharing enabled sites (anything except Disabled)
    $externalEnabledSites = ($Script:Data.Sites | Where-Object { 
        $_.SharingCapability -ne "Disabled" 
    }).Count

    # External sharing links
    $externalLinks = ($Script:Data.SharingLinks | Where-Object { 
        $_.IsExternal -eq $true 
    }).Count

    # Unique permission items
    $uniquePermItems = $Script:Data.UniquePermissions.Count

    # Sites with members (sites that have user data)
    $sitesWithMembers = ($Script:Data.SiteMembers | 
        Group-Object SiteUrl | 
        Measure-Object).Count

    # Total external users
    $totalExternalUsers = ($Script:Data.SiteMembers | 
        Where-Object { $_.IsExternal -eq $true }).Count

    Write-Log "  Summary: $totalSites sites, $(Convert-BytesToReadable ($totalStorage * 1MB)) used" -Level Debug
    Write-Log "  External: $externalEnabledSites sites enabled, $externalLinks links, $totalExternalUsers users" -Level Debug
    # ======================================================================
    Write-Log "Generating HTML report..." -Level Info

    $htmlPath = Join-Path $OutputPath "SPO_SecurityReport_$Script:Timestamp.html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SharePoint Online Security Report - ${TenantName}</title>
<style>
:root { --yw-orange: #FF6600; --yw-dark-orange: #CC5200; --yw-light-orange: #FFF3E6; --yw-grey: #6B7280; --yw-dark-grey: #4B5563; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
.header { background: linear-gradient(135deg, var(--yw-orange), var(--yw-dark-orange)); color: #fff; padding: 25px 40px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 26px; font-weight: 300; }
.header .tagline { font-size: 13px; opacity: 0.9; margin-top: 4px; }
.header .company { text-align: right; }
.header .company-name { font-size: 16px; font-weight: 600; }
.header .report-date { font-size: 11px; opacity: 0.8; }
.container { max-width: 1400px; margin: 0 auto; padding: 25px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 25px; }
.summary-card { background: white; border-radius: 8px; padding: 18px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); border-left: 4px solid var(--yw-orange); }
.summary-card.warning { border-left-color: #f0ad4e; }
.summary-card.danger { border-left-color: #dc3545; }
.summary-card .value { font-size: 28px; font-weight: 600; color: var(--yw-orange); }
.summary-card .label { font-size: 12px; color: #666; margin-top: 4px; }
.section { background: #fff; border-radius: 8px; margin-bottom: 25px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); overflow: hidden; }
.section-header { background: var(--yw-light-orange); padding: 14px 20px; border-bottom: 2px solid var(--yw-orange); cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none; }
.section-header:hover { background: #FFE8D4; }
.section-header h2 { font-size: 16px; color: var(--yw-dark-orange); font-weight: 600; }
.section-header .count { background: var(--yw-orange); color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px; }
.section-header .toggle { font-size: 11px; color: #666; margin-left: 10px; }
.section-content { padding: 0; max-height: 500px; overflow: auto; }
.section-content.collapsed { display: none; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #f8f9fa; padding: 10px 12px; text-align: left; font-weight: 600; color: var(--yw-dark-orange); border-bottom: 2px solid #dee2e6; position: sticky; top: 0; }
td { padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:hover { background: #f8f9fa; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; white-space: nowrap; }
.badge-success { background: #d4edda; color: #155724; }
.badge-warning { background: #fff3cd; color: #856404; }
.badge-danger { background: #f8d7da; color: #721c24; }
.badge-info { background: #d1ecf1; color: #0c5460; }
.progress-bar { width: 100%; height: 6px; background: #e9ecef; border-radius: 3px; overflow: hidden; }
.progress-bar-fill { height: 100%; background: var(--yw-orange); }
.progress-bar-fill.warning { background: #f0ad4e; }
.progress-bar-fill.danger { background: #dc3545; }
.tenant-settings { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; padding: 15px; }
.setting-item { display: flex; justify-content: space-between; padding: 8px 12px; background: #f8f9fa; border-radius: 4px; font-size: 12px; }
.setting-label { color: #555; }
.setting-value { font-weight: 600; color: var(--yw-dark-orange); }
.footer { text-align: center; padding: 20px; color: #666; font-size: 11px; }
.footer .tagline { color: var(--yw-orange); font-weight: 600; font-size: 13px; }
.truncate { max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle; }
a { color: var(--yw-orange); text-decoration: none; }
a:hover { text-decoration: underline; }
.chart-container { padding: 20px; }
.chart-title { font-size: 14px; font-weight: 600; color: #333; margin-bottom: 15px; }
.donut-chart { display: flex; align-items: center; gap: 30px; flex-wrap: wrap; }
.donut-svg { width: 200px; height: 200px; }
.chart-legend { display: flex; flex-direction: column; gap: 8px; }
.legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.legend-color { width: 14px; height: 14px; border-radius: 3px; }
.bar-chart { display: flex; flex-direction: column; gap: 8px; padding: 20px; }
.bar-item { display: flex; align-items: center; gap: 10px; }
.bar-label { width: 200px; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 500; }
.bar-container { flex: 1; height: 20px; background: #e9ecef; border-radius: 4px; overflow: hidden; position: relative; }
.bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; justify-content: flex-end; padding-right: 8px; }
.bar-value { font-size: 10px; color: white; font-weight: 600; text-shadow: 0 1px 2px rgba(0,0,0,0.3); }
.bar-size { width: 80px; text-align: right; font-size: 11px; color: #666; font-weight: 600; }
@media print { .section-content { max-height: none !important; } }
</style>
</head>
<body>
<div class="header">
<div>
<h1>SharePoint Online Security Report</h1>
<div class="tagline">Tenant: ${TenantName}</div>
</div>
<div class="company">
<div class="company-name">${($Script:Branding.CompanyName)}</div>
<div class="report-date">${($Script:ReportDate)}</div>
<div class="tagline">${($Script:Branding.Tagline)}</div>
</div>
</div>
<div class="container">

<!-- START OF FULL REPORT SECTIONS -->

<!-- Summary Header -->
<!-- You can generate detailed summary cards here, or all sections as in your script -->
"@

    # Insert your report after the head, replacing with static/loop code as needed
    # For example, your first section: total sites, storage, external sharing
    $html += @"
<div class="summary-grid">
  <div class="summary-card"><div class="value">$($totalSites)</div><div class="label">Total Sites</div></div>
  <div class="summary-card"><div class="value">$(Convert-BytesToReadable ($totalStorage * 1MB))</div><div class="label">Storage Used</div></div>
  <div class="summary-card$(if ($externalEnabledSites -gt 0) { ' warning' })"><div class="value">$($externalEnabledSites)</div><div class="label">External Sharing Enabled</div></div>
  <div class="summary-card$(if ($externalLinks -gt 0) { ' danger' })"><div class="value">$($externalLinks)</div><div class="label">External Links</div></div>
  <div class="summary-card$(if ($uniquePermItems -gt 0) { ' warning' })"><div class="value">$($uniquePermItems)</div><div class="label">Unique Permissions</div></div>
  <div class="summary-card"><div class="value">$($sitesWithMembers)</div><div class="label">Sites w/Members</div></div>
</div>
"@

    # Tenant Settings Block (you can generate this from your data)
    if ($Script:Data.TenantSettings) {
        $ts = $Script:Data.TenantSettings
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>Tenant Settings</h2><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="tenant-settings">
<div class="setting-item"><span class="setting-label">External Sharing</span><span class="setting-value">$($ts.SharingCapabilityDescription)</span></div>
<div class="setting-item"><span class="setting-label">OneDrive Sharing</span><span class="setting-value">$(Get-SharingCapabilityText $ts.OneDriveSharingCapability)</span></div>
<div class="setting-item"><span class="setting-label">Default Link Type</span><span class="setting-value">$(Get-DefaultLinkTypeText $ts.DefaultSharingLinkType)</span></div>
<div class="setting-item"><span class="setting-label">Default Link Permission</span><span class="setting-value">$($ts.DefaultLinkPermission)</span></div>
<div class="setting-item"><span class="setting-label">Anon Link Expire</span><span class="setting-value">$(if ($ts.RequireAnonymousLinksExpireInDays -gt 0) { "$($ts.RequireAnonymousLinksExpireInDays) days" } else { "Never" })</span></div>
<div class="setting-item"><span class="setting-label">Guest Exp. Days</span><span class="setting-value">$(if ($ts.ExternalUserExpirationRequired) { "$($ts.ExternalUserExpireInDays) days" } else { "Disabled" })</span></div>
<div class="setting-item"><span class="setting-label">Resharing</span><span class="setting-value">$($ts.PreventExternalUsersFromResharing)</span></div>
<div class="setting-item"><span class="setting-label">Domain List</span><span class="setting-value">$($ts.SharingDomainRestrictionMode)</span></div>
<div class="setting-item"><span class="setting-label">Storage Quota</span><span class="setting-value">$($ts.StorageQuotaReadable)</span></div>
<div class="setting-item"><span class="setting-label">Legacy Auth</span><span class="setting-value">$($ts.LegacyAuthProtocolsEnabled)</span></div>
</div>
</div>
</div>
"@
    }

    # Sites list table
    $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>SharePoint Sites</h2><span class="count">$($Script:Data.Sites.Count) sites</span><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Site</th><th>Type</th><th>Storage</th><th>% of Tenant</th><th>Sharing</th><th>Owner</th><th>Modified</th></tr>
"@

    foreach ($site in ($Script:Data.Sites | Sort-Object StorageUsageMB -Descending)) {
        $pct = 0
        if ($Script:Data.TenantSettings.StorageQuota -gt 0) {
            $pct = [math]::Round(($site.StorageUsageMB / $Script:Data.TenantSettings.StorageQuota) * 100, 2)
        } elseif (($Script:Data.Sites | Measure-Object -Property StorageUsageMB -Sum).Sum -gt 0) {
            $totalUsed = ($Script:Data.Sites | Measure-Object -Property StorageUsageMB -Sum).Sum
            $pct = [math]::Round(($site.StorageUsageMB / $totalUsed) * 100, 2)
        }

        $ShareBadge = switch ($site.SharingCapability) {
            "Disabled" { "<span class='badge badge-success'>Disabled</span>" }
            "ExistingExternalUserSharingOnly" { "<span class='badge badge-info'>Existing</span>" }
            "ExternalUserSharingOnly" { "<span class='badge badge-warning'>Guests</span>" }
            "ExternalUserAndGuestSharing" { "<span class='badge badge-danger'>Anyone</span>" }
            default { "<span class='badge'>" + (Get-HtmlSafeString $site.SharingCapabilityDesc) + "</span>" }
        }

        $modDate = if ($site.LastModifiedDateTime) { ([DateTime] $site.LastModifiedDateTime).ToString("yyyy-MM-dd") } else { "-" }

        $html += "<tr><td><a href=`"$($site.Url)`" target=`"_blank`" class=`"truncate`" title=`"$($site.Url)`">$(Get-HtmlSafeString $site.Title)</a></td>"
        $html += "<td>$($site.SiteType)</td>"
        $html += "<td>$($site.StorageUsageReadable)</td>"
        $html += "<td><div class=`"progress-bar`"><div class=`"progress-bar-fill`" style=`"width:$([math]::Min($pct,100))%`"></div></div><small>$($pct)%</small></td>"
        $html += "<td>$ShareBadge</td>"
        $html += "<td class=`"truncate`">$(Get-HtmlSafeString $site.Owner)</td>"
        $html += "<td>$modDate</td></tr>"
    }
    $html += "</table></div></div>"

    # Site Members Sections
    $siteMembers = $Script:Data.SiteMembers | Where-Object { $_.Role -ne $null }
    if ($siteMembers.Count -gt 0) {
        $grouped = $siteMembers | Group-Object SiteUrl | Sort-Object { $_.Group[0].SiteTitle }

        $totalExt = ($siteMembers | Where-Object { $_.IsExternal }).Count

        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>Site Permissions</h2><span class="count">$($siteMembers.Count) users across $($grouped.Count) sites$(if ($totalExt -gt 0) { " | $($totalExt) external" })</span><span class="toggle">&#9660;</span></div>
<div class="section-content" style="max-height:none;padding:15px;">
"@

        foreach ($group in $grouped) {
            $siteTitle = $group.Group[0].SiteTitle
            $siteUrl = $group.Group[0].SiteUrl
            $sUserCount = $group.Count
            $sExtCount = ($group.Group | Where-Object { $_.IsExternal }).Count

            $adminCount = ($group.Group | Where-Object { $_.Role -eq "Site Admin" }).Count
            $ownerCount = ($group.Group | Where-Object { $_.Role -eq "Owner" }).Count
            $memberCount = ($group.Group | Where-Object { $_.Role -eq "Member" }).Count
            $visitorCount = ($group.Group | Where-Object { $_.Role -eq "Visitor" }).Count

            $countParts = @()
            if ($adminCount -gt 0) { $countParts += "$adminCount admin" }
            if ($ownerCount -gt 0) { $countParts += "$ownerCount owner" }
            if ($memberCount -gt 0) { $countParts += "$memberCount member" }
            if ($visitorCount -gt 0) { $countParts += "$visitorCount visitor" }
            $countsStr = $countParts -join ", "

            $extBadgeHtml = if ($sExtCount -gt 0) { "<span class='badge badge-danger'>$sExtCount external</span>" } else { "" }
            $html += @"
<div class="site-perms-block" style="margin-bottom:15px;border:1px solid #dee2e6;border-radius:6px;overflow:hidden;">
<div class="site-perms-header" onclick="toggleSection(this)" style="background:#f8f9fa;padding:10px 15px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #dee2e6;">
<div>
<a href="$siteUrl" target="_blank" style="font-weight:600;font-size:13px;">$(Get-HtmlSafeString $siteTitle)</a>
<span style="color:#666;font-size:11px;margin-left:10px;">$countsStr</span>
</div>
<div style="display:flex;align-items:center;gap:10px;">$extBadgeHtml<span class="toggle" style="font-size:11px;color:#666;">&#9654;</span></div>
</div>
<div class="section-content collapsed" style="max-height:300px;overflow:auto;">
<table style="margin:0;"><thead><tr><th>User</th><th>Email</th><th>Role</th><th>External</th></tr></thead><tbody>
"@

            # Sorted users: Admin > Owner > Member > Visitor
            $sortedUsers = $group.Group | Sort-Object @{E={switch ($_.Role) { "Site Admin" { 0 } "Owner" { 1 } "Member" { 2 } "Visitor" { 3 } default { 4 } }}}, MemberName

            foreach ($member in $sortedUsers) {
                $roleBadge = switch ($member.Role) {
                    "Site Admin" { "<span class='badge badge-danger'>Site Admin</span>" }
                    "Owner" { "<span class='badge badge-warning'>Owner</span>" }
                    "Member" { "<span class='badge badge-info'>Member</span>" }
                    "Visitor" { "<span class='badge badge-success'>Visitor</span>" }
                    "Broad Access" { "<span class='badge badge-danger' style='font-weight:700'>[!] BROAD ACCESS</span>" }
                    default { "<span class='badge'>" + (Get-HtmlSafeString $member.Role) + "</span>" }
                }
                $extHtml = if ($member.IsExternal) { "<span class='badge badge-danger'>Yes</span>" } else { "" }
                $html += "<tr><td>$(Get-HtmlSafeString $member.MemberName)</td><td class=`"truncate`" style=`"max-width:200px`">$(Get-HtmlSafeString $member.Email)</td><td>$roleBadge</td><td>$extHtml</td></tr>"
            }
            $html += "</tbody></table></div></div>"
        }
        $html += "</div></div>" # End site perms block
    }

    # External sharing donut chart
    if ($Script:Data.ExternalSharing -and $Script:Data.ExternalSharing.Count -gt 0) {
        $shareGroups = $Script:Data.ExternalSharing | Group-Object SharingCapability | Sort-Object Count -Descending
        $totalSharing = $Script:Data.ExternalSharing.Count
        $svgPaths = ""
        $legendHtml = ""
        $startAngle = 0
        $colorsHash = @{
            "Disabled"="#28a745"; 
            "ExistingExternalUserSharingOnly"="#17a2b8"; 
            "ExternalUserSharingOnly"="#ffc107"; 
            "ExternalUserAndGuestSharing"="#dc3545"
        }
        $indexColor = 0
        foreach ($group in $shareGroups) {
            $pct = $group.Count / $totalSharing
            $angle = $pct * 360
            $endAngle = $startAngle + $angle
            $largeArcFlag = if ($angle -gt 180) { 1 } else { 0 }
            $startRad = $startAngle * [Math]::PI / 180
            $endRad = $endAngle * [Math]::PI / 180
            $x1 = 100 + 80 * [Math]::Sin($startRad)
            $y1 = 100 - 80 * [Math]::Cos($startRad)
            $x2 = 100 + 80 * [Math]::Sin($endRad)
            $y2 = 100 - 80 * [Math]::Cos($endRad)
            $colorVal = if ($colorsHash.ContainsKey($group.Name)) { $colorsHash[$group.Name] } else { $Script:ChartColors[$indexColor % $Script:ChartColors.Count] }
            $labelText = switch ($group.Name) {
                "Disabled" { "Disabled" }
                "ExistingExternalUserSharingOnly" { "Existing" }
                "ExternalUserSharingOnly" { "Guests" }
                "ExternalUserAndGuestSharing" { "Anyone" }
                Default { $group.Name }
            }
            if ($pct -lt 1) {
                $svg += "<path d=`"M 100 100 L $x1 $y1 A 80 80 0 $largeArcFlag 1 $x2 $y2 Z`" fill=`"$colorVal`" />"
            } else {
                $svg += "<circle cx=`"100`" cy=`"100`" r=`"80`" fill=`"$colorVal`" />"
            }
            $legendHtml += "<div class=`"legend-item`"><div class=`"legend-color`" style=`"background:$colorVal`"></div><span>$labelText : $($group.Count) ($([math]::Round($pct*100,1)))%)</span></div>"
            $startAngle = $endAngle
            $indexColor++
        }
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>External Sharing Overview</h2><span class="count">$($totalSharing) sites</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="chart-container">
<div class="chart-title">Sharing Capability Distribution</div>
<svg class="donut-svg" viewBox="0 0 200 200">$svg</svg>
<div class="chart-legend">$legendHtml</div>
</div></div></div>
"@
    }

# === REWORKED: Storage Distribution by Library (Expandable) ===
$allFoldersRaw = $Script:Data.FolderSizes | Where-Object { $_.SizeBytes -gt 0 }

if ($allFoldersRaw.Count -gt 0) {
    # Deduplicate folders (same path may appear multiple times)
    $uniqueFolders = $allFoldersRaw | Group-Object { "$($_.SiteUrl)|$($_.LibraryName)|$($_.FolderPath)" } | ForEach-Object {
        $_.Group | Sort-Object SizeBytes -Descending | Select-Object -First 1
    }

# Group by Site + Library for expandable display
$groupedByLibrary = $uniqueFolders | Group-Object { "$($_.SiteUrl)|$($_.LibraryName)" } | ForEach-Object {
    $parts = $_.Name -split "\|"
    
    # Find the root folder (Depth = 0 or FolderPath = "/")
    $rootFolder = $_.Group | Where-Object { $_.Depth -eq 0 -or $_.FolderPath -eq "/" } | Select-Object -First 1
    
    # Use ROOT size as library total (it already includes all subfolders)
    # If no root found, fall back to summing (shouldn't happen but safety check)
    $libraryTotal = if ($rootFolder) { 
        $rootFolder.SizeBytes 
    } else { 
        ($_.Group | Measure-Object -Property SizeBytes -Sum).Sum 
    }
    
    [PSCustomObject]@{
        SiteUrl     = $parts[0]
        LibraryName = $parts[1]
        SiteName    = $_.Group[0].SiteName
        Folders     = $_.Group | Sort-Object SizeBytes -Descending
        TotalSize   = $libraryTotal  # Fixed - use root size, not sum
    }
} | Sort-Object TotalSize -Descending

    $totalLibraries = $groupedByLibrary.Count
    $totalFolders = $uniqueFolders.Count

    $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
<h2>Storage Distribution by Library</h2>
<span class="count">$totalLibraries libraries | $totalFolders folders</span>
<span class="toggle">&#9660;</span>
</div>
<div class="section-content" style="max-height:none;padding:15px;">
"@

    # Create expandable block for each library
    foreach ($library in $groupedByLibrary) {
        $librarySize = Convert-BytesToReadable $library.TotalSize
        $folderCount = $library.Folders.Count

        # Calculate percentage of total storage across all libraries
        $totalAllStorage = ($groupedByLibrary | Measure-Object -Property TotalSize -Sum).Sum
        $libraryPctOfTotal = if ($totalAllStorage -gt 0) { 
            [math]::Round(($library.TotalSize / $totalAllStorage) * 100, 1) 
        } else { 0 }

        $html += @"
<div class="library-storage-block" style="margin-bottom:15px;border:1px solid #dee2e6;border-radius:6px;overflow:hidden;">
<div class="library-storage-header" onclick="toggleSection(this)" style="background:#f8f9fa;padding:12px 15px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #dee2e6;">
<div style="flex:1;">
<div style="font-weight:600;font-size:13px;color:var(--yw-dark-orange);">
$(Get-HtmlSafeString $library.SiteName) &rarr; $(Get-HtmlSafeString $library.LibraryName)
</div>
<div style="font-size:11px;color:#666;margin-top:2px;">
$folderCount folders | $librarySize total | $libraryPctOfTotal% of all storage
</div>
</div>
<div style="display:flex;align-items:center;gap:10px;">
<span class="toggle" style="font-size:11px;color:#666;">&#9654;</span>
</div>
</div>
<div class="section-content collapsed" style="max-height:400px;overflow:auto;">
<table style="margin:0;"><thead><tr>
<th style="width:40%">Folder Path</th>
<th style="width:15%;text-align:right">Size</th>
<th style="width:25%">% of Library</th>
<th style="width:10%;text-align:center">Items</th>
<th style="width:10%;text-align:center">Depth</th>
</tr></thead><tbody>
"@

        # Show folders within this library with percentages relative to THIS library
        foreach ($folder in $library.Folders) {
            # Calculate percentage relative to THIS LIBRARY (not global max)
            $pctOfLibrary = if ($library.TotalSize -gt 0) {
                [math]::Round(($folder.SizeBytes / $library.TotalSize) * 100, 1)
            } else { 0 }

            $folderPathDisplay = if ($folder.FolderPath -eq "/") { 
                "<em style=`"color:#666;`">(root)</em>" 
            } else { 
                Get-HtmlSafeString $folder.FolderPath 
            }

            $depthIndent = "&nbsp;" * ($folder.Depth * 2)

            # Color code the progress bar based on percentage
            $barColor = if ($pctOfLibrary -gt 50) { "#dc3545" } elseif ($pctOfLibrary -gt 25) { "#ffc107" } else { "#FF6600" }

            $html += @"
<tr>
<td>$depthIndent$folderPathDisplay</td>
<td style="text-align:right;font-weight:600;font-family:monospace;">$($folder.SizeReadable)</td>
<td>
<div style="display:flex;align-items:center;gap:8px;">
<div class="progress-bar" style="flex:1;height:18px;">
<div class="progress-bar-fill" style="width:$pctOfLibrary%;background:$barColor"></div>
</div>
<span style="font-size:11px;font-weight:600;color:#666;min-width:45px;text-align:right;">$pctOfLibrary%</span>
</div>
</td>
<td style="text-align:center;">$($folder.ItemCount)</td>
<td style="text-align:center;color:#999;">$($folder.Depth)</td>
</tr>
"@
        }

        $html += "</tbody></table></div></div>"
    }

    $html += "</div></div>`n"

    }

    # External sharing links
    if ($Script:Data.SharingLinks.Count -gt 0) {
        $linksCount = $Script:Data.SharingLinks.Count
        $displayLinks = $Script:Data.SharingLinks | Where-Object { $_.IsExternal } | Select-Object -First 100
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>External Sharing Links</h2><span class="count">$linksCount links</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<table>
<tr><th>Site</th><th>Library</th><th>Item</th><th>Type</th><th>Scope</th><th>Expires</th></tr>
"@
        foreach ($link in $displayLinks) {
            $scopeBadge = switch ($link.LinkScope) {
                "anonymous" { "<span class='badge badge-danger'>Anyone</span>" }
                "organization" { "<span class='badge badge-warning'>Org</span>" }
                "users" { "<span class='badge badge-info'>Specific</span>" }
                default { "<span class='badge'>" + $link.LinkScope + "</span>" }
            }
            $expiresText = if ($link.ExpirationDate) { ([DateTime]$link.ExpirationDate).ToString("yyyy-MM-dd") } else { "Never" }
            $html += "<tr><td class=`"truncate`">$($link.SiteName)</td><td>$($link.LibraryName)</td><td><a href=`"$($link.ItemUrl)`" target=`"_blank`" class=`"truncate`">$(Get-HtmlSafeString $link.ItemName)</a></td><td>$($link.ItemType)</td><td>$scopeBadge</td><td>$expiresText</td></tr>"
        }
        $html += "</table></div></div>"
    }

    # Unique permissions table
    if ($Script:Data.UniquePermissions.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>Items with Unique Permissions</h2><span class="count">$($Script:Data.UniquePermissions.Count) items</span><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Site</th><th>Library</th><th>Item</th><th>Type</th><th>#</th><th>Permissions</th></tr>
"@
        foreach ($perm in ($Script:Data.UniquePermissions | Select-Object -First 100)) {
            $html += "<tr><td class=`"truncate`">$($perm.SiteName)</td><td>$($perm.LibraryName)</td><td><a href=`"$($perm.ItemUrl)`" target=`"_blank`" class=`"truncate`">$(Get-HtmlSafeString $perm.ItemName)</a></td><td>$($perm.ItemType)</td><td>$($perm.UniquePermCount)</td><td class=`"truncate`" title=`"$(Get-HtmlSafeString $perm.Permissions)`">$(Get-HtmlSafeString $perm.Permissions)</td></tr>"
        }
        $html += "</table></div></div>"
    }

    # Errors section
    if ($Script:Data.Errors.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)" style="background:#fff3cd"><h2>Errors</h2><span class="count" style="background:#856404">$($Script:Data.Errors.Count)</span><span class="toggle">&#9654;</span></div>
<div class="section-content collapsed"><table>
<tr><th>Time</th><th>Operation</th><th>Target</th><th>Error</th></tr>
"@
        foreach ($err in $Script:Data.Errors) {
            $html += "<tr><td>$($err.Timestamp)</td><td>$($err.Operation)</td><td class=`"truncate`">$($err.Target)</td><td class=`"truncate`">$(Get-HtmlSafeString $err.Error)</td></tr>"
        }
        $html += "</table></div></div>"
    }

    # Footer & Scripts
    $html += @"
</div>
<div class="footer">
<div class="tagline">${($Script:Branding.Tagline)}</div>
<p>Generated by ${($Script:Branding.CompanyName)} SharePoint Security Report v3.3</p>
<p>${($Script:ReportDate)}</p>
</div>
<script>
function toggleSection(header) {
    var content = header.nextElementSibling;
    if (content) {
        if (content.classList.contains('collapsed')) {
            content.classList.remove('collapsed');
            header.querySelector('.toggle').innerHTML = '&#9660;';
        } else {
            content.classList.add('collapsed');
            header.querySelector('.toggle').innerHTML = '&#9654;';
        }
    }
}
</script>
</body>
</html>
"@

    # Write the file
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "HTML report generated: $htmlPath" -Level Success
    return $htmlPath
}
#endregion

#region Main Execution
function Invoke-SPOSecurityReport {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor DarkYellow
    Write-Host "     SharePoint Online Security & Usage Report Tool v3.3             " -ForegroundColor DarkYellow
    Write-Host "     $($Script:Branding.CompanyName) - $($Script:Branding.Tagline)                      " -ForegroundColor DarkYellow
    Write-Host "======================================================================" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  No app registration required - uses delegated authentication" -ForegroundColor Green
    Write-Host "  Scans ALL SharePoint site types for permissions and sharing" -ForegroundColor Green
    Write-Host ""
    if ($IncludeOneDrive) {
        Write-Host "  OneDrive sites: INCLUDED (personal storage will be scanned)" -ForegroundColor Yellow
    } else {
        Write-Host "  OneDrive sites: EXCLUDED (use -IncludeOneDrive to include)" -ForegroundColor Cyan
    }
    Write-Host ""
    
    if (-not (Test-Path $OutputPath)) {
        try { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null; Write-Log "Created output directory: $OutputPath" -Level Success }
        catch { Write-Log "Cannot create output directory: $OutputPath" -Level Error; return }
    }
    
    Write-Log "Checking required modules..." -Level Info
    if (-not (Install-RequiredModules)) { Write-Log "Module requirements not met. Exiting." -Level Error; return }
    
    try { Connect-Services }
    catch { Write-Log "Failed to establish connections. Exiting." -Level Error; return }
    
    try {
        Get-TenantSharingSettings
        
        $sites = Get-AllSharePointSites
        if ($sites.Count -eq 0) { Write-Log "No sites found to process" -Level Warning; return }
        
        $siteIndex = 0
        foreach ($site in $sites) {
            $siteIndex++
            Process-Site -SPOSite $site -Index $siteIndex -Total $sites.Count
        }
        
        Write-Progress -Activity "Processing Sites" -Completed
        
        $csvFiles = Export-ToCsv
        $htmlFile = Export-ToHtml
        
        $stopwatch.Stop()
        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host "                    Report Generation Complete                        " -ForegroundColor Green
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Log "Execution time: $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))" -Level Success
        Write-Log "Sites processed: $($Script:Data.Sites.Count)" -Level Success
        Write-Log "Site users found: $($Script:Data.SiteMembers.Count)" -Level Success
        Write-Log "External users: $(($Script:Data.SiteMembers | Where-Object { $_.IsExternal -eq $true }).Count)" -Level $(if (($Script:Data.SiteMembers | Where-Object { $_.IsExternal -eq $true }).Count -gt 0) { "Warning" } else { "Success" })
        Write-Log "Errors encountered: $($Script:Data.Errors.Count)" -Level $(if ($Script:Data.Errors.Count -gt 0) { "Warning" } else { "Success" })
        Write-Host ""
        Write-Log "Output files:" -Level Info
        foreach ($csv in $csvFiles) { Write-Host "    CSV: $csv" -ForegroundColor White }
        Write-Host "    HTML: $htmlFile" -ForegroundColor DarkYellow
        Write-Host ""
        
        $openReport = Read-Host "Open HTML report in browser? (Y/N)"
        if ($openReport -eq 'Y') { Start-Process $htmlFile }
    }
    finally { Disconnect-Services }
}

Invoke-SPOSecurityReport
#endregion
