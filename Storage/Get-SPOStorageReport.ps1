<#
.SYNOPSIS
    SharePoint Online Storage Management Report Tool v1.0

.DESCRIPTION
    MSP-friendly storage reporting tool using Microsoft Graph SDK and SPO Management Shell.
    No app registrations required - uses delegated permissions with interactive sign-in.

    Generates detailed reports on where storage is being consumed across SharePoint Online:
    - All SharePoint sites with storage metrics (OneDrive INCLUDED by default)
    - Top storage consumers ranked by size with visual comparisons
    - Stale storage - sites with significant data not recently accessed
    - Sites approaching or exceeding their individual storage quota
    - Per-library storage breakdown (with -IncludeLibraryDeepDive)
    - Tenant-level storage quota summary
    - Exports to CSV files and branded HTML report

    FOCUS: Storage management - designed to identify cleanup opportunities, right-size
    quotas, and understand where tenant storage is concentrated. OneDrive is INCLUDED
    by default since personal storage is a significant component of total usage.

.PARAMETER TenantName
    The SharePoint Online tenant name (e.g., 'contoso' for contoso.sharepoint.com)

.PARAMETER OutputPath
    Directory path for output files. Defaults to current directory

.PARAMETER ExcludeOneDrive
    Switch to EXCLUDE OneDrive for Business sites from the report.
    By default, OneDrive sites ARE included since personal storage is often a
    major component of total storage consumption.

.PARAMETER IncludeLibraryDeepDive
    Switch to enable per-library storage breakdown using the Microsoft Graph drives API.
    Shows which document libraries within each site are consuming the most space.
    WARNING: Significantly increases execution time for large tenants.

.PARAMETER SiteUrlFilter
    Optional - Process only sites matching this URL pattern. Supports wildcards (e.g., '*project*')

.PARAMETER MaxSites
    Maximum number of sites to process. Useful for testing. Default is 0 (unlimited)

.PARAMETER SkipTenantSettings
    Skip tenant-level storage quota collection (useful if you lack Global Admin access)

.PARAMETER StaleThresholdDays
    Number of days since last modification to consider a site's storage "stale".
    Sites with storage above StaleMinimumMB not modified within this window are flagged.
    Default: 180 days

.PARAMETER StaleMinimumMB
    Minimum storage (in MB) a site must have to be included in the stale storage report.
    Prevents noise from empty or near-empty unused sites. Default: 50 MB

.EXAMPLE
    .\Get-SPOStorageReport.ps1 -TenantName "contoso"
    Full storage report including OneDrive (default)

.EXAMPLE
    .\Get-SPOStorageReport.ps1 -TenantName "contoso" -ExcludeOneDrive -OutputPath "C:\Reports"
    Storage report for SharePoint sites only, saved to C:\Reports

.EXAMPLE
    .\Get-SPOStorageReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive
    Full report with per-library breakdown (slower, more detailed)

.EXAMPLE
    .\Get-SPOStorageReport.ps1 -TenantName "contoso" -StaleThresholdDays 365 -StaleMinimumMB 100
    Flag sites with 100+ MB unused for over a year

.NOTES
    Author: Yeyland Wutani LLC
    Version: 1.0
    Website: https://github.com/YeylandWutani

    Key Features:
    - OneDrive included by default (use -ExcludeOneDrive to exclude)
    - Storage ranked and charted for at-a-glance analysis
    - Stale storage identification for cleanup planning
    - Quota warnings for sites approaching limits
    - Per-library breakdown with -IncludeLibraryDeepDive

    Required Modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Sites
    - Microsoft.Online.SharePoint.PowerShell
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Tenant name (e.g., 'contoso' for contoso.sharepoint.com)")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false, HelpMessage = "Exclude OneDrive sites (included by default)")]
    [switch]$ExcludeOneDrive,

    [Parameter(Mandatory = $false, HelpMessage = "Enable per-library storage breakdown")]
    [switch]$IncludeLibraryDeepDive,

    [Parameter(Mandatory = $false, HelpMessage = "Find top 10 largest files and folders across all libraries")]
    [switch]$IncludeTopItems,

    [Parameter(Mandatory = $false, HelpMessage = "Analyze storage consumption by file type with charts")]
    [switch]$IncludeFileTypeAnalysis,

    [Parameter(Mandatory = $false, HelpMessage = "Subfolder depth for file type scan (1-10, default: 5)")]
    [ValidateRange(1, 10)]
    [int]$FileTypeScanDepth = 5,

    [Parameter(Mandatory = $false)]
    [string]$SiteUrlFilter = "*",

    [Parameter(Mandatory = $false)]
    [int]$MaxSites = 0,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTenantSettings,

    [Parameter(Mandatory = $false, HelpMessage = "Days without modification to flag as stale (default: 180)")]
    [ValidateRange(1, 3650)]
    [int]$StaleThresholdDays = 180,

    [Parameter(Mandatory = $false, HelpMessage = "Minimum MB to include in stale report (default: 50)")]
    [int]$StaleMinimumMB = 50
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

# Chart colors (orange-first palette)
$Script:ChartColors = @(
    "#FF6600", "#CC5200", "#F97316", "#fd7e14", "#ffc107",
    "#28a745", "#20c997", "#17a2b8", "#6B7280", "#4B5563",
    "#dc3545", "#e83e8c", "#7952b3", "#374151", "#51cf66"
)

# URLs and timestamps
$Script:TenantUrl  = "https://$TenantName.sharepoint.com"
$Script:AdminUrl   = "https://$TenantName-admin.sharepoint.com"
$Script:Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:ReportDate = Get-Date -Format "MMMM dd, yyyy 'at' HH:mm"

# Data collections
$Script:Data = @{
    TenantQuota = $null
    Sites       = [System.Collections.Generic.List[PSObject]]::new()
    OneDrive    = [System.Collections.Generic.List[PSObject]]::new()
    Libraries   = [System.Collections.Generic.List[PSObject]]::new()
    TopFiles    = [System.Collections.Generic.List[PSObject]]::new()
    TopFolders     = [System.Collections.Generic.List[PSObject]]::new()
    FileTypeBytes  = @{}   # extension -> total bytes (long)
    FileTypeCounts = @{}   # extension -> file count (int)
    Errors         = [System.Collections.Generic.List[PSObject]]::new()
}

# File type category mapping (extension -> category name)
$Script:FileTypeCategories = @{
    # Images / Photography
    ".jpg"=  "Images"; ".jpeg"="Images"; ".png"="Images"; ".gif"="Images"; ".bmp"="Images"
    ".tif"=  "Images"; ".tiff"="Images"; ".raw"="Images"; ".cr2"="Images"; ".nef"="Images"
    ".arw"=  "Images"; ".dng"="Images";  ".heic"="Images"; ".webp"="Images"
    # Design files
    ".psd"= "Design"; ".ai"="Design"; ".eps"="Design"; ".svg"="Design"; ".indd"="Design"
    ".xd"=  "Design"; ".sketch"="Design"; ".fig"="Design"
    # Video
    ".mp4"=  "Video"; ".mov"="Video"; ".avi"="Video"; ".mkv"="Video"; ".wmv"="Video"
    ".mpg"=  "Video"; ".mpeg"="Video"; ".m4v"="Video"; ".flv"="Video"; ".webm"="Video"
    ".mxf"=  "Video"; ".f4v"="Video"
    # Audio
    ".mp3"=  "Audio"; ".wav"="Audio"; ".aac"="Audio"; ".flac"="Audio"; ".wma"="Audio"
    ".ogg"=  "Audio"; ".m4a"="Audio"; ".aiff"="Audio"
    # Documents
    ".pdf"=  "Documents"; ".doc"="Documents"; ".docx"="Documents"; ".xls"="Documents"
    ".xlsx"= "Documents"; ".ppt"="Documents"; ".pptx"="Documents"; ".odt"="Documents"
    ".ods"=  "Documents"; ".odp"="Documents"; ".txt"="Documents"; ".rtf"="Documents"
    ".csv"=  "Documents"; ".msg"="Documents"; ".eml"="Documents"
    # Archives
    ".zip"=  "Archives"; ".rar"="Archives"; ".7z"="Archives"; ".tar"="Archives"
    ".gz"=   "Archives"; ".bz2"="Archives"; ".iso"="Archives"; ".dmg"="Archives"
    # Code / Web
    ".js"=   "Code"; ".ts"="Code"; ".py"="Code"; ".ps1"="Code"; ".html"="Code"
    ".css"=  "Code"; ".json"="Code"; ".xml"="Code"; ".sql"="Code"; ".sh"="Code"
    ".cs"=   "Code"; ".vb"="Code"; ".java"="Code"; ".cpp"="Code"; ".php"="Code"
}

# Per-category chart colors
$Script:FileCategoryColors = @{
    "Images"    = "#e83e8c"
    "Design"    = "#FF6600"
    "Video"     = "#7952b3"
    "Documents" = "#17a2b8"
    "Archives"  = "#fd7e14"
    "Audio"     = "#28a745"
    "Code"      = "#20c997"
    "Other"     = "#6B7280"
}

# Microsoft Graph scopes (minimal - read-only)
$Script:GraphScopes = @(
    "Sites.Read.All",
    "Files.Read.All"
)

# Template ID to friendly name mapping
$Script:TemplateNames = @{
    "SPSPERS#10"             = "OneDrive"
    "SPSPERS#12"             = "OneDrive"
    "GROUP#0"                = "Team Site"
    "STS#3"                  = "Team Site (No Group)"
    "STS#0"                  = "Team Site (Classic)"
    "SITEPAGEPUBLISHING#0"   = "Communication Site"
    "SRCHCEN#0"              = "Search Center"
    "SPSMSITEHOST#0"         = "OneDrive Host"
    "POINTPUBLISHINGHUB#0"   = "Hub Site"
    "POINTPUBLISHINGTOPIC#0" = "Topic Site"
    "EHS#1"                  = "Team Site (Classic)"
    "TEAMCHANNEL#0"          = "Teams Private Channel"
    "TEAMCHANNEL#1"          = "Teams Shared Channel"
    "APPCATALOG#0"           = "App Catalog"
    "BDR#0"                  = "Document Center"
    "DEV#0"                  = "Developer Site"
    "PROJECTSITE#0"          = "Project Site"
    "COMMUNITY#0"            = "Community Site"
    "BLANKINTERNET#0"        = "Publishing Site"
    "ENTERWIKI#0"            = "Enterprise Wiki"
    "OFFILE#1"               = "Records Center"
    "RedirectSite#0"         = "Redirect Site"
}

# System libraries to skip during deep dive
$Script:SystemLibraries = @(
    "Preservation Hold Library", "Site Assets", "Style Library",
    "FormServerTemplates", "Form Templates", "Site Collection Documents",
    "Site Collection Images", "Translation Packages", "Images",
    "Pages", "Videos", "Settings", "Organization Logos", "AppPages",
    "Solution Gallery", "Theme Gallery", "Web Part Gallery",
    "Master Page Gallery", "Converted Forms", "Customized Reports",
    "User Photos", "Search Config List", "Content and Structure Reports",
    "Reusable Content", "Workflow Tasks", "Workflow History"
)
$Script:SystemLibraryPatterns = @("_*", "DO_NOT_DELETE*", "PersistedManagedNavigation*")
#endregion

#region Logging Functions
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("Info", "Warning", "Error", "Success", "Debug")][string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors  = @{ Info = "Cyan"; Warning = "Yellow"; Error = "Red"; Success = "Green"; Debug = "Gray" }
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

function Test-IsOneDriveSite {
    param([string]$Url)
    return ($Url -like "*/personal/*" -or $Url -like "*-my.sharepoint.com*")
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
    if ([string]::IsNullOrWhiteSpace($Url)) { return "Unknown" }
    $uri = try { [System.Uri]$Url } catch { return $Url }
    $path = $uri.AbsolutePath.TrimEnd('/').TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($path)) { return $uri.Host }
    return ($path -split '/')[-1]
}

function Get-HtmlSafeString {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return $Text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;")
}

function Get-StorageCategory {
    param([double]$MB)
    if ($MB -ge 10240)  { return "Very Large (10GB+)" }
    if ($MB -ge 1024)   { return "Large (1-10GB)" }
    if ($MB -ge 100)    { return "Medium (100MB-1GB)" }
    if ($MB -ge 1)      { return "Small (1-100MB)" }
    return "Empty (<1MB)"
}

function Get-StorageCategoryColor {
    param([double]$MB)
    if ($MB -ge 10240)  { return "#dc3545" }   # Red - very large
    if ($MB -ge 1024)   { return "#fd7e14" }   # Orange - large
    if ($MB -ge 100)    { return "#ffc107" }   # Yellow - medium
    if ($MB -ge 1)      { return "#28a745" }   # Green - small
    return "#6B7280"                            # Grey - empty
}

function Get-QuotaStatusBadge {
    param([double]$PercentUsed)
    if ($PercentUsed -ge 100) { return "<span class='badge badge-danger'>Over Quota</span>" }
    if ($PercentUsed -ge 90)  { return "<span class='badge badge-danger'>Critical (${PercentUsed}%)</span>" }
    if ($PercentUsed -ge 75)  { return "<span class='badge badge-warning'>Warning (${PercentUsed}%)</span>" }
    if ($PercentUsed -ge 50)  { return "<span class='badge badge-info'>Moderate (${PercentUsed}%)</span>" }
    return "<span class='badge badge-success'>OK (${PercentUsed}%)</span>"
}
#endregion

#region Module Management
function Install-RequiredModules {
    $modules = @(
        @{ Name = "Microsoft.Graph.Authentication"; MinVersion = "2.0.0" },
        @{ Name = "Microsoft.Graph.Sites";          MinVersion = "2.0.0" },
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
        Import-Module Microsoft.Graph.Sites         -ErrorAction Stop
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
            Write-Log "Tenant quota will be unavailable. Continuing..." -Level Warning
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
function Get-TenantStorageQuota {
    if ($SkipTenantSettings) {
        Write-Log "Skipping tenant quota collection" -Level Warning
        return
    }

    Write-Log "Collecting tenant storage quota..." -Level Info
    try {
        $tenant = Get-SPOTenant
        $Script:Data.TenantQuota = [PSCustomObject]@{
            StorageQuotaMB          = $tenant.StorageQuota
            StorageQuotaReadable    = Convert-BytesToReadable ($tenant.StorageQuota * 1MB)
            StorageAllocatedMB      = $tenant.StorageQuotaAllocated
            StorageAllocatedReadable= Convert-BytesToReadable ($tenant.StorageAllocatedMB * 1MB)
            OneDriveStorageQuotaMB  = $tenant.OneDriveStorageQuota
            ResourceQuotaAllocated  = $tenant.ResourceQuotaAllocated
        }
        Write-Log "Tenant quota: $($Script:Data.TenantQuota.StorageQuotaReadable)" -Level Success
    } catch {
        Write-Log "Failed to get tenant quota: $_" -Level Warning
        Add-Error -Operation "Get-TenantStorageQuota" -Target $Script:AdminUrl -ErrorMessage $_.Exception.Message
    }
}

function Get-AllSharePointSites {
    Write-Log "Enumerating SharePoint sites..." -Level Info

    try {
        # Always fetch personal sites (OneDrive) - we'll separate them by URL pattern
        $spoSites = Get-SPOSite -Limit All -IncludePersonalSite $true
        if ($SiteUrlFilter -ne "*") { $spoSites = $spoSites | Where-Object { $_.Url -like $SiteUrlFilter } }

        if ($ExcludeOneDrive) {
            $spoSites = $spoSites | Where-Object { -not (Test-IsOneDriveSite $_.Url) }
            Write-Log "OneDrive sites excluded (-ExcludeOneDrive)" -Level Info
        }

        if ($MaxSites -gt 0) { $spoSites = $spoSites | Select-Object -First $MaxSites }

        $total = ($spoSites | Measure-Object).Count
        Write-Log "Found $total sites to process" -Level Success
        return $spoSites
    } catch {
        Write-Log "Error enumerating sites: $_" -Level Error
        Add-Error -Operation "Get-AllSites" -Target $Script:TenantUrl -ErrorMessage $_.Exception.Message
        return @()
    }
}

function Get-SiteGraphId {
    param([string]$SiteUrl)
    try {
        $uri      = [System.Uri]$SiteUrl
        $hostName = $uri.Host
        $sitePath = $uri.AbsolutePath.TrimEnd('/')
        $graphSite = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/${hostName}:${sitePath}" -ErrorAction Stop
        return $graphSite.id
    } catch { return $null }
}

function Get-SiteLibraries {
    param(
        [Parameter(Mandatory = $true)][string]$SiteGraphId,
        [Parameter(Mandatory = $true)][string]$SiteUrl,
        [Parameter(Mandatory = $true)][string]$SiteTitle
    )

    Write-Log "  Getting library breakdown..." -Level Debug
    try {
        $drives = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/sites/$SiteGraphId/drives?`$select=id,name,driveType,quota,webUrl" `
            -ErrorAction Stop

        # The Graph drives API reports site-level quota.used for all drives in a SharePoint site,
        # not per-library sizes. We collect all drives, then keep only the primary (largest) one
        # per site to avoid duplicate rows with identical sizes.
        $candidates = @()
        foreach ($drive in $drives.value) {
            if (Test-IsSystemLibrary $drive.name) { continue }
            $sizeMB = 0
            if ($drive.quota -and $null -ne $drive.quota.used) {
                $sizeMB = [math]::Round($drive.quota.used / 1MB, 2)
            }
            $candidates += [PSCustomObject]@{
                Name      = $drive.name
                WebUrl    = $drive.webUrl
                DriveType = $drive.driveType
                SizeMB    = $sizeMB
            }
        }

        # Prefer a library named "Documents" if present, otherwise take the largest
        $primary = $candidates | Where-Object { $_.Name -eq "Documents" } | Select-Object -First 1
        if (-not $primary) { $primary = $candidates | Sort-Object SizeMB -Descending | Select-Object -First 1 }

        if ($primary) {
            $remaining = $null
            $firstDrive = $drives.value | Where-Object { $_.name -eq $primary.Name } | Select-Object -First 1
            if ($firstDrive.quota -and $null -ne $firstDrive.quota.remaining) {
                $remaining = [math]::Round($firstDrive.quota.remaining / 1MB, 2)
            }
            $Script:Data.Libraries.Add([PSCustomObject]@{
                SiteTitle        = $siteTitle
                SiteUrl          = $siteUrl
                LibraryName      = $primary.Name
                LibraryUrl       = $primary.WebUrl
                DriveType        = $primary.DriveType
                SizeMB           = $primary.SizeMB
                SizeReadable     = Convert-BytesToReadable ($primary.SizeMB * 1MB)
                QuotaRemainingMB = $remaining
            })
        }
    } catch {
        Write-Log "  Failed to get libraries for ${SiteUrl}: $_" -Level Warning
        Add-Error -Operation "Get-SiteLibraries" -Target $SiteUrl -ErrorMessage $_.Exception.Message
    }
}

function Get-DriveTopItems {
    param(
        [Parameter(Mandatory = $true)][string]$SiteGraphId,
        [Parameter(Mandatory = $true)][string]$SiteUrl,
        [Parameter(Mandatory = $true)][string]$SiteTitle
    )

    Write-Log "  Getting top files and folders..." -Level Debug
    try {
        $drives = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/sites/$SiteGraphId/drives?`$select=id,name,driveType" `
            -ErrorAction Stop

        foreach ($drive in $drives.value) {
            if (Test-IsSystemLibrary $drive.name) { continue }

            # ---- ROOT-LEVEL FOLDERS (size = cumulative total of ALL nested contents) ----
            try {
                $rootItems = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/drives/$($drive.id)/root/children?`$select=name,size,file,folder,webUrl&`$top=500" `
                    -ErrorAction Stop

                foreach ($item in $rootItems.value) {
                    if ($item.folder -and $item.size -gt 0) {
                        $Script:Data.TopFolders.Add([PSCustomObject]@{
                            FolderName   = $item.name
                            SizeBytes    = [long]$item.size
                            SizeReadable = Convert-BytesToReadable ([long]$item.size)
                            Library      = $drive.name
                            SiteTitle    = $SiteTitle
                            SiteUrl      = $SiteUrl
                            Url          = $item.webUrl
                        })
                    }
                }
            } catch {
                Write-Log "  Failed to get root folders for $($drive.name): $_" -Level Debug
            }

            # ---- FILES: search entire drive, take up to 200 largest by client-side sort ----
            # Note: Graph search does not support $orderby on size; we fetch 200 and sort locally.
            # For very large libraries this is a sample - the truly largest files are likely included
            # since Graph tends to surface well-known/recently-touched items.
            try {
                $searchResult = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/drives/$($drive.id)/root/search(q='')?`$select=name,size,file,webUrl,parentReference&`$top=200" `
                    -ErrorAction Stop

                foreach ($item in $searchResult.value) {
                    if ($item.file -and $item.size -gt 0) {
                        $ext = if ($item.name -match '\.([^.]+)$') { ".$($Matches[1].ToLower())" } else { "-" }
                        $parentPath = if ($item.parentReference -and $item.parentReference.path) {
                            ($item.parentReference.path -replace '^.*/root:', '') -replace '^$', '/'
                        } else { "/" }
                        $Script:Data.TopFiles.Add([PSCustomObject]@{
                            FileName     = $item.name
                            SizeBytes    = [long]$item.size
                            SizeReadable = Convert-BytesToReadable ([long]$item.size)
                            Extension    = $ext
                            ParentPath   = $parentPath
                            Library      = $drive.name
                            SiteTitle    = $SiteTitle
                            SiteUrl      = $SiteUrl
                            Url          = $item.webUrl
                        })
                    }
                }
            } catch {
                Write-Log "  Failed to search files in $($drive.name): $_" -Level Debug
            }
        }
    } catch {
        Write-Log "  Failed to enumerate drives for top items in ${SiteUrl}: $_" -Level Warning
        Add-Error -Operation "Get-DriveTopItems" -Target $SiteUrl -ErrorMessage $_.Exception.Message
    }
}

function Get-FileTypeCategory {
    param([string]$Extension)
    if ($Script:FileTypeCategories.ContainsKey($Extension)) { return $Script:FileTypeCategories[$Extension] }
    return "Other"
}

function Invoke-FileTypeEnumeration {
    # Iterative BFS - avoids PowerShell recursion limits on deep folder trees
    param([string]$DriveId, [int]$MaxDepth)

    $queue     = [System.Collections.Generic.Queue[hashtable]]::new()
    $queue.Enqueue(@{ Id = "root"; Depth = 0 })
    $fileCount = 0
    $maxFiles  = 5000   # per-drive safety cap

    while ($queue.Count -gt 0 -and $fileCount -lt $maxFiles) {
        $current = $queue.Dequeue()
        $itemId  = $current.Id
        $depth   = $current.Depth

        $uri = if ($itemId -eq "root") {
            "https://graph.microsoft.com/v1.0/drives/$DriveId/root/children?`$select=name,size,file,folder,id&`$top=200"
        } else {
            "https://graph.microsoft.com/v1.0/drives/$DriveId/items/${itemId}/children?`$select=name,size,file,folder,id&`$top=200"
        }

        do {
            try   { $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop }
            catch { break }

            foreach ($item in $response.value) {
                if ($item.file -and $item.size -gt 0) {
                    $fileCount++
                    $ext = if ($item.name -match '\.([^.]+)$') { ".$($Matches[1].ToLower())" } else { "(no ext)" }
                    if ($Script:Data.FileTypeBytes.ContainsKey($ext)) {
                        $Script:Data.FileTypeBytes[$ext]  += [long]$item.size
                        $Script:Data.FileTypeCounts[$ext] += 1
                    } else {
                        $Script:Data.FileTypeBytes[$ext]  = [long]$item.size
                        $Script:Data.FileTypeCounts[$ext] = 1
                    }
                } elseif ($item.folder -and $depth -lt $MaxDepth) {
                    $queue.Enqueue(@{ Id = $item.id; Depth = $depth + 1 })
                }
            }

            $uri = $response.'@odata.nextLink'
        } while ($uri -and $fileCount -lt $maxFiles)
    }

    if ($fileCount -ge $maxFiles) { Write-Log "    Reached $maxFiles file cap for drive (depth $MaxDepth)" -Level Debug }
    return $fileCount
}

function Get-SiteFileTypes {
    param(
        [Parameter(Mandatory = $true)][string]$SiteGraphId,
        [Parameter(Mandatory = $true)][string]$SiteUrl,
        [Parameter(Mandatory = $true)][string]$SiteTitle
    )

    Write-Log "  Analyzing file types (depth: $FileTypeScanDepth)..." -Level Debug
    try {
        $drives = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/sites/$SiteGraphId/drives?`$select=id,name,driveType" `
            -ErrorAction Stop

        foreach ($drive in $drives.value) {
            if (Test-IsSystemLibrary $drive.name) { continue }
            $count = Invoke-FileTypeEnumeration -DriveId $drive.id -MaxDepth $FileTypeScanDepth
            Write-Log "    $($drive.name): $count files scanned" -Level Debug
        }
    } catch {
        Write-Log "  Failed file type analysis for ${SiteUrl}: $_" -Level Warning
        Add-Error -Operation "Get-SiteFileTypes" -Target $SiteUrl -ErrorMessage $_.Exception.Message
    }
}

function Process-Site {
    param($SPOSite, [int]$Index, [int]$Total)

    $siteUrl  = $SPOSite.Url
    $isOD     = Test-IsOneDriveSite $siteUrl
    Write-Progress -Activity "Processing Sites" -Status "Site $Index of $Total" -CurrentOperation $siteUrl -PercentComplete (($Index / $Total) * 100)
    Write-Log "Processing: $siteUrl" -Level Info

    $siteTitle = $SPOSite.Title
    if ([string]::IsNullOrWhiteSpace($siteTitle)) { $siteTitle = Get-CleanSiteName $siteUrl }

    $ownerDisplay = $SPOSite.Owner
    if ([string]::IsNullOrWhiteSpace($ownerDisplay)) { $ownerDisplay = "-" }

    $siteType = Get-FriendlyTemplateName $SPOSite.Template

    $storageMB      = [double]$SPOSite.StorageUsageCurrent
    $quotaMB        = [double]$SPOSite.StorageQuota
    $percentUsed    = if ($quotaMB -gt 0) { [math]::Round(($storageMB / $quotaMB) * 100, 2) } else { 0 }
    $storageBytes   = [long]($storageMB * 1MB)
    $lastModified   = $SPOSite.LastContentModifiedDate
    $daysSinceMod   = if ($lastModified) { [int]([datetime]::Now - [datetime]$lastModified).TotalDays } else { -1 }
    $isStale        = ($daysSinceMod -ge $StaleThresholdDays -and $storageMB -ge $StaleMinimumMB)

    # Identify sites with meaningfully constrained quotas (not the default "unlimited" 25TB pool)
    # Anything below 2TB is treated as a real custom/limited quota for warning purposes
    $hasCustomQuota = ($quotaMB -gt 0 -and $quotaMB -lt 2097152)

    $record = [PSCustomObject]@{
        Title              = $siteTitle
        Url                = $siteUrl
        SiteType           = $siteType
        Template           = $SPOSite.Template
        IsOneDrive         = $isOD
        StorageUsageMB     = $storageMB
        StorageUsageBytes  = $storageBytes
        StorageReadable    = Convert-BytesToReadable $storageBytes
        StorageQuotaMB     = $quotaMB
        StorageQuotaReadable = Convert-BytesToReadable ($quotaMB * 1MB)
        StoragePercentUsed = $percentUsed
        HasCustomQuota     = $hasCustomQuota
        StorageCategory    = Get-StorageCategory $storageMB
        Owner              = $ownerDisplay
        LastModifiedDate   = if ($lastModified) { ([datetime]$lastModified).ToString("yyyy-MM-dd") } else { "-" }
        DaysSinceModified  = $daysSinceMod
        IsStale            = $isStale
        IsHubSite          = $SPOSite.IsHubSite
        LockState          = $SPOSite.LockState
    }

    if ($isOD) {
        $Script:Data.OneDrive.Add($record)
    } else {
        $Script:Data.Sites.Add($record)
    }

    # Resolve Graph site ID once if any deep-dive feature is enabled
    $graphId = $null
    $needsGraphId = ($IncludeLibraryDeepDive -or $IncludeTopItems -or $IncludeFileTypeAnalysis) -and $storageMB -gt 0 -and -not $isOD -and $SPOSite.Template -ne "RedirectSite#0"
    if ($needsGraphId) {
        $graphId = Get-SiteGraphId -SiteUrl $siteUrl
    }

    if ($IncludeLibraryDeepDive -and $graphId) {
        Get-SiteLibraries -SiteGraphId $graphId -SiteUrl $siteUrl -SiteTitle $siteTitle
    }

    if ($IncludeTopItems -and $graphId) {
        Get-DriveTopItems -SiteGraphId $graphId -SiteUrl $siteUrl -SiteTitle $siteTitle
    }

    if ($IncludeFileTypeAnalysis -and $graphId) {
        Get-SiteFileTypes -SiteGraphId $graphId -SiteUrl $siteUrl -SiteTitle $siteTitle
    }
}
#endregion

#region Export Functions
function Export-ToCsv {
    Write-Log "Exporting data to CSV files..." -Level Info
    $csvFiles = @()

    if ($Script:Data.Sites.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Storage_Sites_$Script:Timestamp.csv"
        $Script:Data.Sites | Sort-Object StorageUsageMB -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }

    if ($Script:Data.OneDrive.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Storage_OneDrive_$Script:Timestamp.csv"
        $Script:Data.OneDrive | Sort-Object StorageUsageMB -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }

    if ($Script:Data.Libraries.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Storage_Libraries_$Script:Timestamp.csv"
        $Script:Data.Libraries | Sort-Object SizeMB -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }

    if ($Script:Data.TopFiles.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Storage_TopFiles_$Script:Timestamp.csv"
        $Script:Data.TopFiles | Sort-Object SizeBytes -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }

    if ($Script:Data.TopFolders.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Storage_TopFolders_$Script:Timestamp.csv"
        $Script:Data.TopFolders | Sort-Object SizeBytes -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $csvFiles += $path
        Write-Log "  Exported: $path" -Level Success
    }

    if ($Script:Data.Errors.Count -gt 0) {
        $path = Join-Path $OutputPath "SPO_Storage_Errors_$Script:Timestamp.csv"
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
    $allSites    = $Script:Data.Sites
    $allOneDrive = $Script:Data.OneDrive

    $totalSites      = $allSites.Count
    $totalODAccounts = $allOneDrive.Count

    $totalStorageMB    = ($allSites | Measure-Object -Property StorageUsageMB -Sum).Sum
    if (-not $totalStorageMB) { $totalStorageMB = 0 }
    $totalODStorageMB  = ($allOneDrive | Measure-Object -Property StorageUsageMB -Sum).Sum
    if (-not $totalODStorageMB) { $totalODStorageMB = 0 }
    $grandTotalMB      = $totalStorageMB + $totalODStorageMB

    $staleSites        = @($allSites | Where-Object { $_.IsStale -eq $true })
    $staleStorageMB    = ($staleSites | Measure-Object -Property StorageUsageMB -Sum).Sum
    if (-not $staleStorageMB) { $staleStorageMB = 0 }

    $warningQuotaSites = @($allSites | Where-Object { $_.HasCustomQuota -and $_.StoragePercentUsed -ge 75 }).Count
    $overQuotaSites    = @($allSites | Where-Object { $_.StoragePercentUsed -ge 100 }).Count

    # Tenant quota covers SharePoint sites only - OneDrive has per-user quotas outside this pool
    $tenantPctUsed = 0
    if ($Script:Data.TenantQuota -and $Script:Data.TenantQuota.StorageQuotaMB -gt 0) {
        $tenantPctUsed = [math]::Round(($totalStorageMB / $Script:Data.TenantQuota.StorageQuotaMB) * 100, 1)
    }

    # Top consumers (non-redirect, non-empty, top 25)
    $topSites = $allSites | Where-Object { $_.StorageUsageMB -gt 0 -and $_.Template -ne "RedirectSite#0" } |
        Sort-Object StorageUsageMB -Descending | Select-Object -First 25

    $maxSiteMB = if ($topSites.Count -gt 0) { ($topSites | Measure-Object StorageUsageMB -Maximum).Maximum } else { 1 }

    # Top files and folders (if collected)
    $top10Files   = $Script:Data.TopFiles   | Sort-Object SizeBytes -Descending | Select-Object -First 10
    $top10Folders = $Script:Data.TopFolders | Sort-Object SizeBytes -Descending | Select-Object -First 10
    $maxFileMB    = if ($top10Files.Count   -gt 0) { [math]::Round(($top10Files   | Measure-Object SizeBytes -Maximum).Maximum / 1MB, 2) } else { 1 }
    $maxFolderMB  = if ($top10Folders.Count -gt 0) { [math]::Round(($top10Folders | Measure-Object SizeBytes -Maximum).Maximum / 1MB, 2) } else { 1 }

    # Storage by site type
    $storageByType = $allSites | Where-Object { $_.StorageUsageMB -gt 0 } |
        Group-Object SiteType |
        Select-Object @{N='Type'; E={$_.Name}}, @{N='TotalMB'; E={($_.Group | Measure-Object StorageUsageMB -Sum).Sum}}, @{N='Count'; E={$_.Count}} |
        Sort-Object TotalMB -Descending

    $maxTypeMB = if ($storageByType.Count -gt 0) { ($storageByType | Measure-Object TotalMB -Maximum).Maximum } else { 1 }

    Write-Log "Generating HTML report..." -Level Info

    $htmlPath = Join-Path $OutputPath "SPO_StorageReport_$Script:Timestamp.html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SharePoint Online Storage Report - ${TenantName}</title>
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
.summary-card.muted { border-left-color: #6B7280; }
.summary-card .value { font-size: 28px; font-weight: 600; color: var(--yw-orange); }
.summary-card.warning .value { color: #d68910; }
.summary-card.danger .value { color: #dc3545; }
.summary-card.muted .value { color: #6B7280; }
.summary-card .label { font-size: 12px; color: #666; margin-top: 4px; }
.summary-card .sublabel { font-size: 10px; color: #999; margin-top: 2px; }
.section { background: #fff; border-radius: 8px; margin-bottom: 25px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); overflow: hidden; }
.section-header { background: var(--yw-light-orange); padding: 14px 20px; border-bottom: 2px solid var(--yw-orange); cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none; }
.section-header:hover { background: #FFE8D4; }
.section-header h2 { font-size: 16px; color: var(--yw-dark-orange); font-weight: 600; }
.section-header .count { background: var(--yw-orange); color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px; }
.section-header .toggle { font-size: 11px; color: #666; margin-left: 10px; }
.section-content { padding: 0; max-height: 600px; overflow: auto; }
.section-content.collapsed { display: none; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #f8f9fa; padding: 10px 12px; text-align: left; font-weight: 600; color: var(--yw-dark-orange); border-bottom: 2px solid #dee2e6; position: sticky; top: 0; z-index: 1; }
td { padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: middle; }
tr:hover { background: #f8f9fa; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; white-space: nowrap; }
.badge-success { background: #d4edda; color: #155724; }
.badge-warning { background: #fff3cd; color: #856404; }
.badge-danger { background: #f8d7da; color: #721c24; }
.badge-info { background: #d1ecf1; color: #0c5460; }
.badge-muted { background: #e9ecef; color: #495057; }
.progress-bar { width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; }
.progress-bar-fill { height: 100%; background: var(--yw-orange); border-radius: 4px; }
.progress-bar-fill.warning { background: #f0ad4e; }
.progress-bar-fill.danger { background: #dc3545; }
.bar-chart { display: flex; flex-direction: column; gap: 10px; padding: 20px; }
.bar-item { display: flex; align-items: center; gap: 10px; }
.bar-label { width: 220px; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 500; flex-shrink: 0; }
.bar-container { flex: 1; height: 22px; background: #e9ecef; border-radius: 4px; overflow: hidden; position: relative; }
.bar-fill { height: 100%; border-radius: 4px; min-width: 4px; }
.bar-value { position: absolute; left: 8px; top: 0; right: 8px; bottom: 0; display: flex; align-items: center; font-size: 10px; color: white; font-weight: 600; text-shadow: 0 1px 3px rgba(0,0,0,0.85); white-space: nowrap; overflow: hidden; pointer-events: none; }
.bar-size { width: 90px; text-align: right; font-size: 11px; color: #555; font-weight: 600; flex-shrink: 0; }
.bar-meta { width: 80px; text-align: right; font-size: 10px; color: #999; flex-shrink: 0; }
.tenant-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; padding: 20px; }
.tenant-item { display: flex; justify-content: space-between; padding: 8px 12px; background: #f8f9fa; border-radius: 4px; font-size: 12px; }
.tenant-label { color: #555; }
.tenant-value { font-weight: 600; color: var(--yw-dark-orange); }
.stale-note { padding: 12px 20px; background: #fff3cd; border-left: 3px solid #ffc107; font-size: 12px; color: #856404; }
.truncate { max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle; }
a { color: var(--yw-orange); text-decoration: none; }
a:hover { text-decoration: underline; }
.footer { text-align: center; padding: 20px; color: #666; font-size: 11px; }
.footer .tagline { color: var(--yw-orange); font-weight: 600; font-size: 13px; }
.chart-two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 0; }
.chart-divider { border-left: 1px solid #eee; }
.chart-heading { font-size: 13px; font-weight: 600; color: #333; padding: 14px 20px 8px; border-bottom: 1px solid #f0f0f0; }
.filetype-grid { display: grid; grid-template-columns: 1fr 1fr; }
.filetype-panel { min-width: 0; }
.filetype-divider { border-left: 1px solid #eee; }
@media (max-width: 900px) { .chart-two-col, .filetype-grid { grid-template-columns: 1fr; } .filetype-divider { border-left: none; border-top: 1px solid #eee; } .bar-label { width: 140px; } }
@media print { .section-content { max-height: none !important; } }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>SharePoint Online Storage Report</h1>
    <div class="tagline">Tenant: ${TenantName} &nbsp;|&nbsp; Storage Management Analysis</div>
  </div>
  <div class="company">
    <div class="company-name">$($Script:Branding.CompanyName)</div>
    <div class="report-date">Generated: $Script:ReportDate</div>
    <div class="tagline">$($Script:Branding.Tagline)</div>
  </div>
</div>
<div class="container">
"@

    # ======================================================================
    # SUMMARY CARDS
    # ======================================================================
    $tenantPctLabel = if ($tenantPctUsed -gt 0) { "${tenantPctUsed}% of tenant quota" } else { "Tenant quota unavailable" }
    $tenantCardClass = if ($tenantPctUsed -ge 90) { "danger" } elseif ($tenantPctUsed -ge 75) { "warning" } else { "" }

    $html += @"
<div class="summary-grid">
  <div class="summary-card">
    <div class="value">$totalSites</div>
    <div class="label">SharePoint Sites</div>
    <div class="sublabel">$(if (-not $ExcludeOneDrive) { "$totalODAccounts OneDrive accounts" } else { "OneDrive excluded" })</div>
  </div>
  <div class="summary-card $tenantCardClass">
    <div class="value">$(Convert-BytesToReadable ($totalStorageMB * 1MB))</div>
    <div class="label">SharePoint Storage</div>
    <div class="sublabel">$tenantPctLabel</div>
  </div>
  <div class="summary-card">
    <div class="value">$(Convert-BytesToReadable ($totalODStorageMB * 1MB))</div>
    <div class="label">OneDrive Storage</div>
    <div class="sublabel">$totalODAccounts accounts (per-user quotas)</div>
  </div>
  <div class="summary-card $(if ($staleSites.Count -gt 0) { 'warning' } else { '' })">
    <div class="value">$(Convert-BytesToReadable ($staleStorageMB * 1MB))</div>
    <div class="label">Stale Storage</div>
    <div class="sublabel">$($staleSites.Count) sites inactive $StaleThresholdDays+ days</div>
  </div>
  <div class="summary-card $(if ($warningQuotaSites -gt 0) { 'warning' } else { '' })">
    <div class="value">$warningQuotaSites</div>
    <div class="label">Quota Warnings</div>
    <div class="sublabel">Sites at 75%+ of custom quota</div>
  </div>
  <div class="summary-card $(if ($overQuotaSites -gt 0) { 'danger' } else { '' })">
    <div class="value">$overQuotaSites</div>
    <div class="label">Over Quota</div>
    <div class="sublabel">Sites exceeding storage limit</div>
  </div>
</div>
"@

    # ======================================================================
    # TENANT QUOTA SECTION
    # ======================================================================
    if ($Script:Data.TenantQuota) {
        $tq = $Script:Data.TenantQuota
        $quotaBarPct = [math]::Min($tenantPctUsed, 100)
        $quotaBarClass = if ($tenantPctUsed -ge 90) { "danger" } elseif ($tenantPctUsed -ge 75) { "warning" } else { "" }
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128190; Tenant Storage Quota</h2><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="tenant-grid">
  <div class="tenant-item"><span class="tenant-label">SharePoint Pool Quota</span><span class="tenant-value">$($tq.StorageQuotaReadable)</span></div>
  <div class="tenant-item"><span class="tenant-label">SharePoint Storage Used</span><span class="tenant-value">$(Convert-BytesToReadable ($totalStorageMB * 1MB))</span></div>
  <div class="tenant-item"><span class="tenant-label">Pool Utilization</span><span class="tenant-value">$tenantPctUsed%</span></div>
  <div class="tenant-item"><span class="tenant-label">SharePoint Sites</span><span class="tenant-value">$(Convert-BytesToReadable ($totalStorageMB * 1MB)) across $totalSites sites</span></div>
  <div class="tenant-item"><span class="tenant-label">OneDrive (separate per-user quotas)</span><span class="tenant-value">$(Convert-BytesToReadable ($totalODStorageMB * 1MB)) across $totalODAccounts accounts</span></div>
  <div class="tenant-item"><span class="tenant-label">Stale Storage</span><span class="tenant-value">$(Convert-BytesToReadable ($staleStorageMB * 1MB)) ($($staleSites.Count) sites)</span></div>
</div>
<div style="padding: 0 20px 20px;">
  <div style="font-size: 11px; color: #666; margin-bottom: 6px;">Tenant quota utilization: $tenantPctUsed%</div>
  <div class="progress-bar" style="height: 14px;">
    <div class="progress-bar-fill $quotaBarClass" style="width: ${quotaBarPct}%; height: 100%;"></div>
  </div>
</div>
</div>
</div>
"@
    }

    # ======================================================================
    # STORAGE BY SITE TYPE (BAR CHART)
    # ======================================================================
    $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128202; Storage by Site Type</h2><span class="count">$($storageByType.Count) types</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="bar-chart">
"@
    $colorIdx = 0
    foreach ($typeRow in $storageByType) {
        $barPct = if ($maxTypeMB -gt 0) { [math]::Round(($typeRow.TotalMB / $maxTypeMB) * 100, 1) } else { 0 }
        $color  = $Script:ChartColors[$colorIdx % $Script:ChartColors.Count]
        $colorIdx++
        $html += @"
<div class="bar-item">
  <div class="bar-label" title="$(Get-HtmlSafeString $typeRow.Type)">$(Get-HtmlSafeString $typeRow.Type)</div>
  <div class="bar-container">
    <div class="bar-fill" style="width: ${barPct}%; background: $color;"></div>
    <span class="bar-value">$($typeRow.Count) sites</span>
  </div>
  <div class="bar-size">$(Convert-BytesToReadable ($typeRow.TotalMB * 1MB))</div>
</div>
"@
    }
    $html += "</div></div></div>"

    # ======================================================================
    # TOP STORAGE CONSUMERS
    # ======================================================================
    $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#127942; Top Storage Consumers</h2><span class="count">Top $($topSites.Count) sites</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="bar-chart">
"@
    foreach ($site in $topSites) {
        $barPct = if ($maxSiteMB -gt 0) { [math]::Round(($site.StorageUsageMB / $maxSiteMB) * 100, 1) } else { 0 }
        $color  = Get-StorageCategoryColor $site.StorageUsageMB
        $staleFlag = if ($site.IsStale) { " &#9201;" } else { "" }
        $html += @"
<div class="bar-item">
  <div class="bar-label" title="$(Get-HtmlSafeString $site.Title) - $(Get-HtmlSafeString $site.Url)">
    <a href="$(Get-HtmlSafeString $site.Url)" target="_blank">$(Get-HtmlSafeString $site.Title)</a>$staleFlag
  </div>
  <div class="bar-container">
    <div class="bar-fill" style="width: ${barPct}%; background: $color;"></div>
    <span class="bar-value">$(Get-HtmlSafeString $site.Title) &mdash; $(Get-HtmlSafeString $site.SiteType)</span>
  </div>
  <div class="bar-size">$(Get-HtmlSafeString $site.StorageReadable)</div>
  <div class="bar-meta">$(if ($site.DaysSinceModified -ge 0) { "$($site.DaysSinceModified)d ago" } else { "-" })</div>
</div>
"@
    }
    $html += "</div></div></div>"

    # ======================================================================
    # TOP 10 LARGEST FOLDERS
    # ======================================================================
    if ($top10Folders.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128193; Top 10 Largest Folders</h2><span class="count">Root-level, cumulative size</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div style="padding: 8px 20px 4px; font-size: 11px; color: #856404; background: #fff3cd; border-bottom: 1px solid #ffeaa7;">
  Folder sizes reflect the cumulative total of all files nested within each folder. These are root-level folders in each document library.
</div>
<div class="bar-chart">
"@
        foreach ($folder in $top10Folders) {
            $folderMB  = [math]::Round($folder.SizeBytes / 1MB, 2)
            $barPct    = if ($maxFolderMB -gt 0) { [math]::Round(($folderMB / $maxFolderMB) * 100, 1) } else { 0 }
            $color     = Get-StorageCategoryColor $folderMB
            $html += @"
<div class="bar-item">
  <div class="bar-label" title="$(Get-HtmlSafeString $folder.FolderName)">
    <a href="$(Get-HtmlSafeString $folder.Url)" target="_blank">&#128193; $(Get-HtmlSafeString $folder.FolderName)</a>
  </div>
  <div class="bar-container">
    <div class="bar-fill" style="width: ${barPct}%; background: $color;"></div>
    <span class="bar-value">$(Get-HtmlSafeString $folder.FolderName) &mdash; $(Get-HtmlSafeString $folder.SiteTitle) / $(Get-HtmlSafeString $folder.Library)</span>
  </div>
  <div class="bar-size">$(Get-HtmlSafeString $folder.SizeReadable)</div>
</div>
"@
        }
        $html += @"
</div>
<table style="border-top: 1px solid #eee;">
<tr><th>Folder</th><th>Size</th><th>Library</th><th>Site</th></tr>
"@
        foreach ($folder in $top10Folders) {
            $html += "<tr>"
            $html += "<td><a href='$(Get-HtmlSafeString $folder.Url)' target='_blank'>&#128193; $(Get-HtmlSafeString $folder.FolderName)</a></td>"
            $html += "<td><strong>$(Get-HtmlSafeString $folder.SizeReadable)</strong></td>"
            $html += "<td>$(Get-HtmlSafeString $folder.Library)</td>"
            $html += "<td><a href='$(Get-HtmlSafeString $folder.SiteUrl)' target='_blank' class='truncate'>$(Get-HtmlSafeString $folder.SiteTitle)</a></td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # TOP 10 LARGEST FILES
    # ======================================================================
    if ($top10Files.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128196; Top 10 Largest Files</h2><span class="count">Sampled up to 200 files/library</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="bar-chart">
"@
        foreach ($file in $top10Files) {
            $fileMB = [math]::Round($file.SizeBytes / 1MB, 2)
            $barPct = if ($maxFileMB -gt 0) { [math]::Round(($fileMB / $maxFileMB) * 100, 1) } else { 0 }
            $color  = Get-StorageCategoryColor $fileMB
            $html += @"
<div class="bar-item">
  <div class="bar-label" title="$(Get-HtmlSafeString $file.FileName)">
    <a href="$(Get-HtmlSafeString $file.Url)" target="_blank">$(Get-HtmlSafeString $file.FileName)</a>
  </div>
  <div class="bar-container">
    <div class="bar-fill" style="width: ${barPct}%; background: $color;"></div>
    <span class="bar-value">$(Get-HtmlSafeString $file.FileName) &mdash; $(Get-HtmlSafeString $file.Extension) &mdash; $(Get-HtmlSafeString $file.SiteTitle)</span>
  </div>
  <div class="bar-size">$(Get-HtmlSafeString $file.SizeReadable)</div>
</div>
"@
        }
        $html += @"
</div>
<table style="border-top: 1px solid #eee;">
<tr><th>File</th><th>Type</th><th>Size</th><th>Path</th><th>Library</th><th>Site</th></tr>
"@
        foreach ($file in $top10Files) {
            $html += "<tr>"
            $html += "<td><a href='$(Get-HtmlSafeString $file.Url)' target='_blank'>$(Get-HtmlSafeString $file.FileName)</a></td>"
            $html += "<td><span class='badge badge-muted'>$(Get-HtmlSafeString $file.Extension)</span></td>"
            $html += "<td><strong>$(Get-HtmlSafeString $file.SizeReadable)</strong></td>"
            $html += "<td class='truncate' title='$(Get-HtmlSafeString $file.ParentPath)'>$(Get-HtmlSafeString $file.ParentPath)</td>"
            $html += "<td>$(Get-HtmlSafeString $file.Library)</td>"
            $html += "<td><a href='$(Get-HtmlSafeString $file.SiteUrl)' target='_blank' class='truncate'>$(Get-HtmlSafeString $file.SiteTitle)</a></td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # FILE TYPE ANALYSIS
    # ======================================================================
    if ($Script:Data.FileTypeBytes.Count -gt 0) {
        # Aggregate by category
        $catBytes  = @{}
        $catCounts = @{}
        foreach ($ext in $Script:Data.FileTypeBytes.Keys) {
            $cat   = Get-FileTypeCategory $ext
            $bytes = $Script:Data.FileTypeBytes[$ext]
            $count = $Script:Data.FileTypeCounts[$ext]
            if ($catBytes.ContainsKey($cat)) { $catBytes[$cat] += $bytes; $catCounts[$cat] += $count }
            else                             { $catBytes[$cat]  = $bytes; $catCounts[$cat]  = $count }
        }
        $totalScannedBytes = ($Script:Data.FileTypeBytes.Values | Measure-Object -Sum).Sum

        $sortedCats = $catBytes.GetEnumerator() | Sort-Object Value -Descending
        $maxCatBytes = ($sortedCats | Measure-Object Value -Maximum).Maximum
        if (-not $maxCatBytes -or $maxCatBytes -eq 0) { $maxCatBytes = 1 }

        $sortedExts = $Script:Data.FileTypeBytes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15
        $maxExtBytes = ($sortedExts | Select-Object -First 1).Value
        if (-not $maxExtBytes -or $maxExtBytes -eq 0) { $maxExtBytes = 1 }

        $totalFileCount = ($Script:Data.FileTypeCounts.Values | Measure-Object -Sum).Sum

        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)">
  <h2>&#128202; File Type Distribution</h2>
  <span class="count">$totalFileCount files &mdash; $(Convert-BytesToReadable $totalScannedBytes) scanned &mdash; depth $FileTypeScanDepth</span>
  <span class="toggle">&#9660;</span>
</div>
<div class="section-content">
<div class="filetype-grid">
<div class="filetype-panel">
<div class="chart-heading">Storage by Category</div>
<div class="bar-chart" style="padding: 12px 20px;">
"@
        foreach ($cat in $sortedCats) {
            $catPct   = if ($maxCatBytes -gt 0) { [math]::Round(($cat.Value / $maxCatBytes) * 100, 1) } else { 0 }
            $catPctOf = if ($totalScannedBytes -gt 0) { [math]::Round(($cat.Value / $totalScannedBytes) * 100, 0) } else { 0 }
            $catColor = if ($Script:FileCategoryColors.ContainsKey($cat.Key)) { $Script:FileCategoryColors[$cat.Key] } else { "#6B7280" }
            $html += @"
<div class="bar-item">
  <div class="bar-label" title="$($cat.Key)">$($cat.Key)</div>
  <div class="bar-container">
    <div class="bar-fill" style="width: ${catPct}%; background: $catColor;"></div>
    <span class="bar-value">$($catCounts[$cat.Key]) files &mdash; ${catPctOf}% of scanned</span>
  </div>
  <div class="bar-size">$(Convert-BytesToReadable $cat.Value)</div>
</div>
"@
        }
        $html += @"
</div>
</div>
<div class="filetype-panel filetype-divider">
<div class="chart-heading">Top Extensions by Size</div>
<div class="bar-chart" style="padding: 12px 20px;">
"@
        $extColorIdx = 0
        foreach ($ext in $sortedExts) {
            $extPct   = if ($maxExtBytes -gt 0) { [math]::Round(($ext.Value / $maxExtBytes) * 100, 1) } else { 0 }
            $extColor = $Script:ChartColors[$extColorIdx % $Script:ChartColors.Count]
            $extColorIdx++
            $extCount = $Script:Data.FileTypeCounts[$ext.Key]
            $html += @"
<div class="bar-item">
  <div class="bar-label" title="$($ext.Key)">$($ext.Key)</div>
  <div class="bar-container">
    <div class="bar-fill" style="width: ${extPct}%; background: $extColor;"></div>
    <span class="bar-value">$extCount files</span>
  </div>
  <div class="bar-size">$(Convert-BytesToReadable $ext.Value)</div>
</div>
"@
        }
        $html += "</div></div></div></div></div>"
    }

    # ======================================================================
    # CAPACITY WARNINGS
    # ======================================================================
    $warningSites = $allSites | Where-Object { $_.HasCustomQuota -and $_.StoragePercentUsed -ge 75 } | Sort-Object StoragePercentUsed -Descending
    if ($warningSites.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#9888;&#65039; Quota Warnings</h2><span class="count">$($warningSites.Count) sites</span><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Site</th><th>Type</th><th>Storage Used</th><th>Quota</th><th>% Used</th><th>Status</th><th>Owner</th></tr>
"@
        foreach ($site in $warningSites) {
            $barClass = if ($site.StoragePercentUsed -ge 100) { "danger" } elseif ($site.StoragePercentUsed -ge 90) { "danger" } else { "warning" }
            $barPct = [math]::Min($site.StoragePercentUsed, 100)
            $html += "<tr>"
            $html += "<td><a href='$(Get-HtmlSafeString $site.Url)' target='_blank' class='truncate' title='$(Get-HtmlSafeString $site.Url)'>$(Get-HtmlSafeString $site.Title)</a></td>"
            $html += "<td>$(Get-HtmlSafeString $site.SiteType)</td>"
            $html += "<td>$(Get-HtmlSafeString $site.StorageReadable)</td>"
            $html += "<td>$(Get-HtmlSafeString $site.StorageQuotaReadable)</td>"
            $html += "<td><div class='progress-bar'><div class='progress-bar-fill $barClass' style='width:${barPct}%'></div></div><small>$($site.StoragePercentUsed)%</small></td>"
            $html += "<td>$(Get-QuotaStatusBadge $site.StoragePercentUsed)</td>"
            $html += "<td class='truncate'>$(Get-HtmlSafeString $site.Owner)</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # STALE STORAGE
    # ======================================================================
    if ($staleSites.Count -gt 0) {
        $staleSorted = $staleSites | Sort-Object StorageUsageMB -Descending
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#9201; Stale Storage ($StaleThresholdDays+ Days Inactive)</h2><span class="count">$($staleSites.Count) sites &mdash; $(Convert-BytesToReadable ($staleStorageMB * 1MB))</span><span class="toggle">&#9660;</span></div>
<div class="section-content">
<div class="stale-note">These sites have $StaleMinimumMB+ MB of storage and have not been modified in $StaleThresholdDays or more days. They are candidates for archiving, cleanup, or quota reduction.</div>
<table>
<tr><th>Site</th><th>Type</th><th>Storage</th><th>Days Since Modified</th><th>Last Modified</th><th>Owner</th></tr>
"@
        foreach ($site in $staleSorted) {
            $html += "<tr>"
            $html += "<td><a href='$(Get-HtmlSafeString $site.Url)' target='_blank' class='truncate' title='$(Get-HtmlSafeString $site.Url)'>$(Get-HtmlSafeString $site.Title)</a></td>"
            $html += "<td>$(Get-HtmlSafeString $site.SiteType)</td>"
            $html += "<td>$(Get-HtmlSafeString $site.StorageReadable)</td>"
            $staleClass = if ($site.DaysSinceModified -gt 730) { "badge-danger" } elseif ($site.DaysSinceModified -gt 365) { "badge-warning" } else { "badge-info" }
            $html += "<td><span class='badge $staleClass'>$($site.DaysSinceModified) days</span></td>"
            $html += "<td>$(Get-HtmlSafeString $site.LastModifiedDate)</td>"
            $html += "<td class='truncate'>$(Get-HtmlSafeString $site.Owner)</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # ONEDRIVE ACCOUNTS
    # ======================================================================
    if ($allOneDrive.Count -gt 0) {
        $odSorted  = $allOneDrive | Sort-Object StorageUsageMB -Descending
        $odMaxMB   = ($odSorted | Measure-Object StorageUsageMB -Maximum).Maximum
        if (-not $odMaxMB -or $odMaxMB -eq 0) { $odMaxMB = 1 }

        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128100; OneDrive Accounts</h2><span class="count">$($allOneDrive.Count) accounts &mdash; $(Convert-BytesToReadable ($totalODStorageMB * 1MB))</span><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Account</th><th>Storage Used</th><th>Quota</th><th>% Used</th><th>Last Modified</th><th>Days Inactive</th></tr>
"@
        foreach ($od in $odSorted) {
            $odBarPct   = [math]::Min($od.StoragePercentUsed, 100)
            $odBarClass = if ($od.StoragePercentUsed -ge 90) { "danger" } elseif ($od.StoragePercentUsed -ge 75) { "warning" } else { "" }
            $html += "<tr>"
            $html += "<td><a href='$(Get-HtmlSafeString $od.Url)' target='_blank' class='truncate' title='$(Get-HtmlSafeString $od.Url)'>$(Get-HtmlSafeString $od.Title)</a></td>"
            $html += "<td>$(Get-HtmlSafeString $od.StorageReadable)</td>"
            $html += "<td>$(Get-HtmlSafeString $od.StorageQuotaReadable)</td>"
            $html += "<td><div class='progress-bar'><div class='progress-bar-fill $odBarClass' style='width:${odBarPct}%'></div></div><small>$($od.StoragePercentUsed)%</small></td>"
            $html += "<td>$(Get-HtmlSafeString $od.LastModifiedDate)</td>"
            $staleOD = if ($od.IsStale) { "<span class='badge badge-warning'>$($od.DaysSinceModified)d</span>" } elseif ($od.DaysSinceModified -ge 0) { "$($od.DaysSinceModified)d" } else { "-" }
            $html += "<td>$staleOD</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # LIBRARY BREAKDOWN (DEEP DIVE)
    # ======================================================================
    if ($Script:Data.Libraries.Count -gt 0) {
        $libsSorted = $Script:Data.Libraries | Sort-Object SizeMB -Descending
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128196; Library Storage Breakdown</h2><span class="count">$($Script:Data.Libraries.Count) libraries</span><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Site</th><th>Library</th><th>Type</th><th>Size</th></tr>
"@
        foreach ($lib in $libsSorted) {
            $html += "<tr>"
            $html += "<td class='truncate'><a href='$(Get-HtmlSafeString $lib.SiteUrl)' target='_blank' title='$(Get-HtmlSafeString $lib.SiteUrl)'>$(Get-HtmlSafeString $lib.SiteTitle)</a></td>"
            $html += "<td><a href='$(Get-HtmlSafeString $lib.LibraryUrl)' target='_blank'>$(Get-HtmlSafeString $lib.LibraryName)</a></td>"
            $html += "<td>$(Get-HtmlSafeString $lib.DriveType)</td>"
            $html += "<td>$(Get-HtmlSafeString $lib.SizeReadable)</td>"
            $html += "</tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # ALL SITES (FULL TABLE)
    # ======================================================================
    $activeSites = $allSites | Where-Object { $_.Template -ne "RedirectSite#0" } | Sort-Object StorageUsageMB -Descending
    $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128337; All SharePoint Sites</h2><span class="count">$($activeSites.Count) sites</span><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Site</th><th>Type</th><th>Storage</th><th>Quota</th><th>% Used</th><th>Category</th><th>Owner</th><th>Last Modified</th><th>Status</th></tr>
"@
    foreach ($site in $activeSites) {
        $barPct   = [math]::Min($site.StoragePercentUsed, 100)
        $barClass = if ($site.StoragePercentUsed -ge 90) { "danger" } elseif ($site.StoragePercentUsed -ge 75) { "warning" } else { "" }
        $catColor = Get-StorageCategoryColor $site.StorageUsageMB
        $statusBadge = if ($site.IsStale) { "<span class='badge badge-warning'>Stale</span>" } elseif ($site.LockState -eq "ReadOnly") { "<span class='badge badge-muted'>Read-Only</span>" } elseif ($site.LockState -eq "NoAccess") { "<span class='badge badge-danger'>Locked</span>" } else { "<span class='badge badge-success'>Active</span>" }
        $html += "<tr>"
        $html += "<td><a href='$(Get-HtmlSafeString $site.Url)' target='_blank' class='truncate' title='$(Get-HtmlSafeString $site.Url)'>$(Get-HtmlSafeString $site.Title)</a></td>"
        $html += "<td>$(Get-HtmlSafeString $site.SiteType)</td>"
        $html += "<td>$(Get-HtmlSafeString $site.StorageReadable)</td>"
        $html += "<td>$(if ($site.HasCustomQuota) { Get-HtmlSafeString $site.StorageQuotaReadable } else { "<span class='badge badge-muted'>Pooled</span>" })</td>"
        $html += "<td>$(if ($site.HasCustomQuota) { "<div class='progress-bar'><div class='progress-bar-fill $barClass' style='width:${barPct}%'></div></div><small>$($site.StoragePercentUsed)%</small>" } else { "-" })</td>"
        $html += "<td><span class='badge' style='background:$(Get-StorageCategoryColor $site.StorageUsageMB)22; color:$catColor; border: 1px solid ${catColor}44;'>$(Get-HtmlSafeString $site.StorageCategory)</span></td>"
        $html += "<td class='truncate'>$(Get-HtmlSafeString $site.Owner)</td>"
        $html += "<td>$(Get-HtmlSafeString $site.LastModifiedDate)</td>"
        $html += "<td>$statusBadge</td>"
        $html += "</tr>"
    }
    $html += "</table></div></div>"

    # ======================================================================
    # REDIRECT SITES (COLLAPSED BY DEFAULT)
    # ======================================================================
    $redirectSites = $allSites | Where-Object { $_.Template -eq "RedirectSite#0" }
    if ($redirectSites.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#128279; Redirect Sites</h2><span class="count">$($redirectSites.Count) sites</span><span class="toggle">&#9658;</span></div>
<div class="section-content collapsed"><table>
<tr><th>Title</th><th>URL</th><th>Last Modified</th><th>Lock State</th></tr>
"@
        foreach ($site in ($redirectSites | Sort-Object Title)) {
            $html += "<tr><td>$(Get-HtmlSafeString $site.Title)</td>"
            $html += "<td><a href='$(Get-HtmlSafeString $site.Url)' target='_blank' class='truncate'>$(Get-HtmlSafeString $site.Url)</a></td>"
            $html += "<td>$(Get-HtmlSafeString $site.LastModifiedDate)</td>"
            $html += "<td>$(Get-HtmlSafeString $site.LockState)</td></tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # ERRORS
    # ======================================================================
    if ($Script:Data.Errors.Count -gt 0) {
        $html += @"
<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>&#9888;&#65039; Errors ($($Script:Data.Errors.Count))</h2><span class="toggle">&#9660;</span></div>
<div class="section-content"><table>
<tr><th>Time</th><th>Operation</th><th>Target</th><th>Error</th></tr>
"@
        foreach ($err in $Script:Data.Errors) {
            $html += "<tr><td>$($err.Timestamp)</td><td>$(Get-HtmlSafeString $err.Operation)</td><td class='truncate'>$(Get-HtmlSafeString $err.Target)</td><td>$(Get-HtmlSafeString $err.Error)</td></tr>"
        }
        $html += "</table></div></div>"
    }

    # ======================================================================
    # FOOTER + JAVASCRIPT
    # ======================================================================
    $html += @"
</div><!-- /container -->
<div class="footer">
  <div class="tagline">$($Script:Branding.CompanyName) &mdash; $($Script:Branding.Tagline)</div>
  <div style="margin-top: 4px;">SharePoint Online Storage Report &bull; Tenant: ${TenantName} &bull; $Script:ReportDate</div>
  <div style="margin-top: 4px;">&#9201; Stale threshold: $StaleThresholdDays days &nbsp; | &nbsp; Sites scanned: $totalSites SharePoint + $totalODAccounts OneDrive</div>
</div>
<script>
function toggleSection(header) {
    var content = header.nextElementSibling;
    var toggle  = header.querySelector('.toggle');
    if (content.classList.contains('collapsed')) {
        content.classList.remove('collapsed');
        if (toggle) toggle.innerHTML = '&#9660;';
    } else {
        content.classList.add('collapsed');
        if (toggle) toggle.innerHTML = '&#9658;';
    }
}
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "HTML report saved: $htmlPath" -Level Success
    return $htmlPath
}
#endregion

#region Main Execution
function Invoke-SPOStorageReport {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor DarkYellow
    Write-Host "     SharePoint Online Storage Management Report Tool v1.0           " -ForegroundColor DarkYellow
    Write-Host "     $($Script:Branding.CompanyName) - $($Script:Branding.Tagline)   " -ForegroundColor DarkYellow
    Write-Host "======================================================================" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  No app registration required - uses delegated authentication" -ForegroundColor Green
    Write-Host "  Identifies storage consumption, stale data, and quota issues"  -ForegroundColor Green
    Write-Host ""

    if ($ExcludeOneDrive) {
        Write-Host "  OneDrive sites: EXCLUDED (-ExcludeOneDrive)" -ForegroundColor Yellow
    } else {
        Write-Host "  OneDrive sites: INCLUDED (use -ExcludeOneDrive to exclude)" -ForegroundColor Cyan
    }
    if ($IncludeLibraryDeepDive) {
        Write-Host "  Library deep dive: ENABLED (this will increase execution time)" -ForegroundColor Yellow
    }
    if ($IncludeTopItems) {
        Write-Host "  Top files/folders: ENABLED (enumerates root folders + searches up to 200 files/library)" -ForegroundColor Yellow
    }
    if ($IncludeFileTypeAnalysis) {
        Write-Host "  File type analysis: ENABLED (scan depth: $FileTypeScanDepth, up to 5,000 files/drive)" -ForegroundColor Yellow
    }
    Write-Host "  Stale threshold: $StaleThresholdDays days with $StaleMinimumMB+ MB" -ForegroundColor Cyan
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
        Get-TenantStorageQuota

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
        $totalSPO = $Script:Data.Sites.Count
        $totalOD  = $Script:Data.OneDrive.Count
        $grandMB  = (($Script:Data.Sites | Measure-Object StorageUsageMB -Sum).Sum) +
                    (($Script:Data.OneDrive | Measure-Object StorageUsageMB -Sum).Sum)

        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host "                    Report Generation Complete                        " -ForegroundColor Green
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Log "Execution time: $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))" -Level Success
        Write-Log "SharePoint sites: $totalSPO" -Level Success
        Write-Log "OneDrive accounts: $totalOD" -Level Success
        Write-Log "Total storage: $(Convert-BytesToReadable ($grandMB * 1MB))" -Level Success
        Write-Log "Stale sites: $(($Script:Data.Sites | Where-Object {$_.IsStale}).Count)" -Level $(if (($Script:Data.Sites | Where-Object {$_.IsStale}).Count -gt 0) { "Warning" } else { "Success" })
        Write-Log "Libraries collected: $($Script:Data.Libraries.Count)" -Level $(if ($IncludeLibraryDeepDive) { "Success" } else { "Info" })
        Write-Log "Top files collected: $($Script:Data.TopFiles.Count) (showing top 10)" -Level $(if ($IncludeTopItems) { "Success" } else { "Info" })
        Write-Log "Top folders collected: $($Script:Data.TopFolders.Count) (showing top 10)" -Level $(if ($IncludeTopItems) { "Success" } else { "Info" })
        Write-Log "File types indexed: $($Script:Data.FileTypeBytes.Count) extensions, $($Script:Data.FileTypeCounts.Values | Measure-Object -Sum | Select-Object -Expand Sum) files" -Level $(if ($IncludeFileTypeAnalysis) { "Success" } else { "Info" })
        Write-Log "Errors: $($Script:Data.Errors.Count)" -Level $(if ($Script:Data.Errors.Count -gt 0) { "Warning" } else { "Success" })
        Write-Host ""
        Write-Log "Output files:" -Level Info
        foreach ($csv in $csvFiles) { Write-Host "    CSV:  $csv" -ForegroundColor White }
        Write-Host "    HTML: $htmlFile" -ForegroundColor DarkYellow
        Write-Host ""

        $openReport = Read-Host "Open HTML report in browser? (Y/N)"
        if ($openReport -eq 'Y') { Start-Process $htmlFile }
    }
    finally { Disconnect-Services }
}

Invoke-SPOStorageReport
#endregion
