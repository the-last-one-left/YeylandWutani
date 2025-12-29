<#
.SYNOPSIS
    Microsoft 365 Copilot Readiness Assessment Tool
    
.DESCRIPTION
    Comprehensive assessment tool that evaluates an organization's readiness 
    to deploy Microsoft 365 Copilot. Analyzes licensing eligibility, data 
    governance, security posture, user readiness, and SharePoint/OneDrive 
    configuration to identify gaps and provide actionable recommendations.
    
    Assessment Areas:
    - Licensing Analysis (eligible base licenses, Copilot assignments)
    - User Readiness (mailbox, OneDrive, M365 Apps usage)
    - Data Governance (sensitivity labels, information protection)
    - Security Posture (Conditional Access, MFA, external sharing)
    - SharePoint/OneDrive Configuration (sharing settings, oversharing risks)
    - Sharing Links Analysis (anonymous links, org-wide links exposure)
    - Teams Configuration (transcription/recording for Copilot meetings)
    
.PARAMETER OutputPath
    Directory for HTML report and CSV exports. Defaults to current directory.
    
.PARAMETER IncludeUserDetails
    Include detailed per-user analysis (increases runtime for large tenants).
    
.PARAMETER TopCandidates
    Number of top Copilot candidates to identify based on M365 usage. Default 50.
    
.PARAMETER DaysInactive
    Days of inactivity to flag users as potentially unsuitable. Default 30.
    
.PARAMETER ExportCSV
    Export detailed findings to CSV files in addition to HTML report.

.EXAMPLE
    .\Get-CopilotReadinessReport.ps1
    Runs assessment with default settings.
    
.EXAMPLE
    .\Get-CopilotReadinessReport.ps1 -IncludeUserDetails -TopCandidates 100 -ExportCSV
    Full assessment with user details, top 100 candidates, and CSV exports.
    
.EXAMPLE
    .\Get-CopilotReadinessReport.ps1 -OutputPath "C:\Reports" -DaysInactive 60
    Assessment with custom output path and 60-day inactivity threshold.

.NOTES
    Author:         Yeyland Wutani LLC
    Version:        1.2.0
    Created:        2025-12-29
    Modified:       2025-12-29 - Added Sharing Links Analysis for Copilot exposure detection
    
    Required Modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Users
    - Microsoft.Graph.Identity.DirectoryManagement
    - Microsoft.Graph.Reports
    - Microsoft.Graph.Groups
    - ExchangeOnlineManagement (optional, for mailbox details)
    - Microsoft.Online.SharePoint.PowerShell (optional, for SPO settings)
    
    Required Graph Permissions:
    - User.Read.All
    - Directory.Read.All
    - Reports.Read.All
    - Policy.Read.All
    - Sites.Read.All
    - Group.Read.All
    - Files.Read.All (for sharing link analysis)
    - InformationProtectionPolicy.Read.All (optional)
    
    Building Better Systems
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter()]
    [string]$ClientName,
    
    [Parameter()]
    [switch]$IncludeUserDetails,
    
    [Parameter()]
    [ValidateRange(10, 500)]
    [int]$TopCandidates = 50,
    
    [Parameter()]
    [ValidateRange(7, 180)]
    [int]$DaysInactive = 30,
    
    [Parameter()]
    [switch]$ExportCSV,
    
    [Parameter()]
    [Alias('UseExistingSession')]
    [switch]$SkipNewConnection,
    
    [Parameter()]
    [ValidateRange(10, 200)]
    [int]$MaxSitesToScan = 50,
    
    [Parameter()]
    [ValidateRange(50, 500)]
    [int]$MaxItemsPerSite = 100
)

#region Configuration
$Script:Config = @{
    Version = "1.2.0"  # Added Sharing Links Analysis
    ReportDate = Get-Date
    
    # Eligible base licenses for Copilot (SKU Part Numbers)
    EligibleBaseLicenses = @{
        # Enterprise
        'SPE_E3'                    = 'Microsoft 365 E3'
        'SPE_E5'                    = 'Microsoft 365 E5'
        'ENTERPRISEPACK'            = 'Office 365 E3'
        'ENTERPRISEPREMIUM'         = 'Office 365 E5'
        'ENTERPRISEPREMIUM_NOPSTNCONF' = 'Office 365 E5 (No PSTN)'
        # Business
        'O365_BUSINESS_ESSENTIALS'  = 'Microsoft 365 Business Basic'
        'O365_BUSINESS_PREMIUM'     = 'Microsoft 365 Business Standard'
        'SPB'                       = 'Microsoft 365 Business Premium'
        'SMB_BUSINESS_ESSENTIALS'   = 'Microsoft 365 Business Basic'
        'SMB_BUSINESS_PREMIUM'      = 'Microsoft 365 Business Standard'
        # Frontline
        'SPE_F1'                    = 'Microsoft 365 F1'
        'M365_F1_COMM'              = 'Microsoft 365 F1'
        'SPE_F3'                    = 'Microsoft 365 F3'
        # Office 365 E1
        'STANDARDPACK'              = 'Office 365 E1'
        # Apps
        'O365_BUSINESS'             = 'Microsoft 365 Apps for Business'
        'OFFICESUBSCRIPTION'        = 'Microsoft 365 Apps for Enterprise'
    }
    
    # Copilot license SKUs
    CopilotLicenses = @{
        'Microsoft_365_Copilot'     = 'Microsoft 365 Copilot'
        'COPILOT_STUDIO_IN_COPILOT_FOR_M365' = 'Copilot Studio in Copilot for M365'
    }
    
    # Branding
    Brand = @{
        Name     = "Yeyland Wutani LLC"
        Tagline  = "Building Better Systems"
        Orange   = "#FF6600"
        Grey     = "#6B7280"
        DarkGrey = "#374151"
        LightGrey = "#F3F4F6"
        White    = "#FFFFFF"
        Success  = "#10B981"
        Warning  = "#F59E0B"
        Danger   = "#EF4444"
    }
}

# Initialize TenantInfo with defaults (will be populated during connection)
$Script:TenantInfo = @{
    TenantId    = "Unknown"
    DisplayName = "Unknown Organization"
    Domain      = "Unknown"
    Country     = "Unknown"
}

$Script:ClientDisplayName = "Unknown Organization"
#endregion

#region Helper Functions
function Show-YWBanner {
    <#
    .SYNOPSIS
        Displays the Yeyland Wutani ASCII banner with brand colors.
    #>
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
        "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
    )
    
    $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
    $border  = ("=" * 81)
    
    Write-Host ""
    Write-Host $border -ForegroundColor Gray
    foreach ($line in $logo) {
        Write-Host $line -ForegroundColor DarkYellow
    }
    Write-Host ""
    Write-Host $tagline.PadLeft(62) -ForegroundColor Gray
    Write-Host $border -ForegroundColor Gray
    Write-Host ""
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        'Info'    = 'Cyan'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }
    $prefixes = @{
        'Info'    = '[*]'
        'Warning' = '[!]'
        'Error'   = '[X]'
        'Success' = '[+]'
    }
    
    Write-Host "$($prefixes[$Level]) $timestamp - $Message" -ForegroundColor $colors[$Level]
}

function Test-GraphConnection {
    <#
    .SYNOPSIS
        Validates Microsoft Graph connection and required permissions.
    #>
    try {
        $context = Get-MgContext -ErrorAction Stop
        if (-not $context) {
            return $false
        }
        Write-Log "Connected to Graph as: $($context.Account)" -Level Success
        Write-Log "Tenant: $($context.TenantId)" -Level Info
        return $true
    }
    catch {
        return $false
    }
}

function Connect-RequiredServices {
    <#
    .SYNOPSIS
        Connects to required Microsoft services with appropriate scopes.
    #>
    param(
        [switch]$ForceNew
    )
    
    $requiredScopes = @(
        "User.Read.All",
        "Directory.Read.All", 
        "Reports.Read.All",
        "Policy.Read.All",
        "Sites.Read.All",
        "Group.Read.All",
        "Organization.Read.All",
        "Files.Read.All"  # Added for sharing link analysis
    )
    
    # Disconnect existing session if forcing new connection
    if ($ForceNew) {
        Write-Log "Disconnecting existing Graph session..." -Level Info
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Ignore disconnect errors
        }
    }
    
    Write-Log "Checking Microsoft Graph connection..." -Level Info
    
    # Always connect fresh if ForceNew, otherwise check existing
    $needsConnection = $ForceNew -or (-not (Test-GraphConnection))
    
    if ($needsConnection) {
        Write-Log "Connecting to Microsoft Graph (authentication required)..." -Level Info
        try {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
            if (-not (Test-GraphConnection)) {
                throw "Failed to establish Graph connection"
            }
        }
        catch {
            Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
            throw
        }
    }
    
    # Verify scopes
    $context = Get-MgContext
    $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missingScopes) {
        Write-Log "Warning: Missing recommended scopes: $($missingScopes -join ', ')" -Level Warning
        Write-Log "Some assessment features may be limited." -Level Warning
    }
    
    # Get organization/tenant information
    Write-Log "Retrieving tenant information..." -Level Info
    try {
        $orgResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization" -Method GET -ErrorAction Stop
        $org = $orgResponse.value | Select-Object -First 1
        $Script:TenantInfo = @{
            TenantId    = $org.id
            DisplayName = $org.displayName
            Domain      = ($org.verifiedDomains | Where-Object { $_.isDefault }).name
            Country     = $org.countryLetterCode
        }
        Write-Log "Connected to tenant: $($Script:TenantInfo.DisplayName)" -Level Success
    }
    catch {
        Write-Log "Unable to retrieve organization info: $($_.Exception.Message)" -Level Warning
        $Script:TenantInfo = @{
            TenantId    = $context.TenantId
            DisplayName = "Unknown Organization"
            Domain      = "Unknown"
            Country     = "Unknown"
        }
    }
}

function Get-FriendlyLicenseName {
    param([string]$SkuPartNumber)
    
    if ($Script:Config.EligibleBaseLicenses.ContainsKey($SkuPartNumber)) {
        return $Script:Config.EligibleBaseLicenses[$SkuPartNumber]
    }
    return $SkuPartNumber
}

function Get-ReadinessScore {
    <#
    .SYNOPSIS
        Calculates overall readiness score based on assessment findings.
    #>
    param(
        [hashtable]$Findings
    )
    
    $score = 0
    $maxScore = 100
    
    # Licensing (20 points)
    if ($Findings.Licensing.EligibleUserCount -gt 0) { $score += 12 }
    if ($Findings.Licensing.AvailableCopilotLicenses -gt 0) { $score += 8 }
    
    # Data Governance (20 points)
    if ($Findings.DataGovernance.SensitivityLabelsConfigured) { $score += 12 }
    if ($Findings.DataGovernance.LabeledSitesPercent -ge 50) { $score += 8 }
    
    # Security (20 points)
    if ($Findings.Security.ConditionalAccessEnabled) { $score += 8 }
    if ($Findings.Security.MFAEnforcementPercent -ge 80) { $score += 8 }
    if (-not $Findings.Security.AnonymousLinksAllowed) { $score += 4 }
    
    # User Readiness (20 points)
    if ($Findings.UserReadiness.ActiveUsersPercent -ge 70) { $score += 12 }
    if ($Findings.UserReadiness.OneDriveProvisionedPercent -ge 80) { $score += 8 }
    
    # Sharing Links (20 points) - NEW
    if ($Findings.SharingLinks) {
        # Fewer anonymous links = better score
        if ($Findings.SharingLinks.AnonymousLinkCount -eq 0) { 
            $score += 10 
        }
        elseif ($Findings.SharingLinks.AnonymousLinkCount -lt 10) { 
            $score += 5 
        }
        
        # Fewer org-wide links = better score  
        if ($Findings.SharingLinks.OrgWideLinkCount -eq 0) { 
            $score += 10 
        }
        elseif ($Findings.SharingLinks.OrgWideLinkCount -lt 50) { 
            $score += 5 
        }
    }
    else {
        # If no sharing analysis, give partial credit
        $score += 10
    }
    
    return [math]::Round(($score / $maxScore) * 100)
}

function Get-ReadinessLevel {
    param([int]$Score)
    
    switch ($Score) {
        { $_ -ge 80 } { return @{ Level = "Ready"; Color = $Script:Config.Brand.Success; Description = "Your organization is well-prepared for Copilot deployment." } }
        { $_ -ge 60 } { return @{ Level = "Mostly Ready"; Color = $Script:Config.Brand.Warning; Description = "Some improvements recommended before deployment." } }
        { $_ -ge 40 } { return @{ Level = "Partially Ready"; Color = $Script:Config.Brand.Warning; Description = "Significant preparation needed for optimal Copilot experience." } }
        default { return @{ Level = "Not Ready"; Color = $Script:Config.Brand.Danger; Description = "Critical gaps must be addressed before Copilot deployment." } }
    }
}
#endregion

#region Assessment Functions
function Get-LicensingAnalysis {
    <#
    .SYNOPSIS
        Analyzes tenant licensing for Copilot eligibility.
    #>
    Write-Log "Analyzing licensing..." -Level Info
    
    $results = @{
        TotalUsers = 0
        EligibleUserCount = 0
        EligibleUsers = @()
        CopilotAssignedCount = 0
        CopilotAssignedUsers = @()
        AvailableCopilotLicenses = 0
        LicenseSummary = @()
        IneligibleUserCount = 0
    }
    
    try {
        # Get all subscribed SKUs using Graph REST API
        $skuResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -Method GET -ErrorAction Stop
        $skus = $skuResponse.value
        
        # Analyze license availability
        foreach ($sku in $skus) {
            $available = $sku.prepaidUnits.enabled - $sku.consumedUnits
            
            # Check for Copilot licenses
            if ($sku.skuPartNumber -match 'Copilot|COPILOT') {
                $results.AvailableCopilotLicenses += [math]::Max(0, $available)
                $results.LicenseSummary += [PSCustomObject]@{
                    License     = $sku.skuPartNumber
                    FriendlyName = "Microsoft 365 Copilot"
                    Total       = $sku.prepaidUnits.enabled
                    Consumed    = $sku.consumedUnits
                    Available   = [math]::Max(0, $available)
                    Type        = "Copilot"
                }
            }
            # Check for eligible base licenses
            elseif ($Script:Config.EligibleBaseLicenses.ContainsKey($sku.skuPartNumber)) {
                $results.LicenseSummary += [PSCustomObject]@{
                    License     = $sku.skuPartNumber
                    FriendlyName = Get-FriendlyLicenseName $sku.skuPartNumber
                    Total       = $sku.prepaidUnits.enabled
                    Consumed    = $sku.consumedUnits
                    Available   = [math]::Max(0, $available)
                    Type        = "EligibleBase"
                }
            }
        }
        
        # Get eligible base license SKU IDs
        $eligibleSkuIds = @($skus | Where-Object { 
            $Script:Config.EligibleBaseLicenses.ContainsKey($_.skuPartNumber) 
        } | ForEach-Object { $_.skuId })
        
        # Get Copilot license SKU IDs
        $copilotSkuIds = @($skus | Where-Object { 
            $_.skuPartNumber -match 'Copilot|COPILOT' 
        } | ForEach-Object { $_.skuId })
        
        Write-Log "Found $($eligibleSkuIds.Count) eligible base license SKUs, $($copilotSkuIds.Count) Copilot SKUs" -Level Info
        
        # Get all users with licenses
        Write-Log "Retrieving user license assignments..." -Level Info
        
        $users = @()
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,assignedLicenses,accountEnabled&`$top=999"
        
        try {
            do {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                $users += $response.value
                $uri = $response.'@odata.nextLink'
                if ($users.Count % 500 -eq 0) {
                    Write-Log "Retrieved $($users.Count) users so far..." -Level Info
                }
            } while ($uri)
            
            $results.TotalUsers = $users.Count
            Write-Log "Retrieved $($results.TotalUsers) users" -Level Info
        }
        catch {
            Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
            $users = @()
        }
        
        foreach ($user in $users) {
            if (-not $user.assignedLicenses -or $user.assignedLicenses.Count -eq 0) { continue }
            
            $userSkuIds = @($user.assignedLicenses.skuId)
            
            # Check for Copilot license
            $hasCopilot = $false
            foreach ($userSku in $userSkuIds) {
                if ($userSku -in $copilotSkuIds) {
                    $hasCopilot = $true
                    break
                }
            }
            
            if ($hasCopilot) {
                $results.CopilotAssignedCount++
                $results.CopilotAssignedUsers += [PSCustomObject]@{
                    DisplayName = $user.displayName
                    UPN         = $user.userPrincipalName
                    Enabled     = $user.accountEnabled
                }
            }
            else {
                # Check for eligible base license
                $hasEligible = $false
                foreach ($userSku in $userSkuIds) {
                    if ($userSku -in $eligibleSkuIds) {
                        $hasEligible = $true
                        break
                    }
                }
                
                if ($hasEligible) {
                    $results.EligibleUserCount++
                    $results.EligibleUsers += [PSCustomObject]@{
                        DisplayName = $user.displayName
                        UPN         = $user.userPrincipalName
                        Enabled     = $user.accountEnabled
                    }
                }
            }
        }
        
        $results.IneligibleUserCount = $results.TotalUsers - $results.EligibleUserCount - $results.CopilotAssignedCount
        
        Write-Log "Found $($results.EligibleUserCount) users eligible for Copilot, $($results.CopilotAssignedCount) already assigned" -Level Success
    }
    catch {
        Write-Log "Error analyzing licenses: $($_.Exception.Message)" -Level Error
    }
    
    return $results
}

function Get-DataGovernanceAnalysis {
    <#
    .SYNOPSIS
        Analyzes data governance readiness including sensitivity labels.
    #>
    Write-Log "Analyzing data governance..." -Level Info
    
    $results = @{
        SensitivityLabelsConfigured = $false
        SensitivityLabels = @()
        LabeledSitesCount = 0
        TotalSitesChecked = 0
        LabeledSitesPercent = 0
        DLPPoliciesConfigured = $false
        RetentionPoliciesConfigured = $false
        Recommendations = @()
    }
    
    try {
        # Try to get sensitivity labels
        try {
            $labels = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels" -Method GET
            if ($labels.value.Count -gt 0) {
                $results.SensitivityLabelsConfigured = $true
                $results.SensitivityLabels = $labels.value | ForEach-Object {
                    [PSCustomObject]@{
                        Name        = $_.name
                        Id          = $_.id
                        Description = $_.description
                        IsActive    = $_.isActive
                        Priority    = $_.priority
                    }
                }
                Write-Log "Found $($labels.value.Count) sensitivity labels configured" -Level Success
            }
        }
        catch {
            Write-Log "Unable to retrieve sensitivity labels (may require additional permissions)" -Level Warning
            $results.Recommendations += "Grant InformationProtectionPolicy.Read.All permission for complete label analysis"
        }
        
        # Get groups/sites with sensitivity labels
        try {
            $groups = @()
            $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName,assignedLabels&`$top=999"
            
            do {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                $groups += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            $results.TotalSitesChecked = $groups.Count
            $results.LabeledSitesCount = ($groups | Where-Object { $_.assignedLabels.Count -gt 0 }).Count
            
            if ($results.TotalSitesChecked -gt 0) {
                $results.LabeledSitesPercent = [math]::Round(($results.LabeledSitesCount / $results.TotalSitesChecked) * 100, 1)
            }
            
            Write-Log "$($results.LabeledSitesCount) of $($results.TotalSitesChecked) M365 Groups have sensitivity labels ($($results.LabeledSitesPercent)%)" -Level Info
        }
        catch {
            Write-Log "Error checking group labels: $($_.Exception.Message)" -Level Warning
        }
        
        # Generate recommendations
        if (-not $results.SensitivityLabelsConfigured) {
            $results.Recommendations += "Configure sensitivity labels in Microsoft Purview to classify and protect content"
        }
        if ($results.LabeledSitesPercent -lt 50) {
            $results.Recommendations += "Apply sensitivity labels to Microsoft 365 Groups and SharePoint sites to control Copilot access"
        }
    }
    catch {
        Write-Log "Error in data governance analysis: $($_.Exception.Message)" -Level Error
    }
    
    return $results
}

function Get-SecurityPostureAnalysis {
    <#
    .SYNOPSIS
        Analyzes security configuration relevant to Copilot deployment.
    #>
    Write-Log "Analyzing security posture..." -Level Info
    
    $results = @{
        ConditionalAccessEnabled = $false
        ConditionalAccessPolicies = @()
        MFAEnforcementPercent = 0
        ExternalSharingLevel = "Unknown"
        AnonymousLinksAllowed = $true
        GuestAccessEnabled = $false
        GuestUserCount = 0
        Recommendations = @()
    }
    
    try {
        # Check Conditional Access policies
        try {
            $caPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method GET
            $results.ConditionalAccessPolicies = $caPolicies.value | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.displayName
                    State       = $_.state
                    CreatedDate = $_.createdDateTime
                }
            }
            $results.ConditionalAccessEnabled = ($caPolicies.value | Where-Object { $_.state -eq "enabled" }).Count -gt 0
            Write-Log "Found $($caPolicies.value.Count) Conditional Access policies" -Level Info
        }
        catch {
            Write-Log "Unable to retrieve Conditional Access policies (requires Policy.Read.All)" -Level Warning
        }
        
        # Check guest users
        try {
            $guestResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=1" -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
            $results.GuestUserCount = $guestResponse.'@odata.count'
            if (-not $results.GuestUserCount) {
                $guests = @()
                $uri = "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id&`$top=999"
                do {
                    $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                    $guests += $response.value
                    $uri = $response.'@odata.nextLink'
                } while ($uri -and $guests.Count -lt 1000)
                $results.GuestUserCount = $guests.Count
            }
            $results.GuestAccessEnabled = $results.GuestUserCount -gt 0
            Write-Log "Found $($results.GuestUserCount) guest users in tenant" -Level Info
        }
        catch {
            Write-Log "Error counting guest users: $($_.Exception.Message)" -Level Warning
        }
        
        # Generate recommendations
        if (-not $results.ConditionalAccessEnabled) {
            $results.Recommendations += "Enable Conditional Access policies to control Copilot access based on user/device risk"
        }
        if ($results.GuestUserCount -gt 0) {
            $results.Recommendations += "Review guest user access - Copilot can surface content accessible to the signed-in user"
        }
    }
    catch {
        Write-Log "Error in security analysis: $($_.Exception.Message)" -Level Error
    }
    
    return $results
}

function Get-UserReadinessAnalysis {
    <#
    .SYNOPSIS
        Analyzes user readiness based on M365 usage patterns.
    #>
    param([int]$DaysInactive, [int]$TopCandidates)
    
    Write-Log "Analyzing user readiness..." -Level Info
    
    $results = @{
        TotalAnalyzed = 0
        ActiveUsersPercent = 0
        OneDriveProvisionedPercent = 0
        OneDriveProvisionedCount = 0
        OneDriveNotProvisionedCount = 0
        UsersWithoutOneDrive = @()
        TopCopilotCandidates = @()
        InactiveUsers = @()
        UsageMetrics = @{
            TeamsActive = 0
            OutlookActive = 0
            OneDriveActive = 0
            SharePointActive = 0
        }
        Recommendations = @()
        OneDriveReportUserCount = 0
        LicensedUserCount = 0
    }
    
    try {
        # Get OneDrive provisioning status
        Write-Log "Retrieving OneDrive provisioning status..." -Level Info
        try {
            $oneDriveUsage = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='D30')" -Method GET -OutputType HttpResponseMessage
            $csvContent = [System.Text.Encoding]::UTF8.GetString($oneDriveUsage.Content.ReadAsByteArrayAsync().Result)
            
            if ($csvContent.StartsWith([char]0xFEFF)) {
                $csvContent = $csvContent.Substring(1)
            }
            $csvContent = $csvContent -replace '^\xEF\xBB\xBF', ''
            
            $oneDriveData = $csvContent | ConvertFrom-Csv
            
            if ($oneDriveData.Count -gt 0) {
                $sampleRow = $oneDriveData | Select-Object -First 1
                $columns = @($sampleRow.PSObject.Properties.Name)
                
                $results.OneDriveReportUserCount = $oneDriveData.Count
                $results.OneDriveProvisionedCount = $oneDriveData.Count
                
                Write-Log "All $($oneDriveData.Count) users in OneDrive report are counted as provisioned" -Level Info
                
                $activityColumn = $columns | Where-Object { $_ -match 'Last.*Activity|Activity.*Date' } | Select-Object -First 1
                
                if (-not $activityColumn) {
                    foreach ($col in $columns) {
                        $testValue = "$($sampleRow.$col)"
                        if ($testValue -match '^\d{4}-\d{2}-\d{2}') {
                            $activityColumn = $col
                            break
                        }
                    }
                }
                
                if ($activityColumn) {
                    $results.UsageMetrics.OneDriveActive = @($oneDriveData | Where-Object { 
                        $_.$activityColumn -and $_.$activityColumn.Trim() -ne '' 
                    }).Count
                    Write-Log "OneDrive active users (with activity date): $($results.UsageMetrics.OneDriveActive)" -Level Info
                }
                else {
                    $results.UsageMetrics.OneDriveActive = $oneDriveData.Count
                    Write-Log "Could not identify activity column - using total count as active estimate" -Level Warning
                }
            }
        }
        catch {
            Write-Log "Unable to retrieve OneDrive usage data: $($_.Exception.Message)" -Level Warning
        }
        
        # Get Teams usage
        try {
            $teamsUsage = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserDetail(period='D30')" -Method GET -OutputType HttpResponseMessage
            $teamsData = [System.Text.Encoding]::UTF8.GetString($teamsUsage.Content.ReadAsByteArrayAsync().Result) | ConvertFrom-Csv
            $results.UsageMetrics.TeamsActive = ($teamsData | Where-Object { $_.'Last Activity Date' }).Count
            Write-Log "Teams active users: $($results.UsageMetrics.TeamsActive)" -Level Info
        }
        catch {
            Write-Log "Unable to retrieve Teams usage data: $($_.Exception.Message)" -Level Warning
        }
        
        # Get Outlook usage
        try {
            $outlookUsage = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D30')" -Method GET -OutputType HttpResponseMessage
            $outlookData = [System.Text.Encoding]::UTF8.GetString($outlookUsage.Content.ReadAsByteArrayAsync().Result) | ConvertFrom-Csv
            $results.UsageMetrics.OutlookActive = ($outlookData | Where-Object { $_.'Last Activity Date' }).Count
            Write-Log "Outlook active users: $($results.UsageMetrics.OutlookActive)" -Level Info
        }
        catch {
            Write-Log "Unable to retrieve Outlook usage data: $($_.Exception.Message)" -Level Warning
        }
        
        # Get total licensed user count
        try {
            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=assignedLicenses/`$count ne 0&`$select=id&`$top=999&`$count=true"
            
            try {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
                $results.LicensedUserCount = $response.'@odata.count'
                
                if (-not $results.LicensedUserCount -or $results.LicensedUserCount -eq 0) {
                    $countResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/`$count" -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
                    $results.LicensedUserCount = $countResponse
                }
            }
            catch {
                $countResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/`$count" -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction SilentlyContinue
                $results.LicensedUserCount = if ($countResponse) { $countResponse } else { 0 }
            }
            
            Write-Log "Total users for comparison: $($results.LicensedUserCount)" -Level Info
        }
        catch {
            Write-Log "Error getting user count: $($_.Exception.Message)" -Level Warning
        }
        
        # Calculate percentages
        $results.TotalAnalyzed = $results.LicensedUserCount
        
        if ($results.LicensedUserCount -gt 0 -and $results.OneDriveProvisionedCount -gt 0) {
            $results.OneDriveNotProvisionedCount = [math]::Max(0, $results.LicensedUserCount - $results.OneDriveProvisionedCount)
            $results.OneDriveProvisionedPercent = [math]::Round(
                ($results.OneDriveProvisionedCount / $results.LicensedUserCount) * 100, 1
            )
            $results.OneDriveProvisionedPercent = [math]::Min(100, $results.OneDriveProvisionedPercent)
        }
        elseif ($results.OneDriveProvisionedCount -gt 0) {
            $results.TotalAnalyzed = $results.OneDriveProvisionedCount
            $results.OneDriveProvisionedPercent = 100
            $results.OneDriveNotProvisionedCount = 0
        }
        
        Write-Log "OneDrive Provisioned: $($results.OneDriveProvisionedCount) of $($results.TotalAnalyzed) users ($($results.OneDriveProvisionedPercent)%)" -Level Success
        
        $allActiveUsers = @($results.UsageMetrics.TeamsActive, $results.UsageMetrics.OutlookActive, $results.UsageMetrics.OneDriveActive) | 
            Sort-Object -Descending | Select-Object -First 1
        
        if ($results.TotalAnalyzed -gt 0 -and $allActiveUsers -gt 0) {
            $results.ActiveUsersPercent = [math]::Round(($allActiveUsers / $results.TotalAnalyzed) * 100, 1)
        }
        
        Write-Log "Active users: $($results.ActiveUsersPercent)%" -Level Info
        
        # Generate recommendations
        if ($results.ActiveUsersPercent -lt 70) {
            $results.Recommendations += "Active user percentage is $($results.ActiveUsersPercent)% - consider targeting Copilot licenses to most active users first"
        }
        
        if ($results.OneDriveProvisionedPercent -lt 80) {
            $results.Recommendations += "OneDrive provisioning is at $($results.OneDriveProvisionedPercent)% - ensure all target Copilot users have accessed OneDrive at least once"
        }
        
        if ($results.OneDriveNotProvisionedCount -gt 0) {
            $results.Recommendations += "Approximately $($results.OneDriveNotProvisionedCount) licensed user(s) may not have OneDrive provisioned yet. OneDrive is auto-provisioned on first access."
        }
    }
    catch {
        Write-Log "Error in user readiness analysis: $($_.Exception.Message)" -Level Error
    }
    
    return $results
}

function Get-SharingLinksAnalysis {
    <#
    .SYNOPSIS
        Analyzes sharing links across SharePoint and OneDrive that could expose content to Copilot.
        
        CRITICAL FOR COPILOT:
        - Anonymous links ("Anyone with the link") - Content accessible to anyone, including external
        - Organization-wide links ("People in your organization") - ALL internal users can access via Copilot
        - Both types mean Copilot can surface this content to users who didn't create or explicitly receive the link
        
    .DESCRIPTION
        This function scans SharePoint sites and OneDrive locations to identify:
        1. Anonymous sharing links (highest risk)
        2. Organization-wide sharing links (high risk for Copilot)
        3. Files/folders with multiple sharing links
        4. Recently created broad sharing links
        
    .PARAMETER MaxSitesToScan
        Maximum number of sites to scan. Default 50.
        
    .PARAMETER MaxItemsPerSite
        Maximum items to check per site. Default 100.
    #>
    param(
        [int]$MaxSitesToScan = 50,
        [int]$MaxItemsPerSite = 100
    )
    
    Write-Log "Analyzing sharing links for Copilot exposure risks..." -Level Info
    
    $results = @{
        TotalSitesScanned = 0
        TotalItemsScanned = 0
        AnonymousLinkCount = 0
        OrgWideLinkCount = 0
        AnonymousLinks = @()
        OrgWideLinks = @()
        HighRiskItems = @()  # Items with multiple broad sharing links
        SitesSummary = @()
        ScanLimitReached = $false
        Recommendations = @()
    }
    
    try {
        # Get sites to scan
        Write-Log "Retrieving SharePoint sites for sharing link analysis..." -Level Info
        $sites = @()
        
        try {
            $uri = "https://graph.microsoft.com/v1.0/sites/getAllSites?`$top=100&`$select=id,displayName,webUrl,siteCollection"
            do {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                $sites += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri -and $sites.Count -lt ($MaxSitesToScan * 2))
        }
        catch {
            # Fallback: get sites from groups
            Write-Log "getAllSites not available, using M365 Groups..." -Level Warning
            $groups = @()
            $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName&`$top=100"
            
            do {
                $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method GET -ErrorAction Stop
                $groups += $groupResponse.value
                $groupUri = $groupResponse.'@odata.nextLink'
            } while ($groupUri -and $groups.Count -lt $MaxSitesToScan)
            
            foreach ($group in $groups | Select-Object -First $MaxSitesToScan) {
                try {
                    $site = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/sites/root" -Method GET -ErrorAction SilentlyContinue
                    if ($site) { $sites += $site }
                }
                catch { }
            }
        }
        
        # Limit sites to scan
        $sitesToScan = $sites | Select-Object -First $MaxSitesToScan
        Write-Log "Will scan $($sitesToScan.Count) sites for sharing links (max: $MaxSitesToScan)" -Level Info
        
        $siteCount = 0
        foreach ($site in $sitesToScan) {
            $siteCount++
            $results.TotalSitesScanned++
            
            $siteId = $site.id
            $siteName = $site.displayName
            $siteUrl = $site.webUrl
            
            $siteSummary = @{
                SiteName = $siteName
                SiteUrl = $siteUrl
                AnonymousLinks = 0
                OrgWideLinks = 0
                ItemsScanned = 0
            }
            
            if ($siteCount % 10 -eq 0) {
                Write-Log "Scanning site $siteCount of $($sitesToScan.Count): $siteName" -Level Info
            }
            
            try {
                # Get drives (document libraries) for this site
                $drives = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/drives?`$select=id,name,webUrl" -Method GET -ErrorAction SilentlyContinue
                
                foreach ($drive in $drives.value) {
                    $driveId = $drive.id
                    $driveName = $drive.name
                    
                    # Get items with sharing permissions
                    # We'll use search or enumerate root items
                    try {
                        $itemsToCheck = @()
                        
                        # Get root items and some children
                        $rootItems = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/root/children?`$top=50&`$select=id,name,webUrl,folder,file,shared" -Method GET -ErrorAction SilentlyContinue
                        
                        if ($rootItems.value) {
                            $itemsToCheck += $rootItems.value
                            
                            # For folders, get one level of children
                            foreach ($folder in ($rootItems.value | Where-Object { $_.folder }) | Select-Object -First 10) {
                                try {
                                    $children = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$($folder.id)/children?`$top=20&`$select=id,name,webUrl,folder,file,shared" -Method GET -ErrorAction SilentlyContinue
                                    if ($children.value) {
                                        $itemsToCheck += $children.value
                                    }
                                }
                                catch { }
                                
                                if ($itemsToCheck.Count -ge $MaxItemsPerSite) { break }
                            }
                        }
                        
                        # Check each item for sharing links
                        foreach ($item in $itemsToCheck | Select-Object -First $MaxItemsPerSite) {
                            $results.TotalItemsScanned++
                            $siteSummary.ItemsScanned++
                            
                            $itemId = $item.id
                            $itemName = $item.name
                            $itemUrl = $item.webUrl
                            $isFolder = $null -ne $item.folder
                            
                            # Get permissions for this item
                            try {
                                $permissions = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/items/$itemId/permissions" -Method GET -ErrorAction SilentlyContinue
                                
                                $itemAnonymousLinks = 0
                                $itemOrgLinks = 0
                                
                                foreach ($perm in $permissions.value) {
                                    # Check for sharing links
                                    if ($perm.link) {
                                        $linkScope = $perm.link.scope
                                        $linkType = $perm.link.type
                                        $linkUrl = $perm.link.webUrl
                                        
                                        if ($linkScope -eq 'anonymous') {
                                            # Anonymous link - anyone with the link can access
                                            $itemAnonymousLinks++
                                            $results.AnonymousLinkCount++
                                            $siteSummary.AnonymousLinks++
                                            
                                            $results.AnonymousLinks += [PSCustomObject]@{
                                                SiteName    = $siteName
                                                SiteUrl     = $siteUrl
                                                Library     = $driveName
                                                ItemName    = $itemName
                                                ItemUrl     = $itemUrl
                                                ItemType    = if ($isFolder) { "Folder" } else { "File" }
                                                LinkType    = $linkType  # view, edit, etc.
                                                LinkUrl     = $linkUrl
                                                Risk        = "CRITICAL"
                                                CopilotImpact = "Content accessible to ANYONE - external and internal"
                                            }
                                        }
                                        elseif ($linkScope -eq 'organization') {
                                            # Organization-wide link - all internal users can access
                                            $itemOrgLinks++
                                            $results.OrgWideLinkCount++
                                            $siteSummary.OrgWideLinks++
                                            
                                            $results.OrgWideLinks += [PSCustomObject]@{
                                                SiteName    = $siteName
                                                SiteUrl     = $siteUrl
                                                Library     = $driveName
                                                ItemName    = $itemName
                                                ItemUrl     = $itemUrl
                                                ItemType    = if ($isFolder) { "Folder" } else { "File" }
                                                LinkType    = $linkType
                                                LinkUrl     = $linkUrl
                                                Risk        = "HIGH"
                                                CopilotImpact = "Content accessible to ALL users in organization via Copilot"
                                            }
                                        }
                                    }
                                }
                                
                                # Flag items with multiple broad sharing links
                                if (($itemAnonymousLinks + $itemOrgLinks) -gt 1) {
                                    $results.HighRiskItems += [PSCustomObject]@{
                                        SiteName        = $siteName
                                        ItemName        = $itemName
                                        ItemUrl         = $itemUrl
                                        ItemType        = if ($isFolder) { "Folder" } else { "File" }
                                        AnonymousLinks  = $itemAnonymousLinks
                                        OrgWideLinks    = $itemOrgLinks
                                        TotalBroadLinks = $itemAnonymousLinks + $itemOrgLinks
                                        Risk            = if ($itemAnonymousLinks -gt 0) { "CRITICAL" } else { "HIGH" }
                                    }
                                }
                            }
                            catch {
                                # Permission check failed for this item
                            }
                        }
                    }
                    catch {
                        # Drive enumeration failed
                    }
                }
            }
            catch {
                # Site processing failed
            }
            
            # Add site summary
            if ($siteSummary.AnonymousLinks -gt 0 -or $siteSummary.OrgWideLinks -gt 0) {
                $results.SitesSummary += [PSCustomObject]@{
                    SiteName       = $siteSummary.SiteName
                    SiteUrl        = $siteSummary.SiteUrl
                    AnonymousLinks = $siteSummary.AnonymousLinks
                    OrgWideLinks   = $siteSummary.OrgWideLinks
                    TotalBroadLinks = $siteSummary.AnonymousLinks + $siteSummary.OrgWideLinks
                    ItemsScanned   = $siteSummary.ItemsScanned
                    Risk           = if ($siteSummary.AnonymousLinks -gt 0) { "CRITICAL" } elseif ($siteSummary.OrgWideLinks -gt 10) { "HIGH" } else { "MEDIUM" }
                }
            }
        }
        
        # Check if we hit limits
        if ($sites.Count -gt $MaxSitesToScan) {
            $results.ScanLimitReached = $true
            Write-Log "Scan limit reached - only $MaxSitesToScan of $($sites.Count) sites were scanned" -Level Warning
        }
        
        # Log summary
        Write-Log "Sharing Links Analysis Complete:" -Level Info
        Write-Log "  Sites scanned: $($results.TotalSitesScanned)" -Level Info
        Write-Log "  Items scanned: $($results.TotalItemsScanned)" -Level Info
        Write-Log "  Anonymous links found: $($results.AnonymousLinkCount)" -Level $(if($results.AnonymousLinkCount -gt 0){'Warning'}else{'Info'})
        Write-Log "  Organization-wide links found: $($results.OrgWideLinkCount)" -Level $(if($results.OrgWideLinkCount -gt 0){'Warning'}else{'Info'})
        
        # Generate recommendations
        if ($results.AnonymousLinkCount -gt 0) {
            $results.Recommendations += "CRITICAL: Found $($results.AnonymousLinkCount) anonymous sharing link(s). These allow ANYONE (including external users) to access content. While external users can't use your Copilot, anyone who gets the link can view/download the content."
        }
        
        if ($results.OrgWideLinkCount -gt 0) {
            $results.Recommendations += "HIGH RISK: Found $($results.OrgWideLinkCount) organization-wide sharing link(s). Copilot will surface this content to ANY user in your organization, even if they weren't explicitly shared on the file."
        }
        
        if ($results.HighRiskItems.Count -gt 0) {
            $results.Recommendations += "Found $($results.HighRiskItems.Count) item(s) with multiple broad sharing links. Review these items as they have elevated exposure risk."
        }
        
        if ($results.OrgWideLinkCount -gt 50) {
            $results.Recommendations += "Consider implementing a policy to limit 'People in your organization' links. Use SharePoint Admin Center > Policies > Sharing to restrict default link types."
        }
        
        if ($results.AnonymousLinkCount -gt 0 -or $results.OrgWideLinkCount -gt 0) {
            $results.Recommendations += "Use the SharePoint Admin Center 'Sharing' report or run Get-SPOSite -Limit All | Select-Object Url, SharingCapability to audit sharing settings across all sites."
            $results.Recommendations += "Consider using sensitivity labels with 'Block download' or encryption to prevent oversharing of sensitive content."
        }
        
        if ($results.ScanLimitReached) {
            $results.Recommendations += "NOTE: Only $($results.TotalSitesScanned) sites were scanned. Run a full tenant audit using SharePoint Admin Center or PnP PowerShell for complete visibility."
        }
    }
    catch {
        Write-Log "Error in sharing links analysis: $($_.Exception.Message)" -Level Error
        $results.Recommendations += "Sharing links analysis encountered errors. Ensure Files.Read.All permission is granted."
    }
    
    return $results
}

function Get-SharePointAnalysis {
    <#
    .SYNOPSIS
        Analyzes SharePoint/OneDrive configuration for Copilot readiness.
        Focuses on identifying oversharing risks that could expose sensitive data.
    #>
    Write-Log "Analyzing SharePoint/OneDrive configuration..." -Level Info
    
    $results = @{
        TotalSites = 0
        ExternalSharingEnabled = 0
        OversharedSites = @()
        EveryoneSites = @()
        SensitiveContentRisks = @()
        SharingCapability = "Unknown"
        Recommendations = @()
    }
    
    try {
        # Get root site
        try {
            $rootSite = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/root" -Method GET -ErrorAction Stop
            Write-Log "Connected to SharePoint: $($rootSite.webUrl)" -Level Info
        }
        catch {
            Write-Log "Unable to access SharePoint root site: $($_.Exception.Message)" -Level Warning
            $results.Recommendations += "Grant Sites.Read.All permission for SharePoint analysis"
            return $results
        }
        
        # Get all sites
        $sites = @()
        try {
            $uri = "https://graph.microsoft.com/v1.0/sites/getAllSites?`$top=100"
            do {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                $sites += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri -and $sites.Count -lt 500)
        }
        catch {
            Write-Log "getAllSites not available, enumerating from M365 Groups..." -Level Warning
            try {
                $groups = @()
                $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName&`$top=100"
                
                do {
                    $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method GET -ErrorAction Stop
                    $groups += $groupResponse.value
                    $groupUri = $groupResponse.'@odata.nextLink'
                } while ($groupUri -and $groups.Count -lt 200)
                
                foreach ($group in $groups) {
                    try {
                        $site = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/sites/root" -Method GET -ErrorAction SilentlyContinue
                        if ($site) { $sites += $site }
                    }
                    catch { }
                }
            }
            catch {
                Write-Log "Unable to enumerate sites: $($_.Exception.Message)" -Level Warning
            }
        }
        
        $results.TotalSites = $sites.Count
        Write-Log "Found $($results.TotalSites) SharePoint sites" -Level Info
        
        # Analyze sites for oversharing risks
        Write-Log "Checking sites for oversharing risks..." -Level Info
        $siteCount = 0
        foreach ($site in $sites | Select-Object -First 50) {
            $siteCount++
            if ($siteCount % 10 -eq 0) {
                Write-Log "Analyzed $siteCount sites..." -Level Info
            }
            
            $siteId = $site.id
            $siteName = $site.displayName
            $siteUrl = $site.webUrl
            
            try {
                $permissions = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/permissions" -Method GET -ErrorAction SilentlyContinue
                
                $hasEveryoneAccess = $false
                $permissionDetails = @()
                
                foreach ($perm in $permissions.value) {
                    if ($perm.grantedToIdentitiesV2) {
                        foreach ($identity in $perm.grantedToIdentitiesV2) {
                            if ($identity.siteUser.loginName -match 'everyone|all users|c:0\(.s\|true' -or
                                $identity.siteUser.displayName -match 'Everyone') {
                                $hasEveryoneAccess = $true
                                $permissionDetails += "Everyone access detected"
                            }
                        }
                    }
                    if ($perm.grantedTo) {
                        if ($perm.grantedTo.user.displayName -match 'Everyone') {
                            $hasEveryoneAccess = $true
                            $permissionDetails += "Everyone: $($perm.roles -join ', ')"
                        }
                    }
                }
                
                if ($permissions.value.Count -gt 15 -or $hasEveryoneAccess) {
                    $results.OversharedSites += [PSCustomObject]@{
                        SiteName        = $siteName
                        SiteUrl         = $siteUrl
                        PermissionCount = $permissions.value.Count
                        HasEveryoneAccess = $hasEveryoneAccess
                        Risk            = if ($hasEveryoneAccess) { "HIGH" } elseif ($permissions.value.Count -gt 20) { "MEDIUM" } else { "LOW" }
                    }
                }
                
                if ($hasEveryoneAccess) {
                    $results.EveryoneSites += [PSCustomObject]@{
                        SiteName = $siteName
                        SiteUrl  = $siteUrl
                        Details  = $permissionDetails -join "; "
                    }
                }
            }
            catch { }
            
            # Check for sensitive content
            try {
                $drives = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/drives" -Method GET -ErrorAction SilentlyContinue
                foreach ($drive in $drives.value) {
                    try {
                        $searchUri = "https://graph.microsoft.com/v1.0/drives/$($drive.id)/root/search(q='SSN OR social security OR credit card OR password OR confidential')?`$top=5"
                        $searchResults = Invoke-MgGraphRequest -Uri $searchUri -Method GET -ErrorAction SilentlyContinue
                        
                        if ($searchResults.value.Count -gt 0) {
                            $sampleFiles = ($searchResults.value | Select-Object -First 3 | ForEach-Object { $_.name }) -join ", "
                            $results.SensitiveContentRisks += [PSCustomObject]@{
                                SiteName    = $siteName
                                SiteUrl     = $siteUrl
                                Library     = $drive.name
                                MatchCount  = $searchResults.value.Count
                                SampleFiles = $sampleFiles
                                Risk        = "REVIEW"
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
        
        Write-Log "Found $($results.EveryoneSites.Count) sites with 'Everyone' access" -Level $(if($results.EveryoneSites.Count -gt 0){'Warning'}else{'Info'})
        Write-Log "Found $($results.SensitiveContentRisks.Count) sites with potentially sensitive content" -Level $(if($results.SensitiveContentRisks.Count -gt 0){'Warning'}else{'Info'})
        
        # Generate recommendations
        if ($results.EveryoneSites.Count -gt 0) {
            $results.Recommendations += "CRITICAL: $($results.EveryoneSites.Count) site(s) have 'Everyone' access - Copilot will expose this content to ALL users"
        }
        if ($results.OversharedSites.Count -gt 0) {
            $results.Recommendations += "Review $($results.OversharedSites.Count) site(s) with broad permission grants before Copilot deployment"
        }
        if ($results.SensitiveContentRisks.Count -gt 0) {
            $results.Recommendations += "IMPORTANT: $($results.SensitiveContentRisks.Count) location(s) contain files with potentially sensitive keywords - review before Copilot deployment"
        }
        $results.Recommendations += "Use SharePoint Admin Center > Active Sites to review sharing settings"
        $results.Recommendations += "Consider enabling sensitivity labels to restrict Copilot access to classified content"
    }
    catch {
        Write-Log "Error analyzing SharePoint: $($_.Exception.Message)" -Level Warning
    }
    
    return $results
}

function Get-TeamsAnalysis {
    <#
    .SYNOPSIS
        Analyzes Teams configuration relevant to Copilot.
    #>
    Write-Log "Analyzing Teams configuration..." -Level Info
    
    $results = @{
        TotalTeams = 0
        TeamsWithGuests = 0
        TranscriptionEnabled = "Unknown"
        RecordingEnabled = "Unknown"
        Recommendations = @()
    }
    
    try {
        $teams = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$select=id,displayName,resourceProvisioningOptions&`$top=999"
        
        try {
            do {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                $teams += $response.value
                $uri = $response.'@odata.nextLink'
            } while ($uri)
            
            $results.TotalTeams = $teams.Count
            Write-Log "Found $($results.TotalTeams) Teams" -Level Info
        }
        catch {
            Write-Log "Teams filter failed, trying alternate method..." -Level Warning
            try {
                $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName,resourceProvisioningOptions&`$top=999"
                do {
                    $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                    $allGroups = $response.value
                    foreach ($group in $allGroups) {
                        if ($group.resourceProvisioningOptions -contains "Team") {
                            $teams += $group
                        }
                    }
                    $uri = $response.'@odata.nextLink'
                } while ($uri -and $teams.Count -lt 500)
                
                $results.TotalTeams = $teams.Count
                Write-Log "Found $($results.TotalTeams) Teams (alternate method)" -Level Info
            }
            catch {
                Write-Log "Counting M365 Groups as Teams estimate..." -Level Warning
                $countUri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$count=true&`$top=1"
                try {
                    $countResponse = Invoke-MgGraphRequest -Uri $countUri -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' }
                    $results.TotalTeams = $countResponse.'@odata.count'
                    Write-Log "Found approximately $($results.TotalTeams) M365 Groups (potential Teams)" -Level Info
                    $results.Recommendations += "M365 Group count shown - verify actual Teams count in Teams Admin Center"
                }
                catch {
                    Write-Log "Unable to count groups: $($_.Exception.Message)" -Level Warning
                }
            }
        }
        
        # Sample check for guests
        $teamsWithGuests = 0
        foreach ($team in $teams | Select-Object -First 5) {
            try {
                $members = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($team.id)/members?`$select=id,userType" -Method GET -ErrorAction SilentlyContinue
                foreach ($member in $members.value) {
                    if ($member.userType -eq 'Guest') {
                        $teamsWithGuests++
                        break
                    }
                }
            }
            catch { }
        }
        $results.TeamsWithGuests = $teamsWithGuests
        
        # Add recommendations
        $results.Recommendations += "Enable meeting transcription for Copilot to reference meeting content after meetings end"
        $results.Recommendations += "Enable meeting recording to allow Copilot to summarize recorded meetings"
        
        if ($results.TeamsWithGuests -gt 0) {
            $results.Recommendations += "Found Teams with guest members - review guest permissions as Copilot respects user access"
        }
    }
    catch {
        Write-Log "Error analyzing Teams: $($_.Exception.Message)" -Level Warning
        $results.Recommendations += "Unable to enumerate Teams - verify Group.Read.All permission"
    }
    
    return $results
}
#endregion

#region Report Generation
function New-HTMLReport {
    <#
    .SYNOPSIS
        Generates the HTML assessment report with sharing links analysis.
    #>
    param(
        [hashtable]$Findings,
        [int]$ReadinessScore,
        [hashtable]$ReadinessLevel,
        [string]$ClientName,
        [hashtable]$TenantInfo
    )
    
    $brand = $Script:Config.Brand
    $reportDate = $Script:Config.ReportDate.ToString("MMMM dd, yyyy HH:mm")
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft 365 Copilot Readiness Report - $ClientName</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: $($brand.LightGrey); 
            color: $($brand.DarkGrey);
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, $($brand.Orange), $($brand.Grey));
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .tagline { font-size: 1.2em; opacity: 0.9; }
        .header .date { margin-top: 15px; font-size: 0.9em; opacity: 0.8; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        .score-card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
        }
        .score-circle {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            border: 12px solid $($ReadinessLevel.Color);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            color: $($ReadinessLevel.Color);
            margin: 20px;
        }
        .score-label {
            font-size: 1.5em;
            font-weight: 600;
            color: $($ReadinessLevel.Color);
            margin: 10px 0;
        }
        .score-description { color: $($brand.Grey); font-size: 1.1em; }
        
        .section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: $($brand.Orange);
            border-bottom: 3px solid $($brand.Orange);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .section h3 { color: $($brand.Grey); margin: 15px 0 10px 0; }
        
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric-card {
            background: $($brand.LightGrey);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid $($brand.Orange);
        }
        .metric-value { font-size: 2.5em; font-weight: bold; color: $($brand.Orange); }
        .metric-label { color: $($brand.Grey); font-size: 0.9em; margin-top: 5px; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: $($brand.Orange);
            color: white;
            font-weight: 600;
        }
        tr:hover { background: $($brand.LightGrey); }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .status-success { background: #D1FAE5; color: #065F46; }
        .status-warning { background: #FEF3C7; color: #92400E; }
        .status-danger { background: #FEE2E2; color: #991B1B; }
        
        .recommendations {
            background: #FFF7ED;
            border-left: 4px solid $($brand.Orange);
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }
        .recommendations h4 { color: $($brand.Orange); margin-bottom: 10px; }
        .recommendations ul { margin-left: 20px; }
        .recommendations li { margin: 8px 0; color: $($brand.DarkGrey); }
        
        .alert-box {
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }
        .alert-critical {
            background: #FEE2E2;
            border-left: 4px solid #EF4444;
        }
        .alert-warning {
            background: #FEF3C7;
            border-left: 4px solid #F59E0B;
        }
        .alert-info {
            background: #EFF6FF;
            border-left: 4px solid #3B82F6;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: $($brand.Grey);
            font-size: 0.9em;
        }
        .footer .company { font-weight: 600; color: $($brand.Orange); }
        
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8em; }
            .metric-grid { grid-template-columns: 1fr 1fr; }
            .score-circle { width: 140px; height: 140px; font-size: 2.5em; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft 365 Copilot Readiness Report</h1>
        <div class="client-name" style="font-size: 1.8em; font-weight: 600; margin: 15px 0;">$([System.Web.HttpUtility]::HtmlEncode($ClientName))</div>
        <div class="tenant-info" style="font-size: 0.95em; opacity: 0.9;">Tenant: $($TenantInfo.Domain) | ID: $(if($TenantInfo.TenantId.Length -gt 8){$TenantInfo.TenantId.Substring(0,8)}else{$TenantInfo.TenantId})...</div>
        <div class="tagline" style="margin-top: 15px;">$($brand.Tagline)</div>
        <div class="date">Generated: $reportDate</div>
    </div>
    
    <div class="container">
        <!-- Readiness Score -->
        <div class="score-card">
            <h2 style="border: none; color: $($brand.DarkGrey);">Overall Readiness Score</h2>
            <div class="score-circle">$ReadinessScore%</div>
            <div class="score-label">$($ReadinessLevel.Level)</div>
            <div class="score-description">$($ReadinessLevel.Description)</div>
        </div>
        
        <!-- Tenant Information -->
        <div class="section">
            <h2>Tenant Information</h2>
            <table>
                <tr>
                    <td style="width: 200px; font-weight: 600;">Organization Name</td>
                    <td>$([System.Web.HttpUtility]::HtmlEncode($ClientName))</td>
                </tr>
                <tr>
                    <td style="font-weight: 600;">Primary Domain</td>
                    <td>$($TenantInfo.Domain)</td>
                </tr>
                <tr>
                    <td style="font-weight: 600;">Tenant ID</td>
                    <td><code>$($TenantInfo.TenantId)</code></td>
                </tr>
                <tr>
                    <td style="font-weight: 600;">Country</td>
                    <td>$($TenantInfo.Country)</td>
                </tr>
                <tr>
                    <td style="font-weight: 600;">Assessment Date</td>
                    <td>$reportDate</td>
                </tr>
            </table>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($Findings.Licensing.EligibleUserCount)</div>
                    <div class="metric-label">Eligible for Copilot</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.Licensing.CopilotAssignedCount)</div>
                    <div class="metric-label">Copilot Assigned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.Licensing.AvailableCopilotLicenses)</div>
                    <div class="metric-label">Available Licenses</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.UserReadiness.ActiveUsersPercent)%</div>
                    <div class="metric-label">Active Users (30d)</div>
                </div>
            </div>
"@

    # Add Sharing Links summary to executive summary if available
    if ($Findings.SharingLinks) {
        $html += @"
            
            <h3>Sharing Links Exposure Summary</h3>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharingLinks.AnonymousLinkCount -gt 0){'#EF4444'}else{'#10B981'});">$($Findings.SharingLinks.AnonymousLinkCount)</div>
                    <div class="metric-label">Anonymous Links (Anyone)</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharingLinks.OrgWideLinkCount -gt 0){'#F59E0B'}else{'#10B981'});">$($Findings.SharingLinks.OrgWideLinkCount)</div>
                    <div class="metric-label">Organization-Wide Links</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.SharingLinks.TotalSitesScanned)</div>
                    <div class="metric-label">Sites Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.SharingLinks.TotalItemsScanned)</div>
                    <div class="metric-label">Items Analyzed</div>
                </div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <!-- Licensing Analysis -->
        <div class="section">
            <h2>Licensing Analysis</h2>
            <p>Analysis of Microsoft 365 licenses that qualify as prerequisites for Copilot deployment.</p>
            
            <h3>License Summary</h3>
            <table>
                <thead>
                    <tr>
                        <th>License</th>
                        <th>Total</th>
                        <th>Assigned</th>
                        <th>Available</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($license in $Findings.Licensing.LicenseSummary) {
        $typeClass = if ($license.Type -eq 'Copilot') { 'status-success' } else { 'status-warning' }
        $html += @"
                    <tr>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($license.FriendlyName))</td>
                        <td>$($license.Total)</td>
                        <td>$($license.Consumed)</td>
                        <td>$($license.Available)</td>
                        <td><span class="status-badge $typeClass">$($license.Type)</span></td>
                    </tr>
"@
    }

    $html += @"
                </tbody>
            </table>
        </div>
        
        <!-- Data Governance -->
        <div class="section">
            <h2>Data Governance</h2>
            <p>Copilot surfaces content based on user permissions. Proper data classification is critical.</p>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$(if($Findings.DataGovernance.SensitivityLabelsConfigured){'Yes'}else{'No'})</div>
                    <div class="metric-label">Sensitivity Labels Configured</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.DataGovernance.SensitivityLabels.Count)</div>
                    <div class="metric-label">Labels Defined</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.DataGovernance.LabeledSitesPercent)%</div>
                    <div class="metric-label">M365 Groups Labeled</div>
                </div>
            </div>
"@

    if ($Findings.DataGovernance.SensitivityLabels.Count -gt 0) {
        $html += @"
            <h3>Configured Sensitivity Labels</h3>
            <table>
                <thead>
                    <tr>
                        <th>Label Name</th>
                        <th>Description</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"@
        foreach ($label in $Findings.DataGovernance.SensitivityLabels) {
            $statusClass = if ($label.IsActive) { 'status-success' } else { 'status-warning' }
            $statusText = if ($label.IsActive) { 'Active' } else { 'Inactive' }
            $html += @"
                    <tr>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($label.Name))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($label.Description))</td>
                        <td><span class="status-badge $statusClass">$statusText</span></td>
                    </tr>
"@
        }
        $html += @"
                </tbody>
            </table>
"@
    }

    if ($Findings.DataGovernance.Recommendations.Count -gt 0) {
        $html += @"
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
"@
        foreach ($rec in $Findings.DataGovernance.Recommendations) {
            $html += "                    <li>$([System.Web.HttpUtility]::HtmlEncode($rec))</li>`n"
        }
        $html += @"
                </ul>
            </div>
"@
    }

    $html += @"
        </div>
        
        <!-- Security Posture -->
        <div class="section">
            <h2>Security Posture</h2>
            <p>Security configurations that affect Copilot data access and protection.</p>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$(if($Findings.Security.ConditionalAccessEnabled){'Yes'}else{'No'})</div>
                    <div class="metric-label">Conditional Access Enabled</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.Security.ConditionalAccessPolicies.Count)</div>
                    <div class="metric-label">CA Policies</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.Security.GuestUserCount)</div>
                    <div class="metric-label">Guest Users</div>
                </div>
            </div>
"@

    if ($Findings.Security.Recommendations.Count -gt 0) {
        $html += @"
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
"@
        foreach ($rec in $Findings.Security.Recommendations) {
            $html += "                    <li>$([System.Web.HttpUtility]::HtmlEncode($rec))</li>`n"
        }
        $html += @"
                </ul>
            </div>
"@
    }

    $html += @"
        </div>
        
        <!-- User Readiness -->
        <div class="section">
            <h2>User Readiness</h2>
            <p>User activity and service provisioning status for optimal Copilot experience.</p>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($Findings.UserReadiness.TotalAnalyzed)</div>
                    <div class="metric-label">Total Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.UserReadiness.ActiveUsersPercent)%</div>
                    <div class="metric-label">Active (30 days)</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.UserReadiness.OneDriveProvisionedPercent -lt 80){'#F59E0B'}else{'#10B981'});">$($Findings.UserReadiness.OneDriveProvisionedPercent)%</div>
                    <div class="metric-label">OneDrive Provisioned</div>
                </div>
            </div>
            
            <div class="alert-box alert-info">
                <h4 style="color: #1E40AF; margin-bottom: 8px;">ℹ️ Understanding OneDrive Provisioning</h4>
                <p style="margin: 0; color: #374151; font-size: 0.95em;">
                    <strong>What it means:</strong> OneDrive must be provisioned for each user before Copilot can access their personal files.<br><br>
                    <strong>Current status:</strong> <span style="color: #10B981; font-weight: 600;">$($Findings.UserReadiness.OneDriveProvisionedCount) users</span> have OneDrive provisioned. 
                    $(if($Findings.UserReadiness.OneDriveNotProvisionedCount -gt 0){"Approximately <span style='color: #F59E0B; font-weight: 600;'>$($Findings.UserReadiness.OneDriveNotProvisionedCount) licensed users</span> may not have accessed OneDrive yet."}else{"All licensed users appear to have OneDrive provisioned."})
                </p>
            </div>
            
            <h3>Application Usage (Last 30 Days)</h3>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($Findings.UserReadiness.UsageMetrics.TeamsActive)</div>
                    <div class="metric-label">Teams Active Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.UserReadiness.UsageMetrics.OutlookActive)</div>
                    <div class="metric-label">Outlook Active Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.UserReadiness.UsageMetrics.OneDriveActive)</div>
                    <div class="metric-label">OneDrive Active Users</div>
                </div>
            </div>
"@

    if ($Findings.UserReadiness.Recommendations.Count -gt 0) {
        $html += @"
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
"@
        foreach ($rec in $Findings.UserReadiness.Recommendations) {
            $html += "                    <li>$([System.Web.HttpUtility]::HtmlEncode($rec))</li>`n"
        }
        $html += @"
                </ul>
            </div>
"@
    }

    $html += @"
        </div>
"@

    # ========================================
    # NEW: Sharing Links Analysis Section
    # ========================================
    if ($Findings.SharingLinks) {
        $html += @"
        
        <!-- Sharing Links Analysis - NEW -->
        <div class="section">
            <h2>Sharing Links Analysis - Copilot Exposure Risk</h2>
            <p><strong>CRITICAL FOR COPILOT:</strong> When users create sharing links with "Anyone" or "People in your organization" scope, that content becomes accessible to Copilot for all applicable users - even if they weren't explicitly shared on the file.</p>
            
            <div class="alert-box alert-info">
                <h4 style="color: #1E40AF; margin-bottom: 8px;">ℹ️ Why Sharing Links Matter for Copilot</h4>
                <p style="margin: 0; color: #374151; font-size: 0.95em;">
                    <strong>Organization-wide links ("People in your organization"):</strong> ANY user in your tenant can access this content, and Copilot will surface it in their responses.<br><br>
                    <strong>Anonymous links ("Anyone with the link"):</strong> While external users can't use your Copilot, the content is broadly accessible and may contain sensitive information.<br><br>
                    <strong>Impact:</strong> A user who creates an org-wide link to a confidential HR document makes that document available to every Copilot user in the organization.
                </p>
            </div>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharingLinks.AnonymousLinkCount -gt 0){'#EF4444'}else{'#10B981'});">$($Findings.SharingLinks.AnonymousLinkCount)</div>
                    <div class="metric-label">Anonymous Links Found</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharingLinks.OrgWideLinkCount -gt 0){'#F59E0B'}else{'#10B981'});">$($Findings.SharingLinks.OrgWideLinkCount)</div>
                    <div class="metric-label">Org-Wide Links Found</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.SharingLinks.TotalSitesScanned)</div>
                    <div class="metric-label">Sites Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($Findings.SharingLinks.TotalItemsScanned)</div>
                    <div class="metric-label">Items Analyzed</div>
                </div>
            </div>
"@

        # Anonymous Links - CRITICAL
        if ($Findings.SharingLinks.AnonymousLinks.Count -gt 0) {
            $html += @"
            
            <div class="alert-box alert-critical">
                <h4 style="color: #991B1B; margin-bottom: 10px;">⚠ CRITICAL: Anonymous Sharing Links Detected</h4>
                <p style="color: #7F1D1D; margin-bottom: 10px;">These items have "Anyone with the link" sharing enabled. The content is accessible to anyone who obtains the link.</p>
                <table style="background: white; border-radius: 8px;">
                    <thead>
                        <tr style="background: #EF4444;">
                            <th>Site</th>
                            <th>Item</th>
                            <th>Type</th>
                            <th>Link Type</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            foreach ($link in ($Findings.SharingLinks.AnonymousLinks | Select-Object -First 20)) {
                $html += @"
                        <tr>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($link.SiteName))</td>
                            <td><a href="$($link.ItemUrl)" target="_blank" style="color: #2563EB;">$([System.Web.HttpUtility]::HtmlEncode($link.ItemName))</a></td>
                            <td>$($link.ItemType)</td>
                            <td>$($link.LinkType)</td>
                        </tr>
"@
            }
            if ($Findings.SharingLinks.AnonymousLinks.Count -gt 20) {
                $html += @"
                        <tr>
                            <td colspan="4" style="text-align: center; font-style: italic; color: #6B7280;">
                                ... and $($Findings.SharingLinks.AnonymousLinks.Count - 20) more anonymous links
                            </td>
                        </tr>
"@
            }
            $html += @"
                    </tbody>
                </table>
            </div>
"@
        }

        # Organization-Wide Links - HIGH RISK
        if ($Findings.SharingLinks.OrgWideLinks.Count -gt 0) {
            $html += @"
            
            <div class="alert-box alert-warning">
                <h4 style="color: #92400E; margin-bottom: 10px;">⚠ HIGH RISK: Organization-Wide Sharing Links</h4>
                <p style="color: #78350F; margin-bottom: 10px;">These items have "People in your organization" sharing links. <strong>Copilot will surface this content to ANY user</strong> in your organization, regardless of whether they were explicitly shared on the item.</p>
                <table style="background: white; border-radius: 8px;">
                    <thead>
                        <tr style="background: #F59E0B;">
                            <th>Site</th>
                            <th>Item</th>
                            <th>Type</th>
                            <th>Link Type</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            foreach ($link in ($Findings.SharingLinks.OrgWideLinks | Select-Object -First 30)) {
                $html += @"
                        <tr>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($link.SiteName))</td>
                            <td><a href="$($link.ItemUrl)" target="_blank" style="color: #2563EB;">$([System.Web.HttpUtility]::HtmlEncode($link.ItemName))</a></td>
                            <td>$($link.ItemType)</td>
                            <td>$($link.LinkType)</td>
                        </tr>
"@
            }
            if ($Findings.SharingLinks.OrgWideLinks.Count -gt 30) {
                $html += @"
                        <tr>
                            <td colspan="4" style="text-align: center; font-style: italic; color: #6B7280;">
                                ... and $($Findings.SharingLinks.OrgWideLinks.Count - 30) more organization-wide links
                            </td>
                        </tr>
"@
            }
            $html += @"
                    </tbody>
                </table>
            </div>
"@
        }

        # Sites Summary
        if ($Findings.SharingLinks.SitesSummary.Count -gt 0) {
            $html += @"
            
            <h3>Sites with Broad Sharing Links</h3>
            <p style="font-size: 0.9em; color: #6B7280;">Sites where broad sharing links were detected, sorted by risk level.</p>
            <table>
                <thead>
                    <tr>
                        <th>Site Name</th>
                        <th>Anonymous Links</th>
                        <th>Org-Wide Links</th>
                        <th>Total</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
"@
            foreach ($siteSummary in ($Findings.SharingLinks.SitesSummary | Sort-Object { if($_.Risk -eq 'CRITICAL'){0}elseif($_.Risk -eq 'HIGH'){1}else{2} }, TotalBroadLinks -Descending | Select-Object -First 20)) {
                $riskColor = switch ($siteSummary.Risk) { 'CRITICAL' { '#EF4444' } 'HIGH' { '#F59E0B' } default { '#10B981' } }
                $riskBg = switch ($siteSummary.Risk) { 'CRITICAL' { '#FEE2E2' } 'HIGH' { '#FEF3C7' } default { '#D1FAE5' } }
                $html += @"
                    <tr>
                        <td><a href="$($siteSummary.SiteUrl)" target="_blank" style="color: #2563EB;">$([System.Web.HttpUtility]::HtmlEncode($siteSummary.SiteName))</a></td>
                        <td style="color: $(if($siteSummary.AnonymousLinks -gt 0){'#EF4444'}else{'inherit'});">$($siteSummary.AnonymousLinks)</td>
                        <td style="color: $(if($siteSummary.OrgWideLinks -gt 0){'#F59E0B'}else{'inherit'});">$($siteSummary.OrgWideLinks)</td>
                        <td><strong>$($siteSummary.TotalBroadLinks)</strong></td>
                        <td><span style="background: $riskBg; color: $riskColor; padding: 2px 8px; border-radius: 4px; font-weight: 600;">$($siteSummary.Risk)</span></td>
                    </tr>
"@
            }
            $html += @"
                </tbody>
            </table>
"@
        }

        # Scan note if limit reached
        if ($Findings.SharingLinks.ScanLimitReached) {
            $html += @"
            
            <div class="alert-box alert-info">
                <p style="margin: 0; color: #374151;">
                    <strong>Note:</strong> This scan was limited to $($Findings.SharingLinks.TotalSitesScanned) sites and $($Findings.SharingLinks.TotalItemsScanned) items. 
                    For a complete audit, use SharePoint Admin Center reports or run a full tenant scan with PnP PowerShell.
                </p>
            </div>
"@
        }

        if ($Findings.SharingLinks.Recommendations.Count -gt 0) {
            $html += @"
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
"@
            foreach ($rec in $Findings.SharingLinks.Recommendations) {
                $html += "                    <li>$([System.Web.HttpUtility]::HtmlEncode($rec))</li>`n"
            }
            $html += @"
                </ul>
            </div>
"@
        }

        $html += @"
        </div>
"@
    }
    # End Sharing Links Section

    # SharePoint/OneDrive Section
    $html += @"
        
        <!-- SharePoint/OneDrive -->
        <div class="section">
            <h2>SharePoint & OneDrive - Site Permissions</h2>
            <p><strong>CRITICAL:</strong> Copilot can access ANY content the user has permission to see. Sites with broad sharing settings expose that content to all Copilot users.</p>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($Findings.SharePoint.TotalSites)</div>
                    <div class="metric-label">SharePoint Sites Analyzed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharePoint.EveryoneSites.Count -gt 0){'#EF4444'}else{'#10B981'});">$($Findings.SharePoint.EveryoneSites.Count)</div>
                    <div class="metric-label">Sites with "Everyone" Access</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharePoint.OversharedSites.Count -gt 0){'#F59E0B'}else{'#10B981'});">$($Findings.SharePoint.OversharedSites.Count)</div>
                    <div class="metric-label">Oversharing Risk Sites</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: $(if($Findings.SharePoint.SensitiveContentRisks.Count -gt 0){'#EF4444'}else{'#10B981'});">$($Findings.SharePoint.SensitiveContentRisks.Count)</div>
                    <div class="metric-label">Sensitive Content Locations</div>
                </div>
            </div>
"@

    if ($Findings.SharePoint.EveryoneSites.Count -gt 0) {
        $html += @"
            
            <div class="alert-box alert-critical">
                <h4 style="color: #991B1B; margin-bottom: 10px;">⚠ CRITICAL: Sites Accessible to Everyone</h4>
                <p style="color: #7F1D1D; margin-bottom: 10px;">These sites have permissions that allow ALL users in your organization to access content.</p>
                <table style="background: white; border-radius: 8px;">
                    <thead>
                        <tr style="background: #EF4444;">
                            <th>Site Name</th>
                            <th>URL</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($site in $Findings.SharePoint.EveryoneSites) {
            $html += @"
                        <tr>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($site.SiteName))</td>
                            <td><a href="$($site.SiteUrl)" target="_blank" style="color: #2563EB;">$([System.Web.HttpUtility]::HtmlEncode($site.SiteUrl))</a></td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
"@
    }

    if ($Findings.SharePoint.SensitiveContentRisks.Count -gt 0) {
        $html += @"
            
            <div class="alert-box alert-warning">
                <h4 style="color: #92400E; margin-bottom: 10px;">⚠ Potentially Sensitive Content Detected</h4>
                <p style="color: #78350F; margin-bottom: 10px;">Files containing keywords like "SSN", "Social Security", "Credit Card", "Password", or "Confidential" were found.</p>
                <table style="background: white; border-radius: 8px;">
                    <thead>
                        <tr style="background: #F59E0B;">
                            <th>Location</th>
                            <th>Library</th>
                            <th>Matches</th>
                            <th>Sample Files</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($risk in $Findings.SharePoint.SensitiveContentRisks) {
            $html += @"
                        <tr>
                            <td><a href="$($risk.SiteUrl)" target="_blank" style="color: #2563EB;">$([System.Web.HttpUtility]::HtmlEncode($risk.SiteName))</a></td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($risk.Library))</td>
                            <td>$($risk.MatchCount)</td>
                            <td style="font-size: 0.85em;">$([System.Web.HttpUtility]::HtmlEncode($risk.SampleFiles))</td>
                        </tr>
"@
        }
        $html += @"
                    </tbody>
                </table>
            </div>
"@
    }

    if ($Findings.SharePoint.OversharedSites.Count -gt 0) {
        $html += @"
            
            <h3>Sites Requiring Permission Review</h3>
            <table>
                <thead>
                    <tr>
                        <th>Site Name</th>
                        <th>Permissions</th>
                        <th>Risk Level</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
"@
        foreach ($site in $Findings.SharePoint.OversharedSites | Sort-Object { if($_.Risk -eq 'HIGH'){0}elseif($_.Risk -eq 'MEDIUM'){1}else{2} }) {
            $riskColor = switch ($site.Risk) { 'HIGH' { '#EF4444' } 'MEDIUM' { '#F59E0B' } default { '#10B981' } }
            $riskBg = switch ($site.Risk) { 'HIGH' { '#FEE2E2' } 'MEDIUM' { '#FEF3C7' } default { '#D1FAE5' } }
            $html += @"
                    <tr>
                        <td><a href="$($site.SiteUrl)" target="_blank" style="color: #2563EB;">$([System.Web.HttpUtility]::HtmlEncode($site.SiteName))</a></td>
                        <td>$($site.PermissionCount)</td>
                        <td><span style="background: $riskBg; color: $riskColor; padding: 2px 8px; border-radius: 4px; font-weight: 600;">$($site.Risk)</span></td>
                        <td><a href="$($site.SiteUrl)/_layouts/15/siteanalytics.aspx" target="_blank" style="color: #2563EB; font-size: 0.85em;">Review</a></td>
                    </tr>
"@
        }
        $html += @"
                </tbody>
            </table>
"@
    }

    if ($Findings.SharePoint.Recommendations.Count -gt 0) {
        $html += @"
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
"@
        foreach ($rec in $Findings.SharePoint.Recommendations) {
            $html += "                    <li>$([System.Web.HttpUtility]::HtmlEncode($rec))</li>`n"
        }
        $html += @"
                </ul>
            </div>
"@
    }

    $html += @"
        </div>
        
        <!-- Teams -->
        <div class="section">
            <h2>Microsoft Teams Configuration</h2>
            <p>Teams settings affecting Copilot meeting and channel features.</p>
            
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">$($Findings.Teams.TotalTeams)</div>
                    <div class="metric-label">Total Teams</div>
                </div>
            </div>
"@

    if ($Findings.Teams.Recommendations.Count -gt 0) {
        $html += @"
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
"@
        foreach ($rec in $Findings.Teams.Recommendations) {
            $html += "                    <li>$([System.Web.HttpUtility]::HtmlEncode($rec))</li>`n"
        }
        $html += @"
                </ul>
            </div>
"@
    }

    $html += @"
        </div>
        
        <!-- Next Steps -->
        <div class="section">
            <h2>Recommended Next Steps</h2>
            <ol style="margin-left: 20px;">
                <li style="margin: 15px 0;"><strong>Review Sharing Links:</strong> Audit and remove unnecessary "Anyone" and "People in your organization" sharing links, especially on sensitive content.</li>
                <li style="margin: 15px 0;"><strong>Review Data Governance:</strong> Ensure sensitivity labels are configured and applied to protect sensitive content from unintended Copilot exposure.</li>
                <li style="margin: 15px 0;"><strong>Audit Site Permissions:</strong> Review SharePoint site and OneDrive sharing settings. Copilot accesses content based on user permissions.</li>
                <li style="margin: 15px 0;"><strong>Configure Sharing Policies:</strong> In SharePoint Admin Center, consider restricting default link types to "Specific people" to prevent accidental oversharing.</li>
                <li style="margin: 15px 0;"><strong>Enable Required Features:</strong> Turn on meeting transcription in Teams for Copilot meeting features.</li>
                <li style="margin: 15px 0;"><strong>Pilot Program:</strong> Start with a small group of power users who actively use Teams, Outlook, and Office apps.</li>
                <li style="margin: 15px 0;"><strong>User Training:</strong> Train users on responsible sharing practices - every org-wide link creates Copilot exposure.</li>
                <li style="margin: 15px 0;"><strong>Monitor Usage:</strong> After deployment, use the Copilot Dashboard in Viva Insights to track adoption and value.</li>
            </ol>
        </div>
    </div>
    
    <div class="footer">
        <p>Prepared for <strong>$([System.Web.HttpUtility]::HtmlEncode($ClientName))</strong></p>
        <p><span class="company">$($brand.Name)</span> | $($brand.Tagline)</p>
        <p>Report Version: $($Script:Config.Version)</p>
    </div>
</body>
</html>
"@

    return $html
}
#endregion

#region Main Execution
function Invoke-CopilotReadinessAssessment {
    <#
    .SYNOPSIS
        Main orchestration function for the assessment.
    #>
    
    Show-YWBanner
    Write-Host "Microsoft 365 Copilot Readiness Assessment" -ForegroundColor DarkYellow
    Write-Host ("=" * 50) -ForegroundColor Gray
    Write-Host ""
    
    # Verify output path
    if (-not (Test-Path $OutputPath)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Log "Created output directory: $OutputPath" -Level Info
        }
        catch {
            Write-Log "Failed to create output directory: $($_.Exception.Message)" -Level Error
            return
        }
    }
    
    # Check for required modules
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Reports',
        'Microsoft.Graph.Groups'
    )
    
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing required modules: $($missingModules -join ', ')" -Level Warning
        Write-Log "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -Level Info
        
        $install = Read-Host "Would you like to install missing modules now? (Y/N)"
        if ($install -eq 'Y') {
            foreach ($module in $missingModules) {
                Write-Log "Installing $module..." -Level Info
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
            }
        }
        else {
            return
        }
    }
    
    # Check module versions
    Write-Log "Checking Microsoft Graph module versions..." -Level Info
    $graphModules = Get-Module -ListAvailable -Name "Microsoft.Graph.*" | 
        Group-Object Name | 
        ForEach-Object { $_.Group | Sort-Object Version -Descending | Select-Object -First 1 }
    
    $versions = $graphModules | Select-Object -ExpandProperty Version -Unique
    if ($versions.Count -gt 1) {
        Write-Log "WARNING: Multiple Microsoft Graph module versions detected!" -Level Warning
        Write-Log "Versions found: $($versions -join ', ')" -Level Warning
        Write-Host ""
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -ne 'Y') {
            return
        }
    }
    
    # Import modules
    Write-Log "Loading Microsoft Graph modules..." -Level Info
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Write-Log "Authentication module loaded" -Level Success
    }
    catch {
        Write-Log "Failed to import Microsoft.Graph.Authentication: $($_.Exception.Message)" -Level Error
        return
    }
    
    Add-Type -AssemblyName System.Web
    
    # Connect to services
    try {
        Connect-RequiredServices -ForceNew:(-not $SkipNewConnection)
    }
    catch {
        Write-Log "Failed to connect to required services. Exiting." -Level Error
        return
    }
    
    # Determine client name
    $Script:ClientDisplayName = if ($ClientName) { 
        $ClientName 
    } else { 
        $Script:TenantInfo.DisplayName 
    }
    
    Write-Host ""
    Write-Log "Starting Copilot Readiness Assessment for: $($Script:ClientDisplayName)" -Level Info
    Write-Host ""
    
    # Run assessments
    $findings = @{}
    
    $findings.Licensing = Get-LicensingAnalysis
    $findings.DataGovernance = Get-DataGovernanceAnalysis
    $findings.Security = Get-SecurityPostureAnalysis
    $findings.UserReadiness = Get-UserReadinessAnalysis -DaysInactive $DaysInactive -TopCandidates $TopCandidates
    $findings.SharePoint = Get-SharePointAnalysis
    
    # NEW: Sharing Links Analysis
    $findings.SharingLinks = Get-SharingLinksAnalysis -MaxSitesToScan $MaxSitesToScan -MaxItemsPerSite $MaxItemsPerSite
    
    $findings.Teams = Get-TeamsAnalysis
    
    # Calculate readiness score
    $readinessScore = Get-ReadinessScore -Findings $findings
    $readinessLevel = Get-ReadinessLevel -Score $readinessScore
    
    Write-Host ""
    Write-Log "Assessment complete. Readiness Score: $readinessScore% ($($readinessLevel.Level))" -Level Success
    
    # Generate HTML report
    Write-Log "Generating HTML report..." -Level Info
    $htmlContent = New-HTMLReport -Findings $findings -ReadinessScore $readinessScore -ReadinessLevel $readinessLevel -ClientName $Script:ClientDisplayName -TenantInfo $Script:TenantInfo
    
    # Generate filename
    $safeClientName = $Script:ClientDisplayName -replace '[\\/:*?"<>|]', '_' -replace '\s+', '_'
    $reportFileName = "CopilotReadiness_${safeClientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath = Join-Path $OutputPath $reportFileName
    
    # Write report
    $utf8WithBom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($reportPath, $htmlContent, $utf8WithBom)
    
    Write-Log "Report saved: $reportPath" -Level Success
    
    # Export CSVs if requested
    if ($ExportCSV) {
        Write-Log "Exporting CSV files..." -Level Info
        
        $findings.Licensing.LicenseSummary | Export-Csv -Path (Join-Path $OutputPath "CopilotReadiness_Licenses.csv") -NoTypeInformation -Encoding UTF8
        
        if ($findings.Licensing.EligibleUsers.Count -gt 0) {
            $findings.Licensing.EligibleUsers | Export-Csv -Path (Join-Path $OutputPath "CopilotReadiness_EligibleUsers.csv") -NoTypeInformation -Encoding UTF8
        }
        
        if ($findings.DataGovernance.SensitivityLabels.Count -gt 0) {
            $findings.DataGovernance.SensitivityLabels | Export-Csv -Path (Join-Path $OutputPath "CopilotReadiness_SensitivityLabels.csv") -NoTypeInformation -Encoding UTF8
        }
        
        # NEW: Export sharing links data
        if ($findings.SharingLinks.AnonymousLinks.Count -gt 0) {
            $findings.SharingLinks.AnonymousLinks | Export-Csv -Path (Join-Path $OutputPath "CopilotReadiness_AnonymousLinks.csv") -NoTypeInformation -Encoding UTF8
        }
        
        if ($findings.SharingLinks.OrgWideLinks.Count -gt 0) {
            $findings.SharingLinks.OrgWideLinks | Export-Csv -Path (Join-Path $OutputPath "CopilotReadiness_OrgWideLinks.csv") -NoTypeInformation -Encoding UTF8
        }
        
        Write-Log "CSV exports complete" -Level Success
    }
    
    # Open report
    Write-Host ""
    Write-Log "Opening report in default browser..." -Level Info
    Start-Process $reportPath
    
    Write-Host ""
    Write-Host ("=" * 50) -ForegroundColor Gray
    Write-Host "Assessment Complete" -ForegroundColor DarkYellow
    Write-Host "Report Location: $reportPath" -ForegroundColor Cyan
    Write-Host ""
    
    return @{
        Findings = $findings
        Score = $readinessScore
        Level = $readinessLevel
        ReportPath = $reportPath
    }
}

# Execute
Invoke-CopilotReadinessAssessment
#endregion
