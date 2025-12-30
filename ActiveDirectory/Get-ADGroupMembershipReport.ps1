<#
.SYNOPSIS
    Generates comprehensive Active Directory group membership reports.

.DESCRIPTION
    Creates detailed reports on AD group memberships including:
    - Direct and nested group members
    - User, computer, and group object types
    - Member details (last logon, status, department)
    - Empty groups identification
    - Large groups identification
    - Nested group depth analysis

.PARAMETER GroupName
    Specific group name to report on. Supports wildcards.

.PARAMETER IncludeNested
    Include all nested group members (recursive).

.PARAMETER ShowEmptyGroups
    Show groups with no members.

.PARAMETER MinimumMembers
    Only show groups with at least this many members.

.PARAMETER ExportPath
    Path to export results to CSV.

.EXAMPLE
    .\Get-ADGroupMembershipReport.ps1 -GroupName "Domain Admins" -IncludeNested
    Full report on Domain Admins including nested members.

.EXAMPLE
    .\Get-ADGroupMembershipReport.ps1 -ShowEmptyGroups -ExportPath "C:\Reports"
    Find all empty groups and export to CSV.

.EXAMPLE
    .\Get-ADGroupMembershipReport.ps1 -MinimumMembers 50
    Show all groups with 50+ members.

.NOTES
    Author: Yeyland Wutani - Building Better Systems
    Requires: ActiveDirectory module, appropriate AD permissions
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GroupName = "*",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNested,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowEmptyGroups,
    
    [Parameter(Mandatory=$false)]
    [int]$MinimumMembers = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Import required module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to import ActiveDirectory module. Ensure RSAT-AD-PowerShell is installed."
    exit 1
}

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
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Function to get nested group members recursively
function Get-NestedGroupMembers {
    param(
        [string]$GroupDN,
        [int]$Depth = 0,
        [hashtable]$ProcessedGroups = @{}
    )
    
    # Prevent infinite loops from circular references
    if ($ProcessedGroups.ContainsKey($GroupDN)) {
        return @()
    }
    
    $ProcessedGroups[$GroupDN] = $true
    $allMembers = @()
    
    try {
        $group = Get-ADGroup -Identity $GroupDN -Properties Members
        
        foreach ($memberDN in $group.Members) {
            try {
                $member = Get-ADObject -Identity $memberDN -Properties objectClass, Name, SamAccountName
                
                $memberInfo = [PSCustomObject]@{
                    DistinguishedName = $memberDN
                    Name = $member.Name
                    SamAccountName = $member.SamAccountName
                    ObjectClass = $member.objectClass
                    Depth = $Depth
                    ParentGroup = $group.Name
                }
                
                $allMembers += $memberInfo
                
                # If this member is a group, recurse into it
                if ($member.objectClass -eq 'group') {
                    $nestedMembers = Get-NestedGroupMembers -GroupDN $memberDN -Depth ($Depth + 1) -ProcessedGroups $ProcessedGroups
                    $allMembers += $nestedMembers
                }
            } catch {
                Write-Verbose "Could not process member: $memberDN"
            }
        }
    } catch {
        Write-Verbose "Could not process group: $GroupDN"
    }
    
    return $allMembers
}

# Get groups based on filter
Write-Host "Searching for groups matching: $GroupName" -ForegroundColor Gray

try {
    $groups = Get-ADGroup -Filter "Name -like '$GroupName'" -Properties Members, Description, 
        GroupCategory, GroupScope, whenCreated, ManagedBy | 
        Sort-Object Name
    
    Write-Host "Found $($groups.Count) group(s)`n" -ForegroundColor Gray
    
} catch {
    Write-Host "[FAIL] Error retrieving groups: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$allResults = @()
$emptyGroups = @()
$largeGroups = @()

foreach ($group in $groups) {
    $directMemberCount = $group.Members.Count
    
    # Skip based on member count filters
    if (-not $ShowEmptyGroups -and $directMemberCount -eq 0) {
        $emptyGroups += $group
        continue
    }
    
    if ($directMemberCount -lt $MinimumMembers) {
        continue
    }
    
    Write-Host "Processing: $($group.Name)" -ForegroundColor Gray
    Write-Host "  Category: $($group.GroupCategory)" -ForegroundColor Gray
    Write-Host "  Scope: $($group.GroupScope)" -ForegroundColor Gray
    Write-Host "  Direct Members: $directMemberCount" -ForegroundColor Gray
    
    if ($group.Description) {
        Write-Host "  Description: $($group.Description)" -ForegroundColor Gray
    }
    
    # Track member types
    $userCount = 0
    $computerCount = 0
    $groupCount = 0
    $nestedMemberCount = 0
    
    # Get member details
    $members = @()
    
    if ($IncludeNested -and $directMemberCount -gt 0) {
        Write-Host "  Retrieving nested members..." -ForegroundColor Gray
        $members = Get-NestedGroupMembers -GroupDN $group.DistinguishedName
        $nestedMemberCount = ($members | Select-Object -Unique DistinguishedName).Count
        Write-Host "  Total Nested Members: $nestedMemberCount" -ForegroundColor Gray
    } else {
        # Get direct members only
        foreach ($memberDN in $group.Members) {
            try {
                $member = Get-ADObject -Identity $memberDN -Properties objectClass, Name, SamAccountName
                $members += [PSCustomObject]@{
                    DistinguishedName = $memberDN
                    Name = $member.Name
                    SamAccountName = $member.SamAccountName
                    ObjectClass = $member.objectClass
                    Depth = 0
                    ParentGroup = $group.Name
                }
            } catch {
                Write-Verbose "Could not retrieve member: $memberDN"
            }
        }
    }
    
    # Count member types
    $userCount = ($members | Where-Object { $_.ObjectClass -eq 'user' }).Count
    $computerCount = ($members | Where-Object { $_.ObjectClass -eq 'computer' }).Count
    $groupCount = ($members | Where-Object { $_.ObjectClass -eq 'group' }).Count
    
    Write-Host "  Users: $userCount | Computers: $computerCount | Groups: $groupCount" -ForegroundColor Gray
    
    # Create detailed member records
    foreach ($member in $members) {
        $memberDetails = $null
        
        # Get additional details based on object type
        try {
            switch ($member.ObjectClass) {
                'user' {
                    $userObj = Get-ADUser -Identity $member.DistinguishedName -Properties Enabled, 
                        LastLogonDate, Department, Title -ErrorAction Stop
                    $memberDetails = [PSCustomObject]@{
                        GroupName = $group.Name
                        GroupDN = $group.DistinguishedName
                        GroupCategory = $group.GroupCategory
                        GroupScope = $group.GroupScope
                        MemberName = $member.Name
                        MemberSamAccountName = $member.SamAccountName
                        MemberType = 'User'
                        MemberDN = $member.DistinguishedName
                        Enabled = $userObj.Enabled
                        LastLogonDate = $userObj.LastLogonDate
                        Department = $userObj.Department
                        Title = $userObj.Title
                        NestingDepth = $member.Depth
                        DirectParentGroup = $member.ParentGroup
                    }
                }
                'computer' {
                    $compObj = Get-ADComputer -Identity $member.DistinguishedName -Properties Enabled, 
                        LastLogonDate, OperatingSystem -ErrorAction Stop
                    $memberDetails = [PSCustomObject]@{
                        GroupName = $group.Name
                        GroupDN = $group.DistinguishedName
                        GroupCategory = $group.GroupCategory
                        GroupScope = $group.GroupScope
                        MemberName = $member.Name
                        MemberSamAccountName = $member.SamAccountName
                        MemberType = 'Computer'
                        MemberDN = $member.DistinguishedName
                        Enabled = $compObj.Enabled
                        LastLogonDate = $compObj.LastLogonDate
                        OperatingSystem = $compObj.OperatingSystem
                        NestingDepth = $member.Depth
                        DirectParentGroup = $member.ParentGroup
                    }
                }
                'group' {
                    $grpObj = Get-ADGroup -Identity $member.DistinguishedName -ErrorAction Stop
                    $memberDetails = [PSCustomObject]@{
                        GroupName = $group.Name
                        GroupDN = $group.DistinguishedName
                        GroupCategory = $group.GroupCategory
                        GroupScope = $group.GroupScope
                        MemberName = $member.Name
                        MemberSamAccountName = $member.SamAccountName
                        MemberType = 'Group'
                        MemberDN = $member.DistinguishedName
                        NestingDepth = $member.Depth
                        DirectParentGroup = $member.ParentGroup
                    }
                }
            }
        } catch {
            Write-Verbose "Could not get details for member: $($member.Name)"
        }
        
        if ($memberDetails) {
            $allResults += $memberDetails
        }
    }
    
    # Track large groups
    if ($directMemberCount -gt 100) {
        $largeGroups += [PSCustomObject]@{
            GroupName = $group.Name
            DirectMembers = $directMemberCount
            TotalMembers = if ($IncludeNested) { $nestedMemberCount } else { $directMemberCount }
        }
    }
    
    Write-Host ""
}

# Report on empty groups if found
if ($emptyGroups.Count -gt 0) {
    Write-Host "=== Empty Groups ===" -ForegroundColor DarkYellow
    Write-Host "Found $($emptyGroups.Count) empty group(s):" -ForegroundColor Yellow
    
    foreach ($emptyGroup in $emptyGroups | Select-Object -First 20) {
        Write-Host "  - $($emptyGroup.Name)" -ForegroundColor Gray
        if ($emptyGroup.Description) {
            Write-Host "    Description: $($emptyGroup.Description)" -ForegroundColor Gray
        }
    }
    
    if ($emptyGroups.Count -gt 20) {
        Write-Host "  ... and $($emptyGroups.Count - 20) more empty groups" -ForegroundColor Gray
    }
    Write-Host ""
}

# Report on large groups
if ($largeGroups.Count -gt 0) {
    Write-Host "=== Large Groups (100+ members) ===" -ForegroundColor DarkYellow
    $largeGroups = $largeGroups | Sort-Object TotalMembers -Descending
    
    foreach ($largeGroup in $largeGroups | Select-Object -First 10) {
        Write-Host "  $($largeGroup.GroupName): $($largeGroup.TotalMembers) members" -ForegroundColor Yellow
    }
    
    if ($largeGroups.Count -gt 10) {
        Write-Host "  ... and $($largeGroups.Count - 10) more large groups" -ForegroundColor Gray
    }
    Write-Host ""
}

# Summary
Write-Host "=== SUMMARY ===" -ForegroundColor DarkYellow
Write-Host "Total Groups Processed: $($groups.Count)"
Write-Host "Total Members Found: $($allResults.Count)"
Write-Host "Empty Groups: $($emptyGroups.Count)"
Write-Host "Large Groups (100+ members): $($largeGroups.Count)"

# Break down by member type
$totalUsers = ($allResults | Where-Object { $_.MemberType -eq 'User' }).Count
$totalComputers = ($allResults | Where-Object { $_.MemberType -eq 'Computer' }).Count
$totalGroups = ($allResults | Where-Object { $_.MemberType -eq 'Group' }).Count

Write-Host "`nMember Types:"
Write-Host "  Users: $totalUsers"
Write-Host "  Computers: $totalComputers"
Write-Host "  Groups: $totalGroups"

# Export results if requested
if ($ExportPath) {
    try {
        # Ensure export path exists
        if (-not (Test-Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        if ($allResults.Count -gt 0) {
            $membersPath = Join-Path $ExportPath "GroupMembers_$timestamp.csv"
            $allResults | Export-Csv -Path $membersPath -NoTypeInformation -Force
            Write-Host "`nGroup members exported to: $membersPath" -ForegroundColor Green
        }
        
        if ($emptyGroups.Count -gt 0) {
            $emptyPath = Join-Path $ExportPath "EmptyGroups_$timestamp.csv"
            $emptyGroups | Select-Object Name, Description, GroupCategory, GroupScope, whenCreated, ManagedBy | 
                Export-Csv -Path $emptyPath -NoTypeInformation -Force
            Write-Host "Empty groups exported to: $emptyPath" -ForegroundColor Green
        }
        
        if ($largeGroups.Count -gt 0) {
            $largePath = Join-Path $ExportPath "LargeGroups_$timestamp.csv"
            $largeGroups | Export-Csv -Path $largePath -NoTypeInformation -Force
            Write-Host "Large groups exported to: $largePath" -ForegroundColor Green
        }
        
    } catch {
        Write-Warning "Failed to export results: $($_.Exception.Message)"
    }
}

Write-Host "`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Return results
return $allResults
