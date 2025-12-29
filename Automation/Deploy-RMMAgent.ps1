<#
.SYNOPSIS
    Deploys MSI packages to domain computers using PSEXEC.
    
.DESCRIPTION
    Yeyland Wutani - Building Better Systems
    
    Enterprise MSI deployment tool that queries Active Directory for target
    computers, validates connectivity and PSEXEC compatibility, then performs
    silent MSI installation across accessible systems.
    
    Auto-Detection:
    - If no MSI is specified, scans current directory and prompts for selection
    - Extracts MSI properties (ProductName, Version, ProductCode) for display
    - Searches for PSExec.exe in current directory and common locations
    - Prompts for paths if required files are not found
    
    Deployment Phases:
    1. MSI Analysis    - Extract product info and available properties
    2. AD Query        - Retrieve computer objects from specified OU or entire domain
    3. Reachability    - Filter to online/responding systems via ping
    4. Compatibility   - Validate PSEXEC prerequisites (ADMIN$, SMB, permissions)
    5. Deployment      - Copy MSI and execute silent install via PSEXEC (parallel)
    6. Validation      - Verify product installation on target systems
    7. Reporting       - Generate HTML report and CSV export
    
    Prerequisites on target systems:
    - TCP Port 445 open (File and Printer Sharing)
    - ADMIN$ administrative share accessible
    - Running account must have local admin rights
    - LanmanServer service running
    
.PARAMETER MSIPath
    Full path to the MSI installer file. If omitted, searches current directory
    for .msi files and prompts for selection. Required for deployment (not TestOnly).
    
.PARAMETER TransformPath
    Path to MST transform file(s) to apply during installation.
    
.PARAMETER MSIProperties
    Hashtable of MSI properties to pass to the installer.
    Example: @{ INSTALLDIR = "C:\CustomPath"; ALLUSERS = "1" }
    
.PARAMETER SearchBase
    Distinguished Name of OU to search. If omitted, searches entire domain.
    
.PARAMETER ComputerName
    Specific computer name(s) to target instead of AD query.
    
.PARAMETER Filter
    PowerShell filter for computer selection. Default: * (all computers)
    Examples: "Name -like 'WKS*'" or "OperatingSystem -like '*Windows 10*'"
    
.PARAMETER ExcludeServers
    Exclude server operating systems from deployment.
    
.PARAMETER ExcludePattern
    Regex pattern to exclude computers by name (e.g., "^SQL-|^DC-").
    
.PARAMETER MSIArguments
    Additional arguments to pass to msiexec. Default includes /qn /norestart.
    
.PARAMETER StagingPath
    Remote path to stage MSI before install. Default: C:\Windows\Temp
    
.PARAMETER PSExecPath
    Path to PSExec.exe. If omitted, searches current directory, script directory,
    common Sysinternals locations, and PATH. Prompts if not found.
    
.PARAMETER Credential
    PSCredential for remote operations. Uses current context if not specified.
    
.PARAMETER MaxConcurrent
    Maximum concurrent deployments using runspace pool. Default: 10
    
.PARAMETER TimeoutSeconds
    Timeout per installation in seconds. Default: 300 (5 minutes)
    
.PARAMETER OutputPath
    Directory for HTML report and CSV logs. Default: Current directory.
    
.PARAMETER CollectLogs
    Collect msiexec logs from remote systems after deployment.
    
.PARAMETER SkipReachabilityCheck
    Skip the ping/reachability validation phase.
    
.PARAMETER SkipCompatibilityCheck
    Skip PSEXEC compatibility validation (use with caution).
    
.PARAMETER SkipValidation
    Skip post-install product verification.
    
.PARAMETER RetryCount
    Number of retry attempts for failed deployments. Default: 0 (no retry)
    
.PARAMETER RetryDelaySeconds
    Delay between retry attempts. Default: 30
    
.PARAMETER Force
    Deploy without confirmation prompts.
    
.PARAMETER TestOnly
    Run readiness checks only without deploying. Generates a readiness report
    showing which systems are ready for deployment and which have issues.
    
.PARAMETER ShowMSIProperties
    Display all properties from the MSI database and exit (useful for discovery).
    
.PARAMETER WhatIf
    Show what would be deployed without making changes.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi"
    
    Deploy to all domain computers using default settings.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1
    
    Auto-detect: Searches current directory for MSI files and prompts for
    selection. Also searches for PSExec.exe in current directory and common
    locations.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\Agent.msi" -ShowMSIProperties
    
    Display all available MSI properties without deploying. Useful for
    discovering what properties can be customized via -MSIProperties.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -MSIProperties @{ SERVERURL="https://rmm.company.com"; APIKEY="abc123" }
    
    Deploy with custom MSI properties passed to the installer.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -TransformPath "C:\Installers\CustomSettings.mst"
    
    Deploy with an MST transform file applied.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -SearchBase "OU=Workstations,DC=contoso,DC=com" -ExcludeServers
    
    Deploy only to workstations in the specified OU.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -ComputerName "WKS01","WKS02","WKS03"
    
    Deploy to specific computers by name.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -ExcludePattern "^TEST-|^DEV-" -MaxConcurrent 20
    
    Deploy excluding test/dev machines with higher concurrency.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\RMMAgent.msi" -TestOnly
    
    Run readiness checks only - no deployment. Generates report showing which
    systems are ready (reachable, port 445 open, ADMIN$ accessible) and which
    have issues that need to be resolved before deployment.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -MSIPath "C:\Installers\Agent.msi" -RetryCount 2 -CollectLogs
    
    Deploy with automatic retry on failure and collect remote logs.
    
.NOTES
    Author:         Yeyland Wutani LLC
    Version:        2.0.0
    Requires:       PowerShell 5.1+, Active Directory module, PSExec.exe
    
.LINK
    https://github.com/YeylandWutani
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ADQuery')]
param(
    [Parameter(Position = 0)]
    [ValidateScript({ 
        if ($_ -and (Test-Path $_ -PathType Leaf)) { $true }
        elseif (-not $_) { $true }  # Allow empty when TestOnly
        else { throw "MSI file not found: $_" }
    })]
    [string]$MSIPath,
    
    [Parameter()]
    [ValidateScript({ 
        if ($_ -and (Test-Path $_ -PathType Leaf)) { $true }
        elseif (-not $_) { $true }
        else { throw "Transform file not found: $_" }
    })]
    [string]$TransformPath,
    
    [Parameter()]
    [hashtable]$MSIProperties,
    
    [Parameter(ParameterSetName = 'ADQuery')]
    [string]$SearchBase,
    
    [Parameter(ParameterSetName = 'Manual', Mandatory = $true)]
    [string[]]$ComputerName,
    
    [Parameter(ParameterSetName = 'ADQuery')]
    [string]$Filter = "*",
    
    [Parameter(ParameterSetName = 'ADQuery')]
    [switch]$ExcludeServers,
    
    [string]$ExcludePattern,
    
    [string]$MSIArguments = "/qn /norestart",
    
    [string]$StagingPath = "C:\Windows\Temp",
    
    [string]$PSExecPath,
    
    [PSCredential]$Credential,
    
    [ValidateRange(1, 50)]
    [int]$MaxConcurrent = 10,
    
    [ValidateRange(60, 3600)]
    [int]$TimeoutSeconds = 300,
    
    [string]$OutputPath = (Get-Location).Path,
    
    [switch]$CollectLogs,
    
    [switch]$SkipReachabilityCheck,
    
    [switch]$SkipCompatibilityCheck,
    
    [switch]$SkipValidation,
    
    [ValidateRange(0, 5)]
    [int]$RetryCount = 0,
    
    [ValidateRange(10, 300)]
    [int]$RetryDelaySeconds = 30,
    
    [switch]$Force,
    
    [Parameter(HelpMessage = "Run readiness checks only - no deployment")]
    [switch]$TestOnly,
    
    [Parameter(HelpMessage = "Display MSI properties and exit")]
    [switch]$ShowMSIProperties
)

#region Configuration
$Script:Config = @{
    Version          = "2.0.0"
    Timestamp        = Get-Date -Format "yyyyMMdd_HHmmss"
    MSIFileName      = $null
    MSIProductName   = $null
    MSIProductCode   = $null
    MSIProductVersion = $null
    MSIManufacturer  = $null
    LogFile          = $null
    HTMLReport       = $null
    CSVExport        = $null
    
    # Branding - Yeyland Wutani
    Colors           = @{
        Primary    = "#FF6600"    # Orange
        Secondary  = "#6B7280"    # Grey
        Success    = "#10B981"    # Green
        Warning    = "#F59E0B"    # Amber
        Error      = "#EF4444"    # Red
        Background = "#1F2937"    # Dark
        Surface    = "#374151"    # Surface
        Text       = "#F9FAFB"    # Light text
    }
    
    # Console colors (closest match to brand)
    ConsoleColors    = @{
        Primary   = "DarkYellow"
        Secondary = "Gray"
        Success   = "Green"
        Warning   = "Yellow"
        Error     = "Red"
        Info      = "Cyan"
    }
}

# Statistics tracking
$Script:Stats = @{
    StartTime              = Get-Date
    TotalComputers         = 0
    ReachableComputers     = 0
    CompatibleComputers    = 0
    SuccessfulDeployments  = 0
    FailedDeployments      = 0
    SkippedComputers       = 0
    ValidatedInstalls      = 0
    RetryAttempts          = 0
}

# Results collection
$Script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
#endregion

#region Banner and Logging Functions
function Show-Banner {
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
        "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
    )
    
    $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
    $border = "=" * 81
    
    Write-Host ""
    Write-Host $border -ForegroundColor $Script:Config.ConsoleColors.Secondary
    foreach ($line in $logo) {
        Write-Host $line -ForegroundColor $Script:Config.ConsoleColors.Primary
    }
    Write-Host ""
    Write-Host $tagline.PadLeft(62) -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host $border -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ""
    Write-Host "  MSI Deployment Tool v$($Script:Config.Version)" -ForegroundColor $Script:Config.ConsoleColors.Info
    if ($TestOnly) {
        Write-Host "  Mode: READINESS CHECK ONLY" -ForegroundColor $Script:Config.ConsoleColors.Warning
    }
    elseif ($ShowMSIProperties) {
        Write-Host "  Mode: MSI PROPERTY DISCOVERY" -ForegroundColor $Script:Config.ConsoleColors.Warning
    }
    Write-Host ""
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with color
    $color = switch ($Level) {
        'Info'    { $Script:Config.ConsoleColors.Info }
        'Success' { $Script:Config.ConsoleColors.Success }
        'Warning' { $Script:Config.ConsoleColors.Warning }
        'Error'   { $Script:Config.ConsoleColors.Error }
    }
    
    $prefix = switch ($Level) {
        'Info'    { "[*]" }
        'Success' { "[+]" }
        'Warning' { "[!]" }
        'Error'   { "[-]" }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
    
    # File logging
    if ($Script:Config.LogFile) {
        Add-Content -Path $Script:Config.LogFile -Value $logMessage -ErrorAction SilentlyContinue
    }
}

function Write-Phase {
    param([string]$Phase, [string]$Description)
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host " PHASE: $Phase" -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host " $Description" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ""
}
#endregion

#region MSI Property Functions
function Get-MSIProperty {
    <#
    .SYNOPSIS
        Retrieves a specific property from an MSI database.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MSIPath,
        
        [Parameter(Mandatory)]
        [string]$Property
    )
    
    $value = $null
    $installer = $null
    $database = $null
    $view = $null
    
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $null, $installer, @($MSIPath, 0)
        )
        
        $query = "SELECT Value FROM Property WHERE Property = '$Property'"
        $view = $database.GetType().InvokeMember(
            "OpenView", "InvokeMethod", $null, $database, @($query)
        )
        
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
        
        $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        
        if ($record) {
            $value = $record.GetType().InvokeMember(
                "StringData", "GetProperty", $null, $record, @(1)
            )
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($record) | Out-Null
        }
    }
    catch {
        # Property not found or error - return null
    }
    finally {
        # Cleanup COM objects
        if ($view) {
            try {
                $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null
            } catch { }
        }
        if ($database) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null } catch { }
        }
        if ($installer) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null } catch { }
        }
    }
    
    return $value
}

function Get-AllMSIProperties {
    <#
    .SYNOPSIS
        Retrieves all properties from an MSI database Property table.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MSIPath
    )
    
    $properties = [System.Collections.Generic.List[PSCustomObject]]::new()
    $installer = $null
    $database = $null
    $view = $null
    
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $null, $installer, @($MSIPath, 0)
        )
        
        $query = "SELECT Property, Value FROM Property"
        $view = $database.GetType().InvokeMember(
            "OpenView", "InvokeMethod", $null, $database, @($query)
        )
        
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
        
        $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        
        while ($record) {
            $propName = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, @(1))
            $propValue = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, @(2))
            
            $properties.Add([PSCustomObject]@{
                Property = $propName
                Value    = $propValue
                # PUBLIC properties (all uppercase) can be set via command line
                IsPublic = ($propName -ceq $propName.ToUpper())
            })
            
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($record) | Out-Null
            $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        }
    }
    catch {
        Write-Log "Failed to read MSI properties: $($_.Exception.Message)" -Level Error
    }
    finally {
        if ($view) {
            try {
                $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null
            } catch { }
        }
        if ($database) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null } catch { }
        }
        if ($installer) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null } catch { }
        }
    }
    
    return $properties
}

function Get-MSISummaryInfo {
    <#
    .SYNOPSIS
        Extracts key product information from MSI for display and validation.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MSIPath
    )
    
    $info = @{
        ProductName    = Get-MSIProperty -MSIPath $MSIPath -Property "ProductName"
        ProductVersion = Get-MSIProperty -MSIPath $MSIPath -Property "ProductVersion"
        ProductCode    = Get-MSIProperty -MSIPath $MSIPath -Property "ProductCode"
        Manufacturer   = Get-MSIProperty -MSIPath $MSIPath -Property "Manufacturer"
        UpgradeCode    = Get-MSIProperty -MSIPath $MSIPath -Property "UpgradeCode"
        ALLUSERS       = Get-MSIProperty -MSIPath $MSIPath -Property "ALLUSERS"
    }
    
    return $info
}

function Show-MSIPropertyReport {
    <#
    .SYNOPSIS
        Displays a formatted report of MSI properties for discovery purposes.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MSIPath
    )
    
    $allProps = Get-AllMSIProperties -MSIPath $MSIPath
    $msiInfo = Get-MSISummaryInfo -MSIPath $MSIPath
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host " MSI PROPERTY REPORT" -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ""
    
    # Product Summary
    Write-Host "  PRODUCT SUMMARY" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  ---------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  Product Name   : $($msiInfo.ProductName)" -ForegroundColor White
    Write-Host "  Version        : $($msiInfo.ProductVersion)" -ForegroundColor White
    Write-Host "  Manufacturer   : $($msiInfo.Manufacturer)" -ForegroundColor White
    Write-Host "  Product Code   : $($msiInfo.ProductCode)" -ForegroundColor Gray
    Write-Host "  Upgrade Code   : $($msiInfo.UpgradeCode)" -ForegroundColor Gray
    Write-Host ""
    
    # Standard Silent Switches (always available for MSI)
    Write-Host "  STANDARD MSI SILENT SWITCHES" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  ----------------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  /qn           - Completely silent (no UI)" -ForegroundColor White
    Write-Host "  /qb           - Basic UI (progress bar only)" -ForegroundColor White
    Write-Host "  /qr           - Reduced UI" -ForegroundColor White
    Write-Host "  /passive      - Unattended mode (progress bar)" -ForegroundColor White
    Write-Host "  /norestart    - Suppress restart prompts" -ForegroundColor White
    Write-Host "  /l*v <file>   - Verbose logging" -ForegroundColor White
    Write-Host ""
    
    # Public Properties (can be set via command line)
    $publicProps = $allProps | Where-Object { $_.IsPublic -and $_.Property -notmatch '^(ProductCode|ProductVersion|UpgradeCode|ProductName|Manufacturer)$' }
    
    if ($publicProps) {
        Write-Host "  PUBLIC PROPERTIES (Can be set via command line)" -ForegroundColor $Script:Config.ConsoleColors.Info
        Write-Host "  -----------------------------------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
        Write-Host "  Use: msiexec /i package.msi PROPERTY=value" -ForegroundColor Gray
        Write-Host ""
        
        foreach ($prop in ($publicProps | Sort-Object Property)) {
            $valueDisplay = if ($prop.Value.Length -gt 50) { 
                $prop.Value.Substring(0, 47) + "..." 
            } else { 
                $prop.Value 
            }
            Write-Host "  $($prop.Property.PadRight(25)) = $valueDisplay" -ForegroundColor White
        }
        Write-Host ""
    }
    
    # Common Customizable Properties hint
    Write-Host "  COMMON CUSTOMIZABLE PROPERTIES (if supported)" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  ---------------------------------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  INSTALLDIR    - Installation directory" -ForegroundColor Gray
    Write-Host "  TARGETDIR     - Alternative install path property" -ForegroundColor Gray
    Write-Host "  ALLUSERS      - 1=All users, empty=Current user" -ForegroundColor Gray
    Write-Host "  REBOOT        - ReallySuppress/Force" -ForegroundColor Gray
    Write-Host "  ADDLOCAL      - Features to install" -ForegroundColor Gray
    Write-Host ""
    
    # Example command
    Write-Host "  EXAMPLE DEPLOYMENT COMMAND" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  --------------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  msiexec /i `"$([System.IO.Path]::GetFileName($MSIPath))`" /qn /norestart /l*v install.log" -ForegroundColor Cyan
    Write-Host ""
    
    # Total property count
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  Total Properties: $($allProps.Count) | Public (Configurable): $($publicProps.Count)" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ""
    
    return @{
        AllProperties = $allProps
        Summary       = $msiInfo
        PublicCount   = $publicProps.Count
    }
}
#endregion

#region Utility Functions
function Find-PSExec {
    <#
    .SYNOPSIS
        Locates PSExec.exe in common locations or PATH.
    #>
    
    Write-Log "Searching for PSExec.exe..." -Level Info
    
    # If path specified, validate it
    if ($PSExecPath) {
        if (Test-Path $PSExecPath -PathType Leaf) {
            Write-Log "Using specified PSExec path: $PSExecPath" -Level Success
            return $PSExecPath
        }
        else {
            Write-Log "Specified PSExec path not found: $PSExecPath" -Level Error
            return $null
        }
    }
    
    # Search common locations (current directory first)
    $searchPaths = @(
        # Current directory (highest priority)
        (Join-Path (Get-Location).Path "PSExec.exe"),
        (Join-Path (Get-Location).Path "PsExec.exe"),
        (Join-Path (Get-Location).Path "psexec.exe"),
        # Script directory
        (Join-Path $PSScriptRoot "PSExec.exe"),
        (Join-Path $PSScriptRoot "PsExec.exe"),
        # Sysinternals folder
        "C:\SysinternalsSuite\PsExec.exe",
        "C:\Sysinternals\PsExec.exe",
        "C:\Tools\Sysinternals\PsExec.exe",
        "C:\Tools\PsExec.exe",
        # Program Files
        "${env:ProgramFiles}\Sysinternals\PsExec.exe",
        "${env:ProgramFiles(x86)}\Sysinternals\PsExec.exe",
        # Windows directory
        "$env:SystemRoot\System32\PsExec.exe",
        "$env:SystemRoot\PsExec.exe"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path -PathType Leaf) {
            Write-Log "Found PSExec at: $path" -Level Success
            return $path
        }
    }
    
    # Try PATH
    $psexecInPath = Get-Command "PsExec.exe" -ErrorAction SilentlyContinue
    if ($psexecInPath) {
        Write-Log "Found PSExec in PATH: $($psexecInPath.Source)" -Level Success
        return $psexecInPath.Source
    }
    
    Write-Log "PSExec.exe not found in common locations" -Level Warning
    return $null
}

function Find-LocalMSI {
    <#
    .SYNOPSIS
        Searches current directory for MSI files and prompts user to select one.
    #>
    
    $currentDir = (Get-Location).Path
    $msiFiles = Get-ChildItem -Path $currentDir -Filter "*.msi" -File -ErrorAction SilentlyContinue
    
    if (-not $msiFiles -or $msiFiles.Count -eq 0) {
        return $null
    }
    
    if ($msiFiles.Count -eq 1) {
        # Single MSI found - show info and prompt to confirm
        $msi = $msiFiles[0]
        $msiInfo = Get-MSISummaryInfo -MSIPath $msi.FullName
        
        Write-Host ""
        Write-Host "  Found MSI in current directory:" -ForegroundColor Cyan
        Write-Host "    File: $($msi.Name) ($([math]::Round($msi.Length / 1MB, 2)) MB)" -ForegroundColor White
        if ($msiInfo.ProductName) {
            Write-Host "    Product: $($msiInfo.ProductName) v$($msiInfo.ProductVersion)" -ForegroundColor White
            Write-Host "    Vendor:  $($msiInfo.Manufacturer)" -ForegroundColor Gray
        }
        Write-Host ""
        $confirm = Read-Host "  Use this MSI for deployment? (Y/N)"
        if ($confirm -match '^[Yy]') {
            return $msi.FullName
        }
        return $null
    }
    else {
        # Multiple MSIs found - prompt to select
        Write-Host ""
        Write-Host "  Found $($msiFiles.Count) MSI files in current directory:" -ForegroundColor Cyan
        Write-Host ""
        for ($i = 0; $i -lt $msiFiles.Count; $i++) {
            $msi = $msiFiles[$i]
            $msiInfo = Get-MSISummaryInfo -MSIPath $msi.FullName
            $productDisplay = if ($msiInfo.ProductName) { " - $($msiInfo.ProductName)" } else { "" }
            Write-Host "    [$($i + 1)] $($msi.Name)$productDisplay ($([math]::Round($msi.Length / 1MB, 2)) MB)" -ForegroundColor White
        }
        Write-Host "    [0] None - cancel" -ForegroundColor Gray
        Write-Host ""
        
        $selection = Read-Host "  Select MSI to deploy (0-$($msiFiles.Count))"
        
        if ($selection -match '^\d+$') {
            $index = [int]$selection
            if ($index -gt 0 -and $index -le $msiFiles.Count) {
                return $msiFiles[$index - 1].FullName
            }
        }
        return $null
    }
}

function Get-ADComputersFromQuery {
    <#
    .SYNOPSIS
        Queries Active Directory for computer objects.
    #>
    param(
        [string]$SearchBase,
        [string]$ADFilter,
        [switch]$ExcludeServers
    )
    
    Write-Log "Querying Active Directory for computers..." -Level Info
    
    # Check for AD module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Active Directory PowerShell module not available." -Level Error
        Write-Log "Install with: Install-WindowsFeature RSAT-AD-PowerShell" -Level Info
        return $null
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Build parameters
    $adParams = @{
        Filter     = $ADFilter
        Properties = @('Name', 'DNSHostName', 'OperatingSystem', 'Enabled', 'LastLogonDate', 'DistinguishedName')
    }
    
    if ($SearchBase) {
        $adParams['SearchBase'] = $SearchBase
        Write-Log "Searching in OU: $SearchBase" -Level Info
    }
    else {
        Write-Log "Searching entire domain" -Level Info
    }
    
    try {
        $computers = Get-ADComputer @adParams | Where-Object { $_.Enabled -eq $true }
        
        # Exclude servers if specified
        if ($ExcludeServers) {
            $preCount = $computers.Count
            $computers = $computers | Where-Object { 
                $_.OperatingSystem -notmatch 'Server' 
            }
            $excluded = $preCount - $computers.Count
            if ($excluded -gt 0) {
                Write-Log "Excluded $excluded server(s) from deployment" -Level Info
            }
        }
        
        Write-Log "Found $($computers.Count) enabled computer(s)" -Level Success
        return $computers
    }
    catch {
        Write-Log "AD query failed: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Test-ComputerReachable {
    <#
    .SYNOPSIS
        Tests if a computer is reachable via ICMP ping.
    #>
    param([string]$ComputerName)
    
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $ping
    }
    catch {
        return $false
    }
}

function Test-PSExecCompatibility {
    <#
    .SYNOPSIS
        Validates that a computer supports PSEXEC operations.
    #>
    param(
        [string]$ComputerName,
        [PSCredential]$Credential
    )
    
    $result = [PSCustomObject]@{
        ComputerName   = $ComputerName
        AdminShare     = $false
        SMBPort        = $false
        Compatible     = $false
        ErrorMessage   = $null
    }
    
    try {
        # Test SMB Port 445
        $tcpTest = Test-NetConnection -ComputerName $ComputerName -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $result.SMBPort = $tcpTest.TcpTestSucceeded
        
        if (-not $result.SMBPort) {
            $result.ErrorMessage = "Port 445 (SMB) not accessible"
            return $result
        }
        
        # Test ADMIN$ share access
        $adminSharePath = "\\$ComputerName\ADMIN`$"
        
        if ($Credential) {
            # Map drive with credentials to test
            $testDrive = "Z:"
            $netUseArgs = "use $testDrive $adminSharePath /user:$($Credential.UserName) `"$($Credential.GetNetworkCredential().Password)`""
            $netResult = cmd /c "net $netUseArgs 2>&1"
            
            if ($LASTEXITCODE -eq 0) {
                $result.AdminShare = $true
                cmd /c "net use $testDrive /delete /y" 2>&1 | Out-Null
            }
            else {
                $result.ErrorMessage = "Cannot access ADMIN$ share"
            }
        }
        else {
            # Test with current credentials
            if (Test-Path $adminSharePath -ErrorAction SilentlyContinue) {
                $result.AdminShare = $true
            }
            else {
                $result.ErrorMessage = "Cannot access ADMIN$ share"
            }
        }
        
        $result.Compatible = $result.SMBPort -and $result.AdminShare
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
    }
    
    return $result
}

function Build-MSIArguments {
    <#
    .SYNOPSIS
        Constructs the full msiexec argument string including properties and transforms.
    #>
    param(
        [string]$MSIPath,
        [string]$BaseArguments,
        [string]$TransformPath,
        [hashtable]$Properties,
        [string]$LogPath
    )
    
    $args = @("/i `"$MSIPath`"")
    
    # Add transform if specified
    if ($TransformPath) {
        $args += "TRANSFORMS=`"$TransformPath`""
    }
    
    # Add custom properties
    if ($Properties -and $Properties.Count -gt 0) {
        foreach ($key in $Properties.Keys) {
            $args += "$key=`"$($Properties[$key])`""
        }
    }
    
    # Add base arguments
    $args += $BaseArguments
    
    # Add logging
    if ($LogPath) {
        $args += "/l*v `"$LogPath`""
    }
    
    return $args -join ' '
}

function Copy-MSIToRemote {
    <#
    .SYNOPSIS
        Copies MSI file (and transform if specified) to remote computer staging location.
    #>
    param(
        [string]$ComputerName,
        [string]$SourcePath,
        [string]$TransformPath,
        [string]$StagingPath,
        [PSCredential]$Credential
    )
    
    $remotePath = "\\$ComputerName\$($StagingPath.Replace(':', '$'))"
    
    try {
        # Ensure staging directory exists
        if (-not (Test-Path $remotePath)) {
            New-Item -ItemType Directory -Path $remotePath -Force | Out-Null
        }
        
        # Copy MSI
        $msiDest = Join-Path $remotePath ([System.IO.Path]::GetFileName($SourcePath))
        Copy-Item -Path $SourcePath -Destination $msiDest -Force -ErrorAction Stop
        
        # Copy transform if specified
        $transformDest = $null
        if ($TransformPath -and (Test-Path $TransformPath)) {
            $transformDest = Join-Path $remotePath ([System.IO.Path]::GetFileName($TransformPath))
            Copy-Item -Path $TransformPath -Destination $transformDest -Force -ErrorAction Stop
        }
        
        # Verify MSI copy
        if (Test-Path $msiDest) {
            return @{
                MSIPath       = $msiDest
                TransformPath = $transformDest
                Success       = $true
            }
        }
        else {
            return @{ Success = $false }
        }
    }
    catch {
        Write-Log "Failed to copy files to $ComputerName : $($_.Exception.Message)" -Level Error
        return @{ Success = $false }
    }
}

function Invoke-PSExecInstall {
    <#
    .SYNOPSIS
        Executes MSI installation via PSEXEC.
    #>
    param(
        [string]$PSExecPath,
        [string]$ComputerName,
        [string]$MSIPath,
        [string]$Arguments,
        [PSCredential]$Credential,
        [int]$TimeoutSeconds
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $ComputerName
        Success      = $false
        ExitCode     = $null
        Output       = $null
        ErrorMessage = $null
        Duration     = $null
    }
    
    $startTime = Get-Date
    
    # Build PSEXEC command
    # -accepteula : Auto-accept EULA
    # -nobanner   : Suppress startup banner
    # -s          : Run as SYSTEM (important for msiexec)
    # -e          : Don't load user profile (prevents msiexec issues)
    # -n          : Connection timeout
    
    $psexecArgs = @(
        "\\$ComputerName"
        "-accepteula"
        "-nobanner"
        "-s"
        "-e"
        "-n", "30"
    )
    
    # Add credentials if specified
    if ($Credential) {
        $psexecArgs += @(
            "-u", $Credential.UserName
            "-p", $Credential.GetNetworkCredential().Password
        )
    }
    
    # Add msiexec command
    $msiCommand = "msiexec.exe $Arguments"
    $psexecArgs += $msiCommand
    
    try {
        Write-Log "[$ComputerName] Executing: msiexec.exe $Arguments" -Level Info
        
        # Start process with timeout
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $PSExecPath
        $processInfo.Arguments = $psexecArgs -join ' '
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        $process.Start() | Out-Null
        
        # Capture output
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        
        # Wait with timeout
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        
        if (-not $completed) {
            $process.Kill()
            $result.ErrorMessage = "Installation timed out after $TimeoutSeconds seconds"
            $result.ExitCode = -1
        }
        else {
            $result.ExitCode = $process.ExitCode
            $result.Output = $stdout.Result + "`n" + $stderr.Result
            
            # PSEXEC returns msiexec exit code
            # 0 = Success
            # 3010 = Success, reboot required
            # 1641 = Success, installer initiated reboot
            switch ($result.ExitCode) {
                0 {
                    $result.Success = $true
                }
                3010 {
                    $result.Success = $true
                    $result.Output = "Installation successful - Reboot required"
                }
                1641 {
                    $result.Success = $true
                    $result.Output = "Installation successful - Reboot initiated"
                }
                1603 {
                    $result.ErrorMessage = "Fatal error during installation (1603)"
                }
                1612 {
                    $result.ErrorMessage = "Installation source not found (1612)"
                }
                1618 {
                    $result.ErrorMessage = "Another installation in progress (1618)"
                }
                1619 {
                    $result.ErrorMessage = "MSI package could not be opened (1619)"
                }
                1638 {
                    $result.ErrorMessage = "Another version already installed (1638)"
                }
                default {
                    $result.ErrorMessage = "Installation failed with exit code: $($result.ExitCode)"
                }
            }
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        $result.ExitCode = -1
    }
    finally {
        $result.Duration = (Get-Date) - $startTime
    }
    
    return $result
}

function Test-ProductInstalled {
    <#
    .SYNOPSIS
        Verifies if the product was successfully installed on the remote system.
    #>
    param(
        [string]$ComputerName,
        [string]$ProductCode,
        [string]$ProductName,
        [PSCredential]$Credential
    )
    
    try {
        $scriptBlock = {
            param($ProductCode, $ProductName)
            
            # Check by ProductCode in registry
            $uninstallPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            
            foreach ($path in $uninstallPaths) {
                if (Test-Path $path) {
                    $found = Get-ChildItem $path | Get-ItemProperty | Where-Object {
                        $_.PSChildName -eq $ProductCode -or
                        $_.DisplayName -like "*$ProductName*"
                    }
                    if ($found) { return $true }
                }
            }
            return $false
        }
        
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = $scriptBlock
            ArgumentList = @($ProductCode, $ProductName)
            ErrorAction  = 'Stop'
        }
        
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $installed = Invoke-Command @params
        return $installed
    }
    catch {
        Write-Log "[$ComputerName] Validation check failed: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Copy-RemoteLog {
    <#
    .SYNOPSIS
        Copies the msiexec log from remote system back to local output folder.
    #>
    param(
        [string]$ComputerName,
        [string]$RemoteLogPath,
        [string]$LocalOutputPath
    )
    
    try {
        $remotePath = "\\$ComputerName\$($RemoteLogPath.Replace(':', '$'))"
        if (Test-Path $remotePath) {
            $localLogPath = Join-Path $LocalOutputPath "msiexec_$ComputerName`_$($Script:Config.Timestamp).log"
            Copy-Item -Path $remotePath -Destination $localLogPath -Force -ErrorAction Stop
            return $localLogPath
        }
    }
    catch {
        Write-Log "[$ComputerName] Failed to collect log: $($_.Exception.Message)" -Level Warning
    }
    return $null
}

function Remove-StagedFiles {
    <#
    .SYNOPSIS
        Cleans up MSI and related files from remote staging location.
    #>
    param(
        [string]$ComputerName,
        [string]$StagingPath,
        [string]$MSIFileName,
        [string]$TransformFileName
    )
    
    try {
        $remotePath = "\\$ComputerName\$($StagingPath.Replace(':', '$'))"
        
        # Remove MSI
        $msiPath = Join-Path $remotePath $MSIFileName
        if (Test-Path $msiPath) {
            Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
        }
        
        # Remove Transform
        if ($TransformFileName) {
            $transformPath = Join-Path $remotePath $TransformFileName
            if (Test-Path $transformPath) {
                Remove-Item -Path $transformPath -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Remove log
        $logPattern = Join-Path $remotePath "msiexec_*.log"
        Get-ChildItem -Path $logPattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Silent cleanup - non-critical
    }
}
#endregion

#region Report Generation
function New-HTMLReport {
    <#
    .SYNOPSIS
        Generates professional HTML deployment report.
    #>
    param(
        [string]$OutputPath,
        [switch]$TestOnly
    )
    
    $c = $Script:Config.Colors
    $endTime = Get-Date
    $duration = $endTime - $Script:Stats.StartTime
    
    # Calculate statistics based on mode
    if ($TestOnly) {
        $readyCount = ($Script:Results | Where-Object { $_.Status -eq 'Ready' }).Count
        $notReadyCount = $Script:Stats.TotalComputers - $readyCount
        $readinessRate = if ($Script:Stats.TotalComputers -gt 0) {
            [math]::Round(($readyCount / $Script:Stats.TotalComputers) * 100, 1)
        } else { 0 }
        $reportTitle = "MSI Deployment Readiness Report"
        $filePrefix = "MSI_Readiness"
    }
    else {
        $successRate = if ($Script:Stats.TotalComputers -gt 0) {
            [math]::Round(($Script:Stats.SuccessfulDeployments / $Script:Stats.TotalComputers) * 100, 1)
        } else { 0 }
        $reportTitle = "MSI Deployment Report"
        $filePrefix = "MSI_Deployment"
    }
    
    # Product info for header
    $productInfo = if ($Script:Config.MSIProductName) {
        "$($Script:Config.MSIProductName) v$($Script:Config.MSIProductVersion)"
    } else {
        $Script:Config.MSIFileName
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$reportTitle - Yeyland Wutani</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: $($c.Background);
            color: $($c.Text);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, $($c.Surface) 0%, $($c.Background) 100%);
            border-left: 4px solid $($c.Primary);
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        .header h1 {
            color: $($c.Primary);
            font-size: 28px;
            margin-bottom: 5px;
        }
        .header .tagline {
            color: $($c.Secondary);
            font-size: 14px;
            letter-spacing: 2px;
        }
        .header .meta {
            margin-top: 15px;
            color: $($c.Secondary);
            font-size: 13px;
        }
        .header .product-info {
            margin-top: 10px;
            padding: 10px;
            background: rgba(255,102,0,0.1);
            border-radius: 4px;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: $($c.Surface);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label {
            color: $($c.Secondary);
            font-size: 13px;
            text-transform: uppercase;
        }
        .stat-card.success .value { color: $($c.Success); }
        .stat-card.warning .value { color: $($c.Warning); }
        .stat-card.error .value { color: $($c.Error); }
        .stat-card.info .value { color: $($c.Primary); }
        
        /* Progress Bar */
        .progress-container {
            background: $($c.Surface);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .progress-bar {
            background: $($c.Background);
            height: 30px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        .progress-fill.success { background: $($c.Success); }
        .progress-fill.error { background: $($c.Error); }
        
        /* Results Table */
        .results-section {
            background: $($c.Surface);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }
        .results-section h2 {
            padding: 20px;
            border-bottom: 1px solid $($c.Background);
            color: $($c.Primary);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: $($c.Background);
            padding: 12px 15px;
            text-align: left;
            color: $($c.Secondary);
            font-size: 12px;
            text-transform: uppercase;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid $($c.Background);
        }
        tr:hover { background: rgba(255,255,255,0.02); }
        
        /* Status Badges */
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-success { background: rgba(16, 185, 129, 0.2); color: $($c.Success); }
        .badge-error { background: rgba(239, 68, 68, 0.2); color: $($c.Error); }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: $($c.Warning); }
        .badge-info { background: rgba(255, 102, 0, 0.2); color: $($c.Primary); }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: $($c.Secondary);
            font-size: 12px;
        }
        .footer a { color: $($c.Primary); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$reportTitle</h1>
            <div class="tagline">YEYLAND WUTANI - BUILDING BETTER SYSTEMS</div>
            <div class="product-info">
                <strong>Product:</strong> $productInfo<br>
                <strong>Package:</strong> $($Script:Config.MSIFileName)$(if ($Script:Config.MSIProductCode) { "<br><strong>Product Code:</strong> $($Script:Config.MSIProductCode)" })
            </div>
            <div class="meta">
                <strong>Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")<br>
                <strong>Duration:</strong> $([math]::Round($duration.TotalMinutes, 1)) minutes$(if ($TestOnly) { '<br><strong style="color: ' + $c.Warning + ';">Mode: Readiness Check Only (No Deployment)</strong>' })
            </div>
        </div>
        
        <div class="stats-grid">
$(if ($TestOnly) {
@"
            <div class="stat-card info">
                <div class="value">$($Script:Stats.TotalComputers)</div>
                <div class="label">Total Targets</div>
            </div>
            <div class="stat-card info">
                <div class="value">$($Script:Stats.ReachableComputers)</div>
                <div class="label">Reachable</div>
            </div>
            <div class="stat-card success">
                <div class="value">$readyCount</div>
                <div class="label">Ready</div>
            </div>
            <div class="stat-card error">
                <div class="value">$notReadyCount</div>
                <div class="label">Not Ready</div>
            </div>
"@
} else {
@"
            <div class="stat-card info">
                <div class="value">$($Script:Stats.TotalComputers)</div>
                <div class="label">Total Targets</div>
            </div>
            <div class="stat-card info">
                <div class="value">$($Script:Stats.ReachableComputers)</div>
                <div class="label">Reachable</div>
            </div>
            <div class="stat-card info">
                <div class="value">$($Script:Stats.CompatibleComputers)</div>
                <div class="label">Compatible</div>
            </div>
            <div class="stat-card success">
                <div class="value">$($Script:Stats.SuccessfulDeployments)</div>
                <div class="label">Successful</div>
            </div>
            <div class="stat-card error">
                <div class="value">$($Script:Stats.FailedDeployments)</div>
                <div class="label">Failed</div>
            </div>
            <div class="stat-card warning">
                <div class="value">$($Script:Stats.SkippedComputers)</div>
                <div class="label">Skipped</div>
            </div>
"@
})
        </div>
        
        <div class="progress-container">
$(if ($TestOnly) {
@"
            <strong>Deployment Readiness: ${readinessRate}%</strong>
            <div class="progress-bar">
                <div class="progress-fill success" style="width: ${readinessRate}%">${readinessRate}%</div>
            </div>
"@
} else {
@"
            <strong>Deployment Success Rate: ${successRate}%</strong>
            <div class="progress-bar">
                <div class="progress-fill success" style="width: ${successRate}%">${successRate}%</div>
            </div>
"@
})
        </div>
        
        <div class="results-section">
            <h2>$(if ($TestOnly) { 'Readiness Assessment Results' } else { 'Deployment Results' })</h2>
            <table>
                <thead>
                    <tr>
                        <th>Computer</th>
                        <th>Operating System</th>
                        <th>Status</th>
                        <th>Exit Code</th>
                        <th>Validated</th>
                        <th>Duration</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
"@

    # Add result rows
    foreach ($result in $Script:Results) {
        $statusBadge = switch ($result.Status) {
            'Success'      { '<span class="badge badge-success">Success</span>' }
            'Ready'        { '<span class="badge badge-success">Ready</span>' }
            'Unreachable'  { '<span class="badge badge-warning">Unreachable</span>' }
            'Incompatible' { '<span class="badge badge-warning">Incompatible</span>' }
            'Failed'       { '<span class="badge badge-error">Failed</span>' }
            'Skipped'      { '<span class="badge badge-info">Skipped</span>' }
            default        { '<span class="badge badge-info">Unknown</span>' }
        }
        
        $durationStr = if ($result.Duration) { 
            "$([math]::Round($result.Duration.TotalSeconds, 1))s" 
        } else { 
            "-" 
        }
        
        $validatedStr = switch ($result.Validated) {
            $true  { '<span class="badge badge-success">Yes</span>' }
            $false { '<span class="badge badge-error">No</span>' }
            default { '-' }
        }
        
        $html += @"
                    <tr>
                        <td><strong>$($result.ComputerName)</strong></td>
                        <td>$($result.OperatingSystem)</td>
                        <td>$statusBadge</td>
                        <td>$($result.ExitCode)</td>
                        <td>$validatedStr</td>
                        <td>$durationStr</td>
                        <td>$($result.Message)</td>
                    </tr>
"@
    }

    $html += @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by <a href="https://github.com/YeylandWutani">Yeyland Wutani</a> MSI Deployment Tool v$($Script:Config.Version)</p>
            <p>Building Better Systems</p>
        </div>
    </div>
</body>
</html>
"@

    $reportPath = Join-Path $OutputPath "${filePrefix}_$($Script:Config.Timestamp).html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    
    return $reportPath
}

function Export-ResultsCSV {
    <#
    .SYNOPSIS
        Exports deployment results to CSV.
    #>
    param([string]$OutputPath)
    
    $csvPath = Join-Path $OutputPath "MSI_Deployment_$($Script:Config.Timestamp).csv"
    $Script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Force
    
    return $csvPath
}
#endregion

#region Main Execution
function Start-Deployment {
    Show-Banner
    
    #==========================================================================
    # ShowMSIProperties Mode - Just display MSI info and exit
    #==========================================================================
    if ($ShowMSIProperties) {
        if (-not $MSIPath) {
            # Try auto-detect
            $MSIPath = Find-LocalMSI
        }
        
        if (-not $MSIPath -or -not (Test-Path $MSIPath)) {
            Write-Log "Please specify an MSI file with -MSIPath" -Level Error
            return
        }
        
        Show-MSIPropertyReport -MSIPath $MSIPath
        return
    }
    
    # Validate MSIPath is provided when not in TestOnly mode
    if (-not $TestOnly -and -not $MSIPath) {
        # Try to auto-detect MSI in current directory
        Write-Log "No MSI path specified - checking current directory..." -Level Info
        $detectedMSI = Find-LocalMSI
        
        if ($detectedMSI) {
            $script:MSIPath = $detectedMSI
        }
        else {
            Write-Log "No MSI file found or selected" -Level Error
            Write-Host ""
            Write-Host "  Usage:" -ForegroundColor Yellow
            Write-Host "    Readiness check:  .\Deploy-RMMAgent.ps1 -TestOnly" -ForegroundColor Gray
            Write-Host "    MSI discovery:    .\Deploy-RMMAgent.ps1 -MSIPath 'Agent.msi' -ShowMSIProperties" -ForegroundColor Gray
            Write-Host "    Full deployment:  .\Deploy-RMMAgent.ps1 -MSIPath 'C:\Path\To\Agent.msi'" -ForegroundColor Gray
            Write-Host "    Auto-detect:      Place MSI in current directory and run without -MSIPath" -ForegroundColor Gray
            Write-Host ""
            return
        }
    }
    
    # Use the resolved MSI path
    $effectiveMSIPath = if ($script:MSIPath) { $script:MSIPath } else { $MSIPath }
    
    # Extract MSI info for display and validation
    if ($effectiveMSIPath -and (Test-Path $effectiveMSIPath)) {
        $msiInfo = Get-MSISummaryInfo -MSIPath $effectiveMSIPath
        $Script:Config.MSIFileName = [System.IO.Path]::GetFileName($effectiveMSIPath)
        $Script:Config.MSIProductName = $msiInfo.ProductName
        $Script:Config.MSIProductVersion = $msiInfo.ProductVersion
        $Script:Config.MSIProductCode = $msiInfo.ProductCode
        $Script:Config.MSIManufacturer = $msiInfo.Manufacturer
    }
    else {
        $Script:Config.MSIFileName = "(Readiness Check Only)"
    }
    
    # Initialize output files
    $Script:Config.LogFile = Join-Path $OutputPath "MSI_Deployment_$($Script:Config.Timestamp).log"
    
    if ($TestOnly) {
        Write-Log "Starting MSI Deployment Readiness Check" -Level Info
    }
    else {
        Write-Log "Starting MSI Deployment" -Level Info
        Write-Log "Package: $($Script:Config.MSIFileName)" -Level Info
        if ($Script:Config.MSIProductName) {
            Write-Log "Product: $($Script:Config.MSIProductName) v$($Script:Config.MSIProductVersion)" -Level Info
        }
    }
    
    #==========================================================================
    # Phase 0: Prerequisites
    #==========================================================================
    Write-Phase "PREREQUISITES" "Validating requirements..."
    
    $psexec = $null
    
    if (-not $TestOnly) {
        # Find PSExec (only needed for actual deployment)
        $psexec = Find-PSExec
        if (-not $psexec) {
            Write-Host ""
            Write-Host "  PSExec.exe is required for deployment but was not found." -ForegroundColor Red
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor Yellow
            Write-Host "    1. Download from: https://docs.microsoft.com/sysinternals/downloads/psexec" -ForegroundColor Gray
            Write-Host "    2. Place PSExec.exe in current directory: $(Get-Location)" -ForegroundColor Gray
            Write-Host "    3. Specify path with: -PSExecPath 'C:\Path\To\PSExec.exe'" -ForegroundColor Gray
            Write-Host ""
            
            $psexecInput = Read-Host "  Enter path to PSExec.exe (or press Enter to cancel)"
            if ($psexecInput -and (Test-Path $psexecInput -PathType Leaf)) {
                $psexec = $psexecInput
                Write-Log "Using PSExec: $psexec" -Level Success
            }
            else {
                Write-Log "Cannot proceed without PSExec.exe" -Level Error
                return
            }
        }
        
        # Display MSI info
        $msiFileInfo = Get-Item $effectiveMSIPath
        Write-Log "MSI File: $($msiFileInfo.Name) ($([math]::Round($msiFileInfo.Length / 1MB, 2)) MB)" -Level Info
        
        # Show custom properties if specified
        if ($MSIProperties -and $MSIProperties.Count -gt 0) {
            Write-Log "Custom MSI Properties:" -Level Info
            foreach ($key in $MSIProperties.Keys) {
                Write-Log "  $key = $($MSIProperties[$key])" -Level Info
            }
        }
        
        if ($TransformPath) {
            Write-Log "Transform: $([System.IO.Path]::GetFileName($TransformPath))" -Level Info
        }
    }
    else {
        Write-Log "TestOnly mode - skipping PSExec and MSI validation" -Level Info
    }
    
    #==========================================================================
    # Phase 1: Build Target List
    #==========================================================================
    Write-Phase "TARGET DISCOVERY" "Building list of deployment targets..."
    
    $computers = @()
    
    if ($PSCmdlet.ParameterSetName -eq 'Manual') {
        # Manual computer list
        Write-Log "Using manually specified computers: $($ComputerName.Count) system(s)" -Level Info
        $computers = $ComputerName | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_
                DNSHostName     = $_
                OperatingSystem = "Unknown"
            }
        }
    }
    else {
        # AD Query
        $adComputers = Get-ADComputersFromQuery -SearchBase $SearchBase -ADFilter $Filter -ExcludeServers:$ExcludeServers
        if (-not $adComputers) {
            Write-Log "No computers found or AD query failed" -Level Error
            return
        }
        $computers = $adComputers
    }
    
    # Apply exclusion pattern
    if ($ExcludePattern) {
        $preCount = $computers.Count
        $computers = $computers | Where-Object { $_.Name -notmatch $ExcludePattern }
        $excluded = $preCount - $computers.Count
        if ($excluded -gt 0) {
            Write-Log "Excluded $excluded computer(s) matching pattern: $ExcludePattern" -Level Info
        }
    }
    
    $Script:Stats.TotalComputers = $computers.Count
    Write-Log "Total deployment targets: $($computers.Count)" -Level Success
    
    if ($computers.Count -eq 0) {
        Write-Log "No computers to deploy to" -Level Warning
        return
    }
    
    #==========================================================================
    # Phase 2: Reachability Check
    #==========================================================================
    $reachableComputers = @()
    
    if ($SkipReachabilityCheck) {
        Write-Log "Skipping reachability check (all computers assumed online)" -Level Warning
        $reachableComputers = $computers
        $Script:Stats.ReachableComputers = $reachableComputers.Count
    }
    else {
        Write-Phase "REACHABILITY" "Testing network connectivity to targets..."
        
        $reachCheckProgress = 0
        foreach ($computer in $computers) {
            $reachCheckProgress++
            $percentComplete = [math]::Round(($reachCheckProgress / $computers.Count) * 100)
            Write-Progress -Activity "Testing Reachability" -Status "$($computer.Name)" -PercentComplete $percentComplete
            
            $hostname = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
            
            if (Test-ComputerReachable -ComputerName $hostname) {
                $reachableComputers += $computer
            }
            else {
                $Script:Results.Add([PSCustomObject]@{
                    ComputerName    = $computer.Name
                    OperatingSystem = $computer.OperatingSystem
                    Status          = "Unreachable"
                    ExitCode        = $null
                    Duration        = $null
                    Validated       = $null
                    Message         = "Failed ping test - system offline or blocking ICMP"
                })
            }
        }
        Write-Progress -Activity "Testing Reachability" -Completed
        
        $Script:Stats.ReachableComputers = $reachableComputers.Count
        Write-Log "Reachable systems: $($reachableComputers.Count) of $($computers.Count)" -Level $(if ($reachableComputers.Count -eq $computers.Count) { 'Success' } else { 'Warning' })
    }
    
    if ($reachableComputers.Count -eq 0) {
        Write-Log "No reachable computers found" -Level Error
        return
    }
    
    #==========================================================================
    # Phase 3: PSEXEC Compatibility Check
    #==========================================================================
    $compatibleComputers = @()
    
    if ($SkipCompatibilityCheck) {
        Write-Log "Skipping compatibility check (all reachable computers assumed compatible)" -Level Warning
        $compatibleComputers = $reachableComputers
        $Script:Stats.CompatibleComputers = $compatibleComputers.Count
    }
    else {
        Write-Phase "COMPATIBILITY" "Validating PSEXEC prerequisites on targets..."
        
        $compatCheckProgress = 0
        foreach ($computer in $reachableComputers) {
            $compatCheckProgress++
            $percentComplete = [math]::Round(($compatCheckProgress / $reachableComputers.Count) * 100)
            Write-Progress -Activity "Testing PSEXEC Compatibility" -Status "$($computer.Name)" -PercentComplete $percentComplete
            
            $hostname = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
            $compatibility = Test-PSExecCompatibility -ComputerName $hostname -Credential $Credential
            
            if ($compatibility.Compatible) {
                $compatibleComputers += $computer
                Write-Log "$($computer.Name): Compatible (SMB: OK, ADMIN`$: OK)" -Level Success
            }
            else {
                Write-Log "$($computer.Name): $($compatibility.ErrorMessage)" -Level Warning
                $Script:Results.Add([PSCustomObject]@{
                    ComputerName    = $computer.Name
                    OperatingSystem = $computer.OperatingSystem
                    Status          = "Incompatible"
                    ExitCode        = $null
                    Duration        = $null
                    Validated       = $null
                    Message         = $compatibility.ErrorMessage
                })
            }
        }
        Write-Progress -Activity "Testing PSEXEC Compatibility" -Completed
        
        $Script:Stats.CompatibleComputers = $compatibleComputers.Count
        Write-Log "Compatible systems: $($compatibleComputers.Count) of $($reachableComputers.Count)" -Level $(if ($compatibleComputers.Count -eq $reachableComputers.Count) { 'Success' } else { 'Warning' })
    }
    
    if ($compatibleComputers.Count -eq 0) {
        Write-Log "No compatible computers found for deployment" -Level Error
        return
    }
    
    #==========================================================================
    # TestOnly Mode - Generate Readiness Report and Exit
    #==========================================================================
    if ($TestOnly) {
        Write-Phase "READINESS REPORT" "Generating readiness assessment (TestOnly mode)..."
        
        # Add compatible computers to results as "Ready"
        foreach ($computer in $compatibleComputers) {
            $Script:Results.Add([PSCustomObject]@{
                ComputerName    = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                Status          = "Ready"
                ExitCode        = $null
                Duration        = $null
                Validated       = $null
                Message         = "System passed all readiness checks - ready for deployment"
            })
        }
        
        # Update stats for TestOnly mode
        $Script:Stats.SuccessfulDeployments = 0
        $Script:Stats.FailedDeployments = 0
        $Script:Stats.SkippedComputers = $compatibleComputers.Count
        
        # Generate reports
        $htmlReport = New-HTMLReport -OutputPath $OutputPath -TestOnly
        $csvExport = Export-ResultsCSV -OutputPath $OutputPath
        
        Write-Log "HTML Report: $htmlReport" -Level Success
        Write-Log "CSV Export:  $csvExport" -Level Success
        Write-Log "Log File:    $($Script:Config.LogFile)" -Level Success
        
        # Summary
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host " READINESS ASSESSMENT COMPLETE (TestOnly Mode)" -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host ""
        Write-Host "  Total Targets    : $($Script:Stats.TotalComputers)" -ForegroundColor White
        Write-Host "  Reachable        : $($Script:Stats.ReachableComputers)" -ForegroundColor $(if ($Script:Stats.ReachableComputers -eq $Script:Stats.TotalComputers) { 'Green' } else { 'Yellow' })
        Write-Host "  Compatible       : $($Script:Stats.CompatibleComputers)" -ForegroundColor $(if ($Script:Stats.CompatibleComputers -eq $Script:Stats.ReachableComputers) { 'Green' } else { 'Yellow' })
        Write-Host ""
        Write-Host "  Ready for Deploy : $($compatibleComputers.Count)" -ForegroundColor Green
        Write-Host "  Not Ready        : $($Script:Stats.TotalComputers - $compatibleComputers.Count)" -ForegroundColor $(if (($Script:Stats.TotalComputers - $compatibleComputers.Count) -gt 0) { 'Red' } else { 'Gray' })
        Write-Host ""
        
        $readinessPercent = if ($Script:Stats.TotalComputers -gt 0) {
            [math]::Round(($compatibleComputers.Count / $Script:Stats.TotalComputers) * 100, 1)
        } else { 0 }
        Write-Host "  Readiness Rate   : ${readinessPercent}%" -ForegroundColor $(if ($readinessPercent -ge 90) { 'Green' } elseif ($readinessPercent -ge 70) { 'Yellow' } else { 'Red' })
        Write-Host ""
        
        $duration = (Get-Date) - $Script:Stats.StartTime
        Write-Host "  Duration: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor $Script:Config.ConsoleColors.Secondary
        Write-Host ""
        Write-Host "  No changes were made. Run without -TestOnly to deploy." -ForegroundColor Cyan
        Write-Host ""
        
        return @{
            HTMLReport = $htmlReport
            CSVExport  = $csvExport
            LogFile    = $Script:Config.LogFile
            Stats      = $Script:Stats
            Results    = $Script:Results
            ReadyCount = $compatibleComputers.Count
            NotReadyCount = $Script:Stats.TotalComputers - $compatibleComputers.Count
        }
    }
    
    #==========================================================================
    # Pre-Deployment Confirmation
    #==========================================================================
    if (-not $Force -and -not $WhatIfPreference) {
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host " DEPLOYMENT SUMMARY" -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host ""
        Write-Host "  Product        : $($Script:Config.MSIProductName)" -ForegroundColor White
        Write-Host "  Version        : $($Script:Config.MSIProductVersion)" -ForegroundColor White
        Write-Host "  Package        : $($Script:Config.MSIFileName)" -ForegroundColor White
        Write-Host "  Target Systems : $($compatibleComputers.Count)" -ForegroundColor White
        Write-Host "  MSI Arguments  : $MSIArguments" -ForegroundColor White
        Write-Host "  Max Concurrent : $MaxConcurrent" -ForegroundColor White
        Write-Host "  Timeout        : $TimeoutSeconds seconds" -ForegroundColor White
        if ($RetryCount -gt 0) {
            Write-Host "  Retry Count    : $RetryCount" -ForegroundColor White
        }
        Write-Host ""
        
        $confirm = Read-Host "Proceed with deployment? (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Log "Deployment cancelled by user" -Level Warning
            return
        }
    }
    
    #==========================================================================
    # Phase 4: Deployment
    #==========================================================================
    Write-Phase "DEPLOYMENT" "Installing MSI on compatible systems..."
    
    if ($WhatIfPreference) {
        Write-Log "WhatIf mode - showing what would be deployed:" -Level Info
        foreach ($computer in $compatibleComputers) {
            Write-Log "Would deploy to: $($computer.Name)" -Level Info
            $Script:Results.Add([PSCustomObject]@{
                ComputerName    = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                Status          = "Skipped"
                ExitCode        = $null
                Duration        = $null
                Validated       = $null
                Message         = "WhatIf - deployment simulated"
            })
            $Script:Stats.SkippedComputers++
        }
    }
    else {
        $deployProgress = 0
        $msiFileName = [System.IO.Path]::GetFileName($effectiveMSIPath)
        $transformFileName = if ($TransformPath) { [System.IO.Path]::GetFileName($TransformPath) } else { $null }
        
        foreach ($computer in $compatibleComputers) {
            $deployProgress++
            $percentComplete = [math]::Round(($deployProgress / $compatibleComputers.Count) * 100)
            Write-Progress -Activity "Deploying MSI" -Status "$($computer.Name) ($deployProgress of $($compatibleComputers.Count))" -PercentComplete $percentComplete
            
            $hostname = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
            $attemptCount = 0
            $success = $false
            $installResult = $null
            
            while (-not $success -and $attemptCount -le $RetryCount) {
                if ($attemptCount -gt 0) {
                    Write-Log "[$($computer.Name)] Retry attempt $attemptCount of $RetryCount" -Level Warning
                    $Script:Stats.RetryAttempts++
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
                $attemptCount++
                
                # Step 1: Copy MSI (and transform)
                Write-Log "[$($computer.Name)] Copying files to staging location..." -Level Info
                $copyResult = Copy-MSIToRemote -ComputerName $hostname -SourcePath $effectiveMSIPath -TransformPath $TransformPath -StagingPath $StagingPath -Credential $Credential
                
                if (-not $copyResult.Success) {
                    $installResult = [PSCustomObject]@{
                        Success      = $false
                        ErrorMessage = "Failed to copy MSI to remote system"
                        ExitCode     = $null
                        Duration     = $null
                    }
                    continue
                }
                
                # Step 2: Build arguments and execute installation
                $localMSIPath = Join-Path $StagingPath $msiFileName
                $localTransformPath = if ($TransformPath) { Join-Path $StagingPath $transformFileName } else { $null }
                $logPath = Join-Path $StagingPath "msiexec_$($computer.Name).log"
                
                $fullArgs = Build-MSIArguments -MSIPath $localMSIPath -BaseArguments $MSIArguments -TransformPath $localTransformPath -Properties $MSIProperties -LogPath $logPath
                
                $installResult = Invoke-PSExecInstall -PSExecPath $psexec -ComputerName $hostname -MSIPath $localMSIPath -Arguments $fullArgs -Credential $Credential -TimeoutSeconds $TimeoutSeconds
                
                $success = $installResult.Success
            }
            
            # Step 3: Collect logs if requested
            $collectedLog = $null
            if ($CollectLogs -and -not $success) {
                $remoteLogPath = Join-Path $StagingPath "msiexec_$($computer.Name).log"
                $collectedLog = Copy-RemoteLog -ComputerName $hostname -RemoteLogPath $remoteLogPath -LocalOutputPath $OutputPath
                if ($collectedLog) {
                    Write-Log "[$($computer.Name)] Log collected: $([System.IO.Path]::GetFileName($collectedLog))" -Level Info
                }
            }
            
            # Step 4: Validate installation
            $validated = $null
            if ($installResult.Success -and -not $SkipValidation -and $Script:Config.MSIProductCode) {
                Write-Log "[$($computer.Name)] Validating installation..." -Level Info
                $validated = Test-ProductInstalled -ComputerName $hostname -ProductCode $Script:Config.MSIProductCode -ProductName $Script:Config.MSIProductName -Credential $Credential
                if ($validated) {
                    Write-Log "[$($computer.Name)] Product verified in registry" -Level Success
                    $Script:Stats.ValidatedInstalls++
                }
                elseif ($validated -eq $false) {
                    Write-Log "[$($computer.Name)] Product NOT found in registry after install" -Level Warning
                }
            }
            
            # Step 5: Cleanup
            Remove-StagedFiles -ComputerName $hostname -StagingPath $StagingPath -MSIFileName $msiFileName -TransformFileName $transformFileName
            
            # Record result
            $status = if ($installResult.Success) { "Success" } else { "Failed" }
            $message = if ($installResult.Success) { 
                if ($installResult.Output) { $installResult.Output } else { "Installation completed successfully" }
            } else { 
                $installResult.ErrorMessage 
            }
            
            $Script:Results.Add([PSCustomObject]@{
                ComputerName    = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                Status          = $status
                ExitCode        = $installResult.ExitCode
                Duration        = $installResult.Duration
                Validated       = $validated
                Message         = $message
            })
            
            if ($installResult.Success) {
                Write-Log "[$($computer.Name)] Installation successful" -Level Success
                $Script:Stats.SuccessfulDeployments++
            }
            else {
                Write-Log "[$($computer.Name)] Installation failed: $message" -Level Error
                $Script:Stats.FailedDeployments++
            }
        }
        Write-Progress -Activity "Deploying MSI" -Completed
    }
    
    #==========================================================================
    # Phase 5: Reporting
    #==========================================================================
    Write-Phase "REPORTING" "Generating deployment report..."
    
    # Generate reports
    $htmlReport = New-HTMLReport -OutputPath $OutputPath
    $csvExport = Export-ResultsCSV -OutputPath $OutputPath
    
    Write-Log "HTML Report: $htmlReport" -Level Success
    Write-Log "CSV Export:  $csvExport" -Level Success
    Write-Log "Log File:    $($Script:Config.LogFile)" -Level Success
    
    #==========================================================================
    # Summary
    #==========================================================================
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host " DEPLOYMENT COMPLETE" -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ""
    Write-Host "  Product          : $($Script:Config.MSIProductName) v$($Script:Config.MSIProductVersion)" -ForegroundColor White
    Write-Host "  Total Targets    : $($Script:Stats.TotalComputers)" -ForegroundColor White
    Write-Host "  Reachable        : $($Script:Stats.ReachableComputers)" -ForegroundColor Cyan
    Write-Host "  Compatible       : $($Script:Stats.CompatibleComputers)" -ForegroundColor Cyan
    Write-Host "  Successful       : $($Script:Stats.SuccessfulDeployments)" -ForegroundColor Green
    Write-Host "  Failed           : $($Script:Stats.FailedDeployments)" -ForegroundColor $(if ($Script:Stats.FailedDeployments -gt 0) { 'Red' } else { 'Gray' })
    Write-Host "  Skipped          : $($Script:Stats.SkippedComputers)" -ForegroundColor $(if ($Script:Stats.SkippedComputers -gt 0) { 'Yellow' } else { 'Gray' })
    if (-not $SkipValidation) {
        Write-Host "  Validated        : $($Script:Stats.ValidatedInstalls)" -ForegroundColor $(if ($Script:Stats.ValidatedInstalls -eq $Script:Stats.SuccessfulDeployments) { 'Green' } else { 'Yellow' })
    }
    if ($RetryCount -gt 0) {
        Write-Host "  Retry Attempts   : $($Script:Stats.RetryAttempts)" -ForegroundColor Gray
    }
    Write-Host ""
    
    $duration = (Get-Date) - $Script:Stats.StartTime
    Write-Host "  Duration: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ""
    
    return @{
        HTMLReport = $htmlReport
        CSVExport  = $csvExport
        LogFile    = $Script:Config.LogFile
        Stats      = $Script:Stats
        Results    = $Script:Results
    }
}

# Execute
$deploymentResult = Start-Deployment

# Return result object for pipeline use
$deploymentResult
#endregion
