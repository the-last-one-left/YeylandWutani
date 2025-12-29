<#
.SYNOPSIS
    Deploys MSI and EXE packages to domain computers using PSEXEC.
    
.DESCRIPTION
    Yeyland Wutani - Building Better Systems
    
    Enterprise installer deployment tool that queries Active Directory for target
    computers, validates connectivity and PSEXEC compatibility, then performs
    silent installation across accessible systems.
    
    Supports both MSI and EXE installers:
    - MSI: Extracts ProductName, Version, ProductCode, and available properties
    - EXE: Detects installer framework (NSIS, Inno Setup, InstallShield, etc.)
           and determines appropriate silent switches automatically
    
    Auto-Detection:
    - Scans current directory for installer files and prompts for selection
    - Searches for PSExec.exe in current directory and common locations
    - For EXE files, detects framework and suggests silent switches
    
    Deployment Phases:
    1. Installer Analysis - Extract product info / detect framework
    2. AD Query           - Retrieve computer objects from specified OU or domain
    3. Reachability       - Filter to online/responding systems via ping
    4. Compatibility      - Validate PSEXEC prerequisites (ADMIN$, SMB, permissions)
    5. Deployment         - Copy installer and execute silent install via PSEXEC
    6. Validation         - Verify product installation on target systems
    7. Reporting          - Generate HTML report and CSV export
    
    Supported EXE Frameworks (auto-detected):
    - NSIS (Nullsoft)      : /S
    - Inno Setup           : /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
    - InstallShield        : /s /v"/qn /norestart" (Basic MSI) or requires .iss
    - Wise InstallMaster   : /s
    - WiX Burn             : /quiet /norestart
    - InstallAware         : /s
    
    Prerequisites on target systems:
    - TCP Port 445 open (File and Printer Sharing)
    - ADMIN$ administrative share accessible
    - Running account must have local admin rights
    - LanmanServer service running
    
.PARAMETER InstallerPath
    Full path to the MSI or EXE installer file. If omitted, searches current 
    directory for installer files and prompts for selection.
    Alias: -MSIPath, -Path
    
.PARAMETER TransformPath
    Path to MST transform file(s) to apply during MSI installation.
    
.PARAMETER InstallerProperties
    Hashtable of properties to pass to the installer.
    For MSI: @{ INSTALLDIR = "C:\CustomPath"; ALLUSERS = "1" }
    For EXE: Framework-specific, passed as additional arguments
    Alias: -MSIProperties
    
.PARAMETER InstallerArguments
    Override automatic silent switches with custom arguments.
    For MSI: Replaces default "/qn /norestart"
    For EXE: Replaces auto-detected framework switches
    Alias: -MSIArguments, -EXEArguments
    
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
    
.PARAMETER StagingPath
    Remote path to stage installer before execution. Default: C:\Windows\Temp
    
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
    Collect installation logs from remote systems after deployment.
    
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
    
.PARAMETER ShowInstallerInfo
    Display installer information and exit:
    - MSI: Shows all properties from the database
    - EXE: Shows detected framework and suggested silent switches
    Alias: -ShowMSIProperties
    
.PARAMETER WhatIf
    Show what would be deployed without making changes.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\RMMAgent.msi"
    
    Deploy MSI to all domain computers using default settings.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Setup.exe"
    
    Deploy EXE to all domain computers. Auto-detects installer framework
    and uses appropriate silent switches.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1
    
    Auto-detect: Searches current directory for installer files (.msi, .exe)
    and prompts for selection.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Setup.exe" -ShowInstallerInfo
    
    Analyze EXE file to detect framework and show recommended silent switches.
    Does not deploy - useful for discovery before deployment.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Agent.msi" -ShowInstallerInfo
    
    Display all available MSI properties. Useful for discovering what 
    properties can be customized via -InstallerProperties.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Setup.exe" -InstallerArguments "/S /D=C:\CustomPath"
    
    Deploy EXE with custom silent switches (overrides auto-detection).
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\RMMAgent.msi" -InstallerProperties @{ SERVERURL="https://rmm.company.com" }
    
    Deploy MSI with custom properties passed to the installer.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\RMMAgent.msi" -TransformPath "C:\Installers\CustomSettings.mst"
    
    Deploy MSI with a transform file applied.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Setup.exe" -ComputerName "WKS01","WKS02" -Force
    
    Deploy EXE to specific computers without confirmation prompt.
    
.EXAMPLE
    .\Deploy-RMMAgent.ps1 -InstallerPath "C:\Installers\Agent.msi" -TestOnly
    
    Run readiness checks only - no deployment.
    
.NOTES
    Author:         Yeyland Wutani LLC
    Version:        2.1.0
    Requires:       PowerShell 5.1+, Active Directory module (for AD query), PSExec.exe
    
.LINK
    https://github.com/YeylandWutani
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ADQuery')]
param(
    [Parameter(Position = 0)]
    [Alias('MSIPath', 'Path')]
    [ValidateScript({ 
        if ($_ -and (Test-Path $_ -PathType Leaf)) { $true }
        elseif (-not $_) { $true }  # Allow empty when TestOnly
        else { throw "Installer file not found: $_" }
    })]
    [string]$InstallerPath,
    
    [Parameter()]
    [ValidateScript({ 
        if ($_ -and (Test-Path $_ -PathType Leaf)) { $true }
        elseif (-not $_) { $true }
        else { throw "Transform file not found: $_" }
    })]
    [string]$TransformPath,
    
    [Parameter()]
    [Alias('MSIProperties')]
    [hashtable]$InstallerProperties,
    
    [Parameter(ParameterSetName = 'ADQuery')]
    [string]$SearchBase,
    
    [Parameter(ParameterSetName = 'Manual', Mandatory = $true)]
    [string[]]$ComputerName,
    
    [Parameter(ParameterSetName = 'ADQuery')]
    [string]$Filter = "*",
    
    [Parameter(ParameterSetName = 'ADQuery')]
    [switch]$ExcludeServers,
    
    [string]$ExcludePattern,
    
    [Alias('MSIArguments', 'EXEArguments')]
    [string]$InstallerArguments,
    
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
    
    [Parameter(HelpMessage = "Display installer info and exit")]
    [Alias('ShowMSIProperties')]
    [switch]$ShowInstallerInfo
)

#region Configuration
$Script:Config = @{
    Version           = "2.1.0"
    Timestamp         = Get-Date -Format "yyyyMMdd_HHmmss"
    InstallerFileName = $null
    InstallerType     = $null          # 'MSI' or 'EXE'
    ProductName       = $null
    ProductCode       = $null
    ProductVersion    = $null
    Manufacturer      = $null
    EXEFramework      = $null          # NSIS, InnoSetup, InstallShield, etc.
    SilentSwitches    = $null
    LogFile           = $null
    HTMLReport        = $null
    CSVExport         = $null
    
    # Branding - Yeyland Wutani
    Colors            = @{
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
    ConsoleColors     = @{
        Primary   = "DarkYellow"
        Secondary = "Gray"
        Success   = "Green"
        Warning   = "Yellow"
        Error     = "Red"
        Info      = "Cyan"
    }
    
    # EXE Framework definitions
    Frameworks        = @{
        NSIS = @{
            Name           = "NSIS (Nullsoft Scriptable Install System)"
            Signatures     = @("NullsoftInst", "Nullsoft.NSIS", "NSIS Error")
            SilentSwitches = "/S"
            Notes          = "Switch is case-sensitive. /D=PATH sets install directory."
            Reliability    = "High"
        }
        InnoSetup = @{
            Name           = "Inno Setup"
            Signatures     = @("Inno Setup", "InnoSetupVersion", "JRSoftware.InnoSetup")
            SilentSwitches = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"
            Notes          = "/DIR=PATH sets install dir. /LOG=file enables logging."
            Reliability    = "High"
        }
        InstallShieldMSI = @{
            Name           = "InstallShield (Basic MSI)"
            Signatures     = @("InstallShield")
            SecondaryCheck = "MSI"  # Must also contain MSI indicators
            SilentSwitches = '/s /v"/qn /norestart"'
            Notes          = "Wraps an MSI. The /v passes args to msiexec."
            Reliability    = "Medium"
        }
        InstallShieldLegacy = @{
            Name           = "InstallShield (Legacy/InstallScript)"
            Signatures     = @("InstallShield")
            ExcludeCheck   = "MSI"  # Must NOT contain MSI indicators
            SilentSwitches = '/s /f1"response.iss"'
            Notes          = "Requires pre-recorded response file. Create with: setup.exe /r"
            Reliability    = "Low - Manual Setup Required"
        }
        Wise = @{
            Name           = "Wise InstallMaster"
            Signatures     = @("Wise Installation", "WiseMain", "Wise Solutions")
            SilentSwitches = "/s"
            Notes          = "Basic silent switch. May need additional parameters."
            Reliability    = "Medium"
        }
        WiXBurn = @{
            Name           = "WiX Burn Bootstrapper"
            Signatures     = @("WixBurn", "WixBundleManifest", "wix.dll")
            SilentSwitches = "/quiet /norestart"
            Notes          = "/log logfile.txt enables logging. /passive shows progress."
            Reliability    = "High"
        }
        InstallAware = @{
            Name           = "InstallAware"
            Signatures     = @("InstallAware", "INSTALLAWARE")
            SilentSwitches = "/s"
            Notes          = "May support TARGETDIR= for custom path."
            Reliability    = "Medium"
        }
        AdvancedInstaller = @{
            Name           = "Advanced Installer"
            Signatures     = @("Advanced Installer", "Caphyon")
            SilentSwitches = "/i /qn"
            Notes          = "Usually wraps MSI. /exenoui for EXE UI suppression."
            Reliability    = "Medium"
        }
        SFXRAR = @{
            Name           = "Self-Extracting RAR/WinRAR"
            Signatures     = @("WinRAR SFX", "WINRAR.SFX", "Rar!")
            SilentSwitches = "/s"
            Notes          = "Extracts files only. May contain another installer inside."
            Reliability    = "Low - Extraction Only"
        }
        SFX7Zip = @{
            Name           = "Self-Extracting 7-Zip"
            Signatures     = @("7-Zip", "7z SFX", "7zS.sfx")
            SilentSwitches = "-y"
            Notes          = "Extracts files only. May contain another installer inside."
            Reliability    = "Low - Extraction Only"
        }
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
    Write-Host "  Installer Deployment Tool v$($Script:Config.Version)" -ForegroundColor $Script:Config.ConsoleColors.Info
    if ($TestOnly) {
        Write-Host "  Mode: READINESS CHECK ONLY" -ForegroundColor $Script:Config.ConsoleColors.Warning
    }
    elseif ($ShowInstallerInfo) {
        Write-Host "  Mode: INSTALLER ANALYSIS" -ForegroundColor $Script:Config.ConsoleColors.Warning
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

#region Installer Type Detection
function Get-InstallerType {
    <#
    .SYNOPSIS
        Determines if the file is an MSI or EXE installer.
    #>
    param([string]$Path)
    
    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    
    switch ($extension) {
        '.msi' { return 'MSI' }
        '.exe' { return 'EXE' }
        default { return 'Unknown' }
    }
}
#endregion

#region EXE Framework Detection
function Get-EXEFramework {
    <#
    .SYNOPSIS
        Detects the installer framework used to create an EXE file by scanning
        for known signatures in the binary.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $result = [PSCustomObject]@{
        Framework        = "Unknown"
        FrameworkName    = "Unknown Installer Framework"
        SilentSwitches   = $null
        Notes            = "Unable to detect framework. Try common switches: /s, /S, /silent, /quiet"
        Reliability      = "Unknown"
        Signatures       = @()
        FileInfo         = $null
    }
    
    try {
        # Get file version info
        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $result.FileInfo = $fileInfo
        
        # Read file content for signature scanning
        # Read first 2MB and last 512KB for efficiency (signatures usually in headers/resources)
        $fileSize = (Get-Item $Path).Length
        $readSize = [Math]::Min($fileSize, 2MB)
        $tailSize = [Math]::Min($fileSize, 512KB)
        
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        
        # Convert to string for pattern matching (using ASCII for signatures)
        $contentHead = [System.Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min($bytes.Length, $readSize))
        $contentTail = ""
        if ($bytes.Length -gt $tailSize) {
            $contentTail = [System.Text.Encoding]::ASCII.GetString($bytes, $bytes.Length - $tailSize, $tailSize)
        }
        $content = $contentHead + $contentTail
        
        # Also check file description and product name from version info
        $versionStrings = @(
            $fileInfo.FileDescription,
            $fileInfo.ProductName,
            $fileInfo.CompanyName,
            $fileInfo.InternalName,
            $fileInfo.OriginalFilename
        ) -join " "
        
        $allContent = $content + " " + $versionStrings
        
        # Check for MSI indicators (for InstallShield detection)
        $hasMSIIndicators = $allContent -match "Windows Installer|\.msi|MSI \(s\)|msiexec"
        
        # Scan for framework signatures
        $detectedFramework = $null
        $matchedSignatures = @()
        
        foreach ($fwKey in $Script:Config.Frameworks.Keys) {
            $fw = $Script:Config.Frameworks[$fwKey]
            
            foreach ($sig in $fw.Signatures) {
                if ($allContent -match [regex]::Escape($sig)) {
                    $matchedSignatures += $sig
                    
                    # Handle InstallShield variants
                    if ($fwKey -eq 'InstallShieldMSI' -and -not $hasMSIIndicators) {
                        continue  # Skip MSI variant if no MSI indicators
                    }
                    if ($fwKey -eq 'InstallShieldLegacy' -and $hasMSIIndicators) {
                        continue  # Skip legacy if MSI indicators present
                    }
                    
                    $detectedFramework = $fwKey
                    break
                }
            }
            
            if ($detectedFramework) { break }
        }
        
        # Set result based on detection
        if ($detectedFramework) {
            $fw = $Script:Config.Frameworks[$detectedFramework]
            $result.Framework = $detectedFramework
            $result.FrameworkName = $fw.Name
            $result.SilentSwitches = $fw.SilentSwitches
            $result.Notes = $fw.Notes
            $result.Reliability = $fw.Reliability
            $result.Signatures = $matchedSignatures
        }
        else {
            # Check version info for clues
            if ($versionStrings -match "Setup|Install|Installer") {
                $result.Notes = "Generic installer detected. Common silent switches to try: /s, /S, /silent, /quiet, /verysilent, -silent"
            }
        }
    }
    catch {
        $result.Notes = "Error scanning file: $($_.Exception.Message)"
    }
    
    return $result
}

function Show-EXEInfo {
    <#
    .SYNOPSIS
        Displays detected framework and silent switch information for an EXE.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $detection = Get-EXEFramework -Path $Path
    $fileName = [System.IO.Path]::GetFileName($Path)
    $fileSize = [math]::Round((Get-Item $Path).Length / 1MB, 2)
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host " EXE INSTALLER ANALYSIS" -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ""
    
    # File Info
    Write-Host "  FILE INFORMATION" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  ----------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  File Name    : $fileName" -ForegroundColor White
    Write-Host "  File Size    : $fileSize MB" -ForegroundColor White
    
    if ($detection.FileInfo) {
        $fi = $detection.FileInfo
        if ($fi.ProductName) { Write-Host "  Product      : $($fi.ProductName)" -ForegroundColor White }
        if ($fi.FileVersion) { Write-Host "  Version      : $($fi.FileVersion)" -ForegroundColor White }
        if ($fi.CompanyName) { Write-Host "  Vendor       : $($fi.CompanyName)" -ForegroundColor White }
        if ($fi.FileDescription) { Write-Host "  Description  : $($fi.FileDescription)" -ForegroundColor Gray }
    }
    Write-Host ""
    
    # Detection Result
    Write-Host "  FRAMEWORK DETECTION" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  -------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    
    $fwColor = if ($detection.Framework -eq "Unknown") { "Yellow" } else { "Green" }
    Write-Host "  Detected     : $($detection.FrameworkName)" -ForegroundColor $fwColor
    Write-Host "  Reliability  : $($detection.Reliability)" -ForegroundColor $(
        switch ($detection.Reliability) {
            "High" { "Green" }
            "Medium" { "Yellow" }
            default { "Red" }
        }
    )
    
    if ($detection.Signatures.Count -gt 0) {
        Write-Host "  Signatures   : $($detection.Signatures -join ', ')" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Silent Switches
    Write-Host "  SILENT INSTALLATION" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  -------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    
    if ($detection.SilentSwitches) {
        Write-Host "  Switches     : " -ForegroundColor White -NoNewline
        Write-Host "$($detection.SilentSwitches)" -ForegroundColor Cyan
    }
    else {
        Write-Host "  Switches     : Unknown - manual detection required" -ForegroundColor Yellow
    }
    
    Write-Host "  Notes        : $($detection.Notes)" -ForegroundColor Gray
    Write-Host ""
    
    # Example Command
    Write-Host "  DEPLOYMENT COMMAND" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  ------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    
    if ($detection.SilentSwitches) {
        Write-Host "  $fileName $($detection.SilentSwitches)" -ForegroundColor Cyan
    }
    else {
        Write-Host "  Try: $fileName /s" -ForegroundColor Yellow
        Write-Host "  Or:  $fileName /S" -ForegroundColor Yellow
        Write-Host "  Or:  $fileName /silent" -ForegroundColor Yellow
        Write-Host "  Or:  $fileName /quiet" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Common EXE switches reference
    Write-Host "  COMMON EXE SILENT SWITCHES REFERENCE" -ForegroundColor $Script:Config.ConsoleColors.Info
    Write-Host "  ------------------------------------" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host "  NSIS          : /S (case-sensitive)" -ForegroundColor Gray
    Write-Host "  Inno Setup    : /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -ForegroundColor Gray
    Write-Host "  InstallShield : /s /v`"/qn`"" -ForegroundColor Gray
    Write-Host "  Wise          : /s" -ForegroundColor Gray
    Write-Host "  WiX Burn      : /quiet /norestart" -ForegroundColor Gray
    Write-Host "  Generic       : /s, /S, /silent, /quiet, -s, -silent" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ""
    
    return $detection
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

function Find-LocalInstaller {
    <#
    .SYNOPSIS
        Searches current directory for installer files and prompts user to select one.
    #>
    
    $currentDir = (Get-Location).Path
    # Note: -Include requires wildcard in path or -Recurse to work properly
    $installerFiles = Get-ChildItem -Path "$currentDir\*" -Include "*.msi", "*.exe" -File -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -notmatch '^(psexec|cmd|powershell|unins)' }
    
    if (-not $installerFiles -or $installerFiles.Count -eq 0) {
        return $null
    }
    
    if ($installerFiles.Count -eq 1) {
        # Single installer found - show info and prompt to confirm
        $installer = $installerFiles[0]
        $installerType = Get-InstallerType -Path $installer.FullName
        
        Write-Host ""
        Write-Host "  Found installer in current directory:" -ForegroundColor Cyan
        Write-Host "    File: $($installer.Name) ($([math]::Round($installer.Length / 1MB, 2)) MB)" -ForegroundColor White
        Write-Host "    Type: $installerType" -ForegroundColor White
        
        if ($installerType -eq 'MSI') {
            $msiInfo = Get-MSISummaryInfo -MSIPath $installer.FullName
            if ($msiInfo.ProductName) {
                Write-Host "    Product: $($msiInfo.ProductName) v$($msiInfo.ProductVersion)" -ForegroundColor White
                Write-Host "    Vendor:  $($msiInfo.Manufacturer)" -ForegroundColor Gray
            }
        }
        elseif ($installerType -eq 'EXE') {
            $exeInfo = Get-EXEFramework -Path $installer.FullName
            Write-Host "    Framework: $($exeInfo.FrameworkName)" -ForegroundColor White
            if ($exeInfo.FileInfo.ProductName) {
                Write-Host "    Product: $($exeInfo.FileInfo.ProductName)" -ForegroundColor White
            }
        }
        
        Write-Host ""
        $confirm = Read-Host "  Use this installer for deployment? (Y/N)"
        if ($confirm -match '^[Yy]') {
            return $installer.FullName
        }
        return $null
    }
    else {
        # Multiple installers found - prompt to select
        Write-Host ""
        Write-Host "  Found $($installerFiles.Count) installer files in current directory:" -ForegroundColor Cyan
        Write-Host ""
        
        for ($i = 0; $i -lt $installerFiles.Count; $i++) {
            $installer = $installerFiles[$i]
            $installerType = Get-InstallerType -Path $installer.FullName
            $productDisplay = ""
            
            if ($installerType -eq 'MSI') {
                $msiInfo = Get-MSISummaryInfo -MSIPath $installer.FullName
                if ($msiInfo.ProductName) { $productDisplay = " - $($msiInfo.ProductName)" }
            }
            elseif ($installerType -eq 'EXE') {
                $exeInfo = Get-EXEFramework -Path $installer.FullName
                $productDisplay = " - [$($exeInfo.Framework)]"
                if ($exeInfo.FileInfo.ProductName) {
                    $productDisplay = " - $($exeInfo.FileInfo.ProductName) [$($exeInfo.Framework)]"
                }
            }
            
            Write-Host "    [$($i + 1)] [$installerType] $($installer.Name)$productDisplay ($([math]::Round($installer.Length / 1MB, 2)) MB)" -ForegroundColor White
        }
        Write-Host "    [0] None - cancel" -ForegroundColor Gray
        Write-Host ""
        
        $selection = Read-Host "  Select installer to deploy (0-$($installerFiles.Count))"
        
        if ($selection -match '^\d+$') {
            $index = [int]$selection
            if ($index -gt 0 -and $index -le $installerFiles.Count) {
                return $installerFiles[$index - 1].FullName
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

function Build-InstallCommand {
    <#
    .SYNOPSIS
        Constructs the full installation command based on installer type.
    #>
    param(
        [string]$InstallerPath,
        [string]$InstallerType,
        [string]$BaseArguments,
        [string]$TransformPath,
        [hashtable]$Properties,
        [string]$LogPath,
        [string]$EXEFramework
    )
    
    $fileName = [System.IO.Path]::GetFileName($InstallerPath)
    
    if ($InstallerType -eq 'MSI') {
        # MSI installation via msiexec
        $args = @("/i `"$InstallerPath`"")
        
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
        
        # Add base arguments (default: /qn /norestart)
        $effectiveArgs = if ($BaseArguments) { $BaseArguments } else { "/qn /norestart" }
        $args += $effectiveArgs
        
        # Add logging
        if ($LogPath) {
            $args += "/l*v `"$LogPath`""
        }
        
        return @{
            Executable = "msiexec.exe"
            Arguments  = $args -join ' '
            FullCommand = "msiexec.exe $($args -join ' ')"
        }
    }
    else {
        # EXE direct execution
        $args = @()
        
        # Use provided arguments or auto-detected switches
        if ($BaseArguments) {
            $args += $BaseArguments
        }
        elseif ($Script:Config.SilentSwitches) {
            $args += $Script:Config.SilentSwitches
        }
        
        # Add custom properties (framework-specific handling)
        if ($Properties -and $Properties.Count -gt 0) {
            foreach ($key in $Properties.Keys) {
                # Different frameworks use different property syntax
                switch ($EXEFramework) {
                    'NSIS' { $args += "/$key=$($Properties[$key])" }
                    'InnoSetup' { $args += "/$key=`"$($Properties[$key])`"" }
                    default { $args += "$key=$($Properties[$key])" }
                }
            }
        }
        
        return @{
            Executable = "`"$InstallerPath`""
            Arguments  = $args -join ' '
            FullCommand = "`"$InstallerPath`" $($args -join ' ')"
        }
    }
}

function Copy-InstallerToRemote {
    <#
    .SYNOPSIS
        Copies installer file (and transform if specified) to remote computer staging location.
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
        
        # Copy installer
        $installerDest = Join-Path $remotePath ([System.IO.Path]::GetFileName($SourcePath))
        Copy-Item -Path $SourcePath -Destination $installerDest -Force -ErrorAction Stop
        
        # Copy transform if specified
        $transformDest = $null
        if ($TransformPath -and (Test-Path $TransformPath)) {
            $transformDest = Join-Path $remotePath ([System.IO.Path]::GetFileName($TransformPath))
            Copy-Item -Path $TransformPath -Destination $transformDest -Force -ErrorAction Stop
        }
        
        # Verify copy
        if (Test-Path $installerDest) {
            return @{
                InstallerPath = $installerDest
                LocalPath     = Join-Path $StagingPath ([System.IO.Path]::GetFileName($SourcePath))
                TransformPath = $transformDest
                LocalTransform = if ($TransformPath) { Join-Path $StagingPath ([System.IO.Path]::GetFileName($TransformPath)) } else { $null }
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
        Executes installation via PSEXEC.
    #>
    param(
        [string]$PSExecPath,
        [string]$ComputerName,
        [string]$Command,
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
    
    # Add command
    $psexecArgs += $Command
    
    try {
        Write-Log "[$ComputerName] Executing: $Command" -Level Info
        
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
            
            # Interpret exit codes
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
                    $result.ErrorMessage = "Package could not be opened (1619)"
                }
                1638 {
                    $result.ErrorMessage = "Another version already installed (1638)"
                }
                default {
                    if ($result.ExitCode -eq 0 -or ($result.ExitCode -ge 0 -and $result.ExitCode -le 3)) {
                        # Some EXE installers use 0-3 as success
                        $result.Success = $true
                    }
                    else {
                        $result.ErrorMessage = "Installation failed with exit code: $($result.ExitCode)"
                    }
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
        Uses registry query via remote registry for better compatibility than WinRM.
    #>
    param(
        [string]$ComputerName,
        [string]$ProductCode,
        [string]$ProductName,
        [PSCredential]$Credential
    )
    
    # Determine if this is the local computer
    $localNames = @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '.')
    $isLocal = $localNames -contains $ComputerName -or $ComputerName -eq [System.Net.Dns]::GetHostName()
    
    $checkRegistry = {
        param($ProductCode, $ProductName)
        
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        foreach ($path in $uninstallPaths) {
            if (Test-Path $path) {
                $found = Get-ChildItem $path -ErrorAction SilentlyContinue | 
                    Get-ItemProperty -ErrorAction SilentlyContinue | 
                    Where-Object {
                        $_.PSChildName -eq $ProductCode -or
                        $_.DisplayName -like "*$ProductName*"
                    }
                if ($found) { return $true }
            }
        }
        return $false
    }
    
    try {
        if ($isLocal) {
            # Local check - run directly
            $installed = & $checkRegistry $ProductCode $ProductName
            return $installed
        }
        else {
            # Remote check - try remote registry first (more reliable than WinRM)
            $regPaths = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            
            foreach ($regPath in $regPaths) {
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                    $uninstallKey = $reg.OpenSubKey($regPath)
                    
                    if ($uninstallKey) {
                        foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                            # Check ProductCode match
                            if ($subKeyName -eq $ProductCode) {
                                $reg.Close()
                                return $true
                            }
                            
                            # Check DisplayName match
                            $subKey = $uninstallKey.OpenSubKey($subKeyName)
                            if ($subKey) {
                                $displayName = $subKey.GetValue('DisplayName')
                                if ($displayName -and $displayName -like "*$ProductName*") {
                                    $subKey.Close()
                                    $uninstallKey.Close()
                                    $reg.Close()
                                    return $true
                                }
                                $subKey.Close()
                            }
                        }
                        $uninstallKey.Close()
                    }
                    $reg.Close()
                }
                catch {
                    # Remote registry access failed, continue to next path or return null
                }
            }
            return $false
        }
    }
    catch {
        Write-Log "[$ComputerName] Validation check failed: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Copy-RemoteLog {
    <#
    .SYNOPSIS
        Copies the installation log from remote system back to local output folder.
    #>
    param(
        [string]$ComputerName,
        [string]$RemoteLogPath,
        [string]$LocalOutputPath
    )
    
    try {
        $remotePath = "\\$ComputerName\$($RemoteLogPath.Replace(':', '$'))"
        if (Test-Path $remotePath) {
            $localLogPath = Join-Path $LocalOutputPath "install_$ComputerName`_$($Script:Config.Timestamp).log"
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
        Cleans up installer and related files from remote staging location.
    #>
    param(
        [string]$ComputerName,
        [string]$StagingPath,
        [string]$InstallerFileName,
        [string]$TransformFileName
    )
    
    try {
        $remotePath = "\\$ComputerName\$($StagingPath.Replace(':', '$'))"
        
        # Remove installer
        $installerPath = Join-Path $remotePath $InstallerFileName
        if (Test-Path $installerPath) {
            Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
        }
        
        # Remove Transform
        if ($TransformFileName) {
            $transformPath = Join-Path $remotePath $TransformFileName
            if (Test-Path $transformPath) {
                Remove-Item -Path $transformPath -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Remove log
        $logPattern = Join-Path $remotePath "install_*.log"
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
        $reportTitle = "Deployment Readiness Report"
        $filePrefix = "Deployment_Readiness"
    }
    else {
        $successRate = if ($Script:Stats.TotalComputers -gt 0) {
            [math]::Round(($Script:Stats.SuccessfulDeployments / $Script:Stats.TotalComputers) * 100, 1)
        } else { 0 }
        $reportTitle = "Installer Deployment Report"
        $filePrefix = "Deployment"
    }
    
    # Product info for header
    $productInfo = if ($Script:Config.ProductName) {
        "$($Script:Config.ProductName) v$($Script:Config.ProductVersion)"
    } else {
        $Script:Config.InstallerFileName
    }
    
    $installerTypeInfo = "[$($Script:Config.InstallerType)]"
    if ($Script:Config.InstallerType -eq 'EXE' -and $Script:Config.EXEFramework) {
        $installerTypeInfo += " $($Script:Config.EXEFramework)"
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
        .header {
            background: linear-gradient(135deg, $($c.Surface) 0%, $($c.Background) 100%);
            border-left: 4px solid $($c.Primary);
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        .header h1 { color: $($c.Primary); font-size: 28px; margin-bottom: 5px; }
        .header .tagline { color: $($c.Secondary); font-size: 14px; letter-spacing: 2px; }
        .header .meta { margin-top: 15px; color: $($c.Secondary); font-size: 13px; }
        .header .product-info { margin-top: 10px; padding: 10px; background: rgba(255,102,0,0.1); border-radius: 4px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: $($c.Surface); padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card .value { font-size: 36px; font-weight: bold; margin-bottom: 5px; }
        .stat-card .label { color: $($c.Secondary); font-size: 13px; text-transform: uppercase; }
        .stat-card.success .value { color: $($c.Success); }
        .stat-card.warning .value { color: $($c.Warning); }
        .stat-card.error .value { color: $($c.Error); }
        .stat-card.info .value { color: $($c.Primary); }
        .progress-container { background: $($c.Surface); padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .progress-bar { background: $($c.Background); height: 30px; border-radius: 4px; overflow: hidden; margin-top: 10px; }
        .progress-fill { height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
        .progress-fill.success { background: $($c.Success); }
        .results-section { background: $($c.Surface); border-radius: 8px; overflow: hidden; margin-bottom: 30px; }
        .results-section h2 { padding: 20px; border-bottom: 1px solid $($c.Background); color: $($c.Primary); }
        table { width: 100%; border-collapse: collapse; }
        th { background: $($c.Background); padding: 12px 15px; text-align: left; color: $($c.Secondary); font-size: 12px; text-transform: uppercase; }
        td { padding: 12px 15px; border-bottom: 1px solid $($c.Background); }
        tr:hover { background: rgba(255,255,255,0.02); }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge-success { background: rgba(16, 185, 129, 0.2); color: $($c.Success); }
        .badge-error { background: rgba(239, 68, 68, 0.2); color: $($c.Error); }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: $($c.Warning); }
        .badge-info { background: rgba(255, 102, 0, 0.2); color: $($c.Primary); }
        .footer { text-align: center; padding: 20px; color: $($c.Secondary); font-size: 12px; }
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
                <strong>Package:</strong> $($Script:Config.InstallerFileName) $installerTypeInfo$(if ($Script:Config.ProductCode) { "<br><strong>Product Code:</strong> $($Script:Config.ProductCode)" })$(if ($Script:Config.SilentSwitches) { "<br><strong>Silent Switches:</strong> $($Script:Config.SilentSwitches)" })
            </div>
            <div class="meta">
                <strong>Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")<br>
                <strong>Duration:</strong> $([math]::Round($duration.TotalMinutes, 1)) minutes$(if ($TestOnly) { '<br><strong style="color: ' + $c.Warning + ';">Mode: Readiness Check Only (No Deployment)</strong>' })
            </div>
        </div>
        
        <div class="stats-grid">
$(if ($TestOnly) {
@"
            <div class="stat-card info"><div class="value">$($Script:Stats.TotalComputers)</div><div class="label">Total Targets</div></div>
            <div class="stat-card info"><div class="value">$($Script:Stats.ReachableComputers)</div><div class="label">Reachable</div></div>
            <div class="stat-card success"><div class="value">$readyCount</div><div class="label">Ready</div></div>
            <div class="stat-card error"><div class="value">$notReadyCount</div><div class="label">Not Ready</div></div>
"@
} else {
@"
            <div class="stat-card info"><div class="value">$($Script:Stats.TotalComputers)</div><div class="label">Total Targets</div></div>
            <div class="stat-card info"><div class="value">$($Script:Stats.ReachableComputers)</div><div class="label">Reachable</div></div>
            <div class="stat-card info"><div class="value">$($Script:Stats.CompatibleComputers)</div><div class="label">Compatible</div></div>
            <div class="stat-card success"><div class="value">$($Script:Stats.SuccessfulDeployments)</div><div class="label">Successful</div></div>
            <div class="stat-card error"><div class="value">$($Script:Stats.FailedDeployments)</div><div class="label">Failed</div></div>
            <div class="stat-card warning"><div class="value">$($Script:Stats.SkippedComputers)</div><div class="label">Skipped</div></div>
"@
})
        </div>
        
        <div class="progress-container">
$(if ($TestOnly) {
            "<strong>Deployment Readiness: ${readinessRate}%</strong><div class='progress-bar'><div class='progress-fill success' style='width: ${readinessRate}%'>${readinessRate}%</div></div>"
} else {
            "<strong>Deployment Success Rate: ${successRate}%</strong><div class='progress-bar'><div class='progress-fill success' style='width: ${successRate}%'>${successRate}%</div></div>"
})
        </div>
        
        <div class="results-section">
            <h2>$(if ($TestOnly) { 'Readiness Assessment Results' } else { 'Deployment Results' })</h2>
            <table>
                <thead><tr><th>Computer</th><th>Operating System</th><th>Status</th><th>Exit Code</th><th>Validated</th><th>Duration</th><th>Details</th></tr></thead>
                <tbody>
"@

    foreach ($result in $Script:Results) {
        $statusBadge = switch ($result.Status) {
            'Success' { '<span class="badge badge-success">Success</span>' }
            'Ready' { '<span class="badge badge-success">Ready</span>' }
            'Unreachable' { '<span class="badge badge-warning">Unreachable</span>' }
            'Incompatible' { '<span class="badge badge-warning">Incompatible</span>' }
            'Failed' { '<span class="badge badge-error">Failed</span>' }
            'Skipped' { '<span class="badge badge-info">Skipped</span>' }
            default { '<span class="badge badge-info">Unknown</span>' }
        }
        $durationStr = if ($result.Duration) { "$([math]::Round($result.Duration.TotalSeconds, 1))s" } else { "-" }
        $validatedStr = switch ($result.Validated) { $true { '<span class="badge badge-success">Yes</span>' }; $false { '<span class="badge badge-error">No</span>' }; default { '-' } }
        
        $html += "<tr><td><strong>$($result.ComputerName)</strong></td><td>$($result.OperatingSystem)</td><td>$statusBadge</td><td>$($result.ExitCode)</td><td>$validatedStr</td><td>$durationStr</td><td>$($result.Message)</td></tr>`n"
    }

    $html += @"
                </tbody>
            </table>
        </div>
        <div class="footer">
            <p>Generated by <a href="https://github.com/YeylandWutani">Yeyland Wutani</a> Installer Deployment Tool v$($Script:Config.Version)</p>
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
    param([string]$OutputPath)
    
    $csvPath = Join-Path $OutputPath "Deployment_$($Script:Config.Timestamp).csv"
    $Script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Force
    
    return $csvPath
}
#endregion

#region Main Execution
function Start-Deployment {
    Show-Banner
    
    #==========================================================================
    # ShowInstallerInfo Mode - Just display info and exit
    #==========================================================================
    if ($ShowInstallerInfo) {
        if (-not $InstallerPath) {
            $InstallerPath = Find-LocalInstaller
        }
        
        if (-not $InstallerPath -or -not (Test-Path $InstallerPath)) {
            Write-Log "Please specify an installer file with -InstallerPath" -Level Error
            return
        }
        
        $installerType = Get-InstallerType -Path $InstallerPath
        
        if ($installerType -eq 'MSI') {
            Show-MSIPropertyReport -MSIPath $InstallerPath
        }
        elseif ($installerType -eq 'EXE') {
            Show-EXEInfo -Path $InstallerPath
        }
        else {
            Write-Log "Unknown installer type: $InstallerPath" -Level Error
        }
        return
    }
    
    # Resolve installer path
    if (-not $InstallerPath) {
        if (-not $TestOnly) {
            Write-Log "No installer path specified - checking current directory..." -Level Info
            $InstallerPath = Find-LocalInstaller
            
            if (-not $InstallerPath) {
                Write-Log "No installer file found or selected" -Level Error
                Write-Host ""
                Write-Host "  Usage:" -ForegroundColor Yellow
                Write-Host "    Readiness check:  .\Deploy-RMMAgent.ps1 -TestOnly" -ForegroundColor Gray
                Write-Host "    Analyze MSI:      .\Deploy-RMMAgent.ps1 -InstallerPath 'App.msi' -ShowInstallerInfo" -ForegroundColor Gray
                Write-Host "    Analyze EXE:      .\Deploy-RMMAgent.ps1 -InstallerPath 'Setup.exe' -ShowInstallerInfo" -ForegroundColor Gray
                Write-Host "    Deploy:           .\Deploy-RMMAgent.ps1 -InstallerPath 'C:\Path\To\Installer'" -ForegroundColor Gray
                Write-Host ""
                return
            }
        }
    }
    
    # Set script-level path
    $script:InstallerPath = $InstallerPath
    
    # Determine installer type and gather info
    if ($InstallerPath -and (Test-Path $InstallerPath)) {
        $Script:Config.InstallerType = Get-InstallerType -Path $InstallerPath
        $Script:Config.InstallerFileName = [System.IO.Path]::GetFileName($InstallerPath)
        
        if ($Script:Config.InstallerType -eq 'MSI') {
            $msiInfo = Get-MSISummaryInfo -MSIPath $InstallerPath
            $Script:Config.ProductName = $msiInfo.ProductName
            $Script:Config.ProductVersion = $msiInfo.ProductVersion
            $Script:Config.ProductCode = $msiInfo.ProductCode
            $Script:Config.Manufacturer = $msiInfo.Manufacturer
            $Script:Config.SilentSwitches = if ($InstallerArguments) { $InstallerArguments } else { "/qn /norestart" }
        }
        elseif ($Script:Config.InstallerType -eq 'EXE') {
            $exeInfo = Get-EXEFramework -Path $InstallerPath
            $Script:Config.EXEFramework = $exeInfo.Framework
            $Script:Config.ProductName = $exeInfo.FileInfo.ProductName
            $Script:Config.ProductVersion = $exeInfo.FileInfo.FileVersion
            $Script:Config.Manufacturer = $exeInfo.FileInfo.CompanyName
            $Script:Config.SilentSwitches = if ($InstallerArguments) { $InstallerArguments } else { $exeInfo.SilentSwitches }
            
            # Warn if unknown framework
            if ($exeInfo.Framework -eq "Unknown" -and -not $InstallerArguments) {
                Write-Log "Unknown EXE framework detected" -Level Warning
                Write-Host ""
                Write-Host "  Unable to auto-detect installer framework." -ForegroundColor Yellow
                Write-Host "  Run with -ShowInstallerInfo for analysis, or provide -InstallerArguments manually." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  Common silent switches to try:" -ForegroundColor Cyan
                Write-Host "    /s, /S, /silent, /quiet, /verysilent" -ForegroundColor Gray
                Write-Host ""
                
                $customArgs = Read-Host "  Enter silent switches (or press Enter to cancel)"
                if ($customArgs) {
                    $Script:Config.SilentSwitches = $customArgs
                }
                else {
                    Write-Log "Deployment cancelled - no silent switches provided" -Level Warning
                    return
                }
            }
        }
    }
    else {
        $Script:Config.InstallerFileName = "(Readiness Check Only)"
    }
    
    # Initialize output files
    $Script:Config.LogFile = Join-Path $OutputPath "Deployment_$($Script:Config.Timestamp).log"
    
    if ($TestOnly) {
        Write-Log "Starting Deployment Readiness Check" -Level Info
    }
    else {
        Write-Log "Starting Installer Deployment" -Level Info
        Write-Log "Package: $($Script:Config.InstallerFileName) [$($Script:Config.InstallerType)]" -Level Info
        if ($Script:Config.ProductName) {
            Write-Log "Product: $($Script:Config.ProductName) v$($Script:Config.ProductVersion)" -Level Info
        }
        if ($Script:Config.InstallerType -eq 'EXE') {
            Write-Log "Framework: $($Script:Config.EXEFramework)" -Level Info
        }
        Write-Log "Silent Switches: $($Script:Config.SilentSwitches)" -Level Info
    }
    
    #==========================================================================
    # Phase 0: Prerequisites
    #==========================================================================
    Write-Phase "PREREQUISITES" "Validating requirements..."
    
    $psexec = $null
    
    if (-not $TestOnly) {
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
        
        $installerFileInfo = Get-Item $InstallerPath
        Write-Log "Installer: $($installerFileInfo.Name) ($([math]::Round($installerFileInfo.Length / 1MB, 2)) MB)" -Level Info
    }
    else {
        Write-Log "TestOnly mode - skipping PSExec and installer validation" -Level Info
    }
    
    #==========================================================================
    # Phase 1: Build Target List
    #==========================================================================
    Write-Phase "TARGET DISCOVERY" "Building list of deployment targets..."
    
    $computers = @()
    
    if ($PSCmdlet.ParameterSetName -eq 'Manual') {
        Write-Log "Using manually specified computers: $($ComputerName.Count) system(s)" -Level Info
        $computers = @($ComputerName | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_
                DNSHostName     = $_
                OperatingSystem = "Unknown"
            }
        })
    }
    else {
        $adComputers = Get-ADComputersFromQuery -SearchBase $SearchBase -ADFilter $Filter -ExcludeServers:$ExcludeServers
        if (-not $adComputers) {
            Write-Log "No computers found or AD query failed" -Level Error
            return
        }
        $computers = @($adComputers)
    }
    
    if ($ExcludePattern) {
        $preCount = $computers.Count
        $computers = @($computers | Where-Object { $_.Name -notmatch $ExcludePattern })
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
            $percentComplete = if ($computers.Count -gt 0) { [math]::Round(($reachCheckProgress / $computers.Count) * 100) } else { 0 }
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
            $percentComplete = if ($reachableComputers.Count -gt 0) { [math]::Round(($compatCheckProgress / $reachableComputers.Count) * 100) } else { 0 }
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
        
        $Script:Stats.SuccessfulDeployments = 0
        $Script:Stats.FailedDeployments = 0
        $Script:Stats.SkippedComputers = $compatibleComputers.Count
        
        $htmlReport = New-HTMLReport -OutputPath $OutputPath -TestOnly
        $csvExport = Export-ResultsCSV -OutputPath $OutputPath
        
        Write-Log "HTML Report: $htmlReport" -Level Success
        Write-Log "CSV Export:  $csvExport" -Level Success
        Write-Log "Log File:    $($Script:Config.LogFile)" -Level Success
        
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host " READINESS ASSESSMENT COMPLETE (TestOnly Mode)" -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
        Write-Host ""
        Write-Host "  Total Targets    : $($Script:Stats.TotalComputers)" -ForegroundColor White
        Write-Host "  Reachable        : $($Script:Stats.ReachableComputers)" -ForegroundColor $(if ($Script:Stats.ReachableComputers -eq $Script:Stats.TotalComputers) { 'Green' } else { 'Yellow' })
        Write-Host "  Compatible       : $($Script:Stats.CompatibleComputers)" -ForegroundColor $(if ($Script:Stats.CompatibleComputers -eq $Script:Stats.ReachableComputers) { 'Green' } else { 'Yellow' })
        Write-Host "  Ready for Deploy : $($compatibleComputers.Count)" -ForegroundColor Green
        Write-Host "  Not Ready        : $($Script:Stats.TotalComputers - $compatibleComputers.Count)" -ForegroundColor $(if (($Script:Stats.TotalComputers - $compatibleComputers.Count) -gt 0) { 'Red' } else { 'Gray' })
        Write-Host ""
        
        $readinessPercent = if ($Script:Stats.TotalComputers -gt 0) { [math]::Round(($compatibleComputers.Count / $Script:Stats.TotalComputers) * 100, 1) } else { 0 }
        Write-Host "  Readiness Rate   : ${readinessPercent}%" -ForegroundColor $(if ($readinessPercent -ge 90) { 'Green' } elseif ($readinessPercent -ge 70) { 'Yellow' } else { 'Red' })
        Write-Host ""
        
        $duration = (Get-Date) - $Script:Stats.StartTime
        Write-Host "  Duration: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor $Script:Config.ConsoleColors.Secondary
        Write-Host "  No changes were made. Run without -TestOnly to deploy." -ForegroundColor Cyan
        Write-Host ""
        
        return @{ HTMLReport = $htmlReport; CSVExport = $csvExport; LogFile = $Script:Config.LogFile; Stats = $Script:Stats; Results = $Script:Results }
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
        Write-Host "  Product        : $($Script:Config.ProductName)" -ForegroundColor White
        Write-Host "  Version        : $($Script:Config.ProductVersion)" -ForegroundColor White
        Write-Host "  Package        : $($Script:Config.InstallerFileName)" -ForegroundColor White
        Write-Host "  Type           : $($Script:Config.InstallerType)$(if ($Script:Config.EXEFramework) { " ($($Script:Config.EXEFramework))" })" -ForegroundColor White
        Write-Host "  Silent Args    : $($Script:Config.SilentSwitches)" -ForegroundColor Cyan
        Write-Host "  Target Systems : $($compatibleComputers.Count)" -ForegroundColor White
        Write-Host "  Max Concurrent : $MaxConcurrent" -ForegroundColor White
        Write-Host "  Timeout        : $TimeoutSeconds seconds" -ForegroundColor White
        if ($RetryCount -gt 0) { Write-Host "  Retry Count    : $RetryCount" -ForegroundColor White }
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
    Write-Phase "DEPLOYMENT" "Installing on compatible systems..."
    
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
        $installerFileName = [System.IO.Path]::GetFileName($InstallerPath)
        $transformFileName = if ($TransformPath) { [System.IO.Path]::GetFileName($TransformPath) } else { $null }
        
        foreach ($computer in $compatibleComputers) {
            $deployProgress++
            $percentComplete = if ($compatibleComputers.Count -gt 0) { [math]::Round(($deployProgress / $compatibleComputers.Count) * 100) } else { 0 }
            Write-Progress -Activity "Deploying Installer" -Status "$($computer.Name) ($deployProgress of $($compatibleComputers.Count))" -PercentComplete $percentComplete
            
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
                
                # Copy installer
                Write-Log "[$($computer.Name)] Copying files to staging location..." -Level Info
                $copyResult = Copy-InstallerToRemote -ComputerName $hostname -SourcePath $InstallerPath -TransformPath $TransformPath -StagingPath $StagingPath -Credential $Credential
                
                if (-not $copyResult.Success) {
                    $installResult = [PSCustomObject]@{ Success = $false; ErrorMessage = "Failed to copy installer to remote system"; ExitCode = $null; Duration = $null }
                    continue
                }
                
                # Build and execute install command
                $logPath = Join-Path $StagingPath "install_$($computer.Name).log"
                $cmdInfo = Build-InstallCommand -InstallerPath $copyResult.LocalPath -InstallerType $Script:Config.InstallerType -BaseArguments $Script:Config.SilentSwitches -TransformPath $copyResult.LocalTransform -Properties $InstallerProperties -LogPath $logPath -EXEFramework $Script:Config.EXEFramework
                
                $installResult = Invoke-PSExecInstall -PSExecPath $psexec -ComputerName $hostname -Command $cmdInfo.FullCommand -Credential $Credential -TimeoutSeconds $TimeoutSeconds
                
                $success = $installResult.Success
            }
            
            # Collect logs if requested
            if ($CollectLogs -and -not $success) {
                $remoteLogPath = Join-Path $StagingPath "install_$($computer.Name).log"
                Copy-RemoteLog -ComputerName $hostname -RemoteLogPath $remoteLogPath -LocalOutputPath $OutputPath | Out-Null
            }
            
            # Validate installation
            $validated = $null
            if ($installResult.Success -and -not $SkipValidation -and ($Script:Config.ProductCode -or $Script:Config.ProductName)) {
                Write-Log "[$($computer.Name)] Validating installation..." -Level Info
                $validated = Test-ProductInstalled -ComputerName $hostname -ProductCode $Script:Config.ProductCode -ProductName $Script:Config.ProductName -Credential $Credential
                if ($validated) {
                    Write-Log "[$($computer.Name)] Product verified in registry" -Level Success
                    $Script:Stats.ValidatedInstalls++
                }
                elseif ($validated -eq $false) {
                    Write-Log "[$($computer.Name)] Product NOT found in registry after install" -Level Warning
                }
            }
            
            # Cleanup
            Remove-StagedFiles -ComputerName $hostname -StagingPath $StagingPath -InstallerFileName $installerFileName -TransformFileName $transformFileName
            
            # Record result
            $status = if ($installResult.Success) { "Success" } else { "Failed" }
            $message = if ($installResult.Success) { if ($installResult.Output) { $installResult.Output } else { "Installation completed successfully" } } else { $installResult.ErrorMessage }
            
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
        Write-Progress -Activity "Deploying Installer" -Completed
    }
    
    #==========================================================================
    # Phase 5: Reporting
    #==========================================================================
    Write-Phase "REPORTING" "Generating deployment report..."
    
    $htmlReport = New-HTMLReport -OutputPath $OutputPath
    $csvExport = Export-ResultsCSV -OutputPath $OutputPath
    
    Write-Log "HTML Report: $htmlReport" -Level Success
    Write-Log "CSV Export:  $csvExport" -Level Success
    Write-Log "Log File:    $($Script:Config.LogFile)" -Level Success
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host " DEPLOYMENT COMPLETE" -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.ConsoleColors.Primary
    Write-Host ""
    Write-Host "  Product          : $($Script:Config.ProductName) v$($Script:Config.ProductVersion)" -ForegroundColor White
    Write-Host "  Installer Type   : $($Script:Config.InstallerType)$(if ($Script:Config.EXEFramework -and $Script:Config.EXEFramework -ne 'Unknown') { " ($($Script:Config.EXEFramework))" })" -ForegroundColor White
    Write-Host "  Total Targets    : $($Script:Stats.TotalComputers)" -ForegroundColor White
    Write-Host "  Reachable        : $($Script:Stats.ReachableComputers)" -ForegroundColor Cyan
    Write-Host "  Compatible       : $($Script:Stats.CompatibleComputers)" -ForegroundColor Cyan
    Write-Host "  Successful       : $($Script:Stats.SuccessfulDeployments)" -ForegroundColor Green
    Write-Host "  Failed           : $($Script:Stats.FailedDeployments)" -ForegroundColor $(if ($Script:Stats.FailedDeployments -gt 0) { 'Red' } else { 'Gray' })
    Write-Host "  Skipped          : $($Script:Stats.SkippedComputers)" -ForegroundColor $(if ($Script:Stats.SkippedComputers -gt 0) { 'Yellow' } else { 'Gray' })
    if (-not $SkipValidation) {
        Write-Host "  Validated        : $($Script:Stats.ValidatedInstalls)" -ForegroundColor $(if ($Script:Stats.ValidatedInstalls -eq $Script:Stats.SuccessfulDeployments) { 'Green' } else { 'Yellow' })
    }
    if ($RetryCount -gt 0) { Write-Host "  Retry Attempts   : $($Script:Stats.RetryAttempts)" -ForegroundColor Gray }
    Write-Host ""
    
    $duration = (Get-Date) - $Script:Stats.StartTime
    Write-Host "  Duration: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor $Script:Config.ConsoleColors.Secondary
    Write-Host ""
    
    return @{ HTMLReport = $htmlReport; CSVExport = $csvExport; LogFile = $Script:Config.LogFile; Stats = $Script:Stats; Results = $Script:Results }
}

# Execute
$deploymentResult = Start-Deployment
$deploymentResult
#endregion
