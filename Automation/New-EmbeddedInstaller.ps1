<#
.SYNOPSIS
    Creates self-contained PowerShell deployment scripts with embedded installers.

.DESCRIPTION
    Encodes an installer (EXE/MSI) into Base64 and generates a standalone PowerShell
    script that can be deployed through RMM tools without requiring file server access.
    
    The generated script:
    - Decodes the embedded binary at runtime
    - Writes to a temp location
    - Executes with specified silent install arguments
    - Cleans up after installation
    - Returns proper exit codes for RMM status tracking
    
    EXE Framework Auto-Detection:
    - NSIS (Nullsoft)      : /S (case-sensitive)
    - Inno Setup           : /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
    - InstallShield        : /s /v"/qn /norestart"
    - Wise InstallMaster   : /s
    - WiX Burn             : /quiet /norestart
    - InstallAware         : /s
    
    Ideal for RMM deployments where you can push scripts but not files directly.

.PARAMETER InstallerPath
    Path to the installer file (EXE or MSI) to embed.

.PARAMETER OutputPath
    Path for the generated PowerShell deployment script.
    Defaults to "Deploy-[InstallerName].ps1" in current directory.

.PARAMETER Arguments
    Silent install arguments. If not specified, attempts to detect framework
    for EXE files or uses /qn /norestart for MSI files.

.PARAMETER Description
    Optional description to include in the generated script header.

.PARAMETER PreScript
    Optional PowerShell code to run BEFORE installation.

.PARAMETER PostScript
    Optional PowerShell code to run AFTER successful installation.

.PARAMETER KeepInstaller
    If specified, the decoded installer is not deleted after execution.

.PARAMETER Compress
    Compress the binary before Base64 encoding to reduce script size.
    Requires .NET 4.5+ on target systems for decompression.

.PARAMETER ShowInstallerInfo
    Analyze the installer and display detected framework info without generating script.

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\Agent.msi"
    
    Creates Deploy-Agent.ps1 with embedded MSI and default /qn arguments.

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\WG-MVPN-SSL_12_11_5.exe"
    
    Auto-detects NSIS framework and uses /S switch.

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\Setup.exe" -ShowInstallerInfo
    
    Analyzes the EXE and shows detected framework and silent switches.

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\Setup.exe" -Arguments "/S /NORESTART" -OutputPath ".\Deploy-App.ps1"
    
    Creates Deploy-App.ps1 with custom silent arguments (overrides detection).

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\BigApp.msi" -Compress -Description "Deploys BigApp v2.1"
    
    Creates compressed embedded script with description.

.NOTES
    Author:     Yeyland Wutani LLC
    Version:    1.1.0
    Purpose:    RMM deployment automation
    
    Size Considerations:
    - Base64 encoding increases file size by ~33%
    - Compression can reduce size by 40-60% for some installers
    - Check your RMM's script size limits before deployment
    
    Common RMM Script Limits:
    - Datto RMM: ~1MB script size
    - ConnectWise Automate: ~16MB
    - NinjaRMM: ~5MB
    - Syncro: ~1MB
    
    For large installers exceeding RMM limits, consider:
    - External hosting with download
    - Chunked deployment scripts
    - Network share deployment (Deploy-RMMAgent.ps1)

.LINK
    https://github.com/YeylandWutani
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Installer not found: $_"
        }
        if ($_ -notmatch '\.(exe|msi)$') {
            throw "Unsupported file type. Only EXE and MSI files are supported."
        }
        $true
    })]
    [string]$InstallerPath,

    [Parameter(Position = 1)]
    [string]$OutputPath,

    [Parameter()]
    [string]$Arguments,

    [Parameter()]
    [string]$Description,

    [Parameter()]
    [string]$PreScript,

    [Parameter()]
    [string]$PostScript,

    [Parameter()]
    [switch]$KeepInstaller,

    [Parameter()]
    [switch]$Compress,

    [Parameter()]
    [switch]$ShowInstallerInfo
)

#region Configuration
$Script:Frameworks = @{
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
        SecondaryCheck = "MSI"
        SilentSwitches = '/s /v"/qn /norestart"'
        Notes          = "Wraps an MSI. The /v passes args to msiexec."
        Reliability    = "Medium"
    }
    InstallShieldLegacy = @{
        Name           = "InstallShield (Legacy/InstallScript)"
        Signatures     = @("InstallShield")
        ExcludeCheck   = "MSI"
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
#endregion

#region Banner
function Show-YWBanner {
    $banner = @"
  __   __       _                 _  __      __     _              _ 
  \ \ / /__ _  | | __ _ _ __   __| | \ \    / /   _| |_ __ _ _ __ (_)
   \ V / _ \ \| |/ _` | '_ \ / _` |  \ \/\/ / | | | __/ _` | '_ \| |
    | |  __/\   | (_| | | | | (_| |   \    /| |_| | || (_| | | | | |
    |_|\___| |_|\__,_|_| |_|\__,_|    \/\/  \__,_|\__\__,_|_| |_|_|
"@
    Write-Host ""
    Write-Host ("=" * 75) -ForegroundColor DarkYellow
    Write-Host $banner -ForegroundColor DarkYellow
    Write-Host "  Building Better Systems" -ForegroundColor Gray
    Write-Host ("=" * 75) -ForegroundColor DarkYellow
    Write-Host ""
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
        
        foreach ($fwKey in $Script:Frameworks.Keys) {
            $fw = $Script:Frameworks[$fwKey]
            
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
            $fw = $Script:Frameworks[$detectedFramework]
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

function Show-InstallerInfo {
    <#
    .SYNOPSIS
        Displays detected framework and silent switch information.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $installerItem = Get-Item $Path
    $installerExt = $installerItem.Extension.ToLower()
    $fileSize = [math]::Round($installerItem.Length / 1MB, 2)
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkYellow
    Write-Host " INSTALLER ANALYSIS" -ForegroundColor DarkYellow
    Write-Host ("=" * 70) -ForegroundColor DarkYellow
    Write-Host ""
    
    # File Info
    Write-Host "  FILE INFORMATION" -ForegroundColor Cyan
    Write-Host "  ----------------" -ForegroundColor Gray
    Write-Host "  File Name    : $($installerItem.Name)" -ForegroundColor White
    Write-Host "  File Size    : $fileSize MB" -ForegroundColor White
    Write-Host "  Type         : $($installerExt.ToUpper().TrimStart('.'))" -ForegroundColor White
    
    if ($installerExt -eq '.msi') {
        # MSI - show standard info
        Write-Host ""
        Write-Host "  MSI SILENT SWITCHES (Standard)" -ForegroundColor Cyan
        Write-Host "  ------------------------------" -ForegroundColor Gray
        Write-Host "  Default      : /qn /norestart" -ForegroundColor Green
        Write-Host "  With Log     : /qn /norestart /l*v install.log" -ForegroundColor White
        Write-Host "  Basic UI     : /qb /norestart" -ForegroundColor White
        Write-Host ""
        Write-Host "  Reliability  : High (MSI standard)" -ForegroundColor Green
        
        return @{
            Framework      = "MSI"
            FrameworkName  = "Windows Installer (MSI)"
            SilentSwitches = "/qn /norestart"
            Reliability    = "High"
        }
    }
    else {
        # EXE - detect framework
        $detection = Get-EXEFramework -Path $Path
        
        if ($detection.FileInfo) {
            $fi = $detection.FileInfo
            if ($fi.ProductName) { Write-Host "  Product      : $($fi.ProductName)" -ForegroundColor White }
            if ($fi.FileVersion) { Write-Host "  Version      : $($fi.FileVersion)" -ForegroundColor White }
            if ($fi.CompanyName) { Write-Host "  Vendor       : $($fi.CompanyName)" -ForegroundColor White }
            if ($fi.FileDescription) { Write-Host "  Description  : $($fi.FileDescription)" -ForegroundColor Gray }
        }
        Write-Host ""
        
        # Detection Result
        Write-Host "  FRAMEWORK DETECTION" -ForegroundColor Cyan
        Write-Host "  -------------------" -ForegroundColor Gray
        
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
        Write-Host "  SILENT INSTALLATION" -ForegroundColor Cyan
        Write-Host "  -------------------" -ForegroundColor Gray
        
        if ($detection.SilentSwitches) {
            Write-Host "  Switches     : " -ForegroundColor White -NoNewline
            Write-Host "$($detection.SilentSwitches)" -ForegroundColor Green
        }
        else {
            Write-Host "  Switches     : Unknown - manual detection required" -ForegroundColor Yellow
        }
        
        Write-Host "  Notes        : $($detection.Notes)" -ForegroundColor Gray
        Write-Host ""
        
        # Example command
        Write-Host "  DEPLOYMENT COMMAND" -ForegroundColor Cyan
        Write-Host "  ------------------" -ForegroundColor Gray
        
        if ($detection.SilentSwitches) {
            Write-Host "  $($installerItem.Name) $($detection.SilentSwitches)" -ForegroundColor Cyan
        }
        else {
            Write-Host "  Try: $($installerItem.Name) /s" -ForegroundColor Yellow
            Write-Host "  Or:  $($installerItem.Name) /S" -ForegroundColor Yellow
            Write-Host "  Or:  $($installerItem.Name) /silent" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Gray
        Write-Host ""
        
        return $detection
    }
}
#endregion

#region Main Logic
Show-YWBanner

# Resolve full path
$InstallerPath = Resolve-Path $InstallerPath | Select-Object -ExpandProperty Path
$installerItem = Get-Item $InstallerPath
$installerName = $installerItem.BaseName
$installerExt = $installerItem.Extension.ToLower()
$originalSize = $installerItem.Length

# ShowInstallerInfo mode - analyze and exit
if ($ShowInstallerInfo) {
    Show-InstallerInfo -Path $InstallerPath
    return
}

Write-Host "[*] Processing: $($installerItem.Name)" -ForegroundColor Cyan
Write-Host "    Size: $([math]::Round($originalSize / 1MB, 2)) MB" -ForegroundColor Gray

# Set default output path
if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location) "Deploy-$installerName.ps1"
}

# Detect/set silent arguments
$detectedFramework = $null
$frameworkName = $null

if (-not $Arguments) {
    if ($installerExt -eq '.msi') {
        $Arguments = '/qn /norestart'
        $frameworkName = "MSI (Windows Installer)"
        Write-Host "[*] Installer type: MSI" -ForegroundColor Cyan
        Write-Host "[*] Using default MSI arguments: $Arguments" -ForegroundColor Green
    }
    else {
        # EXE - detect framework
        Write-Host "[*] Detecting EXE installer framework..." -ForegroundColor Cyan
        $detection = Get-EXEFramework -Path $InstallerPath
        $detectedFramework = $detection.Framework
        $frameworkName = $detection.FrameworkName
        
        if ($detection.SilentSwitches) {
            $Arguments = $detection.SilentSwitches
            Write-Host "[+] Detected: $frameworkName" -ForegroundColor Green
            Write-Host "[*] Using silent switches: $Arguments" -ForegroundColor Green
            
            if ($detection.Reliability -ne "High") {
                Write-Host "[!] Detection reliability: $($detection.Reliability)" -ForegroundColor Yellow
                Write-Host "    $($detection.Notes)" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "[!] Unknown framework - unable to auto-detect silent switches" -ForegroundColor Yellow
            Write-Host "    Run with -ShowInstallerInfo for analysis" -ForegroundColor Gray
            Write-Host ""
            Write-Host "    Common silent switches to try:" -ForegroundColor Cyan
            Write-Host "      /s, /S, /silent, /quiet, /verysilent" -ForegroundColor Gray
            Write-Host ""
            
            $customArgs = Read-Host "    Enter silent switches (or press Enter to cancel)"
            if ($customArgs) {
                $Arguments = $customArgs
                $frameworkName = "Custom (user-specified)"
            }
            else {
                Write-Host "[!] Cancelled - no silent switches provided" -ForegroundColor Red
                return
            }
        }
    }
}
else {
    Write-Host "[*] Using provided arguments: $Arguments" -ForegroundColor Cyan
    $frameworkName = "Custom (user-specified)"
}

# Read and encode the installer
Write-Host "[*] Reading installer binary..." -ForegroundColor Cyan
$fileBytes = [System.IO.File]::ReadAllBytes($InstallerPath)

$encodedData = $null
$isCompressed = $false

if ($Compress) {
    Write-Host "[*] Compressing binary data..." -ForegroundColor Cyan
    try {
        $memoryStream = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GZipStream($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
        $gzipStream.Write($fileBytes, 0, $fileBytes.Length)
        $gzipStream.Close()
        $compressedBytes = $memoryStream.ToArray()
        $memoryStream.Close()
        
        $compressionRatio = [math]::Round((1 - ($compressedBytes.Length / $fileBytes.Length)) * 100, 1)
        Write-Host "    Compression ratio: $compressionRatio% reduction" -ForegroundColor Gray
        
        $encodedData = [Convert]::ToBase64String($compressedBytes)
        $isCompressed = $true
    }
    catch {
        Write-Host "[!] Compression failed, using uncompressed encoding" -ForegroundColor Yellow
        $encodedData = [Convert]::ToBase64String($fileBytes)
    }
}
else {
    $encodedData = [Convert]::ToBase64String($fileBytes)
}

$encodedSize = $encodedData.Length
Write-Host "[*] Base64 encoded size: $([math]::Round($encodedSize / 1MB, 2)) MB" -ForegroundColor Cyan

# Warn about common RMM limits
if ($encodedSize -gt 1MB) {
    Write-Host ""
    Write-Host "[!] WARNING: Large script size detected" -ForegroundColor Yellow
    Write-Host "    Some RMM tools have script size limits:" -ForegroundColor Yellow
    Write-Host "    - Datto RMM: ~1MB" -ForegroundColor Gray
    Write-Host "    - Syncro: ~1MB" -ForegroundColor Gray
    Write-Host "    - NinjaRMM: ~5MB" -ForegroundColor Gray
    Write-Host "    - ConnectWise Automate: ~16MB" -ForegroundColor Gray
    if (-not $Compress) {
        Write-Host "    Consider using -Compress to reduce size" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Build description block
$descriptionBlock = if ($Description) {
    "    $Description"
} else {
    "    Deploys $($installerItem.Name) silently."
}

# Build pre/post script blocks
$preScriptBlock = if ($PreScript) {
@"

    # Pre-installation script
    Write-Host "[*] Running pre-installation tasks..." -ForegroundColor Cyan
    try {
        $PreScript
    }
    catch {
        Write-Host "[!] Pre-installation script failed: `$_" -ForegroundColor Red
        exit 1
    }
"@
} else { "" }

$postScriptBlock = if ($PostScript) {
@"

    # Post-installation script
    Write-Host "[*] Running post-installation tasks..." -ForegroundColor Cyan
    try {
        $PostScript
    }
    catch {
        Write-Host "[!] Post-installation script failed: `$_" -ForegroundColor Yellow
    }
"@
} else { "" }

# Build cleanup block
$cleanupBlock = if ($KeepInstaller) {
@"
    Write-Host "[*] Installer retained at: `$installerPath" -ForegroundColor Gray
"@
} else {
@"
    # Cleanup
    if (Test-Path `$installerPath) {
        Remove-Item `$installerPath -Force -ErrorAction SilentlyContinue
        Write-Host "[*] Cleaned up temporary installer" -ForegroundColor Gray
    }
"@
}

# Build decompression block if needed
$decompressionBlock = if ($isCompressed) {
@"

    # Decompress the data
    Write-Host "[*] Decompressing installer data..." -ForegroundColor Cyan
    `$compressedBytes = [Convert]::FromBase64String(`$encodedInstaller)
    `$inputStream = New-Object System.IO.MemoryStream(,`$compressedBytes)
    `$gzipStream = New-Object System.IO.Compression.GZipStream(`$inputStream, [System.IO.Compression.CompressionMode]::Decompress)
    `$outputStream = New-Object System.IO.MemoryStream
    `$gzipStream.CopyTo(`$outputStream)
    `$gzipStream.Close()
    `$inputStream.Close()
    `$fileBytes = `$outputStream.ToArray()
    `$outputStream.Close()
"@
} else {
@"

    # Decode the installer
    Write-Host "[*] Decoding installer..." -ForegroundColor Cyan
    `$fileBytes = [Convert]::FromBase64String(`$encodedInstaller)
"@
}

# Build execution block based on installer type
$executionBlock = if ($installerExt -eq '.msi') {
@"
    # Execute MSI installer
    Write-Host "[*] Installing via msiexec..." -ForegroundColor Cyan
    `$msiArgs = "/i `"`$installerPath`" $Arguments"
    `$process = Start-Process -FilePath "msiexec.exe" -ArgumentList `$msiArgs -Wait -PassThru -NoNewWindow
    `$exitCode = `$process.ExitCode
"@
} else {
@"
    # Execute EXE installer
    Write-Host "[*] Running installer..." -ForegroundColor Cyan
    `$process = Start-Process -FilePath `$installerPath -ArgumentList "$Arguments" -Wait -PassThru -NoNewWindow
    `$exitCode = `$process.ExitCode
"@
}

# Generate the deployment script
Write-Host "[*] Generating deployment script..." -ForegroundColor Cyan

$deploymentScript = @"
<#
.SYNOPSIS
    Self-contained installer deployment script.

.DESCRIPTION
$descriptionBlock
    
    This script was generated by New-EmbeddedInstaller.ps1
    The installer binary is Base64 encoded within this script.

.NOTES
    Generated:    $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Generator:    Yeyland Wutani - New-EmbeddedInstaller.ps1 v1.1.0
    Source:       $($installerItem.Name)
    Framework:    $frameworkName
    Original:     $([math]::Round($originalSize / 1MB, 2)) MB
    Encoded:      $([math]::Round($encodedSize / 1MB, 2)) MB
    Compressed:   $isCompressed
    Arguments:    $Arguments
#>

#Requires -Version 5.1

`$ErrorActionPreference = 'Stop'

# Embedded installer data (Base64 encoded$(if ($isCompressed) { ", GZip compressed" }))
`$encodedInstaller = @'
$encodedData
'@

try {
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    Write-Host " Yeyland Wutani - Embedded Installer Deployment" -ForegroundColor DarkYellow
    Write-Host " Building Better Systems" -ForegroundColor Gray
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "[*] Target: $($installerItem.Name)" -ForegroundColor Cyan
    Write-Host "[*] Framework: $frameworkName" -ForegroundColor Gray
    Write-Host "[*] Started: `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
$preScriptBlock
$decompressionBlock

    # Write to temp location
    `$tempDir = Join-Path `$env:TEMP "YW_Deploy_`$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path `$tempDir -Force | Out-Null
    `$installerPath = Join-Path `$tempDir "$($installerItem.Name)"
    
    Write-Host "[*] Writing installer to: `$installerPath" -ForegroundColor Gray
    [System.IO.File]::WriteAllBytes(`$installerPath, `$fileBytes)

$executionBlock

    # Evaluate exit code
    Write-Host ""
    switch (`$exitCode) {
        0       { Write-Host "[+] Installation completed successfully" -ForegroundColor Green }
        1641    { Write-Host "[+] Installation completed, reboot initiated" -ForegroundColor Green }
        3010    { Write-Host "[+] Installation completed, reboot required" -ForegroundColor Yellow }
        1618    { Write-Host "[!] Another installation in progress" -ForegroundColor Yellow }
        1619    { Write-Host "[!] Installer package could not be opened" -ForegroundColor Red }
        1620    { Write-Host "[!] Installer package invalid" -ForegroundColor Red }
        default { 
            if (`$exitCode -ne 0) {
                Write-Host "[!] Installation returned exit code: `$exitCode" -ForegroundColor Yellow
            }
        }
    }
$postScriptBlock

$cleanupBlock

    # Cleanup temp directory
    if (Test-Path `$tempDir) {
        Remove-Item `$tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "[*] Completed: `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    
    exit `$exitCode
}
catch {
    Write-Host "[!] FATAL ERROR: `$_" -ForegroundColor Red
    Write-Host `$_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
"@

# Write the deployment script
try {
    $deploymentScript | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "[+] Deployment script created successfully!" -ForegroundColor Green
    Write-Host "    Output: $OutputPath" -ForegroundColor Gray
    Write-Host ""
    
    $outputItem = Get-Item $OutputPath
    Write-Host "    Script size: $([math]::Round($outputItem.Length / 1MB, 2)) MB ($($outputItem.Length.ToString('N0')) bytes)" -ForegroundColor Gray
    
    # Summary
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    Write-Host " DEPLOYMENT SUMMARY" -ForegroundColor DarkYellow
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
    Write-Host "  Source Installer:  $($installerItem.Name)" -ForegroundColor Gray
    Write-Host "  Installer Type:    $($installerExt.ToUpper().TrimStart('.'))" -ForegroundColor Gray
    if ($frameworkName) {
        Write-Host "  Framework:         $frameworkName" -ForegroundColor Gray
    }
    Write-Host "  Original Size:     $([math]::Round($originalSize / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "  Script Size:       $([math]::Round($outputItem.Length / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "  Compression:       $(if ($isCompressed) { 'Yes' } else { 'No' })" -ForegroundColor Gray
    Write-Host "  Install Arguments: $Arguments" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  To deploy: Copy the script content to your RMM and execute" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
}
catch {
    Write-Host "[!] Failed to write deployment script: $_" -ForegroundColor Red
    exit 1
}
#endregion
