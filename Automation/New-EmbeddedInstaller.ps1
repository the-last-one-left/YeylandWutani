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
    
    Ideal for RMM deployments where you can push scripts but not files directly.

.PARAMETER InstallerPath
    Path to the installer file (EXE or MSI) to embed.

.PARAMETER OutputPath
    Path for the generated PowerShell deployment script.
    Defaults to "Deploy-[InstallerName].ps1" in current directory.

.PARAMETER Arguments
    Silent install arguments. If not specified, attempts to detect common patterns
    or uses defaults (/qn for MSI, /S for common EXE installers).

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

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\Agent.msi"
    
    Creates Deploy-Agent.ps1 with embedded MSI and default /qn arguments.

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\Setup.exe" -Arguments "/S /NORESTART" -OutputPath ".\Deploy-App.ps1"
    
    Creates Deploy-App.ps1 with custom silent arguments.

.EXAMPLE
    .\New-EmbeddedInstaller.ps1 -InstallerPath ".\BigApp.msi" -Compress -Description "Deploys BigApp v2.1"
    
    Creates compressed embedded script with description.

.NOTES
    Author:     Yeyland Wutani LLC
    Version:    1.0.0
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
    [switch]$Compress
)

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

#region Main Logic
Show-YWBanner

# Resolve full path
$InstallerPath = Resolve-Path $InstallerPath | Select-Object -ExpandProperty Path
$installerItem = Get-Item $InstallerPath
$installerName = $installerItem.BaseName
$installerExt = $installerItem.Extension.ToLower()
$originalSize = $installerItem.Length

Write-Host "[*] Processing: $($installerItem.Name)" -ForegroundColor Cyan
Write-Host "    Size: $([math]::Round($originalSize / 1MB, 2)) MB" -ForegroundColor Gray

# Set default output path
if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location) "Deploy-$installerName.ps1"
}

# Detect silent arguments if not provided
if (-not $Arguments) {
    if ($installerExt -eq '.msi') {
        $Arguments = '/qn /norestart'
        Write-Host "[*] Using default MSI arguments: $Arguments" -ForegroundColor Yellow
    }
    else {
        # Common silent switches for EXE installers
        $Arguments = '/S'
        Write-Host "[*] Using default EXE arguments: $Arguments (adjust if needed)" -ForegroundColor Yellow
    }
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
    Generator:    Yeyland Wutani - New-EmbeddedInstaller.ps1
    Source:       $($installerItem.Name)
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
    Write-Host "  Original Size:     $([math]::Round($originalSize / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "  Script Size:       $([math]::Round($outputItem.Length / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "  Compression:       $(if ($isCompressed) { 'Yes' } else { 'No' })" -ForegroundColor Gray
    Write-Host "  Install Arguments: $Arguments" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  To deploy: Copy the script content to your RMM and execute" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkYellow
}
catch {
    Write-Host "[!] Failed to write deployment script: $_" -ForegroundColor Red
    exit 1
}
#endregion
