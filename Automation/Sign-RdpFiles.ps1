<#
.SYNOPSIS
    Signs all .rdp files found on user desktops and in documents folders,
    and installs the signing certificate into the machine's trusted stores.

.DESCRIPTION
    Self-contained deployment script intended for execution via ASIO (or any RMM
    tool running as SYSTEM/admin). No external dependencies or file drops required.

    On each run the script:
      1. Installs the public certificate into LocalMachine\TrustedPublishers and
         LocalMachine\Root so signed RDP files are trusted without prompting.
      2. Temporarily imports the PFX (private key) into LocalMachine\My for signing.
      3. Scans Desktop and Documents for every user profile under C:\Users, including
         common OneDrive-redirected paths (OneDrive, OneDrive - *).
      4. Signs each .rdp file in place using rdpsign.exe.
      5. Removes the private key from the store on exit (cleanup).

    Re-running the script is safe: the cert install is idempotent and previously
    signed files will simply be re-signed with the same certificate.

.NOTES
    Author:      Yeyland Wutani LLC
    Version:     1.0.0
    Purpose:     RDP file signing - ASIO workstation deployment

    SETUP: Run New-RdpSigningCert.ps1 on your admin machine and paste the three
    output values into the CONFIGURATION section below before deploying.

    SECURITY: This script embeds the PFX private key as Base64. Restrict access
    to the script file as you would a password or credential file.

    EXIT CODES:
      0  All files signed successfully (or no RDP files found)
      1  One or more files failed to sign, or a fatal error occurred
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

# ==============================================================================
# CONFIGURATION — paste output from New-RdpSigningCert.ps1 here
# ==============================================================================
$PFX_BASE64   = ''
$CER_BASE64   = ''
$PFX_PASSWORD = ''
# ==============================================================================

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

#region Elevation Check
function Assert-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[!] This script must run as Administrator or SYSTEM." -ForegroundColor Red
        exit 1
    }
}
#endregion

#region Certificate Helpers
function Install-CertToStore {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$StoreName,
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName, $StoreLocation
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        if (-not $existing) {
            $store.Add($Cert)
            Write-Host "[+] Cert installed : $StoreLocation\$StoreName ($($Cert.Thumbprint))" -ForegroundColor Green
        }
        else {
            Write-Host "[*] Cert present   : $StoreLocation\$StoreName (no change)" -ForegroundColor Gray
        }
    }
    finally {
        $store.Close()
    }
}

function Remove-CertFromStore {
    param(
        [string]$Thumbprint,
        [string]$StoreName,
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName, $StoreLocation
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $matches = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
        foreach ($c in $matches) { $store.Remove($c) }
    }
    finally {
        $store.Close()
    }
}
#endregion

Show-YWBanner
Assert-Admin

Write-Host "[*] Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "[*] Host    : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host ""

#region Validate Configuration
if ([string]::IsNullOrWhiteSpace($PFX_BASE64) -or
    [string]::IsNullOrWhiteSpace($CER_BASE64) -or
    [string]::IsNullOrWhiteSpace($PFX_PASSWORD)) {
    Write-Host "[!] CONFIGURATION INCOMPLETE" -ForegroundColor Red
    Write-Host "    PFX_BASE64, CER_BASE64, and PFX_PASSWORD must all be populated." -ForegroundColor Yellow
    Write-Host "    Run New-RdpSigningCert.ps1 and paste the output into this script." -ForegroundColor Yellow
    exit 1
}

$rdpsign = "$env:SystemRoot\System32\rdpsign.exe"
if (-not (Test-Path $rdpsign)) {
    Write-Host "[!] rdpsign.exe not found at $rdpsign" -ForegroundColor Red
    exit 1
}
#endregion

#region Install Trust Certificates
Write-Host "[*] Installing trust certificates..." -ForegroundColor Cyan

try {
    $cerBytes  = [Convert]::FromBase64String($CER_BASE64.Trim())
    $publicCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytes)

    # TrustedPublishers — marks this cert as a known/trusted software publisher
    Install-CertToStore -Cert $publicCert `
        -StoreName "TrustedPublisher" `
        -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)

    # Root — required for self-signed cert chain validation
    Install-CertToStore -Cert $publicCert `
        -StoreName "Root" `
        -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
}
catch {
    Write-Host "[!] Failed to install trust certificates: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region Import Signing Certificate (PFX)
Write-Host ""
Write-Host "[*] Importing signing certificate..." -ForegroundColor Cyan

$pfxTempPath = $null
$thumbprint  = $null

try {
    $pfxBytes    = [Convert]::FromBase64String($PFX_BASE64.Trim())
    $pfxTempPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName() + ".pfx")
    [IO.File]::WriteAllBytes($pfxTempPath, $pfxBytes)

    $securePass    = ConvertTo-SecureString $PFX_PASSWORD -AsPlainText -Force
    $signingCert   = Import-PfxCertificate -FilePath $pfxTempPath `
                         -CertStoreLocation "Cert:\LocalMachine\My" `
                         -Password $securePass
    $thumbprint    = $signingCert.Thumbprint

    Write-Host "[+] Signing cert imported: $thumbprint" -ForegroundColor Green
    Write-Host "    Subject  : $($signingCert.Subject)" -ForegroundColor Gray
    Write-Host "    Expires  : $($signingCert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
}
catch {
    Write-Host "[!] Failed to import PFX: $_" -ForegroundColor Red
    exit 1
}
finally {
    if ($pfxTempPath -and (Test-Path $pfxTempPath)) {
        Remove-Item $pfxTempPath -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Scan and Sign
$excludedProfiles = @('Public', 'Default', 'Default User', 'All Users', 'defaultuser0')

$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin $excludedProfiles }

Write-Host ""
Write-Host "[*] Scanning $($userProfiles.Count) user profile(s)..." -ForegroundColor Cyan

$countFound  = 0
$countSigned = 0
$countFailed = 0

foreach ($profile in $userProfiles) {
    # Build list of paths to search for this profile
    $searchPaths = [System.Collections.Generic.List[string]]::new()

    foreach ($folder in @('Desktop', 'Documents')) {
        $standard = Join-Path $profile.FullName $folder
        if (Test-Path $standard) { $searchPaths.Add($standard) }
    }

    # OneDrive-redirected Desktop/Documents (handles "OneDrive" and "OneDrive - Corp" etc.)
    $oneDriveFolders = Get-ChildItem -Path $profile.FullName -Directory -Filter "OneDrive*" `
                           -ErrorAction SilentlyContinue
    foreach ($od in $oneDriveFolders) {
        foreach ($folder in @('Desktop', 'Documents')) {
            $odPath = Join-Path $od.FullName $folder
            if (Test-Path $odPath) { $searchPaths.Add($odPath) }
        }
    }

    if ($searchPaths.Count -eq 0) { continue }

    foreach ($searchPath in $searchPaths) {
        $rdpFiles = Get-ChildItem -Path $searchPath -Filter "*.rdp" -Recurse `
                        -ErrorAction SilentlyContinue

        foreach ($file in $rdpFiles) {
            $countFound++
            Write-Host "  Signing: $($file.FullName)" -ForegroundColor Gray

            $output     = & $rdpsign /sha256 $thumbprint $file.FullName 2>&1
            $exitCode   = $LASTEXITCODE

            if ($exitCode -eq 0) {
                $countSigned++
                Write-Host "    [OK]" -ForegroundColor Green
            }
            else {
                $countFailed++
                Write-Host "    [FAILED] Exit $exitCode — $output" -ForegroundColor Red
            }
        }
    }
}
#endregion

#region Remove Private Key
Write-Host ""
Write-Host "[*] Removing private key from store..." -ForegroundColor Cyan
try {
    Remove-CertFromStore -Thumbprint $thumbprint `
        -StoreName "My" `
        -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    Write-Host "[+] Private key removed from LocalMachine\My" -ForegroundColor Green
}
catch {
    Write-Host "[!] Warning: failed to remove private key from store: $_" -ForegroundColor Yellow
}
#endregion

#region Summary
Write-Host ""
Write-Host ("=" * 75) -ForegroundColor DarkYellow
Write-Host " RESULTS" -ForegroundColor DarkYellow
Write-Host ("=" * 75) -ForegroundColor DarkYellow
Write-Host "  Profiles scanned : $($userProfiles.Count)" -ForegroundColor Gray
Write-Host "  RDP files found  : $countFound" -ForegroundColor Gray

$signedColor = if ($countSigned -gt 0) { "Green" } else { "Gray" }
$failedColor = if ($countFailed -gt 0) { "Red"   } else { "Gray" }

Write-Host "  Signed           : $countSigned" -ForegroundColor $signedColor
Write-Host "  Failed           : $countFailed" -ForegroundColor $failedColor
Write-Host ""
Write-Host "[*] Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ("=" * 75) -ForegroundColor DarkYellow
Write-Host ""
#endregion

exit $(if ($countFailed -gt 0) { 1 } else { 0 })
