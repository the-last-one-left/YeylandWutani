<#
.SYNOPSIS
    Prepares the Base64 values needed to populate Sign-RdpFiles.ps1, either by
    generating a new self-signed certificate or by extracting them from an
    existing PFX file.

.DESCRIPTION
    MODE 1 — Generate new cert (default, no -ExistingPfxPath):
      Creates a code-signing certificate in LocalMachine\My, exports it as a
      PFX and a public CER, and prints the Base64 strings to paste into
      Sign-RdpFiles.ps1. Run once on your admin workstation.

    MODE 2 — Use existing PFX (-ExistingPfxPath):
      Reads a PFX you already have, extracts the public certificate, and
      outputs both Base64 strings ready to paste into Sign-RdpFiles.ps1.
      No new certificate is created; no changes are made to the cert store.

.PARAMETER ExistingPfxPath
    Path to an existing PFX file. When provided the script skips cert
    creation and extracts values from this file instead.

.PARAMETER PfxPassword
    PFX password.
    - Mode 1: password to protect the newly created PFX (and to paste into
      Sign-RdpFiles.ps1). Defaults to a random value.
    - Mode 2: password for the existing PFX. Required.

.PARAMETER Subject
    Certificate subject CN. Mode 1 only. Defaults to "RDP File Signing".

.PARAMETER Organization
    Organization name appended to the CN. Mode 1 only.
    Defaults to "Yeyland Wutani".

.PARAMETER ValidYears
    Cert validity period in years. Mode 1 only. Defaults to 5.

.EXAMPLE
    .\New-RdpSigningCert.ps1

    Generates a new self-signed cert with default settings.

.EXAMPLE
    .\New-RdpSigningCert.ps1 -ExistingPfxPath "C:\Certs\my-signing.pfx" -PfxPassword "hunter2"

    Extracts Base64 strings from an existing PFX without creating anything new.

.EXAMPLE
    .\New-RdpSigningCert.ps1 -ValidYears 3 -PfxPassword "SuperSecret99!"

    Generates a new 3-year cert protected with a specific password.

.NOTES
    Author:  Yeyland Wutani LLC
    Version: 1.1.0
    Purpose: One-time cert preparation for RDP file signing deployment

    SECURITY: Sign-RdpFiles.ps1 will contain the private key once populated.
    Treat that script like a credential file — restrict access accordingly.
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Generate')]
param(
    [Parameter(ParameterSetName = 'Existing', Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ExistingPfxPath,

    [Parameter(ParameterSetName = 'Existing', Mandatory)]
    [Parameter(ParameterSetName = 'Generate')]
    [string]$PfxPassword = "RdpSign$(Get-Random -Minimum 1000 -Maximum 9999)!",

    [Parameter(ParameterSetName = 'Generate')]
    [string]$Subject = "RDP File Signing",

    [Parameter(ParameterSetName = 'Generate')]
    [string]$Organization = "Yeyland Wutani",

    [Parameter(ParameterSetName = 'Generate')]
    [ValidateRange(1, 10)]
    [int]$ValidYears = 5
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

Show-YWBanner

#region Mode 2 — Existing PFX
if ($PSCmdlet.ParameterSetName -eq 'Existing') {
    Write-Host "[*] Mode: extracting from existing PFX" -ForegroundColor Cyan
    Write-Host "    Path: $ExistingPfxPath" -ForegroundColor Gray
    Write-Host ""

    try {
        $securePass = ConvertTo-SecureString $PfxPassword -AsPlainText -Force

        # Load the PFX — Exportable flag needed to pull the public bytes back out
        $keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $ExistingPfxPath, $securePass, $keyFlags
        )
    }
    catch {
        Write-Host "[!] Failed to open PFX — wrong password or corrupt file: $_" -ForegroundColor Red
        exit 1
    }

    # PFX base64 — read the file bytes directly (preserves original packaging)
    $pfxBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ExistingPfxPath))

    # CER base64 — public cert only (no private key)
    $cerBytes  = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $cerBase64 = [Convert]::ToBase64String($cerBytes)

    Write-Host "[+] PFX loaded successfully." -ForegroundColor Green
    Write-Host "    Subject  : $($cert.Subject)" -ForegroundColor Gray
    Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "    Expires  : $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor $(
        if ($cert.NotAfter -lt (Get-Date).AddMonths(6)) { "Yellow" } else { "Gray" }
    )

    # Fall through to shared output block
}
#endregion

#region Mode 1 — Generate New Cert
else {
    #Requires -RunAsAdministrator

    Write-Host "[*] Mode: generating new self-signed certificate" -ForegroundColor Cyan
    Write-Host "    Subject   : CN=$Subject, O=$Organization" -ForegroundColor Gray
    Write-Host "    Valid for : $ValidYears year(s)" -ForegroundColor Gray
    Write-Host ""

    $certParams = @{
        Subject           = "CN=$Subject, O=$Organization"
        CertStoreLocation = "Cert:\LocalMachine\My"
        KeyUsage          = "DigitalSignature"
        KeyAlgorithm      = "RSA"
        KeyLength         = 2048
        HashAlgorithm     = "SHA256"
        NotAfter          = (Get-Date).AddYears($ValidYears)
        Type              = "CodeSigningCert"
    }

    try {
        $cert = New-SelfSignedCertificate @certParams
        Write-Host "[+] Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to create certificate: $_" -ForegroundColor Red
        exit 1
    }

    $pfxTempPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName() + ".pfx")
    $cerTempPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName() + ".cer")

    try {
        $securePass = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath $pfxTempPath -Password $securePass | Out-Null
        Export-Certificate    -Cert $cert -FilePath $cerTempPath | Out-Null

        $pfxBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxTempPath))
        $cerBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($cerTempPath))
    }
    catch {
        Write-Host "[!] Failed to export certificate: $_" -ForegroundColor Red
        exit 1
    }
    finally {
        Remove-Item $pfxTempPath, $cerTempPath -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Shared Output
Write-Host ""
Write-Host ("=" * 75) -ForegroundColor DarkYellow
Write-Host " PASTE THESE VALUES INTO Sign-RdpFiles.ps1" -ForegroundColor DarkYellow
Write-Host ("=" * 75) -ForegroundColor DarkYellow
Write-Host ""
Write-Host "`$PFX_BASE64   = '$pfxBase64'" -ForegroundColor Cyan
Write-Host ""
Write-Host "`$CER_BASE64   = '$cerBase64'" -ForegroundColor Cyan
Write-Host ""
Write-Host "`$PFX_PASSWORD = '$PfxPassword'" -ForegroundColor Cyan
Write-Host ""
Write-Host ("=" * 75) -ForegroundColor DarkYellow
Write-Host ""
Write-Host "[!] SECURITY REMINDER" -ForegroundColor Red
Write-Host "    Sign-RdpFiles.ps1 will contain the private key once populated." -ForegroundColor Yellow
Write-Host "    Treat it as a credential file — restrict access accordingly." -ForegroundColor Yellow
Write-Host ""
#endregion
