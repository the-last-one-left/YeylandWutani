<#
.SYNOPSIS
    Server baseline configuration script for MSP environments.

.DESCRIPTION
    Yeyland Wutani - Building Better Systems
    
    Comprehensive server baseline automation for MSP deployments:
    - ConnectWise Control (ScreenConnect) agent deployment
    - Hardware-specific driver management (Dell DSU, HP SPP)
    - Windows Terminal and PowerShell 7 installation
    - NTP time source configuration
    - Server Manager auto-start disable
    - Power management optimization
    - Windows Update configuration
    - Remote Desktop optimization
    - Security and audit logging
    - Event log size adjustments

.PARAMETER AgentToken
    Agent token for ConnectWise Control installation (REQUIRED for agent install).
    This is the only installation property required by the MSI installer.
    If not provided, you will be prompted during execution.
    If skipped, ConnectWise Control installation will be skipped entirely.

.PARAMETER NTPServer
    Custom NTP server (default: us.pool.ntp.org)

.PARAMETER SkipRMMInstall
    Skip ConnectWise Control agent installation
    
.PARAMETER SkipDriverUpdates
    Skip hardware driver updates (Dell DSU/HP SPP)
    
.PARAMETER SkipServerManager
    Skip disabling Server Manager auto-start
    
.PARAMETER SkipTerminalInstall
    Skip Windows Terminal installation
    
.PARAMETER SkipPowerShell7
    Skip PowerShell 7 installation
    
.PARAMETER DisableIESecurity
    Disable Internet Explorer Enhanced Security Configuration
    
.PARAMETER Force
    Skip all interactive prompts and use defaults

.EXAMPLE
    .\Set-ServerBaseline.ps1

    Full baseline with all defaults. Will prompt for agent token during execution.

.EXAMPLE
    .\Set-ServerBaseline.ps1 -AgentToken "your-agent-token-here"

    Full baseline with embedded ConnectWise Control agent using provided token.

.EXAMPLE
    .\Set-ServerBaseline.ps1 -SkipRMMInstall -NTPServer "time.windows.com"

    Baseline without RMM agent, using custom NTP server.

.EXAMPLE
    .\Set-ServerBaseline.ps1 -Force

    Run full baseline with no interactive prompts, using all defaults.
    Will prompt for agent token if not provided.

.NOTES
    Author:         Yeyland Wutani LLC
    Version:        3.0.0
    Requires:       PowerShell 5.1+, Administrator privileges
    
.LINK
    https://github.com/YeylandWutani
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AgentToken,

    [Parameter(Mandatory = $false)]
    [string]$NTPServer = "us.pool.ntp.org",

    [Parameter(Mandatory = $false)]
    [switch]$SkipRMMInstall,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDriverUpdates,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServerManager,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTerminalInstall,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPowerShell7,

    [Parameter(Mandatory = $false)]
    [switch]$DisableIESecurity,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#region Configuration
$Script:Config = @{
    Version = "3.0.0"
    Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Branding - Yeyland Wutani
    Colors = @{
        Primary = "DarkYellow"
        Secondary = "Gray"
        Success = "Green"
        Warning = "Yellow"
        Error = "Red"
        Info = "Cyan"
    }
}

# Embedded ConnectWise Control Agent (Base64-encoded MSI)
# To embed your agent: Run .\Encode-MSIToBase64.ps1 and paste the output here
# This eliminates the need for URL-based downloads
$Script:EmbeddedAgent = ""
# If you want to use the embedded agent, set $UseEmbeddedAgent = $true
# or pass -UseEmbeddedAgent parameter when running the script

$Script:Results = @{
    RMMInstalled          = $false
    DriversUpdated        = $false
    NTPConfigured         = $false
    ServerManagerDisabled = $false
    TerminalInstalled     = $false
    PowerShell7Installed  = $false
    OptimizationsApplied  = $false
}
#endregion

#region Banner
function Show-YWBanner {
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
        "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
    )
    $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
    $border = "=" * 81
    
    Write-Host ""
    Write-Host $border -ForegroundColor $Script:Config.Colors.Secondary
    foreach ($line in $logo) {
        Write-Host $line -ForegroundColor $Script:Config.Colors.Primary
    }
    Write-Host ""
    Write-Host $tagline.PadLeft(62) -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host $border -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host ""
    Write-Host "  Server Baseline Configuration Tool v$($Script:Config.Version)" -ForegroundColor $Script:Config.Colors.Info
    Write-Host ""
}
#endregion

#region Helper Functions
function Write-YWLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { $Script:Config.Colors.Info }
        'Success' { $Script:Config.Colors.Success }
        'Warning' { $Script:Config.Colors.Warning }
        'Error'   { $Script:Config.Colors.Error }
    }
    
    $prefix = switch ($Level) {
        'Info'    { '[*]' }
        'Success' { '[+]' }
        'Warning' { '[!]' }
        'Error'   { '[-]' }
    }
    
    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Write-Phase {
    param(
        [Parameter(Mandatory)]
        [string]$Phase,
        
        [Parameter(Mandatory)]
        [string]$Description
    )
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host " PHASE: $Phase" -ForegroundColor $Script:Config.Colors.Primary
    Write-Host " $Description" -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host ("=" * 70) -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host ""
}

function Test-IsVirtualMachine {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $biosInfo = Get-CimInstance -ClassName Win32_BIOS
    
    $vmIndicators = @(
        $computerSystem.Model -match 'Virtual|VMware|VirtualBox|Hyper-V|QEMU|Xen|KVM',
        $computerSystem.Manufacturer -match 'VMware|Microsoft Corporation|Xen|QEMU|oVirt',
        $biosInfo.Manufacturer -match 'VMware|Microsoft|Xen|QEMU|Amazon EC2',
        $biosInfo.SerialNumber -match 'VMware|0{8,}'
    )
    
    return ($vmIndicators -contains $true)
}

function Get-HardwareManufacturer {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    return $computerSystem.Manufacturer
}

function Get-UserConfirmation {
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,
        
        [Parameter(Mandatory = $false)]
        [bool]$Default = $true
    )
    
    if ($Force) {
        return $Default
    }
    
    $response = Read-Host "$Prompt (Y/N)"
    return ($response -match '^[Yy]')
}

function Get-UserInput {
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,
        
        [Parameter(Mandatory = $false)]
        [string]$Default
    )
    
    if ($Force -and $Default) {
        return $Default
    }
    
    $input = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($input) -and $Default) {
        return $Default
    }
    return $input
}
#endregion

#region ConnectWise Control Installation
function Install-ConnectWiseControl {
    <#
    .SYNOPSIS
        Installs ConnectWise Control (ScreenConnect) agent from embedded Base64-encoded MSI.
    .NOTES
        Always uses embedded Base64-encoded MSI (no network dependency).
        Agent token is the only optional install property required.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$Token
    )

    Write-YWLog "Installing ConnectWise Control agent..." -Level Info

    $tempPath = "$env:TEMP\CWControl"
    New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
    $installerPath = "$tempPath\ConnectWiseControl.msi"
    $logPath = "$tempPath\install.log"

    try {
        # Check if embedded agent is configured
        if ([string]::IsNullOrWhiteSpace($Script:EmbeddedAgent)) {
            Write-YWLog "ERROR: Embedded agent is not configured!" -Level Error
            Write-Host ""
            Write-Host "  To use embedded agent installation:" -ForegroundColor Yellow
            Write-Host "  1. Run: .\Encode-MSIToBase64.ps1 -MSIPath 'path\to\Agent.msi'" -ForegroundColor Gray
            Write-Host "  2. Copy the Base64 string from EmbeddedAgent.txt" -ForegroundColor Gray
            Write-Host "  3. Paste it into the `$Script:EmbeddedAgent variable in this script" -ForegroundColor Gray
            Write-Host ""
            return $false
        }

        # Decode embedded agent
        Write-YWLog "Decoding embedded agent..." -Level Info
        try {
            $bytes = [System.Convert]::FromBase64String($Script:EmbeddedAgent)
            $sizeMB = [math]::Round($bytes.Length / 1MB, 2)
            Write-YWLog "Decoded $sizeMB MB MSI installer" -Level Success

            Write-YWLog "Writing installer to disk..." -Level Info
            [System.IO.File]::WriteAllBytes($installerPath, $bytes)
            Write-YWLog "Installer ready at: $installerPath" -Level Success
        }
        catch {
            Write-YWLog "Failed to decode embedded agent: $($_.Exception.Message)" -Level Error
            return $false
        }

        # Build MSI installation arguments
        $msiArgs = @(
            "/i"
            "`"$installerPath`""
            "/qn"
            "/norestart"
            "/l*v"
            "`"$logPath`""
        )

        # Add agent token if provided
        # ConnectWise Control typically uses e_install_key or INSTALLKEY parameter
        if (-not [string]::IsNullOrWhiteSpace($Token)) {
            Write-YWLog "Using provided agent token for installation" -Level Info
            # Try common parameter names for ConnectWise Control
            $msiArgs += "e_install_key=`"$Token`""
        }
        else {
            Write-YWLog "No token provided - installing with embedded configuration" -Level Info
        }

        $argString = $msiArgs -join " "

        # Attempt installation
        Write-YWLog "Installing ConnectWise Control agent..." -Level Info
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $argString -Wait -PassThru

        # Handle exit code 1638 (another version already installed)
        if ($process.ExitCode -eq 1638) {
            Write-YWLog "Another version of ConnectWise Control is already installed (exit code 1638)" -Level Warning
            Write-YWLog "Attempting to uninstall existing version..." -Level Info

            # Step 1: Stop all related services first
            $serviceNames = @("ScreenConnect Client*", "ConnectWise Control Client*", "screenconnect*", "connectwise*", "ITSPlatform*")
            foreach ($serviceName in $serviceNames) {
                $services = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                foreach ($service in $services) {
                    if ($service.Status -eq 'Running') {
                        Write-YWLog "Stopping service: $($service.DisplayName)" -Level Info
                        try {
                            Stop-Service -Name $service.Name -Force -ErrorAction Stop
                            Write-YWLog "Service stopped: $($service.DisplayName)" -Level Success
                        }
                        catch {
                            Write-YWLog "Could not stop service: $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
            }

            Start-Sleep -Seconds 3

            # Step 2: Kill any related processes
            $processNames = @("ScreenConnect.ClientService", "ScreenConnect.WindowsClient", "ConnectWiseControl.Client")
            foreach ($processName in $processNames) {
                $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
                foreach ($proc in $processes) {
                    Write-YWLog "Killing process: $($proc.Name) (PID: $($proc.Id))" -Level Info
                    try {
                        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    }
                    catch {
                        Write-YWLog "Could not kill process: $($_.Exception.Message)" -Level Warning
                    }
                }
            }

            Start-Sleep -Seconds 2

            # Step 3: Find and uninstall installed products
            $products = Get-CimInstance -ClassName Win32_Product -Filter "Name LIKE '%ConnectWise%' OR Name LIKE '%ScreenConnect%' OR Name LIKE '%ITSPlatform%'"

            if ($products) {
                foreach ($product in $products) {
                    Write-YWLog "Found installed product: $($product.Name)" -Level Info
                    Write-YWLog "Uninstalling $($product.Name)..." -Level Info

                    # Uninstall using product code
                    $uninstallArgs = @(
                        "/x"
                        $product.IdentifyingNumber
                        "/quiet"
                        "/norestart"
                        "/l*v"
                        "`"$tempPath\uninstall.log`""
                    )

                    $uninstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList ($uninstallArgs -join " ") -Wait -PassThru

                    if ($uninstallProcess.ExitCode -eq 0 -or $uninstallProcess.ExitCode -eq 3010) {
                        Write-YWLog "Successfully uninstalled $($product.Name)" -Level Success
                    }
                    else {
                        Write-YWLog "Uninstall completed with exit code: $($uninstallProcess.ExitCode)" -Level Warning
                    }
                }

                # Step 4: Wait longer for uninstall to fully complete
                Write-YWLog "Waiting for cleanup to complete..." -Level Info
                Start-Sleep -Seconds 10

                # Step 5: Clean up leftover directories
                $cleanupPaths = @(
                    "$env:ProgramFiles\ScreenConnect Client*",
                    "$env:ProgramFiles (x86)\ScreenConnect Client*",
                    "$env:ProgramFiles\ConnectWise Control*",
                    "$env:ProgramFiles (x86)\ConnectWise Control*"
                )

                foreach ($path in $cleanupPaths) {
                    $dirs = Get-Item -Path $path -ErrorAction SilentlyContinue
                    foreach ($dir in $dirs) {
                        Write-YWLog "Removing leftover directory: $($dir.FullName)" -Level Info
                        try {
                            Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
                            Write-YWLog "Directory removed successfully" -Level Success
                        }
                        catch {
                            Write-YWLog "Could not remove directory: $($_.Exception.Message)" -Level Warning
                        }
                    }
                }

                # Step 6: Retry installation
                Write-YWLog "Retrying installation after cleanup..." -Level Info
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $argString -Wait -PassThru
            }
            else {
                Write-YWLog "Could not find existing ConnectWise Control installation to remove" -Level Warning
                Write-YWLog "Manual uninstall may be required" -Level Warning
                return $false
            }
        }

        # Check installation result
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-YWLog "ConnectWise Control agent installed successfully" -Level Success

            # Wait for services to start
            Start-Sleep -Seconds 5

            # Verify service is running (check both old and new service names)
            $serviceNames = @(
                "ScreenConnect Client*",
                "ConnectWise Control Client*",
                "screenconnect*",
                "connectwise*",
                "ITSPlatform*"
            )

            $serviceFound = $false
            foreach ($serviceName in $serviceNames) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    Write-YWLog "Found service: $($service.DisplayName)" -Level Info
                    if ($service.Status -eq 'Running') {
                        Write-YWLog "Agent service is running" -Level Success
                        $serviceFound = $true
                        break
                    }
                    else {
                        Write-YWLog "Service found but not running (Status: $($service.Status))" -Level Warning
                        Write-YWLog "Attempting to start service..." -Level Info
                        try {
                            Start-Service -Name $service.Name -ErrorAction Stop
                            Write-YWLog "Service started successfully" -Level Success
                            $serviceFound = $true
                            break
                        }
                        catch {
                            Write-YWLog "Failed to start service: $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
            }

            if (-not $serviceFound) {
                Write-YWLog "Could not verify agent service status" -Level Warning
                Write-YWLog "Agent may still be initializing..." -Level Info
            }

            return $true
        }
        else {
            Write-YWLog "Agent installation failed with exit code: $($process.ExitCode)" -Level Error

            # Show log excerpt for troubleshooting
            if (Test-Path $logPath) {
                Write-YWLog "Installation log (last 30 lines):" -Level Info
                $logLines = Get-Content $logPath -Tail 30
                $logLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }

            Write-Host ""
            Write-Host "  Common exit codes:" -ForegroundColor Yellow
            Write-Host "    1603 - Fatal error during installation" -ForegroundColor Gray
            Write-Host "    1618 - Another installation is in progress" -ForegroundColor Gray
            Write-Host "    1619 - Package could not be opened" -ForegroundColor Gray
            Write-Host "    1638 - Another version is already installed" -ForegroundColor Gray
            Write-Host ""

            return $false
        }
    }
    catch {
        Write-YWLog "Error installing ConnectWise Control agent: $($_.Exception.Message)" -Level Error
        return $false
    }
    finally {
        # Cleanup
        if (Test-Path $tempPath) {
            Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
#endregion

#region Hardware Management
function Install-DellSystemUpdate {
    <#
    .SYNOPSIS
        Downloads and installs Dell System Update (DSU) utility.
    #>
    
    Write-YWLog "Detected Dell hardware" -Level Info
    Write-Phase "DELL DRIVER UPDATES" "Installing Dell System Update utility..."
    
    # Dell DSU download URL (latest version as of knowledge cutoff)
    $dsuUrl = "https://dl.dell.com/FOLDER09762248M/1/Systems-Management_Application_RPW7K_WN64_2.1.0.13_A00.EXE"
    $tempPath = "$env:TEMP\DSU"
    $installerPath = "$tempPath\DSU.exe"
    
    try {
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
        
        Write-YWLog "Downloading Dell System Update from: $dsuUrl" -Level Info
        
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($dsuUrl, $installerPath)
        
        if (Test-Path $installerPath) {
            $fileSize = [math]::Round((Get-Item $installerPath).Length / 1MB, 2)
            Write-YWLog "DSU downloaded successfully ($fileSize MB)" -Level Success
            
            # Prompt for execution
            Write-Host ""
            Write-Host "Dell System Update is ready to install." -ForegroundColor Cyan
            Write-Host "This will:" -ForegroundColor White
            Write-Host "  1. Install DSU utility" -ForegroundColor Gray
            Write-Host "  2. Scan for available updates" -ForegroundColor Gray
            Write-Host "  3. Apply critical firmware and driver updates" -ForegroundColor Gray
            Write-Host ""
            
            $execute = Get-UserConfirmation -Prompt "Execute Dell System Update now?"
            
            if ($execute) {
                Write-YWLog "Installing Dell System Update..." -Level Info
                $process = Start-Process -FilePath $installerPath -ArgumentList "/s" -Wait -PassThru
                
                if ($process.ExitCode -eq 0) {
                    Write-YWLog "Dell System Update installed successfully" -Level Success
                    
                    # Check if DSU executable exists
                    $dsuExe = "C:\Program Files\Dell\DELL System Update\DSU.exe"
                    if (Test-Path $dsuExe) {
                        Write-YWLog "Running Dell System Update scan and update..." -Level Info
                        Write-Host "  This may take several minutes..." -ForegroundColor Yellow
                        
                        # Run DSU with catalog and auto-apply
                        $dsuProcess = Start-Process -FilePath $dsuExe `
                            -ArgumentList "--catalog-location=https://downloads.dell.com --apply-updates" `
                            -Wait -PassThru -NoNewWindow
                        
                        if ($dsuProcess.ExitCode -eq 0) {
                            Write-YWLog "Dell System Update completed successfully" -Level Success
                        }
                        else {
                            Write-YWLog "DSU scan completed with code: $($dsuProcess.ExitCode)" -Level Warning
                        }
                        
                        return $true
                    }
                    else {
                        Write-YWLog "DSU installed but executable not found" -Level Warning
                        return $false
                    }
                }
                else {
                    Write-YWLog "Dell System Update installation failed" -Level Error
                    return $false
                }
            }
            else {
                Write-YWLog "Dell System Update installation skipped by user" -Level Warning
                Write-Host "  DSU installer saved to: $installerPath" -ForegroundColor Yellow
                return $false
            }
        }
        else {
            Write-YWLog "Failed to download Dell System Update" -Level Error
            return $false
        }
    }
    catch {
        Write-YWLog "Error with Dell System Update: $($_.Exception.Message)" -Level Error
        Write-Host "  Manual download: https://www.dell.com/support/kbdoc/en-us/000130590" -ForegroundColor Yellow
        return $false
    }
    finally {
        # Don't delete temp folder if user skipped execution (they may want to run it manually)
    }
}

function Prompt-HPDriverUpdates {
    <#
    .SYNOPSIS
        Prompts user with HP Service Pack for ProLiant information.
    #>
    
    Write-YWLog "Detected HP hardware" -Level Info
    Write-Phase "HP DRIVER UPDATES" "HP Service Pack for ProLiant (SPP) information..."
    
    Write-Host ""
    Write-Host "HP servers use the Service Pack for ProLiant (SPP) for driver updates." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Download SPP from:" -ForegroundColor White
    Write-Host "  https://support.hpe.com/connect/s/softwaredetails?softwareId=MTX-8a0b7f6801fa456e8acb6f1ba2" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "SPP includes:" -ForegroundColor White
    Write-Host "  - Firmware updates" -ForegroundColor Gray
    Write-Host "  - Driver updates" -ForegroundColor Gray
    Write-Host "  - System utilities" -ForegroundColor Gray
    Write-Host "  - iLO firmware" -ForegroundColor Gray
    Write-Host ""
    
    $openURL = Get-UserConfirmation -Prompt "Open HP SPP download page in browser?"
    
    if ($openURL) {
        Start-Process "https://support.hpe.com/connect/s/softwaredetails?softwareId=MTX-8a0b7f6801fa456e8acb6f1ba2"
        Write-YWLog "HP SPP page opened in browser" -Level Info
    }
    
    Write-Host ""
    Write-Host "After downloading SPP ISO:" -ForegroundColor Cyan
    Write-Host "  1. Mount the ISO" -ForegroundColor Gray
    Write-Host "  2. Run launch_sum.bat (for GUI) or hpsum.exe (for CLI)" -ForegroundColor Gray
    Write-Host "  3. Select updates to apply" -ForegroundColor Gray
    Write-Host ""
}
#endregion

#region Application Installation
function Install-Winget {
    <#
    .SYNOPSIS
        Installs winget (Windows Package Manager) if not present.
    .NOTES
        Requires Windows 10 1809+ or Windows Server 2019+.
        Winget requires Windows App Runtime framework which may not be available on older systems.
    #>

    Write-YWLog "Checking for winget..." -Level Info

    # Check if winget is already available
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-YWLog "Winget is already installed" -Level Success
        return $true
    }

    # Check Windows version - winget requires Windows 10 1809+ or Server 2019+
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-YWLog "Winget requires Windows 10 or newer - skipping installation" -Level Warning
        return $false
    }

    Write-YWLog "Winget not found - attempting installation..." -Level Info

    try {
        # Enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Step 1: Install Windows App Runtime (required dependency)
        Write-YWLog "Installing Windows App Runtime dependency..." -Level Info
        $appRuntimeUrl = "https://aka.ms/windowsappruntimeinstall"
        $appRuntimePath = "$env:TEMP\WindowsAppRuntime.exe"

        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($appRuntimeUrl, $appRuntimePath)

            if (Test-Path $appRuntimePath) {
                $process = Start-Process -FilePath $appRuntimePath -ArgumentList "/quiet" -Wait -PassThru
                if ($process.ExitCode -eq 0) {
                    Write-YWLog "Windows App Runtime installed successfully" -Level Success
                }
                else {
                    Write-YWLog "Windows App Runtime installation returned code: $($process.ExitCode)" -Level Warning
                }
                Remove-Item -Path $appRuntimePath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-YWLog "Could not install Windows App Runtime: $($_.Exception.Message)" -Level Warning
            Write-YWLog "Attempting winget install without runtime (may fail)..." -Level Info
        }

        # Step 2: Download and install App Installer (winget)
        $appInstallerUrl = "https://aka.ms/getwinget"
        $tempPath = "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle"

        Write-YWLog "Downloading App Installer..." -Level Info

        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($appInstallerUrl, $tempPath)

        if (Test-Path $tempPath) {
            $fileSize = [math]::Round((Get-Item $tempPath).Length / 1MB, 2)
            Write-YWLog "App Installer downloaded ($fileSize MB)" -Level Success

            # Install the package
            Write-YWLog "Installing App Installer..." -Level Info
            Add-AppxPackage -Path $tempPath -ErrorAction Stop

            Write-YWLog "App Installer installed successfully" -Level Success

            # Cleanup
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue

            # Refresh PATH and verify winget is now available
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

            Start-Sleep -Seconds 2

            $winget = Get-Command winget -ErrorAction SilentlyContinue
            if ($winget) {
                Write-YWLog "Winget is now available" -Level Success
                return $true
            }
            else {
                Write-YWLog "Winget installed but not yet in PATH - restart may be required" -Level Warning
                return $false
            }
        }
        else {
            Write-YWLog "Failed to download App Installer" -Level Error
            return $false
        }
    }
    catch {
        Write-YWLog "Error installing winget: $($_.Exception.Message)" -Level Warning
        Write-YWLog "Winget is not available on this system - will use direct downloads" -Level Info
        Write-Host ""
        Write-Host "  Note: Winget requires Windows App Runtime framework" -ForegroundColor Yellow
        Write-Host "  Installations will use direct MSI downloads instead" -ForegroundColor Gray
        Write-Host ""
        return $false
    }
}

function Install-WindowsTerminal {
    <#
    .SYNOPSIS
        Installs Windows Terminal using winget (automatic, no user interaction).
    #>

    Write-YWLog "Installing Windows Terminal..." -Level Info

    try {
        # Check if already installed
        $terminal = Get-AppxPackage -Name "Microsoft.WindowsTerminal*" -ErrorAction SilentlyContinue
        if ($terminal) {
            Write-YWLog "Windows Terminal already installed (version: $($terminal.Version))" -Level Success
            return $true
        }

        # Check if winget is available, install if not
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-YWLog "Winget not available - attempting to install..." -Level Info
            if (Install-Winget) {
                $winget = Get-Command winget -ErrorAction SilentlyContinue
            }
        }

        if ($winget) {
            Write-YWLog "Using winget to install Windows Terminal..." -Level Info
            $process = Start-Process -FilePath "winget" `
                -ArgumentList "install --id Microsoft.WindowsTerminal --silent --accept-package-agreements --accept-source-agreements" `
                -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -eq 0) {
                Write-YWLog "Windows Terminal installed successfully" -Level Success
                return $true
            }
            else {
                Write-YWLog "Winget installation failed with code: $($process.ExitCode)" -Level Warning
            }
        }
        else {
            Write-YWLog "Winget is not available and could not be installed" -Level Warning
        }

        # If winget failed or not available, provide manual instructions
        Write-YWLog "Windows Terminal could not be installed automatically" -Level Warning
        Write-Host ""
        Write-Host "  To install Windows Terminal manually:" -ForegroundColor Yellow
        Write-Host "  1. Open Microsoft Store" -ForegroundColor Gray
        Write-Host "  2. Search for 'Windows Terminal'" -ForegroundColor Gray
        Write-Host "  3. Click 'Get' or 'Install'" -ForegroundColor Gray
        Write-Host "  OR visit: https://aka.ms/terminal" -ForegroundColor Gray
        Write-Host ""

        return $false
    }
    catch {
        Write-YWLog "Error installing Windows Terminal: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Install-PowerShell7 {
    <#
    .SYNOPSIS
        Installs PowerShell 7 using winget or direct MSI download with retry logic.
    #>

    Write-YWLog "Installing PowerShell 7..." -Level Info

    try {
        # Check if already installed
        $ps7 = Get-Command pwsh -ErrorAction SilentlyContinue
        if ($ps7) {
            $version = & pwsh -Command '$PSVersionTable.PSVersion.ToString()'
            Write-YWLog "PowerShell 7 already installed (version: $version)" -Level Success
            return $true
        }

        # Check if winget is available, install if not
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-YWLog "Winget not available - attempting to install..." -Level Info
            if (Install-Winget) {
                $winget = Get-Command winget -ErrorAction SilentlyContinue
            }
        }

        if ($winget) {
            Write-YWLog "Using winget to install PowerShell 7..." -Level Info
            $process = Start-Process -FilePath "winget" `
                -ArgumentList "install --id Microsoft.PowerShell --silent --accept-package-agreements --accept-source-agreements" `
                -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -eq 0) {
                Write-YWLog "PowerShell 7 installed successfully" -Level Success
                return $true
            }
            else {
                Write-YWLog "Winget installation failed with code: $($process.ExitCode)" -Level Warning
            }
        }
        else {
            Write-YWLog "Winget is not available, attempting direct download..." -Level Info
        }

        # Fallback to MSI download with retry logic
        Write-YWLog "Downloading PowerShell 7 MSI installer..." -Level Info

        # Enable TLS 1.2 for downloads
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Get the latest release info from GitHub API
        $tempPath = "$env:TEMP\PowerShell7.msi"
        $ps7Url = $null

        try {
            Write-YWLog "Querying GitHub API for latest PowerShell release..." -Level Info
            $apiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
            $releaseInfo = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop

            # Find the x64 MSI asset
            $asset = $releaseInfo.assets | Where-Object { $_.name -like "*win-x64.msi" } | Select-Object -First 1

            if ($asset) {
                $ps7Url = $asset.browser_download_url
                Write-YWLog "Found PowerShell $($releaseInfo.tag_name) download URL" -Level Success
            }
            else {
                Write-YWLog "Could not find x64 MSI in latest release" -Level Warning
            }
        }
        catch {
            Write-YWLog "GitHub API query failed: $($_.Exception.Message)" -Level Warning
            Write-YWLog "Falling back to direct download URL..." -Level Info
        }

        # Fallback to known working URL if API failed
        if (-not $ps7Url) {
            # Use latest stable version (not preview)
            $ps7Url = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/PowerShell-7.5.0-win-x64.msi"
            Write-YWLog "Using fallback URL for PowerShell 7.5.0 (stable)" -Level Info
        }

        # Retry logic: up to 3 attempts with exponential backoff
        $maxRetries = 3
        $retryCount = 0
        $downloadSuccess = $false

        while ($retryCount -lt $maxRetries -and -not $downloadSuccess) {
            try {
                if ($retryCount -gt 0) {
                    $waitSeconds = [Math]::Pow(2, $retryCount)
                    Write-YWLog "Retry attempt $retryCount of $maxRetries (waiting $waitSeconds seconds)..." -Level Info
                    Start-Sleep -Seconds $waitSeconds
                }

                Write-YWLog "Downloading from: $ps7Url" -Level Info
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($ps7Url, $tempPath)

                if (Test-Path $tempPath) {
                    $fileSize = [math]::Round((Get-Item $tempPath).Length / 1MB, 2)
                    Write-YWLog "PowerShell 7 MSI downloaded ($fileSize MB)" -Level Success
                    $downloadSuccess = $true
                }
            }
            catch {
                $retryCount++
                if ($retryCount -lt $maxRetries) {
                    Write-YWLog "Download failed: $($_.Exception.Message)" -Level Warning
                }
                else {
                    Write-YWLog "Download failed after $maxRetries attempts: $($_.Exception.Message)" -Level Error
                    throw
                }
            }
        }

        if ($downloadSuccess -and (Test-Path $tempPath)) {
            # Install with full features
            $msiArgs = @(
                "/i"
                "`"$tempPath`""
                "/quiet"
                "/norestart"
                "ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1"
                "ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1"
                "ENABLE_PSREMOTING=1"
                "REGISTER_MANIFEST=1"
            )

            $argString = $msiArgs -join " "
            Write-YWLog "Installing PowerShell 7..." -Level Info

            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $argString -Wait -PassThru

            if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                Write-YWLog "PowerShell 7 installed successfully" -Level Success
                Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue

                # Verify installation
                # Refresh environment variables to detect pwsh
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                $ps7 = Get-Command pwsh -ErrorAction SilentlyContinue
                if ($ps7) {
                    $version = & pwsh -Command '$PSVersionTable.PSVersion.ToString()'
                    Write-YWLog "Installed version: $version" -Level Success
                }

                return $true
            }
            else {
                Write-YWLog "PowerShell 7 installation failed with code: $($process.ExitCode)" -Level Error
                return $false
            }
        }
        else {
            Write-YWLog "Failed to download PowerShell 7 MSI" -Level Error
            return $false
        }
    }
    catch {
        Write-YWLog "Error installing PowerShell 7: $($_.Exception.Message)" -Level Error
        Write-Host ""
        Write-Host "  Manual download: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Yellow
        Write-Host ""
        return $false
    }
}
#endregion

#region System Configuration
function Set-NTPConfiguration {
    <#
    .SYNOPSIS
        Configures Windows Time service with specified NTP server.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Server
    )
    
    Write-YWLog "Configuring NTP time source: $Server" -Level Info
    
    try {
        # Stop Windows Time service
        Stop-Service -Name w32time -Force -ErrorAction SilentlyContinue
        
        # Configure NTP server
        & w32tm /config /manualpeerlist:$Server /syncfromflags:manual /reliable:YES /update | Out-Null
        
        # Start Windows Time service
        Start-Service -Name w32time
        
        # Force synchronization
        Write-YWLog "Synchronizing time with $Server..." -Level Info
        & w32tm /resync /force | Out-Null
        
        # Verify configuration
        Start-Sleep -Seconds 3
        $timeSource = & w32tm /query /source
        $status = & w32tm /query /status
        
        Write-YWLog "NTP configured successfully" -Level Success
        Write-Host "  Current time source: $timeSource" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-YWLog "Error configuring NTP: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Disable-ServerManagerStartup {
    <#
    .SYNOPSIS
        Disables Server Manager auto-start on login.
    #>
    
    Write-YWLog "Disabling Server Manager auto-start..." -Level Info
    
    try {
        # Disable Server Manager startup in registry
        $regPath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "DoNotOpenServerManagerAtLogon" -Value 1 -Type DWord
        
        # Also disable for current user
        $userRegPath = "HKCU:\SOFTWARE\Microsoft\ServerManager"
        if (-not (Test-Path $userRegPath)) {
            New-Item -Path $userRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $userRegPath -Name "DoNotOpenServerManagerAtLogon" -Value 1 -Type DWord
        
        Write-YWLog "Server Manager auto-start disabled" -Level Success
        return $true
    }
    catch {
        Write-YWLog "Error disabling Server Manager: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-OptimalPowerPlan {
    <#
    .SYNOPSIS
        Configures power plan to High Performance for optimal server operation.
    #>
    
    Write-YWLog "Setting power plan to High Performance..." -Level Info
    
    try {
        # Get High Performance GUID
        $highPerf = powercfg /list | Select-String "High performance" | ForEach-Object { 
            if ($_ -match '\(([a-f0-9-]+)\)') { $matches[1] }
        }
        
        if ($highPerf) {
            powercfg /setactive $highPerf | Out-Null
            
            # Verify
            $activePlan = powercfg /getactivescheme
            if ($activePlan -match "High performance") {
                Write-YWLog "Power plan set to High Performance" -Level Success
                return $true
            }
        }
        
        Write-YWLog "High Performance power plan not available" -Level Warning
        return $false
    }
    catch {
        Write-YWLog "Error setting power plan: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Optimize-EventLogSizes {
    <#
    .SYNOPSIS
        Configures event log maximum sizes for improved troubleshooting.
    #>
    
    Write-YWLog "Configuring event log sizes..." -Level Info
    
    try {
        $logs = @{
            'Application' = 100MB
            'System'      = 100MB
            'Security'    = 200MB
        }
        
        foreach ($log in $logs.GetEnumerator()) {
            $logSizeKB = $log.Value / 1KB
            & wevtutil sl $log.Key /ms:$logSizeKB | Out-Null
        }
        
        Write-YWLog "Event log sizes configured (App/Sys: 100MB, Security: 200MB)" -Level Success
        return $true
    }
    catch {
        Write-YWLog "Error configuring event logs: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Enable-RemoteDesktopOptimizations {
    <#
    .SYNOPSIS
        Enables and optimizes Remote Desktop settings.
    #>
    
    Write-YWLog "Optimizing Remote Desktop settings..." -Level Info
    
    try {
        # Enable RDP
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
            -Name "fDenyTSConnections" -Value 0 -Force
        
        # Enable NLA (Network Level Authentication)
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name "UserAuthentication" -Value 1 -Force
        
        # Configure RDP keep-alive
        $tsRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        if (-not (Test-Path $tsRegPath)) {
            New-Item -Path $tsRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $tsRegPath -Name "KeepAliveEnable" -Value 1 -Force
        Set-ItemProperty -Path $tsRegPath -Name "KeepAliveInterval" -Value 1 -Force
        
        # Enable firewall rule
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        Write-YWLog "Remote Desktop enabled and optimized" -Level Success
        return $true
    }
    catch {
        Write-YWLog "Error optimizing Remote Desktop: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Disable-IEESCConfiguration {
    <#
    .SYNOPSIS
        Disables Internet Explorer Enhanced Security Configuration.
    #>
    
    Write-YWLog "Disabling Internet Explorer Enhanced Security Configuration..." -Level Info
    
    try {
        # Disable for Administrators
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" `
            -Name "IsInstalled" -Value 0 -Force
        
        # Disable for Users
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" `
            -Name "IsInstalled" -Value 0 -Force
        
        Write-YWLog "IE Enhanced Security Configuration disabled" -Level Success
        return $true
    }
    catch {
        Write-YWLog "Error disabling IE ESC: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-WindowsUpdateConfiguration {
    <#
    .SYNOPSIS
        Configures Windows Update for manual installation with automatic download.
    #>
    
    Write-YWLog "Configuring Windows Update settings..." -Level Info
    
    try {
        # Configure automatic updates (download but don't auto-install)
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $auPath = "$wuPath\AU"
        
        if (-not (Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }
        
        if (-not (Test-Path $auPath)) {
            New-Item -Path $auPath -Force | Out-Null
        }
        
        # AUOptions: 3 = Auto download and notify for install
        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 3 -Type DWord -Force
        Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
        
        Write-YWLog "Windows Update configured (auto download, manual install)" -Level Success
        return $true
    }
    catch {
        Write-YWLog "Error configuring Windows Update: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Enable-AuditLogging {
    <#
    .SYNOPSIS
        Enables advanced audit logging for security monitoring.
    #>

    Write-YWLog "Enabling advanced audit logging..." -Level Info

    try {
        # Enable audit subcategories (correct syntax for auditpol)
        $auditSubcategories = @(
            "Credential Validation",
            "Kerberos Authentication Service",
            "Kerberos Service Ticket Operations",
            "User Account Management",
            "Computer Account Management",
            "Security Group Management",
            "Logon",
            "Logoff",
            "Account Lockout",
            "Special Logon",
            "File System",
            "Registry",
            "Audit Policy Change",
            "Authentication Policy Change",
            "Sensitive Privilege Use",
            "Process Creation",
            "Security State Change",
            "Security System Extension",
            "System Integrity"
        )

        $successCount = 0
        $failCount = 0

        foreach ($subcategory in $auditSubcategories) {
            try {
                $result = & auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $successCount++
                }
                else {
                    $failCount++
                    Write-YWLog "Failed to enable audit for: $subcategory" -Level Warning
                }
            }
            catch {
                $failCount++
                Write-YWLog "Error enabling audit for $subcategory : $($_.Exception.Message)" -Level Warning
            }
        }

        if ($successCount -gt 0) {
            Write-YWLog "Advanced audit logging enabled ($successCount subcategories configured)" -Level Success
            return $true
        }
        else {
            Write-YWLog "Failed to enable audit logging" -Level Error
            return $false
        }
    }
    catch {
        Write-YWLog "Error enabling audit logging: $($_.Exception.Message)" -Level Error
        return $false
    }
}
#endregion

#region Main Script
function Start-ServerBaseline {
    Show-YWBanner
    
    Write-Host "Server Baseline Configuration" -ForegroundColor $Script:Config.Colors.Primary
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host ""
    
    # System information
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $isVM = Test-IsVirtualMachine
    $manufacturer = Get-HardwareManufacturer
    
    Write-YWLog "System: $($computerSystem.Name)" -Level Info
    Write-YWLog "OS: $($os.Caption) - $($os.Version)" -Level Info
    Write-YWLog "Manufacturer: $manufacturer" -Level Info
    Write-YWLog "Virtual Machine: $isVM" -Level Info
    Write-Host ""
    
    #==========================================================================
    # Phase 1: ConnectWise Control Installation
    #==========================================================================
    if (-not $SkipRMMInstall) {
        Write-Phase "CONNECTWISE CONTROL" "Installing remote monitoring agent..."

        # Prompt for agent token if not provided
        if ([string]::IsNullOrWhiteSpace($AgentToken)) {
            Write-Host ""
            Write-Host "  ConnectWise Control Agent Installation" -ForegroundColor Cyan
            Write-Host "  Agent token is REQUIRED for installation." -ForegroundColor Yellow
            Write-Host ""
            $AgentToken = Get-UserInput -Prompt "Enter Agent Token (or press Enter to skip agent installation)" -Default ""
        }

        # Install embedded agent with token (MANDATORY - skip if not provided)
        if (-not [string]::IsNullOrWhiteSpace($AgentToken)) {
            $Script:Results.RMMInstalled = Install-ConnectWiseControl -Token $AgentToken
        }
        else {
            Write-YWLog "No agent token provided - SKIPPING ConnectWise Control installation" -Level Warning
            Write-Host "  Agent installation skipped. Run script again with -AgentToken parameter to install." -ForegroundColor Yellow
            $Script:Results.RMMInstalled = $false
        }

        Write-Host ""
    }
    
    #==========================================================================
    # Phase 2: Hardware Driver Updates
    #==========================================================================
    if (-not $SkipDriverUpdates) {
        if ($isVM) {
            Write-YWLog "Virtual machine detected - skipping hardware driver updates" -Level Info
            Write-Host ""
        }
        else {
            if ($manufacturer -match "Dell") {
                $Script:Results.DriversUpdated = Install-DellSystemUpdate
            }
            elseif ($manufacturer -match "HP|Hewlett") {
                Prompt-HPDriverUpdates
            }
            else {
                Write-YWLog "Unknown hardware manufacturer ($manufacturer) - skipping driver updates" -Level Warning
            }
            
            Write-Host ""
        }
    }
    
    #==========================================================================
    # Phase 3: NTP Configuration
    #==========================================================================
    Write-Phase "TIME SYNCHRONIZATION" "Configuring NTP time source..."
    
    if (-not $NTPServer) {
        $customNTP = Get-UserInput -Prompt "Enter NTP server" -Default "us.pool.ntp.org"
        $NTPServer = if ($customNTP) { $customNTP } else { "us.pool.ntp.org" }
    }
    
    $Script:Results.NTPConfigured = Set-NTPConfiguration -Server $NTPServer
    Write-Host ""
    
    #==========================================================================
    # Phase 4: Server Manager
    #==========================================================================
    if (-not $SkipServerManager) {
        Write-Phase "SERVER MANAGER" "Disabling auto-start on login..."
        
        $disableSM = Get-UserConfirmation -Prompt "Disable Server Manager auto-start?" -Default $true
        
        if ($disableSM) {
            $Script:Results.ServerManagerDisabled = Disable-ServerManagerStartup
        }
        
        Write-Host ""
    }
    
    #==========================================================================
    # Phase 5: Windows Terminal
    #==========================================================================
    if (-not $SkipTerminalInstall) {
        Write-Phase "WINDOWS TERMINAL" "Installing modern terminal application..."
        
        $installTerminal = Get-UserConfirmation -Prompt "Install Windows Terminal?" -Default $true
        
        if ($installTerminal) {
            $Script:Results.TerminalInstalled = Install-WindowsTerminal
        }
        
        Write-Host ""
    }
    
    #==========================================================================
    # Phase 6: PowerShell 7
    #==========================================================================
    if (-not $SkipPowerShell7) {
        Write-Phase "POWERSHELL 7" "Installing modern PowerShell runtime..."
        
        $installPS7 = Get-UserConfirmation -Prompt "Install PowerShell 7?" -Default $true
        
        if ($installPS7) {
            $Script:Results.PowerShell7Installed = Install-PowerShell7
        }
        
        Write-Host ""
    }
    
    #==========================================================================
    # Phase 7: System Optimizations
    #==========================================================================
    Write-Phase "SYSTEM OPTIMIZATIONS" "Applying server baseline settings..."
    
    $optimizations = @(
        @{ Name = "Power Plan"; Function = { Set-OptimalPowerPlan } },
        @{ Name = "Event Log Sizes"; Function = { Optimize-EventLogSizes } },
        @{ Name = "Remote Desktop"; Function = { Enable-RemoteDesktopOptimizations } },
        @{ Name = "Windows Update"; Function = { Set-WindowsUpdateConfiguration } },
        @{ Name = "Audit Logging"; Function = { Enable-AuditLogging } }
    )
    
    if ($DisableIESecurity) {
        $optimizations += @{ Name = "IE ESC Disable"; Function = { Disable-IEESCConfiguration } }
    }
    
    foreach ($opt in $optimizations) {
        try {
            & $opt.Function | Out-Null
        }
        catch {
            Write-YWLog "Error applying $($opt.Name): $($_.Exception.Message)" -Level Warning
        }
    }
    
    $Script:Results.OptimizationsApplied = $true
    Write-Host ""
    
    #==========================================================================
    # Summary Report
    #==========================================================================
    Write-Host ("=" * 81) -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host "BASELINE CONFIGURATION SUMMARY" -ForegroundColor $Script:Config.Colors.Primary
    Write-Host ("=" * 81) -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host ""
    
    $statusIcon = @{ $true = '[X]'; $false = '[ ]' }
    
    Write-Host "$($statusIcon[$Script:Results.RMMInstalled]) ConnectWise Control Agent" `
        -ForegroundColor $(if ($Script:Results.RMMInstalled) { 'Green' } else { 'Gray' })
    
    Write-Host "$($statusIcon[$Script:Results.DriversUpdated]) Hardware Driver Updates" `
        -ForegroundColor $(if ($Script:Results.DriversUpdated) { 'Green' } else { 'Gray' })
    
    Write-Host "$($statusIcon[$Script:Results.NTPConfigured]) NTP Time Source" `
        -ForegroundColor $(if ($Script:Results.NTPConfigured) { 'Green' } else { 'Gray' })
    
    Write-Host "$($statusIcon[$Script:Results.ServerManagerDisabled]) Server Manager Disabled" `
        -ForegroundColor $(if ($Script:Results.ServerManagerDisabled) { 'Green' } else { 'Gray' })
    
    Write-Host "$($statusIcon[$Script:Results.TerminalInstalled]) Windows Terminal" `
        -ForegroundColor $(if ($Script:Results.TerminalInstalled) { 'Green' } else { 'Gray' })
    
    Write-Host "$($statusIcon[$Script:Results.PowerShell7Installed]) PowerShell 7" `
        -ForegroundColor $(if ($Script:Results.PowerShell7Installed) { 'Green' } else { 'Gray' })
    
    Write-Host "$($statusIcon[$Script:Results.OptimizationsApplied]) System Optimizations" `
        -ForegroundColor $(if ($Script:Results.OptimizationsApplied) { 'Green' } else { 'Gray' })
    
    Write-Host ""
    Write-Host "Baseline configuration completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" `
        -ForegroundColor $Script:Config.Colors.Secondary
    Write-Host ""
    
    # Additional Suggestions
    Write-Host "ADDITIONAL RECOMMENDATIONS:" -ForegroundColor $Script:Config.Colors.Primary
    Write-Host ""
    Write-Host "  [1] Configure antivirus exclusions for applications" -ForegroundColor Cyan
    Write-Host "  [2] Review and configure Windows Firewall rules" -ForegroundColor Cyan
    Write-Host "  [3] Install required server roles (IIS, DNS, AD, etc.)" -ForegroundColor Cyan
    Write-Host "  [4] Configure backup solution" -ForegroundColor Cyan
    Write-Host "  [5] Enable BitLocker drive encryption (if applicable)" -ForegroundColor Cyan
    Write-Host "  [6] Configure performance monitoring baselines" -ForegroundColor Cyan
    Write-Host ""
    
    # Prompt for reboot
    $reboot = Get-UserConfirmation -Prompt "A reboot is recommended. Reboot now?" -Default $false
    
    if ($reboot) {
        Write-YWLog "System will reboot in 60 seconds..." -Level Warning
        Write-Host "  Press Ctrl+C to cancel" -ForegroundColor Yellow
        shutdown /r /t 60 /c "Rebooting to complete server baseline configuration"
    }
    
    return $Script:Results
}

# Execute
$baselineResults = Start-ServerBaseline
$baselineResults
#endregion
