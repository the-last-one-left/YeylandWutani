<#
.SYNOPSIS
    Creates a temporary SQL Server sysadmin account when locked out of an instance.

.DESCRIPTION
    This script recovers access to a SQL Server instance by creating a new sysadmin
    login using single-user mode. Run this locally on the SQL Server as a Windows
    local administrator.
    
    The process:
    1. Stops the SQL Server service
    2. Starts SQL Server in single-user mode (-m)
    3. Creates a new SQL login with sysadmin role
    4. Restarts SQL Server in normal multi-user mode
    
    IMPORTANT: This script requires local administrator privileges and must be run
    directly on the SQL Server host. Single-user mode blocks all other connections.

.PARAMETER InstanceName
    SQL Server instance name. Use 'MSSQLSERVER' for default instance or the 
    instance name for named instances (e.g., 'SQLEXPRESS', 'SQL2019').
    Default: MSSQLSERVER

.PARAMETER LoginName
    Name for the new SQL Server login.
    Default: TempSA

.PARAMETER Password
    Password for the new SQL Server login.
    Default: password

.PARAMETER ServiceTimeout
    Timeout in seconds to wait for service operations.
    Default: 60

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\New-SQLTempAdmin.ps1
    Creates 'TempSA' login with password 'password' on default instance.

.EXAMPLE
    .\New-SQLTempAdmin.ps1 -InstanceName "SQLEXPRESS" -LoginName "RecoveryAdmin" -Password "Str0ngP@ss!"
    Creates 'RecoveryAdmin' on the SQLEXPRESS named instance.

.EXAMPLE
    .\New-SQLTempAdmin.ps1 -Force
    Creates the account without confirmation prompts.

.NOTES
    Author:         Yeyland Wutani LLC
    Version:        1.0.0
    Purpose:        MSP SQL Server Access Recovery
    Requirements:   - Local Administrator privileges
                    - SQL Server service must be running initially
                    - SQLCMD utility (included with SQL Server)

.LINK
    https://github.com/YeylandWutani
    https://www.sqlshack.com/recover-lost-sa-password/
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$InstanceName = "MSSQLSERVER",
    
    [Parameter(Position = 1)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9_]*$')]
    [string]$LoginName = "TempSA",
    
    [Parameter(Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]$Password = "password",
    
    [Parameter()]
    [ValidateRange(30, 300)]
    [int]$ServiceTimeout = 60,
    
    [Parameter()]
    [switch]$Force
)

#region Banner
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
    $border  = "=" * 81
    
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
#endregion

#region Helper Functions
function Write-StatusMessage {
    <#
    .SYNOPSIS
        Writes formatted status messages to console.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Progress')]
        [string]$Type = 'Info'
    )
    
    $prefix = switch ($Type) {
        'Info'     { "[*]"; $color = "Cyan" }
        'Success'  { "[+]"; $color = "Green" }
        'Warning'  { "[!]"; $color = "Yellow" }
        'Error'    { "[-]"; $color = "Red" }
        'Progress' { "[>]"; $color = "DarkYellow" }
    }
    
    Write-Host "$prefix " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Get-SQLServiceName {
    <#
    .SYNOPSIS
        Returns the correct service name for the SQL Server instance.
    #>
    param([string]$Instance)
    
    if ($Instance -eq "MSSQLSERVER" -or [string]::IsNullOrWhiteSpace($Instance)) {
        return "MSSQLSERVER"
    }
    else {
        return "MSSQL`$$Instance"
    }
}

function Get-SQLCmdServerName {
    <#
    .SYNOPSIS
        Returns the correct server string for SQLCMD connection.
    #>
    param([string]$Instance)
    
    if ($Instance -eq "MSSQLSERVER" -or [string]::IsNullOrWhiteSpace($Instance)) {
        return "localhost"
    }
    else {
        return "localhost\$Instance"
    }
}

function Test-SqlCmdAvailable {
    <#
    .SYNOPSIS
        Checks if SQLCMD is available in the system PATH.
    #>
    
    $sqlcmd = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue
    if ($sqlcmd) {
        return $true
    }
    
    # Check common SQL Server installation paths
    $commonPaths = @(
        "${env:ProgramFiles}\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\sqlcmd.exe",
        "${env:ProgramFiles}\Microsoft SQL Server\*\Tools\Binn\sqlcmd.exe",
        "${env:ProgramFiles(x86)}\Microsoft SQL Server\*\Tools\Binn\sqlcmd.exe"
    )
    
    foreach ($pathPattern in $commonPaths) {
        $found = Get-Item $pathPattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            # Add to PATH for this session
            $env:PATH += ";$($found.DirectoryName)"
            return $true
        }
    }
    
    return $false
}

function Wait-ServiceState {
    <#
    .SYNOPSIS
        Waits for a Windows service to reach the specified state.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Running', 'Stopped')]
        [string]$DesiredState,
        
        [Parameter()]
        [int]$TimeoutSeconds = 60
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq $DesiredState) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    
    return $false
}

function Stop-SQLServerService {
    <#
    .SYNOPSIS
        Stops the SQL Server service and dependent services.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [Parameter()]
        [int]$TimeoutSeconds = 60
    )
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "SQL Server service '$ServiceName' not found."
    }
    
    if ($service.Status -eq 'Stopped') {
        Write-StatusMessage "Service '$ServiceName' is already stopped." -Type Info
        return $true
    }
    
    Write-StatusMessage "Stopping SQL Server service '$ServiceName'..." -Type Progress
    
    # Stop dependent services first
    $dependents = Get-Service -Name $ServiceName -DependentServices -ErrorAction SilentlyContinue
    foreach ($dep in $dependents) {
        if ($dep.Status -ne 'Stopped') {
            Write-StatusMessage "Stopping dependent service: $($dep.Name)" -Type Info
            Stop-Service -Name $dep.Name -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Stop the main service
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    
    if (Wait-ServiceState -ServiceName $ServiceName -DesiredState 'Stopped' -TimeoutSeconds $TimeoutSeconds) {
        Write-StatusMessage "Service stopped successfully." -Type Success
        return $true
    }
    else {
        throw "Timeout waiting for service to stop."
    }
}

function Start-SQLServerSingleUser {
    <#
    .SYNOPSIS
        Starts SQL Server in single-user mode using net start.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [Parameter()]
        [int]$TimeoutSeconds = 60
    )
    
    Write-StatusMessage "Starting SQL Server in single-user mode..." -Type Progress
    
    # Use net start for single-user mode parameter support
    $startArgs = if ($ServiceName -eq "MSSQLSERVER") {
        "start MSSQLSERVER /m"
    }
    else {
        "start `"$ServiceName`" /m"
    }
    
    $process = Start-Process -FilePath "net.exe" -ArgumentList $startArgs -Wait -PassThru -NoNewWindow
    
    # Give it a moment to fully initialize
    Start-Sleep -Seconds 3
    
    if (Wait-ServiceState -ServiceName $ServiceName -DesiredState 'Running' -TimeoutSeconds $TimeoutSeconds) {
        Write-StatusMessage "SQL Server started in single-user mode." -Type Success
        return $true
    }
    else {
        throw "Timeout waiting for service to start in single-user mode."
    }
}

function Start-SQLServerNormal {
    <#
    .SYNOPSIS
        Starts SQL Server in normal multi-user mode.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [Parameter()]
        [int]$TimeoutSeconds = 60
    )
    
    Write-StatusMessage "Starting SQL Server in normal mode..." -Type Progress
    
    Start-Service -Name $ServiceName -ErrorAction Stop
    
    if (Wait-ServiceState -ServiceName $ServiceName -DesiredState 'Running' -TimeoutSeconds $TimeoutSeconds) {
        Write-StatusMessage "SQL Server started successfully." -Type Success
        return $true
    }
    else {
        throw "Timeout waiting for service to start."
    }
}

function New-SQLLogin {
    <#
    .SYNOPSIS
        Creates a new SQL Server login with sysadmin role using SQLCMD.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServerName,
        
        [Parameter(Mandatory)]
        [string]$LoginName,
        
        [Parameter(Mandatory)]
        [string]$Password
    )
    
    Write-StatusMessage "Creating SQL login '$LoginName'..." -Type Progress
    
    # Escape single quotes in password for T-SQL
    $escapedPassword = $Password.Replace("'", "''")
    
    # Build T-SQL commands
    # Using ALTER SERVER ROLE (SQL 2012+) as primary, with sp_addsrvrolemember as fallback
    $sqlCommands = @"
-- Create the login
CREATE LOGIN [$LoginName] WITH PASSWORD = N'$escapedPassword', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
GO

-- Add to sysadmin role (SQL 2012+ syntax)
BEGIN TRY
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$LoginName];
END TRY
BEGIN CATCH
    -- Fallback for SQL 2008 and earlier
    EXEC sp_addsrvrolemember @loginame = N'$LoginName', @rolename = N'sysadmin';
END CATCH
GO
"@
    
    # Execute via SQLCMD with Windows Authentication (trusted connection)
    # The -E flag uses Windows Authentication which works because local admin = sysadmin in single-user mode
    $tempFile = [System.IO.Path]::GetTempFileName()
    $tempFile = [System.IO.Path]::ChangeExtension($tempFile, ".sql")
    
    try {
        $sqlCommands | Out-File -FilePath $tempFile -Encoding ASCII
        
        $sqlcmdArgs = @(
            "-S", $ServerName,
            "-E",                    # Windows Authentication
            "-i", $tempFile,         # Input file
            "-b"                     # Exit on error
        )
        
        $result = & sqlcmd.exe @sqlcmdArgs 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            $errorMsg = ($result | Out-String).Trim()
            throw "SQLCMD failed with exit code $exitCode. Output: $errorMsg"
        }
        
        Write-StatusMessage "Login '$LoginName' created and added to sysadmin role." -Type Success
        return $true
    }
    finally {
        # Clean up temp file
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-SQLLogin {
    <#
    .SYNOPSIS
        Verifies the new SQL login can connect.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ServerName,
        
        [Parameter(Mandatory)]
        [string]$LoginName,
        
        [Parameter(Mandatory)]
        [string]$Password
    )
    
    Write-StatusMessage "Verifying login..." -Type Progress
    
    $testQuery = "SELECT SUSER_NAME() AS CurrentUser, IS_SRVROLEMEMBER('sysadmin') AS IsSysAdmin"
    
    $result = & sqlcmd.exe -S $ServerName -U $LoginName -P $Password -Q $testQuery -h -1 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-StatusMessage "Login verification successful." -Type Success
        return $true
    }
    else {
        Write-StatusMessage "Login verification failed. The account may still work - try connecting manually." -Type Warning
        return $false
    }
}
#endregion

#region Main Execution
function Invoke-SQLTempAdminCreation {
    <#
    .SYNOPSIS
        Main execution function for creating the temporary SQL admin account.
    #>
    
    Show-YWBanner
    
    Write-Host "SQL Server Temporary Admin Account Recovery" -ForegroundColor DarkYellow
    Write-Host "=" * 45 -ForegroundColor Gray
    Write-Host ""
    
    # Display configuration
    $serviceName = Get-SQLServiceName -Instance $InstanceName
    $serverName = Get-SQLCmdServerName -Instance $InstanceName
    
    Write-StatusMessage "Configuration:" -Type Info
    Write-Host "   Instance:     $InstanceName" -ForegroundColor White
    Write-Host "   Service:      $serviceName" -ForegroundColor White
    Write-Host "   Server:       $serverName" -ForegroundColor White
    Write-Host "   New Login:    $LoginName" -ForegroundColor White
    Write-Host "   Password:     $('*' * $Password.Length)" -ForegroundColor White
    Write-Host ""
    
    # Verify prerequisites
    Write-StatusMessage "Checking prerequisites..." -Type Progress
    
    # Check for admin privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-StatusMessage "This script must be run as Administrator." -Type Error
        return $false
    }
    Write-StatusMessage "Running with Administrator privileges." -Type Success
    
    # Check for SQLCMD
    if (-not (Test-SqlCmdAvailable)) {
        Write-StatusMessage "SQLCMD utility not found. Ensure SQL Server tools are installed." -Type Error
        Write-Host ""
        Write-Host "   Install SQL Server command line utilities from:" -ForegroundColor Yellow
        Write-Host "   https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility" -ForegroundColor Cyan
        return $false
    }
    Write-StatusMessage "SQLCMD utility found." -Type Success
    
    # Check SQL Server service exists
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-StatusMessage "SQL Server service '$serviceName' not found on this system." -Type Error
        Write-Host ""
        Write-Host "   Available SQL Server services:" -ForegroundColor Yellow
        Get-Service | Where-Object { $_.Name -like "MSSQL*" } | ForEach-Object {
            Write-Host "   - $($_.Name) [$($_.Status)]" -ForegroundColor Cyan
        }
        return $false
    }
    Write-StatusMessage "SQL Server service '$serviceName' found. Status: $($service.Status)" -Type Success
    
    Write-Host ""
    
    # Confirmation prompt
    if (-not $Force -and -not $PSCmdlet.ShouldProcess($serviceName, "Create temporary admin account")) {
        Write-Host "WARNING: This operation will:" -ForegroundColor Yellow
        Write-Host "  1. Stop the SQL Server service (disconnecting all users)" -ForegroundColor White
        Write-Host "  2. Start SQL Server in single-user mode" -ForegroundColor White
        Write-Host "  3. Create a new sysadmin login" -ForegroundColor White
        Write-Host "  4. Restart SQL Server in normal mode" -ForegroundColor White
        Write-Host ""
        
        $confirmation = Read-Host "Continue? (Y/N)"
        if ($confirmation -notmatch '^[Yy]') {
            Write-StatusMessage "Operation cancelled by user." -Type Warning
            return $false
        }
    }
    
    Write-Host ""
    
    # Execute recovery process
    try {
        # Step 1: Stop SQL Server
        Stop-SQLServerService -ServiceName $serviceName -TimeoutSeconds $ServiceTimeout
        
        # Brief pause to ensure clean shutdown
        Start-Sleep -Seconds 2
        
        # Step 2: Start in single-user mode
        Start-SQLServerSingleUser -ServiceName $serviceName -TimeoutSeconds $ServiceTimeout
        
        # Step 3: Create the login
        New-SQLLogin -ServerName $serverName -LoginName $LoginName -Password $Password
        
        # Step 4: Stop single-user mode
        Stop-SQLServerService -ServiceName $serviceName -TimeoutSeconds $ServiceTimeout
        
        # Brief pause
        Start-Sleep -Seconds 2
        
        # Step 5: Start normal mode
        Start-SQLServerNormal -ServiceName $serviceName -TimeoutSeconds $ServiceTimeout
        
        # Step 6: Verify login (optional - may fail if SQL Auth not enabled)
        Start-Sleep -Seconds 3
        Test-SQLLogin -ServerName $serverName -LoginName $LoginName -Password $Password
        
        Write-Host ""
        Write-Host "=" * 60 -ForegroundColor Gray
        Write-StatusMessage "Recovery complete!" -Type Success
        Write-Host ""
        Write-Host "   Connection Details:" -ForegroundColor DarkYellow
        Write-Host "   Server:    $serverName" -ForegroundColor White
        Write-Host "   Login:     $LoginName" -ForegroundColor White
        Write-Host "   Password:  $Password" -ForegroundColor White
        Write-Host ""
        Write-Host "   Connect via SSMS with SQL Server Authentication" -ForegroundColor Gray
        Write-Host ""
        Write-StatusMessage "Remember to change the password and remove this account when done." -Type Warning
        Write-Host "=" * 60 -ForegroundColor Gray
        
        return $true
    }
    catch {
        Write-StatusMessage "Error during recovery: $($_.Exception.Message)" -Type Error
        Write-Host ""
        
        # Attempt to restart SQL Server normally if something went wrong
        Write-StatusMessage "Attempting to restart SQL Server in normal mode..." -Type Warning
        try {
            $currentService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($currentService.Status -ne 'Running') {
                Start-Service -Name $serviceName -ErrorAction Stop
                Write-StatusMessage "SQL Server restarted." -Type Success
            }
        }
        catch {
            Write-StatusMessage "Could not restart SQL Server. Manual intervention may be required." -Type Error
            Write-Host "   Run: net start $serviceName" -ForegroundColor Yellow
        }
        
        return $false
    }
}

# Execute
$result = Invoke-SQLTempAdminCreation
exit ([int](-not $result))
#endregion
