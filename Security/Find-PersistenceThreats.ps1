<#
.SYNOPSIS
    Comprehensive Windows persistence mechanism analyzer with threat scoring.

.DESCRIPTION
    Scans ALL known Windows persistence locations far beyond what Autoruns detects.
    Includes threat scoring based on behavioral indicators, obfuscation detection,
    and comparison against known-good baselines. Designed for incident response,
    security assessments, and routine hygiene checks.

.PARAMETER ComputerName
    Target computer(s) to scan. Defaults to local machine.

.PARAMETER ThreatThreshold
    Minimum threat score to include in results (0-100). Default: 0 (show all).

.PARAMETER ExportHTML
    Export results to branded HTML report.

.PARAMETER ExportCSV
    Export results to CSV for further analysis.

.PARAMETER ExportJSON
    Export results to JSON format.

.PARAMETER BaselineMode
    Generate a baseline of current persistence mechanisms for comparison.

.PARAMETER CompareBaseline
    Path to baseline file for comparison scanning.

.PARAMETER IncludeMicrosoft
    Include Microsoft-signed entries (normally filtered for noise reduction).

.EXAMPLE
    .\Find-PersistenceThreats.ps1
    Scans local machine for all persistence mechanisms.

.EXAMPLE
    .\Find-PersistenceThreats.ps1 -ThreatThreshold 50 -ExportHTML
    Shows only high-threat items and exports branded report.

.EXAMPLE
    .\Find-PersistenceThreats.ps1 -BaselineMode
    Creates baseline file for future comparison.

.NOTES
    Name:        Find-PersistenceThreats.ps1
    Author:      Yeyland Wutani LLC
    Version:     1.1.2
    License:     MIT
    Requires:    PowerShell 5.1+, Administrator privileges recommended

.LINK
    https://github.com/psychosmosis/YeylandWutani
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$ThreatThreshold = 0,

    [Parameter()]
    [switch]$ExportHTML,

    [Parameter()]
    [switch]$ExportCSV,

    [Parameter()]
    [switch]$ExportJSON,

    [Parameter()]
    [switch]$BaselineMode,

    [Parameter()]
    [string]$CompareBaseline,

    [Parameter()]
    [switch]$IncludeMicrosoft,

    [Parameter()]
    [switch]$WhatIf
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:Version = "1.1.2"

# Threat scoring weights
$script:ThreatWeights = @{
    UncommonLocation      = 15
    TempDirectory         = 25
    UserWritableSystem    = 20
    HiddenFile            = 15
    EncodedCommand        = 35
    ObfuscatedPath        = 25
    NoFileOnDisk          = 30
    RecentlyCreated       = 10
    UnsignedBinary        = 20
    SuspiciousName        = 15
    WMIPersistence        = 40
    IFEODebugger          = 35
    COMHijack             = 30
    BITSJob               = 30
    AccessibilityHijack   = 45
    NewSinceBaseline      = 25
    ModifiedSinceBaseline = 20
}

# Known suspicious patterns
$script:SuspiciousPatterns = @(
    '-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]',
    '-[Ee][Cc]\s',
    '-[Ee][Nn][Cc]\s',
    '[Ff][Rr][Oo][Mm][Bb][Aa][Ss][Ee]64',
    '\[Convert\]::FromBase64',
    'IEX\s*\(',
    'Invoke-Expression',
    'DownloadString',
    'DownloadFile',
    'Net\.WebRequest',
    'mshta\.exe',
    'regsvr32\.exe.*\/s.*\/u',
    'rundll32\.exe.*javascript',
    'certutil\.exe.*-decode'
)

# Known good software - paths and patterns that are legitimate
$script:KnownGoodPatterns = @(
    # Microsoft products
    'Microsoft\.Teams',
    'TeamsMeetingAdd-in',
    'Microsoft Office',
    'Microsoft\\Edge',
    'Microsoft\\OneDrive',
    'shell32\.dll',
    'mscoree\.dll',
    'WindowsApps\\Microsoft\.',
    'Microsoft\.Windows\.',
    'mspaint\.exe',
    
    # PowerToys (Microsoft open source)
    'PowerToys',
    
    # Google products
    'Google\\Chrome',
    'Google\\Update',
    'GoogleUpdater',
    'platform_experience_helper',
    
    # Python
    'Python\\Launcher',
    'pyshellext',
    
    # Common enterprise/productivity software
    'Zoom\\',
    'ZoomCptService',
    'Webex',
    'WebexHost',
    'Cisco',
    'Slack',
    'Adobe',
    'Dropbox',
    '1Password',
    'ShareX',
    
    # Security software
    'Cylance',
    'CrowdStrike',
    'SentinelOne',
    'Palo Alto',
    'Traps\\',
    'Specops',
    'DameWare',
    'Cortex',
    
    # Communication
    'UCAddin',
    'LyncAddin',
    'TeamsAddin',
    'OneNote',
    'OscAddin',
    'UmOutlookAddin',
    'VbaAddinForOutlook'
)

# Known good WMI filters (Windows defaults)
$script:KnownGoodWMIFilters = @(
    'SCM Event Log Filter',
    'BVTFilter'
)

# Known good Netsh helper DLLs (Windows defaults - just filenames)
$script:KnownGoodNetshHelpers = @(
    'authfwcfg.dll',
    'dhcpcmonitor.dll',
    'dot3cfg.dll',
    'fwcfg.dll',
    'hnetmon.dll',
    'ifmon.dll',
    'napmontr.dll',
    'netiohlp.dll',
    'netprofm.dll',
    'nettrace.dll',
    'nshhttp.dll',
    'nshipsec.dll',
    'nshwfp.dll',
    'peerdistsh.dll',
    'p2pnetsh.dll',
    'rasmontr.dll',
    'rpcnsh.dll',
    'WcnNetsh.dll',
    'whhelper.dll',
    'wshelper.dll'
)

# Known good Microsoft processes
$script:MicrosoftWhitelist = @(
    'SecurityHealthSystray.exe',
    'OneDrive.exe',
    'Teams.exe',
    'msedge.exe',
    'PhoneExperienceHost.exe',
    'explorer.exe',
    'ctfmon.exe',
    'RuntimeBroker.exe',
    'StartMenuExperienceHost.exe',
    'SearchHost.exe',
    'ShellExperienceHost.exe',
    'ONENOTEM.EXE'
)

# ============================================================================
# BANNER AND OUTPUT FUNCTIONS
# ============================================================================

function Show-Banner {
    $line = "=" * 80
    Write-Host $line -ForegroundColor DarkYellow
    Write-Host '  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___' -ForegroundColor DarkYellow
    Write-Host '  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|' -ForegroundColor DarkYellow
    Write-Host '   \ V /| _| \ V /| |__ / _ \ |  ` | |) |  \ \/\/ /| |_| | | |/ _ \|  ` || |' -ForegroundColor DarkYellow
    Write-Host '    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|' -ForegroundColor DarkYellow
    Write-Host '' -ForegroundColor Green
    Write-Host '                 B U I L D I N G   B E T T E R   S Y S T E M S' -ForegroundColor Green
    Write-Host $line -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "[*] Persistence Threat Analyzer v$script:Version" -ForegroundColor Cyan
    Write-Host "[*] Scanning 22 persistence categories with threat scoring" -ForegroundColor Cyan
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Progress')]
        [string]$Type = 'Info'
    )
    
    switch ($Type) {
        'Info'     { $prefix = "[*]"; $color = "Cyan" }
        'Success'  { $prefix = "[+]"; $color = "Green" }
        'Warning'  { $prefix = "[!]"; $color = "Yellow" }
        'Error'    { $prefix = "[-]"; $color = "Red" }
        'Progress' { $prefix = "[>]"; $color = "Gray" }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-Separator {
    $line = "=" * 80
    Write-Host $line -ForegroundColor DarkGray
}

# ============================================================================
# WHITELIST CHECK FUNCTIONS
# ============================================================================

function Test-IsKnownGood {
    param([string]$Value)
    
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    
    foreach ($pattern in $script:KnownGoodPatterns) {
        if ($Value -match $pattern) {
            return $true
        }
    }
    return $false
}

function Test-IsKnownGoodWMIFilter {
    param([string]$FilterName)
    return $script:KnownGoodWMIFilters -contains $FilterName
}

function Test-IsKnownGoodNetshHelper {
    param([string]$DllName)
    $fileName = Split-Path $DllName -Leaf
    return $script:KnownGoodNetshHelpers -contains $fileName
}

# ============================================================================
# THREAT SCORING FUNCTIONS
# ============================================================================

function Get-ThreatScore {
    param([hashtable]$Entry)
    
    $score = 0
    $reasons = @()
    
    $path = $Entry.Path
    $value = $Entry.Value
    $category = $Entry.Category
    
    # Skip scoring for known-good software
    if (Test-IsKnownGood -Value $value) {
        return @{ Score = 0; Reasons = @("Known legitimate software") }
    }
    
    if (Test-IsKnownGood -Value $path) {
        return @{ Score = 0; Reasons = @("Known legitimate software") }
    }
    
    # Check entry name against known-good patterns
    if (Test-IsKnownGood -Value $Entry.Name) {
        return @{ Score = 0; Reasons = @("Known legitimate software") }
    }
    
    # Check for encoded/suspicious commands
    foreach ($pattern in $script:SuspiciousPatterns) {
        if ($value -match $pattern) {
            $score += $script:ThreatWeights.EncodedCommand
            $reasons += "Suspicious pattern detected"
            break
        }
    }
    
    # Extract executable path for file-based checks
    # Must handle: "C:\path\file.exe" args, C:\path\file.exe args, %envvar% paths, rundll32 patterns
    $executablePath = $null
    if ($value -match '^"([^"]+\.(exe|dll))"') {
        # Quoted path: "C:\Program Files\app.exe" or "%ProgramFiles%\app.exe"
        $executablePath = $matches[1]
    }
    elseif ($value -match '^([A-Za-z]:\\[^\s,]+\.(exe|dll))') {
        # Unquoted path with drive letter: C:\Windows\System32\rundll32.exe
        $executablePath = $matches[1]
    }
    elseif ($value -match '^(%[^%]+%[^\s,]+\.(exe|dll))') {
        # Unquoted path with env var: %windir%\system32\cmd.exe
        $executablePath = $matches[1]
    }
    
    # Expand environment variables in the path
    if ($executablePath -and $executablePath -match '%') {
        $executablePath = [Environment]::ExpandEnvironmentVariables($executablePath)
    }
    
    # Check file location - only flag if EXECUTABLE is in suspicious location
    if ($executablePath) {
        # Skip if executable path matches known-good patterns
        if (Test-IsKnownGood -Value $executablePath) {
            return @{ Score = 0; Reasons = @("Known legitimate software") }
        }
        
        if ($executablePath -match '\\Temp\\|\\tmp\\') {
            $score += $script:ThreatWeights.TempDirectory
            $reasons += "Executable in temp directory"
        }
        
        if ($executablePath -match '\\Users\\Public\\') {
            $score += $script:ThreatWeights.UncommonLocation
            $reasons += "Executable in Public folder"
        }
        
        # Only flag AppData if exe is there AND not known-good
        if ($executablePath -match '\\AppData\\Local\\Temp\\') {
            $score += 15
            $reasons += "Executable in AppData Temp"
        }
    }
    
    # Check if file exists (only if we have a path and it's not known-good)
    if ($executablePath -and -not (Test-Path $executablePath -ErrorAction SilentlyContinue)) {
        # Don't penalize WindowsApps paths as they're virtualized
        if ($executablePath -notmatch 'WindowsApps') {
            $score += $script:ThreatWeights.NoFileOnDisk
            $reasons += "Referenced file not found on disk"
        }
    }
    
    # Check digital signature (skip WindowsApps - different signing)
    if ($executablePath -and (Test-Path $executablePath -ErrorAction SilentlyContinue)) {
        if ($executablePath -notmatch 'WindowsApps|Program Files\\PowerToys') {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $executablePath -ErrorAction SilentlyContinue
                if ($sig -and $sig.Status -ne 'Valid') {
                    $score += $script:ThreatWeights.UnsignedBinary
                    $reasons += "Binary is not properly signed"
                }
            } catch { }
        }
    }
    
    # Category-specific scoring
    switch ($category) {
        'WMI Event Subscription' {
            # Only flag if NOT a known-good filter AND has actual consumers
            if (-not (Test-IsKnownGoodWMIFilter -FilterName $Entry.Name)) {
                if ($Entry.SubCategory -match 'Consumer') {
                    $score += $script:ThreatWeights.WMIPersistence
                    $reasons += "WMI persistence consumer"
                }
            }
        }
        'IFEO Debugger' {
            $score += $script:ThreatWeights.IFEODebugger
            $reasons += "Image File Execution Options debugger"
        }
        'IFEO GlobalFlag' {
            $score += $script:ThreatWeights.IFEODebugger
            $reasons += "IFEO Silent Process Exit monitor"
        }
        'BITS Job' {
            $score += $script:ThreatWeights.BITSJob
            $reasons += "BITS job with command execution"
        }
        'Accessibility Hijack' {
            $score += $script:ThreatWeights.AccessibilityHijack
            $reasons += "Accessibility feature hijack (sticky keys attack)"
        }
    }
    
    # Check for recently created entries
    if ($Entry.Created) {
        try {
            $daysSinceCreated = (Get-Date) - $Entry.Created
            if ($daysSinceCreated.TotalDays -lt 7 -and $daysSinceCreated.TotalDays -ge 0) {
                $score += $script:ThreatWeights.RecentlyCreated
                $reasons += "Created within last 7 days"
            }
        } catch { }
    }
    
    $score = [Math]::Min($score, 100)
    
    return @{ Score = $score; Reasons = $reasons }
}

function Get-ThreatLevel {
    param([int]$Score)
    
    if ($Score -ge 70) { return "Critical" }
    elseif ($Score -ge 50) { return "High" }
    elseif ($Score -ge 30) { return "Medium" }
    elseif ($Score -ge 10) { return "Low" }
    else { return "Info" }
}

# ============================================================================
# PERSISTENCE DETECTION FUNCTIONS
# ============================================================================

function Get-RegistryRunKeys {
    param([string]$Computer)
    
    $results = @()
    
    $runKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
    )
    
    foreach ($keyPath in $runKeyPaths) {
        if (Test-Path $keyPath -ErrorAction SilentlyContinue) {
            try {
                $key = Get-Item $keyPath -ErrorAction SilentlyContinue
                
                if ($keyPath -match 'Active Setup') {
                    $subkeys = Get-ChildItem $keyPath -ErrorAction SilentlyContinue
                    foreach ($subkey in $subkeys) {
                        $stubPath = (Get-ItemProperty $subkey.PSPath -ErrorAction SilentlyContinue).StubPath
                        if ($stubPath) {
                            $results += @{
                                Category    = 'Registry Run Key'
                                SubCategory = 'Active Setup'
                                Location    = $subkey.PSPath
                                Name        = $subkey.PSChildName
                                Value       = $stubPath
                                Path        = $stubPath
                                Computer    = $Computer
                            }
                        }
                    }
                }
                else {
                    $properties = $key.Property
                    foreach ($prop in $properties) {
                        $value = (Get-ItemProperty $keyPath -Name $prop -ErrorAction SilentlyContinue).$prop
                        if ($value) {
                            $results += @{
                                Category    = 'Registry Run Key'
                                SubCategory = ($keyPath -split '\\')[-1]
                                Location    = $keyPath
                                Name        = $prop
                                Value       = $value
                                Path        = $value
                                Computer    = $Computer
                            }
                        }
                    }
                }
            }
            catch { Write-Verbose "Error accessing $keyPath : $_" }
        }
    }
    
    return $results
}

function Get-StartupFolderItems {
    param([string]$Computer)
    
    $results = @()
    $seenItems = @{}
    
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $items = Get-ChildItem $path -File -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $itemKey = "$($item.Name)|$path"
                if ($seenItems.ContainsKey($itemKey)) { continue }
                $seenItems[$itemKey] = $true
                
                $target = $item.FullName
                
                if ($item.Extension -eq '.lnk') {
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $shortcut = $shell.CreateShortcut($item.FullName)
                        $target = $shortcut.TargetPath
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
                    }
                    catch { $target = "Unable to resolve shortcut" }
                }
                
                $results += @{
                    Category    = 'Startup Folder'
                    SubCategory = if ($path -match 'ProgramData') { 'Common' } else { 'User' }
                    Location    = $path
                    Name        = $item.Name
                    Value       = $target
                    Path        = $target
                    Created     = $item.CreationTime
                    Modified    = $item.LastWriteTime
                    Computer    = $Computer
                }
            }
        }
    }
    
    return $results
}

function Get-ScheduledTaskPersistence {
    param([string]$Computer)
    
    $results = @()
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
        
        foreach ($task in $tasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            
            foreach ($action in $task.Actions) {
                if ($action.Execute) {
                    $command = $action.Execute
                    if ($action.Arguments) { $command += " $($action.Arguments)" }
                    
                    $isEncoded = $command -match '-[Ee]([Nn][Cc]|[Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd])'
                    
                    $decodedCommand = $null
                    if ($action.Arguments -match '-[Ee][Nn][Cc][Oo]?[Dd]?[Ee]?[Dd]?[Cc]?[Oo]?[Mm]?[Mm]?[Aa]?[Nn]?[Dd]?\s+([A-Za-z0-9+/=]+)') {
                        try {
                            $decodedCommand = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($matches[1]))
                        } catch { $decodedCommand = "Unable to decode" }
                    }
                    
                    $results += @{
                        Category      = 'Scheduled Task'
                        SubCategory   = if ($isEncoded) { 'Encoded Command' } else { 'Standard' }
                        Location      = $task.TaskPath
                        Name          = $task.TaskName
                        Value         = $command
                        Path          = $action.Execute
                        DecodedCmd    = $decodedCommand
                        Principal     = $task.Principal.UserId
                        Computer      = $Computer
                    }
                }
            }
        }
    }
    catch { Write-Verbose "Error enumerating scheduled tasks: $_" }
    
    return $results
}

function Get-WMIPersistence {
    param([string]$Computer)
    
    $results = @()
    
    try {
        # Only check for actual malicious consumers - these are what execute code
        $cmdConsumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
        foreach ($consumer in $cmdConsumers) {
            $results += @{
                Category    = 'WMI Event Subscription'
                SubCategory = 'CommandLineEventConsumer'
                Location    = 'root\subscription'
                Name        = $consumer.Name
                Value       = "$($consumer.ExecutablePath) $($consumer.CommandLineTemplate)"
                Path        = $consumer.ExecutablePath
                Computer    = $Computer
            }
        }
        
        $scriptConsumers = Get-WmiObject -Namespace "root\subscription" -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        foreach ($consumer in $scriptConsumers) {
            $results += @{
                Category    = 'WMI Event Subscription'
                SubCategory = 'ActiveScriptEventConsumer'
                Location    = 'root\subscription'
                Name        = $consumer.Name
                Value       = $consumer.ScriptText
                Path        = $consumer.ScriptFileName
                Computer    = $Computer
            }
        }
        
        # Don't report EventFilters alone - they're harmless without consumers
    }
    catch { Write-Verbose "Error enumerating WMI subscriptions: $_" }
    
    return $results
}

function Get-ServicePersistence {
    param([string]$Computer)
    
    $results = @()
    
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($svc in $services) {
            $suspicious = $false
            $subcategory = 'Standard'
            
            $exePath = $svc.PathName
            if ($exePath -match '^"([^"]+)"') { $exePath = $matches[1] }
            elseif ($exePath -match '^([^\s]+)') { $exePath = $matches[1] }
            
            # Skip if known-good
            if (Test-IsKnownGood -Value $exePath) { continue }
            if (Test-IsKnownGood -Value $svc.Name) { continue }
            
            if ($exePath -match '\\Temp\\|\\Users\\Public\\') {
                $suspicious = $true
                $subcategory = 'Unusual Path'
            }
            
            if ($exePath -match 'powershell|cmd\.exe|mshta|wscript|cscript') {
                $suspicious = $true
                $subcategory = 'Script Executor'
            }
            
            if ($svc.StartMode -eq 'Auto' -and $svc.State -eq 'Stopped') {
                $suspicious = $true
                $subcategory = 'Auto-Start Stopped'
            }
            
            if ($suspicious) {
                $results += @{
                    Category    = 'Service'
                    SubCategory = $subcategory
                    Location    = 'Services'
                    Name        = $svc.Name
                    Value       = $svc.PathName
                    Path        = $svc.PathName
                    DisplayName = $svc.DisplayName
                    StartMode   = $svc.StartMode
                    State       = $svc.State
                    Computer    = $Computer
                }
            }
        }
    }
    catch { Write-Verbose "Error enumerating services: $_" }
    
    return $results
}

function Get-IFEOPersistence {
    param([string]$Computer)
    
    $results = @()
    
    $ifeoPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )
    
    $silentExitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    
    foreach ($basePath in $ifeoPaths) {
        if (Test-Path $basePath -ErrorAction SilentlyContinue) {
            $subkeys = Get-ChildItem $basePath -ErrorAction SilentlyContinue
            
            foreach ($subkey in $subkeys) {
                $props = Get-ItemProperty $subkey.PSPath -ErrorAction SilentlyContinue
                
                if ($props.Debugger) {
                    $results += @{
                        Category    = 'IFEO Debugger'
                        SubCategory = 'Debugger Hijack'
                        Location    = $subkey.PSPath
                        Name        = $subkey.PSChildName
                        Value       = $props.Debugger
                        Path        = $props.Debugger
                        Computer    = $Computer
                    }
                }
                
                if ($props.GlobalFlag -eq 512) {
                    $silentKey = Join-Path $silentExitPath $subkey.PSChildName
                    if (Test-Path $silentKey -ErrorAction SilentlyContinue) {
                        $silentProps = Get-ItemProperty $silentKey -ErrorAction SilentlyContinue
                        if ($silentProps.MonitorProcess) {
                            $results += @{
                                Category    = 'IFEO GlobalFlag'
                                SubCategory = 'Silent Exit Monitor'
                                Location    = $silentKey
                                Name        = $subkey.PSChildName
                                Value       = $silentProps.MonitorProcess
                                Path        = $silentProps.MonitorProcess
                                Computer    = $Computer
                            }
                        }
                    }
                }
            }
        }
    }
    
    return $results
}

function Get-WinlogonPersistence {
    param([string]$Computer)
    
    $results = @()
    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    
    if (Test-Path $winlogonPath -ErrorAction SilentlyContinue) {
        $props = Get-ItemProperty $winlogonPath -ErrorAction SilentlyContinue
        
        if ($props.Shell -and $props.Shell -ne 'explorer.exe') {
            $results += @{
                Category    = 'Winlogon'
                SubCategory = 'Shell Modification'
                Location    = $winlogonPath
                Name        = 'Shell'
                Value       = $props.Shell
                Path        = $props.Shell
                Computer    = $Computer
            }
        }
        
        $expectedUserinit = 'C:\Windows\system32\userinit.exe,'
        if ($props.Userinit -and $props.Userinit -ne $expectedUserinit -and $props.Userinit -ne 'C:\Windows\system32\userinit.exe') {
            $results += @{
                Category    = 'Winlogon'
                SubCategory = 'Userinit Modification'
                Location    = $winlogonPath
                Name        = 'Userinit'
                Value       = $props.Userinit
                Path        = $props.Userinit
                Computer    = $Computer
            }
        }
        
        if ($props.Taskman) {
            $results += @{
                Category    = 'Winlogon'
                SubCategory = 'Taskman Override'
                Location    = $winlogonPath
                Name        = 'Taskman'
                Value       = $props.Taskman
                Path        = $props.Taskman
                Computer    = $Computer
            }
        }
    }
    
    return $results
}

function Get-BITSJobs {
    param([string]$Computer)
    
    $results = @()
    
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -ne 'Transferred' }
        
        foreach ($job in $bitsJobs) {
            if ($job.NotifyCmdLine) {
                $results += @{
                    Category    = 'BITS Job'
                    SubCategory = 'NotifyCmdLine'
                    Location    = 'BITS'
                    Name        = $job.DisplayName
                    Value       = $job.NotifyCmdLine
                    Path        = $job.NotifyCmdLine
                    Computer    = $Computer
                }
            }
        }
    }
    catch { Write-Verbose "Unable to enumerate BITS jobs: $_" }
    
    return $results
}

function Get-AppInitDLLs {
    param([string]$Computer)
    
    $results = @()
    
    $paths = @(
        @{Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Value = 'AppInit_DLLs'; Category = 'AppInit DLLs'},
        @{Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'; Value = 'AppInit_DLLs'; Category = 'AppInit DLLs (WOW64)'},
        @{Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Value = 'AppCertDLLs'; Category = 'AppCert DLLs'}
    )
    
    foreach ($item in $paths) {
        if (Test-Path $item.Path -ErrorAction SilentlyContinue) {
            $props = Get-ItemProperty $item.Path -ErrorAction SilentlyContinue
            $value = $props.($item.Value)
            
            if ($value -and $value -ne '') {
                $results += @{
                    Category    = $item.Category
                    SubCategory = 'DLL Injection'
                    Location    = $item.Path
                    Name        = $item.Value
                    Value       = $value
                    Path        = $value
                    Computer    = $Computer
                }
            }
        }
    }
    
    return $results
}

function Get-AccessibilityHijacks {
    param([string]$Computer)
    
    $results = @()
    $accessibilityBinaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
    $ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    
    foreach ($binary in $accessibilityBinaries) {
        $keyPath = Join-Path $ifeoPath $binary
        if (Test-Path $keyPath -ErrorAction SilentlyContinue) {
            $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
            if ($props.Debugger) {
                $results += @{
                    Category    = 'Accessibility Hijack'
                    SubCategory = $binary
                    Location    = $keyPath
                    Name        = 'Debugger'
                    Value       = $props.Debugger
                    Path        = $props.Debugger
                    Computer    = $Computer
                }
            }
        }
    }
    
    return $results
}

function Get-COMHijacks {
    param([string]$Computer)
    
    $results = @()
    $hkcuClsidPath = 'HKCU:\SOFTWARE\Classes\CLSID'
    
    if (Test-Path $hkcuClsidPath -ErrorAction SilentlyContinue) {
        $subkeys = Get-ChildItem $hkcuClsidPath -ErrorAction SilentlyContinue
        
        foreach ($subkey in $subkeys) {
            foreach ($serverType in @('InprocServer32', 'LocalServer32')) {
                $serverPath = Join-Path $subkey.PSPath $serverType
                if (Test-Path $serverPath -ErrorAction SilentlyContinue) {
                    $props = Get-ItemProperty $serverPath -ErrorAction SilentlyContinue
                    $dllPath = $props.'(default)'
                    
                    if ($dllPath -and -not (Test-IsKnownGood -Value $dllPath)) {
                        $results += @{
                            Category    = 'COM Hijack'
                            SubCategory = "HKCU $serverType"
                            Location    = $serverPath
                            Name        = $subkey.PSChildName
                            Value       = $dllPath
                            Path        = $dllPath
                            Computer    = $Computer
                        }
                    }
                }
            }
        }
    }
    
    return $results
}

function Get-PowerShellProfiles {
    param([string]$Computer)
    
    $results = @()
    
    $profilePaths = @(
        "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1",
        "$env:WINDIR\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        "$env:USERPROFILE\Documents\PowerShell\profile.ps1",
        "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    )
    
    foreach ($profilePath in $profilePaths) {
        if (Test-Path $profilePath -ErrorAction SilentlyContinue) {
            $content = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
            $fileInfo = Get-Item $profilePath -ErrorAction SilentlyContinue
            
            $results += @{
                Category    = 'PowerShell Profile'
                SubCategory = Split-Path $profilePath -Leaf
                Location    = Split-Path $profilePath -Parent
                Name        = Split-Path $profilePath -Leaf
                Value       = if ($content.Length -gt 500) { $content.Substring(0, 500) + "..." } else { $content }
                Path        = $profilePath
                Created     = $fileInfo.CreationTime
                Modified    = $fileInfo.LastWriteTime
                Computer    = $Computer
            }
        }
    }
    
    return $results
}

function Get-BrowserExtensions {
    param([string]$Computer)
    
    $results = @()
    
    # Chrome
    $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtPath -ErrorAction SilentlyContinue) {
        $extensions = Get-ChildItem $chromeExtPath -Directory -ErrorAction SilentlyContinue
        foreach ($ext in $extensions) {
            $manifestPath = Get-ChildItem $ext.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            $name = $ext.Name
            if ($manifestPath) {
                try { $name = (Get-Content $manifestPath.FullName -Raw | ConvertFrom-Json).name } catch { }
            }
            
            $results += @{
                Category    = 'Browser Extension'
                SubCategory = 'Chrome'
                Location    = $chromeExtPath
                Name        = $name
                Value       = $ext.Name
                Path        = $ext.FullName
                Computer    = $Computer
            }
        }
    }
    
    # Edge
    $edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgeExtPath -ErrorAction SilentlyContinue) {
        $extensions = Get-ChildItem $edgeExtPath -Directory -ErrorAction SilentlyContinue
        foreach ($ext in $extensions) {
            $manifestPath = Get-ChildItem $ext.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            $name = $ext.Name
            if ($manifestPath) {
                try { $name = (Get-Content $manifestPath.FullName -Raw | ConvertFrom-Json).name } catch { }
            }
            
            $results += @{
                Category    = 'Browser Extension'
                SubCategory = 'Edge'
                Location    = $edgeExtPath
                Name        = $name
                Value       = $ext.Name
                Path        = $ext.FullName
                Computer    = $Computer
            }
        }
    }
    
    return $results
}

function Get-SecurityProviders {
    param([string]$Computer)
    
    $results = @()
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    
    if (Test-Path $lsaPath -ErrorAction SilentlyContinue) {
        $props = Get-ItemProperty $lsaPath -ErrorAction SilentlyContinue
        
        $knownSecurityPackages = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', '')
        $knownAuthPackages = @('msv1_0', '')
        
        if ($props.'Security Packages') {
            foreach ($pkg in ($props.'Security Packages' | Where-Object { $_ -ne '' })) {
                if ($pkg -notin $knownSecurityPackages) {
                    $results += @{
                        Category    = 'Security Provider'
                        SubCategory = 'Security Package'
                        Location    = $lsaPath
                        Name        = 'Security Packages'
                        Value       = $pkg
                        Path        = $pkg
                        Computer    = $Computer
                    }
                }
            }
        }
        
        if ($props.'Authentication Packages') {
            foreach ($pkg in ($props.'Authentication Packages' | Where-Object { $_ -ne '' })) {
                if ($pkg -notin $knownAuthPackages) {
                    $results += @{
                        Category    = 'Security Provider'
                        SubCategory = 'Authentication Package'
                        Location    = $lsaPath
                        Name        = 'Authentication Packages'
                        Value       = $pkg
                        Path        = $pkg
                        Computer    = $Computer
                    }
                }
            }
        }
    }
    
    return $results
}

function Get-PrintMonitors {
    param([string]$Computer)
    
    $results = @()
    $monitorPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $knownMonitors = @('Local Port', 'Standard TCP/IP Port', 'USB Monitor', 'WSD Port', 'Microsoft Shared Fax Monitor')
    
    if (Test-Path $monitorPath -ErrorAction SilentlyContinue) {
        $monitors = Get-ChildItem $monitorPath -ErrorAction SilentlyContinue
        
        foreach ($monitor in $monitors) {
            if ($monitor.PSChildName -notin $knownMonitors) {
                $props = Get-ItemProperty $monitor.PSPath -ErrorAction SilentlyContinue
                if ($props.Driver) {
                    $results += @{
                        Category    = 'Print Monitor'
                        SubCategory = 'Custom Monitor'
                        Location    = $monitor.PSPath
                        Name        = $monitor.PSChildName
                        Value       = $props.Driver
                        Path        = $props.Driver
                        Computer    = $Computer
                    }
                }
            }
        }
    }
    
    return $results
}

function Get-NetshHelpers {
    param([string]$Computer)
    
    $results = @()
    $netshPath = 'HKLM:\SOFTWARE\Microsoft\NetSh'
    
    if (Test-Path $netshPath -ErrorAction SilentlyContinue) {
        $props = Get-ItemProperty $netshPath -ErrorAction SilentlyContinue
        
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS') {
                $dllPath = $prop.Value
                
                # Only flag non-default netsh helpers with full paths outside System32
                if (-not (Test-IsKnownGoodNetshHelper -DllName $dllPath)) {
                    if ($dllPath -match '^[A-Za-z]:\\' -and $dllPath -notmatch 'Windows\\System32') {
                        $results += @{
                            Category    = 'Netsh Helper'
                            SubCategory = 'Non-System32 DLL'
                            Location    = $netshPath
                            Name        = $prop.Name
                            Value       = $dllPath
                            Path        = $dllPath
                            Computer    = $Computer
                        }
                    }
                }
            }
        }
    }
    
    return $results
}

function Get-TimeProviders {
    param([string]$Computer)
    
    $results = @()
    $timeProvPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
    
    if (Test-Path $timeProvPath -ErrorAction SilentlyContinue) {
        $providers = Get-ChildItem $timeProvPath -ErrorAction SilentlyContinue
        
        foreach ($provider in $providers) {
            $props = Get-ItemProperty $provider.PSPath -ErrorAction SilentlyContinue
            if ($props.DllName -and $props.DllName -notmatch 'w32time\.dll') {
                $results += @{
                    Category    = 'Time Provider'
                    SubCategory = 'Custom Provider'
                    Location    = $provider.PSPath
                    Name        = $provider.PSChildName
                    Value       = $props.DllName
                    Path        = $props.DllName
                    Computer    = $Computer
                }
            }
        }
    }
    
    return $results
}

function Get-BootExecute {
    param([string]$Computer)
    
    $results = @()
    $sessionMgrPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    
    if (Test-Path $sessionMgrPath -ErrorAction SilentlyContinue) {
        $props = Get-ItemProperty $sessionMgrPath -ErrorAction SilentlyContinue
        
        if ($props.BootExecute) {
            foreach ($entry in $props.BootExecute) {
                if ($entry -and $entry -ne '' -and $entry -notmatch '^autocheck autochk') {
                    $results += @{
                        Category    = 'Boot Execute'
                        SubCategory = 'BootExecute'
                        Location    = $sessionMgrPath
                        Name        = 'BootExecute'
                        Value       = $entry
                        Path        = $entry
                        Computer    = $Computer
                    }
                }
            }
        }
        
        if ($props.SetupExecute) {
            foreach ($entry in $props.SetupExecute) {
                if ($entry -and $entry -ne '') {
                    $results += @{
                        Category    = 'Boot Execute'
                        SubCategory = 'SetupExecute'
                        Location    = $sessionMgrPath
                        Name        = 'SetupExecute'
                        Value       = $entry
                        Path        = $entry
                        Computer    = $Computer
                    }
                }
            }
        }
    }
    
    return $results
}

function Get-OfficeAddins {
    param([string]$Computer)
    
    $results = @()
    $officeApps = @('Word', 'Excel', 'PowerPoint', 'Outlook')
    $officeVersions = @('16.0', '15.0', '14.0')
    
    foreach ($app in $officeApps) {
        foreach ($version in $officeVersions) {
            $addinPath = "HKCU:\SOFTWARE\Microsoft\Office\$version\$app\Addins"
            if (Test-Path $addinPath -ErrorAction SilentlyContinue) {
                $addins = Get-ChildItem $addinPath -ErrorAction SilentlyContinue
                foreach ($addin in $addins) {
                    # Skip known-good Office add-ins
                    if (Test-IsKnownGood -Value $addin.PSChildName) { continue }
                    
                    $props = Get-ItemProperty $addin.PSPath -ErrorAction SilentlyContinue
                    $results += @{
                        Category    = 'Office Add-in'
                        SubCategory = "$app ($version)"
                        Location    = $addin.PSPath
                        Name        = $addin.PSChildName
                        Value       = $props.Description
                        Path        = $props.Manifest
                        Computer    = $Computer
                    }
                }
            }
        }
    }
    
    return $results
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

function Export-HTMLReport {
    param(
        [array]$Results,
        [string]$ComputerName,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $criticalCount = @($Results | Where-Object { $_.ThreatLevel -eq 'Critical' }).Count
    $highCount = @($Results | Where-Object { $_.ThreatLevel -eq 'High' }).Count
    $mediumCount = @($Results | Where-Object { $_.ThreatLevel -eq 'Medium' }).Count
    $lowCount = @($Results | Where-Object { $_.ThreatLevel -eq 'Low' }).Count
    $infoCount = @($Results | Where-Object { $_.ThreatLevel -eq 'Info' }).Count
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Persistence Threat Analysis - $ComputerName</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #FF6600 0%, #cc5200 100%); padding: 30px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .subtitle { color: #ddd; font-size: 1.1em; }
        .header .brand { margin-top: 15px; font-size: 0.9em; color: #fff; opacity: 0.9; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
        .summary-card { background: #16213e; border-radius: 10px; padding: 20px; text-align: center; border-left: 4px solid; }
        .summary-card.critical { border-color: #dc3545; }
        .summary-card.high { border-color: #fd7e14; }
        .summary-card.medium { border-color: #ffc107; }
        .summary-card.low { border-color: #17a2b8; }
        .summary-card.info { border-color: #6c757d; }
        .summary-card .count { font-size: 2.5em; font-weight: bold; }
        .summary-card .label { color: #aaa; text-transform: uppercase; font-size: 0.8em; }
        .category-section { background: #16213e; border-radius: 10px; margin: 20px 0; overflow: hidden; }
        .category-header { background: #1f3460; padding: 15px 20px; font-size: 1.2em; border-left: 4px solid #FF6600; }
        .entry { padding: 15px 20px; border-bottom: 1px solid #2a2a4a; }
        .entry:last-child { border-bottom: none; }
        .entry-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .entry-name { font-weight: bold; color: #FF6600; }
        .threat-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }
        .threat-critical { background: #dc3545; }
        .threat-high { background: #fd7e14; }
        .threat-medium { background: #ffc107; color: #000; }
        .threat-low { background: #17a2b8; }
        .threat-info { background: #6c757d; }
        .entry-details { font-size: 0.9em; color: #aaa; }
        .entry-details .label { color: #888; min-width: 100px; display: inline-block; }
        .entry-value { background: #0d1117; padding: 8px 12px; border-radius: 5px; font-family: 'Consolas', monospace; font-size: 0.85em; word-break: break-all; margin: 5px 0; }
        .reasons { margin-top: 10px; padding: 10px; background: rgba(255, 102, 0, 0.1); border-radius: 5px; border-left: 3px solid #FF6600; }
        .reasons ul { margin-left: 20px; }
        .reasons li { color: #ff9966; font-size: 0.85em; }
        .footer { text-align: center; padding: 30px; color: #666; border-top: 1px solid #2a2a4a; margin-top: 30px; }
        .meta-info { background: #16213e; padding: 15px 20px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; }
        .meta-info span { color: #aaa; }
        .meta-info strong { color: #FF6600; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Persistence Threat Analysis</h1>
        <div class="subtitle">Comprehensive scan of $($Results.Count) persistence mechanisms</div>
        <div class="brand">Yeyland Wutani LLC - Building Better Systems</div>
    </div>
    <div class="container">
        <div class="meta-info">
            <span>Target: <strong>$ComputerName</strong></span>
            <span>Scan Time: <strong>$timestamp</strong></span>
            <span>Total Entries: <strong>$($Results.Count)</strong></span>
        </div>
        <div class="summary-grid">
            <div class="summary-card critical"><div class="count">$criticalCount</div><div class="label">Critical</div></div>
            <div class="summary-card high"><div class="count">$highCount</div><div class="label">High</div></div>
            <div class="summary-card medium"><div class="count">$mediumCount</div><div class="label">Medium</div></div>
            <div class="summary-card low"><div class="count">$lowCount</div><div class="label">Low</div></div>
            <div class="summary-card info"><div class="count">$infoCount</div><div class="label">Info</div></div>
        </div>
"@

    $grouped = $Results | Group-Object Category | Sort-Object { ($_.Group | Measure-Object ThreatScore -Maximum).Maximum } -Descending
    
    foreach ($group in $grouped) {
        $maxScore = ($group.Group | Measure-Object ThreatScore -Maximum).Maximum
        $html += "`n        <div class=`"category-section`">`n            <div class=`"category-header`">$($group.Name) ($($group.Count) entries, max score: $maxScore)</div>"
        
        foreach ($entry in ($group.Group | Sort-Object ThreatScore -Descending)) {
            $threatClass = "threat-$($entry.ThreatLevel.ToLower())"
            $entryName = [System.Net.WebUtility]::HtmlEncode($entry.Name)
            $entryLocation = [System.Net.WebUtility]::HtmlEncode($entry.Location)
            $entrySubCategory = [System.Net.WebUtility]::HtmlEncode($entry.SubCategory)
            $entryValue = [System.Net.WebUtility]::HtmlEncode($entry.Value)
            
            $html += "`n            <div class=`"entry`">"
            $html += "`n                <div class=`"entry-header`"><span class=`"entry-name`">$entryName</span><span class=`"threat-badge $threatClass`">$($entry.ThreatLevel) ($($entry.ThreatScore))</span></div>"
            $html += "`n                <div class=`"entry-details`"><div><span class=`"label`">Location:</span> $entryLocation</div><div><span class=`"label`">Subcategory:</span> $entrySubCategory</div></div>"
            $html += "`n                <div class=`"entry-value`">$entryValue</div>"
            
            if ($entry.ThreatReasons -and $entry.ThreatReasons.Count -gt 0 -and $entry.ThreatReasons[0] -ne "Known legitimate software") {
                $html += "`n                <div class=`"reasons`"><strong>Threat Indicators:</strong><ul>"
                foreach ($reason in $entry.ThreatReasons) {
                    $html += "<li>$([System.Net.WebUtility]::HtmlEncode($reason))</li>"
                }
                $html += "</ul></div>"
            }
            $html += "`n            </div>"
        }
        $html += "`n        </div>"
    }
    
    $html += @"

        <div class="footer">
            <p>Generated by Find-PersistenceThreats.ps1 v$script:Version</p>
            <p>Yeyland Wutani LLC - Building Better Systems</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Show-Banner

foreach ($computer in $ComputerName) {
    Write-Host ""
    Write-Separator
    Write-Status "Scanning: $computer" -Type Info
    
    $allResults = @()
    $scanCategories = @(
        @{ Name = 'Registry Run Keys';      Function = 'Get-RegistryRunKeys' },
        @{ Name = 'Startup Folders';        Function = 'Get-StartupFolderItems' },
        @{ Name = 'Scheduled Tasks';        Function = 'Get-ScheduledTaskPersistence' },
        @{ Name = 'WMI Subscriptions';      Function = 'Get-WMIPersistence' },
        @{ Name = 'Services';               Function = 'Get-ServicePersistence' },
        @{ Name = 'IFEO Persistence';       Function = 'Get-IFEOPersistence' },
        @{ Name = 'Winlogon';               Function = 'Get-WinlogonPersistence' },
        @{ Name = 'BITS Jobs';              Function = 'Get-BITSJobs' },
        @{ Name = 'AppInit/AppCert DLLs';   Function = 'Get-AppInitDLLs' },
        @{ Name = 'Accessibility Hijacks';  Function = 'Get-AccessibilityHijacks' },
        @{ Name = 'COM Hijacks';            Function = 'Get-COMHijacks' },
        @{ Name = 'PowerShell Profiles';    Function = 'Get-PowerShellProfiles' },
        @{ Name = 'Browser Extensions';     Function = 'Get-BrowserExtensions' },
        @{ Name = 'Security Providers';     Function = 'Get-SecurityProviders' },
        @{ Name = 'Print Monitors';         Function = 'Get-PrintMonitors' },
        @{ Name = 'Netsh Helpers';          Function = 'Get-NetshHelpers' },
        @{ Name = 'Time Providers';         Function = 'Get-TimeProviders' },
        @{ Name = 'Boot Execute';           Function = 'Get-BootExecute' },
        @{ Name = 'Office Add-ins';         Function = 'Get-OfficeAddins' }
    )
    
    $totalCategories = $scanCategories.Count
    $currentCategory = 0
    
    foreach ($category in $scanCategories) {
        $currentCategory++
        Write-Status "[$currentCategory/$totalCategories] Checking $($category.Name)..." -Type Progress
        
        try {
            $results = & $category.Function -Computer $computer
            
            if ($results) {
                foreach ($result in $results) {
                    $threatInfo = Get-ThreatScore -Entry $result
                    $result.ThreatScore = $threatInfo.Score
                    $result.ThreatLevel = Get-ThreatLevel -Score $threatInfo.Score
                    $result.ThreatReasons = $threatInfo.Reasons
                    $allResults += [PSCustomObject]$result
                }
            }
        }
        catch { Write-Verbose "Error in $($category.Name): $_" }
    }
    
    # Filter Microsoft whitelist if not included
    if (-not $IncludeMicrosoft) {
        $originalCount = $allResults.Count
        $allResults = $allResults | Where-Object {
            $value = $_.Value
            $isMicrosoft = $false
            foreach ($item in $script:MicrosoftWhitelist) {
                if ($value -match [regex]::Escape($item)) { $isMicrosoft = $true; break }
            }
            -not $isMicrosoft
        }
        $filteredCount = $originalCount - $allResults.Count
        if ($filteredCount -gt 0) {
            Write-Status "Filtered $filteredCount known Microsoft entries" -Type Info
        }
    }
    
    # Filter by threat threshold
    if ($ThreatThreshold -gt 0) {
        $allResults = $allResults | Where-Object { $_.ThreatScore -ge $ThreatThreshold }
    }
    
    $allResults = $allResults | Sort-Object ThreatScore -Descending
    
    # Display summary
    Write-Host ""
    Write-Status "SCAN COMPLETE FOR $computer" -Type Success
    
    $critical = @($allResults | Where-Object { $_.ThreatLevel -eq 'Critical' }).Count
    $high = @($allResults | Where-Object { $_.ThreatLevel -eq 'High' }).Count
    $medium = @($allResults | Where-Object { $_.ThreatLevel -eq 'Medium' }).Count
    $low = @($allResults | Where-Object { $_.ThreatLevel -eq 'Low' }).Count
    $info = @($allResults | Where-Object { $_.ThreatLevel -eq 'Info' }).Count
    
    Write-Host "  Total entries:  $($allResults.Count)" -ForegroundColor White
    if ($critical -gt 0) { Write-Host "  Critical:       $critical" -ForegroundColor Red }
    if ($high -gt 0) { Write-Host "  High:           $high" -ForegroundColor DarkYellow }
    if ($medium -gt 0) { Write-Host "  Medium:         $medium" -ForegroundColor Yellow }
    if ($low -gt 0) { Write-Host "  Low:            $low" -ForegroundColor Cyan }
    if ($info -gt 0) { Write-Host "  Info:           $info" -ForegroundColor Gray }
    
    # Display high-threat items
    $highThreat = $allResults | Where-Object { $_.ThreatScore -ge 30 }
    if ($highThreat) {
        Write-Host ""
        Write-Status "HIGH-THREAT ENTRIES:" -Type Warning
        foreach ($item in $highThreat) {
            $color = switch ($item.ThreatLevel) {
                'Critical' { 'Red' }
                'High' { 'DarkYellow' }
                'Medium' { 'Yellow' }
                default { 'White' }
            }
            Write-Host "  [$($item.ThreatLevel.ToUpper())] $($item.Category): $($item.Name)" -ForegroundColor $color
            $displayValue = if ($item.Value.Length -gt 80) { $item.Value.Substring(0, 80) + "..." } else { $item.Value }
            Write-Host "    Value: $displayValue" -ForegroundColor Gray
        }
    }
    
    # Export reports
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $baseFileName = "PersistenceThreats_${computer}_${timestamp}"
    
    if ($ExportHTML) {
        $htmlPath = Join-Path (Get-Location) "$baseFileName.html"
        Export-HTMLReport -Results $allResults -ComputerName $computer -OutputPath $htmlPath
        Write-Status "HTML report: $htmlPath" -Type Success
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path (Get-Location) "$baseFileName.csv"
        $allResults | Select-Object Computer, Category, SubCategory, Name, Location, Value, ThreatScore, ThreatLevel, @{N='ThreatReasons';E={$_.ThreatReasons -join '; '}} | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Status "CSV export: $csvPath" -Type Success
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path (Get-Location) "$baseFileName.json"
        $allResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Status "JSON export: $jsonPath" -Type Success
    }
    
    if ($BaselineMode) {
        $baselinePath = Join-Path (Get-Location) "baseline_${computer}_${timestamp}.json"
        $allResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $baselinePath -Encoding UTF8
        Write-Status "Baseline saved: $baselinePath" -Type Success
    }
}

Write-Host ""
Write-Separator
Write-Status "Scan complete." -Type Success
