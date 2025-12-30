<#
.SYNOPSIS
    RMM & Remote Access Artifact Detection Tool v1.0
    
.DESCRIPTION
    Comprehensive scanner that detects remnants of Remote Monitoring and Management 
    (RMM) tools and remote access software. Essential when onboarding new clients to 
    identify artifacts from previous MSPs that weren't properly removed.
    
    Detects artifacts from:
    
    RMM Platforms:
    - NinjaRMM (NinjaOne)
    - Datto RMM (Autotask AEM, CentraStage)
    - ConnectWise Automate (LabTech)
    - ConnectWise RMM (Continuum)
    - Atera
    - Kaseya VSA
    - Syncro
    - N-able N-central
    - N-able N-sight (SolarWinds RMM)
    - Action1
    - ManageEngine Desktop Central
    - Pulseway
    - Naverisk
    - SuperOps
    - Level.io
    
    Remote Access Tools:
    - ConnectWise Control (ScreenConnect)
    - TeamViewer
    - AnyDesk
    - LogMeIn
    - GoToAssist / GoTo Resolve
    - Splashtop
    - BeyondTrust (Bomgar)
    - RustDesk
    - Chrome Remote Desktop
    - VNC variants (TightVNC, UltraVNC, RealVNC)
    - Zoho Assist
    - RemotePC
    - Supremo
    
    Detection Methods:
    - Windows Services (running and stopped)
    - Registry keys (HKLM/HKCU uninstall, run keys, service keys)
    - File system paths (Program Files, ProgramData, AppData)
    - Scheduled Tasks
    - Running Processes
    - Installed Software (WMI/Registry)
    
.PARAMETER ComputerName
    Target computer(s) to scan. Defaults to local computer.
    Supports pipeline input and comma-separated values.
    
.PARAMETER OutputPath
    Directory for HTML report output. Defaults to current directory.
    
.PARAMETER ExportCSV
    Additionally export findings to CSV for further analysis.
    
.PARAMETER IncludeRemoteAccess
    Include remote access tools in scan (TeamViewer, AnyDesk, etc.)
    Enabled by default. Use -IncludeRemoteAccess:$false to disable.
    
.PARAMETER ExcludeProducts
    Array of product names to exclude from detection (your expected tools).
    Example: -ExcludeProducts "NinjaRMMAgent","Datto RMM"
    
.PARAMETER DeepScan
    Enable deep file system scanning (slower but more thorough).

.EXAMPLE
    .\Find-RMMArtifacts.ps1
    Scans local computer for all RMM and remote access artifacts.
    
.EXAMPLE
    .\Find-RMMArtifacts.ps1 -ComputerName "PC01","PC02" -OutputPath "C:\Reports"
    Scans multiple computers and saves report to specified path.
    
.EXAMPLE
    .\Find-RMMArtifacts.ps1 -ExcludeProducts "NinjaRMMAgent" -ExportCSV
    Scans excluding NinjaRMM (your current RMM) and exports to CSV.
    
.EXAMPLE
    .\Find-RMMArtifacts.ps1 -IncludeRemoteAccess:$false
    Scans only for RMM tools, excluding remote access software.

.NOTES
    Author:     Yeyland Wutani LLC
    Version:    1.0.0
    Created:    2024-12-29
    
    Use Case:
    When taking over a new client, run this tool to find all remnants 
    of their previous MSP's management tools. Leftover agents can:
    - Create security vulnerabilities
    - Cause service conflicts
    - Generate unnecessary network traffic
    - Maintain unauthorized remote access
    - Consume system resources
    
    Building Better Systems

.LINK
    https://github.com/YeylandWutani
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('CN', 'Server', 'Host')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter()]
    [switch]$ExportCSV,
    
    [Parameter()]
    [bool]$IncludeRemoteAccess = $true,
    
    [Parameter()]
    [string[]]$ExcludeProducts = @(),
    
    [Parameter()]
    [switch]$DeepScan
)

#region Configuration
$Script:Version = "1.0.0"
$Script:ReportDate = Get-Date

# Branding
$Script:Brand = @{
    Name      = "Yeyland Wutani LLC"
    Tagline   = "Building Better Systems"
    Orange    = "#FF6600"
    Grey      = "#6B7280"
    DarkGrey  = "#374151"
    LightGrey = "#F3F4F6"
    White     = "#FFFFFF"
    Success   = "#10B981"
    Warning   = "#F59E0B"
    Danger    = "#EF4444"
    Info      = "#3B82F6"
}

# RMM Product Definitions
$Script:RMMProducts = @(
    # NinjaRMM / NinjaOne
    @{
        Name = "NinjaRMM"
        Vendor = "NinjaOne"
        Category = "RMM"
        Services = @("NinjaRMMAgent", "NinjaRMMAgentPatcher", "ninjarmm-agent")
        Processes = @("NinjaRMMAgent", "NinjaRMMAgentPatcher", "ninjarmm-cli")
        Paths = @(
            "C:\Program Files\NinjaRMMAgent"
            "C:\Program Files (x86)\NinjaRMMAgent"
            "C:\ProgramData\NinjaRMMAgent"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\NinjaRMM LLC"
            "HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC"
        )
        UninstallPatterns = @("NinjaRMM*", "Ninja RMM*", "NinjaOne*")
        ScheduledTaskPatterns = @("*NinjaRMM*", "*Ninja*Agent*")
    }
    
    # Datto RMM (formerly CentraStage, Autotask AEM)
    @{
        Name = "Datto RMM"
        Vendor = "Datto (Kaseya)"
        Category = "RMM"
        Services = @("CagService", "AEMAgent", "Datto RMM")
        Processes = @("CagService", "AEMAgent", "AEMNetworkAgent")
        Paths = @(
            "C:\Program Files\CentraStage"
            "C:\Program Files (x86)\CentraStage"
            "C:\ProgramData\CentraStage"
            "C:\Program Files\Datto"
            "C:\ProgramData\Datto"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\CentraStage"
            "HKLM:\SOFTWARE\WOW6432Node\CentraStage"
            "HKLM:\SOFTWARE\Datto"
        )
        UninstallPatterns = @("*CentraStage*", "*Datto*RMM*", "*AEM*Agent*", "*Autotask*Endpoint*")
        ScheduledTaskPatterns = @("*CentraStage*", "*Datto*", "*AEM*")
    }
    
    # ConnectWise Automate (LabTech)
    @{
        Name = "ConnectWise Automate"
        Vendor = "ConnectWise"
        Category = "RMM"
        Services = @("LTService", "LTSvcMon", "LabTech")
        Processes = @("LTSvc", "LTSVC", "LTTray", "LTClient")
        Paths = @(
            "C:\Windows\LTSvc"
            "C:\Windows\LTSVC"
            "C:\Program Files\LabTech Client"
            "C:\Program Files (x86)\LabTech Client"
            "C:\Windows\Temp\LabTech"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\LabTech"
            "HKLM:\SOFTWARE\WOW6432Node\LabTech"
            "HKLM:\SOFTWARE\ConnectWise"
        )
        UninstallPatterns = @("*LabTech*", "*ConnectWise*Automate*", "*LT Agent*")
        ScheduledTaskPatterns = @("*LabTech*", "*LTSvc*", "*ConnectWise*Automate*")
    }
    
    # ConnectWise RMM (Continuum)
    @{
        Name = "ConnectWise RMM"
        Vendor = "ConnectWise"
        Category = "RMM"
        Services = @("ITSPlatform", "DPMA", "SAAZOD", "ITSupportAgent")
        Processes = @("ITSPlatform", "SAAZOD", "ITSupportAgent")
        Paths = @(
            "C:\Program Files\ITSPlatform"
            "C:\Program Files (x86)\ITSPlatform"
            "C:\Program Files\SAAZOD"
            "C:\ProgramData\Continuum"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\SAAZOD"
            "HKLM:\SOFTWARE\ITSPlatform"
            "HKLM:\SOFTWARE\Continuum"
        )
        UninstallPatterns = @("*ITSPlatform*", "*Continuum*", "*SAAZOD*", "*ConnectWise*RMM*", "*DPMA*")
        ScheduledTaskPatterns = @("*ITSPlatform*", "*Continuum*", "*SAAZOD*")
    }
    
    # Atera
    @{
        Name = "Atera"
        Vendor = "Atera Networks"
        Category = "RMM"
        Services = @("AteraAgent", "Atera Agent")
        Processes = @("AteraAgent", "AgentPackageMonitoring", "AgentPackageSTRemote")
        Paths = @(
            "C:\Program Files\ATERA Networks"
            "C:\Program Files (x86)\ATERA Networks"
            "C:\Program Files\Atera Networks\AteraAgent"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\ATERA Networks"
            "HKLM:\SOFTWARE\WOW6432Node\ATERA Networks"
        )
        UninstallPatterns = @("*Atera*", "*ATERA*")
        ScheduledTaskPatterns = @("*Atera*")
    }
    
    # Kaseya VSA
    @{
        Name = "Kaseya VSA"
        Vendor = "Kaseya"
        Category = "RMM"
        Services = @("Kaseya Agent", "KaseyaAgent", "kagent")
        Processes = @("agentmon", "KaseyaAgent", "kagent")
        Paths = @(
            "C:\Program Files\Kaseya"
            "C:\Program Files (x86)\Kaseya"
            "C:\Kaseya"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Kaseya"
            "HKLM:\SOFTWARE\WOW6432Node\Kaseya"
        )
        UninstallPatterns = @("*Kaseya*Agent*", "*Kaseya*VSA*")
        ScheduledTaskPatterns = @("*Kaseya*")
    }
    
    # Syncro
    @{
        Name = "Syncro"
        Vendor = "Syncro MSP"
        Category = "RMM"
        Services = @("Syncro", "SyncroLive", "SyncroRecovery", "Kabuto")
        Processes = @("Syncro", "SyncroLive", "Kabuto")
        Paths = @(
            "C:\Program Files\Syncro"
            "C:\Program Files (x86)\Syncro"
            "C:\ProgramData\Syncro"
            "C:\Program Files\RepairTech\Kabuto"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Syncro"
            "HKLM:\SOFTWARE\RepairTech"
        )
        UninstallPatterns = @("*Syncro*", "*Kabuto*")
        ScheduledTaskPatterns = @("*Syncro*", "*Kabuto*")
    }
    
    # N-able N-central
    @{
        Name = "N-able N-central"
        Vendor = "N-able (SolarWinds)"
        Category = "RMM"
        Services = @("Windows Agent Service", "N-central", "BASupSrvc", "NCentralAgent")
        Processes = @("Windows Agent", "BASupSrvc", "NCentralAgent")
        Paths = @(
            "C:\Program Files\N-able Technologies"
            "C:\Program Files (x86)\N-able Technologies"
            "C:\Program Files\BeAnywhere"
            "C:\Program Files\SolarWinds MSP\N-able Technologies"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\N-able Technologies"
            "HKLM:\SOFTWARE\BeAnywhere"
            "HKLM:\SOFTWARE\SolarWinds MSP"
        )
        UninstallPatterns = @("*N-able*", "*N-central*", "*BeAnywhere*", "*Windows Agent*")
        ScheduledTaskPatterns = @("*N-able*", "*N-central*", "*BeAnywhere*")
    }
    
    # N-able N-sight (SolarWinds RMM)
    @{
        Name = "N-able N-sight"
        Vendor = "N-able (SolarWinds)"
        Category = "RMM"
        Services = @("Advanced Monitoring Agent", "Advanced Monitoring Agent GP", "SolarWinds.Agent")
        Processes = @("Agent", "AgentComm", "SolarWinds.Agent")
        Paths = @(
            "C:\Program Files\SolarWinds MSP"
            "C:\Program Files (x86)\SolarWinds MSP"
            "C:\Program Files\Advanced Monitoring Agent"
            "C:\Program Files\Advanced Monitoring Agent GP"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\SolarWinds MSP"
            "HKLM:\SOFTWARE\LogicNow"
            "HKLM:\SOFTWARE\Advanced Monitoring Agent"
        )
        UninstallPatterns = @("*SolarWinds*MSP*", "*Advanced Monitoring*", "*N-sight*", "*LogicNow*")
        ScheduledTaskPatterns = @("*SolarWinds*", "*N-sight*", "*Advanced Monitoring*")
    }
    
    # Action1
    @{
        Name = "Action1"
        Vendor = "Action1 Corporation"
        Category = "RMM"
        Services = @("action1_agent", "action1_remote")
        Processes = @("action1_agent", "action1_remote")
        Paths = @(
            "C:\Windows\Action1"
            "C:\Program Files\Action1"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Action1"
        )
        UninstallPatterns = @("*Action1*")
        ScheduledTaskPatterns = @("*Action1*")
    }
    
    # ManageEngine Desktop Central
    @{
        Name = "ManageEngine Desktop Central"
        Vendor = "Zoho (ManageEngine)"
        Category = "RMM"
        Services = @("dcagentservice", "ManageEngine Desktop Central", "UEMS")
        Processes = @("dcagentservice", "DCFAService64", "dcagentregister")
        Paths = @(
            "C:\Program Files\DesktopCentral_Agent"
            "C:\Program Files (x86)\DesktopCentral_Agent"
            "C:\ManageEngine"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\ManageEngine"
            "HKLM:\SOFTWARE\DesktopCentral"
            "HKLM:\SOFTWARE\AdventNet"
        )
        UninstallPatterns = @("*ManageEngine*", "*Desktop Central*", "*DesktopCentral*")
        ScheduledTaskPatterns = @("*ManageEngine*", "*DesktopCentral*")
    }
    
    # Pulseway
    @{
        Name = "Pulseway"
        Vendor = "Pulseway"
        Category = "RMM"
        Services = @("Pulseway", "PCMonitorSrv")
        Processes = @("PCMonitorSrv", "PCMonitorManager")
        Paths = @(
            "C:\Program Files\Pulseway"
            "C:\Program Files (x86)\Pulseway"
            "C:\Program Files\MMSOFT Design"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\MMSOFT Design"
            "HKLM:\SOFTWARE\Pulseway"
        )
        UninstallPatterns = @("*Pulseway*", "*PC Monitor*")
        ScheduledTaskPatterns = @("*Pulseway*", "*PCMonitor*")
    }
    
    # Level.io
    @{
        Name = "Level"
        Vendor = "Level.io"
        Category = "RMM"
        Services = @("Level", "LevelAgent")
        Processes = @("Level", "level-windows-amd64")
        Paths = @(
            "C:\Program Files\Level"
            "C:\ProgramData\Level"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Level"
        )
        UninstallPatterns = @("*Level*")
        ScheduledTaskPatterns = @("*Level*")
    }
    
    # Intune
    @{
        Name = "Microsoft Intune"
        Vendor = "Microsoft"
        Category = "RMM"
        Services = @("IntuneManagementExtension")
        Processes = @("Microsoft.Management.Services.IntuneWindowsAgent", "AgentExecutor")
        Paths = @(
            "C:\Program Files\Microsoft Intune Management Extension"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension"
        )
        UninstallPatterns = @("*Intune*Management*")
        ScheduledTaskPatterns = @("*Intune*")
    }
)

# Remote Access Product Definitions
$Script:RemoteAccessProducts = @(
    # ConnectWise Control (ScreenConnect)
    @{
        Name = "ConnectWise Control"
        Vendor = "ConnectWise"
        Category = "Remote Access"
        Services = @("ScreenConnect Client*", "ConnectWiseControl*")
        Processes = @("ScreenConnect.ClientService", "ScreenConnect.WindowsClient", "ConnectWiseControl.Client")
        Paths = @(
            "C:\Program Files\ScreenConnect Client*"
            "C:\Program Files (x86)\ScreenConnect Client*"
            "C:\Program Files\ConnectWise Control Client*"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\ScreenConnect Client*"
            "HKLM:\SOFTWARE\WOW6432Node\ScreenConnect Client*"
        )
        UninstallPatterns = @("*ScreenConnect*", "*ConnectWise Control*")
        ScheduledTaskPatterns = @("*ScreenConnect*", "*ConnectWise Control*")
    }
    
    # TeamViewer
    @{
        Name = "TeamViewer"
        Vendor = "TeamViewer GmbH"
        Category = "Remote Access"
        Services = @("TeamViewer")
        Processes = @("TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64")
        Paths = @(
            "C:\Program Files\TeamViewer"
            "C:\Program Files (x86)\TeamViewer"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\TeamViewer"
            "HKLM:\SOFTWARE\WOW6432Node\TeamViewer"
        )
        UninstallPatterns = @("*TeamViewer*")
        ScheduledTaskPatterns = @("*TeamViewer*")
    }
    
    # AnyDesk
    @{
        Name = "AnyDesk"
        Vendor = "AnyDesk Software"
        Category = "Remote Access"
        Services = @("AnyDesk", "AnyDeskService")
        Processes = @("AnyDesk")
        Paths = @(
            "C:\Program Files\AnyDesk"
            "C:\Program Files (x86)\AnyDesk"
            "C:\ProgramData\AnyDesk"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\AnyDesk"
            "HKLM:\SOFTWARE\WOW6432Node\AnyDesk"
        )
        UninstallPatterns = @("*AnyDesk*")
        ScheduledTaskPatterns = @("*AnyDesk*")
    }
    
    # LogMeIn
    @{
        Name = "LogMeIn"
        Vendor = "LogMeIn (GoTo)"
        Category = "Remote Access"
        Services = @("LogMeIn", "LMIGuardianSvc", "LMIMaint")
        Processes = @("LogMeIn", "LMIGuardianSvc", "LogMeInSystray")
        Paths = @(
            "C:\Program Files\LogMeIn"
            "C:\Program Files (x86)\LogMeIn"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\LogMeIn"
            "HKLM:\SOFTWARE\WOW6432Node\LogMeIn"
        )
        UninstallPatterns = @("*LogMeIn*")
        ScheduledTaskPatterns = @("*LogMeIn*")
    }
    
    # GoTo products (GoToAssist, GoTo Resolve)
    @{
        Name = "GoTo (GoToAssist/Resolve)"
        Vendor = "GoTo (LogMeIn)"
        Category = "Remote Access"
        Services = @("GoToAssist*", "g2svc", "GoTo*")
        Processes = @("g2mcomm", "g2mlauncher", "GoToAssist", "GoToResolve")
        Paths = @(
            "C:\Program Files\GoToAssist*"
            "C:\Program Files (x86)\GoToAssist*"
            "C:\Program Files\GoTo*"
            "$env:LOCALAPPDATA\GoToMeeting"
            "$env:LOCALAPPDATA\GoToAssist*"
            "$env:LOCALAPPDATA\GoTo Resolve*"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\GoTo*"
            "HKLM:\SOFTWARE\Citrix\GoTo*"
        )
        UninstallPatterns = @("*GoToAssist*", "*GoTo Resolve*", "*GoToMeeting*")
        ScheduledTaskPatterns = @("*GoToAssist*", "*GoTo*")
    }
    
    # Splashtop
    @{
        Name = "Splashtop"
        Vendor = "Splashtop Inc."
        Category = "Remote Access"
        Services = @("SplashtopRemoteService", "Splashtop*")
        Processes = @("SRManager", "SRService", "SplashtopStreamer")
        Paths = @(
            "C:\Program Files\Splashtop"
            "C:\Program Files (x86)\Splashtop"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Splashtop"
            "HKLM:\SOFTWARE\WOW6432Node\Splashtop"
        )
        UninstallPatterns = @("*Splashtop*")
        ScheduledTaskPatterns = @("*Splashtop*")
    }
    
    # BeyondTrust (Bomgar)
    @{
        Name = "BeyondTrust Remote Support"
        Vendor = "BeyondTrust (Bomgar)"
        Category = "Remote Access"
        Services = @("bomgar*", "BeyondTrust*")
        Processes = @("bomgar-scc", "bomgar-pac")
        Paths = @(
            "C:\Program Files\Bomgar"
            "C:\Program Files (x86)\Bomgar"
            "C:\Program Files\BeyondTrust"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Bomgar"
            "HKLM:\SOFTWARE\BeyondTrust"
        )
        UninstallPatterns = @("*Bomgar*", "*BeyondTrust*")
        ScheduledTaskPatterns = @("*Bomgar*", "*BeyondTrust*")
    }
    
    # VNC Variants
    @{
        Name = "VNC (Various)"
        Vendor = "Various"
        Category = "Remote Access"
        Services = @("tvnserver", "vncserver", "winvnc*", "uvnc*")
        Processes = @("tvnserver", "vncserver", "winvnc", "vncviewer")
        Paths = @(
            "C:\Program Files\TightVNC"
            "C:\Program Files (x86)\TightVNC"
            "C:\Program Files\uvnc bvba\UltraVNC"
            "C:\Program Files\RealVNC"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\TightVNC"
            "HKLM:\SOFTWARE\ORL\WinVNC"
            "HKLM:\SOFTWARE\RealVNC"
        )
        UninstallPatterns = @("*TightVNC*", "*UltraVNC*", "*RealVNC*", "*VNC Server*")
        ScheduledTaskPatterns = @("*VNC*")
    }
    
    # Zoho Assist
    @{
        Name = "Zoho Assist"
        Vendor = "Zoho Corporation"
        Category = "Remote Access"
        Services = @("ZohoAssist*", "ZohoMeeting*")
        Processes = @("ZohoURS", "ZohoURSService", "ZohoMeeting")
        Paths = @(
            "C:\Program Files\ZohoMeeting"
            "C:\Program Files (x86)\ZohoMeeting"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\ZOHO"
            "HKLM:\SOFTWARE\ZohoMeeting"
        )
        UninstallPatterns = @("*Zoho Assist*", "*ZohoMeeting*")
        ScheduledTaskPatterns = @("*Zoho*")
    }
    
    # RustDesk
    @{
        Name = "RustDesk"
        Vendor = "RustDesk"
        Category = "Remote Access"
        Services = @("RustDesk")
        Processes = @("rustdesk")
        Paths = @(
            "C:\Program Files\RustDesk"
            "C:\Users\*\AppData\Roaming\RustDesk"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\RustDesk"
        )
        UninstallPatterns = @("*RustDesk*")
        ScheduledTaskPatterns = @("*RustDesk*")
    }
    
    # Chrome Remote Desktop
    @{
        Name = "Chrome Remote Desktop"
        Vendor = "Google"
        Category = "Remote Access"
        Services = @("chromoting*", "Chrome Remote Desktop*")
        Processes = @("remoting_host", "remote_assistance_host")
        Paths = @(
            "C:\Program Files\Google\Chrome Remote Desktop"
            "C:\Program Files (x86)\Google\Chrome Remote Desktop"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Google\Chrome Remote Desktop"
        )
        UninstallPatterns = @("*Chrome Remote Desktop*")
        ScheduledTaskPatterns = @("*Chrome Remote*", "*chromoting*")
    }
    
    # SimpleHelp
    @{
        Name = "SimpleHelp"
        Vendor = "SimpleHelp"
        Category = "Remote Access"
        Services = @("SimpleHelp*", "SimpleService*")
        Processes = @("SimpleHelp", "SimpleService")
        Paths = @(
            "C:\Program Files\SimpleHelp"
            "C:\Program Files (x86)\SimpleHelp"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\SimpleHelp"
        )
        UninstallPatterns = @("*SimpleHelp*")
        ScheduledTaskPatterns = @("*SimpleHelp*")
    }
    
    # DWService
    @{
        Name = "DWService"
        Vendor = "DWService"
        Category = "Remote Access"
        Services = @("DWAgent*")
        Processes = @("dwagent", "dwagsvc")
        Paths = @(
            "C:\Program Files\DWAgent"
            "C:\Program Files (x86)\DWAgent"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\DWAgent"
        )
        UninstallPatterns = @("*DWAgent*", "*DWService*")
        ScheduledTaskPatterns = @("*DWAgent*")
    }
    
    # RemotePC
    @{
        Name = "RemotePC"
        Vendor = "iDrive Inc."
        Category = "Remote Access"
        Services = @("RemotePC*", "RPCService")
        Processes = @("RemotePC", "RPCPerformanceService")
        Paths = @(
            "C:\Program Files\RemotePC"
            "C:\Program Files (x86)\RemotePC"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\RemotePC"
        )
        UninstallPatterns = @("*RemotePC*")
        ScheduledTaskPatterns = @("*RemotePC*")
    }
    
    # Supremo
    @{
        Name = "Supremo"
        Vendor = "Nanosystems"
        Category = "Remote Access"
        Services = @("Supremo*")
        Processes = @("Supremo", "SupremoService")
        Paths = @(
            "C:\Program Files\Supremo"
            "C:\Program Files (x86)\Supremo"
            "$env:APPDATA\Supremo"
        )
        RegistryKeys = @(
            "HKLM:\SOFTWARE\Supremo"
        )
        UninstallPatterns = @("*Supremo*")
        ScheduledTaskPatterns = @("*Supremo*")
    }
)

#endregion

#region Helper Functions

function Show-YWBanner {
    $logo = @(
        "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
        "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
        "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
        "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
    )
    
    $tagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
    $border  = ("=" * 81)
    
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

function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Progress')]
        [string]$Type = 'Info'
    )
    
    $colors = @{
        Info     = 'Cyan'
        Success  = 'Green'
        Warning  = 'Yellow'
        Error    = 'Red'
        Progress = 'DarkYellow'
    }
    
    $prefixes = @{
        Info     = '[*]'
        Success  = '[+]'
        Warning  = '[!]'
        Error    = '[-]'
        Progress = '[>]'
    }
    
    Write-Host "$($prefixes[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Test-ServiceExists {
    param(
        [string]$ComputerName,
        [string[]]$ServicePatterns
    )
    
    $found = @()
    
    foreach ($pattern in $ServicePatterns) {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                $services = Get-Service -Name $pattern -ErrorAction SilentlyContinue
            } else {
                $services = Get-Service -ComputerName $ComputerName -Name $pattern -ErrorAction SilentlyContinue
            }
            
            foreach ($svc in $services) {
                $found += [PSCustomObject]@{
                    Name        = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status      = $svc.Status.ToString()
                    StartType   = $svc.StartType.ToString()
                }
            }
        } catch {
            # Service pattern not found - continue
        }
    }
    
    return $found
}

function Test-ProcessExists {
    param(
        [string]$ComputerName,
        [string[]]$ProcessNames
    )
    
    $found = @()
    
    foreach ($procName in $ProcessNames) {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
            } else {
                $processes = Get-Process -ComputerName $ComputerName -Name $procName -ErrorAction SilentlyContinue
            }
            
            foreach ($proc in $processes) {
                $found += [PSCustomObject]@{
                    Name      = $proc.ProcessName
                    Id        = $proc.Id
                    Path      = $proc.Path
                    StartTime = $proc.StartTime
                }
            }
        } catch {
            # Process not found - continue
        }
    }
    
    return $found
}

function Test-PathExists {
    param(
        [string]$ComputerName,
        [string[]]$Paths
    )
    
    $found = @()
    
    foreach ($path in $Paths) {
        try {
            # Handle environment variables in paths
            $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
            
            # For remote computers, convert to UNC if needed
            if ($ComputerName -ne $env:COMPUTERNAME -and -not $expandedPath.StartsWith("\\")) {
                $uncPath = "\\$ComputerName\" + $expandedPath.Replace(":", "$")
            } else {
                $uncPath = $expandedPath
            }
            
            # Handle wildcards in path
            if ($uncPath -match '\*') {
                $parentPath = Split-Path $uncPath -Parent
                $childPattern = Split-Path $uncPath -Leaf
                
                if (Test-Path $parentPath -ErrorAction SilentlyContinue) {
                    $matches = Get-ChildItem -Path $parentPath -Filter $childPattern -ErrorAction SilentlyContinue
                    foreach ($match in $matches) {
                        $found += [PSCustomObject]@{
                            Path     = $match.FullName
                            Type     = if ($match.PSIsContainer) { "Directory" } else { "File" }
                            Created  = $match.CreationTime
                            Modified = $match.LastWriteTime
                            Size     = if ($match.PSIsContainer) { $null } else { $match.Length }
                        }
                    }
                }
            }
            elseif (Test-Path $uncPath -ErrorAction SilentlyContinue) {
                $item = Get-Item $uncPath -ErrorAction SilentlyContinue
                $found += [PSCustomObject]@{
                    Path     = $item.FullName
                    Type     = if ($item.PSIsContainer) { "Directory" } else { "File" }
                    Created  = $item.CreationTime
                    Modified = $item.LastWriteTime
                    Size     = if ($item.PSIsContainer) { $null } else { $item.Length }
                }
            }
        } catch {
            # Path not accessible - continue
        }
    }
    
    return $found
}

function Test-RegistryKeyExists {
    param(
        [string]$ComputerName,
        [string[]]$RegistryKeys
    )
    
    $found = @()
    
    foreach ($key in $RegistryKeys) {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                # Handle wildcards
                if ($key -match '\*') {
                    $parentKey = Split-Path $key -Parent
                    $childPattern = (Split-Path $key -Leaf) -replace '\*', '.*'
                    
                    if (Test-Path $parentKey -ErrorAction SilentlyContinue) {
                        $childKeys = Get-ChildItem -Path $parentKey -ErrorAction SilentlyContinue | 
                            Where-Object { $_.PSChildName -match $childPattern }
                        
                        foreach ($childKey in $childKeys) {
                            $found += [PSCustomObject]@{
                                Path     = $childKey.Name
                                KeyCount = $childKey.SubKeyCount
                                ValueCount = $childKey.ValueCount
                            }
                        }
                    }
                }
                elseif (Test-Path $key -ErrorAction SilentlyContinue) {
                    $regKey = Get-Item -Path $key -ErrorAction SilentlyContinue
                    $found += [PSCustomObject]@{
                        Path       = $key
                        KeyCount   = $regKey.SubKeyCount
                        ValueCount = $regKey.ValueCount
                    }
                }
            } else {
                # Remote registry access
                $hive = switch -Regex ($key) {
                    '^HKLM:\\' { [Microsoft.Win32.RegistryHive]::LocalMachine }
                    '^HKCU:\\' { [Microsoft.Win32.RegistryHive]::CurrentUser }
                    default { $null }
                }
                
                if ($hive) {
                    $subKeyPath = $key -replace '^HK[A-Z]+:\\', ''
                    $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $ComputerName)
                    $remoteKey = $remoteReg.OpenSubKey($subKeyPath)
                    
                    if ($remoteKey) {
                        $found += [PSCustomObject]@{
                            Path       = $key
                            KeyCount   = $remoteKey.SubKeyCount
                            ValueCount = $remoteKey.ValueCount
                        }
                        $remoteKey.Close()
                    }
                    $remoteReg.Close()
                }
            }
        } catch {
            # Registry key not accessible - continue
        }
    }
    
    return $found
}

function Test-InstalledSoftware {
    param(
        [string]$ComputerName,
        [string[]]$Patterns
    )
    
    $found = @()
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($uninstallPath in $uninstallPaths) {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                $apps = Get-ChildItem -Path $uninstallPath -ErrorAction SilentlyContinue | 
                    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue }
            } else {
                # Remote registry for installed software
                $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
                $subPath = $uninstallPath -replace '^HKLM:\\', ''
                
                $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $ComputerName)
                $uninstallKey = $remoteReg.OpenSubKey($subPath)
                
                if ($uninstallKey) {
                    $apps = foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                        $appKey = $uninstallKey.OpenSubKey($subKeyName)
                        if ($appKey) {
                            [PSCustomObject]@{
                                DisplayName    = $appKey.GetValue('DisplayName')
                                DisplayVersion = $appKey.GetValue('DisplayVersion')
                                Publisher      = $appKey.GetValue('Publisher')
                                InstallDate    = $appKey.GetValue('InstallDate')
                                UninstallString = $appKey.GetValue('UninstallString')
                                InstallLocation = $appKey.GetValue('InstallLocation')
                            }
                            $appKey.Close()
                        }
                    }
                    $uninstallKey.Close()
                }
                $remoteReg.Close()
            }
            
            foreach ($pattern in $Patterns) {
                $matches = $apps | Where-Object { $_.DisplayName -like $pattern }
                foreach ($app in $matches) {
                    if ($app.DisplayName) {
                        $found += [PSCustomObject]@{
                            Name            = $app.DisplayName
                            Version         = $app.DisplayVersion
                            Publisher       = $app.Publisher
                            InstallDate     = $app.InstallDate
                            UninstallString = $app.UninstallString
                            InstallLocation = $app.InstallLocation
                        }
                    }
                }
            }
        } catch {
            # Continue on error
        }
    }
    
    return $found | Select-Object -Unique Name, Version, Publisher, InstallDate, UninstallString, InstallLocation
}

function Test-ScheduledTasks {
    param(
        [string]$ComputerName,
        [string[]]$Patterns
    )
    
    $found = @()
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        } else {
            $tasks = Get-ScheduledTask -CimSession $ComputerName -ErrorAction SilentlyContinue
        }
        
        foreach ($pattern in $Patterns) {
            $matches = $tasks | Where-Object { 
                $_.TaskName -like $pattern -or $_.TaskPath -like $pattern 
            }
            
            foreach ($task in $matches) {
                $found += [PSCustomObject]@{
                    Name       = $task.TaskName
                    Path       = $task.TaskPath
                    State      = $task.State.ToString()
                    Author     = $task.Author
                    Description = $task.Description
                }
            }
        }
    } catch {
        # Continue on error
    }
    
    return $found
}

function Invoke-ProductScan {
    param(
        [string]$ComputerName,
        [PSCustomObject]$Product,
        [hashtable]$Results
    )
    
    $productResults = @{
        Product          = $Product.Name
        Vendor           = $Product.Vendor
        Category         = $Product.Category
        Services         = @()
        Processes        = @()
        Paths            = @()
        RegistryKeys     = @()
        InstalledSoftware = @()
        ScheduledTasks   = @()
        TotalArtifacts   = 0
    }
    
    # Check Services
    if ($Product.Services) {
        $productResults.Services = Test-ServiceExists -ComputerName $ComputerName -ServicePatterns $Product.Services
    }
    
    # Check Processes
    if ($Product.Processes) {
        $productResults.Processes = Test-ProcessExists -ComputerName $ComputerName -ProcessNames $Product.Processes
    }
    
    # Check Paths
    if ($Product.Paths) {
        $productResults.Paths = Test-PathExists -ComputerName $ComputerName -Paths $Product.Paths
    }
    
    # Check Registry
    if ($Product.RegistryKeys) {
        $productResults.RegistryKeys = Test-RegistryKeyExists -ComputerName $ComputerName -RegistryKeys $Product.RegistryKeys
    }
    
    # Check Installed Software
    if ($Product.UninstallPatterns) {
        $productResults.InstalledSoftware = Test-InstalledSoftware -ComputerName $ComputerName -Patterns $Product.UninstallPatterns
    }
    
    # Check Scheduled Tasks
    if ($Product.ScheduledTaskPatterns) {
        $productResults.ScheduledTasks = Test-ScheduledTasks -ComputerName $ComputerName -Patterns $Product.ScheduledTaskPatterns
    }
    
    # Calculate total artifacts
    $productResults.TotalArtifacts = (
        $productResults.Services.Count +
        $productResults.Processes.Count +
        $productResults.Paths.Count +
        $productResults.RegistryKeys.Count +
        $productResults.InstalledSoftware.Count +
        $productResults.ScheduledTasks.Count
    )
    
    return $productResults
}

function New-HTMLReport {
    param(
        [string]$ComputerName,
        [array]$Findings,
        [string]$OutputPath
    )
    
    $totalArtifacts = ($Findings | Measure-Object -Property TotalArtifacts -Sum).Sum
    $productsWithArtifacts = ($Findings | Where-Object { $_.TotalArtifacts -gt 0 }).Count
    
    $rmmFindings = $Findings | Where-Object { $_.Category -eq 'RMM' -and $_.TotalArtifacts -gt 0 }
    $remoteFindings = $Findings | Where-Object { $_.Category -eq 'Remote Access' -and $_.TotalArtifacts -gt 0 }
    
    $riskLevel = switch ($totalArtifacts) {
        { $_ -eq 0 } { "Clean"; break }
        { $_ -le 5 } { "Low"; break }
        { $_ -le 15 } { "Medium"; break }
        { $_ -le 30 } { "High"; break }
        default { "Critical" }
    }
    
    $riskColor = switch ($riskLevel) {
        "Clean"    { $Script:Brand.Success }
        "Low"      { $Script:Brand.Info }
        "Medium"   { $Script:Brand.Warning }
        "High"     { $Script:Brand.Danger }
        "Critical" { "#7C2D12" }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RMM Artifact Detection Report - $ComputerName</title>
    <style>
        :root {
            --yw-orange: $($Script:Brand.Orange);
            --yw-grey: $($Script:Brand.Grey);
            --yw-dark-grey: $($Script:Brand.DarkGrey);
            --yw-light-grey: $($Script:Brand.LightGrey);
            --yw-success: $($Script:Brand.Success);
            --yw-warning: $($Script:Brand.Warning);
            --yw-danger: $($Script:Brand.Danger);
            --yw-info: $($Script:Brand.Info);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--yw-light-grey);
            color: var(--yw-dark-grey);
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, var(--yw-dark-grey) 0%, #1F2937 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .header h1 {
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
        }
        
        .header .tagline {
            color: var(--yw-orange);
            font-size: 0.9rem;
            letter-spacing: 3px;
        }
        
        .header .computer-name {
            background: rgba(255,102,0,0.2);
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 20px;
            margin-top: 1rem;
            font-size: 1.1rem;
            border: 1px solid var(--yw-orange);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .summary-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--yw-orange);
        }
        
        .summary-card .label {
            color: var(--yw-grey);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        
        .summary-card.risk {
            border-left: 4px solid $riskColor;
        }
        
        .summary-card.risk .value {
            color: $riskColor;
        }
        
        .section {
            background: white;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        
        .section-header {
            background: var(--yw-dark-grey);
            color: white;
            padding: 1rem 1.5rem;
            font-size: 1.1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-header.rmm { border-left: 4px solid var(--yw-danger); }
        .section-header.remote { border-left: 4px solid var(--yw-warning); }
        
        .badge {
            background: var(--yw-orange);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
        }
        
        .product-card {
            border-bottom: 1px solid var(--yw-light-grey);
            padding: 1.5rem;
        }
        
        .product-card:last-child { border-bottom: none; }
        
        .product-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .product-name {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--yw-dark-grey);
        }
        
        .product-vendor {
            color: var(--yw-grey);
            font-size: 0.85rem;
        }
        
        .artifact-count {
            background: var(--yw-danger);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-weight: 600;
        }
        
        .artifact-group {
            margin-top: 1rem;
        }
        
        .artifact-group-header {
            font-weight: 600;
            color: var(--yw-grey);
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .artifact-list {
            background: var(--yw-light-grey);
            border-radius: 8px;
            padding: 1rem;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
        }
        
        .artifact-item {
            padding: 0.4rem 0;
            border-bottom: 1px solid rgba(0,0,0,0.05);
        }
        
        .artifact-item:last-child { border-bottom: none; }
        
        .artifact-item .name { color: var(--yw-dark-grey); }
        .artifact-item .status { color: var(--yw-grey); font-size: 0.8rem; }
        .artifact-item .status.running { color: var(--yw-success); }
        .artifact-item .status.stopped { color: var(--yw-danger); }
        
        .no-findings {
            text-align: center;
            padding: 3rem;
            color: var(--yw-success);
        }
        
        .no-findings .icon { font-size: 3rem; margin-bottom: 1rem; }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--yw-grey);
            font-size: 0.85rem;
        }
        
        .footer a {
            color: var(--yw-orange);
            text-decoration: none;
        }
        
        @media print {
            body { background: white; }
            .container { max-width: 100%; }
            .section { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>RMM & Remote Access Artifact Detection</h1>
        <div class="tagline">YEYLAND WUTANI - BUILDING BETTER SYSTEMS</div>
        <div class="computer-name">$ComputerName</div>
    </div>
    
    <div class="container">
        <div class="summary-grid">
            <div class="summary-card risk">
                <div class="value">$riskLevel</div>
                <div class="label">Risk Level</div>
            </div>
            <div class="summary-card">
                <div class="value">$totalArtifacts</div>
                <div class="label">Total Artifacts</div>
            </div>
            <div class="summary-card">
                <div class="value">$($rmmFindings.Count)</div>
                <div class="label">RMM Tools Detected</div>
            </div>
            <div class="summary-card">
                <div class="value">$($remoteFindings.Count)</div>
                <div class="label">Remote Access Tools</div>
            </div>
        </div>
"@

    # RMM Findings Section
    if ($rmmFindings.Count -gt 0) {
        $html += @"
        <div class="section">
            <div class="section-header rmm">
                <span>RMM Tools Detected</span>
                <span class="badge">$($rmmFindings.Count) Found</span>
            </div>
"@
        foreach ($finding in $rmmFindings) {
            $html += New-ProductHTML -Finding $finding
        }
        $html += "</div>"
    }
    
    # Remote Access Findings Section
    if ($remoteFindings.Count -gt 0) {
        $html += @"
        <div class="section">
            <div class="section-header remote">
                <span>Remote Access Tools Detected</span>
                <span class="badge">$($remoteFindings.Count) Found</span>
            </div>
"@
        foreach ($finding in $remoteFindings) {
            $html += New-ProductHTML -Finding $finding
        }
        $html += "</div>"
    }
    
    # Clean system message
    if ($totalArtifacts -eq 0) {
        $html += @"
        <div class="section">
            <div class="no-findings">
                <div class="icon">&#10004;</div>
                <h2>System Clean</h2>
                <p>No RMM or remote access artifacts were detected on this system.</p>
            </div>
        </div>
"@
    }
    
    $html += @"
        <div class="section" style="padding: 1.5rem;">
            <h3 style="margin-bottom: 1rem; color: var(--yw-dark-grey);">Scan Details</h3>
            <table style="width: 100%; font-size: 0.9rem;">
                <tr><td style="padding: 0.5rem 0; color: var(--yw-grey);">Scan Date</td><td>$($Script:ReportDate.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td style="padding: 0.5rem 0; color: var(--yw-grey);">Tool Version</td><td>$($Script:Version)</td></tr>
                <tr><td style="padding: 0.5rem 0; color: var(--yw-grey);">Products Scanned</td><td>$($Findings.Count)</td></tr>
                <tr><td style="padding: 0.5rem 0; color: var(--yw-grey);">Products with Artifacts</td><td>$productsWithArtifacts</td></tr>
            </table>
        </div>
    </div>
    
    <div class="footer">
        <p><strong>Yeyland Wutani LLC</strong> - Building Better Systems</p>
        <p>Report generated $($Script:ReportDate.ToString('MMMM dd, yyyy')) at $($Script:ReportDate.ToString('h:mm tt'))</p>
    </div>
</body>
</html>
"@
    
    return $html
}

function New-ProductHTML {
    param($Finding)
    
    $html = @"
    <div class="product-card">
        <div class="product-header">
            <div>
                <div class="product-name">$($Finding.Product)</div>
                <div class="product-vendor">$($Finding.Vendor)</div>
            </div>
            <div class="artifact-count">$($Finding.TotalArtifacts) Artifacts</div>
        </div>
"@
    
    # Services
    if ($Finding.Services.Count -gt 0) {
        $html += @"
        <div class="artifact-group">
            <div class="artifact-group-header">Services ($($Finding.Services.Count))</div>
            <div class="artifact-list">
"@
        foreach ($svc in $Finding.Services) {
            $statusClass = if ($svc.Status -eq 'Running') { 'running' } else { 'stopped' }
            $html += "<div class='artifact-item'><span class='name'>$($svc.Name)</span> - <span class='status $statusClass'>$($svc.Status)</span></div>`n"
        }
        $html += "</div></div>"
    }
    
    # Processes
    if ($Finding.Processes.Count -gt 0) {
        $html += @"
        <div class="artifact-group">
            <div class="artifact-group-header">Running Processes ($($Finding.Processes.Count))</div>
            <div class="artifact-list">
"@
        foreach ($proc in $Finding.Processes) {
            $html += "<div class='artifact-item'><span class='name'>$($proc.Name)</span> <span class='status'>(PID: $($proc.Id))</span></div>`n"
        }
        $html += "</div></div>"
    }
    
    # Installed Software
    if ($Finding.InstalledSoftware.Count -gt 0) {
        $html += @"
        <div class="artifact-group">
            <div class="artifact-group-header">Installed Software ($($Finding.InstalledSoftware.Count))</div>
            <div class="artifact-list">
"@
        foreach ($sw in $Finding.InstalledSoftware) {
            $html += "<div class='artifact-item'><span class='name'>$($sw.Name)</span> <span class='status'>v$($sw.Version)</span></div>`n"
        }
        $html += "</div></div>"
    }
    
    # File Paths
    if ($Finding.Paths.Count -gt 0) {
        $html += @"
        <div class="artifact-group">
            <div class="artifact-group-header">File System ($($Finding.Paths.Count))</div>
            <div class="artifact-list">
"@
        foreach ($path in $Finding.Paths) {
            $html += "<div class='artifact-item'><span class='name'>$($path.Path)</span> <span class='status'>($($path.Type))</span></div>`n"
        }
        $html += "</div></div>"
    }
    
    # Registry Keys
    if ($Finding.RegistryKeys.Count -gt 0) {
        $html += @"
        <div class="artifact-group">
            <div class="artifact-group-header">Registry Keys ($($Finding.RegistryKeys.Count))</div>
            <div class="artifact-list">
"@
        foreach ($key in $Finding.RegistryKeys) {
            $html += "<div class='artifact-item'><span class='name'>$($key.Path)</span></div>`n"
        }
        $html += "</div></div>"
    }
    
    # Scheduled Tasks
    if ($Finding.ScheduledTasks.Count -gt 0) {
        $html += @"
        <div class="artifact-group">
            <div class="artifact-group-header">Scheduled Tasks ($($Finding.ScheduledTasks.Count))</div>
            <div class="artifact-list">
"@
        foreach ($task in $Finding.ScheduledTasks) {
            $html += "<div class='artifact-item'><span class='name'>$($task.Name)</span> <span class='status'>($($task.State))</span></div>`n"
        }
        $html += "</div></div>"
    }
    
    $html += "</div>"
    
    return $html
}

#endregion

#region Main Execution

Show-YWBanner

Write-StatusMessage "RMM & Remote Access Artifact Detection Tool v$($Script:Version)" -Type Info
Write-Host ""

# Build product list
$productsToScan = [System.Collections.ArrayList]::new()
$productsToScan.AddRange($Script:RMMProducts)

if ($IncludeRemoteAccess) {
    $productsToScan.AddRange($Script:RemoteAccessProducts)
}

# Remove excluded products
if ($ExcludeProducts.Count -gt 0) {
    $productsToScan = $productsToScan | Where-Object { 
        $product = $_
        -not ($ExcludeProducts | Where-Object { $product.Name -like "*$_*" })
    }
    Write-StatusMessage "Excluding products: $($ExcludeProducts -join ', ')" -Type Info
}

Write-StatusMessage "Scanning $($productsToScan.Count) products (RMM: $($Script:RMMProducts.Count), Remote Access: $($Script:RemoteAccessProducts.Count))" -Type Info
Write-Host ""

foreach ($computer in $ComputerName) {
    Write-StatusMessage "Scanning: $computer" -Type Progress
    
    $allFindings = @()
    $productCount = 0
    $totalProducts = $productsToScan.Count
    
    foreach ($product in $productsToScan) {
        $productCount++
        $percentComplete = [math]::Round(($productCount / $totalProducts) * 100)
        Write-Progress -Activity "Scanning $computer" -Status "Checking $($product.Name)" -PercentComplete $percentComplete
        
        $results = Invoke-ProductScan -ComputerName $computer -Product $product
        $allFindings += $results
        
        if ($results.TotalArtifacts -gt 0) {
            Write-StatusMessage "  Found: $($product.Name) ($($results.TotalArtifacts) artifacts)" -Type Warning
        }
    }
    
    Write-Progress -Activity "Scanning $computer" -Completed
    
    # Generate report
    $reportFileName = "RMMArtifacts_$($computer)_$($Script:ReportDate.ToString('yyyyMMdd_HHmmss')).html"
    $reportPath = Join-Path $OutputPath $reportFileName
    
    $htmlReport = New-HTMLReport -ComputerName $computer -Findings $allFindings -OutputPath $OutputPath
    $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    
    Write-Host ""
    Write-StatusMessage "Report saved: $reportPath" -Type Success
    
    # Summary
    $foundProducts = $allFindings | Where-Object { $_.TotalArtifacts -gt 0 }
    $totalArtifacts = ($allFindings | Measure-Object -Property TotalArtifacts -Sum).Sum
    
    if ($foundProducts.Count -gt 0) {
        Write-Host ""
        Write-StatusMessage "SUMMARY FOR $computer" -Type Warning
        Write-Host "  Products with artifacts: $($foundProducts.Count)" -ForegroundColor Yellow
        Write-Host "  Total artifacts found:   $totalArtifacts" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Detected products:" -ForegroundColor Gray
        foreach ($fp in $foundProducts) {
            $icon = if ($fp.Category -eq 'RMM') { '[RMM]' } else { '[RAT]' }
            Write-Host "    $icon $($fp.Product) - $($fp.TotalArtifacts) artifacts" -ForegroundColor $(if ($fp.Category -eq 'RMM') { 'Red' } else { 'DarkYellow' })
        }
    } else {
        Write-Host ""
        Write-StatusMessage "SUMMARY FOR $computer" -Type Success
        Write-Host "  No RMM or remote access artifacts detected!" -ForegroundColor Green
    }
    
    # Export CSV if requested
    if ($ExportCSV -and $foundProducts.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "RMMArtifacts_$($computer)_$($Script:ReportDate.ToString('yyyyMMdd_HHmmss')).csv"
        
        $csvData = foreach ($finding in $foundProducts) {
            foreach ($svc in $finding.Services) {
                [PSCustomObject]@{
                    Computer     = $computer
                    Product      = $finding.Product
                    Category     = $finding.Category
                    ArtifactType = 'Service'
                    Name         = $svc.Name
                    Details      = "Status: $($svc.Status), StartType: $($svc.StartType)"
                }
            }
            foreach ($proc in $finding.Processes) {
                [PSCustomObject]@{
                    Computer     = $computer
                    Product      = $finding.Product
                    Category     = $finding.Category
                    ArtifactType = 'Process'
                    Name         = $proc.Name
                    Details      = "PID: $($proc.Id), Path: $($proc.Path)"
                }
            }
            foreach ($path in $finding.Paths) {
                [PSCustomObject]@{
                    Computer     = $computer
                    Product      = $finding.Product
                    Category     = $finding.Category
                    ArtifactType = 'FilePath'
                    Name         = $path.Path
                    Details      = "Type: $($path.Type), Modified: $($path.Modified)"
                }
            }
            foreach ($key in $finding.RegistryKeys) {
                [PSCustomObject]@{
                    Computer     = $computer
                    Product      = $finding.Product
                    Category     = $finding.Category
                    ArtifactType = 'Registry'
                    Name         = $key.Path
                    Details      = "SubKeys: $($key.KeyCount), Values: $($key.ValueCount)"
                }
            }
            foreach ($sw in $finding.InstalledSoftware) {
                [PSCustomObject]@{
                    Computer     = $computer
                    Product      = $finding.Product
                    Category     = $finding.Category
                    ArtifactType = 'Software'
                    Name         = $sw.Name
                    Details      = "Version: $($sw.Version), Publisher: $($sw.Publisher)"
                }
            }
            foreach ($task in $finding.ScheduledTasks) {
                [PSCustomObject]@{
                    Computer     = $computer
                    Product      = $finding.Product
                    Category     = $finding.Category
                    ArtifactType = 'ScheduledTask'
                    Name         = $task.Name
                    Details      = "State: $($task.State), Path: $($task.Path)"
                }
            }
        }
        
        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Force
        Write-StatusMessage "CSV exported: $csvPath" -Type Success
    }
}

Write-Host ""
Write-Host ("=" * 81) -ForegroundColor Gray
Write-StatusMessage "Scan complete." -Type Success

#endregion
