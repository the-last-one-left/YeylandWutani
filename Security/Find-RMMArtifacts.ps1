#################################################################
#
#  Microsoft 365 Security Analysis Tool - Yeyland Wutani Edition
#  
#  PURPOSE:
#  Comprehensive security analysis tool for Microsoft 365 tenants
#  using Microsoft Graph PowerShell to identify compromised users,
#  detect security threats, and analyze suspicious activity patterns.
#
#  CAPABILITIES:
#  +-------------------------------------------------------------+
#  | DATA COLLECTION                                             |
#  +-------------------------------------------------------------+
#  | - Sign-in logs with geolocation analysis                    |
#  | - Admin audit logs with risk assessment                     |
#  | - Inbox rules (forwarding, deletion, suspicious patterns)   |
#  | - Mailbox delegations                                       |
#  | - App registrations and service principals                  |
#  | - Conditional Access policies                               |
#  | - Exchange message traces (ETR format)                      |
#  +-------------------------------------------------------------+
#
#  +-------------------------------------------------------------+
#  | ANALYSIS & DETECTION                                        |
#  +-------------------------------------------------------------+
#  | - Unusual location detection                                |
#  | - Spam pattern analysis with risk scoring                   |
#  | - High-risk operation monitoring                            |
#  | - Suspicious rule detection                                 |
#  | - Risk-based user scoring                                   |
#  | - HTML report generation with detailed findings             |
#  +-------------------------------------------------------------+
#
#  REQUIREMENTS:
#  - PowerShell 5.1 or later
#  - Microsoft.Graph.* modules (auto-installed if missing)
#  - ExchangeOnlineManagement module (auto-installed if missing)
#  - Administrative permissions in Microsoft 365 tenant:
#    - Global Administrator, Security Administrator, or
#    - Security Reader + Exchange Administrator (recommended minimum)
#
#  AUTHOR:
#  Yeyland Wutani LLC (info@yeylandwutani.com)
#  
#  ENHANCED BY:
#  Claude (Anthropic AI) - Code organization, documentation,
#  error handling, performance optimization
#  
#  COPYRIGHT & LICENSING:
#  (c) Yeyland Wutani LLC - Professional Security Toolkit
#  
#  *** AUTHORIZED USE ONLY ***
#  This tool is developed by Yeyland Wutani LLC.
#  Licensed for use by Yeyland Wutani consulting clients.
#  Unauthorized use, distribution, or modification is strictly prohibited.
#
#
#################################################################

#region SCRIPT CONFIGURATION AND INITIALIZATION

#--------------------------------------------------------------
# SCRIPT VERSION
#--------------------------------------------------------------
# Update this version number when making significant changes
# Format: Major.Minor (e.g., 8.2)
$ScriptVer = "10.4"

#--------------------------------------------------------------
# GLOBAL CONNECTION STATE
#--------------------------------------------------------------
# Tracks the current Microsoft Graph connection status
# This is updated throughout the script lifecycle to maintain
# connection awareness and enable proper cleanup
$Global:ConnectionState = @{
    IsConnected  = $false       # Is currently connected to Graph
    TenantId     = $null        # Microsoft 365 Tenant ID (GUID)
    TenantName   = $null        # Tenant display name
    Account      = $null        # Connected user account (UPN)
    ConnectedAt  = $null        # Connection timestamp
}

#--------------------------------------------------------------
# EXCHANGE ONLINE CONNECTION STATE
#--------------------------------------------------------------
# Separate tracking for Exchange Online connections
# Exchange Online uses different authentication than Graph
$Global:ExchangeOnlineState = @{
    IsConnected       = $false  # Is currently connected to EXO
    LastChecked       = $null   # Last connection verification time
    ConnectionAttempts = 0      # Number of connection attempts (for retry logic)
}

#--------------------------------------------------------------
# IPSTACK API KEY STATE
#--------------------------------------------------------------
# Tracks whether the IPStack API key has been validated
# and is available for geolocation lookups
$Global:IPStackKeyState = @{
    IsValid     = $false        # Has been validated
    KeySource   = $null         # "Environment" or "UserProvided"
    LastChecked = $null         # Last validation timestamp
}

#===============================================================================
# HIGH-RISK ISP DETECTION
#===============================================================================
# List of Internet Service Providers associated with heightened security risk
# These ISPs are commonly used by VPS/hosting providers and may indicate
# suspicious activity when used for M365 sign-ins
$script:HighRiskISPs = @(
    "12651980 Canada Inc.",
    "Aurologic Gmbh",
    "Clouvider Limited",
    "Datacamp Limited",
    "Internet Utilities Europe and Asia Limited",
    "latitude.sh",
    "Mtn Nigeria Communication Limited",
    "Packethub s.A.",
    "Servers Australia Customers",
    "m247 Europe Srl",
    "Ovh Sas"
)

#══════════════════════════════════════════════════════════════════════════════
# YEYLAND WUTANI THEME SYSTEM
#══════════════════════════════════════════════════════════════════════════════
# Add this entire section BEFORE the Show-MainGUI function

# Theme Color Configuration
$script:ThemeColors = @{
    # LIGHT MODE COLORS - Yeyland Wutani brand colors (Orange and Grey)
    Light = @{
        Primary         = [System.Drawing.Color]::FromArgb(255, 102, 0)     # Yeyland Wutani Orange
        Secondary       = [System.Drawing.Color]::FromArgb(107, 114, 128)  # Yeyland Wutani Grey
        Accent          = [System.Drawing.Color]::FromArgb(255, 152, 0)    # Orange
        Success         = [System.Drawing.Color]::FromArgb(76, 175, 80)    # Green
        Warning         = [System.Drawing.Color]::FromArgb(255, 152, 0)    # Orange
        Danger          = [System.Drawing.Color]::FromArgb(244, 67, 54)    # Red
        Background      = [System.Drawing.Color]::FromArgb(245, 245, 245)  # Light gray
        Surface         = [System.Drawing.Color]::White                     # White
        TextPrimary     = [System.Drawing.Color]::FromArgb(33, 33, 33)     # Dark text
        TextSecondary   = [System.Drawing.Color]::FromArgb(117, 117, 117)  # Gray text
        Border          = [System.Drawing.Color]::FromArgb(224, 224, 224)  # Light borders
    }
    
    # DARK MODE COLORS
    Dark = @{
        Primary         = [System.Drawing.Color]::FromArgb(255, 133, 51)   # Lighter orange
        Secondary       = [System.Drawing.Color]::FromArgb(156, 163, 175)  # Lighter grey
        Accent          = [System.Drawing.Color]::FromArgb(255, 167, 38)   # Lighter orange
        Success         = [System.Drawing.Color]::FromArgb(102, 187, 106)  # Lighter green
        Warning         = [System.Drawing.Color]::FromArgb(255, 167, 38)   # Lighter orange
        Danger          = [System.Drawing.Color]::FromArgb(239, 83, 80)    # Lighter red
        Background      = [System.Drawing.Color]::FromArgb(18, 18, 18)     # Very dark
        Surface         = [System.Drawing.Color]::FromArgb(30, 30, 30)     # Dark panels
        TextPrimary     = [System.Drawing.Color]::FromArgb(255, 255, 255)  # White text
        TextSecondary   = [System.Drawing.Color]::FromArgb(189, 189, 189)  # Light gray
        Border          = [System.Drawing.Color]::FromArgb(60, 60, 60)     # Dark borders
    }
}

# Default to Dark Mode
$script:CurrentTheme = "Dark"

function Get-ThemeColor {
    <#
    .SYNOPSIS
        Gets a color from the current theme
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Primary", "Secondary", "Accent", "Success", "Warning", "Danger", 
                     "Background", "Surface", "TextPrimary", "TextSecondary", "Border")]
        [string]$ColorName
    )
    
    return $ThemeColors[$script:CurrentTheme][$ColorName]
}

function Set-Theme {
    <#
    .SYNOPSIS
        Switches between light and dark themes
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Light", "Dark")]
        [string]$Theme
    )
    
    $script:CurrentTheme = $Theme
    
    # Apply theme to GUI if it exists
    if ($script:MainForm) {
        Apply-ThemeToGui
    }
    
    Write-Log "Theme changed to: $Theme" -Level "Info"
}

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

function Apply-ThemeToGui {
    <#
    .SYNOPSIS
        Applies the current theme colors to all GUI elements
    #>
    
    if (-not $script:MainForm) { return }
    
    try {
        # Update form background
        $script:MainForm.BackColor = Get-ThemeColor -ColorName "Background"
        
        # Recursively update all controls
        function Update-ControlColors {
            param ($Control)
            
            foreach ($child in $Control.Controls) {
                # Update panels
                if ($child -is [System.Windows.Forms.Panel]) {
                    $child.BackColor = Get-ThemeColor -ColorName "Surface"
                }
                
                # Update labels
                if ($child -is [System.Windows.Forms.Label]) {
                    $child.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
                    if ($child.Name -eq "StatusLabel") {
                        $child.BackColor = Get-ThemeColor -ColorName "Surface"
                    }
                }
                
                # Update checkboxes
                if ($child -is [System.Windows.Forms.CheckBox]) {
                    $child.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
                }
                
                # Recursively update nested controls
                if ($child.Controls.Count -gt 0) {
                    Update-ControlColors -Control $child
                }
            }
        }
        
        Update-ControlColors -Control $script:MainForm
        
        # Update specific labels if they exist
        if ($script:TitleLabel) {
            $script:TitleLabel.ForeColor = Get-ThemeColor -ColorName "Primary"
        }
        
        if ($script:SubtitleLabel) {
            $script:SubtitleLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
        }
        
        # Refresh the form
        $script:MainForm.Refresh()
    }
    catch {
        Write-Log "Error applying theme: $($_.Exception.Message)" -Level "Warning"
    }
}

function New-GuiButton {
    param(
        [string]$text,
        [int]$x,
        [int]$y,
        [int]$width,
        [int]$height,
        [string]$ColorType,
        [scriptblock]$action
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $text
    $button.Location = New-Object System.Drawing.Point($x, $y)
    $button.Size = New-Object System.Drawing.Size($width, $height)
    $button.BackColor = Get-ThemeColor -ColorName $ColorType

    # ALWAYS USE WHITE TEXT ON COLORED BUTTONS FOR MAXIMUM CONTRAST
    $button.ForeColor = [System.Drawing.Color]::White

    # Enhanced visual styling
    $button.FlatStyle = "Flat"
    $button.FlatAppearance.BorderSize = 2

    # Create a slightly darker border color for depth
    $baseColor = Get-ThemeColor -ColorName $ColorType
    $darkerColor = [System.Drawing.Color]::FromArgb(
        [Math]::Max(0, $baseColor.R - 30),
        [Math]::Max(0, $baseColor.G - 30),
        [Math]::Max(0, $baseColor.B - 30)
    )
    $button.FlatAppearance.BorderColor = $darkerColor

    # Improved typography
    $button.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5, [System.Drawing.FontStyle]::Bold)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand

    # Store original color in Tag property for hover effect
    $button.Tag = $button.BackColor

    # Add hover effect
    $button.Add_MouseEnter({
        if ($this.Tag -and $this.Tag -is [System.Drawing.Color]) {
            $origColor = $this.Tag
            $hoverColor = [System.Drawing.Color]::FromArgb(
                [Math]::Min(255, $origColor.R + 20),
                [Math]::Min(255, $origColor.G + 20),
                [Math]::Min(255, $origColor.B + 20)
            )
            $this.BackColor = $hoverColor
        }
    })

    $button.Add_MouseLeave({
        if ($this.Tag -and $this.Tag -is [System.Drawing.Color]) {
            $this.BackColor = $this.Tag
        }
    })

    if ($action) {
        $button.Add_Click($action)
    }

    return $button
}

function New-ThemeToggle {
    param (
        [int]$x,
        [int]$y
    )
    
    # Simple button toggle
    $toggleButton = New-Object System.Windows.Forms.Button
    $toggleButton.Location = New-Object System.Drawing.Point($x, $y)
    $toggleButton.Size = New-Object System.Drawing.Size(120, 35)
    $toggleButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $toggleButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $toggleButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $toggleButton.FlatAppearance.BorderSize = 0
    
    # Set initial state
    if ($script:CurrentTheme -eq "Dark") {
        $toggleButton.Text = "DARK MODE"
        $toggleButton.BackColor = Get-ThemeColor -ColorName "Primary"
        $toggleButton.ForeColor = [System.Drawing.Color]::White
    }
    else {
        $toggleButton.Text = "LIGHT MODE"
        $toggleButton.BackColor = Get-ThemeColor -ColorName "Border"
        $toggleButton.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    }
    
    # Click event to toggle
    $toggleButton.Add_Click({
        if ($script:CurrentTheme -eq "Dark") {
            Set-Theme -Theme "Light"
            $this.Text = "LIGHT MODE"
            $this.BackColor = Get-ThemeColor -ColorName "Border"
            $this.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
        }
        else {
            Set-Theme -Theme "Dark"
            $this.Text = "DARK MODE"
            $this.BackColor = Get-ThemeColor -ColorName "Primary"
            $this.ForeColor = [System.Drawing.Color]::White
        }
    })
    
    return $toggleButton
}

#══════════════════════════════════════════════════════════════════════════════
# END OF THEME SYSTEM
#══════════════════════════════════════════════════════════════════════════════

#──────────────────────────────────────────────────────────────
# MAIN CONFIGURATION DATA STRUCTURE
#──────────────────────────────────────────────────────────────
# Centralized configuration for all script operations
# Modify these values to customize behavior
$ConfigData = @{
    
    #───────────────────────────────────────────────────────────
    # File System Configuration
    #───────────────────────────────────────────────────────────
    
    # Working directory for logs and output files
    # During tenant connection, a tenant-specific subdirectory
    # will be created (e.g., C:\Temp\ContosoTenant\120320250125\)
    WorkDir = "C:\Temp\"
    
    #───────────────────────────────────────────────────────────
    # Data Collection Configuration
    #───────────────────────────────────────────────────────────
    
    # Default date range for data collection (days to look back)
    # Valid range: 1-365 days
    # Note: Larger values significantly increase processing time
    # Exchange Online message trace limited to 10 days
    DateRange = 14
    
    #───────────────────────────────────────────────────────────
    # IP Geolocation Configuration
    #───────────────────────────────────────────────────────────
    
    # IPStack API key is now retrieved from environment variable
    # Set IPSTACK_KEY environment variable with your API key
    # Get a free key at: https://ipstack.com/signup/free
    # 
    # To set permanently (PowerShell as Admin):
    #   [Environment]::SetEnvironmentVariable("IPSTACK_KEY", "your-api-key", "User")
    #
    # Or temporarily for current session:
    #   $env:IPSTACK_KEY = "your-api-key"
    
    # Expected sign-in countries for unusual location detection
    # Customize this list based on your organization's geographic presence
    # Sign-ins from countries NOT in this list will be flagged as unusual
    ExpectedCountries = @("United States", "Canada")
    
    #───────────────────────────────────────────────────────────
    # Microsoft Graph API Configuration
    #───────────────────────────────────────────────────────────
    
    # Required Microsoft Graph API scopes for full functionality
    # These permissions will be requested during authentication
    RequiredScopes = @(
        "User.Read.All",                    # Read all user profiles
        "AuditLog.Read.All",                # Read audit logs and sign-in activity
        "Directory.Read.All",               # Read directory data (groups, roles, etc.)
        "Mail.Read",                        # Read user mail (for inbox rules)
        "MailboxSettings.Read",             # Read mailbox settings
        "Mail.ReadWrite",                   # Read and write mail (if needed)
        "MailboxSettings.ReadWrite",        # Read and write mailbox settings
        "SecurityEvents.Read.All",          # Read security events
        "IdentityRiskEvent.Read.All",       # Read identity risk events
        "IdentityRiskyUser.Read.All",       # Read risky user information
        "Application.Read.All",             # Read application registrations
        "RoleManagement.Read.All",          # Read role assignments
        "Policy.Read.All",                  # Read policies (Conditional Access, etc.)
		"UserAuthenticationMethod.Read.All" # Read MFA Status
    )
    
    #───────────────────────────────────────────────────────────
    # Security Monitoring Configuration
    #───────────────────────────────────────────────────────────
    
    # High-risk administrative operations to monitor
    # These operations will be flagged with high severity in audit analysis
    # Add additional operations as needed for your security requirements
    HighRiskOperations = @(
        "Add mailbox permission",           # Mailbox access grants
        "Remove mailbox permission",        # Mailbox access removal
        "Update mailbox",                   # Mailbox configuration changes
        "Add member to role",               # Role membership additions
        "Remove member from role",          # Role membership removals
        "Create application",               # New app registrations
        "Update application",               # App registration modifications
        "Create inbox rule",                # New inbox rules (potential data exfiltration)
        "Update transport rule"             # Mail flow rule changes
    )
    
    #───────────────────────────────────────────────────────────
    # Performance Optimization Settings
    #───────────────────────────────────────────────────────────
    
    # Number of records to process in each batch
    # Larger values = faster processing but more memory usage
    # Recommended range: 250-1000
    BatchSize = 500
    
    # Maximum concurrent IP geolocation lookups
    # Limited to prevent API rate limiting
    # Note: Currently not used (sequential processing for stability)
    MaxConcurrentGeolookups = 10
    
    # IP geolocation cache timeout in seconds
    # Cached results older than this will be re-queried
    # Default: 3600 seconds (1 hour)
    CacheTimeout = 3600
}

#──────────────────────────────────────────────────────────────
# ETR (EXCHANGE TRACE REPORT) ANALYSIS CONFIGURATION
#──────────────────────────────────────────────────────────────
# Settings for message trace analysis and spam pattern detection
$ConfigData.ETRAnalysis = @{
    
    #───────────────────────────────────────────────────────────
    # File Detection Patterns
    #───────────────────────────────────────────────────────────
    # Patterns used to automatically detect ETR/message trace files
    # in the working directory. Add custom patterns as needed.
    FilePatterns = @(
        "ETR_*.csv",                        # Standard ETR export format
        "MessageTrace_*.csv",               # Common message trace export
        "ExchangeTrace_*.csv",              # Alternative naming
        "MT_*.csv",                         # Abbreviated format
        "*MessageTrace*.csv",               # Catch-all for message trace
        "MessageTraceResult.csv"            # Direct export name
    )
    
    #───────────────────────────────────────────────────────────
    # Spam Detection Thresholds
    #───────────────────────────────────────────────────────────
    
    # Maximum messages with identical subject before flagging as spam
    # Recommended: 50-100 for large organizations
    MaxSameSubjectMessages = 50
    
    # Maximum same-subject messages per hour
    # Lower threshold for time-based detection
    MaxSameSubjectPerHour = 20
    
    # Maximum total messages per sender before flagging
    # Detects compromised accounts with high send volume
    MaxMessagesPerSender = 200
    
    # Minimum subject length for analysis
    # Very short subjects are often spam
    MinSubjectLength = 5
    
    #───────────────────────────────────────────────────────────
    # Spam Keyword Patterns
    #───────────────────────────────────────────────────────────
    # Keywords commonly found in spam messages
    # Customize based on your organization's spam patterns
    SpamKeywords = @(
        # Urgency tactics
        "urgent", "act now", "limited time", "expires today",
        
        # Common spam words
        "free", "winner", "congratulations", "prize",
        
        # Call-to-action phrases
        "click here", "order now", "special offer", "buy now",
        
        # Trust/guarantee language
        "guaranteed", "risk-free", "no obligation", "certified",
        
        # Financial spam
        "make money", "earn cash", "get rich", "double your income",
        "work from home", "financial freedom",
        
        # Cryptocurrency/investment spam
        "bitcoin", "cryptocurrency", "investment opportunity",
        "crypto trading", "forex"
    )
    
    #───────────────────────────────────────────────────────────
    # Risk Scoring Weights
    #───────────────────────────────────────────────────────────
    # Point values assigned to different risk indicators
    # Higher values = more severe risk factor
    # Total risk score determines overall threat level
    RiskWeights = @{
        RiskyIPMatch      = 25   # Messages from IPs flagged in sign-in analysis (highest risk)
        ExcessiveVolume   = 20   # High message volume from single sender
        SpamKeywords      = 15   # Spam keywords in message subjects
        MassDistribution  = 15   # Same message sent to many recipients
        FailedDelivery    = 10   # High rate of delivery failures (spam detection)
        SuspiciousTimiming = 8   # Unusual send time patterns
    }
}

#──────────────────────────────────────────────────────────────
# REQUIRED .NET ASSEMBLIES
#──────────────────────────────────────────────────────────────
# Load necessary .NET assemblies for GUI and functionality
# These are required before creating any Windows Forms controls
Write-Host "Loading required .NET assemblies..." -ForegroundColor Cyan
try {
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    Add-Type -AssemblyName Microsoft.VisualBasic
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Write-Host "✓ Assemblies loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "✗ Failed to load required assemblies: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  The script may not function properly." -ForegroundColor Yellow
}

#──────────────────────────────────────────────────────────────
# GLOBAL GUI ELEMENT REFERENCES
#──────────────────────────────────────────────────────────────
# These variables store references to GUI elements for status updates
# Initialized to $null and populated when GUI is created
$Global:MainForm = $null            # Main application form
$Global:StatusLabel = $null         # Bottom status bar label
$Global:ConnectionLabel = $null     # Connection status label
$Global:TenantInfoLabel = $null     # Tenant information label
$Global:WorkDirLabel = $null        # Working directory display label
$Global:DateRangeLabel = $null      # Date range configuration label

#endregion

#region IPSTACK API KEY MANAGEMENT

#══════════════════════════════════════════════════════════════
# IPSTACK API KEY VALIDATION AND SETUP
#══════════════════════════════════════════════════════════════

function Get-IPStackAPIKey {
    <#
    .SYNOPSIS
        Retrieves the IPStack API key from environment variable.
    
    .DESCRIPTION
        Checks for the IPSTACK_KEY environment variable and returns 
        the API key if found. Returns $null if not configured.
    
    .OUTPUTS
        String - The API key if found, $null otherwise.
    
    .EXAMPLE
        $apiKey = Get-IPStackAPIKey
        if ($apiKey) { Write-Host "Key found" }
    #>
    
    [CmdletBinding()]
    param()
    
    # Check for environment variable (supports both User and Machine scope)
    $apiKey = $env:IPSTACK_KEY
    
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        return $null
    }
    
    return $apiKey.Trim()
}

function Test-IPStackAPIKey {
    <#
    .SYNOPSIS
        Validates the IPStack API key by making a test API call.
    
    .DESCRIPTION
        Tests if the provided API key is valid by querying a known IP address
        (8.8.8.8 - Google DNS) and checking for a successful response.
    
    .PARAMETER APIKey
        The IPStack API key to validate.
    
    .OUTPUTS
        PSCustomObject with properties:
        - IsValid: Boolean indicating if the key is valid
        - Message: Descriptive message about the result
        - QuotaRemaining: Remaining API calls (if available)
    
    .EXAMPLE
        $result = Test-IPStackAPIKey -APIKey "your-api-key"
        if ($result.IsValid) { Write-Host "Key is valid!" }
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$APIKey
    )
    
    try {
        # Test with Google's public DNS IP
        $testIP = "8.8.8.8"
        $uri = "http://api.ipstack.com/${testIP}?access_key=${APIKey}&output=json"
        
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop
        
        # Check for API error responses
        if ($response.success -eq $false) {
            $errorInfo = $response.error
            return [PSCustomObject]@{
                IsValid        = $false
                Message        = "API Error: $($errorInfo.info)"
                ErrorCode      = $errorInfo.code
                QuotaRemaining = $null
            }
        }
        
        # Check for valid response data
        if ($response.ip -eq $testIP) {
            return [PSCustomObject]@{
                IsValid        = $true
                Message        = "API key validated successfully"
                ErrorCode      = $null
                QuotaRemaining = $null  # Free tier doesn't return quota info
            }
        }
        
        return [PSCustomObject]@{
            IsValid        = $false
            Message        = "Unexpected API response format"
            ErrorCode      = $null
            QuotaRemaining = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            IsValid        = $false
            Message        = "Connection error: $($_.Exception.Message)"
            ErrorCode      = $null
            QuotaRemaining = $null
        }
    }
}

function Initialize-IPStackAPIKey {
    <#
    .SYNOPSIS
        Ensures IPStack API key is configured and valid.
    
    .DESCRIPTION
        Checks for existing IPSTACK_KEY environment variable, validates it,
        and prompts user for setup if not configured. Provides clear 
        instructions for obtaining a free API key.
    
    .PARAMETER Silent
        If specified, skips user prompts and returns status only.
    
    .OUTPUTS
        PSCustomObject with properties:
        - Success: Boolean indicating if a valid key is available
        - APIKey: The validated API key (or $null)
        - Source: "Environment" or "UserProvided"
        - Message: Status message
    
    .EXAMPLE
        $keyStatus = Initialize-IPStackAPIKey
        if ($keyStatus.Success) {
            # Proceed with geolocation lookups
        }
    #>
    
    [CmdletBinding()]
    param(
        [switch]$Silent
    )
    
    Write-Log "Checking IPStack API key configuration..." -Level "Info"
    
    # First, check for existing environment variable
    $existingKey = Get-IPStackAPIKey
    
    if ($existingKey) {
        Write-Log "Found IPSTACK_KEY environment variable, validating..." -Level "Info"
        
        $validation = Test-IPStackAPIKey -APIKey $existingKey
        
        if ($validation.IsValid) {
            Write-Log "IPStack API key validated successfully" -Level "Info"
            
            $Global:IPStackKeyState.IsValid = $true
            $Global:IPStackKeyState.KeySource = "Environment"
            $Global:IPStackKeyState.LastChecked = Get-Date
            
            return [PSCustomObject]@{
                Success = $true
                APIKey  = $existingKey
                Source  = "Environment"
                Message = "API key validated successfully"
            }
        }
        else {
            Write-Log "IPStack API key validation failed: $($validation.Message)" -Level "Warning"
            
            if (-not $Silent) {
                Write-Host ""
                Write-Host "WARNING: Your IPSTACK_KEY environment variable contains an invalid key." -ForegroundColor Yellow
                Write-Host "Error: $($validation.Message)" -ForegroundColor Yellow
                Write-Host ""
            }
        }
    }
    
    # No valid key found - prompt user if not silent
    if (-not $Silent) {
        return Request-IPStackAPIKey
    }
    
    # Silent mode with no valid key
    return [PSCustomObject]@{
        Success = $false
        APIKey  = $null
        Source  = $null
        Message = "No valid IPStack API key configured. Set IPSTACK_KEY environment variable."
    }
}

function Request-IPStackAPIKey {
    <#
    .SYNOPSIS
        Prompts user to enter IPStack API key with setup instructions.
    
    .DESCRIPTION
        Displays instructions for obtaining a free IPStack API key,
        prompts user to enter their key, validates it, and offers
        to save it as an environment variable.
    
    .OUTPUTS
        PSCustomObject with Success, APIKey, Source, and Message properties.
    #>
    
    [CmdletBinding()]
    param()
    
    $separator = "=" * 70
    
    Write-Host ""
    Write-Host $separator -ForegroundColor DarkYellow
    Write-Host "                   IPSTACK API KEY CONFIGURATION" -ForegroundColor DarkYellow
    Write-Host $separator -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  This tool requires an IPStack API key for IP geolocation lookups." -ForegroundColor White
    Write-Host "  IPStack provides a FREE tier with 100 lookups per month." -ForegroundColor White
    Write-Host ""
    Write-Host "  TO GET YOUR FREE API KEY:" -ForegroundColor Cyan
    Write-Host "  -------------------------" -ForegroundColor Cyan
    Write-Host "  1. Visit: " -ForegroundColor Gray -NoNewline
    Write-Host "https://ipstack.com/signup/free" -ForegroundColor Green
    Write-Host "  2. Create a free account (email verification required)" -ForegroundColor Gray
    Write-Host "  3. Copy your API Access Key from the dashboard" -ForegroundColor Gray
    Write-Host "  4. Paste it below when prompted" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: The free tier includes:" -ForegroundColor Yellow
    Write-Host "        - 100 API requests per month" -ForegroundColor Gray
    Write-Host "        - Basic geolocation data (country, city, region)" -ForegroundColor Gray
    Write-Host "        - IPv4 and IPv6 support" -ForegroundColor Gray
    Write-Host ""
    Write-Host $separator -ForegroundColor DarkYellow
    Write-Host ""
    
    # Prompt for API key
    $userKey = Read-Host "Enter your IPStack API key (or press Enter to skip)"
    
    if ([string]::IsNullOrWhiteSpace($userKey)) {
        Write-Host ""
        Write-Host "Skipping API key configuration." -ForegroundColor Yellow
        Write-Host "Geolocation will use fallback service (ip-api.com) with limited features." -ForegroundColor Yellow
        Write-Host ""
        
        return [PSCustomObject]@{
            Success = $false
            APIKey  = $null
            Source  = $null
            Message = "User skipped API key configuration"
        }
    }
    
    # Validate the provided key
    Write-Host ""
    Write-Host "Validating API key..." -ForegroundColor Cyan
    
    $validation = Test-IPStackAPIKey -APIKey $userKey.Trim()
    
    if ($validation.IsValid) {
        Write-Host "API key validated successfully!" -ForegroundColor Green
        Write-Host ""
        
        # Offer to save as environment variable
        $saveChoice = Read-Host "Would you like to save this key as an environment variable for future use? (Y/N)"
        
        if ($saveChoice -match '^[Yy]') {
            try {
                # Save to User environment (persists across sessions)
                [Environment]::SetEnvironmentVariable("IPSTACK_KEY", $userKey.Trim(), "User")
                
                # Also set for current session
                $env:IPSTACK_KEY = $userKey.Trim()
                
                Write-Host ""
                Write-Host "API key saved to user environment variables." -ForegroundColor Green
                Write-Host "It will be available automatically in future PowerShell sessions." -ForegroundColor Gray
                Write-Host ""
                
                $Global:IPStackKeyState.IsValid = $true
                $Global:IPStackKeyState.KeySource = "Environment"
                $Global:IPStackKeyState.LastChecked = Get-Date
                
                return [PSCustomObject]@{
                    Success = $true
                    APIKey  = $userKey.Trim()
                    Source  = "Environment"
                    Message = "API key validated and saved to environment"
                }
            }
            catch {
                Write-Host ""
                Write-Host "Could not save to environment variable: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "You can set it manually with:" -ForegroundColor Yellow
                Write-Host '  [Environment]::SetEnvironmentVariable("IPSTACK_KEY", "your-key", "User")' -ForegroundColor Gray
                Write-Host ""
            }
        }
        
        # Key is valid but not saved to environment
        $Global:IPStackKeyState.IsValid = $true
        $Global:IPStackKeyState.KeySource = "UserProvided"
        $Global:IPStackKeyState.LastChecked = Get-Date
        
        # Store in current session
        $env:IPSTACK_KEY = $userKey.Trim()
        
        return [PSCustomObject]@{
            Success = $true
            APIKey  = $userKey.Trim()
            Source  = "UserProvided"
            Message = "API key validated (session only)"
        }
    }
    else {
        Write-Host ""
        Write-Host "API key validation failed: $($validation.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please check your API key and try again." -ForegroundColor Yellow
        Write-Host "You can also set the IPSTACK_KEY environment variable manually." -ForegroundColor Gray
        Write-Host ""
        
        return [PSCustomObject]@{
            Success = $false
            APIKey  = $null
            Source  = $null
            Message = "Invalid API key: $($validation.Message)"
        }
    }
}

function Get-ValidatedIPStackKey {
    <#
    .SYNOPSIS
        Returns a validated IPStack API key for use in geolocation lookups.
    
    .DESCRIPTION
        Quick function to get the current API key, using cached validation
        state to avoid repeated API calls. Returns $null if no valid key.
    
    .OUTPUTS
        String - The validated API key, or $null if not available.
    #>
    
    [CmdletBinding()]
    param()
    
    # Check if we have a recently validated key
    if ($Global:IPStackKeyState.IsValid -and $Global:IPStackKeyState.LastChecked) {
        $timeSinceCheck = (Get-Date) - $Global:IPStackKeyState.LastChecked
        
        # Reuse validation for up to 1 hour
        if ($timeSinceCheck.TotalHours -lt 1) {
            return Get-IPStackAPIKey
        }
    }
    
    # Need to validate
    $keyStatus = Initialize-IPStackAPIKey -Silent
    
    if ($keyStatus.Success) {
        return $keyStatus.APIKey
    }
    
    return $null
}

#endregion

#region CORE HELPER FUNCTIONS

#══════════════════════════════════════════════════════════════
# INITIALIZATION AND ENVIRONMENT SETUP
#══════════════════════════════════════════════════════════════

function Initialize-Environment {
    <#
    .SYNOPSIS
        Initializes the script environment and working directory.
    
    .DESCRIPTION
        Performs initial setup tasks when the script starts:
        • Creates the working directory if it doesn't exist
        • Starts transcript logging for audit trail
        • Checks for existing Microsoft Graph connections
        • Validates directory permissions
        
        This function should be called once at script startup before
        any other operations are performed.
    
    .PARAMETER None
        This function does not accept parameters.
    
    .OUTPUTS
        None. Writes log messages to console and transcript.
    
    .EXAMPLE
        Initialize-Environment
        # Called at script startup to set up environment
    
    .NOTES
        - Creates transcript log with timestamp in filename
        - Uses existing Graph connection if available
        - Safe to call multiple times (idempotent)
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        # Create working directory if it doesn't exist
        if (-not (Test-Path -Path $ConfigData.WorkDir)) {
            try {
                New-Item -Path $ConfigData.WorkDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Log "Created working directory: $($ConfigData.WorkDir)" -Level "Info"
            }
            catch {
                Write-Log "Failed to create working directory: $($_.Exception.Message)" -Level "Error"
                throw "Cannot create working directory. Check permissions and path validity."
            }
        }
        else {
            Write-Log "Working directory exists: $($ConfigData.WorkDir)" -Level "Info"
        }

        # Start transcript logging for complete audit trail
        $logFile = Join-Path -Path $ConfigData.WorkDir -ChildPath "ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        try {
            Start-Transcript -Path $logFile -Force -ErrorAction Stop
            Write-Log "Script initialization started. Version $ScriptVer" -Level "Info"
            Write-Log "Transcript logging to: $logFile" -Level "Info"
        }
        catch {
            # Non-fatal error - script can continue without transcript
            Write-Log "Warning: Failed to start transcript: $($_.Exception.Message)" -Level "Warning"
            Write-Log "Continuing without transcript logging" -Level "Warning"
        }
        
        # Check for existing Microsoft Graph connection
        # This allows resuming work without re-authenticating
        Write-Log "Checking for existing Microsoft Graph connection..." -Level "Info"
        $existingConnection = Test-ExistingGraphConnection
        
        if ($existingConnection) {
            Write-Log "Using existing Microsoft Graph connection" -Level "Info"
            Write-Log "Tenant: $($Global:ConnectionState.TenantName)" -Level "Info"
            Write-Log "Account: $($Global:ConnectionState.Account)" -Level "Info"
        }
        else {
            Write-Log "No existing connection found. User will need to connect manually." -Level "Info"
        }
        
        # Initialize IPStack API key
        Write-Log "Checking IPStack API key configuration..." -Level "Info"
        $ipStackStatus = Initialize-IPStackAPIKey
        
        if ($ipStackStatus.Success) {
            Write-Log "IPStack API key configured ($($ipStackStatus.Source))" -Level "Info"
        }
        else {
            Write-Log "IPStack API key not configured - geolocation will use fallback service" -Level "Warning"
        }
        
        Write-Log "Environment initialization completed successfully" -Level "Info"
    }
    catch {
        Write-Log "Critical error during environment initialization: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

#══════════════════════════════════════════════════════════════
# LOGGING AND STATUS REPORTING
#══════════════════════════════════════════════════════════════

function Write-Log {
    <#
    .SYNOPSIS
        Writes formatted log entries to console and transcript.
    
    .DESCRIPTION
        Provides consistent, color-coded logging throughout the script.
        Log entries include timestamp and severity level, and are written
        to both the console (color-coded) and transcript file (if active).
        
        This is the primary logging mechanism used throughout the script
        and should be used instead of Write-Host for all status messages.
    
    .PARAMETER Message
        The log message to write. Can be a simple string or formatted text.
        Required parameter.
    
    .PARAMETER Level
        The severity level of the log entry. Valid values:
        • Info    - Normal operational messages (Green)
        • Warning - Non-critical issues or important notices (Yellow)
        • Error   - Error conditions requiring attention (Red)
        
        Default: Info
    
    .OUTPUTS
        None. Writes to console and transcript.
    
    .EXAMPLE
        Write-Log "Operation completed successfully" -Level "Info"
        # Output: [2025-01-20 14:30:45] [Info] Operation completed successfully
    
    .EXAMPLE
        Write-Log "Configuration file not found, using defaults" -Level "Warning"
        # Output: [2025-01-20 14:30:46] [Warning] Configuration file not found, using defaults
    
    .EXAMPLE
        Write-Log "Failed to connect to service" -Level "Error"
        # Output: [2025-01-20 14:30:47] [Error] Failed to connect to service
    
    .NOTES
        - Messages are automatically formatted with timestamp
        - Color coding helps quickly identify severity in console
        - All messages written to transcript for audit purposes
        - Thread-safe for concurrent logging
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    # Format timestamp for log entry (ISO 8601 compatible)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Color-code output based on severity level
    # Colors chosen for readability on both light and dark consoles
    switch ($Level) {
        "Info"    { 
            Write-Host $logEntry -ForegroundColor Green 
        }
        "Warning" { 
            Write-Host $logEntry -ForegroundColor Yellow 
        }
        "Error"   { 
            Write-Host $logEntry -ForegroundColor Red 
        }
    }
    
    # Note: Write-Host output is automatically captured by Start-Transcript
    # so we don't need to explicitly write to the transcript file
}

function Update-GuiStatus {
    <#
    .SYNOPSIS
        Updates the GUI status label with a message and color.
    
    .DESCRIPTION
        Provides visual feedback to the user through the GUI status bar.
        Also logs the message using Write-Log for audit purposes.
        
        This function is safe to call even if the GUI is not initialized
        (e.g., during initial script execution before GUI creation).
        
        The status bar is located at the bottom of the main window and
        provides real-time feedback during operations.
    
    .PARAMETER Message
        The status message to display in the GUI status bar.
        Should be concise but informative (recommended: < 100 characters).
        Required parameter.
    
    .PARAMETER Color
        The color for the status text (System.Drawing.Color object).
        Common colors:
        • Green  - Success/completion messages
        • Orange - In-progress or warning messages  
        • Red    - Error messages
        • Gray   - Informational messages
        
        Default: Gray (neutral color)
    
    .OUTPUTS
        None. Updates GUI and writes to log.
    
    .EXAMPLE
        Update-GuiStatus "Operation completed successfully" ([System.Drawing.Color]::Green)
        # Shows green success message in status bar
    
    .EXAMPLE
        Update-GuiStatus "Processing data..." ([System.Drawing.Color]::Orange)
        # Shows orange in-progress message
    
    .EXAMPLE
        Update-GuiStatus "Connection failed" ([System.Drawing.Color]::Red)
        # Shows red error message
    
    .NOTES
        - Automatically refreshes GUI to ensure immediate visibility
        - Safe to call before GUI initialization
        - Also logs message for audit trail
        - Forces GUI refresh with DoEvents for responsiveness
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [System.Drawing.Color]$Color = [System.Drawing.Color]::FromArgb(108, 117, 125)  # Default gray color
    )
    
    # Update GUI status label if it exists (GUI may not be initialized yet)
    if ($null -ne $Global:StatusLabel) {
        try {
            $Global:StatusLabel.Text = $Message
            $Global:StatusLabel.ForeColor = $Color
            $Global:StatusLabel.Refresh()
            
            # Process Windows message queue to ensure immediate GUI update
            [System.Windows.Forms.Application]::DoEvents()
        }
        catch {
            # Fail silently if GUI update fails - don't interrupt workflow
            Write-Log "Warning: Failed to update GUI status: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Always log the status message for audit trail
    Write-Log $Message
}

function Update-ConnectionStatus {
    <#
    .SYNOPSIS
        Updates the GUI connection status display.
    
    .DESCRIPTION
        Refreshes the connection status labels in the GUI based on the
        current global connection state. Shows:
        • Connection status (Connected/Not Connected)
        • Tenant name and ID
        • Connected user account
        
        The display is color-coded:
        • Green - Connected successfully
        • Red - Not connected
        • Blue - Tenant information
        • Gray - No connection info
    
    .PARAMETER None
        This function does not accept parameters. It reads from the
        global $Global:ConnectionState variable.
    
    .OUTPUTS
        None. Updates GUI elements directly.
    
    .EXAMPLE
        Update-ConnectionStatus
        # Called after connecting or disconnecting to refresh display
    
    .NOTES
        - Safe to call even if GUI elements don't exist
        - Reads current state from $Global:ConnectionState
        - Automatically color-codes based on connection status
        - Forces GUI refresh for immediate visibility
    #>
    
    [CmdletBinding()]
    param()
    
    # Only update if GUI elements exist
    if ($null -ne $Global:ConnectionLabel -and $null -ne $Global:TenantInfoLabel) {
        try {
            if ($Global:ConnectionState.IsConnected) {
                # Connected state - show green with tenant details
                $Global:ConnectionLabel.Text = "Microsoft Graph: Connected"
                $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Green
                
                # Format tenant info with account details
                $tenantInfo = "Tenant: $($Global:ConnectionState.TenantName) | Account: $($Global:ConnectionState.Account)"
                $Global:TenantInfoLabel.Text = $tenantInfo
                $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)  # Microsoft blue
            }
            else {
                # Disconnected state - show red with no info
                $Global:ConnectionLabel.Text = "Microsoft Graph: Not Connected"
                $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Red
                $Global:TenantInfoLabel.Text = "Not connected to any tenant"
                $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::Gray
            }
            
            # Force UI refresh to show changes immediately
            $Global:ConnectionLabel.Refresh()
            $Global:TenantInfoLabel.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        }
        catch {
            Write-Log "Warning: Failed to update connection status display: $($_.Exception.Message)" -Level "Warning"
        }
    }
}

function Update-WorkingDirectoryDisplay {
    <#
    .SYNOPSIS
        Updates the working directory configuration and GUI display.
    
    .DESCRIPTION
        Changes the working directory path in the global configuration
        and updates the GUI label to reflect the new path. This is used
        when the user manually changes the working directory or when a
        tenant-specific directory is created during connection.
        
        The function validates that the path is accessible and updates
        both the configuration and GUI atomically.
    
    .PARAMETER NewWorkDir
        The new working directory path to set. Should be a valid,
        accessible directory path. Required parameter.
    
    .OUTPUTS
        None. Updates configuration and GUI.
    
    .EXAMPLE
        Update-WorkingDirectoryDisplay -NewWorkDir "C:\M365Audit\Tenant1"
        # Changes working directory and updates display
    
    .EXAMPLE
        Update-WorkingDirectoryDisplay -NewWorkDir "D:\SecurityAnalysis\$(Get-Date -Format 'yyyyMMdd')"
        # Sets working directory with date-stamped folder
    
    .NOTES
        - Updates global $ConfigData.WorkDir configuration
        - Updates GUI label if it exists
        - Safe to call before GUI initialization
        - Does not create the directory (use Initialize-Environment)
        - Validates path format but not existence
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$NewWorkDir
    )
    
    # Update the global configuration
    $ConfigData.WorkDir = $NewWorkDir
    Write-Log "Working directory configuration updated to: $NewWorkDir" -Level "Info"
    
    # Update GUI display if it exists
    if ($null -ne $Global:WorkDirLabel) {
        try {
            $Global:WorkDirLabel.Text = "Working Directory: $NewWorkDir"
            $Global:WorkDirLabel.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
            Write-Log "Updated GUI working directory display" -Level "Info"
        }
        catch {
            Write-Log "Warning: Failed to update GUI working directory display: $($_.Exception.Message)" -Level "Warning"
        }
    }
}

#══════════════════════════════════════════════════════════════
# USER INTERACTION DIALOGS
#══════════════════════════════════════════════════════════════

function Get-Folder {
    <#
    .SYNOPSIS
        Shows a folder browser dialog for directory selection.
    
    .DESCRIPTION
        Displays a Windows folder browser dialog and returns the selected path.
        Used for selecting the working directory where logs and reports will
        be saved.
        
        The dialog shows a tree view of the file system and allows the user
        to navigate to or create a new folder.
    
    .PARAMETER initialDirectory
        The initial directory to show in the browser. If not specified or
        if the path doesn't exist, shows the "My Computer" root.
        Optional parameter.
    
    .OUTPUTS
        System.String. The selected folder path, or $null if the user cancels.
    
    .EXAMPLE
        $folder = Get-Folder -initialDirectory "C:\Temp"
        if ($folder) {
            Write-Host "Selected: $folder"
        }
    
    .EXAMPLE
        $folder = Get-Folder
        # Shows dialog starting at My Computer
    
    .NOTES
        - Returns $null if user clicks Cancel
        - Selected path is validated by Windows dialog
        - User can create new folders within the dialog
        - Thread-safe for GUI operations
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$initialDirectory = ""
    )
    
    try {
        # Load Windows Forms assembly if not already loaded
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
        
        # Create and configure folder browser dialog
        $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
        $foldername.Description = "Select a working folder for logs and reports"
        $foldername.rootfolder = "MyComputer"
        $foldername.ShowNewFolderButton = $true
        
        # Set initial directory if provided and valid
        if (-not [string]::IsNullOrEmpty($initialDirectory) -and (Test-Path $initialDirectory)) {
            $foldername.SelectedPath = $initialDirectory
        }
        
        # Show dialog and return selected path
        if ($foldername.ShowDialog() -eq "OK") {
            return $foldername.SelectedPath
        }
        
        return $null
    }
    catch {
        Write-Log "Error showing folder browser dialog: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Test-IPAddress {
    <#
    .SYNOPSIS
        Validates and categorizes IP addresses (IPv4 or IPv6)
    
    .DESCRIPTION
        Tests if a string is a valid IP address and determines:
        • IP version (IPv4 or IPv6)
        • Whether it's private/internal
        • Type of private address
    
    .PARAMETER IPAddress
        IP address string to validate
    
    .OUTPUTS
        PSCustomObject with validation results
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    $result = [PSCustomObject]@{
        IsValid = $false
        IPVersion = $null
        IsPrivate = $false
        PrivateType = $null
        ParsedIP = $null
    }
    
    try {
        $ipObj = [System.Net.IPAddress]::Parse($IPAddress)
        $result.IsValid = $true
        $result.ParsedIP = $ipObj
        
        if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $result.IPVersion = "IPv4"
            
            # Check IPv4 private ranges
            if ($IPAddress -match "^10\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Class A Private (10.0.0.0/8)"
            }
            elseif ($IPAddress -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Class B Private (172.16.0.0/12)"
            }
            elseif ($IPAddress -match "^192\.168\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Class C Private (192.168.0.0/16)"
            }
            elseif ($IPAddress -match "^127\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Loopback (127.0.0.0/8)"
            }
            elseif ($IPAddress -match "^169\.254\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Link-Local (169.254.0.0/16)"
            }
        }
        elseif ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $result.IPVersion = "IPv6"
            $ipLower = $IPAddress.ToLower()
            
            # Check IPv6 special ranges
            if ($ipLower -eq "::1") {
                $result.IsPrivate = $true
                $result.PrivateType = "Loopback (::1)"
            }
            elseif ($ipLower -match "^fe[89ab][0-9a-f]:") {
                $result.IsPrivate = $true
                $result.PrivateType = "Link-Local (fe80::/10)"
            }
            elseif ($ipLower -match "^f[cd][0-9a-f]{2}:") {
                $result.IsPrivate = $true
                $result.PrivateType = "Unique Local Address (fc00::/7)"
            }
            elseif ($ipLower -match "^fec[0-9a-f]:") {
                $result.IsPrivate = $true
                $result.PrivateType = "Site-Local (deprecated, fec0::/10)"
            }
            elseif ($ipLower -match "^::ffff:") {
                $result.IsPrivate = $true
                $result.PrivateType = "IPv4-Mapped (::ffff:0:0/96)"
            }
            elseif ($ipLower -match "^64:ff9b::") {
                $result.IsPrivate = $true
                $result.PrivateType = "IPv4/IPv6 Translation (64:ff9b::/96)"
            }
        }
    }
    catch {
        # Invalid IP address
        $result.IsValid = $false
    }
    
    return $result
}

function Get-DateRangeInput {
    <#
    .SYNOPSIS
        Prompts user for date range configuration.
    
    .DESCRIPTION
        Shows an input dialog for the user to specify how many days back
        to collect data. Validates the input is between 1-365 days and
        provides appropriate error messages for invalid input.
        
        The date range affects all data collection operations and determines
        how far back in time the script will query for logs and activities.
    
    .PARAMETER CurrentValue
        The current date range value to show as the default in the input box.
        Optional parameter. Default: 14 days.
    
    .OUTPUTS
        System.Int32. The new date range value (1-365), or $null if canceled or invalid.
    
    .EXAMPLE
        $newRange = Get-DateRangeInput -CurrentValue 14
        if ($newRange) {
            $ConfigData.DateRange = $newRange
        }
    
    .EXAMPLE
        $range = Get-DateRangeInput
        # Uses default current value of 14 days
    
    .NOTES
        - Returns $null if user cancels
        - Validates input is numeric and within valid range (1-365)
        - Shows appropriate error messages for invalid input
        - Warns user about performance impact of large ranges
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateRange(1, 365)]
        [int]$CurrentValue = 14
    )
    
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic
        
        # Show input box with current value and helpful information
        $newValue = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Enter the number of days to look back for data collection:`n`n" +
            "Current value: $CurrentValue days`n`n" +
            "Valid range: 1-365 days`n`n" +
            "Note: Larger values may take significantly longer to process." +
            "`nExchange message trace is limited to 10 days.",
            "Change Date Range",
            $CurrentValue
        )
        
        # Handle cancellation
        if ([string]::IsNullOrWhiteSpace($newValue)) {
            Write-Log "User cancelled date range input" -Level "Info"
            return $null
        }
        
        # Validate input is numeric
        $intValue = 0
        if ([int]::TryParse($newValue, [ref]$intValue)) {
            # Validate range
            if ($intValue -gt 0 -and $intValue -le 365) {
                Write-Log "User selected date range: $intValue days" -Level "Info"
                return $intValue
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Date range must be between 1 and 365 days.`n`nPlease try again.",
                    "Invalid Range",
                    "OK",
                    "Warning"
                )
                Write-Log "Invalid date range entered: $intValue (out of range)" -Level "Warning"
                return $null
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Please enter a valid number.`n`n'$newValue' is not a valid integer.",
                "Invalid Input",
                "OK",
                "Warning"
            )
            Write-Log "Invalid date range entered: '$newValue' (not numeric)" -Level "Warning"
            return $null
        }
    }
    catch {
        Write-Log "Error in date range input dialog: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#endregion

#region VERSION CHECKING AND UPDATE MANAGEMENT

#══════════════════════════════════════════════════════════════
# SCRIPT VERSION VALIDATION
#══════════════════════════════════════════════════════════════

function Test-ScriptVersion {
    <#
    .SYNOPSIS
        Checks if the script is running the latest version from GitHub.
    
    .DESCRIPTION
        Compares the current script version ($ScriptVer) with the version
        available on GitHub. If a newer version is found, optionally prompts
        the user to download the update.
        
        This function helps ensure users are running the latest version with
        all bug fixes and feature improvements.
        
        The version check:
        • Fetches the raw script content from GitHub
        • Extracts the version number using regex
        • Compares versions (simple string comparison)
        • Optionally shows message box with update prompt
        • Opens GitHub page in browser if user accepts
    
    .PARAMETER GitHubUrl
        The URL to the raw script file on GitHub. Should point to the
        main/master branch for stable releases.
        Default: Yeyland Wutani Security Tools repository
    
    .PARAMETER ShowMessageBox
        Whether to show interactive message boxes for user feedback.
        Set to $false for silent/automated version checking.
        Default: $true
    
    .OUTPUTS
        Hashtable with the following properties:
        • IsLatest       - Boolean, true if current version is latest
        • CurrentVersion - String, the current version number
        • LatestVersion  - String, the latest version from GitHub
        • Error          - String, error message if check failed (optional)
    
    .EXAMPLE
        $versionCheck = Test-ScriptVersion -ShowMessageBox $true
        if (-not $versionCheck.IsLatest) {
            Write-Warning "Update available: $($versionCheck.LatestVersion)"
        }
    
    .EXAMPLE
        # Silent version check without user interaction
        $versionCheck = Test-ScriptVersion -ShowMessageBox $false
        if ($versionCheck.Error) {
            Write-Host "Version check failed: $($versionCheck.Error)"
        }
    
    .EXAMPLE
        # Check against custom repository
        $check = Test-ScriptVersion -GitHubUrl "https://raw.githubusercontent.com/myorg/scripts/main/script.ps1"
    
    .NOTES
        - Requires internet connection to GitHub
        - Uses 10-second timeout for web request
        - Version comparison is simple string equality
        - Does not automatically download/install updates
        - Safe to call multiple times (no side effects)
        - Updates GUI status during operation
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$GitHubUrl = "https://raw.githubusercontent.com/the-last-one-left/YeylandWutani/refs/heads/main/Security/Get-M365SecurityAnalysis.ps1",
        
        [Parameter(Mandatory = $false)]
        [bool]$ShowMessageBox = $true
    )
    
    try {
        Update-GuiStatus "Checking for script updates..." ([System.Drawing.Color]::Orange)
        Write-Log "Checking script version against GitHub repository" -Level "Info"
        Write-Log "GitHub URL: $GitHubUrl" -Level "Info"
        
        # Fetch the latest script content from GitHub
        # Use basic parsing to avoid HTML rendering issues
        # Set reasonable timeout to avoid hanging
        $latestScriptContent = Invoke-WebRequest -Uri $GitHubUrl `
                                                  -UseBasicParsing `
                                                  -TimeoutSec 10 `
                                                  -ErrorAction Stop
        
        # Extract version number using regex
        # Pattern matches: $ScriptVer = "8.2" or $ScriptVer = '8.2'
        # Captures the version number in group 1
        $versionPattern = '\$ScriptVer\s*=\s*["'']([0-9.]+)["'']'
        
        if ($latestScriptContent.Content -match $versionPattern) {
            $latestVersion = $matches[1]
            $currentVersion = $ScriptVer
            
            Write-Log "Current version: $currentVersion | Latest version: $latestVersion" -Level "Info"
            
            # Compare versions (simple string comparison)
            # For more complex versioning, consider [System.Version] casting
            if ($latestVersion -eq $currentVersion) {
                # Running latest version
                Update-GuiStatus "Script is up to date (v$currentVersion)" ([System.Drawing.Color]::Green)
                Write-Log "Script is running the latest version" -Level "Info"
                
                if ($ShowMessageBox) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "You are running the latest version!`n`n" +
                        "Current Version: $currentVersion`n" +
                        "Latest Version: $latestVersion",
                        "Version Check - Up to Date",
                        "OK",
                        "Information"
                    )
                }
                
                return @{
                    IsLatest       = $true
                    CurrentVersion = $currentVersion
                    LatestVersion  = $latestVersion
                }
            }
            else {
                # Newer version available
                Update-GuiStatus "Update available! Current: v$currentVersion | Latest: v$latestVersion" ([System.Drawing.Color]::Orange)
                Write-Log "Newer version available: $latestVersion (current: $currentVersion)" -Level "Warning"
                
                if ($ShowMessageBox) {
                    $updateChoice = [System.Windows.Forms.MessageBox]::Show(
                        "A newer version of the script is available!`n`n" +
                        "Current Version: $currentVersion`n" +
                        "Latest Version: $latestVersion`n`n" +
                        "Would you like to download the latest version?`n`n" +
                        "Note: The script will open in your default browser.",
                        "Update Available",
                        "YesNo",
                        "Information"
                    )
                    
                    if ($updateChoice -eq "Yes") {
                        # Open GitHub page in default browser
                        $githubPageUrl = "https://github.com/the-last-one-left/YeylandWutani/blob/main/Security/Get-M365SecurityAnalysis.ps1"
                        Start-Process $githubPageUrl
                        Update-GuiStatus "Opening GitHub page for update download..." ([System.Drawing.Color]::Green)
                        Write-Log "User chose to update - opening GitHub page" -Level "Info"
                    }
                    else {
                        Update-GuiStatus "Update declined by user" ([System.Drawing.Color]::Orange)
                        Write-Log "User declined to update" -Level "Info"
                    }
                }
                
                return @{
                    IsLatest       = $false
                    CurrentVersion = $currentVersion
                    LatestVersion  = $latestVersion
                }
            }
        }
        else {
            # Could not parse version from GitHub content
            throw "Could not parse version number from GitHub script"
        }
    }
    catch {
        # Handle errors gracefully
        Update-GuiStatus "Version check failed: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error checking for updates: $($_.Exception.Message)" -Level "Error"
        
        if ($ShowMessageBox) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to check for updates.`n`n" +
                "Error: $($_.Exception.Message)`n`n" +
                "Current Version: $ScriptVer`n`n" +
                "Please check your internet connection or visit GitHub manually.",
                "Version Check Failed",
                "OK",
                "Warning"
            )
        }
        
        return @{
            IsLatest       = $null
            CurrentVersion = $ScriptVer
            LatestVersion  = $null
            Error          = $_.Exception.Message
        }
    }
}

#endregion

#region IP GEOLOCATION SERVICES

#══════════════════════════════════════════════════════════════
# IP ADDRESS GEOLOCATION
#══════════════════════════════════════════════════════════════

function Invoke-IPGeolocation {
    <#
    .SYNOPSIS
        Looks up geographic information for IPv4 or IPv6 addresses.
    
    .DESCRIPTION
        Performs geolocation lookup using a two-tier approach with IPv6 support:
        
        PRIMARY SERVICE: IPStack API
        • Supports both IPv4 and IPv6
        • Requires API key (configured in $ConfigData)
        • More detailed information
        
        FALLBACK SERVICE: ip-api.com
        • Free service supporting IPv4 and IPv6
        • Basic geographic information
        
        CACHING STRATEGY:
        • Results cached for 1 hour (configurable)
        • Reduces API calls significantly
        • Cache stored in provided hashtable
    
    .PARAMETER IPAddress
        IPv4 or IPv6 address to look up. Examples:
        • IPv4: 8.8.8.8, 192.168.1.1
        • IPv6: 2001:4860:4860::8888, ::1, fe80::1
        
    .PARAMETER RetryCount
        Number of retry attempts for failed lookups on the primary service.
        Valid range: 1-10, Default: 3
    
    .PARAMETER RetryDelay
        Base delay in seconds between retry attempts.
        Valid range: 1-30 seconds, Default: 2 seconds
    
    .PARAMETER Cache
        Hashtable for caching geolocation results.
        Required parameter (pass empty hashtable if not using cache).
    
    .OUTPUTS
        PSCustomObject with geolocation data
    
    .NOTES
        • Supports both IPv4 and IPv6 addresses
        • Private/internal IPs return generic data
        • IPv6 loopback (::1) and link-local (fe80::) are detected
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 30)]
        [int]$RetryDelay = 2,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )
    
    # ═══════════════════════════════════════════════════════════
    # VALIDATE IP ADDRESS (IPv4 or IPv6)
    # ═══════════════════════════════════════════════════════════
    
    $isIPv4 = $false
    $isIPv6 = $false
    
    # Try to parse as IP address
    try {
        $ipObj = [System.Net.IPAddress]::Parse($IPAddress)
        
        if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $isIPv4 = $true
        }
        elseif ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $isIPv6 = $true
        }
    }
    catch {
        Write-Log "Invalid IP address format: $IPAddress" -Level "Warning"
        return @{
            ip           = $IPAddress
            city         = "Invalid IP"
            region_name  = "Invalid IP"
            country_name = "Invalid IP"
            connection   = @{ isp = "Invalid IP" }
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # CHECK CACHE FIRST
    # ═══════════════════════════════════════════════════════════
    
    if ($Cache.ContainsKey($IPAddress)) {
        $cachedEntry = $Cache[$IPAddress]
        $cacheAge = (Get-Date) - $cachedEntry.CachedAt
        
        if ($cacheAge.TotalSeconds -lt $ConfigData.CacheTimeout) {
            return $cachedEntry.Data
        }
        else {
            $Cache.Remove($IPAddress)
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # CHECK FOR PRIVATE/SPECIAL IP ADDRESSES
    # ═══════════════════════════════════════════════════════════
    
    $isPrivate = $false
    $privateType = ""
    
    if ($isIPv4) {
        # IPv4 private ranges
        if ($IPAddress -match "^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.|^127\.") {
            $isPrivate = $true
            $privateType = "Private/Internal IPv4"
        }
        elseif ($IPAddress -match "^169\.254\.") {
            $isPrivate = $true
            $privateType = "Link-Local IPv4"
        }
    }
    elseif ($isIPv6) {
        # IPv6 special ranges
        $ipv6Lower = $IPAddress.ToLower()
        
        # Loopback ::1
        if ($ipv6Lower -eq "::1") {
            $isPrivate = $true
            $privateType = "Loopback IPv6"
        }
        # Link-local fe80::/10
        elseif ($ipv6Lower -match "^fe[89ab][0-9a-f]:") {
            $isPrivate = $true
            $privateType = "Link-Local IPv6"
        }
        # Unique local addresses fc00::/7 (fd00::/8 is most common)
        elseif ($ipv6Lower -match "^f[cd][0-9a-f]{2}:") {
            $isPrivate = $true
            $privateType = "Private IPv6 (ULA)"
        }
        # Site-local (deprecated but still seen) fec0::/10
        elseif ($ipv6Lower -match "^fec[0-9a-f]:") {
            $isPrivate = $true
            $privateType = "Site-Local IPv6 (deprecated)"
        }
        # IPv4-mapped IPv6 addresses ::ffff:0:0/96
        elseif ($ipv6Lower -match "^::ffff:") {
            $isPrivate = $true
            $privateType = "IPv4-mapped IPv6"
        }
    }
    
    if ($isPrivate) {
        $privateResult = @{
            ip           = $IPAddress
            city         = $privateType
            region_name  = "Private Network"
            country_name = "Private Network"
            connection   = @{ isp = "Internal" }
            ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
            is_private   = $true
        }
        
        $Cache[$IPAddress] = @{
            Data     = $privateResult
            CachedAt = Get-Date
        }
        
        return $privateResult
    }
    
    # ═══════════════════════════════════════════════════════════
    # ATTEMPT GEOLOCATION LOOKUP
    # ═══════════════════════════════════════════════════════════
    
    $attempt = 0
    $success = $false
    $result = $null
    
    # Get API key from environment variable
    $apiKey = Get-ValidatedIPStackKey
    
    # Try primary service (IPStack) with retries - only if API key is available
    if ($apiKey) {
        while ($attempt -lt $RetryCount -and -not $success) {
            $attempt++
            
            try {
                $uri = "http://api.ipstack.com/${IPAddress}?access_key=${apiKey}&output=json"
                
                $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop
                
                if ($response -and $response.ip) {
                    $result = @{
                        ip           = $response.ip
                        city         = if ($response.city) { $response.city } else { "Unknown" }
                        region_name  = if ($response.region_name) { $response.region_name } else { "Unknown" }
                        country_name = if ($response.country_name) { $response.country_name } else { "Unknown" }
                        connection   = @{ 
                            isp = if ($response.connection -and $response.connection.isp) { 
                                $response.connection.isp 
                            } else { 
                                "Unknown" 
                            }
                        }
                        ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
                        latitude     = $response.latitude
                        longitude    = $response.longitude
                        is_private   = $false
                    }
                    
                    $success = $true
                    
                    $Cache[$IPAddress] = @{
                        Data     = $result
                        CachedAt = Get-Date
                    }
                    
                    return $result
                }
            }
            catch {
                if ($attempt -lt $RetryCount) {
                    $delay = $RetryDelay * [Math]::Pow(2, $attempt - 1)
                    Start-Sleep -Seconds $delay
                }
            }
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # FALLBACK SERVICE (ip-api.com)
    # ═══════════════════════════════════════════════════════════
    
    if (-not $success) {
        try {
            # ip-api.com supports both IPv4 and IPv6
            $uri = "http://ip-api.com/json/${IPAddress}"
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop
            
            if ($response -and $response.status -eq "success") {
                $result = @{
                    ip           = $response.query
                    city         = if ($response.city) { $response.city } else { "Unknown" }
                    region_name  = if ($response.regionName) { $response.regionName } else { "Unknown" }
                    country_name = if ($response.country) { $response.country } else { "Unknown" }
                    connection   = @{ 
                        isp = if ($response.isp) { $response.isp } else { "Unknown" }
                    }
                    ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
                    latitude     = $response.lat
                    longitude    = $response.lon
                    fallback_source = "ip-api.com"
                    is_private   = $false
                }
                
                $success = $true
                
                $Cache[$IPAddress] = @{
                    Data     = $result
                    CachedAt = Get-Date
                }
                
                return $result
            }
        }
        catch {
            Write-Log "Fallback geolocation service also failed for $IPAddress : $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # ALL ATTEMPTS FAILED - RETURN FAILURE RESULT
    # ═══════════════════════════════════════════════════════════
    
    $failureResult = @{
        ip           = $IPAddress
        city         = "Unknown"
        region_name  = "Unknown"
        country_name = "Unknown"
        connection   = @{ isp = "Unknown" }
        ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
        is_private   = $false
    }
    
    $Cache[$IPAddress] = @{
        Data     = $failureResult
        CachedAt = Get-Date
    }
    
    return $failureResult
}

#endregion


#region CONNECTION MANAGEMENT

#══════════════════════════════════════════════════════════════
# MICROSOFT GRAPH CONNECTION MANAGEMENT
#══════════════════════════════════════════════════════════════

function Test-ExistingGraphConnection {
    <#
    .SYNOPSIS
        Checks for and loads existing Microsoft Graph connection.
    
    .DESCRIPTION
        Tests if there's already an active Microsoft Graph connection from
        a previous session or script execution. If found:
        • Loads connection details into global state
        • Retrieves tenant information
        • Creates tenant-specific working directory
        • Updates GUI to reflect connection status
        
        This allows users to resume work without re-authenticating, which is
        especially useful during script development and testing.
        
        TENANT-SPECIFIC DIRECTORY:
        When an existing connection is detected, a tenant-specific working
        directory is created with the format:
        C:\Temp\<TenantName>\<Timestamp>\
        
        This ensures data from different tenants doesn't mix and provides
        clear organization for audit purposes.
    
    .PARAMETER None
        This function does not accept parameters.
    
    .OUTPUTS
        System.Boolean
        Returns $true if existing connection found and loaded, $false otherwise.
    
    .EXAMPLE
        if (Test-ExistingGraphConnection) {
            Write-Host "Using existing connection to $($Global:ConnectionState.TenantName)"
        } else {
            Write-Host "No existing connection - authentication required"
        }
    
    .EXAMPLE
        # Called during script initialization
        Initialize-Environment
        # Automatically calls Test-ExistingGraphConnection
    
    .NOTES
        - Safe to call multiple times (idempotent)
        - Updates $Global:ConnectionState if connection found
        - Creates tenant-specific directory automatically
        - Updates GUI connection status
        - Does not re-authenticate if connection exists
        - Connection may be stale if token expired
    #>
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()
    
    try {
        # Try to get current Microsoft Graph context
        # This will succeed if there's an active connection
        $context = Get-MgContext -ErrorAction Stop
        
        if ($context) {
            Write-Log "Detected existing Microsoft Graph connection" -Level "Info"
            Write-Log "Context: Tenant=$($context.TenantId), Account=$($context.Account)" -Level "Info"
            
            # Retrieve organization details for tenant name
            try {
                $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                
                if (-not $organization) {
                    Write-Log "Warning: Could not retrieve organization details" -Level "Warning"
                    return $false
                }
                
                #──────────────────────────────────────────────────
                # CREATE TENANT-SPECIFIC WORKING DIRECTORY
                #──────────────────────────────────────────────────
                # Format: C:\Temp\<TenantName>\<HHMMDDMMYY>\
                # This prevents data mixing between tenants
                
                # Clean tenant name - remove invalid filename characters
                $cleanTenantName = $organization.DisplayName -replace '[<>:"/\\|?*]', '_'
                
                # Create timestamp for unique directory
                $timestamp = Get-Date -Format "HHmmddMMyy"
                
                # Build full path
                $newWorkDir = "C:\Temp\$cleanTenantName\$timestamp"
                
                try {
                    if (-not (Test-Path -Path $newWorkDir)) {
                        New-Item -Path $newWorkDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created tenant-specific working directory: $newWorkDir" -Level "Info"
                    }
                    
                    # Update working directory configuration and display
                    Update-WorkingDirectoryDisplay -NewWorkDir $newWorkDir
                }
                catch {
                    Write-Log "Could not create tenant-specific directory, using default: $($_.Exception.Message)" -Level "Warning"
                    # Continue with default directory - non-fatal error
                }
                
                #──────────────────────────────────────────────────
                # UPDATE GLOBAL CONNECTION STATE
                #──────────────────────────────────────────────────
                $Global:ConnectionState = @{
                    IsConnected = $true
                    TenantId    = $context.TenantId
                    TenantName  = $organization.DisplayName
                    Account     = $context.Account
                    ConnectedAt = Get-Date
                }
                
                # Update GUI to show connection status
                Update-ConnectionStatus
                Update-GuiStatus "Existing Microsoft Graph connection detected and loaded" ([System.Drawing.Color]::Green)
                
                Write-Log "Successfully loaded existing connection" -Level "Info"
                Write-Log "Tenant: $($organization.DisplayName)" -Level "Info"
                Write-Log "Account: $($context.Account)" -Level "Info"
                Write-Log "Working directory: $($ConfigData.WorkDir)" -Level "Info"
                
                return $true
            }
            catch {
                Write-Log "Could not retrieve organization details from existing connection: $($_.Exception.Message)" -Level "Warning"
                return $false
            }
        }
    }
    catch {
        # No existing connection - this is expected on first run
        Write-Log "No existing Microsoft Graph connection found" -Level "Info"
        return $false
    }
    
    return $false
}

function Connect-TenantServices {
    <#
    .SYNOPSIS
        Establishes connection to Microsoft Graph and Exchange Online.
    
    .DESCRIPTION
        Comprehensive connection function that orchestrates the entire
        authentication and setup process:
        
        PHASE 1: MODULE VERIFICATION
        • Check for required Microsoft Graph modules
        • Prompt to install missing modules
        • Import all required modules
        
        PHASE 2: AUTHENTICATION
        • Clear any existing connections (force fresh login)
        • Prompt user for tenant selection
        • Authenticate with Microsoft Graph (interactive browser)
        • Request all required API scopes
        
        PHASE 3: TENANT SETUP
        • Retrieve tenant information
        • Create tenant-specific working directory
        • Update global connection state
        • Start tenant-specific transcript logging
        
        PHASE 4: VALIDATION
        • Test admin audit log access
        • Display audit status to user
        • Provide recommendations if issues found
        
        PHASE 5: EXCHANGE ONLINE
        • Check for Exchange Online module
        • Clean up any existing EXO sessions
        • Connect to Exchange Online
        • Verify connection with test command
        • Initialize EXO connection state
        
        The function provides detailed user feedback throughout and handles
        errors gracefully at each stage.
    
    .PARAMETER None
        This function does not accept parameters. Configuration comes from
        the global $ConfigData structure.
    
    .OUTPUTS
        System.Boolean
        Returns $true if connection successful, $false otherwise.
    
    .EXAMPLE
        if (Connect-TenantServices) {
            Write-Host "Successfully connected to tenant"
            # Proceed with data collection
        } else {
            Write-Host "Connection failed"
            exit 1
        }
    
    .EXAMPLE
        # Called from GUI button
        $btnConnect.Add_Click({
            $result = Connect-TenantServices
            if ($result) {
                Enable-DataCollectionButtons
            }
        })
    
    .NOTES
        - Requires user interaction (browser authentication)
        - May take 30-60 seconds to complete
        - Forces fresh login (clears cached credentials)
        - Creates tenant-specific directory structure
        - Updates GUI throughout process
        - Handles module installation if needed
        - Tests critical permissions after connection
        - Exchange Online connection is optional (non-fatal if fails)
    #>
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()
    
    #══════════════════════════════════════════════════════════
    # PHASE 1: MODULE VERIFICATION AND INSTALLATION
    #══════════════════════════════════════════════════════════
    
    Clear-Host
    Update-GuiStatus "Checking Microsoft Graph PowerShell modules..." ([System.Drawing.Color]::Orange)
    
    # Define required Graph modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",           # Core authentication
        "Microsoft.Graph.Users",                    # User operations
        "Microsoft.Graph.Reports",                  # Sign-in logs
		 "Microsoft.Graph.Beta.Reports",              # BETA - for complete data
        "Microsoft.Graph.Identity.DirectoryManagement",  # Directory operations
        "Microsoft.Graph.Applications"              # App registrations
    )
    
    $missingModules = @()
    
    # Check which modules are missing
    Write-Log "Checking for required Microsoft Graph modules..." -Level "Info"
    foreach ($module in $requiredModules) {
        $installedModule = Get-Module -Name $module -ListAvailable | Select-Object -Last 1
        if ($null -eq $installedModule) {
            $missingModules += $module
            Write-Log "Missing module: $module" -Level "Warning"
        }
        else {
            Write-Log "$module found (Version: $($installedModule.Version))" -Level "Info"
        }
    }
    
    # Install missing modules if needed
    if ($missingModules.Count -gt 0) {
        Update-GuiStatus "Missing required modules: $($missingModules -join ', ')" ([System.Drawing.Color]::Red)
        
        $installPrompt = [System.Windows.Forms.MessageBox]::Show(
            "Missing required Microsoft Graph modules:`n`n" +
            ($missingModules -join "`n") + "`n`n" +
            "These modules are required for the script to function.`n" +
            "Install missing modules now?`n`n" +
            "Note: Installation may take several minutes.",
            "Missing Modules",
            "YesNo",
            "Question"
        )
        
        if ($installPrompt -eq "Yes") {
            Update-GuiStatus "Installing Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
            
            try {
                foreach ($module in $missingModules) {
                    Write-Log "Installing $module..." -Level "Info"
                    Update-GuiStatus "Installing $module..." ([System.Drawing.Color]::Orange)
                    
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                    Write-Log "$module installed successfully" -Level "Info"
                }
                Update-GuiStatus "All modules installed successfully" ([System.Drawing.Color]::Green)
            }
            catch {
                $errorMsg = "Failed to install required modules: $($_.Exception.Message)"
                Update-GuiStatus $errorMsg ([System.Drawing.Color]::Red)
                Write-Log $errorMsg -Level "Error"
                
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to install required modules:`n`n$($_.Exception.Message)`n`n" +
                    "Please install modules manually or run PowerShell as Administrator.",
                    "Installation Error",
                    "OK",
                    "Error"
                )
                return $false
            }
        }
        else {
            Write-Log "User declined to install required modules" -Level "Warning"
            Update-GuiStatus "User declined to install required modules" ([System.Drawing.Color]::Red)
            return $false
        }
    }
    
    #══════════════════════════════════════════════════════════
    # PHASE 2: MODULE IMPORT AND AUTHENTICATION PREPARATION
    #══════════════════════════════════════════════════════════
    
    try {
        # Import required modules
        Update-GuiStatus "Loading Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
        Write-Log "Importing Microsoft Graph modules..." -Level "Info"
        
        foreach ($module in $requiredModules) {
            Import-Module $module -Force -ErrorAction Stop
        }
        Write-Log "All modules imported successfully" -Level "Info"
        
        # Clear any existing context for fresh login
        # This ensures we don't reuse potentially expired tokens
        Update-GuiStatus "Clearing cached authentication context..." ([System.Drawing.Color]::Orange)
        Write-Log "Clearing any existing Microsoft Graph connection..." -Level "Info"
        
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Log "Cleared existing Microsoft Graph connection" -Level "Info"
        }
        catch {
            # Ignore errors - not connected is fine
        }
        
        # Reset global connection state
        $Global:ConnectionState = @{
            IsConnected = $false
            TenantId    = $null
            TenantName  = $null
            Account     = $null
            ConnectedAt = $null
        }
        
        #══════════════════════════════════════════════════════════
        # PHASE 3: USER AUTHENTICATION
        #══════════════════════════════════════════════════════════
        
        # Prompt user about tenant selection
        Update-GuiStatus "Prompting for tenant selection..." ([System.Drawing.Color]::Orange)
        
        $tenantPrompt = [System.Windows.Forms.MessageBox]::Show(
            "You will now be prompted to sign in to Microsoft Graph.`n`n" +
            "IMPORTANT:`n" +
            "• If you have access to multiple tenants, carefully select the correct one`n" +
            "• The browser authentication window will open shortly`n" +
            "• You must have appropriate admin permissions in the tenant`n`n" +
            "Required permissions:`n" +
            "• Global Administrator, Security Administrator, or`n" +
            "• Security Reader + Exchange Administrator (minimum)`n`n" +
            "Continue with authentication?",
            "Tenant Selection Required",
            "OKCancel",
            "Information"
        )
        
        if ($tenantPrompt -eq "Cancel") {
            Write-Log "User cancelled authentication" -Level "Info"
            Update-GuiStatus "User cancelled authentication" ([System.Drawing.Color]::Orange)
            return $false
        }
        
        # Connect to Microsoft Graph with interactive authentication
        Update-GuiStatus "Opening browser for Microsoft Graph authentication..." ([System.Drawing.Color]::Orange)
        Write-Log "Starting interactive authentication to Microsoft Graph" -Level "Info"
        Write-Log "Requesting scopes: $($ConfigData.RequiredScopes -join ', ')" -Level "Info"
        
        # This will open a browser window for authentication
        Connect-MgGraph -Scopes $ConfigData.RequiredScopes -ErrorAction Stop | Out-Null
        
        Write-Log "Microsoft Graph authentication completed" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 4: TENANT INFORMATION RETRIEVAL
        #══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Retrieving tenant information..." ([System.Drawing.Color]::Orange)
        Write-Log "Retrieving tenant context and organization information..." -Level "Info"
        
        $context = Get-MgContext -ErrorAction Stop
        $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        
        if (-not $context -or -not $organization) {
            throw "Failed to retrieve tenant context or organization information"
        }
        
        Write-Log "Successfully retrieved tenant information" -Level "Info"
        Write-Log "Tenant ID: $($context.TenantId)" -Level "Info"
        Write-Log "Tenant Name: $($organization.DisplayName)" -Level "Info"
        Write-Log "Connected Account: $($context.Account)" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 5: TENANT-SPECIFIC DIRECTORY SETUP
        #══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Setting up tenant-specific working directory..." ([System.Drawing.Color]::Orange)
        Write-Log "Creating tenant-specific working directory..." -Level "Info"
        
        # Clean tenant name for filesystem
        $cleanTenantName = $organization.DisplayName -replace '[<>:"/\\|?*]', '_'
        $timestamp = Get-Date -Format "HHmmddMMyy"
        $newWorkDir = "C:\Temp\$cleanTenantName\$timestamp"
        
        try {
            if (-not (Test-Path -Path $newWorkDir)) {
                New-Item -Path $newWorkDir -ItemType Directory -Force | Out-Null
                Write-Log "Created tenant-specific working directory: $newWorkDir" -Level "Info"
            }
            
            # Update configuration and GUI
            Update-WorkingDirectoryDisplay -NewWorkDir $newWorkDir
            Update-GuiStatus "Working directory updated to: $newWorkDir" ([System.Drawing.Color]::Green)
        }
        catch {
            Write-Log "Warning: Could not create tenant-specific directory, using default: $($_.Exception.Message)" -Level "Warning"
            # Non-fatal - continue with default directory
        }
        
        #══════════════════════════════════════════════════════════
        # PHASE 6: UPDATE CONNECTION STATE AND LOGGING
        #══════════════════════════════════════════════════════════
        
        # Update global connection state
        $Global:ConnectionState = @{
            IsConnected = $true
            TenantId    = $context.TenantId
            TenantName  = $organization.DisplayName
            Account     = $context.Account
            ConnectedAt = Get-Date
        }
        
        # Start new transcript in tenant-specific directory
        $logFile = Join-Path -Path $ConfigData.WorkDir -ChildPath "ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            Start-Transcript -Path $logFile -Force
            Write-Log "Started new transcript in tenant-specific directory" -Level "Info"
        }
        catch {
            Write-Log "Could not start transcript in new directory: $($_.Exception.Message)" -Level "Warning"
        }
        
        # Update GUI
        Update-ConnectionStatus
        Update-GuiStatus "Connected to Microsoft Graph successfully" ([System.Drawing.Color]::Green)
        
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        Write-Log "SUCCESSFULLY CONNECTED TO MICROSOFT GRAPH" -Level "Info"
        Write-Log "Tenant: $($organization.DisplayName)" -Level "Info"
        Write-Log "Tenant ID: $($context.TenantId)" -Level "Info"
        Write-Log "Account: $($context.Account)" -Level "Info"
        Write-Log "Working Directory: $($ConfigData.WorkDir)" -Level "Info"
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 7: AUDIT LOG VALIDATION
        #══════════════════════════════════════════════════════════
        
        Write-Log "Testing admin audit log configuration..." -Level "Info"
        $auditStatus = Test-AdminAuditLogging -ShowProgress $true
        
        # Show audit status in GUI
        if ($auditStatus.IsEnabled) {
            if ($auditStatus.HasRecentData) {
                Update-GuiStatus "Connection complete - Admin audit logging is enabled and working" ([System.Drawing.Color]::Green)
            }
            else {
                Update-GuiStatus "Connection complete - Admin audit logging enabled but no recent data" ([System.Drawing.Color]::Orange)
            }
        }
        else {
            Update-GuiStatus "Connection complete - WARNING: Admin audit logging issue detected" ([System.Drawing.Color]::Red)
        }
        
        # Show audit status popup to user
        Show-AuditLogStatusWarning -AuditStatus $auditStatus
        Write-Log "Admin audit log status: $($auditStatus.Status) - $($auditStatus.Message)" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 8: EXCHANGE ONLINE CONNECTION
        #══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Preparing Exchange Online connection..." ([System.Drawing.Color]::Orange)
        Write-Log "Preparing Exchange Online connection after Graph connection" -Level "Info"
        
        # Clean up any existing Exchange Online sessions first
        $existingSessions = Get-PSSession | Where-Object { 
            $_.ConfigurationName -eq "Microsoft.Exchange" 
        }
        
        if ($existingSessions) {
            Update-GuiStatus "Cleaning up existing Exchange Online sessions..." ([System.Drawing.Color]::Orange)
            Write-Log "Found $($existingSessions.Count) existing Exchange Online session(s), cleaning up..." -Level "Info"
            
            try {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            }
            catch {
                # Force remove sessions if disconnect fails
                $existingSessions | Remove-PSSession -ErrorAction SilentlyContinue
            }
        }
        
        Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Orange)
        
        try {
            # Check if Exchange Online module is available
            if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
                Update-GuiStatus "Installing Exchange Online module..." ([System.Drawing.Color]::Orange)
                Write-Log "Exchange Online module not found, installing..." -Level "Info"
                
                Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Log "Exchange Online module installed successfully" -Level "Info"
            }
            
            # Import the module
            if (-not (Get-Module -Name ExchangeOnlineManagement)) {
                Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
                Write-Log "Exchange Online module imported" -Level "Info"
            }
            
            # Connect to Exchange Online (uses same auth as Graph when possible)
            Connect-ExchangeOnline -ShowProgress $false -ShowBanner:$false -ErrorAction Stop
            
            # Test connection to verify it worked
            $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
            if ($testResult) {
                Write-Log "Exchange Online connection successful and verified" -Level "Info"
                Update-GuiStatus "Connected to both Microsoft Graph and Exchange Online" ([System.Drawing.Color]::Green)
                
                # Initialize Exchange Online state tracking
                $Global:ExchangeOnlineState = @{
                    IsConnected       = $true
                    LastChecked       = Get-Date
                    ConnectionAttempts = 0
                }
            }
        }
        catch {
            # Exchange Online connection is non-fatal
            Write-Log "Exchange Online connection failed (non-fatal): $($_.Exception.Message)" -Level "Warning"
            Update-GuiStatus "Graph connected, Exchange Online failed - will retry during inbox rules collection" ([System.Drawing.Color]::Orange)
            
            # Initialize Exchange Online state as failed
            $Global:ExchangeOnlineState = @{
                IsConnected       = $false
                LastChecked       = Get-Date
                ConnectionAttempts = 1
            }
        }
        
        #══════════════════════════════════════════════════════════
        # PHASE 9: SUCCESS SUMMARY
        #══════════════════════════════════════════════════════════
        
        $exoStatus = if ($Global:ExchangeOnlineState.IsConnected) { "Connected" } else { "Failed (will retry)" }
        
        $successMessage = "Successfully connected to Microsoft Graph!`n`n" +
                         "═══════════════════════════════════════`n" +
                         "TENANT INFORMATION`n" +
                         "═══════════════════════════════════════`n" +
                         "Tenant: $($organization.DisplayName)`n" +
                         "Tenant ID: $($context.TenantId)`n" +
                         "Account: $($context.Account)`n" +
                         "Working Directory: $newWorkDir`n`n" +
                         "═══════════════════════════════════════`n" +
                         "CONNECTION STATUS`n" +
                         "═══════════════════════════════════════`n" +
                         "Microsoft Graph: ✓ Connected`n" +
                         "Exchange Online: $exoStatus`n" +
                         "Admin Audit: $($auditStatus.Status)`n`n" +
                         "You can now proceed with data collection."
        
        [System.Windows.Forms.MessageBox]::Show($successMessage, "Connection Successful", "OK", "Information")
        
        return $true
    }
    catch {
        # Handle connection failure
        $errorMsg = "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        Update-GuiStatus $errorMsg ([System.Drawing.Color]::Red)
        Write-Log $errorMsg -Level "Error"
        
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to connect to Microsoft Graph:`n`n$($_.Exception.Message)`n`n" +
            "Please check:`n" +
            "• Internet connection is active`n" +
            "• You have appropriate admin permissions`n" +
            "• Multi-factor authentication is completed`n" +
            "• Firewall/proxy allows connections to Microsoft services",
            "Connection Failed",
            "OK",
            "Error"
        )
        
        return $false
    }
}

function Disconnect-GraphSafely {
    <#
    .SYNOPSIS
        Safely disconnects from Microsoft Graph.
    
    .DESCRIPTION
        Performs a clean disconnect from Microsoft Graph and updates
        the global connection state. Optionally shows confirmation message.
        
        This function:
        • Disconnects active Graph connection
        • Resets global connection state
        • Updates GUI to reflect disconnection
        • Logs the disconnect operation
        • Shows optional confirmation to user
    
    .PARAMETER ShowMessage
        Whether to show a confirmation message box after disconnect.
        Default: $false (silent disconnect)
    
    .OUTPUTS
        None. Updates global state and GUI.
    
    .EXAMPLE
        Disconnect-GraphSafely -ShowMessage $true
        # Disconnects and shows confirmation dialog
    
    .EXAMPLE
        # Silent disconnect during cleanup
        Disconnect-GraphSafely
    
    .NOTES
        - Safe to call even if not connected
        - Resets connection state even if disconnect fails
        - Non-blocking (doesn't halt script on error)
        - Updates GUI connection status
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool]$ShowMessage = $false
    )
    
    try {
        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Disconnecting from Microsoft Graph..." ([System.Drawing.Color]::Orange)
            Write-Log "Disconnecting from Microsoft Graph..." -Level "Info"
            
            Disconnect-MgGraph -ErrorAction Stop
            
            # Reset global connection state
            $Global:ConnectionState = @{
                IsConnected = $false
                TenantId    = $null
                TenantName  = $null
                Account     = $null
                ConnectedAt = $null
            }
            
            Update-ConnectionStatus
            Update-GuiStatus "Disconnected from Microsoft Graph" ([System.Drawing.Color]::Green)
            Write-Log "Successfully disconnected from Microsoft Graph" -Level "Info"
            
            if ($ShowMessage) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Successfully disconnected from Microsoft Graph.",
                    "Disconnected",
                    "OK",
                    "Information"
                )
            }
        }
        else {
            Write-Log "Disconnect called but no active connection found" -Level "Info"
        }
    }
    catch {
        Write-Log "Error during disconnect: $($_.Exception.Message)" -Level "Warning"
        # Reset connection state anyway
        $Global:ConnectionState.IsConnected = $false
        Update-ConnectionStatus
    }
}

#══════════════════════════════════════════════════════════════
# EXCHANGE ONLINE CONNECTION MANAGEMENT
#══════════════════════════════════════════════════════════════

function Connect-ExchangeOnlineIfNeeded {
    <#
    .SYNOPSIS
        Ensures Exchange Online connection is established.
    
    .DESCRIPTION
        Checks for existing Exchange Online connection and establishes a new
        connection if needed. Updates global connection state tracking.
        
        This function is called before operations that require Exchange Online:
        • Inbox rules collection
        • Message trace operations
        • Mailbox settings retrieval
        
        Connection verification:
        • Tests connection with Get-AcceptedDomain
        • Updates last checked timestamp
        • Tracks connection attempts for retry logic
    
    .OUTPUTS
        System.Boolean
        Returns $true if Exchange Online is connected, $false otherwise.
    
    .EXAMPLE
        if (Connect-ExchangeOnlineIfNeeded) {
            $rules = Get-InboxRule -Mailbox $user
        }
    
    .NOTES
        - Non-fatal errors (returns false instead of throwing)
        - Updates $Global:ExchangeOnlineState
        - Installs module if missing
        - Uses modern authentication
        - Inherits credentials from Graph when possible
    #>
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()
    
    try {
        # Check if Exchange Online module is available
        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            Write-Log "Exchange Online module not found - attempting to install..." -Level "Warning"
            Update-GuiStatus "Installing Exchange Online module..." ([System.Drawing.Color]::Orange)
            
            try {
                Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
                Write-Log "Exchange Online module installed successfully" -Level "Info"
            }
            catch {
                Write-Log "Failed to install Exchange Online module: $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Exchange Online module installation failed" ([System.Drawing.Color]::Red)
                return $false
            }
        }
        
        # Import module if not already loaded
        if (-not (Get-Module -Name ExchangeOnlineManagement)) {
            Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
        }
        
        # Check for existing connection by testing a command
        Update-GuiStatus "Checking Exchange Online connection..." ([System.Drawing.Color]::Orange)
        
        $isConnected = $false
        try {
            $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
            if ($testResult) {
                $isConnected = $true
                Write-Log "Exchange Online connection verified - already connected" -Level "Info"
                
                # Update global state
                if (-not $Global:ExchangeOnlineState) {
                    $Global:ExchangeOnlineState = @{
                        IsConnected       = $true
                        LastChecked       = Get-Date
                        ConnectionAttempts = 0
                    }
                }
                else {
                    $Global:ExchangeOnlineState.IsConnected = $true
                    $Global:ExchangeOnlineState.LastChecked = Get-Date
                }
                
                Update-GuiStatus "Exchange Online connection verified" ([System.Drawing.Color]::Green)
                return $true
            }
        }
        catch {
            Write-Log "No existing Exchange Online connection found" -Level "Info"
            $isConnected = $false
        }
        
        # If not connected, attempt to connect
        if (-not $isConnected) {
            Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Orange)
            Write-Log "Attempting to connect to Exchange Online..." -Level "Info"
            
            try {
                # Connect using modern auth (inherits credentials from Graph when possible)
                Connect-ExchangeOnline -ShowProgress $false -ShowBanner:$false -ErrorAction Stop
                
                # Verify connection worked
                $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
                if ($testResult) {
                    Write-Log "Exchange Online connection established successfully" -Level "Info"
                    Update-GuiStatus "Connected to Exchange Online successfully" ([System.Drawing.Color]::Green)
                    
                    # Initialize/update global state
                    $Global:ExchangeOnlineState = @{
                        IsConnected       = $true
                        LastChecked       = Get-Date
                        ConnectionAttempts = 0
                    }
                    
                    return $true
                }
                else {
                    throw "Connection succeeded but verification failed"
                }
            }
            catch {
                Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Exchange Online connection failed" ([System.Drawing.Color]::Red)
                
                # Update global state
                if (-not $Global:ExchangeOnlineState) {
                    $Global:ExchangeOnlineState = @{
                        IsConnected       = $false
                        LastChecked       = Get-Date
                        ConnectionAttempts = 1
                    }
                }
                else {
                    $Global:ExchangeOnlineState.IsConnected = $false
                    $Global:ExchangeOnlineState.LastChecked = Get-Date
                    $Global:ExchangeOnlineState.ConnectionAttempts++
                }
                
                return $false
            }
        }
        
        return $isConnected
        
    }
    catch {
        Write-Log "Error in Connect-ExchangeOnlineIfNeeded: $($_.Exception.Message)" -Level "Error"
        Update-GuiStatus "Exchange Online connection check failed" ([System.Drawing.Color]::Red)
        
        # Update global state on error
        if (-not $Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState = @{
                IsConnected       = $false
                LastChecked       = Get-Date
                ConnectionAttempts = 1
            }
        }
        
        return $false
    }
}

function Disconnect-ExchangeOnlineSafely {
    <#
    .SYNOPSIS
        Safely disconnects from Exchange Online.
    
    .DESCRIPTION
        Performs a clean disconnect from Exchange Online and updates
        the global connection state tracking. Shows confirmation message.
    
    .OUTPUTS
        None. Updates global state and shows message box.
    
    .EXAMPLE
        Disconnect-ExchangeOnlineSafely
    
    .NOTES
        - Safe to call even if not connected
        - Shows confirmation message to user
        - Updates connection state tracking
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        # Check for active Exchange Online sessions
        $session = Get-PSSession | Where-Object { 
            $_.ConfigurationName -eq "Microsoft.Exchange" -and 
            $_.State -eq "Opened" 
        }
        
        if ($session) {
            Update-GuiStatus "Disconnecting from Exchange Online..." ([System.Drawing.Color]::Orange)
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
            Write-Log "Disconnected from Exchange Online successfully" -Level "Info"
            Update-GuiStatus "Disconnected from Exchange Online" ([System.Drawing.Color]::Green)
            
            # Update global connection state
            if ($Global:ExchangeOnlineState) {
                $Global:ExchangeOnlineState.IsConnected = $false
                $Global:ExchangeOnlineState.LastChecked = Get-Date
                $Global:ExchangeOnlineState.ConnectionAttempts = 0
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "Disconnected from Exchange Online successfully.",
                "Disconnected",
                "OK",
                "Information"
            )
        }
        else {
            Update-GuiStatus "No active Exchange Online session found" ([System.Drawing.Color]::Orange)
            Write-Log "No active Exchange Online session found" -Level "Info"
            
            # Update global connection state anyway
            if ($Global:ExchangeOnlineState) {
                $Global:ExchangeOnlineState.IsConnected = $false
                $Global:ExchangeOnlineState.LastChecked = Get-Date
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "No active Exchange Online session found.",
                "No Session",
                "OK",
                "Information"
            )
        }
    }
    catch {
        Write-Log "Error disconnecting from Exchange Online: $($_.Exception.Message)" -Level "Warning"
        Update-GuiStatus "Error disconnecting from Exchange Online" ([System.Drawing.Color]::Red)
        
        # Force update connection state on error
        if ($Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState.IsConnected = $false
            $Global:ExchangeOnlineState.LastChecked = Get-Date
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "Error disconnecting from Exchange Online:`n$($_.Exception.Message)",
            "Disconnect Error",
            "OK",
            "Warning"
        )
    }
}

#══════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION TESTING
#══════════════════════════════════════════════════════════════

function Test-SecurityDefaults {
    <#
    .SYNOPSIS
        Checks if Microsoft 365 Security Defaults are enabled.
    
    .DESCRIPTION
        Tests whether security defaults are enabled in the tenant, which can
        block access to sign-in logs via Graph API.
        
        Security Defaults are a baseline security configuration that:
        • Requires MFA for all users
        • Blocks legacy authentication
        • May restrict access to certain API endpoints
        
        If enabled, the script may need to use Exchange Online fallback
        methods for sign-in data collection.
    
    .OUTPUTS
        Hashtable with:
        • IsEnabled   - Boolean or $null
        • PolicyId    - Policy GUID
        • DisplayName - Policy name
        • Description - Policy description
        • Error       - Error message (if check failed)
    
    .EXAMPLE
        $defaults = Test-SecurityDefaults
        if ($defaults.IsEnabled) {
            Write-Warning "Security defaults may block sign-in log access"
            # Use fallback method
        }
    
    .NOTES
        - Returns null for IsEnabled if check fails
        - Non-blocking (continues on error)
        - Updates GUI with status
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()
    
    try {
        Update-GuiStatus "Checking security defaults configuration..." ([System.Drawing.Color]::Orange)
        Write-Log "Testing security defaults status..." -Level "Info"
        
        # Query the security defaults policy
        $securityDefaultsUri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
        $securityDefaultsPolicy = Invoke-MgGraphRequest -Uri $securityDefaultsUri -Method GET -ErrorAction Stop
        
        $isEnabled = $securityDefaultsPolicy.isEnabled -eq $true
        
        if ($isEnabled) {
            Write-Log "Security defaults are ENABLED - this may block sign-in log access" -Level "Warning"
            Update-GuiStatus "Security defaults detected as ENABLED" ([System.Drawing.Color]::Orange)
        }
        else {
            Write-Log "Security defaults are disabled" -Level "Info"
            Update-GuiStatus "Security defaults are disabled" ([System.Drawing.Color]::Green)
        }
        
        return @{
            IsEnabled   = $isEnabled
            PolicyId    = $securityDefaultsPolicy.id
            DisplayName = $securityDefaultsPolicy.displayName
            Description = $securityDefaultsPolicy.description
        }
    }
    catch {
        Write-Log "Could not determine security defaults status: $($_.Exception.Message)" -Level "Warning"
        Update-GuiStatus "Could not check security defaults status" ([System.Drawing.Color]::Orange)
        
        return @{
            IsEnabled = $null
            Error     = $_.Exception.Message
        }
    }
}

function Test-AdminAuditLogging {
    <#
    .SYNOPSIS
        Tests if admin audit logging is enabled and accessible.
    
    .DESCRIPTION
        Attempts to query the admin audit logs to verify that:
        • Audit logging is enabled in the tenant
        • Current user has permission to access audit logs
        • Recent audit data exists
        
        This check helps identify configuration issues early before
        attempting full data collection.
    
    .PARAMETER ShowProgress
        Whether to show progress updates in the GUI.
        Default: $true
    
    .OUTPUTS
        Hashtable with:
        • IsEnabled     - Boolean
        • Status        - Status string
        • Message       - Detailed message
        • HasRecentData - Boolean
    
    .EXAMPLE
        $auditStatus = Test-AdminAuditLogging -ShowProgress $true
        if (-not $auditStatus.IsEnabled) {
            Write-Warning "Audit logging not available"
        }
    
    .NOTES
        - Non-blocking (returns status rather than throwing)
        - Provides actionable recommendations
        - Called automatically during connection
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [bool]$ShowProgress = $true
    )
    
    try {
        if ($ShowProgress) {
            Update-GuiStatus "Checking admin audit log configuration..." ([System.Drawing.Color]::Orange)
        }
        
        Write-Log "Testing admin audit log availability..." -Level "Info"
        
        # Try to get a single audit log entry
        $testUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1"
        $testResponse = Invoke-MgGraphRequest -Uri $testUri -Method GET -ErrorAction Stop
        
        if ($testResponse) {
            if ($testResponse.value -and $testResponse.value.Count -gt 0) {
                Write-Log "Admin audit logging is enabled and working" -Level "Info"
                return @{
                    IsEnabled     = $true
                    Status        = "Enabled"
                    Message       = "Admin audit logging is enabled and working properly"
                    HasRecentData = $true
                }
            }
            else {
                Write-Log "Admin audit logging API accessible but no recent data found" -Level "Warning"
                return @{
                    IsEnabled     = $true
                    Status        = "Enabled-NoData"
                    Message       = "Admin audit logging is enabled but no recent audit events found"
                    HasRecentData = $false
                }
            }
        }
        else {
            Write-Log "Unable to determine audit log status - no response" -Level "Warning"
            return @{
                IsEnabled     = $false
                Status        = "Unknown"
                Message       = "Unable to determine admin audit log status"
                HasRecentData = $false
            }
        }
    }
    catch {
        Write-Log "Error testing admin audit logs: $($_.Exception.Message)" -Level "Warning"
        
        # Analyze error to determine likely cause
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -like "*Forbidden*" -or $errorMessage -like "*Unauthorized*") {
            return @{
                IsEnabled     = $false
                Status        = "PermissionDenied"
                Message       = "Insufficient permissions to access admin audit logs"
                HasRecentData = $false
            }
        }
        elseif ($errorMessage -like "*not found*" -or $errorMessage -like "*AuditLog*disabled*") {
            return @{
                IsEnabled     = $false
                Status        = "Disabled"
                Message       = "Admin audit logging appears to be disabled or not configured"
                HasRecentData = $false
            }
        }
        elseif ($errorMessage -like "*BadRequest*") {
            return @{
                IsEnabled     = $false
                Status        = "ConfigurationIssue"
                Message       = "Admin audit log configuration issue detected"
                HasRecentData = $false
            }
        }
        else {
            return @{
                IsEnabled     = $false
                Status        = "Error"
                Message       = "Error accessing admin audit logs: $errorMessage"
                HasRecentData = $false
            }
        }
    }
}

function Show-AuditLogStatusWarning {
    <#
    .SYNOPSIS
        Displays admin audit log status information to user.
    
    .DESCRIPTION
        Shows a message box with current admin audit logging status
        and provides recommendations for fixing any issues found.
        
        The message content varies based on the audit status and
        includes actionable guidance when problems are detected.
    
    .PARAMETER AuditStatus
        Hashtable from Test-AdminAuditLogging containing status info.
    
    .EXAMPLE
        $status = Test-AdminAuditLogging
        Show-AuditLogStatusWarning -AuditStatus $status
    
    .NOTES
        - Always shows message box (informational)
        - Provides context-specific guidance
        - Non-blocking
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$AuditStatus
    )
    
    $title = "Admin Audit Log Status Check"
    $icon = "Information"
    
    switch ($AuditStatus.Status) {
        "Enabled" {
            $message = "✅ Admin Audit Logging: ENABLED`n`n" +
                      "Status: Working properly with recent data`n" +
                      "Impact: All admin audit data collection will work normally"
            $icon = "Information"
        }
        
        "Enabled-NoData" {
            $message = "⚠️ Admin Audit Logging: ENABLED (No Recent Data)`n`n" +
                      "Status: Audit logging is enabled but no recent admin activities found`n" +
                      "Impact: This is normal if there haven't been recent admin changes`n" +
                      "Note: Data collection will work when admin activities occur"
            $icon = "Warning"
        }
        
        "Disabled" {
            $message = "❌ Admin Audit Logging: DISABLED`n`n" +
                      "Status: Admin audit logging is not enabled in this tenant`n" +
                      "Impact: Admin audit data collection will NOT work`n`n" +
                      "Resolution: Enable audit logging in Microsoft 365 Admin Center:`n" +
                      "1. Go to Microsoft 365 Admin Center`n" +
                      "2. Navigate to Security & Compliance > Audit`n" +
                      "3. Enable 'Record user and admin activities'"
            $icon = "Error"
        }
        
        "PermissionDenied" {
            $message = "🔒 Admin Audit Logging: PERMISSION DENIED`n`n" +
                      "Status: Your account lacks permission to read audit logs`n" +
                      "Impact: Admin audit data collection will NOT work`n`n" +
                      "Resolution: You need one of these roles:`n" +
                      "• Global Administrator`n" +
                      "• Security Administrator`n" +
                      "• Security Reader`n" +
                      "• Reports Reader"
            $icon = "Error"
        }
        
        "ConfigurationIssue" {
            $message = "⚙️ Admin Audit Logging: CONFIGURATION ISSUE`n`n" +
                      "Status: There may be a configuration problem with audit logging`n" +
                      "Impact: Admin audit data collection may not work properly`n`n" +
                      "Resolution: Check audit log configuration in Admin Center"
            $icon = "Warning"
        }
        
        default {
            $message = "❓ Admin Audit Logging: UNKNOWN STATUS`n`n" +
                      "Status: Unable to determine audit log status`n" +
                      "Details: $($AuditStatus.Message)`n`n" +
                      "Impact: Admin audit data collection may not work properly`n" +
                      "Recommendation: Try the data collection and check results"
            $icon = "Warning"
        }
    }
    
    $message += "`n`n" +
               "This check helps ensure your security analysis will be complete.`n" +
               "Other data collection functions (sign-ins, mailbox rules, etc.) are not affected."
    
    [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", $icon)
}

#endregion

#region DATA COLLECTION FUNCTIONS

#══════════════════════════════════════════════════════════════
# SIGN-IN DATA COLLECTION
#══════════════════════════════════════════════════════════════

function Get-SignInStatusDescription {
    <#
    .SYNOPSIS
        Converts Azure AD sign-in error codes to human-readable descriptions
    #>
    param (
        [Parameter(Mandatory = $false)]
        [string]$StatusCode
    )
    
    # Status code lookup table
    $statusCodes = @{
        "0"      = "Success"
        "50053"  = "Account locked - IdsLocked"
        "50055"  = "Password expired - InvalidPasswordExpiredPassword"
        "50056"  = "Invalid or null password"
        "50057"  = "User account disabled"
        "50058"  = "User information required"
        "50074"  = "MFA required but not completed"
        "50076"  = "MFA challenge required (not yet completed)"
        "50079"  = "User needs to enroll for MFA"
        "50125"  = "Sign-in interrupted by password reset or registration"
        "50126"  = "Invalid username or password"
        "50132"  = "Session revoked - credentials have been revoked"
        "50133"  = "Session expired - password expired"
        "50140"  = "Interrupt - sign-in kept alive"
        "50144"  = "Active Directory password expired"
        "50158"  = "External security challenge not satisfied"
        "51004"  = "User account doesn't exist in directory"
        "53003"  = "Blocked by Conditional Access policy"
        "53004"  = "Proof-up required - user needs to complete registration"
        "54000"  = "Missing required claim"
        "65001"  = "Consent required - user or admin consent needed"
        "65004"  = "User declined to consent"
        "70008"  = "Authorization code expired or already used"
        "80012"  = "OnPremises password validation - account sign-in hours"
        "81010"  = "Deserialization error"
        "90010"  = "Grant type not supported"
        "90014"  = "Required field missing from credential"
        "90072"  = "Pass-through auth - account validation failed"
        "90095"  = "Admin consent required"
        "500011" = "Resource principal not found in tenant"
        "500121" = "Authentication failed during strong auth request"
        "500133" = "Assertion is not within valid time range"
        "530032" = "Blocked by Conditional Access - tenant security policy"
        "700016" = "Application not found in directory"
        "700082" = "Refresh token has expired"
        "7000218" = "Request body too large"
    }
    
    if ([string]::IsNullOrEmpty($StatusCode)) {
        return "Success"
    }
    
    if ($statusCodes.ContainsKey($StatusCode)) {
        return $statusCodes[$StatusCode]
    }
    else {
        return "Error Code: $StatusCode (Unknown)"
    }
}

function Get-TenantSignInData {
    <#
    .SYNOPSIS
        Collects sign-in logs from Microsoft Graph with geolocation analysis.
    
    .DESCRIPTION
        Primary function for collecting user sign-in data from Microsoft 365.
        This function:
        
        COLLECTION PROCESS:
        • Queries Microsoft Graph sign-in logs (premium first, then Exchange Online fallback)
        • Retrieves user authentication activity
        • Handles pagination for large datasets
        • Supports both IPv4 and IPv6 addresses
        
        GEOLOCATION ENRICHMENT:
        • Identifies unique IP addresses (IPv4 and IPv6) from sign-ins
        • Performs geolocation lookup with caching
        • Determines unusual locations based on configured countries
        • Adds ISP and geographic information to records
        
        IPv6 SUPPORT:
        • Detects and handles IPv6 addresses
        • Identifies IPv6 private/special ranges
        • Performs geolocation on public IPv6 addresses
        
        OUTPUT FILES:
        • UserLocationData.csv - All sign-in records with geolocation
        • UserLocationData_Unusual.csv - Sign-ins from unexpected countries
        • UserLocationData_Failed.csv - Failed authentication attempts
        • UniqueSignInLocations.csv - Unique IP/location combinations per user
    
    .PARAMETER DaysBack
        Number of days to look back for sign-in data.
        Valid range: 1-365 days
        Default: Value from $ConfigData.DateRange
    
    .PARAMETER OutputPath
        Full path where the CSV output file will be saved.
        Default: WorkDir\UserLocationData.csv
    
    .PARAMETER UseCache
        Whether to use caching for geolocation lookups.
        Default: $true
    
    .OUTPUTS
        Array of PSCustomObject containing sign-in records with geolocation
    
    .EXAMPLE
        Get-TenantSignInData -DaysBack 30
    
    .NOTES
        - Requires AuditLog.Read.All permission
        - Supports both IPv4 and IPv6 addresses
        - Geolocation requires internet connectivity
        - Uses fallback methods: Premium Graph -> Exchange Online (max 10 days)
        - Non-premium tenants automatically use Exchange Online fallback
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"),
        
        [Parameter(Mandatory = $false)]
        [bool]$UseCache = $true
    )
    
    #═══════════════════════════════════════════════════════════════════════════
    # IMPORT REQUIRED MODULE
    #═══════════════════════════════════════════════════════════════════════════
    
    try {
        Import-Module Microsoft.Graph.Beta.Reports -Force -ErrorAction Stop
        Write-Log "Microsoft.Graph.Reports module imported successfully" -Level "Info"
    }
    catch {
        Update-GuiStatus "Failed to import Microsoft.Graph.Reports module: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Failed to import Microsoft.Graph.Reports: $($_.Exception.Message)" -Level "Error"
        throw "Microsoft.Graph.Reports module is required but could not be loaded. Please install it with: Install-Module Microsoft.Graph.Reports"
    }
    
    Update-GuiStatus "Starting sign-in data collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
    Write-Log "SIGN-IN DATA COLLECTION STARTED" -Level "Info"
    Write-Log "Date Range: $DaysBack days" -Level "Info"
    Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Calculate date range
        $startDate = (Get-Date).AddDays(-$DaysBack)
        $filterDate = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Initialize IP cache for geolocation
        $ipCache = @{}
        
        #═══════════════════════════════════════════════════════════════════════
        # QUERY SIGN-IN LOGS WITH STREAMLINED FALLBACK
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Querying Microsoft Graph for sign-in logs..." ([System.Drawing.Color]::Orange)
        Write-Log "Attempting sign-in data collection with fallback support" -Level "Info"
        
        $signInLogs = @()
        $isPremiumTenant = $true
        
        # ATTEMPT 1: Premium Microsoft Graph API
        try {
            Update-GuiStatus "Attempting premium Microsoft Graph API..." ([System.Drawing.Color]::Orange)
            $filter = "createdDateTime ge $filterDate"
            Write-Log "Trying premium Graph API with filter: $filter" -Level "Info"
            
            $signInLogs = Get-MgBetaAuditLogSignIn -Filter $filter -All -ErrorAction Stop
            Write-Log "Premium Graph API successful: $($signInLogs.Count) total records" -Level "Info"
            Update-GuiStatus "Premium Graph API successful - $($signInLogs.Count) records retrieved" ([System.Drawing.Color]::Green)
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Log "Premium Graph API failed: [$($_.Exception.GetType().Name)] : $errorMessage" -Level "Warning"
            
            # Check if the error indicates lack of premium license or B2C tenant
            if ($errorMessage -match "Authentication_RequestFromNonPremiumTenantOrB2CTenant" -or 
                $errorMessage -match "premium license" -or 
                $errorMessage -match "B2C tenant" -or
                ($errorMessage -match "403" -and $errorMessage -match "Forbidden")) {
                
                $isPremiumTenant = $false

                Write-Log "Premium license not available, using Exchange Online fallback..." -Level "Warning"
                Update-GuiStatus "Premium license required - using Exchange Online fallback (max 10 days)" ([System.Drawing.Color]::Orange)
                
                # ATTEMPT 2: Exchange Online Fallback (max 10 days)
                # NOTE: There is no non-premium Graph API method for sign-in logs
                #       Graph API ALWAYS requires Azure AD Premium P1 or P2 license
                try {
                    $fallbackDaysBack = if ($DaysBack -gt 10) { 10 } else { $DaysBack }
                    Write-Log "Using Exchange Online fallback with $fallbackDaysBack days (limited from requested $DaysBack days)" -Level "Info"
                    
                    # FIX #1: Removed -UseCache parameter (not supported by Get-SignInDataFromExchangeOnline)
                    $exchangeData = Get-SignInDataFromExchangeOnline -DaysBack $fallbackDaysBack
                    
                    if ($exchangeData -and $exchangeData.Count -gt 0) {
                        Write-Log "Exchange Online fallback successful: $($exchangeData.Count) records" -Level "Info"
                        Update-GuiStatus "Exchange Online fallback successful - $($exchangeData.Count) records retrieved" ([System.Drawing.Color]::Yellow)
                        $signInLogs = $exchangeData
                    } else {
                        Write-Log "Exchange Online fallback returned no data" -Level "Warning"
                        throw "Exchange Online fallback returned no data"
                    }
                }
                catch {
                    $exchangeError = $_.Exception.Message
                    Write-Log "Exchange Online fallback failed: $exchangeError" -Level "Error"
                    Update-GuiStatus "All fallback methods failed" ([System.Drawing.Color]::Red)
                    throw "All data collection methods failed: Premium Graph and Exchange Online."
                }
            }
            else {
                # Handle other errors (not license-related)
                if ($errorMessage -match "Forbidden") {
                    Write-Log "Permission error - verify permissions" -Level "Error"
                    Update-GuiStatus "Permission denied" ([System.Drawing.Color]::Red)
                }
                Write-Log "Error collecting sign-in data: [$($_.Exception.GetType().Name)] : $errorMessage" -Level "Error"
                throw
            }
        }
        
        if ($signInLogs.Count -eq 0) {
            Update-GuiStatus "No sign-in data found for the specified date range" ([System.Drawing.Color]::Yellow)
            Write-Log "No sign-in data found" -Level "Warning"
            return @()
        }
        
        Update-GuiStatus "Retrieved $($signInLogs.Count) sign-in records" ([System.Drawing.Color]::Orange)
        
        #═══════════════════════════════════════════════════════════════════════
        # EXTRACT AND DEDUPLICATE IP ADDRESSES
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Extracting unique IP addresses..." ([System.Drawing.Color]::Orange)
        
        $uniqueIPs = $signInLogs | 
            Where-Object { -not [string]::IsNullOrEmpty($_.IpAddress) } | 
            Select-Object -ExpandProperty IpAddress -Unique
        
        Write-Log "Found $($uniqueIPs.Count) unique IP addresses (IPv4 and IPv6)" -Level "Info"
        
        #═══════════════════════════════════════════════════════════════════════
        # PERFORM GEOLOCATION LOOKUPS WITH IPv6 SUPPORT
        #═══════════════════════════════════════════════════════════════════════
        
        if ($uniqueIPs.Count -gt 0) {
            Update-GuiStatus "Starting geolocation lookups for $($uniqueIPs.Count) IPs (IPv4/IPv6)..." ([System.Drawing.Color]::Orange)
            Write-Log "Beginning geolocation phase for IP addresses" -Level "Info"
            
            $geolocatedCount = 0
            
            foreach ($ip in $uniqueIPs) {
                $geolocatedCount++
                
                if ($geolocatedCount % 10 -eq 0) {
                    $percentage = [math]::Round(($geolocatedCount / $uniqueIPs.Count) * 100, 1)
                    Update-GuiStatus "Geolocating: $geolocatedCount/$($uniqueIPs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                    [System.Windows.Forms.Application]::DoEvents()
                }
                
                try {
                    $geoResult = Invoke-IPGeolocation -IPAddress $ip -Cache $ipCache
                    if ($geoResult) {
                        $ipType = if ($geoResult.ip_version) { $geoResult.ip_version } else { "Unknown" }
                        Write-Log "Geolocated $ip ($ipType): $($geoResult.city), $($geoResult.region_name), $($geoResult.country_name)" -Level "Info"
                    }
                }
                catch {
                    Write-Log "Error geolocating IP ${ip}: $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            Write-Log "Geolocation completed for $($ipCache.Count) IP addresses" -Level "Info"
        }
        
        #═══════════════════════════════════════════════════════════════════════
        # PROCESS SIGN-IN RECORDS WITH GEOLOCATION
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Processing sign-in records with geolocation data..." ([System.Drawing.Color]::Orange)
        Write-Log "Processing all sign-in records with geolocation enrichment" -Level "Info"
        
        $results = @()
        $processedCount = 0
        
        foreach ($signIn in $signInLogs) {
            $processedCount++
            
            # Progress update every 500 records
            if ($processedCount % 500 -eq 0) {
                $percentage = [Math]::Round(($processedCount / $signInLogs.Count) * 100, 1)
                Update-GuiStatus "Processing sign-ins: $processedCount of $($signInLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Extract basic sign-in info
            $userId = $signIn.UserPrincipalName
            $userDisplayName = $signIn.UserDisplayName
            $creationTime = $signIn.CreatedDateTime
            $userAgent = $signIn.UserAgent
            $ip = $signIn.IpAddress
            
            # Initialize location defaults
            $isUnusual = $false
            $city = "Unknown"
            $region = "Unknown"
            $country = "Unknown"
            $isp = "Unknown"
            $ipVersion = "Unknown"
            $isPrivateIP = $false
            
            # Apply geolocation data if available
            if (-not [string]::IsNullOrEmpty($ip)) {
                #═══════════════════════════════════════════════════════════════
                # VALIDATE IP ADDRESS (IPv4 or IPv6)
                #═══════════════════════════════════════════════════════════════
                
                try {
                    $ipObj = [System.Net.IPAddress]::Parse($ip)
                    
                    if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                        # IPv4 Address
                        $ipVersion = "IPv4"
                        
                        # Check IPv4 private ranges
                        if ($ip -match "^10\." -or 
                            $ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or 
                            $ip -match "^192\.168\." -or 
                            $ip -match "^127\." -or 
                            $ip -match "^169\.254\.") {
                            
                            $isPrivateIP = $true
                            $country = "Private Network"
                            $city = "Private"
                            $region = "Private"
                            $isp = "Private Network"
                        }
                    }
                    elseif ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                        # IPv6 Address
                        $ipVersion = "IPv6"
                        
                        # Check IPv6 private/special ranges
                        if ($ip -match "^::1$" -or                      # Loopback
                            $ip -match "^fe80:" -or                      # Link-local
                            $ip -match "^fc00:" -or $ip -match "^fd00:" -or  # Unique local
                            $ip -match "^ff00:") {                       # Multicast
                            
                            $isPrivateIP = $true
                            $country = "Private Network"
                            $city = "Private"
                            $region = "Private"
                            $isp = "Private Network (IPv6)"
                        }
                    }
                }
                catch {
                    Write-Log "Invalid IP address format: $ip" -Level "Warning"
                }
                
                # Get geolocation data from cache if not private
                if (-not $isPrivateIP -and $ipCache.ContainsKey($ip)) {
                    $geoData = $ipCache[$ip].Data
                    $city = if ($geoData.city) { $geoData.city } else { "Unknown" }
                    $region = if ($geoData.region_name) { $geoData.region_name } else { "Unknown" }
                    $country = if ($geoData.country_name) { $geoData.country_name } else { "Unknown" }
                    $isp = if ($geoData.connection -and $geoData.connection.isp) { $geoData.connection.isp } else { "Unknown" }
                    
                    # Check if location is unusual
                    if ($country -ne "Unknown" -and $ConfigData.ExpectedCountries -notcontains $country) {
                        $isUnusual = $true
                    }
                }
            }
            
			# Check if ISP is in high-risk list
			$isHighRiskISP = $false
			if (-not [string]::IsNullOrEmpty($isp) -and $isp -ne "Unknown" -and $isp -ne "Private Network") {
				foreach ($highRiskProvider in $script:HighRiskISPs) {
					if ($isp -like "*$highRiskProvider*") {
						$isHighRiskISP = $true
						Write-Log "High-risk ISP detected: $isp for user $userDisplayName" -Level "Warning"
						break
					}
				}
			}
			
            # Get sign-in status
            $statusCode = if ($signIn.Status -and $signIn.Status.ErrorCode) { 
                $signIn.Status.ErrorCode.ToString() 
            } else { 
                "0" 
            }
            
            $statusDescription = Get-SignInStatusDescription -StatusCode $statusCode
            
            # Create result object
            $resultObject = [PSCustomObject]@{
                CreationTime = $creationTime
                UserId = $userId
                UserDisplayName = $userDisplayName
                IP = $ip
                IPVersion = $ipVersion
                IsPrivateIP = $isPrivateIP
                City = $city
                RegionName = $region
                Country = $country
                ISP = $isp
				IsHighRiskISP = $isHighRiskISP
                IsUnusualLocation = $isUnusual
                StatusCode = $statusCode
                Status = $statusDescription
                UserAgent = $userAgent
                ConditionalAccessStatus = $signIn.ConditionalAccessStatus
                RiskLevel = $signIn.RiskLevelDuringSignIn
                DeviceOS = if ($signIn.DeviceDetail) { $signIn.DeviceDetail.OperatingSystem } else { "" }
                DeviceBrowser = if ($signIn.DeviceDetail) { $signIn.DeviceDetail.Browser } else { "" }
                IsInteractive = $signIn.IsInteractive
                AppDisplayName = $signIn.AppDisplayName
            }
            
            $results += $resultObject
        }
        
        Write-Log "Processed $($results.Count) sign-in records with geolocation" -Level "Info"
        
        #═══════════════════════════════════════════════════════════════════════
        # EXPORT RESULTS
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Exporting sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Export main results
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Log "Exported all sign-in data to: $OutputPath" -Level "Info"
        
        # Export unusual locations
        $unusualSignIns = $results | Where-Object { $_.IsUnusualLocation -eq $true }
        if ($unusualSignIns.Count -gt 0) {
            $unusualOutputPath = $OutputPath -replace '.csv$', '_Unusual.csv'
            $unusualSignIns | Export-Csv -Path $unusualOutputPath -NoTypeInformation -Force
            Write-Log "Exported $($unusualSignIns.Count) unusual location sign-ins to: $unusualOutputPath" -Level "Info"
        }
        
        # Export failed sign-ins
        $failedSignIns = $results | Where-Object { $_.StatusCode -ne "0" -and ![string]::IsNullOrEmpty($_.StatusCode) }
        if ($failedSignIns.Count -gt 0) {
            $failedOutputPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedSignIns | Export-Csv -Path $failedOutputPath -NoTypeInformation -Force
            Write-Log "Exported $($failedSignIns.Count) failed sign-ins to: $failedOutputPath" -Level "Info"
        }
        
        # Generate unique locations report
        Update-GuiStatus "Generating unique locations report..." ([System.Drawing.Color]::Orange)
        
        $uniqueLogins = @()
        $userLocationGroups = $results | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            $uniqueUserLocations = $userSignIns | 
                Select-Object UserId, UserDisplayName, IP, IPVersion, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) }
            
            foreach ($location in $uniqueUserLocations) {
                $signInCount = ($userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and 
                    $_.City -eq $location.City -and 
                    $_.Country -eq $location.Country 
                }).Count
                
                $locationSignIns = $userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and 
                    $_.City -eq $location.City -and 
                    $_.Country -eq $location.Country 
                } | Sort-Object CreationTime
                
                $firstSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[0].CreationTime } else { "" }
                $lastSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[-1].CreationTime } else { "" }
                
                $isUnusualLocation = $false
                if ($location.Country -and $ConfigData.ExpectedCountries -notcontains $location.Country) {
                    $isUnusualLocation = $true
                }
                
                $uniqueLogin = [PSCustomObject]@{
                    UserId = $location.UserId
                    UserDisplayName = $location.UserDisplayName
                    IP = $location.IP
                    IPVersion = $location.IPVersion
                    City = $location.City
                    RegionName = $location.RegionName
                    Country = $location.Country
                    ISP = $location.ISP
                    IsUnusualLocation = $isUnusualLocation
                    SignInCount = $signInCount
                    FirstSeen = $firstSeen
                    LastSeen = $lastSeen
                }
                
                $uniqueLogins += $uniqueLogin
            }
        }
        
        # Export unique logins
        if ($uniqueLogins.Count -gt 0) {
            $uniqueLoginsPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"
            $uniqueLogins | Export-Csv -Path $uniqueLoginsPath -NoTypeInformation -Force
            Write-Log "Exported $($uniqueLogins.Count) unique location records to: $uniqueLoginsPath" -Level "Info"
            
            $unusualUniqueLogins = $uniqueLogins | Where-Object { $_.IsUnusualLocation -eq $true }
            if ($unusualUniqueLogins.Count -gt 0) {
                $unusualPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv"
                $unusualUniqueLogins | Export-Csv -Path $unusualPath -NoTypeInformation -Force
                Write-Log "Exported $($unusualUniqueLogins.Count) unusual unique locations to: $unusualPath" -Level "Info"
            }
        }
        
        #═══════════════════════════════════════════════════════════════════════
        # SUMMARY STATISTICS
        #═══════════════════════════════════════════════════════════════════════
        
        $ipv4Count = ($results | Where-Object { $_.IPVersion -eq "IPv4" }).Count
        $ipv6Count = ($results | Where-Object { $_.IPVersion -eq "IPv6" }).Count
        $privateIPCount = ($results | Where-Object { $_.Country -eq "Private Network" }).Count
        
        Update-GuiStatus "Sign-in collection complete: $($results.Count) records ($($unusualSignIns.Count) unusual, $($failedSignIns.Count) failed)" ([System.Drawing.Color]::Green)
        
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "SIGN-IN DATA COLLECTION COMPLETED" -Level "Info"
        Write-Log "Data Source: $(if ($isPremiumTenant) { "Premium Graph API" } else { "Exchange Online Fallback" })" -Level "Info"
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "Total Sign-ins: $($results.Count)" -Level "Info"
        Write-Log "  IPv4 Addresses: $ipv4Count" -Level "Info"
        Write-Log "  IPv6 Addresses: $ipv6Count" -Level "Info"
        Write-Log "  Private IPs: $privateIPCount" -Level "Info"
        Write-Log "Unusual Locations: $($unusualSignIns.Count)" -Level "Info"
        Write-Log "Failed Sign-ins: $($failedSignIns.Count)" -Level "Info"
        Write-Log "Unique IP Locations: $($uniqueLogins.Count)" -Level "Info"
        Write-Log "Geolocation Cache: $($ipCache.Count) IPs cached" -Level "Info"
        Write-Log "Output Files:" -Level "Info"
        Write-Log "  Main: $OutputPath" -Level "Info"
        if ($unusualSignIns.Count -gt 0) {
            Write-Log "  Unusual: $($OutputPath -replace '.csv$', '_Unusual.csv')" -Level "Info"
        }
        if ($failedSignIns.Count -gt 0) {
            Write-Log "  Failed: $($OutputPath -replace '.csv$', '_Failed.csv')" -Level "Info"
        }
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        
        return $results
    }
    catch {
        Update-GuiStatus "Error collecting sign-in data: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in sign-in data collection: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
        return $null
    }
}

function Get-SignInDataFromExchangeOnline {
    <#
    .SYNOPSIS
        Collects sign-in data from Exchange Online Unified Audit Log (optimized fallback method).
    
    .DESCRIPTION
        Optimized fallback function when Microsoft Graph API access is blocked.
        
        KEY OPTIMIZATIONS:
        • Uses SessionCommand ReturnLargeSet (60-80% faster)
        • Proper pagination with SessionId
        • Larger chunk sizes (24-48 hours)
        • Removes duplicate records
        • Batched GUI updates
        • No artificial delays
        
        Returns sign-in records in Graph API format for geolocation processing.
    
    .PARAMETER DaysBack
        Number of days to look back (max 10 due to EXO limits)
    
    .PARAMETER OutputPath
        Output file path (optional, not used in current implementation)
    
    .OUTPUTS
        Array of sign-in records ready for geolocation enrichment
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$DaysBack = [Math]::Min($ConfigData.DateRange, 10),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData_EXO.csv")
    )
    
    Update-GuiStatus "Collecting sign-in data via Exchange Online..." ([System.Drawing.Color]::Orange)
    Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
    Write-Log "EXCHANGE ONLINE FALLBACK METHOD STARTED (OPTIMIZED)" -Level "Info"
    Write-Log "Maximum date range: 10 days (Exchange Online limitation)" -Level "Info"
    Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Ensure Exchange Online connection
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            throw "Exchange Online connection failed"
        }
        
        # Calculate date range
        $startDate = (Get-Date).AddDays(-$DaysBack)
        $endDate = Get-Date
        $totalDays = [Math]::Ceiling(($endDate - $startDate).TotalDays)
        
        Write-Log "Date range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd')) ($totalDays days)" -Level "Info"
        
        # Use larger chunks for better performance
        $chunkSizeHours = if ($DaysBack -le 3) { 24 } else { 48 }
        $expectedChunks = [Math]::Ceiling(($endDate - $startDate).TotalHours / $chunkSizeHours)
        
        Write-Log "Using $chunkSizeHours hour chunks, expecting $expectedChunks total chunks" -Level "Info"
        Write-Log "Using SessionCommand ReturnLargeSet for optimal performance" -Level "Info"
        
        # Initialize tracking
        $auditLogs = @()
        $currentStart = $startDate
        $chunkNumber = 0
        $totalRecords = 0
        
        # Process chunks with optimized pagination
        while ($currentStart -lt $endDate) {
            $chunkNumber++
            $currentEnd = if ($currentStart.AddHours($chunkSizeHours) -lt $endDate) { 
                $currentStart.AddHours($chunkSizeHours) 
            } else { 
                $endDate 
            }
            
            if ($currentStart -ge $currentEnd) { break }
            
            $chunkHours = [Math]::Round(($currentEnd - $currentStart).TotalHours, 1)
            $progressPercent = [Math]::Round(($chunkNumber / $expectedChunks) * 100, 1)
            
            Update-GuiStatus "Chunk $chunkNumber/$expectedChunks ($progressPercent%): Querying $chunkHours hours..." ([System.Drawing.Color]::Orange)
            Write-Log "Processing chunk $chunkNumber/$expectedChunks : $($currentStart.ToString('yyyy-MM-dd HH:mm')) to $($currentEnd.ToString('yyyy-MM-dd HH:mm'))" -Level "Info"
            
            try {
                $sessionId = [Guid]::NewGuid().ToString() + "_SignIn_" + $chunkNumber
                $chunkLogs = @()
                $pageCount = 0
                
                # Paginate through all results
                do {
                    $pageCount++
                    $pageResults = Search-UnifiedAuditLog `
                        -StartDate $currentStart `
                        -EndDate $currentEnd `
                        -Operations "UserLoggedIn","UserLoginFailed","UserLoggedOut" `
                        -ResultSize 5000 `
                        -SessionId $sessionId `
                        -SessionCommand ReturnLargeSet `
                        -ErrorAction Stop
                    
                    if ($pageResults -and $pageResults.Count -gt 0) {
                        $chunkLogs += $pageResults
                        Write-Log "  Page $pageCount : Retrieved $($pageResults.Count) records" -Level "Info"
                    }
                } while ($pageResults -and $pageResults.Count -ge 5000)
                
                # Fallback to broader search if no specific operations found
                if ($chunkLogs.Count -eq 0) {
                    Write-Log "No specific operations found, trying broader search..." -Level "Info"
                    $sessionId = [Guid]::NewGuid().ToString() + "_Broad_" + $chunkNumber
                    $pageCount = 0
                    
                    do {
                        $pageCount++
                        $pageResults = Search-UnifiedAuditLog `
                            -StartDate $currentStart `
                            -EndDate $currentEnd `
                            -RecordType "AzureActiveDirectory" `
                            -ResultSize 5000 `
                            -SessionId $sessionId `
                            -SessionCommand ReturnLargeSet `
                            -ErrorAction Stop
                        
                        if ($pageResults -and $pageResults.Count -gt 0) {
                            $chunkLogs += $pageResults
                            Write-Log "  Page $pageCount : Retrieved $($pageResults.Count) records" -Level "Info"
                        }
                    } while ($pageResults -and $pageResults.Count -ge 5000)
                }
                
                Write-Log "Chunk $chunkNumber complete: $($chunkLogs.Count) records" -Level "Info"
                
                if ($chunkLogs -and $chunkLogs.Count -gt 0) {
                    $auditLogs += $chunkLogs
                    $totalRecords += $chunkLogs.Count
                }
            }
            catch {
                Write-Log "Error in chunk ${chunkNumber}: $($_.Exception.Message)" -Level "Warning"
            }
            
            Update-GuiStatus "Progress: $chunkNumber/$expectedChunks chunks. Total: $totalRecords records" ([System.Drawing.Color]::Green)
            [System.Windows.Forms.Application]::DoEvents()
            $currentStart = $currentEnd
        }
        
        Write-Log "Completed all $chunkNumber chunks: $totalRecords total audit log entries" -Level "Info"
        
        # Remove duplicates (ReturnLargeSet returns unsorted data with dupes)
        if ($auditLogs.Count -gt 0) {
            Write-Log "Removing duplicate records..." -Level "Info"
            $originalCount = $auditLogs.Count
            $auditLogs = $auditLogs | Sort-Object Identity -Unique
            $duplicatesRemoved = $originalCount - $auditLogs.Count
            
            if ($duplicatesRemoved -gt 0) {
                Write-Log "Removed $duplicatesRemoved duplicates ($([Math]::Round($duplicatesRemoved/$originalCount*100,1))%)" -Level "Info"
            }
            Write-Log "Final unique record count: $($auditLogs.Count)" -Level "Info"
        }
        
        # Process audit logs into sign-in records
        if ($auditLogs.Count -eq 0) {
            Write-Log "No audit logs found to process" -Level "Warning"
            return @()
        }
        
        Write-Log "Converting $($auditLogs.Count) audit logs to sign-in records..." -Level "Info"
        
        $signInResults = @()
        $processedCount = 0
        $parseErrors = 0
        
        foreach ($log in $auditLogs) {
            $processedCount++
            
            if ($processedCount % 1000 -eq 0) {
                $percentage = [Math]::Round(($processedCount / $auditLogs.Count) * 100, 1)
                Update-GuiStatus "Processing: $processedCount/$($auditLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            try {
                if ([string]::IsNullOrEmpty($log.AuditData)) { continue }
                
                $auditDetails = $log.AuditData | ConvertFrom-Json -ErrorAction Stop
                # DEBUG: Dump first failed record
				if ($signInResults.Count -eq 0 -and ($auditDetails.ResultStatus -match "Failed" -or $auditDetails.Operation -eq "UserLoginFailed")) {
					$auditDetails | ConvertTo-Json -Depth 5 | Out-File "$env:TEMP\FirstFailedSignIn.json"
					Write-Host "DEBUG: Saved first failed record to $env:TEMP\FirstFailedSignIn.json" -ForegroundColor Yellow
				}
                $creationTime = if ($auditDetails.CreationTime) { 
                    $auditDetails.CreationTime 
                } elseif ($log.CreationDate) { 
                    $log.CreationDate 
                } else { 
                    Get-Date 
                }
                
                $userId = if ($auditDetails.UserId) { 
                    $auditDetails.UserId 
                } elseif ($log.UserIds) { 
                    $log.UserIds 
                } else { 
                    "Unknown" 
                }
                
                $ipAddress = if ($auditDetails.ClientIP) {
                    $auditDetails.ClientIP
                } elseif ($auditDetails.ClientIPAddress) {
                    $auditDetails.ClientIPAddress
                } elseif ($auditDetails.ActorIpAddress) {
                    $auditDetails.ActorIpAddress
                } else {
                    "Unknown"
                }
                
                $operation = if ($auditDetails.Operation) {
                    $auditDetails.Operation
                } elseif ($log.Operations) {
                    $log.Operations
                } else {
                    "Unknown"
                }
                
				# Default to success
				$statusCode = "0"
				$statusDescription = "Success"

				# Check for ErrorCode property (modern Entra ID sign-in logs - added Feb 2021)
				if ($auditDetails.ErrorCode) {
					$statusCode = $auditDetails.ErrorCode.ToString()
					$statusDescription = Get-SignInStatusDescription -StatusCode $statusCode
				}
				# Check for LogonError property (legacy field that indicates failure)
				elseif ($auditDetails.LogonError) {
					# LogonError present means it's a failed sign-in
					# Try to extract error code from LogonError text
					if ($auditDetails.LogonError -match '(\d{5,6})') {
						$statusCode = $matches[1]
					} else {
						# Try to extract from other common patterns
						if ($auditDetails.LogonError -match 'error\s*[:\s]*(\d{5,6})') {
							$statusCode = $matches[1]
						} elseif ($auditDetails.LogonError -match 'code\s*[:\s]*(\d{5,6})') {
							$statusCode = $matches[1]
						} else {
							# Look for specific error descriptions to map to codes
							switch -Wildcard ($auditDetails.LogonError) {
								"*password*expired*" { $statusCode = "50133" }
								"*account*disabled*" { $statusCode = "50057" }
								"*account*locked*" { $statusCode = "50053" }
								"*password*reset*" { $statusCode = "50125" }
								"*mfa*required*" { $statusCode = "50074" }
								"*consent*required*" { $statusCode = "65001" }
								default { $statusCode = "50126" }  # Only default if nothing else matches
							}
						}
					}
					$statusDescription = "Failed - " + $auditDetails.LogonError
				}
				# Check Operation type - UserLoginFailed explicitly indicates failure
				elseif ($operation -eq "UserLoginFailed") {
					# Check ExtendedProperties for error code
					if ($auditDetails.ExtendedProperties) {
						$errorCodeProp = $auditDetails.ExtendedProperties | Where-Object { 
							$_.Name -eq "ResultStatusDetail" -or $_.Name -eq "errorCode" -or $_.Name -eq "ErrorCode"
						}
						if ($errorCodeProp -and $errorCodeProp.Value -match '(\d{5,6})') {
							$statusCode = $matches[1]
						} else {
							# Check for error description in other properties
							$errorDescProp = $auditDetails.ExtendedProperties | Where-Object { 
								$_.Name -eq "ResultDescription" -or $_.Name -eq "ErrorDescription"
							}
							if ($errorDescProp) {
								switch -Wildcard ($errorDescProp.Value) {
									"*password*expired*" { $statusCode = "50133" }
									"*account*disabled*" { $statusCode = "50057" }
									"*account*locked*" { $statusCode = "50053" }
									"*password*reset*" { $statusCode = "50125" }
									"*mfa*required*" { $statusCode = "50074" }
									"*consent*required*" { $statusCode = "65001" }
									default { $statusCode = "50126" }
								}
							} else {
								$statusCode = "50126"
							}
						}
					} else {
						$statusCode = "50126"
					}
					$statusDescription = Get-SignInStatusDescription -StatusCode $statusCode
				}
				# Check ResultStatus for explicit failure indicators
				elseif ($auditDetails.ResultStatus -and 
						$auditDetails.ResultStatus -match "Failed|Failure|Error") {
					# Try to extract error code from ResultStatus
					if ($auditDetails.ResultStatus -match '(\d{5,6})') {
						$statusCode = $matches[1]
					} else {
						$statusCode = "50126"
					}
					$statusDescription = "Failed - " + $auditDetails.ResultStatus
				}
				# If Operation is UserLoggedIn but ResultStatus shows failure
				elseif ($operation -eq "UserLoggedIn" -and 
						$auditDetails.ResultStatus -eq "Failed") {
					if ($auditDetails.ResultStatus -match '(\d{5,6})') {
						$statusCode = $matches[1]
					} else {
						$statusCode = "50126"
					}
					$statusDescription = Get-SignInStatusDescription -StatusCode $statusCode
				}

                
                $userAgent = if ($auditDetails.UserAgent) {
                    $auditDetails.UserAgent
                } elseif ($auditDetails.ClientInfoString) {
                    $auditDetails.ClientInfoString
                } else {
                    "Unknown"
                }
                
                $isInteractive = $true
                if ($operation -match "NonInteractive") {
                    $isInteractive = $false
                }
                
                $appDisplayName = if ($auditDetails.ApplicationDisplayName) {
                    $auditDetails.ApplicationDisplayName
                } elseif ($auditDetails.ApplicationId) {
                    $auditDetails.ApplicationId
                } else {
                    "Unknown"
                }
                
                $signInRecord = [PSCustomObject]@{
                    CreatedDateTime = $creationTime
                    UserPrincipalName = $userId
                    UserDisplayName = $userId
                    IpAddress = $ipAddress
                    Status = @{ ErrorCode = $statusCode }
                    StatusCode = $statusCode
                    StatusDescription = $statusDescription
                    UserAgent = $userAgent
                    IsInteractive = $isInteractive
                    AppDisplayName = $appDisplayName
                    ConditionalAccessStatus = "notApplied"
                    RiskLevelDuringSignIn = "none"
                    DeviceDetail = @{
                        OperatingSystem = "Unknown"
                        Browser = "Unknown"
                    }
                }
                
                $signInResults += $signInRecord
            }
            catch {
                $parseErrors++
                if ($parseErrors -le 10) {
                    Write-Log "Parse error: $($_.Exception.Message)" -Level "Warning"
                }
                continue
            }
        }
        
        Write-Log "Processing complete: $($signInResults.Count) sign-in records created" -Level "Info"
        if ($parseErrors -gt 0) {
            Write-Log "Parse errors: $parseErrors records failed" -Level "Warning"
        }
        
        if ($signInResults.Count -eq 0) {
            Write-Log "No valid sign-in records created" -Level "Warning"
            return @()
        }
        
        Update-GuiStatus "Exchange Online complete: $($signInResults.Count) records ready for geolocation" ([System.Drawing.Color]::Green)
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "EXCHANGE ONLINE FALLBACK COMPLETED" -Level "Info"
        Write-Log "Created $($signInResults.Count) sign-in records" -Level "Info"
        Write-Log "Returning to Get-TenantSignInData for geolocation" -Level "Info"
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        
        return $signInResults
    }
    catch {
        Update-GuiStatus "Error in Exchange Online collection: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack: $($_.ScriptStackTrace)" -Level "Error"
        return $null
    }
}

function Get-PerUserMFAStatus {
    <#
    .SYNOPSIS
        Gets per-user MFA status using Microsoft Graph Beta API
    
    .DESCRIPTION
        Queries the beta endpoint to retrieve per-user MFA enforcement status
        without requiring the MSOL module.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )
    
    try {
        $uri = "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements"
        $authRequirements = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
        
        if ($authRequirements -and $authRequirements.perUserMfaState) {
            $perUserMFAState = $authRequirements.perUserMfaState
            
            return @{
                State = $perUserMFAState
                IsEnforced = ($perUserMFAState -eq "enforced")
                IsEnabled = ($perUserMFAState -eq "enabled")
                Source = "Beta API"
            }
        }
        
        return @{
            State = "disabled"
            IsEnforced = $false
            IsEnabled = $false
            Source = "Beta API"
        }
    }
    catch {
        return @{
            State = "unknown"
            IsEnforced = $false
            IsEnabled = $false
            Source = "Error"
            Error = $_.Exception.Message
        }
    }
}

function Get-MFAStatusFromSignIns {
    <#
    .SYNOPSIS
        Infers MFA usage from recent sign-in logs
    
    .DESCRIPTION
        Analyzes recent sign-in activity to determine if a user is using MFA.
        This is a fallback method when the beta API is unavailable.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30
    )
    
    try {
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startDate"
        $signIns = Get-MgBetaAuditLogSignIn -Filter $filter -Top 100 -ErrorAction SilentlyContinue
        
        if (-not $signIns -or $signIns.Count -eq 0) {
            return @{
                Status = "No Recent Sign-ins"
                MFAUsagePercent = 0
                TotalSignIns = 0
                MFASignIns = 0
                Source = "Sign-in Analysis"
            }
        }
        
        $mfaSignIns = $signIns | Where-Object { 
            $_.AuthenticationRequirement -eq "multiFactorAuthentication" -or
            ($_.AuthenticationDetails -and 
             ($_.AuthenticationDetails | Where-Object { $_.AuthenticationMethod -match "MFA|Authenticator|SMS|Phone" })) -or
            ($_.Status -and ($_.Status.ErrorCode -eq 50074 -or $_.Status.ErrorCode -eq 50076))
        }
        
        $totalSignIns = $signIns.Count
        $mfaCount = if ($mfaSignIns) { $mfaSignIns.Count } else { 0 }
        $mfaPercent = if ($totalSignIns -gt 0) { [math]::Round(($mfaCount / $totalSignIns) * 100, 1) } else { 0 }
        
        $status = if ($mfaPercent -eq 100) {
            "Always Uses MFA"
        }
        elseif ($mfaPercent -ge 80) {
            "Usually Uses MFA"
        }
        elseif ($mfaPercent -ge 50) {
            "Sometimes Uses MFA"
        }
        elseif ($mfaPercent -gt 0) {
            "Rarely Uses MFA"
        }
        else {
            "Never Uses MFA"
        }
        
        return @{
            Status = $status
            MFAUsagePercent = $mfaPercent
            TotalSignIns = $totalSignIns
            MFASignIns = $mfaCount
            Source = "Sign-in Analysis"
        }
    }
    catch {
        return @{
            Status = "Error"
            MFAUsagePercent = 0
            TotalSignIns = 0
            MFASignIns = 0
            Source = "Error"
            Error = $_.Exception.Message
        }
    }
}

function Get-MFAStatusAudit {
    <#
    .SYNOPSIS
        Performs comprehensive MFA status audit for all users
    
    .DESCRIPTION
        Audits MFA configuration across the tenant using multiple detection methods:
        
        DETECTION METHODS:
        1. Security Defaults - Tenant-wide MFA enforcement
        2. Per-User MFA (Legacy) - Using Graph Beta API + sign-in analysis
        3. Conditional Access Policies - Modern MFA enforcement
        4. MFA Registration Status - Actual enrolled methods
        
        HYBRID APPROACH FOR PER-USER MFA:
        • Attempts to use Graph Beta API first (most accurate)
        • Falls back to sign-in analysis if API unavailable
        • Combines both methods for comprehensive detection
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MFAStatus.csv")
    )
    
    Update-GuiStatus "Starting comprehensive MFA status audit..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
    Write-Log "MFA STATUS AUDIT STARTED" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
    
    try {
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 1: CHECK TENANT-WIDE SETTINGS
        # ═══════════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Checking tenant-wide MFA settings..." ([System.Drawing.Color]::Orange)
        
        # Check Security Defaults
        $securityDefaultsEnabled = $false
        try {
            $policyUri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            $securityDefaultsPolicy = Invoke-MgGraphRequest -Uri $policyUri -Method GET -ErrorAction SilentlyContinue
            
            if ($securityDefaultsPolicy.isEnabled -eq $true) {
                $securityDefaultsEnabled = $true
                Write-Log "Security Defaults: ENABLED (tenant-wide MFA enforcement)" -Level "Info"
                Update-GuiStatus "Security Defaults detected: MFA enforced tenant-wide" ([System.Drawing.Color]::Green)
            }
            else {
                Write-Log "Security Defaults: DISABLED" -Level "Info"
            }
        }
        catch {
            Write-Log "Could not check Security Defaults: $($_.Exception.Message)" -Level "Warning"
        }
        
        # Get Conditional Access Policies
        $caPolicies = @()
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
            Write-Log "Found $($caPolicies.Count) Conditional Access policies" -Level "Info"
        }
        catch {
            Write-Log "Could not retrieve Conditional Access policies: $($_.Exception.Message)" -Level "Warning"
        }
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 2: GET ALL USERS
        # ═══════════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Retrieving all users..." ([System.Drawing.Color]::Orange)
        
        $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
        Write-Log "Retrieved $($users.Count) users" -Level "Info"
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 3: PROCESS EACH USER
        # ═══════════════════════════════════════════════════════════════════════════
        
        $mfaResults = @()
        $processedCount = 0
        
        foreach ($user in $users) {
            $processedCount++
            
            # Progress update
            if ($processedCount % 10 -eq 0) {
                $percentage = [Math]::Round(($processedCount / $users.Count) * 100, 1)
                Update-GuiStatus "Processing users: $processedCount of $($users.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            Write-Log "Processing: $($user.UserPrincipalName)" -Level "Info"
            
            # Skip guests if configured
            if ($user.UserType -eq "Guest" -and $ConfigData.SkipGuests) {
                Write-Log "Skipping guest user: $($user.UserPrincipalName)" -Level "Info"
                continue
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CHECK 1: PER-USER MFA (HYBRID DETECTION)
            # ═══════════════════════════════════════════════════════════════════════════
            
            $perUserMFAState = "Unknown"
            $perUserMFAEnforced = $false
            $mfaUsagePercent = 0
            $detectionSource = "Unknown"
            $signInMFACount = 0
            $signInTotalCount = 0
            
            # Try beta endpoint first
            try {
                Write-Log "Attempting per-user MFA detection via Beta API for $($user.UserPrincipalName)" -Level "Info"
                $perUserMFA = Get-PerUserMFAStatus -UserId $user.Id
                
                if ($perUserMFA.State -ne "unknown") {
                    $perUserMFAState = $perUserMFA.State
                    $perUserMFAEnforced = $perUserMFA.IsEnforced
                    $detectionSource = $perUserMFA.Source
                    
                    Write-Log "$($user.UserPrincipalName): Per-user MFA state = $perUserMFAState (via $detectionSource)" -Level "Info"
                }
                else {
                    throw "Beta API returned unknown"
                }
            }
            catch {
                # Fallback to sign-in analysis
                Write-Log "Falling back to sign-in analysis for $($user.UserPrincipalName)" -Level "Warning"
                
                try {
                    $signInAnalysis = Get-MFAStatusFromSignIns -UserPrincipalName $user.UserPrincipalName -DaysBack 30
                    
                    if ($signInAnalysis.Status -ne "No Recent Sign-ins" -and $signInAnalysis.Status -ne "Error") {
                        $perUserMFAState = "Inferred: $($signInAnalysis.Status)"
                        $mfaUsagePercent = $signInAnalysis.MFAUsagePercent
                        $signInMFACount = $signInAnalysis.MFASignIns
                        $signInTotalCount = $signInAnalysis.TotalSignIns
                        $detectionSource = $signInAnalysis.Source
                        
                        if ($signInAnalysis.Status -eq "Always Uses MFA" -or 
                            ($signInAnalysis.Status -eq "Usually Uses MFA" -and $signInAnalysis.MFAUsagePercent -ge 90)) {
                            $perUserMFAEnforced = $true
                        }
                        
                        Write-Log "$($user.UserPrincipalName): MFA usage = $($signInAnalysis.MFAUsagePercent)% ($($signInAnalysis.MFASignIns)/$($signInAnalysis.TotalSignIns) sign-ins)" -Level "Info"
                    }
                    else {
                        $perUserMFAState = $signInAnalysis.Status
                        $detectionSource = $signInAnalysis.Source
                    }
                }
                catch {
                    Write-Log "Could not analyze sign-ins for $($user.UserPrincipalName): $($_.Exception.Message)" -Level "Warning"
                    $perUserMFAState = "Error"
                    $detectionSource = "Error"
                }
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CHECK 2: CONDITIONAL ACCESS POLICIES
            # ═══════════════════════════════════════════════════════════════════════════
            
            $caPolicyEnforced = $false
            $applicablePolicies = @()
            
            if ($caPolicies.Count -gt 0) {
                foreach ($policy in $caPolicies) {
                    if ($policy.State -ne "enabled") { continue }
                    
                    # Check if policy requires MFA
                    $requiresMFA = $false
                    if ($policy.GrantControls) {
                        $grantControls = $policy.GrantControls.BuiltInControls
                        if ($grantControls -contains "mfa" -or $grantControls -contains "compliantDevice") {
                            $requiresMFA = $true
                        }
                    }
                    
                    if (-not $requiresMFA) { continue }
                    
                    # Check if user is in scope
                    $userInScope = $false
                    
                    if ($policy.Conditions.Users.IncludeUsers -contains "All" -or
                        $policy.Conditions.Users.IncludeUsers -contains $user.Id) {
                        $userInScope = $true
                    }
                    
                    # Check included groups
                    if ($policy.Conditions.Users.IncludeGroups) {
                        foreach ($groupId in $policy.Conditions.Users.IncludeGroups) {
                            try {
                                $isMember = Get-MgGroupMember -GroupId $groupId -All | 
                                    Where-Object { $_.Id -eq $user.Id }
                                
                                if ($isMember) {
                                    $userInScope = $true
                                    break
                                }
                            }
                            catch { }
                        }
                    }
                    
                    # Check exclusions
                    if ($userInScope) {
                        if ($policy.Conditions.Users.ExcludeUsers -contains $user.Id) {
                            $userInScope = $false
                        }
                        
                        if ($policy.Conditions.Users.ExcludeGroups) {
                            foreach ($groupId in $policy.Conditions.Users.ExcludeGroups) {
                                try {
                                    $isMember = Get-MgGroupMember -GroupId $groupId -All | 
                                        Where-Object { $_.Id -eq $user.Id }
                                    
                                    if ($isMember) {
                                        $userInScope = $false
                                        break
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                    
                    if ($userInScope) {
                        $caPolicyEnforced = $true
                        $applicablePolicies += $policy.DisplayName
                    }
                }
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CHECK 3: MFA REGISTRATION STATUS
            # ═══════════════════════════════════════════════════════════════════════════
            
            $registeredMethods = @()
            $hasMFAMethods = $false
            
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                
                if ($authMethods) {
                    foreach ($method in $authMethods) {
                        $methodType = $method.AdditionalProperties.'@odata.type'
                        
                        if ($methodType -match "microsoftAuthenticator|phone|email|softwareOath|fido2") {
                            $registeredMethods += $methodType -replace '#microsoft.graph.', ''
                            $hasMFAMethods = $true
                        }
                    }
                }
            }
            catch {
                Write-Log "Could not retrieve auth methods for $($user.UserPrincipalName): $($_.Exception.Message)" -Level "Warning"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CHECK 4: ADMIN ROLE DETECTION
            # ═══════════════════════════════════════════════════════════════════════════
            
            $isAdmin = $false
            $adminRoles = @()
            
            try {
                $roleAssignments = Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction SilentlyContinue
                
                foreach ($role in $roleAssignments) {
                    $roleName = $role.AdditionalProperties.displayName
                    if ($roleName -like '*Admin*') {
                        $isAdmin = $true
                        $adminRoles += $roleName
                    }
                }
            }
            catch { }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # DETERMINE OVERALL MFA STATUS
            # ═══════════════════════════════════════════════════════════════════════════
            
            # Determine if MFA is enforced
            $mfaEnforced = $perUserMFAEnforced -or $caPolicyEnforced -or $securityDefaultsEnabled
            $mfaCapable = $hasMFAMethods
            
            # Build enforcement method list
            $enforcementMethod = @()
            if ($securityDefaultsEnabled) { $enforcementMethod += "Security Defaults" }
            if ($perUserMFAEnforced) { $enforcementMethod += "Per-User MFA" }
            if ($caPolicyEnforced) { $enforcementMethod += "Conditional Access" }
            
            # Determine HasMFA status (for HTML report compatibility)
            $hasMFAValue = "No"
            $mfaStatusDetail = "No MFA"
            
            if ($mfaEnforced -and $mfaCapable) {
                $hasMFAValue = "Yes"
                $enforcementList = $enforcementMethod -join " + "
                $mfaStatusDetail = "✅ Enforced via $enforcementList with $($registeredMethods.Count) method(s) registered"
            }
            elseif ($mfaEnforced -and -not $mfaCapable) {
                $hasMFAValue = "Partial"
                $enforcementList = $enforcementMethod -join " + "
                $mfaStatusDetail = "⚠️ Enforced via $enforcementList but NO methods registered (broken state)"
            }
            elseif (-not $mfaEnforced -and $mfaCapable) {
                $hasMFAValue = "Capable"
                $mfaStatusDetail = "⚠️ Methods registered ($($registeredMethods.Count)) but NOT enforced"
            }
            elseif ($mfaUsagePercent -gt 0 -and $signInTotalCount -gt 0) {
                if ($mfaUsagePercent -gt 80) {
                    $hasMFAValue = "Likely"
                    $mfaStatusDetail = "Inferred from sign-in behavior ($mfaUsagePercent% MFA usage)"
                }
                else {
                    $hasMFAValue = "Inconsistent"
                    $mfaStatusDetail = "Inconsistent MFA usage ($mfaUsagePercent%)"
                }
            }
            else {
                $hasMFAValue = "No"
                $mfaStatusDetail = "❌ No MFA enforcement or registration"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # RISK ASSESSMENT
            # ═══════════════════════════════════════════════════════════════════════════
            
            $riskLevel = "Low"
            $recommendation = ""
            
            if ($hasMFAValue -eq "No") {
                if ($isAdmin) {
                    $riskLevel = "Critical"
                    $recommendation = "🚨 CRITICAL: Admin account with NO MFA - Enable immediately!"
                }
                else {
                    $riskLevel = "High"
                    $recommendation = "🚨 HIGH: No MFA protection - Enable enforcement and register methods"
                }
            }
            elseif ($hasMFAValue -eq "Partial") {
                if ($isAdmin) {
                    $riskLevel = "Critical"
                    $recommendation = "🚨 CRITICAL: MFA enforced but no methods registered - User cannot sign in!"
                }
                else {
                    $riskLevel = "High"
                    $recommendation = "⚠️ HIGH: MFA enforced but no methods - User needs to register auth methods"
                }
            }
            elseif ($hasMFAValue -eq "Capable") {
                if ($isAdmin) {
                    $riskLevel = "High"
                    $recommendation = "⚠️ HIGH: Admin has MFA methods but not enforced - Enable enforcement"
                }
                else {
                    $riskLevel = "Medium"
                    $recommendation = "⚡ MEDIUM: MFA methods registered but not enforced - Enable per-user MFA or CA policy"
                }
            }
            elseif ($hasMFAValue -eq "Likely" -or $hasMFAValue -eq "Inconsistent") {
                $riskLevel = "Medium"
                $recommendation = "⚡ MEDIUM: Cannot fully verify MFA status - Manual review recommended"
            }
            else {
                # Has MFA = Yes
                $riskLevel = "Low"
                $recommendation = "✅ MFA properly configured"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CREATE RESULT OBJECT
            # ═══════════════════════════════════════════════════════════════════════════
            
            $mfaResults += [PSCustomObject]@{
                # User identification
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                
                # PRIMARY MFA STATUS (for HTML report compatibility)
                HasMFA = $hasMFAValue
                MFAStatusDetail = $mfaStatusDetail
                
                # Enforcement details
                MFAEnforced = $mfaEnforced
                EnforcementMethod = ($enforcementMethod -join ", ")
                SecurityDefaults = $securityDefaultsEnabled
                PerUserMFA = $perUserMFAState
                PerUserMFAEnforced = $perUserMFAEnforced
                ConditionalAccess = $caPolicyEnforced
                ApplicablePolicies = ($applicablePolicies -join "; ")
                
                # Registration details
                MFARegistered = $hasMFAMethods
                RegisteredMethods = ($registeredMethods -join ", ")
                MethodCount = $registeredMethods.Count
                
                # Sign-in analysis
                DetectionSource = $detectionSource
                MFAUsagePercent = if ($signInTotalCount -gt 0) { 
                    [math]::Round(($signInMFACount / $signInTotalCount) * 100, 0) 
                } else { 0 }
                SignInsMFA = $signInMFACount
                SignInsTotal = $signInTotalCount
                
                # Admin status
                IsAdmin = $isAdmin
                AdminRoles = if ($adminRoles.Count -gt 0) { $adminRoles -join ", " } else { "" }
                
                # Risk assessment
                RiskLevel = $riskLevel
                Recommendation = $recommendation
            }
        }
        
        # ═══════════════════════════════════════════════════════════════════════════════
        # EXPORT RESULTS
        # ═══════════════════════════════════════════════════════════════════════════════
        
        if ($mfaResults.Count -gt 0) {
            Update-GuiStatus "Exporting MFA status data..." ([System.Drawing.Color]::Orange)
            
            # Export main results
            $mfaResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Log "Exported MFA status to: $OutputPath" -Level "Info"
            
            # Export high-risk users
            $noMFA = $mfaResults | Where-Object { $_.HasMFA -eq "No" -and $_.AccountEnabled -eq $true }
            if ($noMFA.Count -gt 0) {
                $noMFAPath = $OutputPath -replace '.csv$', '_NoMFA.csv'
                $noMFA | Export-Csv -Path $noMFAPath -NoTypeInformation -Force
                Write-Log "Exported $($noMFA.Count) users without MFA to: $noMFAPath" -Level "Warning"
            }
            
            # Export per-user MFA only
            $perUserOnly = $mfaResults | Where-Object { 
                $_.PerUserMFAEnforced -eq $true -and 
                $_.ConditionalAccess -eq $false -and 
                $_.SecurityDefaults -eq $false
            }
            if ($perUserOnly.Count -gt 0) {
                $perUserOnlyPath = $OutputPath -replace '.csv$', '_PerUserOnly.csv'
                $perUserOnly | Export-Csv -Path $perUserOnlyPath -NoTypeInformation -Force
                Write-Log "Exported $($perUserOnly.Count) users with per-user MFA only to: $perUserOnlyPath" -Level "Info"
            }
            
            # Export critical/high risk
            $highRisk = $mfaResults | Where-Object { $_.RiskLevel -in @("Critical", "High") }
            if ($highRisk.Count -gt 0) {
                $highRiskPath = $OutputPath -replace '.csv$', '_HighRisk.csv'
                $highRisk | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
                Write-Log "Exported $($highRisk.Count) high-risk users to: $highRiskPath" -Level "Warning"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # SUMMARY STATISTICS
            # ═══════════════════════════════════════════════════════════════════════════
            
            $totalUsers = $mfaResults.Count
            $mfaEnabled = ($mfaResults | Where-Object { $_.HasMFA -eq "Yes" }).Count
            $mfaCapable = ($mfaResults | Where-Object { $_.HasMFA -eq "Capable" }).Count
            $noMFACount = ($mfaResults | Where-Object { $_.HasMFA -eq "No" }).Count
            $criticalRisk = ($mfaResults | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highRisk = ($mfaResults | Where-Object { $_.RiskLevel -eq "High" }).Count
            
            $betaAPICount = ($mfaResults | Where-Object { $_.DetectionSource -eq "Beta API" }).Count
            $signInAnalysisCount = ($mfaResults | Where-Object { $_.DetectionSource -eq "Sign-in Analysis" }).Count
            
            Update-GuiStatus "MFA audit complete: $mfaEnabled/$totalUsers users fully protected" ([System.Drawing.Color]::Green)
            
            Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
            Write-Log "MFA STATUS AUDIT COMPLETED" -Level "Info"
            Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
            Write-Log "Total Users: $totalUsers" -Level "Info"
            Write-Log "  Fully Protected (Yes): $mfaEnabled" -Level "Info"
            Write-Log "  Capable (Not Enforced): $mfaCapable" -Level "Info"
            Write-Log "  No MFA: $noMFACount" -Level "Warning"
            Write-Log "Risk Levels:" -Level "Info"
            Write-Log "  Critical: $criticalRisk" -Level "Error"
            Write-Log "  High: $highRisk" -Level "Warning"
            Write-Log "Detection Methods:" -Level "Info"
            Write-Log "  Beta API: $betaAPICount" -Level "Info"
            Write-Log "  Sign-in Analysis: $signInAnalysisCount" -Level "Info"
            Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
            
            return $mfaResults
        }
        else {
            Write-Log "No MFA results to export" -Level "Warning"
            return @()
        }
    }
    catch {
        Update-GuiStatus "Error during MFA audit: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in MFA status audit: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
        return $null
    }
}

function Get-FailedLoginPatterns {
    <#
    .SYNOPSIS
        Analyzes failed login patterns to detect attacks and breaches
    
    .DESCRIPTION
        Reviews sign-in data to identify:
        • Password spray attacks (same IP, many users)
        • Brute force attacks (same user, many attempts)
        • Confirmed breaches (5+ failures then success from SAME IP)
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$SignInDataPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "FailedLoginAnalysis.csv")
    )
    
    Update-GuiStatus "Analyzing failed login patterns..." ([System.Drawing.Color]::Orange)
    Write-Log "Starting failed login pattern analysis" -Level "Info"
    
    try {
        if (-not (Test-Path $SignInDataPath)) {
            Update-GuiStatus "Sign-in data not found! Run Get-TenantSignInData first." ([System.Drawing.Color]::Red)
            Write-Log "Sign-in data file not found: $SignInDataPath" -Level "Error"
            return $null
        }
        
        $signInData = Import-Csv -Path $SignInDataPath
        $failedLogins = $signInData | Where-Object { $_.Status -ne "0" -and ![string]::IsNullOrEmpty($_.Status) }
        $successfulLogins = $signInData | Where-Object { $_.Status -eq "0" -or [string]::IsNullOrEmpty($_.Status) }
        
        Write-Log "Found $($failedLogins.Count) failed logins and $($successfulLogins.Count) successful logins" -Level "Info"
        
        $patterns = @()
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 1: PASSWORD SPRAY DETECTION
        # Same IP attacking multiple users
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting password spray attacks..." ([System.Drawing.Color]::Orange)
        
        $ipGroups = $failedLogins | Group-Object -Property IP
        foreach ($ipGroup in $ipGroups) {
            $uniqueUsers = ($ipGroup.Group | Select-Object -Unique UserId).Count
            $totalAttempts = $ipGroup.Count
            
            if ($totalAttempts -ge 10 -and $uniqueUsers -ge 5) {
                $timespan = 0
                if ($ipGroup.Group.Count -gt 1) {
                    $firstAttempt = [DateTime]($ipGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    $lastAttempt = [DateTime]($ipGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    $timespan = [math]::Round(($lastAttempt - $firstAttempt).TotalHours, 1)
                }
                
                $patterns += [PSCustomObject]@{
                    PatternType = "Password Spray"
                    SourceIP = $ipGroup.Name
                    Location = ($ipGroup.Group | Select-Object -First 1).City + ", " + ($ipGroup.Group | Select-Object -First 1).Country
                    ISP = ($ipGroup.Group | Select-Object -First 1).ISP
                    TargetedUsers = $uniqueUsers
                    FailedAttempts = $totalAttempts
                    TimeSpan = $timespan
                    FirstSeen = ($ipGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    LastSeen = ($ipGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    RiskLevel = if ($uniqueUsers -ge 20 -or $totalAttempts -ge 50) { "Critical" } 
                               elseif ($uniqueUsers -ge 10 -or $totalAttempts -ge 25) { "High" }
                               else { "Medium" }
                    SuccessfulBreach = $false
                    Details = "Password Spray: IP $($ipGroup.Name) attempted $totalAttempts failed logins against $uniqueUsers different users"
                }
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 2: BRUTE FORCE DETECTION
        # Same user, multiple failed attempts
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting brute force attacks..." ([System.Drawing.Color]::Orange)
        
        $userGroups = $failedLogins | Group-Object -Property UserId
        foreach ($userGroup in $userGroups) {
            $totalAttempts = $userGroup.Count
            $uniqueIPs = ($userGroup.Group | Select-Object -Unique IP).Count
            
            if ($totalAttempts -ge 10) {
                $timespan = 0
                if ($userGroup.Group.Count -gt 1) {
                    $firstAttempt = [DateTime]($userGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    $lastAttempt = [DateTime]($userGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    $timespan = [math]::Round(($lastAttempt - $firstAttempt).TotalHours, 1)
                }
                
                $patterns += [PSCustomObject]@{
                    PatternType = "Brute Force"
                    SourceIP = if ($uniqueIPs -eq 1) { ($userGroup.Group | Select-Object -First 1).IP } else { "Multiple IPs ($uniqueIPs)" }
                    Location = if ($uniqueIPs -eq 1) { 
                        ($userGroup.Group | Select-Object -First 1).City + ", " + ($userGroup.Group | Select-Object -First 1).Country 
                    } else { "Multiple Locations" }
                    ISP = if ($uniqueIPs -eq 1) { ($userGroup.Group | Select-Object -First 1).ISP } else { "Various" }
                    TargetedUsers = 1
                    FailedAttempts = $totalAttempts
                    TimeSpan = $timespan
                    FirstSeen = ($userGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    LastSeen = ($userGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    RiskLevel = if ($totalAttempts -ge 50) { "Critical" } 
                               elseif ($totalAttempts -ge 25) { "High" }
                               else { "Medium" }
                    SuccessfulBreach = $false
                    Details = "Brute Force: User $($userGroup.Name) had $totalAttempts failed login attempts from $uniqueIPs different IP(s)"
                }
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 3: SUCCESSFUL BREACH AFTER FAILURES
        # Require 5+ failed attempts AND successful login from SAME IP
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting successful breaches (5+ failures, same IP required)..." ([System.Drawing.Color]::Orange)
        
        # Group failed logins by user and IP combination
        $failedByUserIP = $failedLogins | Group-Object -Property { "$($_.UserId)|$($_.IP)" }
        
        $breachCount = 0
        foreach ($group in $failedByUserIP) {
            # Require at least 5 failed attempts
            if ($group.Count -lt 5) { continue }
            
            # Parse the grouped key
            $parts = $group.Name -split '\|'
            if ($parts.Count -ne 2) { continue }
            
            $userId = $parts[0]
            $ip = $parts[1]
            
            # Skip if missing critical info
            if ([string]::IsNullOrWhiteSpace($userId) -or [string]::IsNullOrWhiteSpace($ip)) { continue }
            
            # Get the failed attempts sorted by time
            $attempts = $group.Group | Sort-Object CreationTime
            $firstFailedTime = [DateTime]($attempts[0].CreationTime)
            $lastFailedTime = [DateTime]($attempts[-1].CreationTime)
            
            # CRITICAL: Look for successful login from THE EXACT SAME IP
            # This ensures legitimate logins from office/home don't get flagged
            $breach = $successfulLogins | Where-Object {
                $_.IP -eq $ip -and                                          # MUST be same IP
                $_.UserId -eq $userId -and                                   # Same user
                [DateTime]$_.CreationTime -gt $lastFailedTime -and          # After last failure
                ([DateTime]$_.CreationTime - $firstFailedTime).TotalHours -le 2  # Within 2 hours
            } | Select-Object -First 1
            
            if ($breach) {
                # Double-check the IP match (redundant but safe)
                if ($breach.IP -ne $ip) {
                    Write-Log "Skipping false positive: Success from $($breach.IP), failures from $ip for $userId" -Level "Info"
                    continue
                }
                
                # Check if already logged
                $existing = $patterns | Where-Object {
                    $_.PatternType -eq "Successful Breach" -and
                    $_.SourceIP -eq $ip -and
                    $_.Details -like "*$userId*"
                }
                
                if (-not $existing) {
                    $breachCount++
                    $breachTime = [DateTime]$breach.CreationTime
                    $totalFailedAttempts = $group.Count
                    $timeToBreach = [math]::Round(($breachTime - $lastFailedTime).TotalMinutes, 1)
                    
                    $patterns += [PSCustomObject]@{
                        PatternType = "Successful Breach"
                        SourceIP = $ip
                        Location = $attempts[0].City + ", " + $attempts[0].Country
                        ISP = $attempts[0].ISP
                        TargetedUsers = 1
                        FailedAttempts = $totalFailedAttempts
                        TimeSpan = [math]::Round(($breachTime - $firstFailedTime).TotalHours, 2)
                        FirstSeen = $attempts[0].CreationTime
                        LastSeen = $breach.CreationTime
                        RiskLevel = if ($totalFailedAttempts -ge 20) { "Critical" } 
                                   elseif ($totalFailedAttempts -ge 10) { "High" } 
                                   else { "Medium" }
                        SuccessfulBreach = $true
                        Details = "CONFIRMED BREACH: User $userId - $totalFailedAttempts failed attempts from $ip ($($attempts[0].City), $($attempts[0].Country)), then successful login from SAME IP after $timeToBreach min"
                    }
                    
                    Write-Log "BREACH DETECTED: $userId - $totalFailedAttempts failures from $ip, success from same IP after $timeToBreach min" -Level "Warning"
                }
            }
        }
        
        Write-Log "Breach detection complete: $breachCount confirmed breaches (same IP requirement)" -Level "Info"
        
        # Export results
        if ($patterns.Count -gt 0) {
            $patterns | Sort-Object RiskLevel, FailedAttempts -Descending | 
                Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            $criticalPatterns = $patterns | Where-Object { $_.RiskLevel -eq "Critical" }
            if ($criticalPatterns.Count -gt 0) {
                $criticalPath = $OutputPath -replace '.csv$', '_Critical.csv'
                $criticalPatterns | Export-Csv -Path $criticalPath -NoTypeInformation -Force
            }
            
            $breaches = $patterns | Where-Object { $_.SuccessfulBreach -eq $true }
            if ($breaches.Count -gt 0) {
                $breachPath = $OutputPath -replace '.csv$', '_Breaches.csv'
                $breaches | Export-Csv -Path $breachPath -NoTypeInformation -Force
            }
            
            $stats = @{
                TotalPatterns = $patterns.Count
                PasswordSpray = ($patterns | Where-Object { $_.PatternType -eq "Password Spray" }).Count
                BruteForce = ($patterns | Where-Object { $_.PatternType -eq "Brute Force" }).Count
                Breaches = $breaches.Count
                Critical = $criticalPatterns.Count
            }
            
            Update-GuiStatus "Attack analysis complete: $($stats.TotalPatterns) patterns detected ($($stats.Breaches) confirmed breaches)" ([System.Drawing.Color]::Green)
            Write-Log "Attack Pattern Summary:" -Level "Info"
            Write-Log "  Total Patterns: $($stats.TotalPatterns)" -Level "Info"
            Write-Log "  Password Spray: $($stats.PasswordSpray)" -Level "Info"
            Write-Log "  Brute Force: $($stats.BruteForce)" -Level "Info"
            Write-Log "  Confirmed Breaches: $($stats.Breaches) (5+ failures + same IP success)" -Level "Info"
            Write-Log "  Critical Risk: $($stats.Critical)" -Level "Info"
        }
        else {
            Update-GuiStatus "No suspicious failed login patterns detected" ([System.Drawing.Color]::Green)
            Write-Log "No attack patterns detected" -Level "Info"
        }
        
        return $patterns
    }
    catch {
        Update-GuiStatus "Error analyzing failed logins: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Failed login analysis error: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-RecentPasswordChanges {
    <#
    .SYNOPSIS
        Identifies suspicious password reset patterns
    
    .DESCRIPTION
        Analyzes admin audit logs for password change patterns
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$AdminAuditPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv"),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "PasswordChangeAnalysis.csv")
    )
    
    Update-GuiStatus "Analyzing password change patterns..." ([System.Drawing.Color]::Orange)
    Write-Log "Starting password change analysis" -Level "Info"
    
    try {
        # Check if admin audit data exists
        if (-not (Test-Path $AdminAuditPath)) {
            Update-GuiStatus "Admin audit data not found! Run Get-AdminAuditData first." ([System.Drawing.Color]::Red)
            Write-Log "Admin audit file not found: $AdminAuditPath" -Level "Error"
            return $null
        }
        
        # Import admin audit data
        Update-GuiStatus "Loading admin audit data..." ([System.Drawing.Color]::Orange)
        $auditData = Import-Csv -Path $AdminAuditPath
        Write-Log "Loaded $($auditData.Count) audit records" -Level "Info"
        
        # Filter password change events with valid dates
        $passwordEvents = $auditData | Where-Object {
            ($_.Activity -like "*password*" -or
             $_.Activity -like "*Reset user password*" -or
             $_.Activity -like "*Change user password*") -and
            (-not [string]::IsNullOrWhiteSpace($_.ActivityDate))
        }
        
        Write-Log "Found $($passwordEvents.Count) password-related events with valid dates" -Level "Info"
        
        if ($passwordEvents.Count -eq 0) {
            Update-GuiStatus "No password change events found" ([System.Drawing.Color]::Green)
            Write-Log "No password changes detected in audit logs" -Level "Info"
            return @()
        }
        
        $suspiciousPatterns = @()
        
        # Group by target user
        $userGroups = $passwordEvents | Group-Object -Property TargetUser | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }
        
        foreach ($userGroup in $userGroups) {
            try {
                # Sort events and convert dates
                $events = $userGroup.Group | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ActivityDate) } | Sort-Object ActivityDate
                $changeCount = $events.Count
                
                # Skip users with only 1 password change
                if ($changeCount -eq 1) { continue }
                
                # Safe date conversion with error handling
                $firstChange = $null
                $lastChange = $null
                
                try {
                    $firstChange = [DateTime]::Parse($events[0].ActivityDate)
                    $lastChange = [DateTime]::Parse($events[-1].ActivityDate)
                } catch {
                    Write-Log "Date parsing error for user $($userGroup.Name): $($_.Exception.Message)" -Level "Warning"
                    continue
                }
                
                $timespan = ($lastChange - $firstChange).TotalHours
                
                # Calculate who initiated changes
                $initiators = ($events | Where-Object { -not [string]::IsNullOrWhiteSpace($_.InitiatedBy) } | Select-Object -Unique InitiatedBy).Count
                $selfReset = ($events | Where-Object { $_.InitiatedBy -eq $_.TargetUser }).Count
                $adminReset = ($events | Where-Object { $_.InitiatedBy -ne $_.TargetUser }).Count
                
                # Check for off-hours activity (before 6 AM or after 10 PM)
                $offHoursChanges = 0
                foreach ($event in $events) {
                    try {
                        $eventDate = [DateTime]::Parse($event.ActivityDate)
                        $hour = $eventDate.Hour
                        if ($hour -lt 6 -or $hour -gt 22) {
                            $offHoursChanges++
                        }
                    } catch {
                        # Skip events with unparseable dates
                        continue
                    }
                }
                
                # SUSPICIOUS PATTERN DETECTION
                $isSuspicious = $false
                $reasons = @()
                $riskScore = 0
                
                # Multiple changes in 24 hours
                if ($timespan -lt 24 -and $changeCount -ge 3) {
                    $isSuspicious = $true
                    $reasons += "Multiple password changes ($changeCount) within 24 hours"
                    $riskScore += 25
                }
                
                # Very rapid changes (less than 6 hours)
                if ($timespan -lt 6 -and $changeCount -ge 2) {
                    $isSuspicious = $true
                    $reasons += "Rapid password changes in less than 6 hours"
                    $riskScore += 35
                }
                
                # Multiple initiators (different people resetting password)
                if ($initiators -gt 2) {
                    $isSuspicious = $true
                    $reasons += "Password reset by $initiators different people"
                    $riskScore += 20
                }
                
                # Off-hours activity
                if ($offHoursChanges -ge 2) {
                    $isSuspicious = $true
                    $reasons += "$offHoursChanges password changes during off-hours"
                    $riskScore += 15
                }
                
                # Many changes over longer period
                if ($changeCount -ge 5) {
                    $isSuspicious = $true
                    $reasons += "Excessive password changes ($changeCount total)"
                    $riskScore += 20
                }
                
                if ($isSuspicious) {
                    $riskLevel = if ($riskScore -ge 50) { "Critical" }
                                elseif ($riskScore -ge 30) { "High" }
                                elseif ($riskScore -ge 15) { "Medium" }
                                else { "Low" }
                    
                    $suspiciousPatterns += [PSCustomObject]@{
                        User = $userGroup.Name
                        ChangeCount = $changeCount
                        TimeSpanHours = [math]::Round($timespan, 1)
                        FirstChange = $firstChange.ToString("yyyy-MM-dd HH:mm")
                        LastChange = $lastChange.ToString("yyyy-MM-dd HH:mm")
                        UniqueInitiators = $initiators
                        SelfResets = $selfReset
                        AdminResets = $adminReset
                        OffHoursChanges = $offHoursChanges
                        RiskScore = $riskScore
                        RiskLevel = $riskLevel
                        SuspiciousReasons = ($reasons -join "; ")
                        Recommendation = if ($riskScore -ge 50) {
                            "URGENT: Investigate immediately - possible active compromise"
                        } elseif ($riskScore -ge 30) {
                            "HIGH PRIORITY: Review account activity"
                        } else {
                            "Review account for suspicious activity"
                        }
                    }
                }
            }
            catch {
                Write-Log "Error processing password changes for $($userGroup.Name): $($_.Exception.Message)" -Level "Warning"
                continue
            }
        }
        
        # Export results
        if ($suspiciousPatterns.Count -gt 0) {
            $suspiciousPatterns | Sort-Object RiskScore -Descending | 
                Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create critical file
            $critical = $suspiciousPatterns | Where-Object { $_.RiskLevel -eq "Critical" }
            if ($critical.Count -gt 0) {
                $criticalPath = $OutputPath -replace '.csv$', '_Critical.csv'
                $critical | Export-Csv -Path $criticalPath -NoTypeInformation -Force
            }
            
            $stats = @{
                Total = $suspiciousPatterns.Count
                Critical = ($suspiciousPatterns | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                High = ($suspiciousPatterns | Where-Object { $_.RiskLevel -eq "High" }).Count
            }
            
            Update-GuiStatus "Password change analysis complete: $($stats.Total) suspicious patterns ($($stats.Critical) critical)" ([System.Drawing.Color]::Green)
            Write-Log "Password Change Analysis: Total=$($stats.Total), Critical=$($stats.Critical), High=$($stats.High)" -Level "Info"
        }
        else {
            Update-GuiStatus "No suspicious password change patterns detected" ([System.Drawing.Color]::Green)
            Write-Log "No suspicious password patterns found" -Level "Info"
        }
        
        return $suspiciousPatterns
    }
    catch {
        Update-GuiStatus "Error analyzing password changes: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Password change analysis error: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# ADMIN AUDIT LOG COLLECTION
#══════════════════════════════════════════════════════════════

function Get-AdminAuditData {
    <#
    .SYNOPSIS
        Collects and analyzes admin audit logs with risk assessment.
    
    .DESCRIPTION
        Retrieves directory audit logs from Microsoft Graph and enriches them with:
        • Risk level classification (Critical/High/Medium/Low)
        • Login status determination (TRUE/FALSE/OTHER)
        • Target resource extraction
        • Activity categorization
        
        Risk scoring based on:
        • Permission changes (highest risk)
        • Role modifications
        • Application changes
        • Mailbox access modifications
        
        Login detection identifies:
        • Successful authentication events
        • Failed login attempts
        • Non-login administrative actions
    
    .PARAMETER DaysBack
        Number of days of audit logs to retrieve (1-365)
        Default: $ConfigData.DateRange
    
    .PARAMETER OutputPath
        Path for main output file
        Additional filtered files created automatically:
        • _Critical.csv - High-risk operations only
        • _Failed.csv - Failed operations
        • _LoginActivity.csv - Login events only
    
    .OUTPUTS
        Array of enriched audit log objects
    
    .EXAMPLE
        Get-AdminAuditData -DaysBack 30
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv")
    )
    
    Update-GuiStatus "Starting admin audit logs collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    
    $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
    $endDate = (Get-Date).ToString("yyyy-MM-dd")
    
    try {
        Update-GuiStatus "Querying Microsoft Graph for admin audit logs..." ([System.Drawing.Color]::Orange)
        
        $auditLogs = @()
        $pageSize = 1000
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $startDate and activityDateTime le $endDate&`$top=$pageSize"
        
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            $auditLogs += $response.value
            $uri = $response.'@odata.nextLink'
            
            Update-GuiStatus "Retrieved $($auditLogs.Count) admin audit records..." ([System.Drawing.Color]::Orange)
        } while ($uri)
        
        Write-Log "Retrieved $($auditLogs.Count) admin audit log records" -Level "Info"
        
        # Process and enrich logs
        $processedLogs = @()
        $counter = 0
        
        foreach ($log in $auditLogs) {
            $counter++
            if ($counter % 100 -eq 0) {
                $percentage = [math]::Round(($counter / $auditLogs.Count) * 100, 1)
                Update-GuiStatus "Processing admin audits: $counter of $($auditLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Risk assessment
            $riskLevel = "Low"
            $activityDisplayName = $log.activityDisplayName
            
            switch -Regex ($activityDisplayName) {
                ".*[Aa]dd.*[Pp]ermission.*|.*[Aa]dd.*[Rr]ole.*" { $riskLevel = "High" }
                ".*[Aa]dd.*[Mm]ember.*" { $riskLevel = "High" }
                ".*[Cc]reate.*[Aa]pplication.*|.*[Cc]reate.*[Ss]ervice [Pp]rincipal.*" { $riskLevel = "Medium" }
                ".*[Uu]pdate.*[Aa]pplication.*" { $riskLevel = "Medium" }
                ".*[Dd]elete.*|.*[Rr]emove.*" { $riskLevel = "Medium" }
                default { $riskLevel = "Low" }
            }
            
            # Login status determination
            $loginStatus = "OTHER"
            $loginActivities = @(
                "Sign-in activity", "User logged in", "User signed in",
                "Interactive user sign in", "Non-interactive user sign in"
            )
            
            $isLoginActivity = $false
            foreach ($loginActivity in $loginActivities) {
                if ($activityDisplayName -like "*$loginActivity*") {
                    $isLoginActivity = $true
                    break
                }
            }
            
            if ($isLoginActivity) {
                switch ($log.result) {
                    "success" { $loginStatus = "TRUE" }
                    "failure" { $loginStatus = "FALSE" }
                    "interrupted" { $loginStatus = "FALSE" }
                    "timeout" { $loginStatus = "FALSE" }
                    default { 
                        if ($log.resultReason -like "*success*" -or $log.resultReason -like "*completed*") {
                            $loginStatus = "TRUE"
                        } elseif ($log.resultReason -like "*fail*" -or $log.resultReason -like "*error*") {
                            $loginStatus = "FALSE"
                        }
                    }
                }
            }
            
            # Extract target resources
            $targetResources = $log.targetResources | ForEach-Object {
                [PSCustomObject]@{
                    Type = $_.type
                    DisplayName = $_.displayName
                    Id = $_.id
                    UserPrincipalName = $_.userPrincipalName
                }
            }
            
            $processedLog = [PSCustomObject]@{
                Timestamp = [DateTime]::Parse($log.activityDateTime)
                UserId = $log.initiatedBy.user.userPrincipalName
                UserDisplayName = $log.initiatedBy.user.displayName
                Activity = $activityDisplayName
                Result = $log.result
                ResultReason = $log.resultReason
                Category = $log.category
                CorrelationId = $log.correlationId
                LoggedByService = $log.loggedByService
                RiskLevel = $riskLevel
                LOGIN = $loginStatus
                TargetResources = ($targetResources | ConvertTo-Json -Compress -Depth 10)
                AdditionalDetails = ($log.additionalDetails | ConvertTo-Json -Compress -Depth 10)
            }
            
            $processedLogs += $processedLog
        }
        
        # Export results
        $processedLogs | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        # Create filtered versions
        $highRiskLogs = $processedLogs | Where-Object { $_.RiskLevel -eq "High" }
        if ($highRiskLogs.Count -gt 0) {
            $highRiskPath = $OutputPath -replace '.csv$', '_Critical.csv'
            $highRiskLogs | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            Write-Log "Found $($highRiskLogs.Count) high-risk admin operations" -Level "Warning"
        }
        
        $failedLogs = $processedLogs | Where-Object { $_.Result -ne "success" }
        if ($failedLogs.Count -gt 0) {
            $failedPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedLogs | Export-Csv -Path $failedPath -NoTypeInformation -Force
        }
        
        $loginLogs = $processedLogs | Where-Object { $_.LOGIN -ne "OTHER" }
        if ($loginLogs.Count -gt 0) {
            $loginPath = $OutputPath -replace '.csv$', '_LoginActivity.csv'
            $loginLogs | Export-Csv -Path $loginPath -NoTypeInformation -Force
        }
        
        Update-GuiStatus "Admin audit log collection completed: $($processedLogs.Count) records." ([System.Drawing.Color]::Green)
        Write-Log "Admin audit collection complete" -Level "Info"
        
        return $processedLogs
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in admin audit collection: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# MAILBOX RULES COLLECTION
#══════════════════════════════════════════════════════════════

function Get-MailboxRules {
    <#
    .SYNOPSIS
        Collects inbox rules with performance optimizations
    
    .DESCRIPTION
        Retrieves inbox rules from all mailboxes with smart filtering
        and progress tracking. Note: Exchange Online cmdlets cannot use
        ForEach-Object -Parallel, so this uses optimized sequential processing.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "InboxRules.csv"),
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeInactive,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysInactive = 90
    )
    
    Update-GuiStatus "Starting mailbox rules collection..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
    Write-Log "MAILBOX RULES COLLECTION STARTED" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
    
    try {
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 1: ENSURE EXCHANGE ONLINE CONNECTION
        # ═══════════════════════════════════════════════════════════════════════════
        
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            Update-GuiStatus "Exchange Online connection failed - skipping rules" ([System.Drawing.Color]::Red)
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online connection required for mailbox rule collection.",
                "Connection Required", "OK", "Warning"
            )
            return @()
        }
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 2: GET FILTERED MAILBOX LIST (PERFORMANCE OPTIMIZATION)
        # ═══════════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Retrieving mailboxes with smart filtering..." ([System.Drawing.Color]::Orange)
        Write-Log "Retrieving user mailboxes" -Level "Info"
        
        # Get mailboxes
        $allMailboxes = Get-Mailbox -ResultSize Unlimited `
                                     -RecipientTypeDetails UserMailbox `
                                     -ErrorAction Stop
        
        Write-Log "Retrieved $($allMailboxes.Count) mailboxes" -Level "Info"
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 3: FILTER OUT INACTIVE USERS (OPTIONAL BUT RECOMMENDED)
        # ═══════════════════════════════════════════════════════════════════════════
        
        $mailboxesToCheck = $allMailboxes
        
        if (-not $IncludeInactive -and $DaysInactive -gt 0) {
            Update-GuiStatus "Filtering out mailboxes inactive for $DaysInactive+ days..." ([System.Drawing.Color]::Orange)
            Write-Log "Checking last sign-in activity to skip inactive users" -Level "Info"
            
            try {
                # Get recent sign-in data to filter inactive users
                $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
                $activeUserUpns = @()
                
                # Get users with recent activity from Graph
                $recentUsers = Get-MgUser -All `
                    -Property UserPrincipalName,SignInActivity `
                    -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        $_.SignInActivity.LastSignInDateTime -and 
                        $_.SignInActivity.LastSignInDateTime -ge $cutoffDate 
                    }
                
                if ($recentUsers) {
                    $activeUserUpns = $recentUsers.UserPrincipalName
                    $mailboxesToCheck = $allMailboxes | Where-Object { 
                        $activeUserUpns -contains $_.UserPrincipalName 
                    }
                    
                    $skipped = $allMailboxes.Count - $mailboxesToCheck.Count
                    Write-Log "Filtered to $($mailboxesToCheck.Count) active mailboxes (skipped $skipped inactive)" -Level "Info"
                    Update-GuiStatus "Checking $($mailboxesToCheck.Count) active mailboxes (skipped $skipped inactive)" ([System.Drawing.Color]::Orange)
                }
                else {
                    Write-Log "Could not retrieve sign-in activity data, checking all mailboxes" -Level "Warning"
                }
            }
            catch {
                Write-Log "Could not filter by sign-in activity, checking all mailboxes: $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        if ($mailboxesToCheck.Count -eq 0) {
            Write-Log "No mailboxes to check" -Level "Warning"
            return @()
        }
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 4: COLLECT RULES (SEQUENTIAL - EXCHANGE ONLINE REQUIREMENT)
        # ═══════════════════════════════════════════════════════════════════════════
        
        Write-Log "Processing $($mailboxesToCheck.Count) mailboxes for inbox rules" -Level "Info"
        Write-Log "NOTE: Exchange Online cmdlets require sequential processing" -Level "Info"
        
        $allRulesArray = @()
        $processedCount = 0
        $startTime = Get-Date
        
        foreach ($mailbox in $mailboxesToCheck) {
            $processedCount++
            
            # Progress update every 5 mailboxes (more frequent for better feedback)
            if ($processedCount % 5 -eq 0 -or $processedCount -eq 1) {
                $percentage = [Math]::Round(($processedCount / $mailboxesToCheck.Count) * 100, 1)
                $elapsed = (Get-Date) - $startTime
                $estimatedTotal = if ($processedCount -gt 0) { 
                    $elapsed.TotalSeconds / $processedCount * $mailboxesToCheck.Count 
                } else { 0 }
                $remaining = [TimeSpan]::FromSeconds($estimatedTotal - $elapsed.TotalSeconds)
                
                $eta = if ($remaining.TotalMinutes -gt 60) {
                    "$([Math]::Round($remaining.TotalHours, 1))h remaining"
                } elseif ($remaining.TotalMinutes -gt 1) {
                    "$([Math]::Round($remaining.TotalMinutes, 0))m remaining"
                } else {
                    "$([Math]::Round($remaining.TotalSeconds, 0))s remaining"
                }
                
                Update-GuiStatus "Processing rules: $processedCount/$($mailboxesToCheck.Count) ($percentage%) - $eta - $($allRulesArray.Count) rules found" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            try {
                Write-Log "Checking rules for: $($mailbox.PrimarySmtpAddress)" -Level "Info"
                
                # Get rules for this mailbox
                $rules = Get-InboxRule -Mailbox $mailbox.PrimarySmtpAddress -ErrorAction Stop
                
                if ($rules) {
                    Write-Log "Found $(@($rules).Count) rule(s) for $($mailbox.PrimarySmtpAddress)" -Level "Info"
                    
                    foreach ($rule in $rules) {
                        # Analyze rule for suspicious patterns
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        # Check for forwarding
                        if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Forwards email"
                            
                            # Check for external forwarding
                            $mailboxDomain = $mailbox.PrimarySmtpAddress.Split('@')[1]
                            if ($rule.ForwardTo) {
                                foreach ($forwardAddr in $rule.ForwardTo) {
                                    if ($forwardAddr -notlike "*$mailboxDomain*") {
                                        $suspiciousReasons += "External forwarding"
                                        break
                                    }
                                }
                            }
                        }
                        
                        # Check for deletion
                        if ($rule.DeleteMessage -eq $true) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Deletes messages"
                        }
                        
                        # Check for suspicious folder moves
                        if ($rule.MoveToFolder) {
                            if ($rule.MoveToFolder -like "*Deleted*" -or 
                                $rule.MoveToFolder -like "*Junk*" -or
                                $rule.MoveToFolder -like "*Archive*") {
                                $isSuspicious = $true
                                $suspiciousReasons += "Moves to suspicious folder"
                            }
                        }
                        
                        # Check for mark as read (common in compromises)
                        if ($rule.MarkAsRead -eq $true) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Marks as read"
                        }
                        
                        # Check for stop processing (hides rule activity)
                        if ($rule.StopProcessingRules -eq $true) {
                            $suspiciousReasons += "Stops processing other rules"
                        }
                        
                        # Check for hidden/suspicious names
                        if ($rule.Name -match "^\.|^\.\.|\s{3,}|^$|^\s+$") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Suspicious/hidden name"
                        }
                        
                        $ruleObject = [PSCustomObject]@{
                            Mailbox = $mailbox.PrimarySmtpAddress
                            DisplayName = $mailbox.DisplayName
                            RuleName = $rule.Name
                            Description = $rule.Description
                            Enabled = $rule.Enabled
                            Priority = $rule.Priority
                            ForwardTo = if ($rule.ForwardTo) { $rule.ForwardTo -join "; " } else { "" }
                            RedirectTo = if ($rule.RedirectTo) { $rule.RedirectTo -join "; " } else { "" }
                            ForwardAsAttachmentTo = if ($rule.ForwardAsAttachmentTo) { $rule.ForwardAsAttachmentTo -join "; " } else { "" }
                            DeleteMessage = $rule.DeleteMessage
                            MarkAsRead = $rule.MarkAsRead
                            StopProcessingRules = $rule.StopProcessingRules
                            MoveToFolder = $rule.MoveToFolder
                            SubjectContains = if ($rule.SubjectContainsWords) { $rule.SubjectContainsWords -join "; " } else { "" }
                            FromAddress = if ($rule.From) { $rule.From -join "; " } else { "" }
                            SentTo = if ($rule.SentTo) { $rule.SentTo -join "; " } else { "" }
                            IsSuspicious = $isSuspicious
                            SuspiciousReasons = if ($suspiciousReasons.Count -gt 0) { $suspiciousReasons -join ", " } else { "" }
                            RuleIdentity = $rule.Identity
                        }
                        
                        $allRulesArray += $ruleObject
                    }
                }
                else {
                    Write-Log "No rules found for $($mailbox.PrimarySmtpAddress)" -Level "Info"
                }
            }
            catch {
                Write-Log "Error getting rules for $($mailbox.PrimarySmtpAddress): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 5: EXPORT RESULTS
        # ═══════════════════════════════════════════════════════════════════════════
        
        $elapsedTime = (Get-Date) - $startTime
        
        if ($allRulesArray.Count -gt 0) {
            Update-GuiStatus "Exporting $($allRulesArray.Count) rules..." ([System.Drawing.Color]::Orange)
            
            # Export all rules
            $allRulesArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Log "Exported $($allRulesArray.Count) rules to: $OutputPath" -Level "Info"
            
            # Export suspicious rules
            $suspiciousRules = $allRulesArray | Where-Object { $_.IsSuspicious -eq $true }
            if ($suspiciousRules.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousRules | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
                Write-Log "Exported $($suspiciousRules.Count) suspicious rules to: $suspiciousPath" -Level "Warning"
            }
            
            # Export forwarding rules specifically
            $forwardingRules = $allRulesArray | Where-Object { 
                $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo 
            }
            if ($forwardingRules.Count -gt 0) {
                $forwardingPath = $OutputPath -replace '.csv$', '_Forwarding.csv'
                $forwardingRules | Export-Csv -Path $forwardingPath -NoTypeInformation -Force
                Write-Log "Exported $($forwardingRules.Count) forwarding rules to: $forwardingPath" -Level "Info"
            }
            
            # Statistics
            $mailboxesWithRules = ($allRulesArray | Select-Object -ExpandProperty Mailbox -Unique).Count
            $enabledRules = ($allRulesArray | Where-Object { $_.Enabled -eq $true }).Count
            $avgRulesPerMailbox = if ($mailboxesWithRules -gt 0) { 
                [Math]::Round($allRulesArray.Count / $mailboxesWithRules, 1) 
            } else { 0 }
            
            Update-GuiStatus "Rules collection complete: $($allRulesArray.Count) rules from $mailboxesWithRules mailboxes ($($suspiciousRules.Count) suspicious)" ([System.Drawing.Color]::Green)
            
            Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
            Write-Log "MAILBOX RULES COLLECTION COMPLETED" -Level "Info"
            Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
            Write-Log "Processing Time: $($elapsedTime.ToString('mm\:ss'))" -Level "Info"
            Write-Log "Mailboxes Checked: $($mailboxesToCheck.Count)" -Level "Info"
            Write-Log "Mailboxes With Rules: $mailboxesWithRules" -Level "Info"
            Write-Log "Total Rules: $($allRulesArray.Count)" -Level "Info"
            Write-Log "Enabled Rules: $enabledRules" -Level "Info"
            Write-Log "Average Rules per Mailbox: $avgRulesPerMailbox" -Level "Info"
            Write-Log "Suspicious Rules: $($suspiciousRules.Count)" -Level "Warning"
            Write-Log "Forwarding Rules: $($forwardingRules.Count)" -Level "Info"
            Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
            
            return $allRulesArray
        }
        else {
            Update-GuiStatus "No inbox rules found in any mailbox" ([System.Drawing.Color]::Yellow)
            Write-Log "No inbox rules found in any mailbox" -Level "Info"
            Write-Log "Mailboxes checked: $($mailboxesToCheck.Count)" -Level "Info"
            Write-Log "Processing time: $($elapsedTime.ToString('mm\:ss'))" -Level "Info"
            return @()
        }
    }
    catch {
        Update-GuiStatus "Error collecting inbox rules: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in mailbox rules collection: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# ADDITIONAL DATA COLLECTION FUNCTIONS
#══════════════════════════════════════════════════════════════

function Get-MailboxDelegationData {
    <#
    .SYNOPSIS
        Collects mailbox delegation permissions.
    
    .DESCRIPTION
        Retrieves mailbox delegation settings identifying:
        • External delegates (high risk)
        • High privilege access (FullAccess, SendAs)
        • Unusual delegation patterns
    
    .OUTPUTS
        Array of delegation objects with risk flags
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MailboxDelegation.csv")
    )
    
    Update-GuiStatus "Starting mailbox delegation collection..." ([System.Drawing.Color]::Orange)
    
    try {
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, Mail | Where-Object { $_.Mail -ne $null }
        $totalCount = $users.Count
        $delegations = @()
        $suspiciousDelegations = @()
        $processedCount = 0
        
        foreach ($user in $users) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                $percentage = [math]::Round(($processedCount / $totalCount) * 100, 1)
                Update-GuiStatus "Processing delegations: $processedCount of $totalCount ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            try {
                $mailboxSettings = Get-MgUserMailboxSetting -UserId $user.Id -ErrorAction Stop
                
                if ($mailboxSettings.DelegatesSettings) {
                    foreach ($delegate in $mailboxSettings.DelegatesSettings) {
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        $delegateEmail = $delegate.EmailAddress.Address
                        if ($delegateEmail -notlike "*onmicrosoft.com" -and $delegateEmail -notlike "*$((Get-MgOrganization).VerifiedDomains[0].Name)*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "External delegate"
                        }
                        
                        if ($delegate.Permissions -contains "FullAccess" -or $delegate.Permissions -contains "SendAs") {
                            $suspiciousReasons += "High privilege access"
                            $isSuspicious = $true
                        }
                        
                        $delegationEntry = [PSCustomObject]@{
                            Mailbox = $user.UserPrincipalName
                            DisplayName = $user.DisplayName
                            DelegateName = $delegate.DisplayName
                            DelegateEmail = $delegateEmail
                            Permissions = ($delegate.Permissions -join "; ")
                            IsSuspicious = $isSuspicious
                            SuspiciousReasons = $suspiciousReasons -join "; "
                        }
                        
                        $delegations += $delegationEntry
                        if ($isSuspicious) { $suspiciousDelegations += $delegationEntry }
                    }
                }
            }
            catch { continue }
        }
        
        if ($delegations.Count -gt 0) {
            $delegations | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            if ($suspiciousDelegations.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousDelegations | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
            }
            
            Update-GuiStatus "Delegation collection complete: $($delegations.Count) delegations." ([System.Drawing.Color]::Green)
        }
        
        return $delegations
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        return $null
    }
}

function Get-AppRegistrationData {
    <#
    .SYNOPSIS
        Collects app registrations with risk assessment.
    
    .DESCRIPTION
        Retrieves application registrations and service principals,
        assessing risk based on:
        • Requested permissions (high-privilege APIs)
        • Missing publisher information
        • Recently created apps
        • Unusual configurations
    
    .OUTPUTS
        Array of app registration objects with risk scores
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AppRegistrations.csv")
    )
    
    Update-GuiStatus "Starting app registration collection..." ([System.Drawing.Color]::Orange)
    $startDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        $applications = Get-MgApplication -All
        $servicePrincipals = Get-MgServicePrincipal -All
        
        $appRegs = @()
        $processedCount = 0
        
        foreach ($app in $applications) {
            $processedCount++
            if ($processedCount % 50 -eq 0) {
                $percentage = [math]::Round(($processedCount / $applications.Count) * 100, 1)
                Update-GuiStatus "Processing apps: $processedCount of $($applications.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            if ($app.CreatedDateTime -ge $startDate) {
                $servicePrincipal = $servicePrincipals | Where-Object { $_.AppId -eq $app.AppId } | Select-Object -First 1
                
                $riskLevel = "Low"
                $riskReasons = @()
                
                # Check high-risk permissions
                foreach ($resourceAccess in $app.RequiredResourceAccess) {
                    foreach ($permission in $resourceAccess.ResourceAccess) {
                        if ($permission.Id -in @(
                            "570282fd-fa5c-430d-a7fd-fc8dc98a9dca",  # Mail.ReadWrite
                            "024d486e-b451-40bb-833d-3e66d98c5c73",  # Mail.Read
                            "75359482-378d-4052-8f01-80520e7db3cd",  # Files.ReadWrite.All
                            "06da0dbc-49e2-44d2-8312-53746b5fccd9"   # Directory.Read.All
                        )) {
                            $riskLevel = "High"
                            $riskReasons += "High-privilege permissions"
                        }
                    }
                }
                
                if ([string]::IsNullOrEmpty($app.PublisherDomain)) {
                    $riskLevel = "Medium"
                    $riskReasons += "No publisher information"
                }
                
                $appReg = [PSCustomObject]@{
                    AppId = $app.AppId
                    DisplayName = $app.DisplayName
                    CreatedDateTime = $app.CreatedDateTime
                    PublisherDomain = $app.PublisherDomain
                    Homepage = $app.Web.HomePageUrl
                    ServicePrincipalId = $servicePrincipal.Id
                    ServicePrincipalType = $servicePrincipal.ServicePrincipalType
                    SignInAudience = $app.SignInAudience
                    RequiredResourceAccess = ($app.RequiredResourceAccess | ConvertTo-Json -Compress -Depth 10)
                    RiskLevel = $riskLevel
                    RiskReasons = ($riskReasons -join "; ")
                }
                
                $appRegs += $appReg
            }
        }
        
        if ($appRegs.Count -gt 0) {
            $appRegs | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            $highRiskApps = $appRegs | Where-Object { $_.RiskLevel -eq "High" }
            if ($highRiskApps.Count -gt 0) {
                $highRiskPath = $OutputPath -replace '.csv$', '_HighRisk.csv'
                $highRiskApps | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            }
            
            Update-GuiStatus "App registration collection complete: $($appRegs.Count) apps." ([System.Drawing.Color]::Green)
        }
        
        return $appRegs
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        return $null
    }
}

function Get-ConditionalAccessData {
    <#
    .SYNOPSIS
        Collects Conditional Access policies with configuration review.
    
    .DESCRIPTION
        Retrieves CA policies and identifies:
        • Recently modified policies
        • Disabled policies
        • Policies excluding admin roles (potential bypass)
        • Configuration issues
    
    .OUTPUTS
        Array of CA policy objects with risk flags
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ConditionalAccess.csv")
    )
    
    Update-GuiStatus "Starting Conditional Access collection..." ([System.Drawing.Color]::Orange)
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        $policies = @()
        $suspiciousPolicies = @()
        
        foreach ($policy in $caPolicies) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            
            if ($policy.ModifiedDateTime -ge (Get-Date).AddDays(-7)) {
                $suspiciousReasons += "Recently modified"
            }
            
            if ($policy.State -eq "disabled") {
                $suspiciousReasons += "Policy is disabled"
                $isSuspicious = $true
            }
            
            if ($policy.Conditions.Users.ExcludeRoles -contains "Company Administrator" -or 
                $policy.Conditions.Users.ExcludeRoles -contains "Global Administrator") {
                $suspiciousReasons += "Excludes admin roles"
                $isSuspicious = $true
            }
            
            $policyEntry = [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                State = $policy.State
                CreatedDateTime = $policy.CreatedDateTime
                ModifiedDateTime = $policy.ModifiedDateTime
                Conditions = ($policy.Conditions | ConvertTo-Json -Compress -Depth 10)
                GrantControls = ($policy.GrantControls | ConvertTo-Json -Compress -Depth 10)
                SessionControls = ($policy.SessionControls | ConvertTo-Json -Compress -Depth 10)
                IsSuspicious = $isSuspicious
                SuspiciousReasons = ($suspiciousReasons -join "; ")
            }
            
            $policies += $policyEntry
            if ($isSuspicious) { $suspiciousPolicies += $policyEntry }
        }
        
        $policies | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        if ($suspiciousPolicies.Count -gt 0) {
            $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
            $suspiciousPolicies | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
        }
        
        Update-GuiStatus "CA policy collection complete: $($policies.Count) policies." ([System.Drawing.Color]::Green)
        return $policies
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        return $null
    }
}


#region ETR ANALYSIS AND MESSAGE TRACE

#══════════════════════════════════════════════════════════════
# EXCHANGE MESSAGE TRACE COLLECTION
#══════════════════════════════════════════════════════════════

function Get-MessageTraceExchangeOnline {
    <#
    .SYNOPSIS
        Collects message trace data from Exchange Online in ETR format.
    
    .DESCRIPTION
        Retrieves message trace data using Get-MessageTraceV2 and converts
        to ETR (Exchange Trace Report) compatible format for analysis.
        
        LIMITATIONS:
        • Maximum 10 days of data (Exchange Online restriction)
        • Date range automatically capped if exceeds limit
        • Subject to Exchange throttling policies
        
        OUTPUT FORMAT:
        Creates ETR-compatible CSV with columns:
        • message_trace_id, sender_address, recipient_address
        • subject, status, to_ip, from_ip, message_size
        • received, message_direction, message_id, event_type
        
        This format enables spam analysis via Analyze-ETRData function.
    
    .PARAMETER DaysBack
        Days to look back (1-10, will be capped at 10)
        Default: Min($ConfigData.DateRange, 10)
    
    .PARAMETER OutputPath
        Output file path (ETR-compatible CSV)
        Default: WorkDir\MessageTraceResult.csv
    
    .PARAMETER MaxMessages
        Maximum messages to retrieve (throttle protection)
        Default: 5000
    
    .OUTPUTS
        Array of message trace objects in ETR format
    
    .EXAMPLE
        Get-MessageTraceExchangeOnline -DaysBack 7 -MaxMessages 10000
    
    .NOTES
        - Requires Exchange Administrator role
        - Uses Get-MessageTraceV2 (modern cmdlet)
        - Automatic EXO connection if needed
        - Compatible with Analyze-ETRData
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$DaysBack = [Math]::Min($ConfigData.DateRange, 10),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MessageTraceResult.csv"),
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 50000)]
        [int]$MaxMessages = 5000
    )
    
    Update-GuiStatus "Starting Exchange Online message trace collection..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    Write-Log "MESSAGE TRACE COLLECTION (ETR FORMAT)" -Level "Info"
    Write-Log "Date Range: $DaysBack days (Exchange limit: 10 days)" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Ensure Exchange Online connection
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            Update-GuiStatus "Exchange Online connection failed - skipping message trace" ([System.Drawing.Color]::Red)
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online connection required for message trace collection.`n`n" +
                "Please ensure you have Exchange Administrator permissions.",
                "Connection Required", "OK", "Warning"
            )
            return @()
        }
        
        # Calculate date range (conservative approach)
        $actualDaysBack = [Math]::Min($DaysBack, 7)
        $startDate = (Get-Date).AddDays(-$actualDaysBack)
        $endDate = Get-Date
        
        if ($DaysBack -gt 7) {
            Update-GuiStatus "Date range adjusted to 7 days (Exchange Online best practice)" ([System.Drawing.Color]::Orange)
            Write-Log "Date range adjusted from $DaysBack to 7 days for optimal performance" -Level "Warning"
        }
        
        Write-Log "Message trace range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))" -Level "Info"
        
        # Call Get-MessageTraceV2
        Update-GuiStatus "Calling Get-MessageTraceV2..." ([System.Drawing.Color]::Orange)
        Write-Log "Executing: Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $MaxMessages" -Level "Info"
        
        $allMessages = Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $MaxMessages -ErrorAction Stop
        
        if (-not $allMessages) {
            $allMessages = @()
        }
        
        Write-Log "Get-MessageTraceV2 returned $($allMessages.Count) messages" -Level "Info"
        
        if ($allMessages.Count -eq 0) {
            Update-GuiStatus "No messages found in date range" ([System.Drawing.Color]::Orange)
            Write-Log "No messages found for the specified date range" -Level "Warning"
            return @()
        }
        
        # Convert to ETR format
        Update-GuiStatus "Converting $($allMessages.Count) messages to ETR format..." ([System.Drawing.Color]::Orange)
        Write-Log "Converting message trace results to ETR-compatible format" -Level "Info"
        
        $etrMessages = @()
        $convertedCount = 0
        
        foreach ($msg in $allMessages) {
            $convertedCount++
            
            if ($convertedCount % 500 -eq 0) {
                $percentage = [math]::Round(($convertedCount / $allMessages.Count) * 100, 1)
                Update-GuiStatus "Converting to ETR format: $convertedCount/$($allMessages.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            $etrMessage = [PSCustomObject]@{
                message_trace_id = if ($msg.MessageTraceId) { $msg.MessageTraceId } else { "" }
                sender_address = if ($msg.SenderAddress) { $msg.SenderAddress } else { "" }
                recipient_address = if ($msg.RecipientAddress) { $msg.RecipientAddress } else { "" }
                subject = if ($msg.Subject) { $msg.Subject } else { "" }
                status = if ($msg.Status) { $msg.Status } else { "" }
                to_ip = if ($msg.ToIP) { $msg.ToIP } else { "" }
                from_ip = if ($msg.FromIP) { $msg.FromIP } else { "" }
                message_size = if ($msg.Size) { $msg.Size } else { 0 }
                received = if ($msg.Received) { $msg.Received } else { "" }
                message_direction = "Unknown"  # V2 doesn't provide this
                message_id = if ($msg.MessageId) { $msg.MessageId } else { "" }
                event_type = "MessageTraceV2"
                timestamp = if ($msg.Received) { $msg.Received } else { "" }
                date = if ($msg.Received) { $msg.Received } else { "" }
            }
            $etrMessages += $etrMessage
        }
        
        # Export to CSV
        Update-GuiStatus "Exporting ETR-formatted data..." ([System.Drawing.Color]::Orange)
        $etrMessages | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        Update-GuiStatus "Message trace complete! $($allMessages.Count) messages exported in ETR format." ([System.Drawing.Color]::Green)
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        Write-Log "MESSAGE TRACE COMPLETED" -Level "Info"
        Write-Log "Messages processed: $($allMessages.Count)" -Level "Info"
        Write-Log "Output: $OutputPath" -Level "Info"
        Write-Log "Format: ETR-compatible (ready for Analyze-ETRData)" -Level "Info"
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        
        return $etrMessages
        
    }
    catch {
        $errorMsg = "Message trace error: $($_.Exception.Message)"
        Update-GuiStatus $errorMsg ([System.Drawing.Color]::Red)
        Write-Log $errorMsg -Level "Error"
        
        # Update global state on error
        if ($Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState.IsConnected = $false
            $Global:ExchangeOnlineState.LastChecked = Get-Date
        }
        
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# ETR FILE DETECTION AND ANALYSIS
#══════════════════════════════════════════════════════════════

function Find-ETRFiles {
    <#
    .SYNOPSIS
        Automatically detects Exchange Trace Report files in working directory.
    
    .DESCRIPTION
        Scans the working directory for files matching common ETR naming patterns.
        Returns sorted list of files (newest first) for analysis.
        
        SUPPORTED PATTERNS:
        • ETR_*.csv
        • MessageTrace_*.csv
        • ExchangeTrace_*.csv
        • MT_*.csv
        • *MessageTrace*.csv
        • MessageTraceResult.csv (default output name)
    
    .PARAMETER WorkingDirectory
        Directory to scan for ETR files
        Default: $ConfigData.WorkDir
    
    .OUTPUTS
        Array of FileInfo objects for detected ETR files
    
    .EXAMPLE
        $etrFiles = Find-ETRFiles
        if ($etrFiles.Count -gt 0) {
            Write-Host "Found $($etrFiles.Count) ETR files"
        }
    
    .NOTES
        - Returns files sorted by creation time (newest first)
        - Removes duplicates if same file matched multiple patterns
        - Logs all detected files
    #>
    
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory = $ConfigData.WorkDir
    )
    
    Write-Log "Searching for ETR files in: $WorkingDirectory" -Level "Info"
    
    $foundFiles = @()
    
    # Search for each pattern
    foreach ($pattern in $ConfigData.ETRAnalysis.FilePatterns) {
        try {
            $files = Get-ChildItem -Path $WorkingDirectory -Filter $pattern -ErrorAction SilentlyContinue
            if ($files) {
                $foundFiles += $files
                Write-Log "Pattern '$pattern' matched $($files.Count) file(s)" -Level "Info"
            }
        }
        catch {
            Write-Log "Error scanning for pattern '$pattern': $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Remove duplicates and sort
    $uniqueFiles = $foundFiles | Sort-Object FullName -Unique | Sort-Object CreationTime -Descending
    
    if ($uniqueFiles.Count -gt 0) {
        Write-Log "Found $($uniqueFiles.Count) unique ETR file(s):" -Level "Info"
        foreach ($file in $uniqueFiles) {
            Write-Log "  • $($file.Name) - $(Get-Date $file.CreationTime -Format 'yyyy-MM-dd HH:mm:ss') - $([math]::Round($file.Length/1MB, 2)) MB" -Level "Info"
        }
    }
    else {
        Write-Log "No ETR files found matching common patterns" -Level "Warning"
    }
    
    return $uniqueFiles
}

function Get-ETRColumnMapping {
    <#
    .SYNOPSIS
        Maps ETR file column names to expected field names.
    
    .DESCRIPTION
        Analyzes CSV headers to identify which columns contain message trace data.
        Handles various column naming conventions from different export sources.
        
        MAPPED FIELDS:
        • MessageId - Message trace ID
        • SenderAddress - From address
        • RecipientAddress - To address
        • Subject - Message subject
        • Status - Delivery status
        • ToIP / FromIP - Network information
        • MessageSize - Size in bytes
        • Received - Timestamp
        • Direction - Message flow direction
        • EventType - Event classification
    
    .PARAMETER Headers
        Array of column header names from CSV
    
    .OUTPUTS
        Hashtable mapping standard field names to actual column names
    
    .EXAMPLE
        $csv = Import-Csv "MessageTrace.csv"
        $mapping = Get-ETRColumnMapping -Headers $csv[0].PSObject.Properties.Name
        $senderId = $csv[0].($mapping.SenderAddress)
    
    .NOTES
        - Case-insensitive matching
        - Handles spaces, hyphens, underscores in column names
        - Supports multiple naming conventions
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$Headers
    )
    
    Write-Log "Analyzing ETR column headers for mapping..." -Level "Info"
    Write-Log "Available headers: $($Headers -join ', ')" -Level "Info"
    
    # Define possible column name variations
    $columnMappings = @{
        MessageId = @("message_trace_id", "messagetraceid", "message_id", "messageid", "id")
        SenderAddress = @("sender_address", "senderaddress", "sender", "from")
        RecipientAddress = @("recipient_address", "recipientaddress", "recipient", "to")
        Subject = @("subject", "message_subject", "messagesubject")
        Status = @("status", "delivery_status", "deliverystatus")
        ToIP = @("to_ip", "toip", "destination_ip", "destinationip")
        FromIP = @("from_ip", "fromip", "source_ip", "sourceip", "client_ip", "clientip")
        MessageSize = @("message_size", "messagesize", "size")
        Received = @("received", "timestamp", "date", "datetime", "received_time")
        Direction = @("direction", "message_direction", "messagedirection")
        EventType = @("event_type", "eventtype", "event")
    }
    
    $mapping = @{}
    
    # Match each field to actual column header
    foreach ($field in $columnMappings.Keys) {
        $possibleNames = $columnMappings[$field]
        
        foreach ($possibleName in $possibleNames) {
            # Normalize both for comparison (remove spaces, hyphens, underscores)
            $matchedHeader = $Headers | Where-Object { 
                $_.ToLower().Replace(" ", "").Replace("-", "").Replace("_", "") -eq $possibleName.Replace("_", "")
            }
            
            if ($matchedHeader) {
                $mapping[$field] = $matchedHeader
                Write-Log "  ✓ Mapped $field -> $matchedHeader" -Level "Info"
                break
            }
        }
        
        if (-not $mapping.ContainsKey($field)) {
            Write-Log "  ✗ No mapping found for $field" -Level "Warning"
        }
    }
    
    Write-Log "Column mapping completed: $($mapping.Count)/$($columnMappings.Count) fields mapped" -Level "Info"
    
    return $mapping
}

function Analyze-ETRData {
    <#
    .SYNOPSIS
        Analyzes ETR message trace data for spam patterns and security threats.
    
    .DESCRIPTION
        Comprehensive spam and security analysis of message trace data with:
        
        DETECTION ALGORITHMS:
        1. Excessive Volume - High message count from single sender
        2. Identical Subjects - Mass distribution of same message
        3. Spam Keywords - Common spam phrases in subjects
        4. Risky IP Correlation - Messages from IPs flagged in sign-in analysis
        5. Failed Delivery - High bounce rate patterns
        
        RISK SCORING:
        Each pattern assigned points based on severity:
        • RiskyIPMatch: 25 points (highest)
        • ExcessiveVolume: 20 points
        • SpamKeywords: 15 points
        • MassDistribution: 15 points
        • FailedDelivery: 10 points
        
        Total risk score determines threat level:
        • 0-10: Low
        • 11-25: Medium
        • 26-50: High
        • 51+: Critical
        
        OUTPUT FILES:
        • ETRSpamAnalysis.csv - All detected patterns
        • ETRSpamAnalysis_MessageRecallReport.csv - High/Critical with Message IDs
    
    .PARAMETER OutputPath
        Path for analysis results CSV
        Default: WorkDir\ETRSpamAnalysis.csv
    
    .PARAMETER RiskyIPs
        Array of IP addresses flagged in sign-in analysis for correlation
        Optional but recommended for comprehensive analysis
    
    .OUTPUTS
        Array of spam indicator objects with risk scores and details
    
    .EXAMPLE
        # Basic analysis
        $results = Analyze-ETRData
    
    .EXAMPLE
        # With risky IP correlation from sign-in analysis
        $signInData = Import-Csv "UserLocationData.csv"
        $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" } | 
                    Select-Object -ExpandProperty IP -Unique
        $results = Analyze-ETRData -RiskyIPs $riskyIPs
    
    .NOTES
        - Requires ETR file in working directory
        - Large files may take significant time
        - Uses ArrayList for performance optimization
        - Progress updates every 10,000 records
        - Memory-efficient batch processing
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ETRSpamAnalysis.csv"),
        
        [Parameter(Mandatory = $false)]
        [array]$RiskyIPs = @()
    )
    
    Update-GuiStatus "Starting ETR message trace analysis..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    Write-Log "ETR SPAM PATTERN ANALYSIS" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Force garbage collection before starting
        [System.GC]::Collect()
        
        # Find ETR files
        $etrFiles = Find-ETRFiles
        
        if ($etrFiles.Count -eq 0) {
            Update-GuiStatus "No ETR files found! Place message trace files in working directory." ([System.Drawing.Color]::Red)
            
            $message = "No Exchange Trace Report (ETR) files found!`n`n" +
                      "Expected file patterns:`n" +
                      ($ConfigData.ETRAnalysis.FilePatterns -join "`n") + "`n`n" +
                      "Please place your message trace files in:`n$($ConfigData.WorkDir)"
            
            [System.Windows.Forms.MessageBox]::Show($message, "ETR Files Not Found", "OK", "Warning")
            return $null
        }
        
        # Use most recent file
        $selectedFile = $etrFiles[0]
        $fileSize = (Get-Item $selectedFile.FullName).Length / 1MB
        
        # Warn if file is very large
        if ($fileSize -gt 100) {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "The ETR file is very large ($([math]::Round($fileSize, 1)) MB).`n`n" +
                "This may cause memory issues or take significant time.`n`n" +
                "Continue with analysis?",
                "Large File Warning", "YesNo", "Warning"
            )
            if ($result -eq "No") {
                return $null
            }
        }
        
        Update-GuiStatus "Analyzing ETR file: $($selectedFile.Name) ($([math]::Round($fileSize, 1)) MB)..." ([System.Drawing.Color]::Orange)
        Write-Log "Selected file: $($selectedFile.FullName)" -Level "Info"
        Write-Log "File size: $([math]::Round($fileSize, 1)) MB" -Level "Info"
        
        # Load ETR data
        $etrData = Import-Csv -Path $selectedFile.FullName -ErrorAction Stop
        
        if (-not $etrData -or $etrData.Count -eq 0) {
            throw "ETR file appears to be empty or invalid"
        }
        
        Write-Log "Loaded $($etrData.Count) message trace records" -Level "Info"
        Update-GuiStatus "Loaded $($etrData.Count) records. Mapping columns..." ([System.Drawing.Color]::Orange)
        
        # Map column headers
        $headers = $etrData[0].PSObject.Properties.Name
        $columnMapping = Get-ETRColumnMapping -Headers $headers
        
        # Validate essential columns
        $requiredFields = @("SenderAddress", "Subject")
        $missingFields = @()
        foreach ($field in $requiredFields) {
            if (-not $columnMapping.ContainsKey($field)) {
                $missingFields += $field
            }
        }
        
        if ($missingFields.Count -gt 0) {
            throw "ETR file missing essential columns: $($missingFields -join ', '). Available: $($headers -join ', ')"
        }
        
        Update-GuiStatus "Processing message trace data for spam patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Beginning spam pattern analysis..." -Level "Info"
        
        # Process messages
        $processedMessages = [System.Collections.ArrayList]::new($etrData.Count)
        $processingCount = 0
        
        foreach ($record in $etrData) {
            $processingCount++
            if ($processingCount % 10000 -eq 0) {
                $percentage = [math]::Round(($processingCount / $etrData.Count) * 100, 1)
                Update-GuiStatus "Processing ETR records: $processingCount of $($etrData.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            # Extract fields using mapping
            $processedMessage = [PSCustomObject]@{
                MessageId = if ($columnMapping.MessageId) { $record.($columnMapping.MessageId) } else { "" }
                SenderAddress = if ($columnMapping.SenderAddress) { $record.($columnMapping.SenderAddress) } else { "" }
                RecipientAddress = if ($columnMapping.RecipientAddress) { $record.($columnMapping.RecipientAddress) } else { "" }
                Subject = if ($columnMapping.Subject) { $record.($columnMapping.Subject) } else { "" }
                Status = if ($columnMapping.Status) { $record.($columnMapping.Status) } else { "" }
                ToIP = if ($columnMapping.ToIP) { $record.($columnMapping.ToIP) } else { "" }
                FromIP = if ($columnMapping.FromIP) { $record.($columnMapping.FromIP) } else { "" }
                MessageSize = if ($columnMapping.MessageSize) { $record.($columnMapping.MessageSize) } else { "" }
                Received = if ($columnMapping.Received) { $record.($columnMapping.Received) } else { "" }
                Direction = if ($columnMapping.Direction) { $record.($columnMapping.Direction) } else { "" }
                EventType = if ($columnMapping.EventType) { $record.($columnMapping.EventType) } else { "" }
            }
            
            [void]$processedMessages.Add($processedMessage)
        }
        
        Write-Log "Processed $($processedMessages.Count) messages" -Level "Info"
        Update-GuiStatus "Analyzing patterns in $($processedMessages.Count) messages..." ([System.Drawing.Color]::Orange)
        
        # Focus on outbound messages
        $outboundMessages = $processedMessages.ToArray() | Where-Object { 
            $_.Direction -like "*outbound*" -or $_.Direction -like "*send*" -or [string]::IsNullOrEmpty($_.Direction)
        }
        
        Write-Log "Analyzing $($outboundMessages.Count) outbound messages for spam patterns" -Level "Info"
        
        if ($outboundMessages.Count -eq 0) {
            Update-GuiStatus "No outbound messages found in ETR data" ([System.Drawing.Color]::Orange)
            return @()
        }
        
        # Initialize spam indicators with ArrayList
        $spamIndicators = [System.Collections.ArrayList]::new()
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 1: EXCESSIVE VOLUME
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing message volume patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Running volume analysis..." -Level "Info"
        
        $senderCounts = @{}
        foreach ($msg in $outboundMessages) {
            $sender = $msg.SenderAddress
            if (-not [string]::IsNullOrEmpty($sender)) {
                if ($senderCounts.ContainsKey($sender)) {
                    $senderCounts[$sender]++
                } else {
                    $senderCounts[$sender] = 1
                }
            }
        }
        
        $volumeFindings = 0
        foreach ($sender in $senderCounts.Keys) {
            $messageCount = $senderCounts[$sender]
            if ($messageCount -gt $ConfigData.ETRAnalysis.MaxMessagesPerSender) {
                $senderMessages = $outboundMessages | Where-Object { $_.SenderAddress -eq $sender }
                
                $indicator = [PSCustomObject]@{
                    SenderAddress = $sender
                    RiskType = "ExcessiveVolume"
                    RiskLevel = "High"
                    MessageCount = $messageCount
                    Description = "Excessive outbound messages: $messageCount messages"
                    MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                    Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join "; "
                    Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                    RiskScore = $ConfigData.ETRAnalysis.RiskWeights.ExcessiveVolume
                }
                [void]$spamIndicators.Add($indicator)
                $volumeFindings++
            }
        }
        Write-Log "Volume analysis: $volumeFindings patterns found" -Level "Info"
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 2: IDENTICAL SUBJECTS
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing identical subject patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Running subject analysis..." -Level "Info"
        
        $subjectGroups = @{}
        foreach ($msg in $outboundMessages) {
            if (-not [string]::IsNullOrEmpty($msg.Subject) -and $msg.Subject.Length -ge $ConfigData.ETRAnalysis.MinSubjectLength) {
                $key = "$($msg.SenderAddress)|$($msg.Subject.ToLower().Trim())"
                if ($subjectGroups.ContainsKey($key)) {
                    $subjectGroups[$key] += @($msg)
                } else {
                    $subjectGroups[$key] = @($msg)
                }
            }
        }
        
        $subjectFindings = 0
        foreach ($key in $subjectGroups.Keys) {
            $messages = $subjectGroups[$key]
            if ($messages.Count -ge $ConfigData.ETRAnalysis.MaxSameSubjectMessages) {
                $indicator = [PSCustomObject]@{
                    SenderAddress = $messages[0].SenderAddress
                    RiskType = "IdenticalSubjects"
                    RiskLevel = "Critical"
                    MessageCount = $messages.Count
                    Description = "Identical subject spam: $($messages.Count) messages"
                    MessageIds = ($messages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                    Recipients = ($messages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                    Subjects = $messages[0].Subject
                    RiskScore = $ConfigData.ETRAnalysis.RiskWeights.MassDistribution
                }
                [void]$spamIndicators.Add($indicator)
                $subjectFindings++
            }
        }
        Write-Log "Subject analysis: $subjectFindings patterns found" -Level "Info"
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 3: SPAM KEYWORDS
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing spam keywords..." ([System.Drawing.Color]::Orange)
        Write-Log "Running keyword analysis..." -Level "Info"
        
        $keywordFindings = 0
        foreach ($keyword in $ConfigData.ETRAnalysis.SpamKeywords) {
            $keywordMessages = $outboundMessages | Where-Object { 
                $_.Subject -like "*$keyword*" -and -not [string]::IsNullOrEmpty($_.Subject)
            }
            
            if ($keywordMessages.Count -gt 5) {
                $senderGroups = @{}
                foreach ($msg in $keywordMessages) {
                    $sender = $msg.SenderAddress
                    if (-not [string]::IsNullOrEmpty($sender)) {
                        if ($senderGroups.ContainsKey($sender)) {
                            $senderGroups[$sender] += @($msg)
                        } else {
                            $senderGroups[$sender] = @($msg)
                        }
                    }
                }
                
                foreach ($sender in $senderGroups.Keys) {
                    $senderMessages = $senderGroups[$sender]
                    if ($senderMessages.Count -gt 3) {
                        $indicator = [PSCustomObject]@{
                            SenderAddress = $sender
                            RiskType = "SpamKeywords"
                            RiskLevel = "Medium"
                            MessageCount = $senderMessages.Count
                            Description = "Spam keyword '$keyword' in $($senderMessages.Count) messages"
                            MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 5) -join "; "
                            Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join "; "
                            Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                            RiskScore = $ConfigData.ETRAnalysis.RiskWeights.SpamKeywords
                            DetectedKeyword = $keyword
                        }
                        [void]$spamIndicators.Add($indicator)
                        $keywordFindings++
                    }
                }
            }
        }
        Write-Log "Keyword analysis: $keywordFindings patterns found" -Level "Info"
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 4: RISKY IP CORRELATION
        #──────────────────────────────────────────────────────
        $ipFindings = 0
        if ($RiskyIPs.Count -gt 0) {
            Update-GuiStatus "Correlating with risky IPs from sign-in analysis..." ([System.Drawing.Color]::Orange)
            Write-Log "Running IP correlation with $($RiskyIPs.Count) flagged IPs" -Level "Info"
            
            foreach ($riskyIP in $RiskyIPs) {
                $riskyIPMessages = $outboundMessages | Where-Object { $_.FromIP -eq $riskyIP -or $_.ToIP -eq $riskyIP }
                
                if ($riskyIPMessages.Count -gt 0) {
                    $indicator = [PSCustomObject]@{
                        SenderAddress = ($riskyIPMessages.SenderAddress | Select-Object -Unique) -join "; "
                        RiskType = "RiskyIPCorrelation"
                        RiskLevel = "Critical"
                        MessageCount = $riskyIPMessages.Count
                        Description = "Messages from/to risky IP $riskyIP"
                        MessageIds = ($riskyIPMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                        Recipients = ($riskyIPMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                        Subjects = ($riskyIPMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                        RiskScore = $ConfigData.ETRAnalysis.RiskWeights.RiskyIPMatch
                        RiskyIP = $riskyIP
                    }
                    [void]$spamIndicators.Add($indicator)
                    $ipFindings++
                }
            }
            Write-Log "IP correlation: $ipFindings patterns found" -Level "Info"
        }
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 5: FAILED DELIVERY
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing failed delivery patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Running failed delivery analysis..." -Level "Info"
        
        $failedMessages = $processedMessages.ToArray() | Where-Object { 
            $_.Status -like "*failed*" -or $_.Status -like "*bounce*" -or 
            $_.Status -like "*reject*" -or $_.Status -like "*blocked*"
        }
        
        $failureFindings = 0
        if ($failedMessages.Count -gt 0) {
            $failedGroups = @{}
            foreach ($msg in $failedMessages) {
                $sender = $msg.SenderAddress
                if (-not [string]::IsNullOrEmpty($sender)) {
                    if ($failedGroups.ContainsKey($sender)) {
                        $failedGroups[$sender] += @($msg)
                    } else {
                        $failedGroups[$sender] = @($msg)
                    }
                }
            }
            
            foreach ($sender in $failedGroups.Keys) {
                $senderFailures = $failedGroups[$sender]
                if ($senderFailures.Count -gt 10) {
                    $indicator = [PSCustomObject]@{
                        SenderAddress = $sender
                        RiskType = "ExcessiveFailures"
                        RiskLevel = "Medium"
                        MessageCount = $senderFailures.Count
                        Description = "Excessive failed deliveries: $($senderFailures.Count) failed"
                        MessageIds = ($senderFailures.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                        Recipients = ($senderFailures.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                        Subjects = ($senderFailures.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                        RiskScore = $ConfigData.ETRAnalysis.RiskWeights.FailedDelivery
                    }
                    [void]$spamIndicators.Add($indicator)
                    $failureFindings++
                }
            }
        }
        Write-Log "Failed delivery analysis: $failureFindings patterns found" -Level "Info"
        
        #══════════════════════════════════════════════════════
        # EXPORT RESULTS
        #══════════════════════════════════════════════════════
        Update-GuiStatus "Exporting ETR analysis results..." ([System.Drawing.Color]::Orange)
        
        $spamIndicatorsArray = @($spamIndicators.ToArray())
        
        # Sort by risk
        $riskOrder = @{"Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3}
        $spamIndicatorsArray = $spamIndicatorsArray | Sort-Object @{Expression={$riskOrder[$_.RiskLevel]}}, @{Expression="RiskScore"; Descending=$true}
        
        if ($spamIndicatorsArray.Count -gt 0) {
            $spamIndicatorsArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create message recall report
            $recallReportPath = $OutputPath -replace '.csv$', '_MessageRecallReport.csv'
            $recallReport = $spamIndicatorsArray | Where-Object { 
                $_.RiskLevel -in @("Critical", "High") -and -not [string]::IsNullOrEmpty($_.MessageIds)
            }
            
            if ($recallReport.Count -gt 0) {
                $recallReport | Export-Csv -Path $recallReportPath -NoTypeInformation -Force
                Write-Log "Created message recall report: $recallReportPath" -Level "Warning"
            }
            
            # Summary
            $criticalCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "High" }).Count
            $mediumCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            
            Update-GuiStatus "ETR analysis complete! $criticalCount critical, $highCount high, $mediumCount medium risk patterns." ([System.Drawing.Color]::Green)
            
            Write-Log "═══════════════════════════════════════════════════" -Level "Info"
            Write-Log "ETR ANALYSIS COMPLETED" -Level "Info"
            Write-Log "Total patterns detected: $($spamIndicatorsArray.Count)" -Level "Info"
            Write-Log "  Critical: $criticalCount" -Level "Info"
            Write-Log "  High: $highCount" -Level "Info"
            Write-Log "  Medium: $mediumCount" -Level "Info"
            Write-Log "Analysis breakdown:" -Level "Info"
            Write-Log "  Volume patterns: $volumeFindings" -Level "Info"
            Write-Log "  Subject patterns: $subjectFindings" -Level "Info"
            Write-Log "  Keyword patterns: $keywordFindings" -Level "Info"
            Write-Log "  IP correlations: $ipFindings" -Level "Info"
            Write-Log "  Failure patterns: $failureFindings" -Level "Info"
            Write-Log "Output: $OutputPath" -Level "Info"
            Write-Log "═══════════════════════════════════════════════════" -Level "Info"
            
            return $spamIndicatorsArray
        }
        else {
            Update-GuiStatus "No suspicious patterns detected in ETR analysis" ([System.Drawing.Color]::Green)
            Write-Log "No suspicious patterns detected" -Level "Info"
            return @()
        }
        
    }
    catch {
        Update-GuiStatus "Error in ETR analysis: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "ETR analysis error: $($_.Exception.Message)" -Level "Error"
        [System.GC]::Collect()
        return $null
    }
}

#endregion

#################################################################
#
#  SECTION 4: ANALYSIS FUNCTIONS
#
#################################################################

#region ANALYSIS FUNCTIONS

function Invoke-CompromiseDetection {
    <#
    .SYNOPSIS
        Performs comprehensive security analysis across all collected data sources.
    
    .DESCRIPTION
        Main analysis engine that aggregates data from all collection functions,
        calculates risk scores, identifies compromised accounts, and generates reports.
    
    .PARAMETER ReportPath
        Full path where the HTML report will be saved.
    
    .RETURNS
        Array of PSCustomObjects containing risk assessment results
    
    .NOTES
        Risk Scoring: Critical (50+), High (30-49), Medium (15-29), Low (0-14)
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ReportPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "SecurityReport.html")
    )
    
    Update-GuiStatus "Starting compromise detection analysis..." ([System.Drawing.Color]::Orange)
    
    # Helper functions for safe data conversion
    function ConvertTo-SafeString {
        param($Value)
        if ($Value -eq $null -or $Value -is [System.DBNull] -or ($Value -is [double] -and [double]::IsNaN($Value))) {
            return ""
        }
        return $Value.ToString()
    }
    
    function ConvertTo-SafeBoolean {
        param($Value)
        if ($Value -eq $null -or $Value -is [System.DBNull] -or ($Value -is [double] -and [double]::IsNaN($Value))) {
            return $false
        }
        if ($Value -is [string]) {
            return $Value -eq "True"
        }
        return [bool]$Value
    }
    
    # Define data sources
    $dataSources = @{
        SignInData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
            Data = $null
            Available = $false
        }
        AdminAuditData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv"
            Data = $null
            Available = $false
        }
        InboxRulesData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "InboxRules.csv"
            Data = $null
            Available = $false
        }
        DelegationData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "MailboxDelegation.csv"
            Data = $null
            Available = $false
        }
        AppRegData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "AppRegistrations.csv"
            Data = $null
            Available = $false
        }
        ConditionalAccessData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "ConditionalAccess.csv"
            Data = $null
            Available = $false
        }
        ETRData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "ETRSpamAnalysis.csv"
            Data = $null
            Available = $false
        }
		MFAStatusData = @{
			Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "MFAStatus.csv"
			Data = $null
			Available = $false
		}
		FailedLoginPatterns = @{
			Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "FailedLoginAnalysis.csv"
			Data = $null
			Available = $false
		}
		PasswordChangeData = @{
			Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "PasswordChangeAnalysis.csv"
			Data = $null
			Available = $false
		}
    }
    
    Update-GuiStatus "Checking for available data sources..." ([System.Drawing.Color]::Orange)
    
    # Load and validate data sources
    $availableDataSources = @()
    
    foreach ($source in $dataSources.GetEnumerator()) {
        $sourceName = $source.Key
        $sourceInfo = $source.Value
		
        foreach ($sourceName in @('MFAStatusData', 'FailedLoginPatterns', 'PasswordChangeData')) {
			$sourceInfo = $dataSources[$sourceName]
			if (Test-Path $sourceInfo.Path) {
				try {
					$rawData = Import-Csv -Path $sourceInfo.Path
					if ($rawData) {
						$sourceInfo.Data = $rawData
						$sourceInfo.Available = $true
						$availableDataSources += $sourceName
						Write-Log "Loaded ${sourceName}: $($rawData.Count) records" -Level "Info"
					}
				}
				catch {
					Write-Log "Error loading ${sourceName}: $($_.Exception.Message)" -Level "Warning"
			}
		}
		
	}
        if (Test-Path -Path $sourceInfo.Path) {
            try {
                $rawData = Import-Csv -Path $sourceInfo.Path -ErrorAction Stop
                
                if ($rawData -and $rawData.Count -gt 0) {
                    # Clean and normalize data based on source type
                    $cleanData = switch ($sourceName) {
                        "SignInData" {
                            $rawData | ForEach-Object {
                                [PSCustomObject]@{
                                    UserId = ConvertTo-SafeString $_.UserId
                                    UserDisplayName = ConvertTo-SafeString $_.UserDisplayName
                                    CreationTime = ConvertTo-SafeString $_.CreationTime
                                    UserAgent = ConvertTo-SafeString $_.UserAgent
                                    IP = ConvertTo-SafeString $_.IP
                                    ISP = ConvertTo-SafeString $_.ISP
                                    City = ConvertTo-SafeString $_.City
                                    RegionName = ConvertTo-SafeString $_.RegionName
                                    Country = ConvertTo-SafeString $_.Country
                                    IsUnusualLocation = ConvertTo-SafeBoolean $_.IsUnusualLocation
                                    Status = ConvertTo-SafeString $_.Status
                                    FailureReason = ConvertTo-SafeString $_.FailureReason
                                    ConditionalAccessStatus = ConvertTo-SafeString $_.ConditionalAccessStatus
                                    RiskLevel = ConvertTo-SafeString $_.RiskLevel
                                    DeviceOS = ConvertTo-SafeString $_.DeviceOS
                                    DeviceBrowser = ConvertTo-SafeString $_.DeviceBrowser
                                    IsInteractive = ConvertTo-SafeBoolean $_.IsInteractive
                                    AppDisplayName = ConvertTo-SafeString $_.AppDisplayName
                                }
                            }
                        }
                        
                        "AdminAuditData" {
                            $rawData | ForEach-Object {
                                [PSCustomObject]@{
                                    Timestamp = ConvertTo-SafeString $_.Timestamp
                                    UserId = ConvertTo-SafeString $_.UserId
                                    UserDisplayName = ConvertTo-SafeString $_.UserDisplayName
                                    Activity = ConvertTo-SafeString $_.Activity
                                    Result = ConvertTo-SafeString $_.Result
                                    ResultReason = ConvertTo-SafeString $_.ResultReason
                                    Category = ConvertTo-SafeString $_.Category
                                    CorrelationId = ConvertTo-SafeString $_.CorrelationId
                                    LoggedByService = ConvertTo-SafeString $_.LoggedByService
                                    RiskLevel = ConvertTo-SafeString $_.RiskLevel
                                    TargetResources = ConvertTo-SafeString $_.TargetResources
                                    AdditionalDetails = ConvertTo-SafeString $_.AdditionalDetails
                                }
                            }
                        }
                        
                        "ConditionalAccessData" {
                            $rawData | ForEach-Object {
                                [PSCustomObject]@{
                                    DisplayName = ConvertTo-SafeString $_.DisplayName
                                    State = ConvertTo-SafeString $_.State
                                    CreatedDateTime = ConvertTo-SafeString $_.CreatedDateTime
                                    ModifiedDateTime = ConvertTo-SafeString $_.ModifiedDateTime
                                    Conditions = ConvertTo-SafeString $_.Conditions
                                    GrantControls = ConvertTo-SafeString $_.GrantControls
                                    SessionControls = ConvertTo-SafeString $_.SessionControls
                                    IsSuspicious = ConvertTo-SafeBoolean $_.IsSuspicious
                                    SuspiciousReasons = ConvertTo-SafeString $_.SuspiciousReasons
                                }
                            }
                        }
                        
                        default {
                            # Generic cleaning for other sources
                            $rawData | ForEach-Object {
                                $cleanRow = [PSCustomObject]@{}
                                foreach ($property in $_.PSObject.Properties) {
                                    $cleanRow | Add-Member -NotePropertyName $property.Name -NotePropertyValue (ConvertTo-SafeString $property.Value)
                                }
                                $cleanRow
                            }
                        }
                    }
                    
                    $sourceInfo.Data = $cleanData
                    $sourceInfo.Available = $true
                    $availableDataSources += $sourceName
                    Write-Log "Loaded ${sourceName}: $($cleanData.Count) records" -Level "Info"
                }
            }
            catch {
                Write-Log "Error loading ${sourceName}: $($_.Exception.Message)" -Level "Warning"
            }
        }
    }
    
    # Validate we have data
    if ($availableDataSources.Count -eq 0) {
        Update-GuiStatus "No data sources found! Please run data collection first." ([System.Drawing.Color]::Red)
        [System.Windows.Forms.MessageBox]::Show(
            "No data files found for analysis!`n`nPlease run the data collection functions first.",
            "No Data Available",
            "OK",
            "Warning"
        )
        return $null
    }
    
    Update-GuiStatus "Found $($availableDataSources.Count) data sources" ([System.Drawing.Color]::Green)
    
    # Initialize user tracking
    $users = @{}
    $systemIssues = @()
    
    # Process sign-in data
    if ($dataSources.SignInData.Available) {
        Update-GuiStatus "Analyzing sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Generate unique logins report
        $uniqueLogins = @()
        $userLocationGroups = $dataSources.SignInData.Data | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            $uniqueUserLocations = $userSignIns | 
                Select-Object UserId, UserDisplayName, IP, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) }
            
            foreach ($location in $uniqueUserLocations) {
                $signInCount = ($userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and $_.City -eq $location.City -and $_.Country -eq $location.Country 
                }).Count
                
                $locationSignIns = $userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and $_.City -eq $location.City -and $_.Country -eq $location.Country 
                } | Sort-Object CreationTime
                
                $firstSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[0].CreationTime } else { "" }
                $lastSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[-1].CreationTime } else { "" }
                
                $isUnusualLocation = $false
                if ($location.Country -and $ConfigData.ExpectedCountries -notcontains $location.Country) {
                    $isUnusualLocation = $true
                }
                
                $uniqueLogin = [PSCustomObject]@{
                    UserId = $location.UserId
                    UserDisplayName = $location.UserDisplayName
                    IP = $location.IP
                    City = $location.City
                    RegionName = $location.RegionName
                    Country = $location.Country
                    ISP = $location.ISP
                    IsUnusualLocation = $isUnusualLocation
                    SignInCount = $signInCount
                    FirstSeen = $firstSeen
                    LastSeen = $lastSeen
                }
                
                $uniqueLogins += $uniqueLogin
            }
        }
        
        # Export unique logins
        if ($uniqueLogins.Count -gt 0) {
            $uniqueLoginsPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"
            $uniqueLogins | Export-Csv -Path $uniqueLoginsPath -NoTypeInformation -Force
            
            $unusualUniqueLogins = $uniqueLogins | Where-Object { $_.IsUnusualLocation -eq $true }
            if ($unusualUniqueLogins.Count -gt 0) {
                $unusualPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv"
                $unusualUniqueLogins | Export-Csv -Path $unusualPath -NoTypeInformation -Force
            }
        }
        
        # Process sign-ins for risk analysis
        foreach ($signIn in $dataSources.SignInData.Data) {
            $userId = $signIn.UserId
            if ([string]::IsNullOrEmpty($userId)) { continue }
            
            if (-not $users.ContainsKey($userId)) {
                $users[$userId] = @{
                    UserDisplayName = $signIn.UserDisplayName
                    UnusualSignIns = @()
                    FailedSignIns = @()
                    HighRiskOps = @()
                    SuspiciousRules = @()
                    SuspiciousDelegations = @()
                    HighRiskAppRegs = @()
                    ETRSpamActivity = @()
					HighRiskISPSignIns = @()
                    RiskScore = 0
                }
            }
            
            $isSuccessfulSignIn = ($signIn.Status -eq "0" -or [string]::IsNullOrEmpty($signIn.Status))
            $isFailedSignIn = (-not [string]::IsNullOrEmpty($signIn.Status) -and $signIn.Status -ne "0")
            $isUnusual = $signIn.IsUnusualLocation -eq $true
            
            # Only flag unusual locations for successful sign-ins
            if ($isUnusual -and $isSuccessfulSignIn) {
                $users[$userId].UnusualSignIns += $signIn
                $users[$userId].RiskScore += 5
            }
            
            if ($isFailedSignIn) {
                $users[$userId].FailedSignIns += $signIn
            }
            
            if ($signIn.RiskLevel -and $signIn.RiskLevel -eq "high" -and $isSuccessfulSignIn) {
                $users[$userId].RiskScore += 15
            }
			
			# Check for high-risk ISP sign-ins
			$isHighRiskISP = ConvertTo-SafeBoolean $signIn.IsHighRiskISP
			if ($isHighRiskISP -and $isSuccessfulSignIn) {
				$users[$userId].HighRiskISPSignIns += $signIn
				$users[$userId].RiskScore += 25  # Significant risk score for high-risk ISPs
			}
        }
    }
    
    # Process admin audit data
    if ($dataSources.AdminAuditData.Available) {
        Update-GuiStatus "Analyzing admin audit data..." ([System.Drawing.Color]::Orange)
        
        foreach ($auditLog in $dataSources.AdminAuditData.Data) {
            $userId = $auditLog.UserId
            if ([string]::IsNullOrEmpty($userId)) { continue }
            
            if (-not $users.ContainsKey($userId)) {
                $users[$userId] = @{
                    UserDisplayName = $auditLog.UserDisplayName
                    UnusualSignIns = @()
                    FailedSignIns = @()
                    HighRiskOps = @()
                    SuspiciousRules = @()
                    SuspiciousDelegations = @()
                    HighRiskAppRegs = @()
                    ETRSpamActivity = @()
					HighRiskISPSignIns = @()
                    RiskScore = 0
                }
            }
            
            if ($auditLog.RiskLevel -eq "High") {
                $users[$userId].HighRiskOps += $auditLog
                $users[$userId].RiskScore += 10
            }
        }
    }
    
    # Process inbox rules
    if ($dataSources.InboxRulesData.Available) {
        Update-GuiStatus "Analyzing inbox rules..." ([System.Drawing.Color]::Orange)
        
        foreach ($rule in $dataSources.InboxRulesData.Data) {
            $isSuspicious = ConvertTo-SafeBoolean $rule.IsSuspicious
            
            if ($isSuspicious) {
                $userId = $rule.MailboxOwnerID
                if ([string]::IsNullOrEmpty($userId)) { continue }
                
                if (-not $users.ContainsKey($userId)) {
                    $users[$userId] = @{
                        UserDisplayName = $rule.DisplayName
                        UnusualSignIns = @()
                        FailedSignIns = @()
                        HighRiskOps = @()
                        SuspiciousRules = @()
                        SuspiciousDelegations = @()
                        HighRiskAppRegs = @()
                        ETRSpamActivity = @()
						HighRiskISPSignIns = @()
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousRules += $rule
                $users[$userId].RiskScore += 15
            }
        }
    }
    
    # Process delegations
    if ($dataSources.DelegationData.Available) {
        Update-GuiStatus "Analyzing mailbox delegations..." ([System.Drawing.Color]::Orange)
        
        foreach ($delegation in $dataSources.DelegationData.Data) {
            $isSuspicious = ConvertTo-SafeBoolean $delegation.IsSuspicious
            
            if ($isSuspicious) {
                $userId = $delegation.Mailbox
                if ([string]::IsNullOrEmpty($userId)) { continue }
                
                if (-not $users.ContainsKey($userId)) {
                    $users[$userId] = @{
                        UserDisplayName = $delegation.DisplayName
                        UnusualSignIns = @()
                        FailedSignIns = @()
                        HighRiskOps = @()
                        SuspiciousRules = @()
                        SuspiciousDelegations = @()
                        HighRiskAppRegs = @()
                        ETRSpamActivity = @()
						HighRiskISPSignIns = @()
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousDelegations += $delegation
                $users[$userId].RiskScore += 8
            }
        }
    }
    
    # Process app registrations
    if ($dataSources.AppRegData.Available) {
        Update-GuiStatus "Analyzing app registrations..." ([System.Drawing.Color]::Orange)
        
        foreach ($appReg in $dataSources.AppRegData.Data) {
            if ($appReg.RiskLevel -eq "High") {
                $systemIssues += $appReg
                
                $systemUser = "SYSTEM_WIDE_APPS"
                if (-not $users.ContainsKey($systemUser)) {
                    $users[$systemUser] = @{
                        UserDisplayName = "System-Wide Application Issues"
                        UnusualSignIns = @()
                        FailedSignIns = @()
                        HighRiskOps = @()
                        SuspiciousRules = @()
                        SuspiciousDelegations = @()
                        HighRiskAppRegs = @()
                        ETRSpamActivity = @()
						HighRiskISPSignIns = @()
                        RiskScore = 0
                    }
                }
                
                $users[$systemUser].HighRiskAppRegs += $appReg
                $users[$systemUser].RiskScore += 20
            }
        }
    }
    
    # Process conditional access
    if ($dataSources.ConditionalAccessData.Available) {
        $suspiciousPolicies = $dataSources.ConditionalAccessData.Data | 
            Where-Object { (ConvertTo-SafeBoolean $_.IsSuspicious) -eq $true }
        
        if ($suspiciousPolicies.Count -gt 0) {
            $systemIssues += $suspiciousPolicies
        }
    }
    
    # Process ETR data
    if ($dataSources.ETRData.Available) {
        Update-GuiStatus "Analyzing ETR message trace data..." ([System.Drawing.Color]::Orange)
        
        foreach ($etrRecord in $dataSources.ETRData.Data) {
            $userId = ConvertTo-SafeString $etrRecord.SenderAddress
            if ([string]::IsNullOrEmpty($userId)) { continue }
            
            if (-not $users.ContainsKey($userId)) {
                $users[$userId] = @{
                    UserDisplayName = $userId
                    UnusualSignIns = @()
                    FailedSignIns = @()
                    HighRiskOps = @()
                    SuspiciousRules = @()
                    SuspiciousDelegations = @()
                    HighRiskAppRegs = @()
                    ETRSpamActivity = @()
					HighRiskISPSignIns = @()
                    RiskScore = 0
                }
            }
            
            $users[$userId].ETRSpamActivity += $etrRecord
            
            $riskScore = if ($etrRecord.RiskScore) { 
                try { [int]$etrRecord.RiskScore } catch { 0 }
            } else { 0 }
            $users[$userId].RiskScore += $riskScore
        }
    }
	
	# Process MFA status data
	if ($dataSources.MFAStatusData.Available) {
		Update-GuiStatus "Analyzing MFA status data..." ([System.Drawing.Color]::Orange)
		
		foreach ($mfaRecord in $dataSources.MFAStatusData.Data) {
			$userId = $mfaRecord.UserPrincipalName
			if ([string]::IsNullOrEmpty($userId)) { continue }
			
			if (-not $users.ContainsKey($userId)) {
				$users[$userId] = @{
					UserDisplayName = $mfaRecord.DisplayName
					UnusualSignIns = @()
					FailedSignIns = @()
					HighRiskOps = @()
					SuspiciousRules = @()
					SuspiciousDelegations = @()
					HighRiskAppRegs = @()
					ETRSpamActivity = @()
					HighRiskISPSignIns = @()
					RiskScore = 0
					MFAStatus = $null          
					FailedLoginPatterns = @()  
					PasswordChangeIssues = @() 
				}
			}
			
			# FIX: Ensure we store ONLY a single string value, force to string
			$mfaValue = $mfaRecord.HasMFA
			
			# Normalize to a single string value
			if ($mfaValue -eq "Yes" -or $mfaValue -eq "True" -or $mfaValue -eq $true) {
				$users[$userId].MFAStatus = "Yes"
			}
			elseif ($mfaValue -eq "No" -or $mfaValue -eq "False" -or $mfaValue -eq $false) {
				$users[$userId].MFAStatus = "No"
			}
			else {
				$users[$userId].MFAStatus = "Unknown"
			}
			
			# Add risk for no MFA
			if ($users[$userId].MFAStatus -eq "No") {
				$users[$userId].RiskScore += 40
			}
			
			# Extra risk if admin without MFA
			if ($mfaRecord.RiskLevel -eq "Critical") {
				$users[$userId].RiskScore += 10
			}
		}
	}
	# Process failed login patterns
	if ($dataSources.FailedLoginPatterns.Available) {
		Update-GuiStatus "Analyzing failed login patterns..." ([System.Drawing.Color]::Orange)
		
		foreach ($pattern in $dataSources.FailedLoginPatterns.Data) {
			$details = $pattern.Details
			if ([string]::IsNullOrEmpty($details)) { continue }
			
			# Extract user from Details field
			if ($details -match "User\s+([^\s]+@[^\s]+)") {
				$userId = $Matches[1]
				
				if (-not $users.ContainsKey($userId)) {
					$users[$userId] = @{
						UserDisplayName = $userId
						UnusualSignIns = @()
						FailedSignIns = @()
						HighRiskOps = @()
						SuspiciousRules = @()
						SuspiciousDelegations = @()
						HighRiskAppRegs = @()
						ETRSpamActivity = @()
						HighRiskISPSignIns = @()
						RiskScore = 0
						MFAStatus = $null          # NEW
						FailedLoginPatterns = @()  # NEW
						PasswordChangeIssues = @() # NEW
					}
				}
				
				# STORE the pattern data
				$users[$userId].FailedLoginPatterns += $pattern
				
				# Add risk based on pattern type
				$riskLevel = $pattern.RiskLevel
				$successfulBreach = $pattern.SuccessfulBreach
				
				if ($successfulBreach -eq "True" -or $successfulBreach -eq $true) {
					$users[$userId].RiskScore += 50
				}
				elseif ($riskLevel -eq "Critical") {
					$users[$userId].RiskScore += 30
				}
				elseif ($riskLevel -eq "High") {
					$users[$userId].RiskScore += 20
				}
				elseif ($riskLevel -eq "Medium") {
					$users[$userId].RiskScore += 10
				}
			}
		}
	}

	# Process password change patterns
	if ($dataSources.PasswordChangeData.Available) {
		Update-GuiStatus "Analyzing password change patterns..." ([System.Drawing.Color]::Orange)
		
		foreach ($pwChange in $dataSources.PasswordChangeData.Data) {
			$userId = $pwChange.User
			if ([string]::IsNullOrEmpty($userId)) { continue }
			
			if (-not $users.ContainsKey($userId)) {
				$users[$userId] = @{
					UserDisplayName = $userId
					UnusualSignIns = @()
					FailedSignIns = @()
					HighRiskOps = @()
					SuspiciousRules = @()
					SuspiciousDelegations = @()
					HighRiskAppRegs = @()
					ETRSpamActivity = @()
					HighRiskISPSignIns = @()
					RiskScore = 0
					MFAStatus = $null          # NEW
					FailedLoginPatterns = @()  # NEW
					PasswordChangeIssues = @() # NEW
				}
			}
			
			# STORE the password change data
			$users[$userId].PasswordChangeIssues += $pwChange
			
			# Add risk score
			try {
				$pwRiskScore = [int]$pwChange.RiskScore
				$users[$userId].RiskScore += $pwRiskScore
			}
			catch {
				Write-Log "Could not parse RiskScore for password change: $($pwChange.User)" -Level "Warning"
			}
		}
	}
    
    # Calculate risk levels and create results
    Update-GuiStatus "Calculating risk scores..." ([System.Drawing.Color]::Orange)
    
    $results = @()
    
    foreach ($userId in $users.Keys) {
        $userData = $users[$userId]
        
        $riskLevel = switch ($userData.RiskScore) {
            { $_ -ge 50 } { "Critical"; break }
            { $_ -ge 30 } { "High"; break }
            { $_ -ge 15 } { "Medium"; break }
            default { "Low" }
        }
        
        $resultObject = [PSCustomObject]@{
            UserId = $userId
            UserDisplayName = $userData.UserDisplayName
            RiskScore = $userData.RiskScore
            RiskLevel = $riskLevel
            UnusualSignInCount = $userData.UnusualSignIns.Count
            FailedSignInCount = $userData.FailedSignIns.Count
            HighRiskOperationsCount = $userData.HighRiskOps.Count
            SuspiciousRulesCount = $userData.SuspiciousRules.Count
            SuspiciousDelegationsCount = $userData.SuspiciousDelegations.Count
            HighRiskAppRegistrationsCount = $userData.HighRiskAppRegs.Count
            ETRSpamActivityCount = $userData.ETRSpamActivity.Count
			HighRiskISPCount = $userData.HighRiskISPSignIns.Count
            UnusualSignIns = $userData.UnusualSignIns
            FailedSignIns = $userData.FailedSignIns
            HighRiskOperations = $userData.HighRiskOps
            SuspiciousRules = $userData.SuspiciousRules
            SuspiciousDelegations = $userData.SuspiciousDelegations
            HighRiskAppRegistrations = $userData.HighRiskAppRegs
            ETRSpamActivity = $userData.ETRSpamActivity
			HighRiskISPSignIns = $userData.HighRiskISPSignIns
			MFAStatus = if ($userData.MFAStatus) { $userData.MFAStatus } else { "Unknown" }
			FailedLoginPatternCount = if ($userData.FailedLoginPatterns) { $userData.FailedLoginPatterns.Count } else { 0 }
			FailedLoginPatterns = if ($userData.FailedLoginPatterns) { $userData.FailedLoginPatterns } else { @() }
			PasswordChangeIssuesCount = if ($userData.PasswordChangeIssues) { $userData.PasswordChangeIssues.Count } else { 0 }
			PasswordChangeIssues = if ($userData.PasswordChangeIssues) { $userData.PasswordChangeIssues } else { @() }
        }
        
        $results += $resultObject
    }
    
    $results = $results | Sort-Object -Property RiskScore -Descending
    
    # Export results
    Update-GuiStatus "Exporting analysis results..." ([System.Drawing.Color]::Orange)
    
    $csvPath = $ReportPath -replace '.html$', '.csv'
    $results | Select-Object UserId, UserDisplayName, RiskScore, RiskLevel, UnusualSignInCount, 
        FailedSignInCount, HighRiskOperationsCount, SuspiciousRulesCount, SuspiciousDelegationsCount, 
        HighRiskAppRegistrationsCount, ETRSpamActivityCount |
        Export-Csv -Path $csvPath -NoTypeInformation -Force
    
    # Generate HTML report
    $htmlReport = Generate-HTMLReport -Data $results
    $htmlReport | Out-File -FilePath $ReportPath -Force -Encoding UTF8
    
    $criticalCount = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    
    Update-GuiStatus "Analysis completed! $criticalCount critical, $highCount high risk users" ([System.Drawing.Color]::Green)
    Write-Log "Analysis completed. Report saved to $ReportPath" -Level "Info"
    
    return $results
}

function Generate-HTMLReport {
    <#
    .SYNOPSIS
        Generates a comprehensive HTML security report with Yeyland Wutani theme and dark mode
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data
    )
    
    # Get current theme for default
    $defaultDarkMode = if ($script:CurrentTheme -eq "Dark") { "true" } else { "false" }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft 365 Security Analysis Report - Yeyland Wutani</title>
    <style>
        /* YEYLAND WUTANI THEME VARIABLES */
        :root {
            --primary-color: #FF6600;
            --secondary-color: #6B7280;
            --accent-color: #FF9800;
            --success-color: #4CAF50;
            --warning-color: #FF9800;
            --danger-color: #F44336;
            --critical-color: #D32F2F;
            --background-color: #F5F5F5;
            --surface-color: #FFFFFF;
            --text-primary: #212121;
            --text-secondary: #757575;
            --border-color: #E0E0E0;
            --shadow: rgba(0, 0, 0, 0.1);
        }
        
        body.dark-mode {
            --primary-color: #FF8533;
            --secondary-color: #9CA3AF;
            --accent-color: #FFA726;
            --success-color: #66BB6A;
            --warning-color: #FFA726;
            --danger-color: #EF5350;
            --critical-color: #E57373;
            --background-color: #121212;
            --surface-color: #1E1E1E;
            --text-primary: #FFFFFF;
            --text-secondary: #BDBDBD;
            --border-color: #3C3C3C;
            --shadow: rgba(0, 0, 0, 0.3);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background-color: var(--background-color);
            padding: 20px;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: var(--surface-color);
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px var(--shadow);
            transition: background-color 0.3s ease;
        }
        
        /* HEADER */
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 30px;
            border-bottom: 4px solid var(--primary-color);
            position: relative;
        }
        
        .header h1 {
            color: var(--primary-color);
            font-size: 2.8em;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header .subtitle {
            color: var(--text-secondary);
            font-size: 1.2em;
            margin-bottom: 15px;
        }
        
        .header .report-meta {
            color: var(--text-secondary);
            font-size: 0.95em;
            margin-top: 10px;
        }
        
        /* Dark Mode Toggle */
        .dark-mode-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }
        
        .dark-mode-toggle button {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px var(--shadow);
        }
        
        .dark-mode-toggle button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px var(--shadow);
        }
        
        /* DASHBOARD STATISTICS */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-box {
            background: linear-gradient(135deg, var(--surface-color), var(--background-color));
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid var(--border-color);
            transition: all 0.3s ease;
        }
        
        .stat-box:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px var(--shadow);
        }
        
        .stat-box.critical { border-left: 6px solid var(--critical-color); }
        .stat-box.high { border-left: 6px solid var(--danger-color); }
        .stat-box.medium { border-left: 6px solid var(--warning-color); }
        .stat-box.low { border-left: 6px solid var(--success-color); }
        
        .stat-number {
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
        }
        
        .stat-box.critical .stat-number { color: var(--critical-color); }
        .stat-box.high .stat-number { color: var(--danger-color); }
        .stat-box.medium .stat-number { color: var(--warning-color); }
        .stat-box.low .stat-number { color: var(--success-color); }
        
        .stat-label {
            font-size: 1.1em;
            color: var(--text-secondary);
            font-weight: 600;
        }
        
        /* USER CARDS */
        .users-section {
            margin-top: 40px;
        }
        
        .section-title {
            font-size: 1.8em;
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid var(--primary-color);
        }
        
        .user-card {
            background-color: var(--surface-color);
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }
        
        .user-card:hover {
            box-shadow: 0 6px 20px var(--shadow);
            transform: translateX(5px);
        }
        
        .user-card.critical {
            border-left: 8px solid var(--critical-color);
            background: linear-gradient(to right, rgba(211, 47, 47, 0.05), var(--surface-color));
        }
        
        .user-card.high {
            border-left: 8px solid var(--danger-color);
            background: linear-gradient(to right, rgba(244, 67, 54, 0.05), var(--surface-color));
        }
        
        .user-card.medium { border-left: 8px solid var(--warning-color); }
        .user-card.low { border-left: 8px solid var(--success-color); }
        
        .user-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            cursor: pointer;
            user-select: none;
        }
        
        .user-info h3 {
            color: var(--text-primary);
            font-size: 1.4em;
            margin-bottom: 5px;
        }
        
        .user-email {
            color: var(--text-secondary);
            font-size: 0.95em;
        }
        
        .risk-badge {
            padding: 8px 20px;
            border-radius: 25px;
            font-weight: 700;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .risk-badge.critical { background: var(--critical-color); color: white; }
        .risk-badge.high { background: var(--danger-color); color: white; }
        .risk-badge.medium { background: var(--warning-color); color: white; }
        .risk-badge.low { background: var(--success-color); color: white; }
        
        .risk-score {
            font-size: 2em;
            font-weight: 700;
            text-align: center;
            margin: 10px 0;
        }
        
        /* COLLAPSIBLE SECTIONS */
        .collapsible-content {
            display: none;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid var(--border-color);
        }
        
        .collapsible-content.show {
            display: block;
        }
        
        .toggle-icon {
            font-size: 1.5em;
            transition: transform 0.3s ease;
        }
        
        .toggle-icon.rotated {
            transform: rotate(180deg);
        }
        
        /* TABLES */
        .evidence-section {
            margin-top: 20px;
        }
        
        .evidence-section h4 {
            color: var(--primary-color);
            font-size: 1.2em;
            margin-bottom: 15px;
            padding-left: 15px;
            border-left: 4px solid var(--primary-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background-color: var(--surface-color);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        
        tr:hover {
            background-color: var(--background-color);
        }
        /* High-Risk Row Highlighting */
		.high-risk-row {
			background: linear-gradient(to right, rgba(255, 152, 0, 0.15), transparent) !important;
			border-left: 4px solid var(--danger-color) !important;
			font-weight: 500;
		}

		.high-risk-row:hover {
			background: linear-gradient(to right, rgba(255, 152, 0, 0.25), var(--background-color)) !important;
			box-shadow: 0 2px 8px rgba(255, 152, 0, 0.3);
			transform: translateX(3px);
			transition: all 0.2s ease;
		}

		/* High-Risk ISP Section Title */
		.evidence-section h4.high-risk-title {
			color: var(--danger-color);
			border-left-color: var(--danger-color);
		}

		/* Recommendation Box Styling */
		.recommendation-box {
			margin-top: 15px;
			padding: 12px 15px;
			background-color: rgba(255, 152, 0, 0.1);
			border-left: 4px solid var(--warning-color);
			border-radius: 4px;
			font-size: 0.9em;
			line-height: 1.6;
		}

		.recommendation-box strong {
			color: var(--warning-color);
			display: block;
			margin-bottom: 8px;
			font-size: 1.05em;
		}

		/* Dark Mode Adjustments */
		body.dark-mode .high-risk-row {
			background: linear-gradient(to right, rgba(255, 167, 38, 0.2), transparent) !important;
		}

		body.dark-mode .high-risk-row:hover {
			background: linear-gradient(to right, rgba(255, 167, 38, 0.3), rgba(255, 255, 255, 0.02)) !important;
		}

		body.dark-mode .recommendation-box {
			background-color: rgba(255, 167, 38, 0.15);
		}
        /* BADGES & ALERTS */
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 2px;
        }
        
        .badge.success { background: var(--success-color); color: white; }
        .badge.warning { background: var(--warning-color); color: white; }
        .badge.danger { background: var(--danger-color); color: white; }
        .badge.info { background: var(--primary-color); color: white; }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 5px solid;
        }
        
        .alert.critical {
            background-color: rgba(211, 47, 47, 0.1);
            border-color: var(--critical-color);
            color: var(--critical-color);
        }
        
        .alert.warning {
            background-color: rgba(255, 152, 0, 0.1);
            border-color: var(--warning-color);
            color: var(--warning-color);
        }
        
        .alert.info {
            background-color: rgba(33, 150, 243, 0.1);
            border-color: var(--primary-color);
            color: var(--primary-color);
        }
        
        .alert.success {
            background-color: rgba(76, 175, 80, 0.1);
            border-color: var(--success-color);
            color: var(--success-color);
        }
        
        /* FOOTER */
        .footer {
            margin-top: 60px;
            padding-top: 30px;
            border-top: 3px solid var(--border-color);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9em;
        }
        
        .footer strong {
            color: var(--primary-color);
        }
        
        /* PRINT STYLES */
        @media print {
            .dark-mode-toggle { display: none; }
            .collapsible-content { display: block !important; }
            .user-card { page-break-inside: avoid; }
        }
        
        /* RESPONSIVE DESIGN */
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .user-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .risk-badge {
                margin-top: 10px;
            }
        }
    </style>
</head>
<body class="$( if ($defaultDarkMode -eq "true") { "dark-mode" } else { "" } )">
    <div class="dark-mode-toggle">
        <button onclick="toggleDarkMode()" id="themeToggle">
            <span id="themeIcon">🌙</span> <span id="themeText">Dark Mode</span>
        </button>
    </div>

    <div class="container">
        <div class="header">
            <h1>🛡️ Microsoft 365 Security Analysis Report</h1>
            <div class="subtitle">Yeyland Wutani - Comprehensive Threat Detection & Risk Assessment</div>
            <div class="report-meta">
                Generated: $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss") | 
                Total Users Analyzed: $($Data.Count) | 
                Tool Version: $ScriptVer
            </div>
        </div>

        <div class="stats-grid">
"@

    # Calculate statistics
    $criticalCount = ($Data | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = ($Data | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumCount = ($Data | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowCount = ($Data | Where-Object { $_.RiskLevel -eq "Low" }).Count

    $html += @"
            <div class="stat-box critical">
                <div class="stat-number">$criticalCount</div>
                <div class="stat-label">Critical Risk</div>
            </div>
            <div class="stat-box high">
                <div class="stat-number">$highCount</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-box medium">
                <div class="stat-number">$mediumCount</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-box low">
                <div class="stat-number">$lowCount</div>
                <div class="stat-label">Low Risk</div>
            </div>
        </div>
"@

    if ($criticalCount -gt 0) {
        $html += @"
        <div class="alert critical">
            <strong>⚠️ CRITICAL ALERT:</strong> $criticalCount user(s) identified with critical security risks requiring immediate attention!
        </div>
"@
    }

if ($highCount -gt 0) {
        $html += @"
        <div class="alert warning">
            <strong>⚠️ WARNING:</strong> $highCount user(s) identified with high security risks requiring review.
        </div>
"@
    }

    # Sort users by risk
    $sortedData = $Data | Sort-Object @{Expression = {
        switch ($_.RiskLevel) {
            "Critical" { 1 }
            "High" { 2 }
            "Medium" { 3 }
            "Low" { 4 }
            default { 5 }
        }
    }}, RiskScore -Descending

    # Add User Summary Table
    $html += @"
        <div class="users-section">
            <h2 class="section-title">👥 User Summary Overview</h2>
            <div class="evidence-section">
                <table class="summary-table">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Email</th>
                            <th>Risk Level</th>
                            <th>Risk Score</th>
                            <th>MFA Status</th>
                            <th>Key Indicators</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($user in $sortedData) {
        $riskClass = $user.RiskLevel.ToLower()
        $mfaStatus = if ($user.MFAStatus) { $user.MFAStatus } else { "Unknown" }
        $mfaBadgeClass = switch ($mfaStatus) {
            "Yes" { "success" }
            "No" { "danger" }
            default { "info" }
        }
        
        # Build key indicators summary
        $indicators = @()
        if ($user.UnusualSignInCount -gt 0) { $indicators += "🌍 Unusual Locations ($($user.UnusualSignInCount))" }
        if ($user.FailedSignInCount -gt 0) { $indicators += "🚫 Failed Logins ($($user.FailedSignInCount))" }
        if ($user.HighRiskOperationsCount -gt 0) { $indicators += "⚡ High-Risk Ops ($($user.HighRiskOperationsCount))" }
        if ($user.SuspiciousRulesCount -gt 0) { $indicators += "📨 Suspicious Rules ($($user.SuspiciousRulesCount))" }
        if ($user.FailedLoginPatternCount -gt 0) { $indicators += "🚨 Attack Patterns ($($user.FailedLoginPatternCount))" }
        if ($user.PasswordChangeIssuesCount -gt 0) { $indicators += "🔑 PW Changes ($($user.PasswordChangeIssuesCount))" }
		if ($user.HighRiskISPCount -gt 0) { $indicators += "⚠️ High-Risk ISPs ($($user.HighRiskISPCount))" }
        
        $indicatorText = if ($indicators.Count -gt 0) { $indicators -join "<br>" } else { "None" }
        
        $html += @"
                        <tr class="summary-row-$riskClass">
                            <td><strong>$([System.Web.HttpUtility]::HtmlEncode($user.UserDisplayName))</strong></td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($user.UserId))</td>
                            <td><span class="badge $riskClass">$($user.RiskLevel)</span></td>
                            <td><strong>$($user.RiskScore)</strong></td>
                            <td><span class="badge $mfaBadgeClass">$mfaStatus</span></td>
                            <td style="font-size: 0.85em;">$indicatorText</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="users-section">
            <h2 class="section-title">📊 Detailed User Risk Analysis</h2>
"@

    foreach ($user in $sortedData) {
        $riskClass = $user.RiskLevel.ToLower()
        $autoExpand = if ($user.RiskLevel -in @("Critical", "High")) { "show" } else { "" }
        
        $html += @"
            <div class="user-card $riskClass">
                <div class="user-header" onclick="toggleDetails(this)">
                    <div class="user-info">
                        <h3>$([System.Web.HttpUtility]::HtmlEncode($user.UserDisplayName))</h3>
                        <div class="user-email">$([System.Web.HttpUtility]::HtmlEncode($user.UserId))</div>
                    </div>
                    <div style="text-align: center;">
                        <div class="risk-badge $riskClass">$($user.RiskLevel) RISK</div>
                        <div class="risk-score" style="color: var(--$(if($riskClass -eq "critical"){"critical"}else{$riskClass})-color);">
                            Score: $($user.RiskScore)
                        </div>
                        <span class="toggle-icon $(if($autoExpand){"rotated"}else{""})">▼</span>
                    </div>
                </div>
                
                <div class="collapsible-content $autoExpand">
"@

        # MFA Status
        $mfaStatus = if ($user.MFAStatus) { $user.MFAStatus } else { "Unknown" }
        if ($mfaStatus -eq "No") {
            $html += @"
                    <div class="alert critical">
                        ❌ <strong>MFA Not Enabled</strong> - Account vulnerable to password attacks
                    </div>
"@
        } elseif ($mfaStatus -eq "Yes") {
            $html += @"
                    <div class="alert success">
                        ✅ <strong>MFA Enabled</strong>
                    </div>
"@
        }

        # Risk Summary Table
        $html += @"
                    <div class="evidence-section">
                        <h4>🎯 Risk Summary</h4>
                        <table>
                            <tr>
                                <th>Risk Factor</th>
                                <th>Count</th>
                            </tr>
"@
        
        if ($user.UnusualSignInCount -gt 0) {
            $html += "<tr><td>Unusual Sign-In Locations</td><td><span class='badge warning'>$($user.UnusualSignInCount)</span></td></tr>"
        }
        if ($user.FailedSignInCount -gt 0) {
            $html += "<tr><td>Failed Sign-In Attempts</td><td><span class='badge danger'>$($user.FailedSignInCount)</span></td></tr>"
        }
        if ($user.HighRiskOperationsCount -gt 0) {
            $html += "<tr><td>High-Risk Admin Operations</td><td><span class='badge danger'>$($user.HighRiskOperationsCount)</span></td></tr>"
        }
        if ($user.SuspiciousRulesCount -gt 0) {
            $html += "<tr><td>Suspicious Inbox Rules</td><td><span class='badge danger'>$($user.SuspiciousRulesCount)</span></td></tr>"
        }
        if ($user.SuspiciousDelegationsCount -gt 0) {
            $html += "<tr><td>Suspicious Delegations</td><td><span class='badge warning'>$($user.SuspiciousDelegationsCount)</span></td></tr>"
        }
        if ($user.ETRSpamActivityCount -gt 0) {
            $html += "<tr><td>Spam Activity Detected</td><td><span class='badge danger'>$($user.ETRSpamActivityCount)</span></td></tr>"
        }
        if ($user.FailedLoginPatternCount -gt 0) {
            $html += "<tr><td>Failed Login Patterns</td><td><span class='badge danger'>$($user.FailedLoginPatternCount)</span></td></tr>"
        }
        if ($user.PasswordChangeIssuesCount -gt 0) {
            $html += "<tr><td>Password Change Issues</td><td><span class='badge warning'>$($user.PasswordChangeIssuesCount)</span></td></tr>"
        }
		if ($user.HighRiskISPCount -gt 0) {
			$html += "<tr><td>High-Risk ISP Sign-Ins</td><td><span class='badge danger'>$($user.HighRiskISPCount)</span></td></tr>"
		}
        
        $html += @"
                        </table>
                    </div>
"@

		# Unusual Sign-Ins Details
		if ($user.UnusualSignIns -and $user.UnusualSignIns.Count -gt 0) {
			$html += @"
							<div class="evidence-section">
								<h4>🌍 Unusual Sign-In Locations</h4>
								<table>
									<tr>
										<th>Date/Time</th>
										<th>Location</th>
										<th>IP Address</th>
										<th>ISP</th>
										<th>Risk</th>
									</tr>
"@
		foreach ($signIn in ($user.UnusualSignIns | Select-Object -First 10)) {
			$location = "$($signIn.City), $($signIn.Country)"
			
			# Check if this ISP is high-risk
			$isHighRiskISP = $false
			if ($signIn.PSObject.Properties['IsHighRiskISP']) {
				$isHighRiskISP = $signIn.IsHighRiskISP -eq $true -or $signIn.IsHighRiskISP -eq "True"
			}
			
			$riskBadge = if ($isHighRiskISP) {
				"<span class='badge danger' title='VPN/Hosting/Datacenter Provider'>⚠️ HIGH-RISK ISP</span>"
			} else {
				"<span class='badge info'>Standard</span>"
			}
			
			# Highlight row if high-risk ISP
			$rowClass = if ($isHighRiskISP) { " class='high-risk-row'" } else { "" }
			
			$html += @"
                            <tr$rowClass>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($signIn.CreationTime))</td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($location))</td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($signIn.IP))</td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($signIn.ISP))</td>
                                <td>$riskBadge</td>
                            </tr>
"@
    }
    $html += @"
                        </table>
                    </div>
"@
}


# High-Risk ISP Sign-Ins Section
if ($user.HighRiskISPSignIns -and $user.HighRiskISPSignIns.Count -gt 0) {
    $html += @"
                    <div class="evidence-section">
                        <h4 class="high-risk-title">⚠️ High-Risk ISP Connections (VPN/Hosting/Datacenter)</h4>
                        <div class="alert warning">
                            <strong>Security Alert:</strong> These sign-ins originated from ISPs commonly associated with VPS hosting, 
                            VPN services, or datacenter infrastructure. While not always malicious, these connections warrant investigation 
                            as they may indicate compromised credentials or unauthorized access.
                        </div>
                        <table>
                            <tr>
                                <th>Date/Time</th>
                                <th>Location</th>
                                <th>IP Address</th>
                                <th>High-Risk ISP</th>
                                <th>Device</th>
                            </tr>
"@
    foreach ($signIn in ($user.HighRiskISPSignIns | Select-Object -First 10)) {
        $location = "$($signIn.City), $($signIn.Country)"
        $device = if ($signIn.UserAgent) {
            [System.Web.HttpUtility]::HtmlEncode($signIn.UserAgent)
        } else {
            "Unknown"
        }
        
        $html += @"
                            <tr class="high-risk-row">
                                <td>$([System.Web.HttpUtility]::HtmlEncode($signIn.CreationTime))</td>
                                <td><span class="badge warning">$([System.Web.HttpUtility]::HtmlEncode($location))</span></td>
                                <td><strong>$([System.Web.HttpUtility]::HtmlEncode($signIn.IP))</strong></td>
                                <td><span class="badge danger">$([System.Web.HttpUtility]::HtmlEncode($signIn.ISP))</span></td>
                                <td style="font-size: 0.85em;">$device</td>
                            </tr>
"@
    }
    $html += @"
                        </table>
                        <div class="recommendation-box">
                            <strong>📋 Recommended Actions:</strong><br>
                            • Verify these sign-ins with the user<br>
                            • Confirm if VPN or remote access was authorized<br>
                            • Review for unauthorized access patterns<br>
                            • Consider enforcing Conditional Access policies for datacenter IPs<br>
                            • Enable MFA if not already active
                        </div>
                    </div>
"@
}

        # Failed Login Patterns
        if ($user.FailedLoginPatterns -and $user.FailedLoginPatterns.Count -gt 0) {
            $html += @"
                    <div class="evidence-section">
                        <h4>🚨 Failed Login Attack Patterns</h4>
                        <table>
                            <tr>
                                <th>Pattern Type</th>
                                <th>Source IP</th>
                                <th>Failed Attempts</th>
                                <th>Risk Level</th>
                            </tr>
"@
            foreach ($pattern in ($user.FailedLoginPatterns | Select-Object -First 5)) {
                $html += @"
                            <tr>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($pattern.PatternType))</td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($pattern.SourceIP))</td>
                                <td><span class="badge danger">$($pattern.FailedAttempts)</span></td>
                                <td><span class="badge $(if($pattern.RiskLevel -eq "Critical"){"danger"}else{"warning"})">$($pattern.RiskLevel)</span></td>
                            </tr>
"@
            }
            $html += @"
                        </table>
                    </div>
"@
        }

        # Password Change Issues
        if ($user.PasswordChangeIssues -and $user.PasswordChangeIssues.Count -gt 0) {
            $html += @"
                    <div class="evidence-section">
                        <h4>🔑 Suspicious Password Changes</h4>
                        <table>
                            <tr>
                                <th>Change Count</th>
                                <th>Time Span</th>
                                <th>Off-Hours Changes</th>
                                <th>Risk Level</th>
                            </tr>
"@
            foreach ($pwChange in ($user.PasswordChangeIssues | Select-Object -First 5)) {
                $html += @"
                            <tr>
                                <td><span class="badge warning">$($pwChange.ChangeCount)</span></td>
                                <td>$($pwChange.TimeSpanHours) hours</td>
                                <td>$($pwChange.OffHoursChanges)</td>
                                <td><span class="badge $(if($pwChange.RiskLevel -eq "Critical"){"danger"}else{"warning"})">$($pwChange.RiskLevel)</span></td>
                            </tr>
"@
            }
            $html += @"
                        </table>
                    </div>
"@
        }

        # Suspicious Rules
        if ($user.SuspiciousRules -and $user.SuspiciousRules.Count -gt 0) {
            $html += @"
                    <div class="evidence-section">
                        <h4>📨 Suspicious Inbox Rules</h4>
                        <table>
                            <tr>
                                <th>Rule Name</th>
                                <th>Actions</th>
                                <th>Enabled</th>
                            </tr>
"@
            foreach ($rule in ($user.SuspiciousRules | Select-Object -First 5)) {
                $actions = @()
                if ($rule.ForwardTo) { $actions += "Forwards Email" }
                if ($rule.DeleteMessage -eq $true) { $actions += "Deletes" }
                if ($rule.MarkAsRead -eq $true) { $actions += "Marks Read" }
                $actionText = $actions -join ", "
                
                $html += @"
                            <tr>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($rule.RuleName))</td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($actionText))</td>
                                <td><span class="badge $(if($rule.Enabled -eq $true){"danger"}else{"info"})">$($rule.Enabled)</span></td>
                            </tr>
"@
            }
            $html += @"
                        </table>
                    </div>
"@
        }

        $html += @"
                </div>
            </div>
"@
    }

    $html += @"
        </div>

        <div class="footer">
            <strong>Yeyland Wutani - Microsoft 365 Security Analysis Tool v$ScriptVer</strong><br>
            Report generated using Microsoft Graph PowerShell APIs<br>
            Risk scores calculated based on multiple security indicators<br>
            <br>
            <strong>Recommended Actions:</strong><br>
            • Immediately review and remediate all Critical risk users<br>
            • Enable MFA for all accounts, especially administrative accounts<br>
            • Investigate suspicious sign-in patterns and unusual authentication activities<br>
            • Review and remove unnecessary administrative privileges<br>
            • Monitor inbox rules and delegation settings for potential compromise indicators
        </div>
    </div>

    <script>
        function toggleDarkMode() {
            const body = document.body;
            const isDark = body.classList.toggle('dark-mode');
            
            const icon = document.getElementById('themeIcon');
            const text = document.getElementById('themeText');
            
            if (isDark) {
                icon.textContent = '🌙';
                text.textContent = 'Dark Mode';
            } else {
                icon.textContent = '☀️';
                text.textContent = 'Light Mode';
            }
            
            localStorage.setItem('darkMode', isDark);
        }
        
        window.addEventListener('DOMContentLoaded', function() {
            const savedMode = localStorage.getItem('darkMode');
            const isDark = savedMode === null ? $defaultDarkMode : savedMode === 'true';
            
            if (isDark && !document.body.classList.contains('dark-mode')) {
                document.body.classList.add('dark-mode');
            } else if (!isDark && document.body.classList.contains('dark-mode')) {
                document.body.classList.remove('dark-mode');
            }
            
            const icon = document.getElementById('themeIcon');
            const text = document.getElementById('themeText');
            icon.textContent = isDark ? '🌙' : '☀️';
            text.textContent = isDark ? 'Dark Mode' : 'Light Mode';
        });
        
        function toggleDetails(header) {
            const content = header.nextElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            content.classList.toggle('show');
            icon.classList.toggle('rotated');
        }
        
        window.addEventListener('DOMContentLoaded', function() {
            const criticalAndHigh = document.querySelectorAll('.user-card.critical, .user-card.high');
            criticalAndHigh.forEach(card => {
                const content = card.querySelector('.collapsible-content');
                const icon = card.querySelector('.toggle-icon');
                if (content && !content.classList.contains('show')) {
                    content.classList.add('show');
                    icon.classList.add('rotated');
                }
            });
        });
    </script>
</body>
</html>
"@

    return $html
}

#endregion

#################################################################
#
#  SECTION 5: GUI FUNCTIONS
#
#################################################################

#region GUI FUNCTIONS

function Show-MainGUI {
    <#
    .SYNOPSIS
        Displays the main graphical user interface for the security analysis tool.
    
    .DESCRIPTION
        Creates and displays the primary application window with emoji-enhanced buttons
        and improved color scheme using Yeyland Wutani brand colors.
    
    .EXAMPLE
        Show-MainGUI
        # Displays the main application interface
    
    .NOTES
        All buttons include error handling and visual feedback
        Form cleanup includes proper Microsoft Graph disconnection
    #>
    
    [CmdletBinding()]
    param()
    
    #──────────────────────────────────────────────────────────────
    # ENSURE ASSEMBLIES ARE LOADED
    #──────────────────────────────────────────────────────────────
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
	[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
	[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

	# Set default font that supports emojis
	[System.Windows.Forms.Application]::EnableVisualStyles()

    #──────────────────────────────────────────────────────────────
    # CREATE MAIN FORM
    #──────────────────────────────────────────────────────────────
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Microsoft 365 Security Analysis Tool - v$ScriptVer"
    $form.Size = New-Object System.Drawing.Size(840, 650)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = Get-ThemeColor -ColorName "Background"

    # Set global form reference
    $Global:MainForm = $form

    #──────────────────────────────────────────────────────────────
    # HEADER SECTION WITH THEME TOGGLE
    #──────────────────────────────────────────────────────────────
    
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "🛡️ Microsoft 365 Security Analysis Tool"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 16, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = Get-ThemeColor -ColorName "Primary"
    $headerLabel.Size = New-Object System.Drawing.Size(650, 40)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 20)
    $headerLabel.TextAlign = "MiddleLeft"
    $form.Controls.Add($headerLabel)
    
    # Theme toggle button - Enhanced with better styling
    $themeToggle = New-Object System.Windows.Forms.Button
    $themeToggle.Size = New-Object System.Drawing.Size(110, 38)
    $themeToggle.Location = New-Object System.Drawing.Point(690, 20)
    $themeToggle.FlatStyle = "Flat"
    $themeToggle.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5, [System.Drawing.FontStyle]::Bold)
    $themeToggle.Cursor = [System.Windows.Forms.Cursors]::Hand

    if ($script:CurrentTheme -eq "Dark") {
        $themeToggle.Text = "☀️ Light"
        $themeToggle.BackColor = [System.Drawing.Color]::FromArgb(66, 165, 245)
        $themeToggle.ForeColor = [System.Drawing.Color]::White
        $themeToggle.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(41, 128, 185)
    } else {
        $themeToggle.Text = "🌙 Dark"
        $themeToggle.BackColor = [System.Drawing.Color]::FromArgb(52, 73, 94)
        $themeToggle.ForeColor = [System.Drawing.Color]::White
        $themeToggle.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    }
    $themeToggle.FlatAppearance.BorderSize = 2

    # Store original color in Tag for hover effects
    $themeToggle.Tag = $themeToggle.BackColor

    # Add hover effects
    $themeToggle.Add_MouseEnter({
        if ($script:CurrentTheme -eq "Dark") {
            $this.BackColor = [System.Drawing.Color]::FromArgb(100, 181, 246)
        } else {
            $this.BackColor = [System.Drawing.Color]::FromArgb(69, 90, 100)
        }
    })

    $themeToggle.Add_MouseLeave({
        if ($this.Tag -and $this.Tag -is [System.Drawing.Color]) {
            $this.BackColor = $this.Tag
        }
    })

    $themeToggle.Add_Click({
        if ($script:CurrentTheme -eq "Dark") {
            Set-Theme -Theme "Light"
        } else {
            Set-Theme -Theme "Dark"
        }

        # Properly dispose the form before creating new one
        $form.Dispose()
        Show-MainGUI
    })

    $form.Controls.Add($themeToggle)

    # Version label
    $versionLabel = New-Object System.Windows.Forms.Label
    $versionLabel.Text = "Enhanced MS Graph PowerShell Edition - Version $ScriptVer"
    $versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $versionLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    $versionLabel.Size = New-Object System.Drawing.Size(780, 20)
    $versionLabel.Location = New-Object System.Drawing.Point(20, 60)
    $versionLabel.TextAlign = "MiddleLeft"
    $form.Controls.Add($versionLabel)

    #──────────────────────────────────────────────────────────────
    # STATUS PANEL - Enhanced Design
    #──────────────────────────────────────────────────────────────

    $statusPanel = New-Object System.Windows.Forms.Panel
    $statusPanel.Size = New-Object System.Drawing.Size(780, 150)
    $statusPanel.Location = New-Object System.Drawing.Point(20, 95)
    $statusPanel.BorderStyle = "FixedSingle"
    $statusPanel.BackColor = Get-ThemeColor -ColorName "Surface"

    # Add visual depth with Paint event for custom border
    $statusPanel.Add_Paint({
        param($sender, $e)
        $borderColor = Get-ThemeColor -ColorName "Primary"
        $pen = New-Object System.Drawing.Pen($borderColor, 3)
        $width = [int]$sender.Width - 1
        $height = [int]$sender.Height - 1
        $rect = New-Object System.Drawing.Rectangle(0, 0, $width, $height)
        $e.Graphics.DrawRectangle($pen, $rect)
        $pen.Dispose()
    })

    $form.Controls.Add($statusPanel)

    $Global:WorkDirLabel = New-Object System.Windows.Forms.Label
    $Global:WorkDirLabel.Text = "📁 Working Directory: $($ConfigData.WorkDir)"
    $Global:WorkDirLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5)
    $Global:WorkDirLabel.Size = New-Object System.Drawing.Size(760, 28)
    $Global:WorkDirLabel.Location = New-Object System.Drawing.Point(15, 12)
    $Global:WorkDirLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $statusPanel.Controls.Add($Global:WorkDirLabel)

    $Global:DateRangeLabel = New-Object System.Windows.Forms.Label
    $Global:DateRangeLabel.Text = "📅 Date Range: $($ConfigData.DateRange) days back"
    $Global:DateRangeLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5)
    $Global:DateRangeLabel.Size = New-Object System.Drawing.Size(760, 28)
    $Global:DateRangeLabel.Location = New-Object System.Drawing.Point(15, 40)
    $Global:DateRangeLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $statusPanel.Controls.Add($Global:DateRangeLabel)

    $Global:ConnectionLabel = New-Object System.Windows.Forms.Label
    $Global:ConnectionLabel.Text = "🔌 Microsoft Graph: Not Connected"
    $Global:ConnectionLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5, [System.Drawing.FontStyle]::Bold)
    $Global:ConnectionLabel.Size = New-Object System.Drawing.Size(760, 28)
    $Global:ConnectionLabel.Location = New-Object System.Drawing.Point(15, 68)
    $Global:ConnectionLabel.ForeColor = Get-ThemeColor -ColorName "Danger"
    $statusPanel.Controls.Add($Global:ConnectionLabel)

    $Global:TenantInfoLabel = New-Object System.Windows.Forms.Label
    $Global:TenantInfoLabel.Text = "🏢 Not connected to any tenant"
    $Global:TenantInfoLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5)
    $Global:TenantInfoLabel.Size = New-Object System.Drawing.Size(760, 28)
    $Global:TenantInfoLabel.Location = New-Object System.Drawing.Point(15, 96)
    $Global:TenantInfoLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    $statusPanel.Controls.Add($Global:TenantInfoLabel)

    $performanceLabel = New-Object System.Windows.Forms.Label
    $performanceLabel.Text = "⚡ Performance: Batch Size $($ConfigData.BatchSize) | Cache Timeout $($ConfigData.CacheTimeout)s"
    $performanceLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 8.5)
    $performanceLabel.Size = New-Object System.Drawing.Size(760, 22)
    $performanceLabel.Location = New-Object System.Drawing.Point(15, 124)
    $performanceLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    $statusPanel.Controls.Add($performanceLabel)

    #──────────────────────────────────────────────────────────────
    # BOTTOM STATUS BAR - Enhanced Design
    #──────────────────────────────────────────────────────────────

    # Create a status bar panel for better visual separation
    $statusBarPanel = New-Object System.Windows.Forms.Panel
    $statusBarPanel.Size = New-Object System.Drawing.Size(800, 50)
    $statusBarPanel.Location = New-Object System.Drawing.Point(20, 555)
    $statusBarPanel.BorderStyle = "FixedSingle"
    $statusBarPanel.BackColor = Get-ThemeColor -ColorName "Surface"

    # Add custom border to status bar
    $statusBarPanel.Add_Paint({
        param($sender, $e)
        $borderColor = Get-ThemeColor -ColorName "Border"
        $pen = New-Object System.Drawing.Pen($borderColor, 2)
        $width = [int]$sender.Width - 1
        $height = [int]$sender.Height - 1
        $rect = New-Object System.Drawing.Rectangle(0, 0, $width, $height)
        $e.Graphics.DrawRectangle($pen, $rect)
        $pen.Dispose()
    })

    $Global:StatusLabel = New-Object System.Windows.Forms.Label
    $Global:StatusLabel.Text = "✅ Ready - Please connect to Microsoft Graph to begin"
    $Global:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9.5, [System.Drawing.FontStyle]::Bold)
    $Global:StatusLabel.Size = New-Object System.Drawing.Size(780, 45)
    $Global:StatusLabel.Location = New-Object System.Drawing.Point(15, 2)
    $Global:StatusLabel.TextAlign = "MiddleLeft"

    if ($script:CurrentTheme -eq "Dark") {
        $Global:StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
    } else {
        $Global:StatusLabel.ForeColor = Get-ThemeColor -ColorName "Primary"
    }

    $statusBarPanel.Controls.Add($Global:StatusLabel)
    $form.Controls.Add($statusBarPanel)

    #──────────────────────────────────────────────────────────────
    # ROW 1: SETUP BUTTONS WITH EMOJIS
    #──────────────────────────────────────────────────────────────

    # Section header for Setup Controls
    $setupHeader = New-Object System.Windows.Forms.Label
    $setupHeader.Text = "⚙️ Configuration & Connection"
    $setupHeader.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 10, [System.Drawing.FontStyle]::Bold)
    $setupHeader.ForeColor = Get-ThemeColor -ColorName "Primary"
    $setupHeader.Size = New-Object System.Drawing.Size(780, 25)
    $setupHeader.Location = New-Object System.Drawing.Point(30, 258)
    $form.Controls.Add($setupHeader)

    $btnWorkDir = New-GuiButton -text "📂 Set Working Directory" -x 30 -y 285 -width 145 -height 38 `
        -ColorType "Secondary" -action {
        $folder = Get-Folder -initialDirectory $ConfigData.WorkDir
        if ($folder) {
            Update-WorkingDirectoryDisplay -NewWorkDir $folder
            Update-GuiStatus "✅ Working directory updated successfully" (Get-ThemeColor -ColorName "Success")
            
            if ($Global:ConnectionState.IsConnected) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Working directory updated to:`n$folder`n`n" +
                    "Note: You are currently connected to tenant '$($Global:ConnectionState.TenantName)'. " +
                    "The tenant-specific directory will be recreated on next connection.",
                    "Directory Updated",
                    "OK",
                    "Information"
                )
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Working directory updated to:`n$folder",
                    "Directory Updated",
                    "OK",
                    "Information"
                )
            }
        }
    }
    $form.Controls.Add($btnWorkDir)

    $btnDateRange = New-GuiButton -text "📅 Change Date Range" -x 185 -y 285 -width 145 -height 38 `
        -ColorType "Accent" -action {
        $newRange = Get-DateRangeInput -CurrentValue $ConfigData.DateRange
        if ($newRange -ne $null) {
            $oldRange = $ConfigData.DateRange
            $ConfigData.DateRange = $newRange
            $Global:DateRangeLabel.Text = "📅 Date Range: $($ConfigData.DateRange) days back"
            $Global:DateRangeLabel.Refresh()
            Update-GuiStatus "✅ Date range updated from $oldRange to $newRange days" (Get-ThemeColor -ColorName "Success")
            
            [System.Windows.Forms.MessageBox]::Show(
                "Date range updated successfully!`n`nOld range: $oldRange days`nNew range: $newRange days`n`n" +
                "Note: This will affect all future data collection operations.",
                "Date Range Updated",
                "OK",
                "Information"
            )
        }
    }
    $form.Controls.Add($btnDateRange)

    $btnConnect = New-GuiButton -text "🔌 Connect to Microsoft Graph" -x 340 -y 285 -width 185 -height 38 `
        -ColorType "Primary" -action {
        $btnConnect.Enabled = $false
        $originalText = $btnConnect.Text
        $btnConnect.Text = "⏳ Connecting..."

        try {
            $connected = Connect-TenantServices

            if ($connected) {
                Update-GuiStatus "✅ Connected to Microsoft Graph successfully!" (Get-ThemeColor -ColorName "Success")
            } else {
                Update-GuiStatus "❌ Failed to connect to Microsoft Graph" (Get-ThemeColor -ColorName "Danger")
            }
        }
        finally {
            $btnConnect.Enabled = $true
            $btnConnect.Text = $originalText
        }
    }
    $form.Controls.Add($btnConnect)

    $btnDisconnect = New-GuiButton -text "🔴 Disconnect" -x 535 -y 285 -width 115 -height 38 `
        -ColorType "Danger" -action {
        $btnDisconnect.Enabled = $false
        $originalText = $btnDisconnect.Text
        $btnDisconnect.Text = "⏳ Disconnecting..."

        try {
            Disconnect-GraphSafely -ShowMessage $true
        }
        finally {
            $btnDisconnect.Enabled = $true
            $btnDisconnect.Text = $originalText
        }
    }
    $form.Controls.Add($btnDisconnect)

    $btnCheckVersion = New-GuiButton -text "🔄 Check Version" -x 660 -y 285 -width 140 -height 38 `
        -ColorType "Accent" -action {
        Test-ScriptVersion -ShowMessageBox $true
    }
    $form.Controls.Add($btnCheckVersion)

    #──────────────────────────────────────────────────────────────
    # ROW 2: DATA COLLECTION BUTTONS (PART 1) WITH EMOJIS
    #──────────────────────────────────────────────────────────────

    # Section header for Data Collection
    $dataCollectionHeader = New-Object System.Windows.Forms.Label
    $dataCollectionHeader.Text = "📊 Data Collection"
    $dataCollectionHeader.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 10, [System.Drawing.FontStyle]::Bold)
    $dataCollectionHeader.ForeColor = Get-ThemeColor -ColorName "Success"
    $dataCollectionHeader.Size = New-Object System.Drawing.Size(780, 25)
    $dataCollectionHeader.Location = New-Object System.Drawing.Point(30, 338)
    $form.Controls.Add($dataCollectionHeader)

    $btnSignIn = New-GuiButton -text "👤 Collect Sign-In Data" -x 30 -y 365 -width 185 -height 38 `
        -ColorType "Success" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }
        
        $btnSignIn.Enabled = $false
        $originalText = $btnSignIn.Text
        $btnSignIn.Text = "⏳ Running..."
        
        try {
            $result = Get-TenantSignInData
            if ($result) {
                Update-GuiStatus "✅ Sign-in data collected! Processed $($result.Count) records." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnSignIn.Enabled = $true
            $btnSignIn.Text = $originalText
        }
    }
    $form.Controls.Add($btnSignIn)

    $btnAudit = New-GuiButton -text "📋 Collect Admin Audits" -x 225 -y 365 -width 185 -height 38 `
        -ColorType "Success" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }
        
        $btnAudit.Enabled = $false
        $originalText = $btnAudit.Text
        $btnAudit.Text = "⏳ Running..."
        
        try {
            $result = Get-AdminAuditData
            if ($result) {
                Update-GuiStatus "✅ Admin audit data collected! Processed $($result.Count) records." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnAudit.Enabled = $true
            $btnAudit.Text = $originalText
        }
    }
    $form.Controls.Add($btnAudit)

    $btnRules = New-GuiButton -text "📨 Collect Inbox Rules" -x 420 -y 365 -width 185 -height 38 `
        -ColorType "Success" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }
        
        $btnRules.Enabled = $false
        $originalText = $btnRules.Text
        $btnRules.Text = "⏳ Running..."
        
        try {
            $result = Get-MailboxRules
            if ($result) {
                Update-GuiStatus "✅ Inbox rules collected! Found $($result.Count) rules." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnRules.Enabled = $true
            $btnRules.Text = $originalText
        }
    }
    $form.Controls.Add($btnRules)

    $btnDelegation = New-GuiButton -text "👥 Collect Delegations" -x 615 -y 365 -width 185 -height 38 `
        -ColorType "Success" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }
        
        $btnDelegation.Enabled = $false
        $originalText = $btnDelegation.Text
        $btnDelegation.Text = "⏳ Running..."
        
        try {
            $result = Get-MailboxDelegationData
            if ($result) {
                Update-GuiStatus "✅ Delegation data collected! Found $($result.Count) delegations." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnDelegation.Enabled = $true
            $btnDelegation.Text = $originalText
        }
    }
    $form.Controls.Add($btnDelegation)

    #──────────────────────────────────────────────────────────────
    # ROW 3: DATA COLLECTION BUTTONS (PART 2) WITH EMOJIS
    #──────────────────────────────────────────────────────────────

    $btnApps = New-GuiButton -text "🔐 Collect App Registrations" -x 30 -y 413 -width 185 -height 38 `
        -ColorType "Success" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }
        
        $btnApps.Enabled = $false
        $originalText = $btnApps.Text
        $btnApps.Text = "⏳ Running..."
        
        try {
            $result = Get-AppRegistrationData
            if ($result) {
                Update-GuiStatus "✅ App registration data collected! Found $($result.Count) apps." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnApps.Enabled = $true
            $btnApps.Text = $originalText
        }
    }
    $form.Controls.Add($btnApps)

    $btnConditionalAccess = New-GuiButton -text "🔒 Conditional Access" -x 225 -y 413 -width 185 -height 38 `
        -ColorType "Success" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }

        $btnConditionalAccess.Enabled = $false
        $originalText = $btnConditionalAccess.Text
        $btnConditionalAccess.Text = "⏳ Running..."

        try {
            $result = Get-ConditionalAccessData
            if ($result) {
                Update-GuiStatus "✅ Conditional access data collected! Found $($result.Count) policies." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnConditionalAccess.Enabled = $true
            $btnConditionalAccess.Text = $originalText
        }
    }
    $form.Controls.Add($btnConditionalAccess)

    $btnETRAnalysis = New-GuiButton -text "🔍 Analyze ETR Files" -x 420 -y 413 -width 185 -height 38 `
        -ColorType "Accent" -action {
        $btnETRAnalysis.Enabled = $false
        $originalText = $btnETRAnalysis.Text
        $btnETRAnalysis.Text = "⏳ Analyzing ETR..."
        
        try {
            $riskyIPs = @()
            $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
            if (Test-Path $signInDataPath) {
                try {
                    $signInData = Import-Csv -Path $signInDataPath
                    $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" -and -not [string]::IsNullOrEmpty($_.IP) } | 
                               Select-Object -ExpandProperty IP -Unique
                    Write-Log "Using $($riskyIPs.Count) risky IPs for ETR correlation" -Level "Info"
                } catch {
                    Write-Log "Could not load sign-in data for IP correlation: $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            $result = Analyze-ETRData -RiskyIPs $riskyIPs
            if ($result) {
                $criticalCount = ($result | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                $highCount = ($result | Where-Object { $_.RiskLevel -eq "High" }).Count
                Update-GuiStatus "✅ ETR analysis completed! Found $criticalCount critical and $highCount high-risk patterns." (Get-ThemeColor -ColorName "Success")
            }
        }
        finally {
            $btnETRAnalysis.Enabled = $true
            $btnETRAnalysis.Text = $originalText
        }
    }
    $form.Controls.Add($btnETRAnalysis)

    $btnMessageTrace = New-GuiButton -text "📧 Collect Message Trace" -x 615 -y 413 -width 185 -height 38 `
        -ColorType "Accent" -action {
        $btnMessageTrace.Enabled = $false
        $originalText = $btnMessageTrace.Text
        $btnMessageTrace.Text = "⏳ Running Trace..."
        
        try {
            $result = Get-MessageTraceExchangeOnline
            if ($result) {
                Update-GuiStatus "✅ Message trace collected! Processed $($result.Count) messages." (Get-ThemeColor -ColorName "Success")
                
                $runAnalysis = [System.Windows.Forms.MessageBox]::Show(
                    "Message trace collection complete!`n`n$($result.Count) messages saved.`n`nRun ETR analysis now?",
                    "Run Analysis?",
                    "YesNo",
                    "Question"
                )
                
                if ($runAnalysis -eq "Yes") {
                    $riskyIPs = @()
                    $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
                    if (Test-Path $signInDataPath) {
                        try {
                            $signInData = Import-Csv -Path $signInDataPath
                            $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" } | 
                                       Select-Object -ExpandProperty IP -Unique
                        } catch { }
                    }
                    Analyze-ETRData -RiskyIPs $riskyIPs
                }
            }
        }
        finally {
            $btnMessageTrace.Enabled = $true
            $btnMessageTrace.Text = $originalText
        }
    }
    $form.Controls.Add($btnMessageTrace)

    #──────────────────────────────────────────────────────────────
    # ROW 4: BULK OPERATIONS WITH EMOJIS
    #──────────────────────────────────────────────────────────────

    # Section header for Analysis & Operations
    $operationsHeader = New-Object System.Windows.Forms.Label
    $operationsHeader.Text = "🔬 Analysis & Operations"
    $operationsHeader.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 10, [System.Drawing.FontStyle]::Bold)
    $operationsHeader.ForeColor = Get-ThemeColor -ColorName "Warning"
    $operationsHeader.Size = New-Object System.Drawing.Size(780, 25)
    $operationsHeader.Location = New-Object System.Drawing.Point(30, 466)
    $form.Controls.Add($operationsHeader)

    $btnRunAll = New-GuiButton -text "🚀 Run All Data Collection" -x 30 -y 493 -width 245 -height 45 `
        -ColorType "Warning" -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "❌ Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }
        
        $btnRunAll.Enabled = $false
        $originalText = $btnRunAll.Text
        
        $tasks = @(
            @{Name="Sign-In Data"; Function="Get-TenantSignInData"},
            @{Name="Admin Audits"; Function="Get-AdminAuditData"},
            @{Name="Inbox Rules"; Function="Get-MailboxRules"},
            @{Name="MFA Status Audit"; Function="Get-MFAStatusAudit"},
            @{Name="Failed Login Analysis"; Function="Get-FailedLoginPatterns"},
            @{Name="Password Change Analysis"; Function="Get-RecentPasswordChanges"}
            @{Name="Delegations"; Function="Get-MailboxDelegationData"},
            @{Name="App Registrations"; Function="Get-AppRegistrationData"},
            @{Name="Conditional Access"; Function="Get-ConditionalAccessData"},
            @{Name="Message Trace"; Function="Get-MessageTraceExchangeOnline"},
            @{Name="ETR Analysis"; Function="Analyze-ETRData"}
        )
        $completed = 0
        
        Update-GuiStatus "⏳ Starting comprehensive data collection..." (Get-ThemeColor -ColorName "Warning")
        
        foreach ($task in $tasks) {
            $btnRunAll.Text = "⏳ Running: $($task.Name)..."
            Update-GuiStatus "⏳ Executing: $($task.Name)..." (Get-ThemeColor -ColorName "Warning")
            
            try {
                switch ($task.Function) {
                    "Get-TenantSignInData" { Get-TenantSignInData | Out-Null }
                    "Get-AdminAuditData" { Get-AdminAuditData | Out-Null }
                    "Get-MailboxRules" { Get-MailboxRules | Out-Null }
                    "Get-MFAStatusAudit" { Get-MFAStatusAudit | Out-Null }
                    "Get-FailedLoginPatterns" { Get-FailedLoginPatterns | Out-Null }
                    "Get-RecentPasswordChanges" { Get-RecentPasswordChanges | Out-Null }
                    "Get-MailboxDelegationData" { Get-MailboxDelegationData | Out-Null }
                    "Get-AppRegistrationData" { Get-AppRegistrationData | Out-Null }
                    "Get-ConditionalAccessData" { Get-ConditionalAccessData | Out-Null }
                    "Get-MessageTraceExchangeOnline" { Get-MessageTraceExchangeOnline | Out-Null }
                    "Analyze-ETRData" { 
                        $riskyIPs = @()
                        $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
                        if (Test-Path $signInDataPath) {
                            try {
                                $signInData = Import-Csv -Path $signInDataPath
                                $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" } | 
                                           Select-Object -ExpandProperty IP -Unique
                            } catch { }
                        }
                        Analyze-ETRData -RiskyIPs $riskyIPs | Out-Null 
                    }
                }
                $completed++
                Update-GuiStatus "✅ Completed: $($task.Name) ($completed/$($tasks.Count))" (Get-ThemeColor -ColorName "Success")
            }
            catch {
                Write-Log "Error in $($task.Name): $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "❌ Error in $($task.Name): $($_.Exception.Message)" (Get-ThemeColor -ColorName "Danger")
            }
        }
        
        $btnRunAll.Enabled = $true
        $btnRunAll.Text = $originalText
        Update-GuiStatus "✅ Data collection completed! Finished $completed of $($tasks.Count) tasks." (Get-ThemeColor -ColorName "Success")
        
        [System.Windows.Forms.MessageBox]::Show(
            "Data collection completed!`n`nFinished $completed out of $($tasks.Count) tasks successfully.",
            "Collection Complete",
            "OK",
            "Information"
        )
    }
    $form.Controls.Add($btnRunAll)

    $btnAnalyze = New-GuiButton -text "🔎 Analyze Data" -x 290 -y 493 -width 180 -height 45 `
        -ColorType "Danger" -action {
        $btnAnalyze.Enabled = $false
        $originalText = $btnAnalyze.Text
        $btnAnalyze.Text = "⏳ Analyzing..."
        
        $reportPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "SecurityReport.html"
        
        try {
            Update-GuiStatus "⏳ Starting comprehensive security analysis..." (Get-ThemeColor -ColorName "Warning")
            $results = Invoke-CompromiseDetection -ReportPath $reportPath
            
            if ($results) {
                $critical = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                $high = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
                $medium = ($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
                
                Update-GuiStatus "✅ Analysis completed - $critical critical, $high high, $medium medium risk users" (Get-ThemeColor -ColorName "Success")
                
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Security Analysis Completed!`n`n" +
                    "Risk Summary:`n• Critical Risk: $critical users`n• High Risk: $high users`n• Medium Risk: $medium users`n`n" +
                    "Total Users Analyzed: $($results.Count)`n`nOpen the detailed HTML report now?",
                    "Analysis Complete",
                    "YesNo",
                    "Information"
                )
                
                if ($result -eq "Yes") {
                    Start-Process $reportPath
                }
            } else {
                Update-GuiStatus "❌ Analysis failed - no data available" (Get-ThemeColor -ColorName "Danger")
                [System.Windows.Forms.MessageBox]::Show(
                    "Analysis failed or no data available.`n`nPlease ensure you have collected data first.",
                    "Analysis Failed",
                    "OK",
                    "Warning"
                )
            }
        }
        finally {
            $btnAnalyze.Enabled = $true
            $btnAnalyze.Text = $originalText
        }
    }
    $form.Controls.Add($btnAnalyze)

    $btnViewReports = New-GuiButton -text "📊 View Reports" -x 485 -y 493 -width 155 -height 45 `
        -ColorType "Accent" -action {
        Update-GuiStatus "🔍 Looking for reports in working directory..." (Get-ThemeColor -ColorName "Warning")
        
        $reports = Get-ChildItem -Path $ConfigData.WorkDir -Filter "*.html" -ErrorAction SilentlyContinue
        
        if ($reports.Count -eq 0) {
            Update-GuiStatus "⚠️ No reports found in working directory" (Get-ThemeColor -ColorName "Warning")
            [System.Windows.Forms.MessageBox]::Show(
                "No HTML reports found in the working directory:`n$($ConfigData.WorkDir)`n`n" +
                "Please run the analysis first to generate reports.",
                "No Reports Found",
                "OK",
                "Information"
            )
            return
        }
        
        if ($reports.Count -eq 1) {
            Update-GuiStatus "✅ Opening report: $($reports[0].Name)" (Get-ThemeColor -ColorName "Success")
            Start-Process $reports[0].FullName
        } else {
            $reportForm = New-Object System.Windows.Forms.Form
            $reportForm.Text = "Select Report to Open"
            $reportForm.Size = New-Object System.Drawing.Size(600, 400)
            $reportForm.StartPosition = "CenterParent"
            $reportForm.FormBorderStyle = "FixedDialog"
            $reportForm.MaximizeBox = $false
            $reportForm.MinimizeBox = $false
            $reportForm.BackColor = Get-ThemeColor -ColorName "Background"
            
            $reportLabel = New-Object System.Windows.Forms.Label
            $reportLabel.Text = "📊 Select a report to open:"
            $reportLabel.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 10, [System.Drawing.FontStyle]::Bold)
            $reportLabel.Size = New-Object System.Drawing.Size(560, 30)
            $reportLabel.Location = New-Object System.Drawing.Point(20, 20)
            $reportLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
            $reportForm.Controls.Add($reportLabel)
            
            $listBox = New-Object System.Windows.Forms.ListBox
            $listBox.Size = New-Object System.Drawing.Size(560, 280)
            $listBox.Location = New-Object System.Drawing.Point(20, 50)
            $listBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $listBox.BackColor = Get-ThemeColor -ColorName "Surface"
            $listBox.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
            
            foreach ($report in $reports) {
                $item = "$($report.Name) ($(Get-Date $report.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))"
                $listBox.Items.Add($item) | Out-Null
            }
            
            $reportForm.Controls.Add($listBox)
            
            $buttonPanel = New-Object System.Windows.Forms.Panel
            $buttonPanel.Size = New-Object System.Drawing.Size(560, 50)
            $buttonPanel.Location = New-Object System.Drawing.Point(20, 340)
            $buttonPanel.BackColor = Get-ThemeColor -ColorName "Background"
            $reportForm.Controls.Add($buttonPanel)
            
            $openBtn = New-Object System.Windows.Forms.Button
            $openBtn.Text = "✅ Open Selected Report"
            $openBtn.Size = New-Object System.Drawing.Size(180, 35)
            $openBtn.Location = New-Object System.Drawing.Point(270, 10)
            $openBtn.BackColor = Get-ThemeColor -ColorName "Primary"
            $openBtn.ForeColor = [System.Drawing.Color]::White
            $openBtn.FlatStyle = "Flat"
            $openBtn.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9, [System.Drawing.FontStyle]::Bold)
            $openBtn.Add_Click({
                if ($listBox.SelectedIndex -ge 0) {
                    Start-Process $reports[$listBox.SelectedIndex].FullName
                    $reportForm.Close()
                }
            })
            $buttonPanel.Controls.Add($openBtn)
            
            $cancelBtn = New-Object System.Windows.Forms.Button
            $cancelBtn.Text = "❌ Cancel"
            $cancelBtn.Size = New-Object System.Drawing.Size(100, 35)
            $cancelBtn.Location = New-Object System.Drawing.Point(460, 10)
            $cancelBtn.BackColor = Get-ThemeColor -ColorName "Secondary"
            $cancelBtn.ForeColor = [System.Drawing.Color]::White
            $cancelBtn.FlatStyle = "Flat"
            $cancelBtn.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9, [System.Drawing.FontStyle]::Bold)
            $cancelBtn.Add_Click({ $reportForm.Close() })
            $buttonPanel.Controls.Add($cancelBtn)
            
            [void]$reportForm.ShowDialog()
        }
    }
    $form.Controls.Add($btnViewReports)

    $btnExit = New-GuiButton -text "🚪 Exit Application" -x 655 -y 493 -width 145 -height 45 `
        -ColorType "Secondary" -action {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to exit the application?`n`n" +
            "This will disconnect from Microsoft Graph and close the tool.",
            "Confirm Exit",
            "YesNo",
            "Question"
        )
        
        if ($result -eq "Yes") {
            Update-GuiStatus "⏳ Shutting down application..." (Get-ThemeColor -ColorName "Warning")
            
            if ($Global:ConnectionState.IsConnected) {
                Disconnect-GraphSafely
            }
            
            try {
                Stop-Transcript -ErrorAction SilentlyContinue
            }
            catch { }
            
            $form.Close()
        }
    }
    $form.Controls.Add($btnExit)

    #──────────────────────────────────────────────────────────────
    # FORM EVENT HANDLERS
    #──────────────────────────────────────────────────────────────
    
    $form.Add_FormClosing({
        param($sender, $e)
        
        try {
            if ($Global:ConnectionState.IsConnected) {
                Update-GuiStatus "⏳ Form closing - disconnecting from Microsoft Graph..." (Get-ThemeColor -ColorName "Warning")
                Disconnect-GraphSafely
            }
            
            try {
                Stop-Transcript -ErrorAction SilentlyContinue
            }
            catch { }
            
            Write-Log "Application closed successfully" -Level "Info"
        }
        catch {
            Write-Log "Error during form cleanup: $($_.Exception.Message)" -Level "Warning"
        }
    })

    $form.Add_FormClosed({
        try {
            if (Get-MgContext -ErrorAction SilentlyContinue) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
        }
        catch { }
    })

    $form.Add_Shown({
        Test-ExistingGraphConnection | Out-Null
        Update-ConnectionStatus
        
        $versionCheck = Test-ScriptVersion -ShowMessageBox $false
        if ($versionCheck.IsLatest -eq $false) {
            Test-ScriptVersion -ShowMessageBox $true
        }
        
        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "✅ Application ready - Using existing Microsoft Graph connection" (Get-ThemeColor -ColorName "Success")
        } else {
            Update-GuiStatus "⚠️ Application ready - Please connect to Microsoft Graph to begin" (Get-ThemeColor -ColorName "Warning")
        }
    })

    #──────────────────────────────────────────────────────────────
    # SHOW THE FORM
    #──────────────────────────────────────────────────────────────
    
    [void]$form.ShowDialog()
}

#endregion

#################################################################
#
#  SECTION 6: MAIN EXECUTION
#
#################################################################

#region MAIN EXECUTION

#══════════════════════════════════════════════════════════════
# SCRIPT INITIALIZATION
#══════════════════════════════════════════════════════════════

Show-YWBanner

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ Microsoft 365 Security Analysis Tool - Yeyland Wutani Edition  ║" -ForegroundColor Cyan
Write-Host ("║ Version {0,-55}║" -f $ScriptVer) -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""



# Initialize environment
Write-Host "Initializing environment..." -ForegroundColor Yellow
Initialize-Environment

Write-Log "Starting Enhanced Microsoft 365 Security Analysis Tool v$ScriptVer" -Level "Info"
Write-Log "Enhanced features: Improved sign-in processing, detailed GUI progress, clean Graph disconnection, tenant context display" -Level "Info"
Write-Log "Data collection capabilities: Sign-ins, Admin Audits, Inbox Rules, Delegations, App Registrations, Conditional Access, Message Trace, ETR Analysis" -Level "Info"

#══════════════════════════════════════════════════════════════
# DISPLAY MAIN GUI
#══════════════════════════════════════════════════════════════

Write-Host "Launching graphical user interface..." -ForegroundColor Yellow
Write-Host ""
Write-Host "The GUI window should appear shortly. If not, check for:" -ForegroundColor Gray
Write-Host "  • Windows Forms assembly loading issues" -ForegroundColor Gray
Write-Host "  • PowerShell execution policy restrictions" -ForegroundColor Gray
Write-Host "  • Antivirus or security software blocking" -ForegroundColor Gray
Write-Host ""

Show-MainGUI

#══════════════════════════════════════════════════════════════
# FINAL CLEANUP
#══════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "Performing final cleanup..." -ForegroundColor Yellow
Write-Log "Performing final cleanup..." -Level "Info"

# Ensure clean disconnect from Microsoft Graph
try {
    if ($Global:ConnectionState.IsConnected -or (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Log "Final disconnect from Microsoft Graph" -Level "Info"
        Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected successfully" -ForegroundColor Green
    }
}
catch {
    Write-Log "Final cleanup warning: $($_.Exception.Message)" -Level "Warning"
    Write-Host "⚠ Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Ensure clean disconnect from Exchange Online
try {
    $exchangeSession = Get-PSSession | Where-Object { 
        $_.ConfigurationName -eq "Microsoft.Exchange" -and 
        $_.State -eq "Opened" 
    }
    
    if ($exchangeSession) {
        Write-Log "Final disconnect from Exchange Online" -Level "Info"
        Write-Host "Disconnecting from Exchange Online..." -ForegroundColor Yellow
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected successfully" -ForegroundColor Green
    }
}
catch {
    Write-Log "Exchange Online cleanup warning: $($_.Exception.Message)" -Level "Warning"
    Write-Host "⚠ Exchange cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Stop transcript
try {
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "✓ Script execution completed. Log file saved to working directory." -ForegroundColor Green
    Write-Host "  Log location: $($ConfigData.WorkDir)" -ForegroundColor Gray
}
catch {
    Write-Host ""
    Write-Host "✓ Script execution completed." -ForegroundColor Green
}

# Display final summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                     Script Execution Summary                   ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host ("║  Working Directory: {0,-43}║" -f $ConfigData.WorkDir) -ForegroundColor Cyan
Write-Host ("║  Date Range: {0,-50}║" -f "$($ConfigData.DateRange) days") -ForegroundColor Cyan
Write-Host ("║  Script Version:{0,-47}║" -f $ScriptVer) -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Thank you for using the Microsoft 365 Security Analysis Tool!" -ForegroundColor Green
Write-Host "For support or updates, visit: https://github.com/the-last-one-left/YeylandWutani" -ForegroundColor Gray
Write-Host ""


#endregion

#################################################################
#
#  END OF SCRIPT
#
#  Script completed successfully
#
#################################################################
