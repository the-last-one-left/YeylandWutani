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
#  | - Sign-in logs with geolocation analysis (interactive by    |
#  |   default; non-interactive with -IncludeNonInteractive)     |
#  | - Admin audit logs with risk assessment (Entra directory)   |
#  | - Inbox rules from ALL user and shared mailboxes, hidden    |
#  |   rules included, external forwarding by accepted domain    |
#  | - Mailbox delegations (FullAccess, SendAs, SendOnBehalf)    |
#  | - App registrations AND consented third-party enterprise    |
#  |   apps, risk by resolved permission name                    |
#  | - Conditional Access policies                               |
#  | - MFA status audit (per-user, CA, Security Defaults, roles) |
#  | - Exchange message traces (ETR format, paged)               |
#  +-------------------------------------------------------------+
#
#  DATA COVERAGE:
#  Each collector records its gaps (skipped mailboxes, truncated
#  pulls, fallback sources, unreadable APIs) in CollectionStatus.csv
#  in the working directory. The analysis step reads it back and
#  shows every gap, plus stale or missing sources, in the log and
#  in the Data Coverage section of the HTML report. A collector
#  removes its own previous output before writing, so a run that
#  finds nothing cannot leave old data behind as current.
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
#  - PowerShell 7.0 or later (PowerShell 5.1 is NOT supported)
#  - Microsoft.Graph.* modules (auto-installed if missing)
#  - ExchangeOnlineManagement module (auto-installed if missing)
#  - Administrative permissions in Microsoft 365 tenant:
#    - Global Administrator, Security Administrator, or
#    - Security Reader + Exchange Administrator (recommended minimum)
#    - Exchange Administrator (or Mail Recipients role) is REQUIRED for
#      inbox rules, delegations and message trace. Get-InboxRule does
#      not work for Global Reader or View-Only Organization Management.
#    - Entra ID P2 (PIM) is needed to see eligible admin assignments;
#      without it the MFA audit reports that eligible admins are not
#      included.
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
# Record every change in Security/CHANGELOG-Get-M365SecurityAnalysis.md
$ScriptVer = "12.0"

#--------------------------------------------------------------
# POWERSHELL VERSION CHECK
#--------------------------------------------------------------
# PowerShell 7.0+ is required due to Microsoft Graph SDK compatibility issues
# PowerShell 5.1 is NOT supported (Graph SDK v2.34.0+ breaks in PS 5.1)
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $errorMessage = @"
╔════════════════════════════════════════════════════════════════╗
║  UNSUPPORTED POWERSHELL VERSION                                 ║
╠════════════════════════════════════════════════════════════════╣
║                                                                 ║
║  This script requires PowerShell 7.0 or later.                  ║
║  You are running: PowerShell $($PSVersionTable.PSVersion)                        ║
║                                                                 ║
║  PowerShell 5.1 is NOT supported due to Microsoft Graph SDK     ║
║  compatibility issues (v2.34.0+ breaks in PS 5.1).             ║
║                                                                 ║
║  TO INSTALL POWERSHELL 7:                                       ║
║  1. Visit: https://aka.ms/install-powershell                    ║
║  2. Or run: winget install Microsoft.PowerShell                 ║
║                                                                 ║
║  After installing, run this script in PowerShell 7.             ║
║                                                                 ║
╚════════════════════════════════════════════════════════════════╝
"@
    Write-Host $errorMessage -ForegroundColor Red

    # Show GUI message if possible
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.MessageBox]::Show(
            "This script requires PowerShell 7.0 or later.`n`n" +
            "You are running PowerShell $($PSVersionTable.PSVersion)`n`n" +
            "Please install PowerShell 7 from:`nhttps://aka.ms/install-powershell",
            "Unsupported PowerShell Version",
            "OK",
            "Error"
        )
    } catch {
        # GUI not available, console message already shown
    }

    exit 1
}

#--------------------------------------------------------------
# CLEANUP EXISTING GRAPH MODULES
#--------------------------------------------------------------
# Remove any Graph modules already loaded to prevent version conflicts
# This must happen before anything else to avoid "assembly already loaded" errors
Write-Host "[STARTUP] Checking for pre-loaded Graph modules and assemblies..." -ForegroundColor Cyan

# Check for PowerShell modules
$preloadedModules = Get-Module -Name "Microsoft.Graph*" -ErrorAction SilentlyContinue

# Check for loaded .NET assemblies (more thorough)
$loadedGraphAssemblies = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.FullName -like "Microsoft.Graph.*" } |
    Select-Object -ExpandProperty FullName

if ($preloadedModules -or $loadedGraphAssemblies) {
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  ERROR: Graph modules already loaded in this session      ║" -ForegroundColor Red
    Write-Host "  ╚════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    if ($preloadedModules) {
        Write-Host "  Found $($preloadedModules.Count) pre-loaded PowerShell module(s):" -ForegroundColor Yellow
        foreach ($mod in $preloadedModules) {
            Write-Host "    - $($mod.Name) v$($mod.Version)" -ForegroundColor Yellow
        }
    }
    if ($loadedGraphAssemblies) {
        Write-Host "  Found $($loadedGraphAssemblies.Count) pre-loaded .NET assembly(ies):" -ForegroundColor Yellow
        foreach ($asm in $loadedGraphAssemblies) {
            Write-Host "    - $asm" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "  Once Graph modules are loaded, .NET assemblies cannot be unloaded" -ForegroundColor Yellow
    Write-Host "  without restarting PowerShell. This causes 'assembly already loaded' errors." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  QUICK WORKAROUND (run script with -NoProfile):" -ForegroundColor Cyan
    Write-Host "    pwsh -NoProfile -File .\$(Split-Path -Leaf $PSCommandPath)" -ForegroundColor White
    Write-Host ""
    Write-Host "  PERMANENT FIX:" -ForegroundColor Cyan
    Write-Host "  1. Close this PowerShell window completely" -ForegroundColor White
    Write-Host "  2. Open a NEW PowerShell 7 window" -ForegroundColor White
    Write-Host "  3. Check for Graph modules in old Windows PowerShell path:" -ForegroundColor White
    Write-Host "       Get-Module Microsoft.Graph* -ListAvailable | Where Path -like '*WindowsPowerShell*'" -ForegroundColor Gray
    Write-Host "  4. If found, uninstall them:" -ForegroundColor White
    Write-Host "       Get-InstalledModule Microsoft.Graph* | Where InstalledLocation -like '*WindowsPowerShell*' | Uninstall-Module -AllVersions -Force" -ForegroundColor Gray
    Write-Host "  5. Restart PowerShell and run script normally" -ForegroundColor White
    Write-Host ""
    Write-Host "  Also check your PowerShell profile (if it exists):" -ForegroundColor Cyan
    Write-Host "    Profile location: $PROFILE" -ForegroundColor Gray
    Write-Host "    Remove any 'Import-Module Microsoft.Graph*' commands" -ForegroundColor Gray
    Write-Host ""

    Read-Host "Press Enter to exit"
    exit 1
} else {
    Write-Host "  No pre-loaded modules found - safe to proceed" -ForegroundColor Green
}

# Note: v2.34.0 check removed - was a PowerShell 5.1 issue
# Now that we require PowerShell 7.0+, we can use the latest Graph SDK versions
Write-Host "[STARTUP] PowerShell 7.0+ detected - ready to use latest Graph SDK" -ForegroundColor Green

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
    LastCollectionComplete = $true   # Did the most recent EXO data pull cover the full date range?
    LastCollectionWarning  = $null   # Human-readable note describing any gaps in the last pull
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

# Load System.Drawing assembly for PowerShell 5.1 compatibility
# Required for color definitions below
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

# Theme Color Configuration
$script:ThemeColors = @{
    # Yeyland Wutani tokens. Neutral surfaces with a 1px hairline border; brand orange is reserved
    # for the primary action and accents. Text on an orange fill is OnPrimary (white on orange fails
    # contrast). Secondary and Accent are kept for older callers but no longer used for button fills.
    Light = @{
        Primary         = [System.Drawing.ColorTranslator]::FromHtml("#E85D00")   # Brand orange
        OnPrimary       = [System.Drawing.ColorTranslator]::FromHtml("#1A0D00")   # Text on orange fills
        Secondary       = [System.Drawing.Color]::FromArgb(107, 114, 128)         # Yeyland Wutani grey
        Accent          = [System.Drawing.Color]::FromArgb(255, 152, 0)           # Orange
        Success         = [System.Drawing.ColorTranslator]::FromHtml("#1F7A4D")   # Connected, done, low
        Warning         = [System.Drawing.ColorTranslator]::FromHtml("#B45F00")   # High
        Danger          = [System.Drawing.ColorTranslator]::FromHtml("#C62828")   # Critical, errors
        Medium          = [System.Drawing.ColorTranslator]::FromHtml("#8A6D00")   # Medium risk
        Ai              = [System.Drawing.ColorTranslator]::FromHtml("#4B45C4")   # AI button fill
        Background      = [System.Drawing.ColorTranslator]::FromHtml("#F3F1ED")   # Form
        Surface         = [System.Drawing.ColorTranslator]::FromHtml("#FFFFFF")   # Cards, status bar
        Surface2        = [System.Drawing.ColorTranslator]::FromHtml("#F7F5F1")   # Hover fill
        TextPrimary     = [System.Drawing.ColorTranslator]::FromHtml("#1B1D21")
        TextSecondary   = [System.Drawing.ColorTranslator]::FromHtml("#5F6670")
        Border          = [System.Drawing.ColorTranslator]::FromHtml("#E2DED6")
    }

    Dark = @{
        Primary         = [System.Drawing.ColorTranslator]::FromHtml("#FF6600")
        OnPrimary       = [System.Drawing.ColorTranslator]::FromHtml("#1A0D00")
        Secondary       = [System.Drawing.Color]::FromArgb(125, 133, 148)
        Accent          = [System.Drawing.Color]::FromArgb(255, 167, 38)
        Success         = [System.Drawing.ColorTranslator]::FromHtml("#4CC38A")
        Warning         = [System.Drawing.ColorTranslator]::FromHtml("#FFA033")
        Danger          = [System.Drawing.ColorTranslator]::FromHtml("#FF5C5C")
        Medium          = [System.Drawing.ColorTranslator]::FromHtml("#F2C94C")
        Ai              = [System.Drawing.ColorTranslator]::FromHtml("#5B55D6")
        Background      = [System.Drawing.ColorTranslator]::FromHtml("#0C0E11")
        Surface         = [System.Drawing.ColorTranslator]::FromHtml("#14171B")
        Surface2        = [System.Drawing.ColorTranslator]::FromHtml("#1B1F25")
        TextPrimary     = [System.Drawing.ColorTranslator]::FromHtml("#ECEFF3")
        TextSecondary   = [System.Drawing.ColorTranslator]::FromHtml("#98A1AE")
        Border          = [System.Drawing.ColorTranslator]::FromHtml("#282D35")
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
        [ValidateSet("Primary", "OnPrimary", "Secondary", "Accent", "Success", "Warning", "Danger",
                     "Medium", "Ai", "Background", "Surface", "Surface2", "TextPrimary", "TextSecondary", "Border")]
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

    # Apply theme to GUI if the form exists
    # NOTE: use $Global:MainForm — $script:MainForm is never set
    if ($Global:MainForm) {
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
        Applies the current theme colors to all GUI elements.
        Uses $Global:MainForm (the correct scope — $script:MainForm was never set).
    #>

    if (-not $Global:MainForm) { return }

    try {
        # Update form background
        $Global:MainForm.BackColor = Get-ThemeColor -ColorName "Background"

        # Recursively update all controls
        function Update-ControlColors {
            param ($Control)

            foreach ($child in $Control.Controls) {

                # -- Buttons --
                if ($child -is [System.Windows.Forms.Button]) {
                    if ($child.Tag -and $child.Tag.ColorType) {
                        # Legacy themed button (New-GuiButton): re-derive colors from the current theme
                        $newBg = Get-ThemeColor -ColorName $child.Tag.ColorType
                        $newBorder = [System.Drawing.Color]::FromArgb(
                            [Math]::Max(0, $newBg.R - 25),
                            [Math]::Max(0, $newBg.G - 25),
                            [Math]::Max(0, $newBg.B - 25)
                        )
                        $child.BackColor = $newBg
                        $child.FlatAppearance.BorderColor = $newBorder
                        $child.Tag = [PSCustomObject]@{
                            BgColor     = $newBg
                            BorderColor = $newBorder
                            ColorType   = $child.Tag.ColorType
                        }
                    }
                    elseif ($child.Tag -and "$($child.Tag.Variant)" -like "Flat*") {
                        # Neutral / primary flat buttons (theme toggle, dialog buttons)
                        Set-GuiFlatButtonColors -Button $child
                    }
                }

                # -- Panels --
                elseif ($child -is [System.Windows.Forms.Panel]) {
                    if ($child.Tag -is [string] -and $child.Tag -eq "separator") {
                        # Hairline separators use Border color, not Surface
                        $child.BackColor = Get-ThemeColor -ColorName "Border"
                    }
                    elseif ($child.Tag -and $child.Tag.BackRole) {
                        # Self-painting controls (cards, tiles, pill, session block, status bar) read
                        # their colors at paint time; only the backdrop and a repaint are needed
                        $child.BackColor = Get-ThemeColor -ColorName $child.Tag.BackRole
                        $child.Invalidate()
                    }
                    else {
                        $child.BackColor = Get-ThemeColor -ColorName "Surface"
                        # Force repaint so custom Paint-event borders redraw
                        $child.Invalidate()
                    }
                }

                # -- Labels: Tag.ColorName pins a theme color; untagged labels are body text --
                elseif ($child -is [System.Windows.Forms.Label]) {
                    if ($child.Tag -and $child.Tag.ColorName) {
                        $child.ForeColor = Get-ThemeColor -ColorName $child.Tag.ColorName
                    }
                    # Legacy labels tagged with a semantic color name carry intentional color - skip them
                    elseif (-not $child.Tag -or $child.Tag -notmatch "^(Primary|Secondary|Accent|Success|Warning|Danger)$") {
                        $child.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
                    }
                }

                # -- CheckBoxes --
                elseif ($child -is [System.Windows.Forms.CheckBox]) {
                    $child.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
                }

                # Recurse into nested controls
                if ($child.Controls.Count -gt 0) {
                    Update-ControlColors -Control $child
                }
            }
        }

        Update-ControlColors -Control $Global:MainForm

        # Re-apply connection/tenant label colors (they have intentional colors)
        Update-ConnectionStatus

        # Refresh the form
        $Global:MainForm.Refresh()
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

    # White text on all colored buttons
    $button.ForeColor = [System.Drawing.Color]::White

    # Flat modern style
    $button.FlatStyle = "Flat"
    $button.FlatAppearance.BorderSize = 1

    # Subtle darker border for depth (no heavy outline)
    $baseColor = Get-ThemeColor -ColorName $ColorType
    $darkerColor = [System.Drawing.Color]::FromArgb(
        [Math]::Max(0, $baseColor.R - 25),
        [Math]::Max(0, $baseColor.G - 25),
        [Math]::Max(0, $baseColor.B - 25)
    )
    $button.FlatAppearance.BorderColor = $darkerColor

    # Segoe UI Emoji required — "Segoe UI" alone does not render emoji glyphs
    $button.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 9, [System.Drawing.FontStyle]::Bold)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand

    # Tag stores colors for hover restore AND ColorType for theme switching
    $button.Tag = [PSCustomObject]@{
        BgColor     = $button.BackColor
        BorderColor = $darkerColor
        ColorType   = $ColorType
    }

    # Subtle hover: +25 brightness, slightly lighter border — no white glow
    $button.Add_MouseEnter({
        if ($this.Tag -and $this.Tag.BgColor) {
            $orig = $this.Tag.BgColor
            $this.BackColor = [System.Drawing.Color]::FromArgb(
                [Math]::Min(255, $orig.R + 25),
                [Math]::Min(255, $orig.G + 25),
                [Math]::Min(255, $orig.B + 25)
            )
            $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(
                [Math]::Min(255, $orig.R + 60),
                [Math]::Min(255, $orig.G + 60),
                [Math]::Min(255, $orig.B + 60)
            )
        }
    })

    # Restore both BackColor AND BorderColor on leave
    $button.Add_MouseLeave({
        if ($this.Tag -and $this.Tag.BgColor) {
            $this.BackColor     = $this.Tag.BgColor
            $this.FlatAppearance.BorderColor = $this.Tag.BorderColor
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

#--------------------------------------------------------------
# GUI PRIMITIVES: fonts, colors, glyphs, card buttons, collector tiles
#--------------------------------------------------------------
# The main window is built from neutral surfaces with a hairline border and a single orange
# fill for the primary action of each step. Cards, tiles and the connection pill paint
# themselves (rounded rectangle via GraphicsPath) and read their colors from the theme at
# paint time, so a theme switch only has to Invalidate() them.
#
# Glyphs are built from code points so this section stays ASCII-only.
$script:GlyphDot      = [string][char]0x00B7   # middle dot
$script:GlyphBullet   = [string][char]0x25CF   # black circle
$script:GlyphSparkle  = [string][char]0x2726   # four pointed star (AI button)
$script:GlyphEllipsis = [string][char]0x2026

$script:GuiFontCache = @{}
$script:TilePulseHigh = $true

function Get-GuiFont {
    <#
    .SYNOPSIS
        Returns a cached Font. Paint handlers run constantly; creating a Font per paint leaks GDI handles.
    #>
    param (
        [string]$Family = "Segoe UI",
        [double]$Size = 9,
        [string]$Style = "Regular"
    )

    $key = "$Family|$Size|$Style"
    if (-not $script:GuiFontCache.ContainsKey($key)) {
        $script:GuiFontCache[$key] = New-Object System.Drawing.Font($Family, [single]$Size, [System.Drawing.FontStyle]$Style)
    }
    return $script:GuiFontCache[$key]
}

function Get-BlendedColor {
    <#
    .SYNOPSIS
        Mixes two colors. Amount 0 returns From, 1 returns To.
    #>
    param (
        [System.Drawing.Color]$From,
        [System.Drawing.Color]$To,
        [double]$Amount
    )

    $mix = { param($a, $b) [int][Math]::Round($a + (($b - $a) * $Amount)) }
    return [System.Drawing.Color]::FromArgb(
        (& $mix $From.R $To.R),
        (& $mix $From.G $To.G),
        (& $mix $From.B $To.B)
    )
}

function New-GuiRoundedPath {
    param (
        [System.Drawing.RectangleF]$Rect,
        [single]$Radius
    )

    $diameter = [Math]::Min([double]($Radius * 2), [Math]::Min($Rect.Width, $Rect.Height))
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    if ($diameter -le 0) {
        $path.AddRectangle($Rect)
        return $path
    }
    $d = [single]$diameter
    $path.AddArc($Rect.X, $Rect.Y, $d, $d, 180, 90)
    $path.AddArc(($Rect.Right - $d), $Rect.Y, $d, $d, 270, 90)
    $path.AddArc(($Rect.Right - $d), ($Rect.Bottom - $d), $d, $d, 0, 90)
    $path.AddArc($Rect.X, ($Rect.Bottom - $d), $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

function Enable-GuiPaintStyle {
    <#
    .SYNOPSIS
        Double-buffers a self-painting Panel and makes it focusable (both are protected members).
    #>
    param (
        [System.Windows.Forms.Control]$Control
    )

    $flags = [System.Reflection.BindingFlags]"Instance,NonPublic"
    [void]$Control.GetType().GetProperty("DoubleBuffered", $flags).SetValue($Control, $true)
    [void]$Control.GetType().GetMethod("SetStyle", $flags).Invoke($Control, @([System.Windows.Forms.ControlStyles]::Selectable, $true))
}

function Invoke-GuiControlClick {
    param (
        [System.Windows.Forms.Control]$Control
    )

    $flags = [System.Reflection.BindingFlags]"Instance,NonPublic"
    [void]$Control.GetType().GetMethod("OnClick", $flags).Invoke($Control, @([System.EventArgs]::Empty))
}

function Invoke-GuiCardPaint {
    param (
        [System.Windows.Forms.Control]$Control,
        [System.Drawing.Graphics]$Graphics
    )

    $state = $Control.Tag
    $scale = $Control.DeviceDpi / 96.0
    $Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $enabled = $Control.Enabled
    $hover = $state.Hover -and $enabled
    $pressed = $state.Pressed -and $enabled

    switch ($state.Variant) {
        "Primary" {
            $fill = Get-ThemeColor -ColorName "Primary"
            if ($pressed) { $fill = Get-BlendedColor $fill ([System.Drawing.Color]::Black) 0.08 }
            elseif ($hover) { $fill = Get-BlendedColor $fill ([System.Drawing.Color]::White) 0.08 }
            $border = $fill
            $fore = Get-ThemeColor -ColorName "OnPrimary"
        }
        "Ai" {
            $fill = Get-ThemeColor -ColorName "Ai"
            if ($pressed) { $fill = Get-BlendedColor $fill ([System.Drawing.Color]::Black) 0.08 }
            elseif ($hover) { $fill = Get-BlendedColor $fill ([System.Drawing.Color]::White) 0.08 }
            $border = $fill
            $fore = [System.Drawing.Color]::White
        }
        default {
            $fill = Get-ThemeColor -ColorName $(if ($hover -or $pressed) { "Surface2" } else { "Surface" })
            $border = Get-ThemeColor -ColorName $(if ($hover -or $pressed) { "Primary" } else { "Border" })
            $fore = Get-ThemeColor -ColorName $(if ($state.Variant -eq "Muted") { "TextSecondary" } else { "TextPrimary" })
        }
    }
    if ($Control.Focused -and $enabled -and $state.Variant -eq "Default") { $border = Get-ThemeColor -ColorName "Primary" }
    $hintColor = Get-ThemeColor -ColorName "TextSecondary"
    if (-not $enabled) {
        $fore = Get-BlendedColor $fore $fill 0.5
        $hintColor = Get-BlendedColor $hintColor $fill 0.5
    }

    $rect = New-Object System.Drawing.RectangleF(0.5, 0.5, ($Control.Width - 1), ($Control.Height - 1))
    $path = New-GuiRoundedPath -Rect $rect -Radius (8 * $scale)
    $brush = New-Object System.Drawing.SolidBrush($fill)
    $pen = New-Object System.Drawing.Pen($border, 1)
    $Graphics.FillPath($brush, $path)
    $Graphics.DrawPath($pen, $path)
    $brush.Dispose(); $pen.Dispose(); $path.Dispose()

    $titleFont = Get-GuiFont -Family "Segoe UI Semibold" -Size $state.TitleSize
    $flagsBase = [System.Windows.Forms.TextFormatFlags]"NoPadding, EndEllipsis, SingleLine"
    $inset = [int](14 * $scale)
    $textWidth = $Control.Width - (2 * $inset)

    if ([string]::IsNullOrEmpty($state.Hint)) {
        $titleRect = New-Object System.Drawing.Rectangle($inset, 0, $textWidth, $Control.Height)
        $flags = $flagsBase -bor [System.Windows.Forms.TextFormatFlags]"HorizontalCenter, VerticalCenter"
        [System.Windows.Forms.TextRenderer]::DrawText($Graphics, $Control.Text, $titleFont, $titleRect, $fore, $flags)
    }
    else {
        $hintFont = Get-GuiFont -Family "Segoe UI" -Size 8.5
        $titleH = $titleFont.Height
        $hintH = $hintFont.Height
        $top = [int](($Control.Height - ($titleH + 2 + $hintH)) / 2)
        $flags = $flagsBase -bor [System.Windows.Forms.TextFormatFlags]::Left
        $titleRect = New-Object System.Drawing.Rectangle($inset, $top, $textWidth, $titleH)
        $hintRect = New-Object System.Drawing.Rectangle($inset, ($top + $titleH + 2), $textWidth, $hintH)
        [System.Windows.Forms.TextRenderer]::DrawText($Graphics, $Control.Text, $titleFont, $titleRect, $fore, $flags)
        [System.Windows.Forms.TextRenderer]::DrawText($Graphics, $state.Hint, $hintFont, $hintRect, $hintColor, $flags)
    }
}

function New-GuiCardButton {
    <#
    .SYNOPSIS
        Self-painting button: a title with an optional hint line.

    .DESCRIPTION
        Returns a Panel (Cursor = Hand) that behaves like a Button: Text is the title, Enabled greys
        it out and blocks clicks, Click runs -Action. The hint can be changed with Set-GuiCardHint.

        Variants: Default (surface + hairline), Primary (orange fill), Muted (Default with secondary
        text) and Ai (indigo fill).
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$Title,
        [string]$Hint = "",
        [int]$X = 0,
        [int]$Y = 0,
        [int]$Width = 176,
        [int]$Height = 56,
        [ValidateSet("Default", "Primary", "Muted", "Ai")]
        [string]$Variant = "Default",
        [double]$TitleSize = 9.5,
        [scriptblock]$Action
    )

    $card = New-Object System.Windows.Forms.Panel
    $card.Text = $Title
    $card.Location = New-Object System.Drawing.Point($X, $Y)
    $card.Size = New-Object System.Drawing.Size($Width, $Height)
    $card.BackColor = Get-ThemeColor -ColorName "Background"
    $card.Cursor = [System.Windows.Forms.Cursors]::Hand
    $card.TabStop = $true
    Enable-GuiPaintStyle -Control $card
    $card.Tag = [PSCustomObject]@{
        Kind      = "card"
        BackRole  = "Background"
        Variant   = $Variant
        Hint      = $Hint
        TitleSize = $TitleSize
        Hover     = $false
        Pressed   = $false
    }

    $card.Add_Paint({ param($sender, $e) Invoke-GuiCardPaint -Control $sender -Graphics $e.Graphics })
    $card.Add_MouseEnter({ $this.Tag.Hover = $true; $this.Invalidate() })
    $card.Add_MouseLeave({ $this.Tag.Hover = $false; $this.Tag.Pressed = $false; $this.Invalidate() })
    $card.Add_MouseDown({ $this.Tag.Pressed = $true; $this.Invalidate() })
    $card.Add_MouseUp({ $this.Tag.Pressed = $false; $this.Invalidate() })
    $card.Add_TextChanged({ $this.Invalidate() })
    $card.Add_EnabledChanged({ $this.Invalidate() })
    $card.Add_GotFocus({ $this.Invalidate() })
    $card.Add_LostFocus({ $this.Invalidate() })
    $card.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter -or $e.KeyCode -eq [System.Windows.Forms.Keys]::Space) {
            $e.Handled = $true
            if ($sender.Enabled) { Invoke-GuiControlClick -Control $sender }
        }
    })
    if ($Action) { $card.Add_Click($Action) }

    return $card
}

function Set-GuiCardHint {
    param (
        [System.Windows.Forms.Control]$Card,
        [string]$Hint
    )

    if ($null -eq $Card -or $null -eq $Card.Tag) { return }
    $Card.Tag.Hint = $Hint
    $Card.Invalidate()
}

#--------------------------------------------------------------
# COLLECTOR TILES
#--------------------------------------------------------------

# Key = tile id; Source = Source column in CollectionStatus.csv ($null when the collector does
# not report one); Unit = word shown after the count.
$script:GuiTileDefs = @(
    @{ Key = "SignIns";           Title = "Sign-in data";        Source = "SignIns";           Unit = "records";  File = $null }
    @{ Key = "AdminAudit";        Title = "Admin audits";        Source = "AdminAudit";        Unit = "records";  File = $null }
    @{ Key = "InboxRules";        Title = "Inbox rules";         Source = "InboxRules";        Unit = "records";  File = $null }
    @{ Key = "MailboxDelegation"; Title = "Delegations";         Source = "MailboxDelegation"; Unit = "records";  File = $null }
    @{ Key = "AppRegistrations";  Title = "App registrations";   Source = "AppRegistrations";  Unit = "records";  File = $null }
    @{ Key = "ConditionalAccess"; Title = "Conditional access";  Source = "ConditionalAccess"; Unit = "policies"; File = $null }
    @{ Key = "ETR";               Title = "ETR files";           Source = $null;               Unit = "records";  File = "ETRSpamAnalysis.csv" }
    @{ Key = "MessageTrace";      Title = "Message trace";       Source = "MessageTrace";      Unit = "records";  File = $null }
)

$Global:GuiTiles = @{}
$Global:GuiToolTip = $null

function Invoke-GuiTilePaint {
    param (
        [System.Windows.Forms.Control]$Control,
        [System.Drawing.Graphics]$Graphics
    )

    $state = $Control.Tag
    $scale = $Control.DeviceDpi / 96.0
    $Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $enabled = $Control.Enabled
    $hover = ($state.Hover -or $state.Pressed) -and $enabled
    $fill = Get-ThemeColor -ColorName $(if ($hover) { "Surface2" } else { "Surface" })
    $border = Get-ThemeColor -ColorName $(if ($hover) { "Primary" } elseif ($Control.Focused) { "Primary" } else { "Border" })

    $statusColor = switch ($state.State) {
        "running"    { Get-ThemeColor -ColorName "Primary" }
        "done"       { Get-ThemeColor -ColorName "Success" }
        "incomplete" { Get-ThemeColor -ColorName "Warning" }
        "error"      { Get-ThemeColor -ColorName "Danger" }
        default      { Get-ThemeColor -ColorName "TextSecondary" }
    }
    $titleColor = Get-ThemeColor -ColorName "TextPrimary"
    if (-not $enabled) {
        $titleColor = Get-BlendedColor $titleColor $fill 0.5
        $statusColor = Get-BlendedColor $statusColor $fill 0.5
    }

    $rect = New-Object System.Drawing.RectangleF(0.5, 0.5, ($Control.Width - 1), ($Control.Height - 1))
    $path = New-GuiRoundedPath -Rect $rect -Radius (8 * $scale)
    $brush = New-Object System.Drawing.SolidBrush($fill)
    $pen = New-Object System.Drawing.Pen($border, 1)
    $Graphics.FillPath($brush, $path)
    $Graphics.DrawPath($pen, $path)
    $brush.Dispose(); $pen.Dispose(); $path.Dispose()

    $inset = [int](14 * $scale)
    $flags = [System.Windows.Forms.TextFormatFlags]"NoPadding, EndEllipsis, SingleLine, Left"

    # Status dot (top right). A running collector pulses by toggling the alpha.
    $dotSize = [int](10 * $scale)
    $dotColor = $statusColor
    if ($state.State -eq "running" -and -not $script:TilePulseHigh) { $dotColor = [System.Drawing.Color]::FromArgb(90, $statusColor) }
    $dotBrush = New-Object System.Drawing.SolidBrush($dotColor)
    $dotX = $Control.Width - $inset - $dotSize
    $dotY = [int](14 * $scale)
    $Graphics.FillEllipse($dotBrush, $dotX, $dotY, $dotSize, $dotSize)
    $dotBrush.Dispose()

    $titleFont = Get-GuiFont -Family "Segoe UI Semibold" -Size 10
    $titleRect = New-Object System.Drawing.Rectangle($inset, [int](11 * $scale), ($dotX - $inset - [int](8 * $scale)), $titleFont.Height)
    [System.Windows.Forms.TextRenderer]::DrawText($Graphics, $Control.Text, $titleFont, $titleRect, $titleColor, $flags)

    $statusFont = Get-GuiFont -Family "Consolas" -Size 8.5
    $statusTop = $Control.Height - [int](14 * $scale) - $statusFont.Height
    $statusRect = New-Object System.Drawing.Rectangle($inset, $statusTop, ($Control.Width - (2 * $inset)), $statusFont.Height)
    [System.Windows.Forms.TextRenderer]::DrawText($Graphics, $state.StatusText, $statusFont, $statusRect, $statusColor, $flags)
}

function New-GuiCollectorTile {
    <#
    .SYNOPSIS
        Collector tile: name, status dot and a status line ("Not collected", "52 records", ...).
        Clicking the tile runs the collector (-Action), like the button it replaces.
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$Key,
        [Parameter(Mandatory = $true)] [string]$Title,
        [int]$X = 0,
        [int]$Y = 0,
        [int]$Width = 219,
        [int]$Height = 76,
        [scriptblock]$Action
    )

    $tile = New-Object System.Windows.Forms.Panel
    $tile.Text = $Title
    $tile.Location = New-Object System.Drawing.Point($X, $Y)
    $tile.Size = New-Object System.Drawing.Size($Width, $Height)
    $tile.BackColor = Get-ThemeColor -ColorName "Background"
    $tile.Cursor = [System.Windows.Forms.Cursors]::Hand
    $tile.TabStop = $true
    Enable-GuiPaintStyle -Control $tile
    $tile.Tag = [PSCustomObject]@{
        Kind       = "tile"
        BackRole   = "Background"
        Key        = $Key
        State      = "idle"
        StatusText = "Not collected"
        Note       = ""
        Hover      = $false
        Pressed    = $false
    }

    $tile.Add_Paint({ param($sender, $e) Invoke-GuiTilePaint -Control $sender -Graphics $e.Graphics })
    $tile.Add_MouseEnter({ $this.Tag.Hover = $true; $this.Invalidate() })
    $tile.Add_MouseLeave({ $this.Tag.Hover = $false; $this.Tag.Pressed = $false; $this.Invalidate() })
    $tile.Add_MouseDown({ $this.Tag.Pressed = $true; $this.Invalidate() })
    $tile.Add_MouseUp({ $this.Tag.Pressed = $false; $this.Invalidate() })
    $tile.Add_EnabledChanged({ $this.Invalidate() })
    $tile.Add_GotFocus({ $this.Invalidate() })
    $tile.Add_LostFocus({ $this.Invalidate() })
    $tile.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter -or $e.KeyCode -eq [System.Windows.Forms.Keys]::Space) {
            $e.Handled = $true
            if ($sender.Enabled) { Invoke-GuiControlClick -Control $sender }
        }
    })
    if ($Action) { $tile.Add_Click($Action) }

    $Global:GuiTiles[$Key] = $tile
    return $tile
}

function Set-GuiTileState {
    <#
    .SYNOPSIS
        Sets a collector tile's status. Safe to call before the GUI exists.
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$Key,
        [Parameter(Mandatory = $true)]
        [ValidateSet("idle", "running", "done", "incomplete", "error")]
        [string]$State,
        [string]$Text = "",
        [string]$Note = ""
    )

    $tile = $Global:GuiTiles[$Key]
    if ($null -eq $tile) { return }
    try {
        $tile.Tag.State = $State
        $tile.Tag.StatusText = $Text
        $tile.Tag.Note = $Note
        if ($null -ne $Global:GuiToolTip) { $Global:GuiToolTip.SetToolTip($tile, $Note) }
        $tile.Invalidate()
        # Collectors block the UI thread; repaint now instead of waiting for the message loop
        $tile.Update()
    }
    catch {
        Write-Log "Warning: Failed to update collector tile ${Key}: $($_.Exception.Message)" -Level "Warning"
    }
}

function Get-GuiTileStatusRow {
    <#
    .SYNOPSIS
        Latest CollectionStatus.csv row for a source, optionally only if it was written at or after -Since.
    #>
    param (
        [string]$Source,
        $Since = $null
    )

    if ([string]::IsNullOrEmpty($Source)) { return $null }
    $row = @(Get-CollectionStatus | Where-Object { $_.Source -eq $Source }) | Select-Object -Last 1
    if ($null -eq $row) { return $null }
    if ($null -ne $Since) {
        try {
            $ranAt = [datetime]::Parse("$($row.RunTimeUtc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        }
        catch { return $null }
        if ($ranAt -lt ([datetime]$Since).ToUniversalTime().AddSeconds(-1)) { return $null }
    }
    return $row
}

function Set-GuiTileFromRow {
    param (
        [string]$Key,
        $Row,
        [string]$Unit,
        $Count = $null
    )

    $records = $null
    if ($null -ne $Row -and "$($Row.Records)" -match '^\d+$') { $records = [int]$Row.Records }
    elseif ($null -ne $Count) { $records = [int]$Count }
    if ($null -eq $records) { return $false }

    $note = if ($null -ne $Row) { "$($Row.Note)" } else { "" }
    if ($null -ne $Row -and "$($Row.Complete)" -ne "True") {
        Set-GuiTileState -Key $Key -State "incomplete" -Text "$records $Unit $($script:GlyphDot) incomplete" -Note $note
    }
    else {
        Set-GuiTileState -Key $Key -State "done" -Text "$records $Unit" -Note $note
    }
    return $true
}

function Complete-GuiTile {
    <#
    .SYNOPSIS
        Sets a tile's final state after its collector ran: done, incomplete (the collector reported a
        gap in CollectionStatus.csv) or error (nothing came back).
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$Key,
        [Parameter(Mandatory = $true)] [datetime]$Since,
        $Count = $null
    )

    $def = $script:GuiTileDefs | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
    if ($null -eq $def) { return }
    $row = Get-GuiTileStatusRow -Source $def.Source -Since $Since
    if (-not (Set-GuiTileFromRow -Key $Key -Row $row -Unit $def.Unit -Count $Count)) {
        Set-GuiTileState -Key $Key -State "error" -Text "No data returned" -Note "The collector finished without returning data. Check the log for details."
    }
}

function Initialize-GuiTileStates {
    <#
    .SYNOPSIS
        Fills every tile from what is already in the working directory (CollectionStatus.csv, plus
        the ETR analysis file, which has no status row).
    #>
    foreach ($def in $script:GuiTileDefs) {
        $row = Get-GuiTileStatusRow -Source $def.Source
        if (Set-GuiTileFromRow -Key $def.Key -Row $row -Unit $def.Unit) { continue }

        $count = $null
        if ($def.File) {
            $path = Join-Path -Path $ConfigData.WorkDir -ChildPath $def.File
            if (Test-Path -Path $path) {
                try { $count = @(Import-Csv -Path $path -ErrorAction Stop).Count } catch { $count = $null }
            }
        }
        if ($null -eq $count -or -not (Set-GuiTileFromRow -Key $def.Key -Row $null -Unit $def.Unit -Count $count)) {
            Set-GuiTileState -Key $def.Key -State "idle" -Text "Not collected"
        }
    }
}

function Invoke-GuiCollectorTile {
    <#
    .SYNOPSIS
        Runs one collector from its tile: connection check, busy/running state, result, final state.

    .PARAMETER Collect
        Scriptblock that runs the collector and returns its result (records or $null).

    .PARAMETER Success
        Scriptblock receiving the result; returns the status-bar message for a non-empty result.
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$Key,
        [Parameter(Mandatory = $true)] [scriptblock]$Collect,
        [scriptblock]$Success,
        [bool]$RequireConnection = $true
    )

    $tile = $Global:GuiTiles[$Key]
    if ($RequireConnection -and -not $Global:ConnectionState.IsConnected) {
        Update-GuiStatus "[ERROR] Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
        return
    }

    $tile.Enabled = $false
    $since = Get-Date
    Set-GuiTileState -Key $Key -State "running" -Text "Collecting$($script:GlyphEllipsis)"
    try {
        $result = & $Collect
        if ($result -and $Success) {
            Update-GuiStatus (& $Success $result) (Get-ThemeColor -ColorName "Success")
        }
        Complete-GuiTile -Key $Key -Since $since -Count $(if ($result) { @($result).Count } else { $null })
    }
    catch {
        Write-Log "Collector '$Key' failed: $($_.Exception.Message)" -Level "Error"
        Set-GuiTileState -Key $Key -State "error" -Text "Failed" -Note $_.Exception.Message
        Update-GuiStatus "[ERROR] $($_.Exception.Message)" (Get-ThemeColor -ColorName "Danger")
    }
    finally {
        $tile.Enabled = $true
    }
}

#--------------------------------------------------------------
# CONNECTION PILL, SESSION BLOCK, SECTION HEADERS, STATUS BAR
#--------------------------------------------------------------

function New-GuiConnectionPill {
    param (
        [int]$X,
        [int]$Y,
        [int]$Width = 168,
        [int]$Height = 28
    )

    $pill = New-Object System.Windows.Forms.Panel
    $pill.Location = New-Object System.Drawing.Point($X, $Y)
    $pill.Size = New-Object System.Drawing.Size($Width, $Height)
    $pill.BackColor = Get-ThemeColor -ColorName "Background"
    $pill.Text = "Not connected"
    Enable-GuiPaintStyle -Control $pill
    $pill.Tag = [PSCustomObject]@{ Kind = "pill"; BackRole = "Background"; Connected = $false }

    $pill.Add_TextChanged({ $this.Invalidate() })
    $pill.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $scale = $sender.DeviceDpi / 96.0
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $color = Get-ThemeColor -ColorName $(if ($sender.Tag.Connected) { "Success" } else { "Danger" })

        $rect = New-Object System.Drawing.RectangleF(0.5, 0.5, ($sender.Width - 1), ($sender.Height - 1))
        $path = New-GuiRoundedPath -Rect $rect -Radius ($sender.Height / 2)
        $fill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(26, $color))
        $pen = New-Object System.Drawing.Pen($color, 1)
        $g.FillPath($fill, $path)
        $g.DrawPath($pen, $path)
        $fill.Dispose(); $pen.Dispose(); $path.Dispose()

        $dot = [int](8 * $scale)
        $dotBrush = New-Object System.Drawing.SolidBrush($color)
        $g.FillEllipse($dotBrush, [int](14 * $scale), [int](($sender.Height - $dot) / 2), $dot, $dot)
        $dotBrush.Dispose()

        $font = Get-GuiFont -Family "Segoe UI Semibold" -Size 9
        $textRect = New-Object System.Drawing.Rectangle([int](30 * $scale), 0, ($sender.Width - [int](40 * $scale)), $sender.Height)
        $flags = [System.Windows.Forms.TextFormatFlags]"NoPadding, EndEllipsis, SingleLine, Left, VerticalCenter"
        [System.Windows.Forms.TextRenderer]::DrawText($g, $sender.Text, $font, $textRect, $color, $flags)
    })

    return $pill
}

function New-GuiSessionCell {
    <#
    .SYNOPSIS
        One cell of the session block: caption over value. Returns the value Label.
    #>
    param (
        [Parameter(Mandatory = $true)] [System.Windows.Forms.Control]$Parent,
        [Parameter(Mandatory = $true)] [string]$Caption,
        [string]$Value = "",
        [int]$X,
        [int]$Y,
        [int]$Width = 468
    )

    $captionLabel = New-Object System.Windows.Forms.Label
    $captionLabel.Text = $Caption.ToUpper()
    $captionLabel.Font = Get-GuiFont -Family "Consolas" -Size 7.5
    $captionLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    $captionLabel.Tag = [PSCustomObject]@{ ColorName = "TextSecondary" }
    $captionLabel.AutoSize = $false
    $captionLabel.Location = New-Object System.Drawing.Point(($X + 16), ($Y + 9))
    $captionLabel.Size = New-Object System.Drawing.Size(($Width - 32), 14)
    $Parent.Controls.Add($captionLabel)

    $valueLabel = New-Object System.Windows.Forms.Label
    $valueLabel.Text = $Value
    $valueLabel.Font = Get-GuiFont -Family "Segoe UI Semibold" -Size 10
    $valueLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $valueLabel.AutoSize = $false
    $valueLabel.AutoEllipsis = $true
    $valueLabel.Location = New-Object System.Drawing.Point(($X + 16), ($Y + 26))
    $valueLabel.Size = New-Object System.Drawing.Size(($Width - 32), 22)
    $Parent.Controls.Add($valueLabel)

    return $valueLabel
}

function New-GuiSectionHeader {
    <#
    .SYNOPSIS
        "01  Title ----------" header row: mono number, semibold title, hairline filling the rest.
    #>
    param (
        [Parameter(Mandatory = $true)] [System.Windows.Forms.Control]$Parent,
        [Parameter(Mandatory = $true)] [string]$Number,
        [Parameter(Mandatory = $true)] [string]$Title,
        [int]$Y,
        [int]$Left = 32,
        [int]$Right = 968,
        [int]$RightReserve = 0
    )

    $numberFont = Get-GuiFont -Family "Consolas" -Size 9 -Style "Bold"
    $titleFont = Get-GuiFont -Family "Segoe UI Semibold" -Size 10.5
    $noPad = [System.Windows.Forms.TextFormatFlags]::NoPadding
    # Labels add their own internal padding; without the slack the text wraps and clips
    $numberText = [System.Windows.Forms.TextRenderer]::MeasureText($Number, $numberFont, (New-Object System.Drawing.Size(200, 30)), $noPad).Width
    $titleText = [System.Windows.Forms.TextRenderer]::MeasureText($Title, $titleFont, (New-Object System.Drawing.Size(400, 30)), $noPad).Width
    $numberWidth = $numberText + 10
    $titleWidth = $titleText + 12

    $numberLabel = New-Object System.Windows.Forms.Label
    $numberLabel.Text = $Number
    $numberLabel.Font = $numberFont
    $numberLabel.ForeColor = Get-ThemeColor -ColorName "Primary"
    $numberLabel.Tag = [PSCustomObject]@{ ColorName = "Primary" }
    $numberLabel.AutoSize = $false
    $numberLabel.Location = New-Object System.Drawing.Point($Left, ($Y + 3))
    $numberLabel.Size = New-Object System.Drawing.Size($numberWidth, 18)
    $Parent.Controls.Add($numberLabel)

    $titleX = $Left + $numberText + 12
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = $Title
    $titleLabel.Font = $titleFont
    $titleLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $titleLabel.Tag = [PSCustomObject]@{ ColorName = "TextPrimary" }
    $titleLabel.AutoSize = $false
    $titleLabel.Location = New-Object System.Drawing.Point($titleX, ($Y + 1))
    $titleLabel.Size = New-Object System.Drawing.Size($titleWidth, 22)
    $Parent.Controls.Add($titleLabel)

    $lineX = $titleX + $titleText + 16
    $line = New-Object System.Windows.Forms.Panel
    $line.Location = New-Object System.Drawing.Point($lineX, ($Y + 11))
    $line.Size = New-Object System.Drawing.Size(($Right - $RightReserve - $lineX), 1)
    $line.BackColor = Get-ThemeColor -ColorName "Border"
    $line.Tag = "separator"
    $Parent.Controls.Add($line)
}

function Update-GuiRiskSummary {
    <#
    .SYNOPSIS
        Status-bar summary after an analysis: "Analysis complete  12 critical  23 high  0 medium  43 low".
        The next Update-GuiStatus message replaces it.
    #>
    param (
        [int]$Critical = 0,
        [int]$High = 0,
        [int]$Medium = 0,
        [int]$Low = 0
    )

    if ($null -eq $Global:StatusSummaryPanel) { return }
    try {
        $Global:StatusSummaryPanel.Tag.Critical = $Critical
        $Global:StatusSummaryPanel.Tag.High = $High
        $Global:StatusSummaryPanel.Tag.Medium = $Medium
        $Global:StatusSummaryPanel.Tag.Low = $Low
        if ($null -ne $Global:StatusLabel) { $Global:StatusLabel.Visible = $false }
        $Global:StatusSummaryPanel.Visible = $true
        $Global:StatusSummaryPanel.Invalidate()
        $Global:StatusSummaryPanel.Update()
    }
    catch {
        Write-Log "Warning: Failed to update risk summary: $($_.Exception.Message)" -Level "Warning"
    }
    Write-Log "Analysis summary: $Critical critical, $High high, $Medium medium, $Low low" -Level "Info"
}

function New-GuiFlatButton {
    <#
    .SYNOPSIS
        Standard Button in the neutral style, for dialogs. Primary = orange fill with dark text.
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$Text,
        [int]$X = 0,
        [int]$Y = 0,
        [int]$Width = 110,
        [int]$Height = 32,
        [bool]$Primary = $false
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($Width, $Height)
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.Font = Get-GuiFont -Family "Segoe UI Semibold" -Size 9
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    $button.FlatAppearance.BorderSize = 1
    $button.UseVisualStyleBackColor = $false
    $button.Tag = [PSCustomObject]@{ Variant = $(if ($Primary) { "FlatPrimary" } else { "Flat" }) }
    Set-GuiFlatButtonColors -Button $button

    $button.Add_MouseEnter({ $this.FlatAppearance.BorderColor = Get-ThemeColor -ColorName "Primary" })
    $button.Add_MouseLeave({ Set-GuiFlatButtonColors -Button $this })
    return $button
}

function Set-GuiFlatButtonColors {
    param (
        [System.Windows.Forms.Button]$Button
    )

    if ($Button.Tag.Variant -eq "FlatPrimary") {
        $Button.BackColor = Get-ThemeColor -ColorName "Primary"
        $Button.ForeColor = Get-ThemeColor -ColorName "OnPrimary"
        $Button.FlatAppearance.BorderColor = Get-ThemeColor -ColorName "Primary"
        $Button.FlatAppearance.MouseOverBackColor = Get-BlendedColor (Get-ThemeColor -ColorName "Primary") ([System.Drawing.Color]::White) 0.08
    }
    else {
        $Button.BackColor = Get-ThemeColor -ColorName "Surface"
        $Button.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
        $Button.FlatAppearance.BorderColor = Get-ThemeColor -ColorName "Border"
        $Button.FlatAppearance.MouseOverBackColor = Get-ThemeColor -ColorName "Surface2"
    }
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

    # Rate limiting for geolocation API calls (seconds between requests)
    # Free tier ip-api.com: 45 requests/minute = 1.33s per request minimum
    # Recommended: 1.5-2 seconds to stay safely under the limit
    # Set to 0 to disable rate limiting (if using paid API)
    GeolocationRateLimit = 1.5

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
        SuspiciousTiming = 8   # Unusual send time patterns (reserved - no consumer yet)
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
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    Write-Host "[OK] Assemblies loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "[X] Failed to load required assemblies: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  The script may not function properly." -ForegroundColor Yellow
}

try {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
} catch {
    # Fallback for environments where System.Web isn't available
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    try {
        return [System.Web.HttpUtility]::HtmlEncode($Text)
    } catch {
        return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    }
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
        $uri = "http://api.ipstack.com/${testIP}?access_key=${APIKey}" + "&output=json"
        
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
        # Redact the API key in case a connection/DNS error echoed the request URI
        # (containing access_key=...) into the exception message; this Message is logged.
        $safeMessage = $_.Exception.Message -replace 'access_key=[^&\s"'']+', 'access_key=***REDACTED***'
        return [PSCustomObject]@{
            IsValid        = $false
            Message        = "Connection error: $safeMessage"
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
            # Free text replaces the structured analysis summary (Update-GuiRiskSummary)
            if ($null -ne $Global:StatusSummaryPanel -and $Global:StatusSummaryPanel.Visible) {
                $Global:StatusSummaryPanel.Visible = $false
            }
            $Global:StatusLabel.Visible = $true
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
        
        The display is state-driven:
        - Connection pill: green "Graph connected" or red "Not connected"
        - Tenant and Account cells of the session block
        - The Connect card switches between Connect and Reconnect
    
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
            $connected = [bool]$Global:ConnectionState.IsConnected

            if ($connected) {
                $tenant = "$($Global:ConnectionState.TenantName)"
                $account = "$($Global:ConnectionState.Account)"
                $Global:TenantInfoLabel.Text = $(if ([string]::IsNullOrWhiteSpace($tenant)) { "-" } else { $tenant })
                $Global:ConnectionLabel.Text = $(if ([string]::IsNullOrWhiteSpace($account)) { "-" } else { $account })
                $Global:TenantInfoLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
                $Global:ConnectionLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
            }
            else {
                $Global:TenantInfoLabel.Text = "Not connected"
                $Global:ConnectionLabel.Text = "-"
                $Global:TenantInfoLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
                $Global:ConnectionLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
            }

            # Connection pill: green "Graph connected" / red "Not connected"
            if ($null -ne $Global:ConnectionPill) {
                $Global:ConnectionPill.Tag.Connected = $connected
                $Global:ConnectionPill.Text = $(if ($connected) { "Graph connected" } else { "Not connected" })
                $Global:ConnectionPill.Invalidate()
            }

            # The Connect card doubles as Reconnect once a session exists
            if ($null -ne $Global:ConnectButton) {
                $Global:ConnectButton.Text = $(if ($connected) { "Reconnect" } else { "Connect to Microsoft Graph" })
                # The long disconnected title needs a half point less to fit the 176 px card
                $Global:ConnectButton.Tag.TitleSize = $(if ($connected) { 9.5 } else { 9 })
                Set-GuiCardHint -Card $Global:ConnectButton -Hint $(if ($connected) { "Refresh Graph session" } else { "Sign in to your tenant" })
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
            $Global:WorkDirLabel.Text = $NewWorkDir
            $Global:WorkDirLabel.Refresh()
            # Collector tiles reflect the CollectionStatus.csv of the new directory
            if ($Global:GuiTiles.Count -gt 0) { Initialize-GuiTileStates }
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

#--------------------------------------------------------------
# COLLECTION COVERAGE TRACKING
#--------------------------------------------------------------
# Collectors and analysis run as separate steps (often in separate sessions), so
# coverage gaps are persisted to CollectionStatus.csv in the working directory. The
# analysis step reads it back and surfaces every gap in the log and the HTML report,
# so a partial pull is never mistaken for full coverage.

function Get-CollectionStatusPath {
    return (Join-Path -Path $ConfigData.WorkDir -ChildPath "CollectionStatus.csv")
}

function Set-CollectionStatus {
    <#
    .SYNOPSIS
        Records how complete the most recent run of a collector was.

    .PARAMETER Source
        Collector name (for example "InboxRules", "SignIns").

    .PARAMETER Complete
        $false if the dataset has known gaps (skipped mailboxes, truncated results,
        reduced date range, degraded fallback source).

    .PARAMETER Note
        Human-readable description of the gap. Shown verbatim in the report.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $false)]
        [bool]$Complete = $true,

        [Parameter(Mandatory = $false)]
        [int]$Records = 0,

        [Parameter(Mandatory = $false)]
        [string]$Note = ""
    )

    try {
        $path = Get-CollectionStatusPath
        $rows = @()
        if (Test-Path -Path $path) {
            $rows = @(Import-Csv -Path $path -ErrorAction Stop | Where-Object { $_.Source -ne $Source })
        }
        $rows += [PSCustomObject]@{
            Source     = $Source
            RunTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
            Complete   = $Complete
            Records    = $Records
            Note       = $Note
        }
        $rows | Export-Csv -Path $path -NoTypeInformation -Force
    }
    catch {
        Write-Log "Could not record collection status for ${Source}: $($_.Exception.Message)" -Level "Warning"
    }
}

function Get-CollectionStatus {
    <#
    .SYNOPSIS
        Returns the persisted collection status rows (empty array if none recorded).
    #>
    [CmdletBinding()]
    param ()

    try {
        $path = Get-CollectionStatusPath
        if (Test-Path -Path $path) {
            return @(Import-Csv -Path $path -ErrorAction Stop)
        }
    }
    catch {
        Write-Log "Could not read collection status: $($_.Exception.Message)" -Level "Warning"
    }
    return @()
}

function Remove-StaleOutput {
    <#
    .SYNOPSIS
        Deletes a collector's own previous output files.

    .DESCRIPTION
        Collectors call this before writing results so a run that finds nothing cannot
        leave last run's file behind for the analysis step to pick up as current data.
        Only ever pass paths the calling collector itself writes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Path
    )

    foreach ($p in $Path) {
        if ($p -and (Test-Path -Path $p)) {
            try { Remove-Item -Path $p -Force -ErrorAction Stop }
            catch { Write-Log "Could not remove stale output ${p}: $($_.Exception.Message)" -Level "Warning" }
        }
    }
}

function Invoke-GraphPaged {
    <#
    .SYNOPSIS
        GETs a Microsoft Graph collection and follows @odata.nextLink to the end.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Uri $next -Method GET -ErrorAction Stop
        if ($response.value) { $items.AddRange([object[]]@($response.value)) }
        $next = $response.'@odata.nextLink'
    }
    return $items.ToArray()
}

function Get-AdminRoleMap {
    <#
    .SYNOPSIS
        Builds a user-id -> directory-role map covering active and PIM-eligible assignments.

    .DESCRIPTION
        Reads activated directory roles and their members (expanding role-assignable
        groups to users), then PIM eligible assignments. This replaces the old per-user
        "member of a group/role whose name contains Admin" check, which matched ordinary
        groups named "*Admin*" and missed eligible admins entirely.

        Returns a hashtable:
          Users    - userId -> @{ Active = list of role names; Eligible = list of role
                     names; TemplateIds = HashSet of role template ids }
          Warnings - strings describing anything that could not be read
    #>
    [CmdletBinding()]
    param ()

    $users = @{}
    $warnings = [System.Collections.Generic.List[string]]::new()

    $getEntry = {
        param($userId)
        if (-not $users.ContainsKey($userId)) {
            $users[$userId] = @{
                Active      = [System.Collections.Generic.List[string]]::new()
                Eligible    = [System.Collections.Generic.List[string]]::new()
                TemplateIds = [System.Collections.Generic.HashSet[string]]::new()
            }
        }
        return $users[$userId]
    }

    $expandPrincipal = {
        param($principalId, $odataType)
        if ($odataType -match 'group') {
            try {
                return @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$principalId/transitiveMembers/microsoft.graph.user?`$select=id" |
                    ForEach-Object { $_.id })
            }
            catch {
                $warnings.Add("Could not expand role-assigned group ${principalId}: $($_.Exception.Message)")
                return @()
            }
        }
        if ($odataType -match 'servicePrincipal') { return @() }
        return @($principalId)
    }

    # Active (activated) role assignments
    try {
        $roles = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/directoryRoles")
        foreach ($role in $roles) {
            $members = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id")
            foreach ($member in $members) {
                foreach ($userId in @(& $expandPrincipal $member.id $member.'@odata.type')) {
                    $entry = & $getEntry $userId
                    $entry.Active.Add($role.displayName)
                    if ($role.roleTemplateId) { [void]$entry.TemplateIds.Add($role.roleTemplateId) }
                }
            }
        }
    }
    catch {
        $warnings.Add("Active directory role assignments could not be read: $($_.Exception.Message)")
    }

    # PIM eligible assignments (needs Entra ID P2 / Governance and RoleManagement.Read.All)
    try {
        $definitions = @{}
        foreach ($def in @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId")) {
            $definitions[$def.id] = $def
        }
        $eligible = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal")
        foreach ($item in $eligible) {
            $def = $definitions[$item.roleDefinitionId]
            $roleName = if ($def) { $def.displayName } else { $item.roleDefinitionId }
            foreach ($userId in @(& $expandPrincipal $item.principalId $item.principal.'@odata.type')) {
                $entry = & $getEntry $userId
                $entry.Eligible.Add($roleName)
                if ($def -and $def.templateId) { [void]$entry.TemplateIds.Add($def.templateId) }
            }
        }
    }
    catch {
        $warnings.Add("PIM eligible role assignments could not be read - eligible admins are NOT included: $($_.Exception.Message)")
    }

    return @{ Users = $users; Warnings = $warnings }
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
        $versionPattern = '\$ScriptVer\s*=\s*["\x27]([0-9.]+)["\x27]'
        
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
                $uri = "http://api.ipstack.com/${IPAddress}?access_key=${apiKey}" + "&output=json"
                
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
                # Redact the API key: some connection/DNS errors echo the full request URI
                # (which contains access_key=...) into the exception message, and this string
                # is written to the log file below.
                $errorMsg = $_.Exception.Message -replace 'access_key=[^&\s"'']+', 'access_key=***REDACTED***'
                # Don't retry on auth or permanent errors
                if ($errorMsg -match "401|403|invalid.*key|usage.*limit") {
                    Write-Log "IPStack permanent error for ${IPAddress}: $errorMsg" -Level "Warning"
                    break  # Skip to fallback immediately
                }
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
        $fallbackAttempt = 0
        $maxFallbackRetries = 3

        while ($fallbackAttempt -lt $maxFallbackRetries -and -not $success) {
            $fallbackAttempt++

            try {
                # ip-api.com supports both IPv4 and IPv6
                # Free tier: 45 requests/minute
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
                $errorMessage = $_.Exception.Message

                # Check for 429 rate limit error
                if ($errorMessage -match "429" -or $errorMessage -match "Too Many Requests") {
                    if ($fallbackAttempt -lt $maxFallbackRetries) {
                        # Exponential backoff for rate limiting: 5s, 15s, 45s
                        $backoffDelay = 5 * [Math]::Pow(3, $fallbackAttempt - 1)
                        Write-Log "Rate limit hit for $IPAddress - waiting ${backoffDelay}s before retry $fallbackAttempt/$maxFallbackRetries" -Level "Warning"
                        Start-Sleep -Seconds $backoffDelay
                    }
                    else {
                        Write-Log "Rate limit exceeded for $IPAddress after $maxFallbackRetries retries" -Level "Warning"
                    }
                }
                else {
                    # Non-rate-limit error, don't retry
                    Write-Log "Fallback geolocation service failed for $IPAddress : $errorMessage" -Level "Warning"
                    break
                }
            }
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

function Show-ConsoleWindowBestEffort {
    <#
    .SYNOPSIS
        Makes a console window visible (allocating one if needed) so console-only output
        such as the Exchange Online device code is readable from a WinForms session.
    .NOTES
        Best-effort only - wrapped by the caller in try/catch. Returns $true if a console
        window should now be visible.
    #>
    try {
        if (-not ([System.Management.Automation.PSTypeName]'YW.ConsoleHelper').Type) {
            Add-Type -Namespace YW -Name ConsoleHelper -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)] public static extern bool AllocConsole();
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr hWnd);
'@ -ErrorAction Stop
        }

        $hWnd = [YW.ConsoleHelper]::GetConsoleWindow()
        if ($hWnd -eq [System.IntPtr]::Zero) {
            # No console attached - allocate one and rewire Console.Out so native writes land there
            if ([YW.ConsoleHelper]::AllocConsole()) {
                $stdout = [System.Console]::OpenStandardOutput()
                $writer = New-Object System.IO.StreamWriter($stdout)
                $writer.AutoFlush = $true
                [System.Console]::SetOut($writer)
                $hWnd = [YW.ConsoleHelper]::GetConsoleWindow()
            }
        }

        if ($hWnd -ne [System.IntPtr]::Zero) {
            [YW.ConsoleHelper]::ShowWindow($hWnd, 5)  | Out-Null   # SW_SHOW
            [YW.ConsoleHelper]::SetForegroundWindow($hWnd) | Out-Null
            return $true
        }
    }
    catch {
        Write-Log "Could not reveal console window for device code: $($_.Exception.Message)" -Level "Warning"
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
        "Microsoft.Graph.Beta.Reports",             # Sign-in logs (Beta for complete data)
        "Microsoft.Graph.Identity.DirectoryManagement",  # Directory operations
        "Microsoft.Graph.Identity.SignIns",         # Authentication methods (MFA detection)
        "Microsoft.Graph.Applications",             # App registrations
        "Microsoft.Graph.Groups"                    # Group membership (Get-MgGroupMember)
    )
    
    $missingModules   = @()
    $installedVersions = @{}   # module name -> newest installed [version]

    # Check which modules are missing and record their newest installed version
    Write-Log "Checking for required Microsoft Graph modules..." -Level "Info"
    foreach ($module in $requiredModules) {
        $allInstalled = Get-Module -Name $module -ListAvailable |
            Sort-Object Version -Descending
        if ($null -eq $allInstalled -or $allInstalled.Count -eq 0) {
            $missingModules += $module
            Write-Log "Missing module: $module" -Level "Warning"
        }
        else {
            $installedVersions[$module] = $allInstalled[0].Version
            Write-Log "$module found (Version: $($allInstalled[0].Version))" -Level "Info"
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
                    # Install latest version of all modules (PS 7.0+ compatible)
                    Write-Log "Installing $module (latest version)..." -Level "Info"
                    Update-GuiStatus "Installing $module..." ([System.Drawing.Color]::Orange)
                    Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop

                    $installedVersion = (Get-InstalledModule -Name $module -ErrorAction SilentlyContinue | Select-Object -First 1).Version
                    Write-Log "$module v$installedVersion installed successfully" -Level "Info"
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
    # PHASE 2: VERSION MISMATCH DETECTION + CONFLICT RESOLUTION
    #══════════════════════════════════════════════════════════

    # ── Step 2a: Detect version mismatches across stable (non-Beta) modules ──
    # All stable Graph modules share Microsoft.Graph.Authentication.dll.
    # Mixed versions cause "Assembly already loaded" at import time because
    # .NET cannot unload an assembly once it enters the AppDomain.
    # Remove-Module only removes the PS wrapper — the assembly stays.
    # The only correct fix is to align all modules to the same version,
    # then restart PowerShell for a clean AppDomain before loading them.

    $stableModuleNames = $requiredModules | Where-Object { $_ -notlike "*.Beta.*" }
    $installedStable   = $stableModuleNames | Where-Object { $installedVersions.ContainsKey($_) }
    $uniqueStableVers  = $installedStable |
        ForEach-Object { $installedVersions[$_].ToString() } |
        Select-Object -Unique

    if ($uniqueStableVers.Count -gt 1) {
        Write-Log "WARNING: Mixed Microsoft Graph module versions: $($uniqueStableVers -join ', ')" -Level "Warning"

        $versionLines = ($installedStable |
            ForEach-Object { "  $_ : v$($installedVersions[$_])" }) -join "`n"

        $updatePrompt = [System.Windows.Forms.MessageBox]::Show(
            "Mixed Microsoft Graph module versions detected:`n`n$versionLines`n`n" +
            "All stable Graph modules must be at the same version.`n" +
            "Mixed versions cause ""Assembly already loaded"" errors that cannot`n" +
            "be worked around without restarting PowerShell.`n`n" +
            "Update all Graph modules to the latest version now?`n" +
            "(A PowerShell restart will be required after.)",
            "Module Version Mismatch — Cannot Continue",
            "YesNo",
            "Warning"
        )

        if ($updatePrompt -eq "Yes") {
            Update-GuiStatus "Updating Microsoft Graph modules — this may take a few minutes..." ([System.Drawing.Color]::Orange)
            Write-Log "Running Update-Module for all required Microsoft.Graph.* modules..." -Level "Info"
            try {
                foreach ($mod in $stableModuleNames) {
                    Write-Log "  Updating: $mod" -Level "Info"
                    Update-Module -Name $mod -Force -ErrorAction SilentlyContinue
                }
                Write-Log "Module update complete." -Level "Info"
                [System.Windows.Forms.MessageBox]::Show(
                    "Microsoft Graph modules updated successfully.`n`n" +
                    "Please close PowerShell completely and re-run the tool.`n" +
                    "(A clean restart loads the new assemblies correctly.)",
                    "Restart PowerShell to Continue",
                    "OK",
                    "Information"
                )
            }
            catch {
                Write-Log "Module update failed: $($_.Exception.Message)" -Level "Error"
                [System.Windows.Forms.MessageBox]::Show(
                    "Update failed: $($_.Exception.Message)`n`n" +
                    "Run this manually in an elevated PowerShell, then restart:`n`n" +
                    "  Update-Module Microsoft.Graph -Force",
                    "Update Failed",
                    "OK",
                    "Error"
                )
            }
        }
        else {
            Write-Log "User declined module update. Cannot load mixed versions safely." -Level "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Cannot connect with mixed module versions.`n`n" +
                "Run this in an elevated PowerShell, then restart:`n`n" +
                "  Update-Module Microsoft.Graph -Force",
                "Cannot Continue",
                "OK",
                "Error"
            )
        }

        # Always stop — a PS restart is required to get a clean AppDomain.
        return $false
    }

    # ── Step 2b: Unload any already-loaded Graph PS module wrappers ──
    Update-GuiStatus "Preparing Graph modules..." ([System.Drawing.Color]::Orange)
    Write-Log "Unloading any already-loaded Graph module wrappers..." -Level "Info"

    $loadedGraphModules = Get-Module -Name "Microsoft.Graph.*" -ErrorAction SilentlyContinue
    if ($loadedGraphModules) {
        Write-Log "Removing $($loadedGraphModules.Count) loaded Graph module(s) before re-import" -Level "Info"
        foreach ($mod in $loadedGraphModules) {
            Remove-Module -Name $mod.Name -Force -ErrorAction SilentlyContinue
            Write-Log "  Removed: $($mod.Name)" -Level "Info"
        }
    }

    Write-Log "Microsoft Graph modules prepared successfully" -Level "Info"

    #══════════════════════════════════════════════════════════
    # PHASE 3: MODULE IMPORT AND AUTHENTICATION PREPARATION
    #══════════════════════════════════════════════════════════
    
    try {
        # Import required modules with conflict handling
        Update-GuiStatus "Loading Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
        Write-Log "Importing Microsoft Graph modules..." -Level "Info"

        foreach ($module in $requiredModules) {
            Write-Log "Importing $module..." -Level "Info"
            Import-Module $module -Force -DisableNameChecking -ErrorAction Stop
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

        # Try to get context with retry logic for assembly loading issues
        $context = $null
        $organization = $null
        $retryCount = 0
        $maxRetries = 2

        while ($retryCount -le $maxRetries -and (-not $context)) {
            try {
                if ($retryCount -gt 0) {
                    Write-Log "SELF-HEALING: Retry attempt $retryCount - reimporting Authentication module..." -Level "Info"
                    Remove-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue
                    Import-Module Microsoft.Graph.Authentication -Force -DisableNameChecking -ErrorAction Stop
                    Start-Sleep -Seconds 1
                }

                $context = Get-MgContext -ErrorAction Stop
                $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1

                if ($context -and $organization) {
                    Write-Log "Successfully retrieved tenant information" -Level "Info"
                    break
                }
            }
            catch {
                $errorMsg = $_.Exception.Message

                # Check if this is the assembly loading error indicating corrupted modules
                if ($errorMsg -match "Could not load file or assembly.*Microsoft\.Graph\.Authentication") {
                    Write-Log "Attempt $($retryCount + 1) failed: Assembly loading error detected" -Level "Warning"

                    if ($retryCount -eq 0) {
                        # First failure - try complete module reinstall
                        Write-Log "SELF-HEALING: Graph modules appear corrupted - performing complete reinstall..." -Level "Warning"
                        Update-GuiStatus "Corrupted modules detected - reinstalling Graph SDK (this may take 2-3 minutes)..." ([System.Drawing.Color]::Orange)

                        try {
                            # Uninstall ALL Graph modules
                            Write-Log "Uninstalling all Microsoft.Graph modules..." -Level "Info"
                            Get-InstalledModule -Name "Microsoft.Graph*" -ErrorAction SilentlyContinue |
                                ForEach-Object {
                                    Write-Log "  Removing: $($_.Name)" -Level "Info"
                                    Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
                                }

                            # Remove loaded modules
                            Get-Module -Name "Microsoft.Graph*" | Remove-Module -Force -ErrorAction SilentlyContinue

                            # Reinstall with latest version (PS 7.0+ compatible)
                            Write-Log "Reinstalling Microsoft.Graph SDK (latest version)..." -Level "Info"
                            Install-Module -Name "Microsoft.Graph" -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop

                            $installedVersion = (Get-InstalledModule -Name "Microsoft.Graph" -ErrorAction SilentlyContinue | Select-Object -First 1).Version
                            Write-Log "Graph modules reinstalled successfully (v$installedVersion) - please restart the script" -Level "Info"
                            Update-GuiStatus "Graph modules reinstalled - PLEASE CLOSE AND RESTART PowerShell" ([System.Drawing.Color]::Orange)

                            [System.Windows.Forms.MessageBox]::Show(
                                "Microsoft Graph modules have been reinstalled to fix corruption.`n`n" +
                                "Installed latest version (v$installedVersion)`n`n" +
                                "IMPORTANT: Please close PowerShell completely and restart it, then run the script again.`n`n" +
                                "This ensures the new modules load properly.",
                                "Modules Reinstalled - Restart Required",
                                "OK",
                                "Warning"
                            )

                            throw "Graph modules reinstalled - please restart PowerShell and run the script again"
                        }
                        catch {
                            Write-Log "Failed to reinstall modules: $($_.Exception.Message)" -Level "Error"
                            throw
                        }
                    }
                }

                if ($retryCount -eq $maxRetries) {
                    throw
                }
                Write-Log "Attempt $($retryCount + 1) failed: $errorMsg" -Level "Warning"
                $retryCount++
            }
        }

        if (-not $context -or -not $organization) {
            throw "Failed to retrieve tenant context or organization information after $maxRetries retries"
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

        # Check for existing working Exchange Online connection instead of disconnecting
        $existingConnection = $null
        try {
            # Try to get a test result to verify connection works
            $existingConnection = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
            if ($existingConnection) {
                Write-Log "Found existing working Exchange Online connection - reusing it" -Level "Info"
                Update-GuiStatus "Reusing existing Exchange Online connection" ([System.Drawing.Color]::Green)

                # Mark as connected and skip connection attempt
                $Global:ExchangeOnlineState = @{
                    IsConnected       = $true
                    LastChecked       = Get-Date
                    ConnectionAttempts = 0
                }
                $skipExchangeConnection = $true
            }
        }
        catch {
            Write-Log "No existing working Exchange Online connection found" -Level "Info"
            $skipExchangeConnection = $false
        }

        if (-not $skipExchangeConnection) {
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
            
            # Connect to Exchange Online using appropriate auth method for PowerShell version
            Write-Log "Retrieving authenticated account from Graph session..." -Level "Info"
            $graphContext = Get-MgContext
            $userPrincipalName = $graphContext.Account
            $isPowerShell51 = $PSVersionTable.PSVersion.Major -eq 5

            if ($userPrincipalName) {
                Write-Log "EXO module: $((Get-Module ExchangeOnlineManagement).Version)" -Level "Info"

                # WAM/RuntimeBroker throws a NullReferenceException when MSAL initialises the
                # broker from a WinForms GUI thread (EXO 3.x / MSAL 4.x+). The clean fix is
                # -DisableWAM, which falls back to browser-based SSO - the same interactive flow
                # that already works for Microsoft Graph in this app. Device code is kept only as
                # a last resort for hosts where browser auth also fails (and it needs a console).
                $supportsDisableWAM = (Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')
                $needsDeviceCode = $false

                Write-Log "Connecting to Exchange Online (browser auth$(if ($supportsDisableWAM) { ', WAM disabled' } else { '' }))..." -Level "Info"
                Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Yellow)
                try {
                    $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
                    if ($userPrincipalName)  { $exoParams.UserPrincipalName = $userPrincipalName }
                    if ($supportsDisableWAM) { $exoParams.DisableWAM = $true }
                    Connect-ExchangeOnline @exoParams
                }
                catch {
                    $isWamError = $_.Exception.ToString() -match 'RuntimeBroker|NullReferenceException|broker'
                    if ($isWamError) {
                        Write-Log "Browser auth failed (WAM/broker) - falling back to device code" -Level "Warning"
                        $needsDeviceCode = $true
                    } else {
                        throw
                    }
                }

                if ($needsDeviceCode) {
                    $deviceParamExists = (Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('Device')
                    if (-not $deviceParamExists) {
                        throw "Exchange Online module does not support device code auth (-Device parameter missing)"
                    }

                    Write-Log "Starting device code authentication for Exchange Online" -Level "Info"
                    Update-GuiStatus "Exchange Online: Opening browser for sign-in..." ([System.Drawing.Color]::Yellow)

                    # The device code is written to the console host. Make a console window
                    # visible so it is readable when running as a GUI app with no console.
                    $consoleShown = Show-ConsoleWindowBestEffort

                    # Open browser to device login page before the code is printed to console
                    try { Start-Process "https://microsoft.com/devicelogin" } catch {}

                    $codeLocation = if ($consoleShown) {
                        "The one-time code is shown in the console window that just opened."
                    } else {
                        "The one-time code appears in the PowerShell console/output."
                    }
                    [System.Windows.Forms.MessageBox]::Show(
                        "Exchange Online sign-in required.`n`nA browser window has been opened to:`nhttps://microsoft.com/devicelogin`n`n$codeLocation`nEnter that code in the browser to authenticate.",
                        "Exchange Online Authentication",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    ) | Out-Null

                    Update-GuiStatus "Exchange Online: Waiting for device code authentication..." ([System.Drawing.Color]::Yellow)
                    Connect-ExchangeOnline -UserPrincipalName $userPrincipalName -Device -ShowBanner:$false -ErrorAction Stop
                }
            } else {
                Write-Log "No authenticated account found in Graph context - using direct connection" -Level "Warning"
                Update-GuiStatus "Exchange Online: Waiting for authentication..." ([System.Drawing.Color]::Yellow)
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            }
            
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
        } # End of if (-not $skipExchangeConnection)

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
                         "Microsoft Graph: [OK] Connected`n" +
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
                # Connect using appropriate auth method for PowerShell version
                Write-Log "Retrieving authenticated account from Graph session..." -Level "Info"
                $graphContext = Get-MgContext
                $userPrincipalName = $graphContext.Account

                # WAM/RuntimeBroker crashes in a GUI context. Use -DisableWAM for browser-based
                # SSO (works the same as the Graph connection); device code is the last resort.
                $supportsDisableWAM = (Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')
                $needsDeviceCode = $false
                $connectUpn = if ($userPrincipalName) { $userPrincipalName } else { $null }

                try {
                    $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
                    if ($connectUpn)         { $exoParams.UserPrincipalName = $connectUpn }
                    if ($supportsDisableWAM) { $exoParams.DisableWAM = $true }
                    Connect-ExchangeOnline @exoParams
                }
                catch {
                    if ($_.Exception.ToString() -match 'RuntimeBroker|NullReferenceException|broker') {
                        Write-Log "Browser auth failed (WAM/broker) - falling back to device code" -Level "Warning"
                        $needsDeviceCode = $true
                    } else {
                        throw
                    }
                }

                if ($needsDeviceCode) {
                    $deviceParamExists = (Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('Device')
                    if (-not $deviceParamExists) { throw "Exchange Online module does not support -Device parameter" }

                    Write-Log "Starting device code authentication for Exchange Online" -Level "Info"
                    Update-GuiStatus "Exchange Online: Opening browser for sign-in..." ([System.Drawing.Color]::Yellow)

                    # The device code is written to the console host. Make a console window
                    # visible so it is readable when running as a GUI app with no console.
                    $consoleShown = Show-ConsoleWindowBestEffort

                    try { Start-Process "https://microsoft.com/devicelogin" } catch {}

                    $codeLocation = if ($consoleShown) {
                        "The one-time code is shown in the console window that just opened."
                    } else {
                        "The one-time code appears in the PowerShell console/output."
                    }
                    [System.Windows.Forms.MessageBox]::Show(
                        "Exchange Online sign-in required.`n`nA browser window has been opened to:`nhttps://microsoft.com/devicelogin`n`n$codeLocation`nEnter that code in the browser to authenticate.",
                        "Exchange Online Authentication",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    ) | Out-Null

                    Update-GuiStatus "Exchange Online: Waiting for device code authentication..." ([System.Drawing.Color]::Yellow)
                    if ($connectUpn) {
                        Connect-ExchangeOnline -UserPrincipalName $connectUpn -Device -ShowBanner:$false -ErrorAction Stop
                    } else {
                        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
                    }
                }
                
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
            $message = "[OK] Admin Audit Logging: ENABLED`n`n" +
                      "Status: Working properly with recent data`n" +
                      "Impact: All admin audit data collection will work normally"
            $icon = "Information"
        }
        
        "Enabled-NoData" {
            $message = "[WARNING] Admin Audit Logging: ENABLED (No Recent Data)`n`n" +
                      "Status: Audit logging is enabled but no recent admin activities found`n" +
                      "Impact: This is normal if there haven't been recent admin changes`n" +
                      "Note: Data collection will work when admin activities occur"
            $icon = "Warning"
        }
        
        "Disabled" {
            $message = "[ERROR] Admin Audit Logging: DISABLED`n`n" +
                      "Status: Admin audit logging is not enabled in this tenant`n" +
                      "Impact: Admin audit data collection will NOT work`n`n" +
                      "Resolution: Enable audit logging in Microsoft 365 Admin Center:`n" +
                      "1. Go to Microsoft 365 Admin Center`n" +
                      "2. Navigate to Security & Compliance > Audit`n" +
                      "3. Enable 'Record user and admin activities'"
            $icon = "Error"
        }
        
        "PermissionDenied" {
            $message = "[LOCKED] Admin Audit Logging: PERMISSION DENIED`n`n" +
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
            $message = "≡ Admin Audit Logging: CONFIGURATION ISSUE`n`n" +
                      "Status: There may be a configuration problem with audit logging`n" +
                      "Impact: Admin audit data collection may not work properly`n`n" +
                      "Resolution: Check audit log configuration in Admin Center"
            $icon = "Warning"
        }
        
        default {
            $message = "[UNKNOWN] Admin Audit Logging: UNKNOWN STATUS`n`n" +
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
        "UNKNOWN" = "Failure - cause not reported in the audit record"
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

function Get-AdaptiveGraphTimeoutSec {
    <#
    .SYNOPSIS
        Computes a wall-clock timeout (seconds) for the premium Graph sign-in query, scaled to
        tenant size and the requested look-back window.
    .DESCRIPTION
        The Graph SDK uses a fixed 300s HttpClient timeout. On a small or non-premium tenant
        (whose signIns endpoint hangs instead of erroring) that means a 5-minute wait before the
        Exchange Online fallback kicks in. Scaling the timeout to user count + day window lets
        small tenants fail fast while large tenants still get enough time.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 14
    )

    # Tuning constants (local so the behaviour is easy to see and adjust).
    $baseSec    = 30      # baseline even for a tiny tenant
    $perUserSec = 0.3     # extra seconds per user account
    $perDaySec  = 3       # extra seconds per day of look-back
    $minSec     = 40
    $maxSec     = 480
    $unknownSec = 120     # moderate default when tenant size can't be determined

    $userCount = $null
    try {
        $userCount = [int](Get-MgUserCount -ConsistencyLevel eventual -ErrorAction Stop)
        Write-Log "Tenant size probe: $userCount users" -Level "Info"
    }
    catch {
        Write-Log "Could not determine tenant user count ($($_.Exception.Message)); using moderate default timeout" -Level "Warning"
    }

    if ($null -eq $userCount) {
        $timeout = $unknownSec
    } else {
        $computed = $baseSec + [int]($userCount * $perUserSec) + ($DaysBack * $perDaySec)
        $timeout  = [int][Math]::Max($minSec, [Math]::Min($maxSec, $computed))
    }

    $sizeText = if ($null -eq $userCount) { "unknown" } else { $userCount }
    Write-Log "Adaptive premium Graph timeout: $timeout s (users=$sizeText, days=$DaysBack)" -Level "Info"
    return $timeout
}

function Test-PremiumSignInLicense {
    <#
    .SYNOPSIS
        Determines whether the tenant holds an Azure AD Premium P1/P2 license, which the Graph
        sign-in logs endpoint (auditLogs/signIns) requires.
    .OUTPUTS
        $true  - a premium plan is present (attempt Graph)
        $false - SKUs read successfully and NO premium plan present (skip straight to fallback)
        $null  - could not be determined (caller should still attempt Graph with a timeout)
    .NOTES
        Biased toward attempting Graph: a false negative would silently lose premium sign-in
        data, whereas a false positive merely hits the adaptive timeout and falls back anyway.
    #>
    [CmdletBinding()]
    param()

    # AAD_PREMIUM = P1, AAD_PREMIUM_P2 = P2. Either one enables the sign-in logs API.
    $premiumPlanNames = @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
    try {
        $skus = Get-MgSubscribedSku -All -ErrorAction Stop
        if (-not $skus) { return $null }

        foreach ($sku in $skus) {
            foreach ($plan in $sku.ServicePlans) {
                # Match on plan name only (any status except an explicitly disabled plan) to
                # avoid false negatives that would skip a working premium tenant.
                if ($premiumPlanNames -contains $plan.ServicePlanName -and
                    $plan.ProvisioningStatus -ne 'Disabled') {
                    Write-Log "Premium sign-in license detected: $($plan.ServicePlanName) (SKU $($sku.SkuPartNumber))" -Level "Info"
                    return $true
                }
            }
        }

        Write-Log "No Azure AD Premium (P1/P2) license found in tenant SKUs - sign-in logs API unavailable" -Level "Info"
        return $false
    }
    catch {
        Write-Log "Could not read subscribed SKUs ($($_.Exception.Message)); will attempt Graph with timeout" -Level "Warning"
        return $null
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

    .PARAMETER IncludeNonInteractive
        Also collect NON-INTERACTIVE user sign-ins. The Graph signIns endpoint returns
        interactive sign-ins only unless the signInEventTypes filter is set explicitly, so
        token-based access (refresh-token replay, legacy protocols, background app access)
        is invisible by default. Non-interactive volume is typically 10-50x interactive,
        so this is opt-in and can make the collection much slower.
    
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
        - On a tenant with a CONFIRMED P1/P2 license, a Graph timeout or 403 is treated as
          an error, NOT a licensing problem: the collection fails loudly instead of silently
          dropping to 10 days of degraded unified audit log data.
        - Coverage limits (fallback source, interactive-only, failed geolocation lookups,
          missing source IPs) are written to CollectionStatus.csv and shown in the report.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"),
        
        [Parameter(Mandatory = $false)]
        [bool]$UseCache = $true,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNonInteractive
    )
    
    #═══════════════════════════════════════════════════════════════════════════
    # IMPORT REQUIRED MODULE
    #═══════════════════════════════════════════════════════════════════════════
    
    try {
        Import-Module Microsoft.Graph.Beta.Reports -Force -DisableNameChecking -ErrorAction Stop
        Write-Log "Microsoft.Graph.Beta.Reports module imported successfully" -Level "Info"
    }
    catch {
        Update-GuiStatus "Failed to import Microsoft.Graph.Beta.Reports module: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Failed to import Microsoft.Graph.Beta.Reports: $($_.Exception.Message)" -Level "Error"
        throw "Microsoft.Graph.Beta.Reports module is required but could not be loaded. Please install it with: Install-Module Microsoft.Graph.Beta.Reports"
    }
    
    Update-GuiStatus "Starting sign-in data collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
    Write-Log "SIGN-IN DATA COLLECTION STARTED" -Level "Info"
    Write-Log "Date Range: $DaysBack days" -Level "Info"
    Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Calculate date range
        $startDate = (Get-Date).AddDays(-$DaysBack)
        $filterDate = $startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Initialize IP cache for geolocation
        $ipCache = @{}
        
        #═══════════════════════════════════════════════════════════════════════
        # QUERY SIGN-IN LOGS WITH STREAMLINED FALLBACK
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Querying Microsoft Graph for sign-in logs..." ([System.Drawing.Color]::Orange)
        Write-Log "Attempting sign-in data collection with fallback support" -Level "Info"
        
        $signInLogs = @()
        $isPremiumTenant = $true
        $premiumState = $null
        $coverageGaps = [System.Collections.Generic.List[string]]::new()
        $coverageComplete = $true
        
        # ATTEMPT 1: Premium Microsoft Graph API
        try {
            $filter = "createdDateTime ge $filterDate"

            # Pre-flight: the signIns endpoint requires an Azure AD Premium P1/P2 license.
            # If the tenant positively has none, skip the Graph attempt entirely and drop to
            # the Exchange Online fallback immediately - no probe, no timeout wait.
            $premiumState = Test-PremiumSignInLicense
            if ($premiumState -eq $false) {
                throw "Authentication_RequestFromNonPremiumTenantOrB2CTenant: no Azure AD Premium (P1/P2) license in tenant (pre-flight) - using Exchange Online fallback"
            }

            # The wall-clock timeout exists only to fail fast on tenants that may be
            # non-premium. A CONFIRMED premium tenant is queried directly and allowed to take
            # as long as it needs, so a big tenant is never mistaken for a non-premium one.
            if ($premiumState -eq $true) {
                $graphTimeoutSec = 0
                Update-GuiStatus "Querying premium Microsoft Graph sign-in logs (licensed tenant, no timeout)..." ([System.Drawing.Color]::Orange)
            }
            else {
                $graphTimeoutSec = Get-AdaptiveGraphTimeoutSec -DaysBack $DaysBack
                Update-GuiStatus "Attempting premium Microsoft Graph API (timeout ${graphTimeoutSec}s)..." ([System.Drawing.Color]::Orange)
            }
            Write-Log "Trying premium Graph API with filter: $filter" -Level "Info"

            # Enforce our own wall-clock timeout so a non-premium tenant (whose signIns endpoint
            # hangs rather than erroring) fails fast to the Exchange Online fallback instead of
            # blocking on the SDK's fixed 300s HttpClient timeout. Start-ThreadJob runs in-process,
            # so it shares the Microsoft Graph connection established on the main thread.
            if ($premiumState -ne $true -and (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
                $graphJob = Start-ThreadJob -ScriptBlock {
                    param($f) Get-MgBetaAuditLogSignIn -Filter $f -All -ErrorAction Stop
                } -ArgumentList $filter
                try {
                    if (Wait-Job -Job $graphJob -Timeout $graphTimeoutSec) {
                        $signInLogs = Receive-Job -Job $graphJob -ErrorAction Stop
                    } else {
                        throw "Premium Graph API exceeded the adaptive timeout of $graphTimeoutSec seconds"
                    }
                }
                catch {
                    # If the worker runspace could not see the Graph connection, retry inline so
                    # premium tenants still work (no worse than the original direct call).
                    if ($_.Exception.Message -match 'Authentication needed|Connect-MgGraph|not connected|InteractiveBrowserCredential') {
                        Write-Log "Worker thread lacked Graph context; retrying premium query inline" -Level "Info"
                        $signInLogs = Get-MgBetaAuditLogSignIn -Filter $filter -All -ErrorAction Stop
                    } else {
                        throw
                    }
                }
                finally {
                    Stop-Job   -Job $graphJob -ErrorAction SilentlyContinue
                    Remove-Job -Job $graphJob -Force -ErrorAction SilentlyContinue
                }
            }
            else {
                # Confirmed premium tenant, or ThreadJob unavailable - direct call.
                $signInLogs = Get-MgBetaAuditLogSignIn -Filter $filter -All -ErrorAction Stop
            }

            Write-Log "Premium Graph API successful: $($signInLogs.Count) total records" -Level "Info"

            # The signIns endpoint returns interactive sign-ins only unless signInEventTypes
            # is filtered explicitly.
            if ($IncludeNonInteractive) {
                try {
                    Update-GuiStatus "Querying non-interactive sign-ins (this can be large)..." ([System.Drawing.Color]::Orange)
                    $nonInteractiveFilter = "$filter and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
                    $nonInteractiveLogs = @(Get-MgBetaAuditLogSignIn -Filter $nonInteractiveFilter -All -ErrorAction Stop)
                    Write-Log "Non-interactive sign-ins retrieved: $($nonInteractiveLogs.Count)" -Level "Info"
                    $seenIds = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($existing in @($signInLogs)) { [void]$seenIds.Add("$($existing.Id)") }
                    $merged = [System.Collections.Generic.List[object]]::new()
                    $merged.AddRange([object[]]@($signInLogs))
                    foreach ($record in $nonInteractiveLogs) { if ($seenIds.Add("$($record.Id)")) { $merged.Add($record) } }
                    $signInLogs = $merged.ToArray()
                }
                catch {
                    $coverageComplete = $false
                    $coverageGaps.Add("non-interactive sign-in query failed ($($_.Exception.Message)); only interactive sign-ins were collected")
                    Write-Log "Non-interactive sign-in query failed: $($_.Exception.Message)" -Level "Warning"
                }
            }
            else {
                $coverageGaps.Add("interactive sign-ins only; non-interactive sign-ins (token replay, legacy protocols, background access) are not collected unless -IncludeNonInteractive is used")
            }
            Update-GuiStatus "Premium Graph API successful - $($signInLogs.Count) records retrieved" ([System.Drawing.Color]::Green)
        }
        catch {
            $errorMessage = $_.Exception.Message
            $innerException = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { "None" }
            Write-Log "Premium Graph API failed: [$($_.Exception.GetType().Name)] : $errorMessage" -Level "Warning"
            if ($innerException -ne "None") {
                Write-Log "Inner exception details: $innerException" -Level "Warning"
            }
            
            # A timeout or 403 on a tenant with a CONFIRMED premium license is not a licensing
            # problem. Falling back would silently swap in 10 days of degraded data, so fail loudly.
            if ($premiumState -eq $true -and
                ($errorMessage -match "HttpClient.Timeout|adaptive timeout|Forbidden|403|Authorization_RequestDenied")) {
                Update-GuiStatus "Premium sign-in query failed on a licensed tenant - see log" ([System.Drawing.Color]::Red)
                throw "Premium sign-in query failed on a tenant with a confirmed Entra ID P1/P2 license: $errorMessage. Not falling back to the 10-day Exchange Online source. Check AuditLog.Read.All consent and the admin's Entra role (Reports Reader, Security Reader or higher), or reduce the date range and retry."
            }

            # Check if the error indicates lack of premium license or B2C tenant
            if ($errorMessage -match "Authentication_RequestFromNonPremiumTenantOrB2CTenant" -or
                $errorMessage -match "premium license" -or
                $errorMessage -match "B2C tenant" -or
                $errorMessage -match "HttpClient.Timeout" -or
                $errorMessage -match "adaptive timeout" -or
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
                        $coverageComplete = $false
                        $coverageGaps.Add("Exchange Online unified audit log fallback used: $fallbackDaysBack day(s) of data (requested $DaysBack); Conditional Access, risk level and device fields are unavailable")
                        if (-not $Global:ExchangeOnlineState.LastCollectionComplete) {
                            $coverageGaps.Add("fallback pull had gaps: $($Global:ExchangeOnlineState.LastCollectionWarning)")
                        }
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
            Remove-StaleOutput -Path @(
                $OutputPath,
                ($OutputPath -replace '\.csv$', '_Unusual.csv'),
                ($OutputPath -replace '\.csv$', '_Failed.csv'),
                (Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"),
                (Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv")
            )
            Set-CollectionStatus -Source "SignIns" -Complete $false -Records 0 -Note "No sign-in records were returned for the requested range; there is no sign-in data to analyze."
            return @()
        }
        
        Update-GuiStatus "Retrieved $($signInLogs.Count) sign-in records" ([System.Drawing.Color]::Orange)
        
        #═══════════════════════════════════════════════════════════════════════
        # EXTRACT AND DEDUPLICATE IP ADDRESSES
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Extracting unique IP addresses..." ([System.Drawing.Color]::Orange)
        
        $uniqueIPs = $signInLogs |
            Where-Object { -not [string]::IsNullOrEmpty($_.IpAddress) -and $_.IpAddress -ne "Unknown" } |
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

                if ($geolocatedCount % 5 -eq 0 -or $geolocatedCount -eq 1) {
                    $percentage = [math]::Round(($geolocatedCount / $uniqueIPs.Count) * 100, 1)
                    Update-GuiStatus "Geolocating: $geolocatedCount/$($uniqueIPs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                    [System.Windows.Forms.Application]::DoEvents()
                }

                # Check if this IP is already cached (to avoid unnecessary delays)
                $wasCached = $ipCache.ContainsKey($ip)

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

                # Rate limiting: Only delay if configured, not cached, and not last IP
                if ($ConfigData.GeolocationRateLimit -gt 0 -and -not $wasCached -and $geolocatedCount -lt $uniqueIPs.Count) {
                    Start-Sleep -Seconds $ConfigData.GeolocationRateLimit
                }
            }
            
            Write-Log "Geolocation completed for $($ipCache.Count) IP addresses" -Level "Info"
        }
        
        #═══════════════════════════════════════════════════════════════════════
        # PROCESS SIGN-IN RECORDS WITH GEOLOCATION
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Processing sign-in records with geolocation data..." ([System.Drawing.Color]::Orange)
        Write-Log "Processing all sign-in records with geolocation enrichment" -Level "Info"
        
        $results = [System.Collections.Generic.List[PSCustomObject]]::new($signInLogs.Count)
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
            $geoLookupFailed = $false
            
            # Apply geolocation data if available (skip placeholder "Unknown" values)
            if (-not [string]::IsNullOrEmpty($ip) -and $ip -ne "Unknown") {
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
                            $ip -match "^f[cd][0-9a-fA-F]{2}:" -or       # Unique local (fc00::/7)
                            $ip -match "^ff[0-9a-fA-F]{2}:") {           # Multicast
                            
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
            
            # A public IP with no usable geolocation is NOT "expected" - it just could not be
            # evaluated. Flag it so those sign-ins are not silently treated as normal.
            if (-not [string]::IsNullOrEmpty($ip) -and $ip -ne "Unknown" -and -not $isPrivateIP -and $country -eq "Unknown") {
                $geoLookupFailed = $true
            }

			# Check if ISP is in high-risk list
			$isHighRiskISP = $false
			if (-not [string]::IsNullOrEmpty($isp) -and $isp -ne "Unknown" -and $isp -ne "Private Network") {
				foreach ($highRiskProvider in $script:HighRiskISPs) {
					if ($isp.Trim() -ieq $highRiskProvider.Trim()) {
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
                GeoLookupFailed = $geoLookupFailed
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
            
            $results.Add($resultObject)
        }
        
        Write-Log "Processed $($results.Count) sign-in records with geolocation" -Level "Info"
        
        #═══════════════════════════════════════════════════════════════════════
        # EXPORT RESULTS
        #═══════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Exporting sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Remove the previous run's derived files - they are only rewritten when non-empty,
        # so a clean run would otherwise leave old unusual/failed sign-ins on disk.
        Remove-StaleOutput -Path @(
            $OutputPath,
            ($OutputPath -replace '\.csv$', '_Unusual.csv'),
            ($OutputPath -replace '\.csv$', '_Failed.csv'),
            (Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"),
            (Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv")
        )

        # Export main results
        $resultsArray = $results.ToArray()
        $resultsArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Log "Exported all sign-in data to: $OutputPath" -Level "Info"
        
        # Export unusual locations
        $unusualSignIns = $resultsArray | Where-Object { $_.IsUnusualLocation -eq $true }
        if ($unusualSignIns.Count -gt 0) {
            $unusualOutputPath = $OutputPath -replace '.csv$', '_Unusual.csv'
            $unusualSignIns | Export-Csv -Path $unusualOutputPath -NoTypeInformation -Force
            Write-Log "Exported $($unusualSignIns.Count) unusual location sign-ins to: $unusualOutputPath" -Level "Info"
        }
        
        # Export failed sign-ins
        $failedSignIns = $resultsArray | Where-Object { $_.StatusCode -ne "0" -and ![string]::IsNullOrEmpty($_.StatusCode) }
        if ($failedSignIns.Count -gt 0) {
            $failedOutputPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedSignIns | Export-Csv -Path $failedOutputPath -NoTypeInformation -Force
            Write-Log "Exported $($failedSignIns.Count) failed sign-ins to: $failedOutputPath" -Level "Info"
        }
        
        # Generate unique locations report
        Update-GuiStatus "Generating unique locations report..." ([System.Drawing.Color]::Orange)
        
        $uniqueLogins = [System.Collections.Generic.List[PSCustomObject]]::new()
        $userLocationGroups = $resultsArray | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            $uniqueUserLocations = $userSignIns |
                Select-Object UserId, UserDisplayName, IP, IPVersion, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) -and $_.IP -ne "Unknown" }

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
                
                $uniqueLogins.Add($uniqueLogin)
            }
        }
        
        # Export unique logins
        if ($uniqueLogins.Count -gt 0) {
            $uniqueLoginsArray = $uniqueLogins.ToArray()
            $uniqueLoginsPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"
            $uniqueLoginsArray | Export-Csv -Path $uniqueLoginsPath -NoTypeInformation -Force
            Write-Log "Exported $($uniqueLogins.Count) unique location records to: $uniqueLoginsPath" -Level "Info"
            
            $unusualUniqueLogins = $uniqueLoginsArray | Where-Object { $_.IsUnusualLocation -eq $true }
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
        
        # Record coverage limits so the report cannot present this as a complete picture.
        $geoFailedCount = @($resultsArray | Where-Object { $_.GeoLookupFailed -eq $true }).Count
        if ($geoFailedCount -gt 0) {
            $coverageComplete = $false
            $coverageGaps.Add("$geoFailedCount sign-in(s) came from public IPs that could not be geolocated (lookup failure or quota); they are NOT evaluated for unusual location")
        }
        $noIpCount = @($resultsArray | Where-Object { [string]::IsNullOrWhiteSpace($_.IP) -or $_.IP -eq "Unknown" }).Count
        if ($noIpCount -gt 0) {
            $coverageComplete = $false
            $coverageGaps.Add("$noIpCount sign-in(s) have no source IP; location, spray and breach analysis cannot evaluate them")
        }
        Set-CollectionStatus -Source "SignIns" -Complete $coverageComplete -Records $results.Count -Note ($coverageGaps -join "; ")
        foreach ($gap in $coverageGaps) { Write-Log "SIGN-IN COVERAGE: $gap" -Level "Warning" }

        Update-GuiStatus "Sign-in collection complete: $($results.Count) records ($($unusualSignIns.Count) unusual, $($failedSignIns.Count) failed)" ([System.Drawing.Color]::Green)
        
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "SIGN-IN DATA COLLECTION COMPLETED" -Level "Info"
        Write-Log "Data Source: $(if ($isPremiumTenant) { "Premium Graph API" } else { "Exchange Online Fallback" })" -Level "Info"
        if (-not $isPremiumTenant -and -not $Global:ExchangeOnlineState.LastCollectionComplete) {
            Write-Log "DATA COMPLETENESS: INCOMPLETE - $($Global:ExchangeOnlineState.LastCollectionWarning)" -Level "Error"
        }
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "Total Sign-ins: $($results.Count)" -Level "Info"
        Write-Log "  IPv4 Addresses: $ipv4Count" -Level "Info"
        Write-Log "  IPv6 Addresses: $ipv6Count" -Level "Info"
        Write-Log "  Private IPs: $privateIPCount" -Level "Info"
        Write-Log "Unusual Locations: $($unusualSignIns.Count)" -Level "Info"
        Write-Log "Unique IP Locations: $($uniqueLogins.Count)" -Level "Info"
        Write-Log "Geolocation Cache: $($ipCache.Count) IPs cached" -Level "Info"
        if (-not $isPremiumTenant -and $ipv4Count -eq 0 -and $ipv6Count -eq 0) {
            Write-Log "  Note: IP addresses were null in these audit records (varies by tenant auth flow)" -Level "Info"
        }
        Write-Log "Failed Sign-ins: $($failedSignIns.Count)" -Level "Info"
        Write-Log "Output Files:" -Level "Info"
        Write-Log "  Main: $OutputPath" -Level "Info"
        if ($unusualSignIns.Count -gt 0) {
            Write-Log "  Unusual: $($OutputPath -replace '.csv$', '_Unusual.csv')" -Level "Info"
        }
        if ($failedSignIns.Count -gt 0) {
            Write-Log "  Failed: $($OutputPath -replace '.csv$', '_Failed.csv')" -Level "Info"
        }
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        
        return $resultsArray
    }
    catch {
        Update-GuiStatus "Error collecting sign-in data: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in sign-in data collection: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
        Set-CollectionStatus -Source "SignIns" -Complete $false -Records 0 -Note "Sign-in collection FAILED ($($_.Exception.Message)); any sign-in CSV in the working directory is from an EARLIER run and may be stale."
        return $null
    }
}

function Get-UalStsLogonWindow {
    <#
    .SYNOPSIS
        Pulls every AzureActiveDirectoryStsLogon unified audit log record in [Start, End).

    .DESCRIPTION
        Search-UnifiedAuditLog with SessionCommand ReturnLargeSet exposes at most 50,000
        records per session and returns them unsorted. Two things matter for completeness:
        - Paging continues until the cmdlet returns ZERO records (per Microsoft's docs), not
          until a page comes back smaller than ResultSize.
        - If a window returns the 50,000-record ceiling it is almost certainly truncated,
          so it is split in half and each half re-queried. If a window cannot be split
          further it is reported in TruncatedWindows instead of being passed off as complete.

    .OUTPUTS
        Hashtable: Records (List of audit records), TruncatedWindows (List of strings)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$Start,

        [Parameter(Mandatory = $true)]
        [datetime]$End
    )

    $sessionCap = 50000
    $minWindow = [TimeSpan]::FromMinutes(30)
    $maxPages = 60   # safety stop (300k records)

    $records = [System.Collections.Generic.List[object]]::new()
    $truncated = [System.Collections.Generic.List[string]]::new()
    $sessionId = [Guid]::NewGuid().ToString() + "_SignIn"
    $pageCount = 0

    do {
        $pageCount++
        $page = @(Search-UnifiedAuditLog `
            -StartDate $Start `
            -EndDate $End `
            -RecordType "AzureActiveDirectoryStsLogon" `
            -ResultSize 5000 `
            -SessionId $sessionId `
            -SessionCommand ReturnLargeSet `
            -ErrorAction Stop)

        if ($page.Count -gt 0) {
            $records.AddRange([object[]]$page)
            Write-Log "  Page $pageCount : Retrieved $($page.Count) records" -Level "Info"
        }
    } while ($page.Count -gt 0 -and $pageCount -lt $maxPages)

    if ($records.Count -ge $sessionCap -and ($End - $Start) -gt $minWindow) {
        # Hit the per-session ceiling: discard and re-pull as two smaller windows.
        $mid = $Start.AddTicks([long](($End - $Start).Ticks / 2))
        Write-Log "  Window $($Start.ToString('yyyy-MM-dd HH:mm')) to $($End.ToString('yyyy-MM-dd HH:mm')) hit the $sessionCap-record ceiling - splitting" -Level "Warning"
        $first = Get-UalStsLogonWindow -Start $Start -End $mid
        $second = Get-UalStsLogonWindow -Start $mid -End $End
        $merged = [System.Collections.Generic.List[object]]::new()
        $merged.AddRange($first.Records)
        $merged.AddRange($second.Records)
        $truncated.AddRange($first.TruncatedWindows)
        $truncated.AddRange($second.TruncatedWindows)
        return @{ Records = $merged; TruncatedWindows = $truncated }
    }

    if ($records.Count -ge $sessionCap) {
        $truncated.Add("$($Start.ToString('yyyy-MM-dd HH:mm')) to $($End.ToString('yyyy-MM-dd HH:mm')) (hit the $sessionCap-record ceiling in a window that cannot be split further)")
    }
    if ($pageCount -ge $maxPages -and $page.Count -gt 0) {
        $truncated.Add("$($Start.ToString('yyyy-MM-dd HH:mm')) to $($End.ToString('yyyy-MM-dd HH:mm')) (paging safety limit reached)")
    }

    return @{ Records = $records; TruncatedWindows = $truncated }
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
        $auditLogs = [System.Collections.Generic.List[object]]::new()
        $currentStart = $startDate
        $chunkNumber = 0
        $totalRecords = 0
        $failedChunks = 0
        $failedRanges = [System.Collections.Generic.List[string]]::new()
        $truncatedWindows = [System.Collections.Generic.List[string]]::new()

        # Assume complete until a chunk fails; reset here so a previous run's state
        # does not bleed into this collection.
        $Global:ExchangeOnlineState.LastCollectionComplete = $true
        $Global:ExchangeOnlineState.LastCollectionWarning = $null
        
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
                # Pages until the cmdlet returns zero records and splits any window that hits
                # the 50,000-record ReturnLargeSet ceiling (see Get-UalStsLogonWindow).
                $window = Get-UalStsLogonWindow -Start $currentStart -End $currentEnd
                $chunkLogs = $window.Records
                foreach ($truncatedWindow in $window.TruncatedWindows) { $truncatedWindows.Add($truncatedWindow) }

                Write-Log "Chunk $chunkNumber complete: $($chunkLogs.Count) records" -Level "Info"

                if ($chunkLogs.Count -gt 0) {
                    $auditLogs.AddRange([object[]]$chunkLogs.ToArray())
                    $totalRecords += $chunkLogs.Count
                }
            }
            catch {
                # A failed chunk means this time window is missing from the dataset.
                # Track it so the caller/report can flag the results as incomplete rather
                # than presenting a partial pull as if it covered the full range.
                $failedChunks++
                $rangeText = "$($currentStart.ToString('yyyy-MM-dd HH:mm')) to $($currentEnd.ToString('yyyy-MM-dd HH:mm'))"
                $failedRanges.Add($rangeText)
                Write-Log "Error in chunk ${chunkNumber} ($rangeText): $($_.Exception.Message)" -Level "Warning"
            }

            Update-GuiStatus "Progress: $chunkNumber/$expectedChunks chunks. Total: $totalRecords records" ([System.Drawing.Color]::Green)
            [System.Windows.Forms.Application]::DoEvents()
            $currentStart = $currentEnd
        }
        
        Write-Log "Completed all $chunkNumber chunks: $totalRecords total audit log entries" -Level "Info"

        # If any chunk failed, the dataset has gaps. Make this loud rather than silent so
        # downstream analysis and the report are not mistaken for full-coverage results.
        $exoWarnings = @()
        if ($failedChunks -gt 0) {
            $exoWarnings += "$failedChunks of $chunkNumber EXO chunks failed - sign-in data is INCOMPLETE for: $($failedRanges -join '; ')"
        }
        if ($truncatedWindows.Count -gt 0) {
            $exoWarnings += "unified audit log ceiling reached, records TRUNCATED for: $($truncatedWindows -join '; ')"
        }
        if ($exoWarnings.Count -gt 0) {
            $warning = $exoWarnings -join ' | '
            $Global:ExchangeOnlineState.LastCollectionComplete = $false
            $Global:ExchangeOnlineState.LastCollectionWarning = $warning
            Write-Log $warning -Level "Error"
            Update-GuiStatus "WARNING: EXO sign-in pull is incomplete (see log)" ([System.Drawing.Color]::Red)
        }

        # Remove duplicates (ReturnLargeSet returns unsorted data with dupes)
        if ($auditLogs.Count -gt 0) {
            Write-Log "Removing duplicate records..." -Level "Info"
            $originalCount = $auditLogs.Count
            $auditLogs = @($auditLogs | Sort-Object Identity -Unique)
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
        
        $signInResults = [System.Collections.Generic.List[PSCustomObject]]::new($auditLogs.Count)
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
                } elseif ($auditDetails.IPAddress) {
                    # AzureActiveDirectoryStsLogon (RecordType 15) uses IPAddress as top-level field
                    $auditDetails.IPAddress
                } elseif ($auditDetails.ActorIpAddress) {
                    $auditDetails.ActorIpAddress
                } elseif ($auditDetails.ExtendedProperties) {
                    $ipProp = $auditDetails.ExtendedProperties | Where-Object { $_.Name -eq "ipaddr" -or $_.Name -eq "IP" -or $_.Name -eq "IPAddress" } | Select-Object -First 1
                    if ($ipProp) { $ipProp.Value } else { "Unknown" }
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
								default { $statusCode = "UNKNOWN" }  # Unmapped text: do not guess a cause (50126 would inflate spray/brute-force counts)
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
				# (also covers UserLoggedIn records whose ResultStatus is Failed)
				elseif ($auditDetails.ResultStatus -and $auditDetails.ResultStatus -match "Failed|Failure|Error") {
					if ($auditDetails.ResultStatus -match '(\d{5,6})') {
						$statusCode = $matches[1]
					} else {
						$statusCode = "UNKNOWN"
					}
					$statusDescription = "Failed - " + $auditDetails.ResultStatus
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
                    # The audit log does not carry these; say so instead of asserting "notApplied"/"none"
                    ConditionalAccessStatus = "notAvailable"
                    RiskLevelDuringSignIn = "notAvailable"
                    DeviceDetail = @{
                        OperatingSystem = "Unknown"
                        Browser = "Unknown"
                    }
                }
                
                $signInResults.Add($signInRecord)
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
        
        $signInResultsArray = $signInResults.ToArray()
        
        Update-GuiStatus "Exchange Online complete: $($signInResultsArray.Count) records ready for geolocation" ([System.Drawing.Color]::Green)
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "EXCHANGE ONLINE FALLBACK COMPLETED" -Level "Info"
        Write-Log "Created $($signInResultsArray.Count) sign-in records" -Level "Info"
        Write-Log "Returning to Get-TenantSignInData for geolocation" -Level "Info"
        Write-Log "═════════════════════════════════════════════════════════" -Level "Info"
        
        return $signInResultsArray
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
        # -ErrorAction Stop: a 403/throttle must reach the catch (State = unknown, caller falls back
        # to sign-in analysis) instead of being read as "per-user MFA disabled".
        $authRequirements = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        
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
        $startDate = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startDate"
        $signIns = Get-MgBetaAuditLogSignIn -Filter $filter -Top 100 -ErrorAction Stop
        
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

        CONDITIONAL ACCESS CREDIT (a policy counts as MFA enforcement only when it):
        • is enabled, and grants via "mfa" or an authentication strength (compliantDevice
          alone is NOT MFA; an OR operator with other grant options is not enforcement)
        • includes the user by All / user / group (transitive membership) / role, and does
          not exclude them by user / group / role / guest type
        • targets All cloud apps, All client app types and All platforms, and is not
          risk-conditioned. Policies that are narrower are listed in PartialCAPolicies and
          not credited as full enforcement.

        ADMIN DETECTION uses directory role assignments (active AND PIM-eligible, including
        role-assignable groups), not group names.

        API failures are never read as "no MFA": if registered methods cannot be read the
        user is reported as HasMFA = Unknown, and every gap is recorded in
        CollectionStatus.csv. Disabled accounts (and guests when SkipGuests is set) are
        skipped and counted in the log.
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
        
        $mfaGaps = [System.Collections.Generic.List[string]]::new()

        # Check Security Defaults
        $securityDefaultsEnabled = $false
        try {
            $policyUri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            $securityDefaultsPolicy = Invoke-MgGraphRequest -Uri $policyUri -Method GET -ErrorAction Stop
            
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
            $mfaGaps.Add("Security Defaults state could not be read; tenant-wide MFA enforcement via Security Defaults would not be credited")
            Write-Log "Could not check Security Defaults: $($_.Exception.Message)" -Level "Warning"
        }
        
        # Get Conditional Access Policies
        $caPolicies = @()
        try {
            $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
            Write-Log "Found $($caPolicies.Count) Conditional Access policies" -Level "Info"
        }
        catch {
            $mfaGaps.Add("Conditional Access policies could not be read; MFA enforced through CA would not be credited, so users may appear unprotected")
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
        
        $mfaResults = [System.Collections.Generic.List[PSCustomObject]]::new($users.Count)
        $processedCount = 0
        
        # ═══════════════════════════════════════════════════════════════════════════
        # PRE-CACHE: Group memberships for Conditional Access evaluation
        # ═══════════════════════════════════════════════════════════════════════════
        $groupMembershipCache = @{}
        $failedGroupIds = [System.Collections.Generic.HashSet[string]]::new()

        if ($caPolicies.Count -gt 0) {
            Update-GuiStatus "Pre-caching group memberships for CA policy evaluation..." ([System.Drawing.Color]::Orange)
            Write-Log "Building group membership cache for Conditional Access policies..." -Level "Info"
            
            $allGroupIds = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($policy in $caPolicies) {
                if ($policy.Conditions.Users.IncludeGroups) {
                    foreach ($gid in $policy.Conditions.Users.IncludeGroups) {
                        [void]$allGroupIds.Add($gid)
                    }
                }
                if ($policy.Conditions.Users.ExcludeGroups) {
                    foreach ($gid in $policy.Conditions.Users.ExcludeGroups) {
                        [void]$allGroupIds.Add($gid)
                    }
                }
            }
            
            Write-Log "Found $($allGroupIds.Count) unique groups referenced in CA policies" -Level "Info"
            
            foreach ($groupId in $allGroupIds) {
                try {
                    # Use -ErrorAction Stop so a permission/throttle failure is caught and
                    # tracked, rather than silently returning $null and being cached as an
                    # empty group (which is indistinguishable from a genuinely empty group
                    # and would make in-scope users look uncovered).
                    # Transitive: users in nested groups are in scope of (or excluded by) the policy too.
                    $members = Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction Stop
                    $memberIdSet = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($m in $members) {
                        [void]$memberIdSet.Add($m.Id)
                    }
                    $groupMembershipCache[$groupId] = $memberIdSet
                    Write-Log "  Cached group $groupId : $($memberIdSet.Count) members" -Level "Info"
                }
                catch {
                    $groupMembershipCache[$groupId] = [System.Collections.Generic.HashSet[string]]::new()
                    [void]$failedGroupIds.Add($groupId)
                    Write-Log "  Failed to cache group ${groupId}: $($_.Exception.Message)" -Level "Warning"
                }
            }

            Write-Log "Group membership cache built: $($groupMembershipCache.Count) groups cached" -Level "Info"
            if ($failedGroupIds.Count -gt 0) {
                $mfaGaps.Add("$($failedGroupIds.Count) group(s) referenced by Conditional Access policies could not be read; CA coverage for their members may be misreported")
                Write-Log "WARNING: $($failedGroupIds.Count) CA group(s) could not be read. Conditional Access coverage for users in those groups may be reported as absent when it is not. Affected group IDs: $($failedGroupIds -join ', ')" -Level "Error"
            }
        }
        
        # Directory role assignments (active + PIM eligible) - used for admin detection and for
        # role-targeted Conditional Access policies (IncludeRoles / ExcludeRoles).
        Update-GuiStatus "Reading directory role assignments..." ([System.Drawing.Color]::Orange)
        $adminMap = Get-AdminRoleMap
        foreach ($roleWarning in $adminMap.Warnings) {
            $mfaGaps.Add($roleWarning)
            Write-Log "Role assignment lookup: $roleWarning" -Level "Warning"
        }
        $authMethodFailures = 0
        $skippedDisabled = 0
        $skippedGuests = 0

        foreach ($user in $users) {
            $processedCount++
            
            # Progress update
            if ($processedCount % 10 -eq 0) {
                $percentage = [Math]::Round(($processedCount / $users.Count) * 100, 1)
                Update-GuiStatus "Processing users: $processedCount of $($users.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            Write-Log "Processing: $($user.UserPrincipalName)" -Level "Info"
            
            if ($user.AccountEnabled -eq $false) {
                $skippedDisabled++
                Write-Log "Skipping disabled account: $($user.UserPrincipalName)" -Level "Info"
                continue
            }

            # Skip guests if configured
            if ($user.UserType -eq "Guest" -and $ConfigData.SkipGuests) {
                $skippedGuests++
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
            $partialPolicies = @()

            $userRoleTemplateIds = if ($adminMap.Users.ContainsKey($user.Id)) { $adminMap.Users[$user.Id].TemplateIds } else { $null }
            $userIsGuest = ($user.UserType -eq "Guest")
            
            if ($caPolicies.Count -gt 0) {
                foreach ($policy in $caPolicies) {
                    if ($policy.State -ne "enabled") { continue }
                    
                    # Grant controls: MFA via the built-in "mfa" control or an authentication
                    # strength. compliantDevice is NOT MFA and is not credited. With operator OR
                    # and more than one grant option the user can satisfy the policy without MFA.
                    $requiresMFA = $false
                    if ($policy.GrantControls) {
                        # NOTE: @($null).Count is 1 in PowerShell, so absent properties are
                        # filtered before counting.
                        $builtInControls = @($policy.GrantControls.BuiltInControls | Where-Object { $_ })
                        $hasAuthStrength = ($null -ne $policy.GrantControls.AuthenticationStrength)
                        $grantOptionCount = $builtInControls.Count +
                            $(if ($hasAuthStrength) { 1 } else { 0 }) +
                            @($policy.GrantControls.CustomAuthenticationFactors | Where-Object { $_ }).Count +
                            @($policy.GrantControls.TermsOfUse | Where-Object { $_ }).Count
                        $offersMfa = ($builtInControls -contains "mfa") -or $hasAuthStrength
                        if ($offersMfa -and ($policy.GrantControls.Operator -ne "OR" -or $grantOptionCount -le 1)) {
                            $requiresMFA = $true
                        }
                    }
                    
                    if (-not $requiresMFA) { continue }
                    
                    $policyUsers = $policy.Conditions.Users

                    # Check if user is in scope: All, listed user, group (cache), role, guest type
                    $userInScope = $false
                    
                    if ($policyUsers.IncludeUsers -contains "All" -or
                        $policyUsers.IncludeUsers -contains $user.Id) {
                        $userInScope = $true
                    }
                    
                    if (-not $userInScope -and $policyUsers.IncludeGroups) {
                        foreach ($groupId in $policyUsers.IncludeGroups) {
                            if ($groupMembershipCache.ContainsKey($groupId) -and
                                $groupMembershipCache[$groupId].Contains($user.Id)) {
                                $userInScope = $true
                                break
                            }
                        }
                    }

                    if (-not $userInScope -and $policyUsers.IncludeRoles -and $userRoleTemplateIds) {
                        foreach ($roleId in $policyUsers.IncludeRoles) {
                            if ($userRoleTemplateIds.Contains("$roleId")) { $userInScope = $true; break }
                        }
                    }

                    if (-not $userInScope -and $userIsGuest -and $policyUsers.IncludeGuestsOrExternalUsers) {
                        $userInScope = $true
                    }
                    
                    # Exclusions: user, group (cache), role, guest type
                    if ($userInScope) {
                        if ($policyUsers.ExcludeUsers -contains $user.Id) {
                            $userInScope = $false
                        }
                        
                        if ($userInScope -and $policyUsers.ExcludeGroups) {
                            foreach ($groupId in $policyUsers.ExcludeGroups) {
                                if ($groupMembershipCache.ContainsKey($groupId) -and
                                    $groupMembershipCache[$groupId].Contains($user.Id)) {
                                    $userInScope = $false
                                    break
                                }
                            }
                        }

                        if ($userInScope -and $policyUsers.ExcludeRoles -and $userRoleTemplateIds) {
                            foreach ($roleId in $policyUsers.ExcludeRoles) {
                                if ($userRoleTemplateIds.Contains("$roleId")) { $userInScope = $false; break }
                            }
                        }

                        if ($userInScope -and $userIsGuest -and $policyUsers.ExcludeGuestsOrExternalUsers) {
                            $userInScope = $false
                        }
                    }
                    
                    if (-not $userInScope) { continue }

                    # The policy applies to this user; it only counts as FULL MFA enforcement if
                    # it is not narrowed by app, client type, platform or risk condition.
                    $narrowedBy = @()
                    if ($policy.Conditions.Applications.IncludeApplications -notcontains "All") { $narrowedBy += "specific apps only" }
                    $clientTypes = @($policy.Conditions.ClientAppTypes | Where-Object { $_ })
                    if ($clientTypes.Count -gt 0 -and $clientTypes -notcontains "all") { $narrowedBy += "limited client app types" }
                    $includedPlatforms = @($policy.Conditions.Platforms.IncludePlatforms | Where-Object { $_ })
                    if ($includedPlatforms.Count -gt 0 -and $includedPlatforms -notcontains "all") { $narrowedBy += "limited platforms" }
                    if (@($policy.Conditions.UserRiskLevels | Where-Object { $_ }).Count -gt 0 -or @($policy.Conditions.SignInRiskLevels | Where-Object { $_ }).Count -gt 0) { $narrowedBy += "risk-conditioned" }

                    if ($narrowedBy.Count -gt 0) {
                        $partialPolicies += "$($policy.DisplayName) [$($narrowedBy -join ', ')]"
                    }
                    else {
                        $caPolicyEnforced = $true
                        $policyLabel = $policy.DisplayName
                        if (@($policy.Conditions.Locations.ExcludeLocations) -contains "AllTrusted") { $policyLabel += " (exempts trusted locations)" }
                        $applicablePolicies += $policyLabel
                    }
                }
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CHECK 3: MFA REGISTRATION STATUS
            # ═══════════════════════════════════════════════════════════════════════════
            
            $registeredMethods = @()
            $hasMFAMethods = $false
            $authMethodsFailed = $false
            
            try {
                # -ErrorAction Stop with throttle retry: a failure here must not look like
                # "this user has no methods registered".
                $authMethods = $null
                for ($authAttempt = 1; $authAttempt -le 3; $authAttempt++) {
                    try {
                        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
                        break
                    }
                    catch {
                        if ($_.Exception.Message -match '429|503|throttl|too many requests|TooManyRequests' -and $authAttempt -lt 3) {
                            Start-Sleep -Seconds ([Math]::Pow(2, $authAttempt))
                        }
                        else { throw }
                    }
                }
                
                if ($authMethods) {
                    foreach ($method in $authMethods) {
                        $methodType = $method.AdditionalProperties.'@odata.type'
                        
                        # Email is an SSPR method, not MFA, so it is not counted. Windows Hello
                        # for Business is strong MFA-equivalent.
                        if ($methodType -match "microsoftAuthenticator|phone|softwareOath|fido2|windowsHelloForBusiness") {
                            $registeredMethods += $methodType -replace '#microsoft.graph.', ''
                            $hasMFAMethods = $true
                        }
                    }
                }
            }
            catch {
                $authMethodsFailed = $true
                $authMethodFailures++
                Write-Log "Could not retrieve auth methods for $($user.UserPrincipalName): $($_.Exception.Message)" -Level "Warning"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CHECK 4: ADMIN ROLE DETECTION
            # ═══════════════════════════════════════════════════════════════════════════
            
            $isAdmin = $false
            $adminRoles = @()
            
            # From the pre-built role map: active AND PIM-eligible assignments, role-assignable
            # groups expanded. (The old check matched any group/role NAME containing "Admin".)
            if ($adminMap.Users.ContainsKey($user.Id)) {
                $roleEntry = $adminMap.Users[$user.Id]
                foreach ($roleName in @($roleEntry.Active | Select-Object -Unique)) {
                    if ($roleName -like '*Admin*') { $isAdmin = $true; $adminRoles += $roleName }
                }
                foreach ($roleName in @($roleEntry.Eligible | Select-Object -Unique)) {
                    if ($roleName -like '*Admin*') { $isAdmin = $true; $adminRoles += "$roleName (eligible)" }
                }
            }
            
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
            
            if ($authMethodsFailed) {
                $hasMFAValue = "Unknown"
                $mfaStatusDetail = "[WARNING] Registered MFA methods could not be read (permission or throttling) - MFA status NOT verified"
            }
            elseif ($mfaEnforced -and $mfaCapable) {
                $hasMFAValue = "Yes"
                $enforcementList = $enforcementMethod -join " + "
                $mfaStatusDetail = "[OK] Enforced via $enforcementList with $($registeredMethods.Count) method(s) registered"
            }
            elseif ($mfaEnforced -and -not $mfaCapable) {
                $hasMFAValue = "Partial"
                $enforcementList = $enforcementMethod -join " + "
                $mfaStatusDetail = "[WARNING] Enforced via $enforcementList but NO methods registered (broken state)"
            }
            elseif (-not $mfaEnforced -and $mfaCapable) {
                $hasMFAValue = "Capable"
                $mfaStatusDetail = "[WARNING] Methods registered ($($registeredMethods.Count)) but NOT enforced"
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
                $mfaStatusDetail = "[ERROR] No MFA enforcement or registration"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # RISK ASSESSMENT
            # ═══════════════════════════════════════════════════════════════════════════
            
            $riskLevel = "Low"
            $recommendation = ""
            
            if ($hasMFAValue -eq "No") {
                if ($isAdmin) {
                    $riskLevel = "Critical"
                    $recommendation = "[CRITICAL] CRITICAL: Admin account with NO MFA - Enable immediately!"
                }
                else {
                    $riskLevel = "High"
                    $recommendation = "[CRITICAL] HIGH: No MFA protection - Enable enforcement and register methods"
                }
            }
            elseif ($hasMFAValue -eq "Partial") {
                if ($isAdmin) {
                    $riskLevel = "Critical"
                    $recommendation = "[CRITICAL] CRITICAL: MFA enforced but no methods registered - User cannot sign in!"
                }
                else {
                    $riskLevel = "High"
                    $recommendation = "[WARNING] HIGH: MFA enforced but no methods - User needs to register auth methods"
                }
            }
            elseif ($hasMFAValue -eq "Capable") {
                if ($isAdmin) {
                    $riskLevel = "High"
                    $recommendation = "[WARNING] HIGH: Admin has MFA methods but not enforced - Enable enforcement"
                }
                else {
                    $riskLevel = "Medium"
                    $recommendation = "[ALERT] MEDIUM: MFA methods registered but not enforced - Enable per-user MFA or CA policy"
                }
            }
            elseif ($hasMFAValue -eq "Likely" -or $hasMFAValue -eq "Inconsistent" -or $hasMFAValue -eq "Unknown") {
                $riskLevel = "Medium"
                $recommendation = "[ALERT] MEDIUM: Cannot fully verify MFA status - Manual review recommended"
            }
            else {
                # Has MFA = Yes
                $riskLevel = "Low"
                $recommendation = "[OK] MFA properly configured"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # CREATE RESULT OBJECT
            # ═══════════════════════════════════════════════════════════════════════════
            
            $mfaResults.Add([PSCustomObject]@{
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
                ApplicablePolicies = ($applicablePolicies -join ", ")
                PartialCAPolicies = ($partialPolicies -join "; ")
                
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
            })
        }
        
        # ═══════════════════════════════════════════════════════════════════════════════
        # EXPORT RESULTS
        # ═══════════════════════════════════════════════════════════════════════════════
        
        if ($authMethodFailures -gt 0) {
            $mfaGaps.Add("$authMethodFailures user(s) had registered MFA methods that could not be read; they are reported as HasMFA = Unknown")
        }
        Write-Log "MFA audit skipped $skippedDisabled disabled account(s) and $skippedGuests guest(s)" -Level "Info"

        # Clear the previous run's files (variants are only rewritten when non-empty).
        Remove-StaleOutput -Path @(
            $OutputPath,
            ($OutputPath -replace '\.csv$', '_NoMFA.csv'),
            ($OutputPath -replace '\.csv$', '_PerUserOnly.csv'),
            ($OutputPath -replace '\.csv$', '_HighRisk.csv')
        )
        Set-CollectionStatus -Source "MFAAudit" -Complete ($mfaGaps.Count -eq 0) -Records $mfaResults.Count -Note ($mfaGaps -join "; ")

        if ($mfaResults.Count -gt 0) {
            Update-GuiStatus "Exporting MFA status data..." ([System.Drawing.Color]::Orange)
            
            # Export main results
            $mfaResultsArray = $mfaResults.ToArray()
            $mfaResultsArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Log "Exported MFA status to: $OutputPath" -Level "Info"
            
            # Export high-risk users
            $noMFA = $mfaResultsArray | Where-Object { $_.HasMFA -eq "No" -and $_.AccountEnabled -eq $true }
            if ($noMFA.Count -gt 0) {
                $noMFAPath = $OutputPath -replace '.csv$', '_NoMFA.csv'
                $noMFA | Export-Csv -Path $noMFAPath -NoTypeInformation -Force
                Write-Log "Exported $($noMFA.Count) users without MFA to: $noMFAPath" -Level "Warning"
            }
            
            # Export per-user MFA only
            $perUserOnly = $mfaResultsArray | Where-Object { 
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
            $highRisk = $mfaResultsArray | Where-Object { $_.RiskLevel -in @("Critical", "High") }
            if ($highRisk.Count -gt 0) {
                $highRiskPath = $OutputPath -replace '.csv$', '_HighRisk.csv'
                $highRisk | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
                Write-Log "Exported $($highRisk.Count) high-risk users to: $highRiskPath" -Level "Warning"
            }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # SUMMARY STATISTICS
            # ═══════════════════════════════════════════════════════════════════════════
            
            $totalUsers = $mfaResultsArray.Count
            $mfaEnabled = ($mfaResultsArray | Where-Object { $_.HasMFA -eq "Yes" }).Count
            $mfaCapable = ($mfaResultsArray | Where-Object { $_.HasMFA -eq "Capable" }).Count
            $noMFACount = ($mfaResultsArray | Where-Object { $_.HasMFA -eq "No" }).Count
            $criticalRisk = ($mfaResultsArray | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highRisk = ($mfaResultsArray | Where-Object { $_.RiskLevel -eq "High" }).Count
            
            $betaAPICount = ($mfaResultsArray | Where-Object { $_.DetectionSource -eq "Beta API" }).Count
            $signInAnalysisCount = ($mfaResultsArray | Where-Object { $_.DetectionSource -eq "Sign-in Analysis" }).Count
            
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
            
            return $mfaResultsArray
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
        • Guessed passwords blocked by MFA (5+ failures then an MFA challenge from the
          SAME IP - 50074/50076 means the password was CORRECT)

        Timestamps are parsed to DateTime once (the CSV stores culture-formatted text, which
        sorts wrongly as a string) so first/last attempt and the breach window are correct.
        Failures with no source IP cannot be attributed to an attacker and are counted; the
        gap is recorded in CollectionStatus.csv rather than reported as a clean result.
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
        $gaps = [System.Collections.Generic.List[string]]::new()

        # CreationTime is culture-formatted text in the CSV: parse once so ordering and the
        # breach window use real DateTimes.
        $unparsedTimes = 0
        $signInData = @(foreach ($row in $signInData) {
            [datetime]$parsedTime = [datetime]::MinValue
            if ([DateTime]::TryParse($row.CreationTime, [ref]$parsedTime)) {
                $row | Add-Member -NotePropertyName EventTime -NotePropertyValue $parsedTime -Force -PassThru
            }
            else { $unparsedTimes++ }
        })
        if ($unparsedTimes -gt 0) {
            $gaps.Add("$unparsedTimes sign-in record(s) had an unparseable timestamp and were excluded")
            Write-Log "$unparsedTimes sign-in record(s) had an unparseable CreationTime and were excluded from attack analysis" -Level "Warning"
        }

        # ── IMPORTANT: use StatusCode (numeric), NOT Status (text description) ──
        # The CSV has two columns:
        #   StatusCode = numeric code (0, 50126, 50140, 65001, …)
        #   Status     = human-readable text ("Success", "Interrupt - sign-in kept alive", …)
        # The old filter compared Status (text) against "0" — "Success" -ne "0" is always
        # TRUE, so every successful sign-in incorrectly landed in $failedLogins.
        #
        # Credential-attack codes (actual failed authentication attempts):
        #   50126 = Invalid username or password  ← primary brute-force indicator
        #   50053 = Account locked out (IdsLocked) ← smart lockout triggered
        #   50056 = Weak/null password
        #   50055 = Password expired              ← include as noteworthy failure
        #
        # Intentionally EXCLUDED from attack counts (benign, not credential failures):
        #   50140 = Sign-in interrupt / session kept alive  (normal token refresh)
        #   50058 = Silent sign-in interrupted              (normal)
        #   50072 = MFA enrollment required                 (normal CA challenge)
        #   50074 = MFA required by CA                      (normal)
        #   50076 = MFA challenge required                  (normal)
        #   65001 = Consent required                        (normal OAuth prompt)
        #   500011= Resource principal not found            (misconfiguration, not credential attack)
        #   16003 = Transient error                         (not credential-based)
        #   50207 = Transient error                         (not credential-based)

        $credentialAttackCodes = @("50126", "50053", "50056", "50055")

        $failedLogins    = $signInData | Where-Object { $_.StatusCode -in $credentialAttackCodes }
        $successfulLogins = $signInData | Where-Object { $_.StatusCode -eq "0" -or [string]::IsNullOrEmpty($_.StatusCode) }

        Write-Log "Found $($failedLogins.Count) credential-attack events (codes: $($credentialAttackCodes -join ',')) and $($successfulLogins.Count) successful logins" -Level "Info"
        
        $patterns = [System.Collections.Generic.List[PSCustomObject]]::new()
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 1: PASSWORD SPRAY DETECTION
        # Same IP attacking multiple users
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting password spray attacks..." ([System.Drawing.Color]::Orange)
        
        $ipGroups = $failedLogins | Group-Object -Property IP
        foreach ($ipGroup in $ipGroups) {
            # Skip records with no source IP. EXO UAL fallback data frequently omits the IP,
            # and an empty/null IP would otherwise collapse every IP-less failure across many
            # users into a single phantom password-spray group.
            if ([string]::IsNullOrWhiteSpace($ipGroup.Name)) { continue }

            $uniqueUsers = ($ipGroup.Group | Select-Object -Unique UserId).Count
            $totalAttempts = $ipGroup.Count
            
            if ($totalAttempts -ge 5 -and $uniqueUsers -ge 3) {
                $timespan = 0
                if ($ipGroup.Group.Count -gt 1) {
                    $firstAttempt = [DateTime]($ipGroup.Group | Sort-Object EventTime | Select-Object -First 1).EventTime
                    $lastAttempt = [DateTime]($ipGroup.Group | Sort-Object EventTime | Select-Object -Last 1).EventTime
                    $timespan = [math]::Round(($lastAttempt - $firstAttempt).TotalHours, 1)
                }
                
                $patterns.Add([PSCustomObject]@{
                    PatternType = "Password Spray"
                    SourceIP = $ipGroup.Name
                    SourceIPs = $ipGroup.Name
                    Location = ($ipGroup.Group | Select-Object -First 1).City + ", " + ($ipGroup.Group | Select-Object -First 1).Country
                    ISP = ($ipGroup.Group | Select-Object -First 1).ISP
                    TargetedUsers = $uniqueUsers
                    FailedAttempts = $totalAttempts
                    TimeSpan = $timespan
                    FirstSeen = ($ipGroup.Group | Sort-Object EventTime | Select-Object -First 1).CreationTime
                    LastSeen = ($ipGroup.Group | Sort-Object EventTime | Select-Object -Last 1).CreationTime
                    RiskLevel = if ($uniqueUsers -ge 10 -or $totalAttempts -ge 20) { "Critical" }
                               elseif ($uniqueUsers -ge 5 -or $totalAttempts -ge 10) { "High" }
                               else { "Medium" }
                    SuccessfulBreach = $false
                    Details = "Password Spray: IP $($ipGroup.Name) attempted $totalAttempts credential failures (50126/50053) against $uniqueUsers different users"
                })
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 2: BRUTE FORCE DETECTION
        # Same user, multiple failed attempts
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting brute force attacks..." ([System.Drawing.Color]::Orange)
        
        $userGroups = $failedLogins | Group-Object -Property UserId
        foreach ($userGroup in $userGroups) {
            # Skip records with no user. An empty/null UserId would otherwise collapse
            # unrelated failures into one phantom brute-force pattern.
            if ([string]::IsNullOrWhiteSpace($userGroup.Name)) { continue }

            $totalAttempts = $userGroup.Count
            # Capture the actual distinct source IPs (excluding blanks) so the executive
            # summary can union real IPs instead of a fabricated count.
            $bruteForceIPs = @($userGroup.Group |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.IP) } |
                Select-Object -ExpandProperty IP -Unique)
            $uniqueIPs = $bruteForceIPs.Count

            if ($totalAttempts -ge 5) {
                $timespan = 0
                if ($userGroup.Group.Count -gt 1) {
                    $firstAttempt = [DateTime]($userGroup.Group | Sort-Object EventTime | Select-Object -First 1).EventTime
                    $lastAttempt = [DateTime]($userGroup.Group | Sort-Object EventTime | Select-Object -Last 1).EventTime
                    $timespan = [math]::Round(($lastAttempt - $firstAttempt).TotalHours, 1)
                }
                
                $patterns.Add([PSCustomObject]@{
                    PatternType = "Brute Force"
                    SourceIP = if ($uniqueIPs -eq 1) { $bruteForceIPs[0] } else { "Multiple IPs ($uniqueIPs)" }
                    SourceIPs = ($bruteForceIPs -join ";")
                    Location = if ($uniqueIPs -eq 1) { 
                        ($userGroup.Group | Select-Object -First 1).City + ", " + ($userGroup.Group | Select-Object -First 1).Country 
                    } else { "Multiple Locations" }
                    ISP = if ($uniqueIPs -eq 1) { ($userGroup.Group | Select-Object -First 1).ISP } else { "Various" }
                    TargetedUsers = 1
                    FailedAttempts = $totalAttempts
                    TimeSpan = $timespan
                    FirstSeen = ($userGroup.Group | Sort-Object EventTime | Select-Object -First 1).CreationTime
                    LastSeen = ($userGroup.Group | Sort-Object EventTime | Select-Object -Last 1).CreationTime
                    RiskLevel = if ($totalAttempts -ge 20) { "Critical" }
                               elseif ($totalAttempts -ge 10) { "High" }
                               else { "Medium" }
                    SuccessfulBreach = $false
                    Details = "Brute Force: User $($userGroup.Name) had $totalAttempts credential failures (50126/50053) from $uniqueIPs different IP(s)"
                })
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 3: SUCCESSFUL BREACH AFTER FAILURES
        # Require 5+ failed attempts AND successful login from SAME IP
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting successful breaches (5+ failures, same IP required)..." ([System.Drawing.Color]::Orange)
        
        # Group failed logins by user and IP combination
        # Use Unit Separator (0x1F) as delimiter to avoid collisions with | in data
        $fieldSeparator = [char]0x1F
        $failedByUserIP = $failedLogins | Group-Object -Property { "{0}{1}{2}" -f $_.UserId, $fieldSeparator, $_.IP }
        
        $breachCount = 0
        foreach ($group in $failedByUserIP) {
            # Require at least 5 failed attempts
            if ($group.Count -lt 5) { continue }
            
            # Parse the grouped key using Unit Separator
            $parts = $group.Name -split [regex]::Escape([char]0x1F)
            if ($parts.Count -ne 2) { continue }
            
            $userId = $parts[0]
            $ip = $parts[1]
            
            # Skip if missing critical info
            if ([string]::IsNullOrWhiteSpace($userId) -or [string]::IsNullOrWhiteSpace($ip)) { continue }
            
            # Get the failed attempts sorted by time
            $attempts = $group.Group | Sort-Object EventTime
            $firstFailedTime = $attempts[0].EventTime
            $lastFailedTime = $attempts[-1].EventTime
            
            # CRITICAL: Look for successful login from THE EXACT SAME IP
            # This ensures legitimate logins from office/home don't get flagged
            $breach = $successfulLogins | Where-Object {
                $_.IP -eq $ip -and                                          # MUST be same IP
                $_.UserId -eq $userId -and                                   # Same user
                $_.EventTime -gt $lastFailedTime -and                       # After last failure
                ($_.EventTime - $firstFailedTime).TotalHours -le 2          # Within 2 hours
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
                    $breachTime = $breach.EventTime
                    $totalFailedAttempts = $group.Count
                    $timeToBreach = [math]::Round(($breachTime - $lastFailedTime).TotalMinutes, 1)
                    
                    $patterns.Add([PSCustomObject]@{
                        PatternType = "Successful Breach"
                        SourceIP = $ip
                        SourceIPs = $ip
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
                    })
                    
                    Write-Log "BREACH DETECTED: $userId - $totalFailedAttempts failures from $ip, success from same IP after $timeToBreach min" -Level "Warning"
                }
            }
        }
        
        Write-Log "Breach detection complete: $breachCount confirmed breaches (same IP requirement)" -Level "Info"

        #═══════════════════════════════════════════════════════════
        # PATTERN 4: PASSWORD GUESSED, MFA HELD
        # 5+ credential failures, then an MFA challenge (50074/50076) from the SAME IP.
        # The MFA prompt only appears after the password was accepted, so the password is
        # compromised even though the attacker never got in. Not counted as a success above.
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting guessed passwords blocked by MFA..." ([System.Drawing.Color]::Orange)
        $mfaChallenged = @($signInData | Where-Object { $_.StatusCode -in @("50074", "50076") })
        $mfaHeldCount = 0
        foreach ($group in $failedByUserIP) {
            if ($group.Count -lt 5) { continue }
            $parts = $group.Name -split [regex]::Escape([char]0x1F)
            if ($parts.Count -ne 2) { continue }
            $userId = $parts[0]
            $ip = $parts[1]
            if ([string]::IsNullOrWhiteSpace($userId) -or [string]::IsNullOrWhiteSpace($ip)) { continue }

            $attempts = $group.Group | Sort-Object EventTime
            $firstFailedTime = $attempts[0].EventTime
            $lastFailedTime = $attempts[-1].EventTime

            $challenge = $mfaChallenged | Where-Object {
                $_.IP -eq $ip -and
                $_.UserId -eq $userId -and
                $_.EventTime -gt $lastFailedTime -and
                ($_.EventTime - $firstFailedTime).TotalHours -le 2
            } | Select-Object -First 1

            if ($challenge) {
                $mfaHeldCount++
                $patterns.Add([PSCustomObject]@{
                    PatternType = "Password Guessed - MFA Held"
                    SourceIP = $ip
                    SourceIPs = $ip
                    Location = $attempts[0].City + ", " + $attempts[0].Country
                    ISP = $attempts[0].ISP
                    TargetedUsers = 1
                    FailedAttempts = $group.Count
                    TimeSpan = [math]::Round(($challenge.EventTime - $firstFailedTime).TotalHours, 2)
                    FirstSeen = $attempts[0].CreationTime
                    LastSeen = $challenge.CreationTime
                    RiskLevel = if ($group.Count -ge 20) { "Critical" } else { "High" }
                    SuccessfulBreach = $false
                    Details = "PASSWORD COMPROMISED, MFA HELD: User $userId - $($group.Count) failed attempts from $ip ($($attempts[0].City), $($attempts[0].Country)), then an MFA challenge from the SAME IP. The password was accepted; reset it and review the account."
                })
                Write-Log "MFA-HELD PASSWORD GUESS: $userId from $ip after $($group.Count) failures" -Level "Warning"
            }
        }
        Write-Log "MFA-held password guesses detected: $mfaHeldCount" -Level "Info"

        # Failures with no source IP cannot be grouped by attacker or matched to a later
        # success, so spray and breach detection is blind to them. Count and report.
        $noIpFailures = @($failedLogins | Where-Object { [string]::IsNullOrWhiteSpace($_.IP) -or $_.IP -eq "Unknown" }).Count
        if ($noIpFailures -gt 0) {
            $gaps.Add("$noIpFailures of $($failedLogins.Count) credential-failure event(s) had no source IP; spray and breach detection cannot evaluate them")
            Write-Log "$noIpFailures of $($failedLogins.Count) credential-failure events have no source IP - not evaluated for spray/breach" -Level "Warning"
        }
        
        # Previous run's files are only rewritten when non-empty; remove them so a clean run
        # cannot leave old attack patterns behind for the analysis step.
        Remove-StaleOutput -Path @(
            $OutputPath,
            ($OutputPath -replace '\.csv$', '_Critical.csv'),
            ($OutputPath -replace '\.csv$', '_Breaches.csv')
        )

        # Export results
        $patternsArray = @($patterns.ToArray())
        if ($patterns.Count -gt 0) {
            $riskRank = @{ Critical = 3; High = 2; Medium = 1; Low = 0 }
            $patternsArray | Sort-Object @{ Expression = { $riskRank[$_.RiskLevel] }; Descending = $true }, @{ Expression = 'FailedAttempts'; Descending = $true } | 
                Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            $criticalPatterns = $patternsArray | Where-Object { $_.RiskLevel -eq "Critical" }
            if ($criticalPatterns.Count -gt 0) {
                $criticalPath = $OutputPath -replace '.csv$', '_Critical.csv'
                $criticalPatterns | Export-Csv -Path $criticalPath -NoTypeInformation -Force
            }
            
            $breaches = $patternsArray | Where-Object { $_.SuccessfulBreach -eq $true }
            if ($breaches.Count -gt 0) {
                $breachPath = $OutputPath -replace '.csv$', '_Breaches.csv'
                $breaches | Export-Csv -Path $breachPath -NoTypeInformation -Force
            }
            
            $stats = @{
                TotalPatterns = $patternsArray.Count
                PasswordSpray = ($patternsArray | Where-Object { $_.PatternType -eq "Password Spray" }).Count
                BruteForce = ($patternsArray | Where-Object { $_.PatternType -eq "Brute Force" }).Count
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
            if ($gaps.Count -gt 0) {
                Update-GuiStatus "No attack patterns found, but coverage was incomplete (see log)" ([System.Drawing.Color]::Orange)
            }
            else {
                Update-GuiStatus "No suspicious failed login patterns detected" ([System.Drawing.Color]::Green)
            }
            Write-Log "No attack patterns detected" -Level "Info"
        }

        Set-CollectionStatus -Source "FailedLoginAnalysis" -Complete ($gaps.Count -eq 0) -Records $patterns.Count -Note ($gaps -join "; ")
        
        return $patternsArray
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
        Analyzes admin audit logs for password change patterns per target user: several
        changes in a short window, many different initiators, off-hours activity, and
        excessive totals. Users with a single password event are not flagged here (a lone
        helpdesk reset is normal); admin-initiated changes still appear in the admin audit
        data. Off-hours are evaluated in the local time of the machine running the analysis.
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
        # The audit CSV has no TargetUser / InitiatedBy columns: the initiator is UserId and
        # the target lives in the TargetResources JSON. Derive both, and parse the date once
        # so ordering is chronological (sorting the CSV date strings sorts as text).
        $unresolvedTargets = 0
        $passwordEvents = @(foreach ($row in $auditData) {
            if ($row.Activity -notlike "*password*") { continue }

            [datetime]$eventTime = [datetime]::MinValue
            $rawDate = if (-not [string]::IsNullOrWhiteSpace($row.ActivityDate)) { $row.ActivityDate } else { $row.Timestamp }
            if ([string]::IsNullOrWhiteSpace($rawDate) -or -not [DateTime]::TryParse($rawDate, [ref]$eventTime)) { continue }

            $targetUser = $null
            if (-not [string]::IsNullOrWhiteSpace($row.TargetResources)) {
                try {
                    $targets = @($row.TargetResources | ConvertFrom-Json -ErrorAction Stop)
                    $userTarget = $targets | Where-Object { $_.Type -eq "User" -and $_.UserPrincipalName } | Select-Object -First 1
                    if ($userTarget) { $targetUser = $userTarget.UserPrincipalName }
                    elseif ($targets.Count -gt 0 -and $targets[0].UserPrincipalName) { $targetUser = $targets[0].UserPrincipalName }
                }
                catch { }
            }
            if ([string]::IsNullOrWhiteSpace($targetUser)) { $unresolvedTargets++; continue }

            [PSCustomObject]@{
                TargetUser  = $targetUser
                InitiatedBy = $row.UserId
                Activity    = $row.Activity
                EventTime   = $eventTime
            }
        })
        
        Write-Log "Found $($passwordEvents.Count) password-related events with valid dates and a resolvable target user" -Level "Info"
        if ($unresolvedTargets -gt 0) {
            Write-Log "$unresolvedTargets password-related event(s) had no resolvable target user and were excluded from analysis" -Level "Warning"
        }

        # Clear this analysis' previous output so a clean run cannot leave old findings behind.
        Remove-StaleOutput -Path @($OutputPath, ($OutputPath -replace '\.csv$', '_Critical.csv'))
        Set-CollectionStatus -Source "PasswordChangeAnalysis" `
            -Complete ($unresolvedTargets -eq 0) `
            -Records $passwordEvents.Count `
            -Note $(if ($unresolvedTargets -gt 0) { "$unresolvedTargets password-related audit event(s) had no resolvable target user and were not analyzed" } else { "" })
        
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
                $events = @($userGroup.Group | Sort-Object EventTime)
                $changeCount = $events.Count
                
                # Skip users with only 1 password change
                if ($changeCount -eq 1) { continue }
                
                $firstChange = $events[0].EventTime
                $lastChange = $events[-1].EventTime
                
                $timespan = ($lastChange - $firstChange).TotalHours
                
                # Calculate who initiated changes
                $initiators = ($events | Where-Object { -not [string]::IsNullOrWhiteSpace($_.InitiatedBy) } | Select-Object -Unique InitiatedBy).Count
                $selfReset = ($events | Where-Object { $_.InitiatedBy -eq $_.TargetUser }).Count
                $adminReset = ($events | Where-Object { $_.InitiatedBy -ne $_.TargetUser }).Count
                
                # Check for off-hours activity (before 6 AM or after 10 PM).
                # NOTE: [DateTime]::Parse converts a UTC ('Z') timestamp to the LOCAL time of
                # the machine running this analysis. The off-hours window therefore reflects the
                # analyst's timezone, which may differ from the client tenant's business hours.
                $offHoursChanges = 0
                foreach ($event in $events) {
                    $hour = $event.EventTime.Hour
                    if ($hour -lt 6 -or $hour -gt 22) {
                        $offHoursChanges++
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
                        SuspiciousReasons = ($reasons -join ", ")
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
    
    # Lower bound only. A date-only upper bound ("le yyyy-MM-dd") resolves to midnight
    # UTC and silently drops every event from the current day - the newest and most
    # relevant records in an active investigation.
    $startDate = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString("yyyy-MM-dd")
    
    try {
        Update-GuiStatus "Querying Microsoft Graph for admin audit logs..." ([System.Drawing.Color]::Orange)
        
        $auditLogs = [System.Collections.Generic.List[object]]::new()
        $pageSize = 1000
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $startDate&`$top=$pageSize"

        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($response.value) { $auditLogs.AddRange([object[]]$response.value) }
            $uri = $response.'@odata.nextLink'
            
            Update-GuiStatus "Retrieved $($auditLogs.Count) admin audit records..." ([System.Drawing.Color]::Orange)
        } while ($uri)
        
        Write-Log "Retrieved $($auditLogs.Count) admin audit log records" -Level "Info"
        
        # Process and enrich logs
        $processedLogs = [System.Collections.Generic.List[PSCustomObject]]::new($auditLogs.Count)
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
                # Evaluated last so they win over the generic Delete/Remove match above.
                # These are the classic persistence / defence-evasion operations.
                ".*[Cc]onsent to application.*|.*[Aa]dd service principal credentials.*|.*[Cc]ertificates and secrets.*|.*[Aa]dd owner to (application|service principal).*|.*[Ss]et federation settings.*|.*[Aa]dd (unverified|verified) domain.*|.*[Cc]onditional [Aa]ccess policy.*|.*[Dd]isable [Ss]trong [Aa]uthentication.*" { $riskLevel = "High" }
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
            
            # Actions started by an app / service principal have no initiatedBy.user. Without a
            # fallback they got a blank UserId and were dropped by the analysis step.
            $initiatorType = "User"
            $initiatorId = $log.initiatedBy.user.userPrincipalName
            $initiatorName = $log.initiatedBy.user.displayName
            if ([string]::IsNullOrWhiteSpace($initiatorId)) { $initiatorId = $log.initiatedBy.user.id }
            if ([string]::IsNullOrWhiteSpace($initiatorId)) {
                $initiatorType = "App"
                $initiatorName = $log.initiatedBy.app.displayName
                $initiatorId = if ($initiatorName) { $initiatorName }
                               elseif ($log.initiatedBy.app.servicePrincipalId) { $log.initiatedBy.app.servicePrincipalId }
                               else { $log.initiatedBy.app.appId }
                if ($initiatorId) { $initiatorId = "[App] $initiatorId" }
            }
            
            $processedLog = [PSCustomObject]@{
                Timestamp = [DateTime]::Parse($log.activityDateTime)
                ActivityDate = [DateTime]::Parse($log.activityDateTime)  # Alias for compatibility
                UserId = $initiatorId
                UserDisplayName = $initiatorName
                InitiatedByType = $initiatorType
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
            
            $processedLogs.Add($processedLog)
        }
        
        # Clear the previous run's files (the filtered variants are only rewritten when
        # non-empty) so old findings cannot be mistaken for current ones.
        Remove-StaleOutput -Path @(
            $OutputPath,
            ($OutputPath -replace '\.csv$', '_Critical.csv'),
            ($OutputPath -replace '\.csv$', '_Failed.csv'),
            ($OutputPath -replace '\.csv$', '_LoginActivity.csv')
        )

        # Export results
        $processedLogsArray = $processedLogs.ToArray()
        Set-CollectionStatus -Source "AdminAudit" -Complete $true -Records $processedLogsArray.Count `
            -Note "Microsoft Entra directory audit only (role, app, user and policy changes). Exchange admin actions such as New-InboxRule or Add-MailboxPermission are not in this source."
        if ($processedLogsArray.Count -gt 0) {
            $processedLogsArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        }
        
        # Create filtered versions
        $highRiskLogs = $processedLogsArray | Where-Object { $_.RiskLevel -eq "High" }
        if ($highRiskLogs.Count -gt 0) {
            $highRiskPath = $OutputPath -replace '.csv$', '_Critical.csv'
            $highRiskLogs | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            Write-Log "Found $($highRiskLogs.Count) high-risk admin operations" -Level "Warning"
        }
        
        $failedLogs = $processedLogsArray | Where-Object { $_.Result -ne "success" }
        if ($failedLogs.Count -gt 0) {
            $failedPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedLogs | Export-Csv -Path $failedPath -NoTypeInformation -Force
        }
        
        $loginLogs = $processedLogsArray | Where-Object { $_.LOGIN -ne "OTHER" }
        if ($loginLogs.Count -gt 0) {
            $loginPath = $OutputPath -replace '.csv$', '_LoginActivity.csv'
            $loginLogs | Export-Csv -Path $loginPath -NoTypeInformation -Force
        }
        
        Update-GuiStatus "Admin audit log collection completed: $($processedLogsArray.Count) records." ([System.Drawing.Color]::Green)
        Write-Log "Admin audit collection complete" -Level "Info"
        
        return $processedLogsArray
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in admin audit collection: $($_.Exception.Message)" -Level "Error"
        Set-CollectionStatus -Source "AdminAudit" -Complete $false -Records 0 -Note "Admin audit collection FAILED ($($_.Exception.Message)); any admin audit CSV in the working directory is from an EARLIER run."
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# MAILBOX RULES COLLECTION
#══════════════════════════════════════════════════════════════

function Get-MailboxRules {
    <#
    .SYNOPSIS
        Collects inbox rules from every user and shared mailbox in the tenant
    
    .DESCRIPTION
        Retrieves inbox rules from every user and shared mailbox regardless of sign-in
        activity, with progress tracking. Note: Exchange Online cmdlets cannot use
        ForEach-Object -Parallel, so this uses optimized sequential processing.

        - Hidden rules are included (Get-InboxRule -IncludeHidden). Attackers use hidden
          rules precisely because they do not show up in Outlook or a plain Get-InboxRule.
        - Forwarding/redirect targets are checked against the tenant's ACCEPTED DOMAINS
          (ForwardTo, ForwardAsAttachmentTo and RedirectTo). A target outside those domains
          is tagged "External forwarding".
        - The Mailbox column is the UPN, so rule findings line up with sign-in data for
          hybrid users whose UPN and primary SMTP address differ. The SMTP address is in
          PrimarySmtpAddress.
        - Mailboxes that cannot be read (errors, persistent throttling) are logged by name
          and written to InboxRules_Skipped.csv, and the run is recorded as INCOMPLETE in
          CollectionStatus.csv. A previous run's output is removed first so a run that
          finds nothing cannot leave stale rules behind.

    .NOTES
        Get-InboxRule does not work for members of the View-Only Organization Management
        role group or the Global Reader Entra role. Use Exchange Administrator (or a
        role group with the Mail Recipients role).
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "InboxRules.csv")
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
        # STEP 2: GET MAILBOX LIST
        # ═══════════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Retrieving mailboxes..." ([System.Drawing.Color]::Orange)
        Write-Log "Retrieving user and shared mailboxes" -Level "Info"
        
        # Get mailboxes
        $allMailboxes = Get-Mailbox -ResultSize Unlimited `
                                     -RecipientTypeDetails UserMailbox,SharedMailbox `
                                     -ErrorAction Stop
        
        Write-Log "Retrieved $($allMailboxes.Count) mailboxes" -Level "Info"
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 3: CHECK ALL MAILBOXES
        # No sign-in based filtering: a compromised admin can plant rules in
        # mailboxes whose owners never sign in (dormant, shared, etc.).
        # ═══════════════════════════════════════════════════════════════════════════
        
        $mailboxesToCheck = $allMailboxes
        
        if ($mailboxesToCheck.Count -eq 0) {
            Write-Log "No mailboxes to check" -Level "Warning"
            return @()
        }
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 4: COLLECT RULES (SEQUENTIAL - EXCHANGE ONLINE REQUIREMENT)
        # ═══════════════════════════════════════════════════════════════════════════
        
        Write-Log "Processing $($mailboxesToCheck.Count) mailboxes for inbox rules" -Level "Info"
        Write-Log "NOTE: Exchange Online cmdlets require sequential processing" -Level "Info"

        # Accepted domains define "internal" for the external forwarding check.
        $orgDomains = @()
        try {
            $orgDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { $_.DomainName.ToString().ToLower() })
            Write-Log "Loaded $($orgDomains.Count) accepted domains for external forwarding checks" -Level "Info"
        }
        catch {
            Write-Log "Could not retrieve accepted domains ($($_.Exception.Message)) - falling back to each mailbox's own domain, so forwarding between the tenant's other domains will be reported as external" -Level "Warning"
        }

        # Remove this collector's previous output so a run that finds nothing cannot leave
        # last run's rules behind for the analysis step.
        $skippedPath = $OutputPath -replace '\.csv$', '_Skipped.csv'
        Remove-StaleOutput -Path @(
            $OutputPath,
            ($OutputPath -replace '\.csv$', '_Suspicious.csv'),
            ($OutputPath -replace '\.csv$', '_Forwarding.csv'),
            $skippedPath
        )
        
        $allRulesArray = [System.Collections.Generic.List[PSCustomObject]]::new()
        $processedCount = 0
        $skippedMailboxes = [System.Collections.Generic.List[PSCustomObject]]::new()
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

                # Get rules for this mailbox, retrying on Exchange Online throttling (429/503).
                # Without this, a throttled mailbox is silently skipped and its rules go
                # unreported - a real risk on large tenants where forwarding rules are the
                # primary compromise indicator.
                $rules = $null
                $ruleAttempt = 0
                $maxRuleAttempts = 4
                while ($ruleAttempt -lt $maxRuleAttempts) {
                    $ruleAttempt++
                    try {
                        $rules = Get-InboxRule -Mailbox $mailbox.PrimarySmtpAddress -IncludeHidden -ErrorAction Stop
                        break
                    }
                    catch {
                        $isThrottle = $_.Exception.Message -match '429|503|throttl|too many requests|ServerBusy'
                        if ($isThrottle -and $ruleAttempt -lt $maxRuleAttempts) {
                            $backoff = [Math]::Min(30, [Math]::Pow(2, $ruleAttempt))
                            Write-Log "Throttled on $($mailbox.PrimarySmtpAddress) (attempt $ruleAttempt) - backing off $backoff s" -Level "Warning"
                            Start-Sleep -Seconds $backoff
                        }
                        else {
                            throw
                        }
                    }
                }

                if ($rules) {
                    Write-Log "Found $(@($rules).Count) rule(s) for $($mailbox.PrimarySmtpAddress)" -Level "Info"
                    
                    foreach ($rule in $rules) {
                        # Analyze rule for suspicious patterns
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        $externalTargets = @()
                        
                        # Check for forwarding
                        if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Forwards email"
                            
                            # External = any target whose address domain is not an accepted
                            # domain of the tenant. Checks ForwardTo, ForwardAsAttachmentTo
                            # AND RedirectTo, and compares whole domains (a substring match
                            # lets evilcontoso.com pass for contoso.com). Targets with no SMTP
                            # address (internal recipients, [EX:...]) are treated as internal.
                            $internalDomains = if ($orgDomains.Count -gt 0) { $orgDomains } else { @($mailbox.PrimarySmtpAddress.ToString().Split('@')[1].ToLower()) }
                            $externalTargets = @()
                            foreach ($targetList in @($rule.ForwardTo, $rule.ForwardAsAttachmentTo, $rule.RedirectTo)) {
                                foreach ($target in @($targetList)) {
                                    $targetText = "$target"
                                    if ([string]::IsNullOrWhiteSpace($targetText)) { continue }
                                    $targetDomain = $null
                                    if ($targetText -match 'SMTP:[^\]\s@]+@([^\]\s]+)') { $targetDomain = $Matches[1] }
                                    elseif ($targetText -match '[A-Za-z0-9._%+''-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})') { $targetDomain = $Matches[1] }
                                    if ($targetDomain -and ($internalDomains -notcontains $targetDomain.ToLower())) {
                                        $externalTargets += $targetText
                                    }
                                }
                            }
                            if ($externalTargets.Count -gt 0) {
                                $suspiciousReasons += "External forwarding"
                            }
                        }
                        
                        # Check for deletion (hard delete or soft delete to Deleted Items)
                        if ($rule.DeleteMessage -eq $true -or $rule.SoftDeleteMessage -eq $true) {
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
                            Mailbox = $mailbox.UserPrincipalName
                            PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                            MailboxType = $mailbox.RecipientTypeDetails
                            DisplayName = $mailbox.DisplayName
                            RuleName = $rule.Name
                            Description = $rule.Description
                            Enabled = $rule.Enabled
                            Priority = $rule.Priority
                            ForwardTo = if ($rule.ForwardTo) { $rule.ForwardTo -join ", " } else { "" }
                            RedirectTo = if ($rule.RedirectTo) { $rule.RedirectTo -join ", " } else { "" }
                            ForwardAsAttachmentTo = if ($rule.ForwardAsAttachmentTo) { $rule.ForwardAsAttachmentTo -join ", " } else { "" }
                            ExternalTargets = ($externalTargets -join ", ")
                            DeleteMessage = $rule.DeleteMessage
                            SoftDeleteMessage = $rule.SoftDeleteMessage
                            MarkAsRead = $rule.MarkAsRead
                            StopProcessingRules = $rule.StopProcessingRules
                            MoveToFolder = $rule.MoveToFolder
                            SubjectContains = if ($rule.SubjectContainsWords) { $rule.SubjectContainsWords -join ", " } else { "" }
                            FromAddress = if ($rule.From) { $rule.From -join ", " } else { "" }
                            SentTo = if ($rule.SentTo) { $rule.SentTo -join ", " } else { "" }
                            IsSuspicious = $isSuspicious
                            SuspiciousReasons = if ($suspiciousReasons.Count -gt 0) { $suspiciousReasons -join ", " } else { "" }
                            RuleIdentity = $rule.Identity
                        }
                        
                        $allRulesArray.Add($ruleObject)
                    }
                }
                else {
                    Write-Log "No rules found for $($mailbox.PrimarySmtpAddress)" -Level "Info"
                }
            }
            catch {
                $skippedMailboxes.Add([PSCustomObject]@{
                    Mailbox = $mailbox.UserPrincipalName
                    PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                    Error = $_.Exception.Message
                })
                Write-Log "Error getting rules for $($mailbox.PrimarySmtpAddress): $($_.Exception.Message)" -Level "Warning"
            }
        }

        # If any mailboxes could not be read, the rules dataset is incomplete - name them,
        # write them out and record the gap so the report shows it.
        if ($skippedMailboxes.Count -gt 0) {
            $skippedMailboxes | Export-Csv -Path $skippedPath -NoTypeInformation -Force
            Write-Log "$($skippedMailboxes.Count) of $($mailboxesToCheck.Count) mailboxes could not be read (errors/throttling) - inbox rule results are INCOMPLETE. Unread mailboxes listed in $skippedPath" -Level "Error"
            Update-GuiStatus "WARNING: $($skippedMailboxes.Count) mailbox(es) skipped - rule results incomplete (see log)" ([System.Drawing.Color]::Red)
        }
        Set-CollectionStatus -Source "InboxRules" `
            -Complete ($skippedMailboxes.Count -eq 0) `
            -Records $allRulesArray.Count `
            -Note $(if ($skippedMailboxes.Count -gt 0) { "$($skippedMailboxes.Count) of $($mailboxesToCheck.Count) mailboxes could not be read; rules for those mailboxes are missing (see InboxRules_Skipped.csv)" } else { "" })

        # ═══════════════════════════════════════════════════════════════════════════
        # STEP 5: EXPORT RESULTS
        # ═══════════════════════════════════════════════════════════════════════════
        
        $elapsedTime = (Get-Date) - $startTime
        
        if ($allRulesArray.Count -gt 0) {
            Update-GuiStatus "Exporting $($allRulesArray.Count) rules..." ([System.Drawing.Color]::Orange)
            
            # Export all rules
            $allRulesExport = $allRulesArray.ToArray()
            $allRulesExport | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Log "Exported $($allRulesArray.Count) rules to: $OutputPath" -Level "Info"
            
            # Export suspicious rules
            $suspiciousRules = $allRulesExport | Where-Object { $_.IsSuspicious -eq $true }
            if ($suspiciousRules.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousRules | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
                Write-Log "Exported $($suspiciousRules.Count) suspicious rules to: $suspiciousPath" -Level "Warning"
            }
            
            # Export forwarding rules specifically
            $forwardingRules = $allRulesExport | Where-Object { 
                $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo 
            }
            if ($forwardingRules.Count -gt 0) {
                $forwardingPath = $OutputPath -replace '.csv$', '_Forwarding.csv'
                $forwardingRules | Export-Csv -Path $forwardingPath -NoTypeInformation -Force
                Write-Log "Exported $($forwardingRules.Count) forwarding rules to: $forwardingPath" -Level "Info"
            }
            
            # Statistics
            $mailboxesWithRules = ($allRulesExport | Select-Object -ExpandProperty Mailbox -Unique).Count
            $enabledRules = ($allRulesExport | Where-Object { $_.Enabled -eq $true }).Count
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
            
            return $allRulesExport
        }
        else {
            if ($skippedMailboxes.Count -gt 0) {
                Update-GuiStatus "No inbox rules found in the $($mailboxesToCheck.Count - $skippedMailboxes.Count) readable mailboxes - $($skippedMailboxes.Count) could not be read" ([System.Drawing.Color]::Red)
                Write-Log "No inbox rules found in the readable mailboxes; $($skippedMailboxes.Count) mailbox(es) could not be read, so this is NOT a clean result" -Level "Warning"
            }
            else {
                Update-GuiStatus "No inbox rules found in any mailbox" ([System.Drawing.Color]::Yellow)
                Write-Log "No inbox rules found in any mailbox" -Level "Info"
            }
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
        Collects mailbox delegation permissions from Exchange Online.

    .DESCRIPTION
        Enumerates every user and shared mailbox in the tenant, regardless of sign-in
        activity, and records three kinds of delegation:
        - FullAccess   (Get-MailboxPermission, explicit non-inherited Allow entries)
        - SendAs       (Get-RecipientPermission)
        - SendOnBehalf (GrantSendOnBehalfTo on the mailbox)

        Microsoft Graph mailboxSettings has no delegate or permission data, so the
        Exchange Online cmdlets are the only source for this.

        Flagged as suspicious:
        - Delegate outside the tenant's accepted domains (guest / #EXT# accounts included)
        - Orphaned SID (delegate account was deleted, permission left behind)
        - FullAccess / SendAs / SendOnBehalf on a USER mailbox. The same grants on a
          shared mailbox are expected and are recorded but not flagged on their own.

        Mailboxes that cannot be read (errors, persistent throttling) are logged by name
        and written to a _Skipped.csv so the result is never silently incomplete.

    .OUTPUTS
        Array of delegation objects with risk flags
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MailboxDelegation.csv")
    )

    Update-GuiStatus "Starting mailbox delegation collection..." ([System.Drawing.Color]::Orange)
    Write-Log "MAILBOX DELEGATION COLLECTION STARTED" -Level "Info"

    try {
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            Update-GuiStatus "Exchange Online connection failed - skipping delegation collection" ([System.Drawing.Color]::Red)
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online connection required for mailbox delegation collection.",
                "Connection Required", "OK", "Warning"
            )
            return @()
        }

        # Accepted domains define "internal" for the external-delegate check.
        $orgDomains = @()
        try {
            $orgDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { $_.DomainName.ToString().ToLower() })
            Write-Log "Loaded $($orgDomains.Count) accepted domains" -Level "Info"
        }
        catch {
            Write-Log "Could not retrieve accepted domains ($($_.Exception.Message)) - external delegate check will only catch #EXT# guests" -Level "Warning"
        }

        # Runs a script block, backing off and retrying on Exchange Online throttling.
        $invokeWithRetry = {
            param([scriptblock]$Action, [string]$Label)
            $maxAttempts = 4
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                try {
                    return (& $Action)
                }
                catch {
                    $isThrottle = $_.Exception.Message -match '429|503|throttl|too many requests|ServerBusy'
                    if ($isThrottle -and $attempt -lt $maxAttempts) {
                        $backoff = [Math]::Min(30, [Math]::Pow(2, $attempt))
                        Write-Log "Throttled on $Label (attempt $attempt) - backing off $backoff s" -Level "Warning"
                        Start-Sleep -Seconds $backoff
                    }
                    else {
                        throw
                    }
                }
            }
        }

        Update-GuiStatus "Retrieving mailboxes..." ([System.Drawing.Color]::Orange)
        $mailboxes = @(Get-Mailbox -ResultSize Unlimited `
                                   -RecipientTypeDetails UserMailbox,SharedMailbox `
                                   -ErrorAction Stop)
        $totalCount = $mailboxes.Count
        Write-Log "Retrieved $totalCount mailboxes for delegation review" -Level "Info"

        $delegations = [System.Collections.Generic.List[PSCustomObject]]::new()
        $skipped = [System.Collections.Generic.List[PSCustomObject]]::new()
        $processedCount = 0
        $startTime = Get-Date

        foreach ($mailbox in $mailboxes) {
            $processedCount++
            if ($processedCount % 5 -eq 0 -or $processedCount -eq 1) {
                $percentage = [math]::Round(($processedCount / $totalCount) * 100, 1)
                Update-GuiStatus "Processing delegations: $processedCount of $totalCount ($percentage%) - $($delegations.Count) found" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }

            $mbxId = $mailbox.PrimarySmtpAddress.ToString()
            $mbxType = $mailbox.RecipientTypeDetails.ToString()
            $isSharedMbx = ($mbxType -eq "SharedMailbox")

            # Each entry: Delegate, Permission
            $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

            try {
                # --- FullAccess ---
                $fullAccess = & $invokeWithRetry {
                    Get-MailboxPermission -Identity $mbxId -ResultSize Unlimited -ErrorAction Stop
                } "FullAccess on $mbxId"

                foreach ($perm in @($fullAccess)) {
                    if ($perm.IsInherited -eq $true -or $perm.Deny -eq $true) { continue }
                    if (@($perm.AccessRights) -notcontains "FullAccess") { continue }
                    $who = $perm.User.ToString()
                    if ($who -match '^NT AUTHORITY\\') { continue }
                    $entries.Add([PSCustomObject]@{ Delegate = $who; Permission = "FullAccess" })
                }

                # --- SendAs ---
                $sendAs = & $invokeWithRetry {
                    Get-RecipientPermission -Identity $mbxId -ResultSize Unlimited -ErrorAction Stop
                } "SendAs on $mbxId"

                foreach ($perm in @($sendAs)) {
                    if ($perm.AccessControlType -ne "Allow") { continue }
                    if (@($perm.AccessRights) -notcontains "SendAs") { continue }
                    $who = $perm.Trustee.ToString()
                    if ($who -match '^NT AUTHORITY\\') { continue }
                    $entries.Add([PSCustomObject]@{ Delegate = $who; Permission = "SendAs" })
                }

                # --- SendOnBehalf ---
                foreach ($grantee in @($mailbox.GrantSendOnBehalfTo)) {
                    if ([string]::IsNullOrWhiteSpace($grantee)) { continue }
                    $entries.Add([PSCustomObject]@{ Delegate = $grantee.ToString(); Permission = "SendOnBehalf" })
                }
            }
            catch {
                $skipped.Add([PSCustomObject]@{ Mailbox = $mbxId; Error = $_.Exception.Message })
                Write-Log "Error reading delegation for ${mbxId}: $($_.Exception.Message)" -Level "Warning"
                continue
            }

            # Merge per delegate so one person with FullAccess + SendAs is one row.
            foreach ($group in ($entries | Group-Object -Property Delegate)) {
                $delegate = $group.Name
                $permissions = @($group.Group | Select-Object -ExpandProperty Permission -Unique)

                $isSuspicious = $false
                $reasons = @()

                $isOrphanedSid = ($delegate -match '^S-1-5-21-')
                $delegateDomain = $null
                if ($delegate -match '@([^@\s]+)$') { $delegateDomain = $Matches[1].ToLower() }

                $isExternal = $false
                if ($delegate -match '#EXT#') { $isExternal = $true }
                elseif ($delegateDomain -and $orgDomains.Count -gt 0 -and $orgDomains -notcontains $delegateDomain) { $isExternal = $true }

                if ($isOrphanedSid) {
                    $isSuspicious = $true
                    $reasons += "Orphaned SID (delegate account deleted)"
                }
                if ($isExternal) {
                    $isSuspicious = $true
                    $reasons += "External delegate"
                }
                if (-not $isSharedMbx) {
                    $isSuspicious = $true
                    $reasons += "Delegated access on user mailbox ($($permissions -join '/'))"
                }
                elseif ($permissions.Count -gt 0) {
                    $reasons += "Shared mailbox delegate (expected, not flagged alone)"
                }

                $delegations.Add([PSCustomObject]@{
                    Mailbox           = $mailbox.UserPrincipalName
                    PrimarySmtpAddress = $mbxId
                    DisplayName       = $mailbox.DisplayName
                    MailboxType       = $mbxType
                    DelegateName      = $delegate
                    DelegateEmail     = if ($delegateDomain) { $delegate } else { "" }
                    Permissions       = ($permissions -join ", ")
                    IsSuspicious      = $isSuspicious
                    SuspiciousReasons = ($reasons -join ", ")
                })
            }
        }

        # Never present a partial pull as complete.
        $skippedPath = $OutputPath -replace '\.csv$', '_Skipped.csv'
        if ($skipped.Count -gt 0) {
            $skipped | Export-Csv -Path $skippedPath -NoTypeInformation -Force
            Write-Log "$($skipped.Count) of $totalCount mailboxes could not be read - delegation results are INCOMPLETE (see $skippedPath)" -Level "Error"
            Update-GuiStatus "WARNING: $($skipped.Count) mailbox(es) skipped - delegation results incomplete (see log)" ([System.Drawing.Color]::Red)
        }
        elseif (Test-Path -Path $skippedPath) {
            Remove-Item -Path $skippedPath -Force -ErrorAction SilentlyContinue
        }
        Set-CollectionStatus -Source "MailboxDelegation" `
            -Complete ($skipped.Count -eq 0) `
            -Records $delegations.Count `
            -Note $(if ($skipped.Count -gt 0) { "$($skipped.Count) of $totalCount mailboxes could not be read; delegations on those mailboxes are missing (see MailboxDelegation_Skipped.csv)" } else { "" })

        # Overwrite our own previous output either way so a clean run cannot leave last
        # run's delegations behind for the analysis step to pick up.
        $suspiciousPath = $OutputPath -replace '\.csv$', '_Suspicious.csv'
        foreach ($stale in @($OutputPath, $suspiciousPath)) {
            if (Test-Path -Path $stale) { Remove-Item -Path $stale -Force -ErrorAction SilentlyContinue }
        }

        $delegationArray = $delegations.ToArray()
        $suspiciousDelegations = @($delegationArray | Where-Object { $_.IsSuspicious -eq $true })

        if ($delegationArray.Count -gt 0) {
            $delegationArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            if ($suspiciousDelegations.Count -gt 0) {
                $suspiciousDelegations | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
            }
        }

        $elapsed = (Get-Date) - $startTime
        Write-Log "Delegation collection complete: $($delegationArray.Count) delegations across $totalCount mailboxes ($($suspiciousDelegations.Count) suspicious, $($skipped.Count) mailboxes skipped) in $($elapsed.ToString('mm\:ss'))" -Level "Info"

        if ($skipped.Count -eq 0) {
            Update-GuiStatus "Delegation collection complete: $($delegationArray.Count) delegations ($($suspiciousDelegations.Count) suspicious)." ([System.Drawing.Color]::Green)
        }

        return $delegationArray
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in delegation collection: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-AppRegistrationData {
    <#
    .SYNOPSIS
        Collects app registrations AND consented enterprise apps with risk assessment.

    .DESCRIPTION
        Covers both places an OAuth abuse can live:
        - App registrations owned by this tenant (Get-MgApplication), evaluated
          regardless of creation date. IsRecent marks apps created inside the date range.
        - Third-party enterprise apps (service principals) that hold consent in this
          tenant. Illicit-consent attacks use a multi-tenant app the attacker owns, so it
          exists here ONLY as a service principal with grants and never as an app
          registration.

        Risk is based on permission NAMES, resolved from the Microsoft Graph, Exchange
        Online, SharePoint and Azure AD Graph service principals (not a hard-coded ID
        list), across three sources:
        - Requested   (RequiredResourceAccess on the app registration)
        - Delegated   (oauth2PermissionGrants, including tenant-wide admin consent)
        - Application (app role assignments on Graph and Exchange Online)

        Risk only ever escalates: a missing publisher raises Low to Medium but never
        lowers a High.

    .PARAMETER DaysBack
        Window used for the IsRecent flag (default: configured date range).

    .OUTPUTS
        Array of app objects with risk level and reasons
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AppRegistrations.csv")
    )

    Update-GuiStatus "Starting app registration collection..." ([System.Drawing.Color]::Orange)
    Write-Log "APP REGISTRATION / ENTERPRISE APP COLLECTION STARTED" -Level "Info"
    $recentCutoff = (Get-Date).AddDays(-$DaysBack)
    $gaps = [System.Collections.Generic.List[string]]::new()

    # Permission names that let an app read or send mail, read files/sites, or change
    # identity/role configuration. Matched by permission name against requested, delegated
    # and application grants.
    $highRiskPermissions = @(
        'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Mail.ReadBasic', 'Mail.ReadBasic.All',
        'Mail.Read.Shared', 'Mail.ReadWrite.Shared', 'Mail.Send.Shared', 'MailboxSettings.ReadWrite',
        'Files.Read.All', 'Files.ReadWrite.All', 'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All',
        'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'User.ReadWrite.All', 'Group.ReadWrite.All',
        'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory', 'Policy.ReadWrite.ConditionalAccess',
        'full_access_as_app', 'EWS.AccessAsUser.All', 'EAS.AccessAsUser.All', 'IMAP.AccessAsUser.All',
        'POP.AccessAsUser.All', 'SMTP.Send', 'Contacts.ReadWrite', 'Calendars.ReadWrite',
        'Chat.ReadWrite', 'ChatMessage.Read', 'Notes.ReadWrite.All'
    )
    $mediumRiskPermissions = @(
        'Directory.Read.All', 'User.Read.All', 'Group.Read.All', 'AuditLog.Read.All',
        'Calendars.Read', 'Contacts.Read', 'People.Read.All'
    )
    # First-party Microsoft owner tenants - excluded from the enterprise-app sweep.
    $microsoftOwnerTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
    # Resource APIs whose permission IDs are resolved to names.
    $graphAppId    = '00000003-0000-0000-c000-000000000000'
    $exchangeAppId = '00000002-0000-0ff1-ce00-000000000000'
    $resourceAppIds = @($graphAppId, $exchangeAppId, '00000003-0000-0ff1-ce00-000000000000', '00000002-0000-0000-c000-000000000000')

    try {
        $applications = @(Get-MgApplication -All -ErrorAction Stop)
        $servicePrincipals = @(Get-MgServicePrincipal -All -ErrorAction Stop)
        Write-Log "Retrieved $($applications.Count) app registrations and $($servicePrincipals.Count) service principals" -Level "Info"

        $spById = @{}
        $spByAppId = @{}
        foreach ($sp in $servicePrincipals) {
            $spById[$sp.Id] = $sp
            if ($sp.AppId) { $spByAppId[$sp.AppId] = $sp }
        }

        # Permission id -> name
        $permissionNames = @{}
        foreach ($resourceAppId in $resourceAppIds) {
            $resourceSp = $spByAppId[$resourceAppId]
            if (-not $resourceSp) { continue }
            foreach ($scope in @($resourceSp.Oauth2PermissionScopes)) { if ($scope.Id) { $permissionNames["$($scope.Id)"] = $scope.Value } }
            foreach ($role in @($resourceSp.AppRoles)) { if ($role.Id) { $permissionNames["$($role.Id)"] = $role.Value } }
        }

        # Delegated consent (per client service principal)
        $delegatedByClient = @{}
        try {
            foreach ($grant in @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants")) {
                if (-not $delegatedByClient.ContainsKey($grant.clientId)) {
                    $delegatedByClient[$grant.clientId] = [System.Collections.Generic.List[object]]::new()
                }
                $delegatedByClient[$grant.clientId].Add($grant)
            }
        }
        catch {
            $gaps.Add("delegated consent grants could not be read")
            Write-Log "Could not read oauth2PermissionGrants: $($_.Exception.Message)" -Level "Warning"
        }

        # Application permissions granted on Graph / Exchange Online (per client service principal)
        $appRolesByClient = @{}
        foreach ($resourceAppId in @($graphAppId, $exchangeAppId)) {
            $resourceSp = $spByAppId[$resourceAppId]
            if (-not $resourceSp) { continue }
            try {
                foreach ($assignment in @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($resourceSp.Id)/appRoleAssignedTo")) {
                    if (-not $appRolesByClient.ContainsKey($assignment.principalId)) {
                        $appRolesByClient[$assignment.principalId] = [System.Collections.Generic.List[string]]::new()
                    }
                    $roleName = $permissionNames["$($assignment.appRoleId)"]
                    if (-not $roleName) { $roleName = "$($resourceSp.DisplayName):$($assignment.appRoleId)" }
                    $appRolesByClient[$assignment.principalId].Add($roleName)
                }
            }
            catch {
                $gaps.Add("application permission grants on $($resourceSp.DisplayName) could not be read")
                Write-Log "Could not read app role assignments on $($resourceSp.DisplayName): $($_.Exception.Message)" -Level "Warning"
            }
        }

        $appRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
        $registeredAppIds = [System.Collections.Generic.HashSet[string]]::new()

        # Builds one output row for an app registration and/or its service principal.
        $buildRow = {
            param($Source, $DisplayName, $AppId, $Created, $PublisherDomain, $VerifiedPublisher, $Homepage, $Sp, $App)

            $requestedNames = [System.Collections.Generic.List[string]]::new()
            $requestedDisplay = [System.Collections.Generic.List[string]]::new()
            if ($App) {
                foreach ($resourceAccess in @($App.RequiredResourceAccess | Where-Object { $_ })) {
                    foreach ($permission in @($resourceAccess.ResourceAccess | Where-Object { $_ })) {
                        $name = $permissionNames["$($permission.Id)"]
                        if ($name) {
                            $requestedNames.Add($name)
                            $requestedDisplay.Add("$name ($($permission.Type))")
                        }
                        else {
                            $requestedDisplay.Add("$($resourceAccess.ResourceAppId):$($permission.Id) ($($permission.Type))")
                        }
                    }
                }
            }

            $delegatedNames = [System.Collections.Generic.List[string]]::new()
            $adminConsentAll = $false
            if ($Sp -and $delegatedByClient.ContainsKey($Sp.Id)) {
                foreach ($grant in $delegatedByClient[$Sp.Id]) {
                    if ($grant.consentType -eq 'AllPrincipals') { $adminConsentAll = $true }
                    foreach ($scopeName in @("$($grant.scope)" -split '\s+' | Where-Object { $_ })) { $delegatedNames.Add($scopeName) }
                }
            }
            $applicationNames = @()
            if ($Sp -and $appRolesByClient.ContainsKey($Sp.Id)) { $applicationNames = @($appRolesByClient[$Sp.Id] | Select-Object -Unique) }
            $delegatedUnique = @($delegatedNames | Select-Object -Unique)

            $level = 0
            $reasons = @()
            $allNames = @(@($requestedNames) + @($delegatedUnique) + @($applicationNames) | Select-Object -Unique)
            $highHits = @($allNames | Where-Object { $highRiskPermissions -contains $_ })
            $mediumHits = @($allNames | Where-Object { $mediumRiskPermissions -contains $_ })
            if ($highHits.Count -gt 0) {
                $level = 2
                $reasons += "High-privilege permissions: $($highHits -join ', ')"
            }
            elseif ($mediumHits.Count -gt 0) {
                $level = 1
                $reasons += "Broad read permissions: $($mediumHits -join ', ')"
            }
            if ($adminConsentAll -and @($delegatedUnique | Where-Object { $highRiskPermissions -contains $_ }).Count -gt 0) {
                $reasons += "Tenant-wide admin consent to high-privilege delegated permissions"
            }
            if (@($applicationNames | Where-Object { $highRiskPermissions -contains $_ }).Count -gt 0) {
                $reasons += "High-privilege APPLICATION permissions (act without a signed-in user)"
            }
            if ([string]::IsNullOrEmpty($PublisherDomain) -and [string]::IsNullOrEmpty($VerifiedPublisher)) {
                $level = [Math]::Max($level, 1)
                $reasons += "No publisher information"
            }
            $isRecent = $false
            [datetime]$createdTime = [datetime]::MinValue
            if ($Created -and [DateTime]::TryParse("$Created", [ref]$createdTime) -and $createdTime -ge $recentCutoff) {
                $isRecent = $true
                if ($level -ge 1) { $reasons += "Created within the last $DaysBack days" }
            }

            [PSCustomObject]@{
                AppId                  = $AppId
                DisplayName            = $DisplayName
                Source                 = $Source
                CreatedDateTime        = $Created
                IsRecent               = $isRecent
                PublisherDomain        = $PublisherDomain
                VerifiedPublisher      = $VerifiedPublisher
                Homepage               = $Homepage
                ServicePrincipalId     = if ($Sp) { $Sp.Id } else { "" }
                ServicePrincipalType   = if ($Sp) { $Sp.ServicePrincipalType } else { "" }
                SignInAudience         = if ($App) { $App.SignInAudience } else { "" }
                RequestedPermissions   = ($requestedDisplay -join "; ")
                GrantedDelegated       = ($delegatedUnique -join "; ")
                GrantedApplication     = ($applicationNames -join "; ")
                AdminConsentAllUsers   = $adminConsentAll
                RequiredResourceAccess = if ($App) { ($App.RequiredResourceAccess | ConvertTo-Json -Compress -Depth 10) } else { "" }
                RiskLevel              = @("Low", "Medium", "High")[$level]
                RiskReasons            = ($reasons -join ", ")
            }
        }

        $processedCount = 0
        foreach ($app in $applications) {
            $processedCount++
            if ($processedCount % 50 -eq 0) {
                $percentage = [math]::Round(($processedCount / $applications.Count) * 100, 1)
                Update-GuiStatus "Processing apps: $processedCount of $($applications.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            [void]$registeredAppIds.Add("$($app.AppId)")
            $sp = $spByAppId[$app.AppId]
            $appRegs.Add((& $buildRow "AppRegistration" $app.DisplayName $app.AppId $app.CreatedDateTime $app.PublisherDomain $app.VerifiedPublisher.DisplayName $app.Web.HomePageUrl $sp $app))
        }

        # Enterprise apps owned by other tenants that hold consent here.
        foreach ($sp in $servicePrincipals) {
            if ($registeredAppIds.Contains("$($sp.AppId)")) { continue }
            if ($sp.ServicePrincipalType -ne 'Application') { continue }
            if ($microsoftOwnerTenants -contains "$($sp.AppOwnerOrganizationId)") { continue }
            $hasGrants = $delegatedByClient.ContainsKey($sp.Id) -or $appRolesByClient.ContainsKey($sp.Id)
            if (-not $hasGrants) { continue }

            $created = $sp.CreatedDateTime
            if (-not $created -and $sp.AdditionalProperties) { $created = $sp.AdditionalProperties['createdDateTime'] }
            $appRegs.Add((& $buildRow "EnterpriseApp" $sp.DisplayName $sp.AppId $created "" $sp.VerifiedPublisher.DisplayName $sp.Homepage $sp $null))
        }

        # Remove previous output so a run with no apps cannot leave stale data behind.
        $highRiskPath = $OutputPath -replace '\.csv$', '_HighRisk.csv'
        Remove-StaleOutput -Path @($OutputPath, $highRiskPath)

        $appRegArray = $appRegs.ToArray()
        if ($appRegArray.Count -gt 0) {
            $appRegArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force

            $highRiskApps = @($appRegArray | Where-Object { $_.RiskLevel -eq "High" })
            if ($highRiskApps.Count -gt 0) {
                $highRiskApps | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            }
        }

        $enterpriseCount = @($appRegArray | Where-Object { $_.Source -eq "EnterpriseApp" }).Count
        Set-CollectionStatus -Source "AppRegistrations" `
            -Complete ($gaps.Count -eq 0) `
            -Records $appRegArray.Count `
            -Note $(if ($gaps.Count -gt 0) { "Partial app data: $($gaps -join '; '). Risk ratings may be understated." } else { "" })

        Update-GuiStatus "App collection complete: $($appRegArray.Count) apps ($enterpriseCount third-party enterprise apps)." ([System.Drawing.Color]::Green)
        Write-Log "App collection complete: $($applications.Count) registrations, $enterpriseCount third-party enterprise apps with consent, $(@($appRegArray | Where-Object { $_.RiskLevel -eq 'High' }).Count) high risk" -Level "Info"
        return $appRegArray
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in app registration collection: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-ConditionalAccessData {
    <#
    .SYNOPSIS
        Collects Conditional Access policies with configuration review.

    .DESCRIPTION
        Retrieves CA policies and flags (IsSuspicious):
        - Policies modified inside the configured date range (CA tampering)
        - Disabled policies
        - Policies that exclude administrator roles. ExcludeRoles holds role TEMPLATE
          GUIDs, so they are resolved to names through directoryRoleTemplates before
          matching (comparing against display names never matches).

        Also recorded as reasons (not flagged on their own): report-only state, excluded
        users/groups, and trusted-location exemptions. A tenant with no CA policies is
        recorded as a coverage note in CollectionStatus.csv.

    .OUTPUTS
        Array of CA policy objects with risk flags
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ConditionalAccess.csv")
    )

    Update-GuiStatus "Starting Conditional Access collection..." ([System.Drawing.Color]::Orange)
    Write-Log "CONDITIONAL ACCESS COLLECTION STARTED" -Level "Info"

    try {
        $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        $recentCutoff = (Get-Date).AddDays(-$ConfigData.DateRange)

        # Role template id -> display name
        $roleNames = @{}
        $roleLookupFailed = $false
        try {
            foreach ($template in @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/directoryRoleTemplates")) {
                $roleNames["$($template.id)"] = $template.displayName
            }
        }
        catch {
            $roleLookupFailed = $true
            Write-Log "Could not resolve directory role templates ($($_.Exception.Message)) - only Global Administrator exclusions will be detected" -Level "Warning"
        }
        if (-not $roleNames.ContainsKey('62e90394-69f5-4237-9190-012177145e10')) {
            $roleNames['62e90394-69f5-4237-9190-012177145e10'] = 'Global Administrator'
        }

        $policies = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($policy in $caPolicies) {
            $isSuspicious = $false
            $reasons = @()

            if ($policy.ModifiedDateTime -and $policy.ModifiedDateTime -ge $recentCutoff) {
                $reasons += "Modified in the last $($ConfigData.DateRange) days"
                $isSuspicious = $true
            }

            if ($policy.State -eq "disabled") {
                $reasons += "Policy is disabled"
                $isSuspicious = $true
            }
            elseif ($policy.State -eq "enabledForReportingButNotEnforced") {
                $reasons += "Report-only (not enforced)"
            }

            $excludedRoleNames = @()
            foreach ($roleId in @($policy.Conditions.Users.ExcludeRoles)) {
                if ([string]::IsNullOrWhiteSpace($roleId)) { continue }
                $excludedRoleNames += $(if ($roleNames.ContainsKey("$roleId")) { $roleNames["$roleId"] } else { "$roleId" })
            }
            $excludedAdminRoles = @($excludedRoleNames | Where-Object { $_ -like '*Administrator*' })
            if ($excludedAdminRoles.Count -gt 0) {
                $reasons += "Excludes admin roles ($($excludedAdminRoles -join ', '))"
                $isSuspicious = $true
            }

            $excludedUserCount = @($policy.Conditions.Users.ExcludeUsers | Where-Object { $_ }).Count
            $excludedGroupCount = @($policy.Conditions.Users.ExcludeGroups | Where-Object { $_ }).Count
            if ($excludedUserCount -gt 0) { $reasons += "Excludes $excludedUserCount user(s)/user type(s)" }
            if ($excludedGroupCount -gt 0) { $reasons += "Excludes $excludedGroupCount group(s)" }
            if (@($policy.Conditions.Locations.ExcludeLocations) -contains 'AllTrusted') { $reasons += "Exempts trusted locations" }

            $policies.Add([PSCustomObject]@{
                DisplayName = $policy.DisplayName
                State = $policy.State
                CreatedDateTime = $policy.CreatedDateTime
                ModifiedDateTime = $policy.ModifiedDateTime
                Conditions = ($policy.Conditions | ConvertTo-Json -Compress -Depth 10)
                GrantControls = ($policy.GrantControls | ConvertTo-Json -Compress -Depth 10)
                SessionControls = ($policy.SessionControls | ConvertTo-Json -Compress -Depth 10)
                IsSuspicious = $isSuspicious
                SuspiciousReasons = ($reasons -join ", ")
            })
        }

        $suspiciousPath = $OutputPath -replace '\.csv$', '_Suspicious.csv'
        Remove-StaleOutput -Path @($OutputPath, $suspiciousPath)

        $policyArray = $policies.ToArray()
        $suspiciousPolicies = @($policyArray | Where-Object { $_.IsSuspicious -eq $true })
        if ($policyArray.Count -gt 0) {
            $policyArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            if ($suspiciousPolicies.Count -gt 0) {
                $suspiciousPolicies | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
            }
        }

        $note = ""
        if ($policyArray.Count -eq 0) {
            $note = "No Conditional Access policies exist in this tenant. Confirm Security Defaults is on, otherwise sign-ins have no CA protection."
            Write-Log $note -Level "Warning"
        }
        elseif ($roleLookupFailed) {
            $note = "Directory role names could not be resolved; only Global Administrator role exclusions were checked."
        }
        Set-CollectionStatus -Source "ConditionalAccess" -Complete (-not $roleLookupFailed) -Records $policyArray.Count -Note $note

        Update-GuiStatus "CA policy collection complete: $($policyArray.Count) policies ($($suspiciousPolicies.Count) flagged)." ([System.Drawing.Color]::Green)
        return $policyArray
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in Conditional Access collection: $($_.Exception.Message)" -Level "Error"
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
        Maximum messages to retrieve across ALL pages (safety cap).
        Get-MessageTraceV2 returns at most 5000 records per call and has no paging, so
        this function pages manually (StartingRecipientAddress + EndDate from the last
        record of each page, as Microsoft documents). If the cap is reached the result
        is flagged INCOMPLETE in CollectionStatus.csv and the report.
        Default: 50000
    
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
        [ValidateRange(100, 500000)]
        [int]$MaxMessages = 50000
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
        
        # Calculate date range. Exchange rejects ranges over 10 days, so a full 10-day
        # request starts a minute late to stay safely inside the limit.
        $actualDaysBack = $DaysBack
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$actualDaysBack)
        if ($actualDaysBack -ge 10) { $startDate = $startDate.AddMinutes(1) }
        
        Write-Log "Message trace range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))" -Level "Info"
        
        # Page through Get-MessageTraceV2. Max 5000 per call and no native paging: take the
        # Received time and recipient of the LAST record of each page as the next EndDate /
        # StartingRecipientAddress. Results are de-duplicated on trace id + recipient.
        Update-GuiStatus "Calling Get-MessageTraceV2..." ([System.Drawing.Color]::Orange)
        Write-Log "Executing paged Get-MessageTraceV2 from $startDate to $endDate (cap $MaxMessages)" -Level "Info"

        $allMessages = [System.Collections.Generic.List[object]]::new()
        $seenKeys = [System.Collections.Generic.HashSet[string]]::new()
        $pageEnd = $endDate
        $startingRecipient = $null
        $hitCap = $false
        $pageNumber = 0

        while ($true) {
            $remaining = $MaxMessages - $allMessages.Count
            if ($remaining -le 0) { $hitCap = $true; break }
            $pageSize = [Math]::Min(5000, $remaining)
            $pageNumber++

            $traceParams = @{
                StartDate   = $startDate
                EndDate     = $pageEnd
                ResultSize  = $pageSize
                ErrorAction = 'Stop'
            }
            if ($startingRecipient) { $traceParams['StartingRecipientAddress'] = $startingRecipient }

            $page = @(Get-MessageTraceV2 @traceParams)
            if ($page.Count -eq 0) { break }

            $added = 0
            foreach ($traceRecord in $page) {
                if ($seenKeys.Add("$($traceRecord.MessageTraceId)|$($traceRecord.RecipientAddress)")) {
                    $allMessages.Add($traceRecord)
                    $added++
                }
            }
            Update-GuiStatus "Message trace: $($allMessages.Count) messages retrieved (page $pageNumber)..." ([System.Drawing.Color]::Orange)
            Write-Log "  Trace page ${pageNumber}: $($page.Count) records ($added new)" -Level "Info"

            if ($page.Count -lt $pageSize) { break }   # last page

            $lastRecord = $page[-1]
            $receivedUtc = $lastRecord.Received
            $pageEnd = if ($receivedUtc.Kind -eq [DateTimeKind]::Unspecified) { [DateTime]::SpecifyKind($receivedUtc, [DateTimeKind]::Utc) } else { $receivedUtc.ToUniversalTime() }
            $startingRecipient = $lastRecord.RecipientAddress

            if ($added -eq 0) {
                # Paging is not advancing - stop rather than loop forever, and say so.
                $hitCap = $true
                Write-Log "Message trace paging stopped advancing at $pageEnd - results are TRUNCATED" -Level "Warning"
                break
            }
        }

        Write-Log "Get-MessageTraceV2 returned $($allMessages.Count) messages in $pageNumber page(s)" -Level "Info"

        # Previous output would otherwise be picked up as current if this run finds nothing.
        Remove-StaleOutput -Path @($OutputPath)

        $traceNote = ""
        if ($hitCap) {
            $traceNote = "message trace stopped at the $MaxMessages-message cap; older messages in the $actualDaysBack-day window are NOT included (raise -MaxMessages or narrow the range)"
            Write-Log "Message trace hit the $MaxMessages-message cap - results are TRUNCATED" -Level "Warning"
            Update-GuiStatus "WARNING: message trace capped at $MaxMessages messages - results incomplete" ([System.Drawing.Color]::Red)
        }
        Set-CollectionStatus -Source "MessageTrace" -Complete (-not $hitCap) -Records $allMessages.Count -Note $traceNote

        if ($allMessages.Count -eq 0) {
            Update-GuiStatus "No messages found in date range" ([System.Drawing.Color]::Orange)
            Write-Log "No messages found for the specified date range" -Level "Warning"
            return @()
        }
        
        # Convert to ETR format
        Update-GuiStatus "Converting $($allMessages.Count) messages to ETR format..." ([System.Drawing.Color]::Orange)
        Write-Log "Converting message trace results to ETR-compatible format" -Level "Info"
        
        $etrMessages = [System.Collections.Generic.List[object]]::new($allMessages.Count)
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
            $etrMessages.Add($etrMessage)
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
        
        return $etrMessages.ToArray()
        
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
            Write-Log "  [X] No mapping found for $field" -Level "Warning"
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
                "The ETR file is very large ($([math]::Round($fileSize, 1))) MB.`n`n" +
                "This may cause memory issues or take significant time.`n`n" +
                "Continue with analysis?",
                "Large File Warning", "YesNo", "Warning"
            )
            if ($result -eq "No") {
                return $null
            }
        }
        
        Update-GuiStatus "Analyzing ETR file: $($selectedFile.Name) ($([math]::Round($fileSize, 1))) MB..." ([System.Drawing.Color]::Orange)
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
                Update-GuiStatus "Processing ETR records: $processingCount of $($etrData.Count) ($percentage)%" ([System.Drawing.Color]::Orange)
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
        $outboundMessages = foreach ($msg in $processedMessages) {
            if ($msg.Direction -like "*outbound*" -or $msg.Direction -like "*send*" -or [string]::IsNullOrEmpty($msg.Direction)) {
                $msg
            }
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
                    MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join ", "
                    Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join ", "
                    Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join ", "
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
                $normalizedSubject = $msg.Subject.ToLower().Trim()
                $key = "$($msg.SenderAddress)`0$normalizedSubject"
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
                    MessageIds = ($messages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join ", "
                    Recipients = ($messages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join ", "
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
                            MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 5) -join ", "
                            Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join ", "
                            Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join ", "
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
                        SenderAddress = ($riskyIPMessages.SenderAddress | Select-Object -Unique) -join ", "
                        RiskType = "RiskyIPCorrelation"
                        RiskLevel = "Critical"
                        MessageCount = $riskyIPMessages.Count
                        Description = "Messages from/to risky IP $riskyIP"
                        MessageIds = ($riskyIPMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join ", "
                        Recipients = ($riskyIPMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join ", "
                        Subjects = ($riskyIPMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join ", "
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
                        MessageIds = ($senderFailures.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join ", "
                        Recipients = ($senderFailures.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join ", "
                        Subjects = ($senderFailures.Subject | Select-Object -Unique | Select-Object -First 3) -join ", "
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
                                    IPVersion = ConvertTo-SafeString $_.IPVersion
                                    ISP = ConvertTo-SafeString $_.ISP
                                    City = ConvertTo-SafeString $_.City
                                    RegionName = ConvertTo-SafeString $_.RegionName
                                    Country = ConvertTo-SafeString $_.Country
                                    IsUnusualLocation = ConvertTo-SafeBoolean $_.IsUnusualLocation
                                    IsHighRiskISP = ConvertTo-SafeBoolean $_.IsHighRiskISP
                                    StatusCode = ConvertTo-SafeString $_.StatusCode
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
                                    InitiatedByType = ConvertTo-SafeString $_.InitiatedByType
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

    #══════════════════════════════════════════════════════════════
    # DATA COVERAGE CHECK
    # Every collector records gaps in CollectionStatus.csv (skipped mailboxes, truncated
    # pulls, fallback sources, unreadable APIs). Surface them here and in the report, and
    # flag stale or missing sources, so a partial dataset is never read as a clean one.
    #══════════════════════════════════════════════════════════════
    $coverageNotes = [System.Collections.Generic.List[PSCustomObject]]::new()
    $statusRows = @(Get-CollectionStatus)

    foreach ($row in $statusRows) {
        $rowComplete = ("$($row.Complete)" -eq "True")
        if (-not $rowComplete -or -not [string]::IsNullOrWhiteSpace($row.Note)) {
            $coverageNotes.Add([PSCustomObject]@{
                Source  = $row.Source
                Level   = $(if ($rowComplete) { "Note" } else { "Incomplete" })
                Message = $row.Note
            })
        }
    }

    # Data source -> collection status key
    $statusKeys = @{
        SignInData            = "SignIns"
        AdminAuditData        = "AdminAudit"
        InboxRulesData        = "InboxRules"
        DelegationData        = "MailboxDelegation"
        AppRegData            = "AppRegistrations"
        ConditionalAccessData = "ConditionalAccess"
        MFAStatusData         = "MFAAudit"
    }
    $staleAfterDays = 2
    foreach ($entry in $dataSources.GetEnumerator()) {
        $info = $entry.Value
        if ($info.Available) {
            $fileTime = (Get-Item -Path $info.Path -ErrorAction SilentlyContinue).LastWriteTime
            if ($fileTime -and ((Get-Date) - $fileTime).TotalDays -gt $staleAfterDays) {
                $coverageNotes.Add([PSCustomObject]@{
                    Source  = $entry.Key
                    Level   = "Stale"
                    Message = "Data file $([System.IO.Path]::GetFileName($info.Path)) was last written $($fileTime.ToString('yyyy-MM-dd HH:mm')) ($([Math]::Round(((Get-Date) - $fileTime).TotalDays, 1)) days ago). Re-run the collector if this is not the data you intend to analyze."
                })
            }
        }
        elseif ($statusKeys.ContainsKey($entry.Key)) {
            $hasStatus = @($statusRows | Where-Object { $_.Source -eq $statusKeys[$entry.Key] }).Count -gt 0
            if (-not $hasStatus) {
                $coverageNotes.Add([PSCustomObject]@{
                    Source  = $entry.Key
                    Level   = "Missing"
                    Message = "No data for this source and no record that its collector ran. It was not collected in this working directory, so it is NOT reflected in this report."
                })
            }
        }
    }

    $levelOrder = @{ Incomplete = 0; Missing = 1; Stale = 2; Note = 3 }
    $coverageNotes = @($coverageNotes | Sort-Object @{ Expression = { $levelOrder[$_.Level] } }, Source)
    $script:ReportCoverageNotes = $coverageNotes
    foreach ($note in $coverageNotes) {
        Write-Log "DATA COVERAGE [$($note.Level)] $($note.Source): $($note.Message)" -Level $(if ($note.Level -eq "Note") { "Info" } else { "Warning" })
    }
    $incompleteCount = @($coverageNotes | Where-Object { $_.Level -in @("Incomplete", "Missing", "Stale") }).Count
    if ($incompleteCount -gt 0) {
        Update-GuiStatus "WARNING: $incompleteCount data source(s) incomplete, missing or stale - see the Data Coverage section of the report" ([System.Drawing.Color]::Orange)
    }
    
    # Initialize user tracking
    $users = @{}
    $systemIssues = @()
    
    # Process sign-in data
    if ($dataSources.SignInData.Available) {
        Update-GuiStatus "Analyzing sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Generate unique logins report
        $uniqueLogins = [System.Collections.Generic.List[PSCustomObject]]::new()
        $userLocationGroups = $dataSources.SignInData.Data | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            $uniqueUserLocations = $userSignIns |
                Select-Object UserId, UserDisplayName, IP, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) -and $_.IP -ne "Unknown" }
            
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
                
                $uniqueLogins.Add($uniqueLogin)
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
                    UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
                    SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
                    SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
                    ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    MFAStatus = $null
                    FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
                    RiskScore = 0
                }
            }
            
            $isSuccessfulSignIn = ($signIn.StatusCode -eq "0" -or [string]::IsNullOrEmpty($signIn.StatusCode))
            $isFailedSignIn = (-not [string]::IsNullOrEmpty($signIn.StatusCode) -and $signIn.StatusCode -ne "0")
            $isUnusual = $signIn.IsUnusualLocation -eq $true
            
            # Only flag unusual locations for successful sign-ins
            if ($isUnusual -and $isSuccessfulSignIn) {
                $users[$userId].UnusualSignIns.Add($signIn)
                $users[$userId].RiskScore += 5
            }
            
            if ($isFailedSignIn) {
                $users[$userId].FailedSignIns.Add($signIn)
            }
            
            if ($signIn.RiskLevel -and $signIn.RiskLevel -eq "high" -and $isSuccessfulSignIn) {
                $users[$userId].RiskScore += 15
            }
			
			# Check for high-risk ISP sign-ins
			$isHighRiskISP = ConvertTo-SafeBoolean $signIn.IsHighRiskISP
			if ($isHighRiskISP -and $isSuccessfulSignIn) {
				$users[$userId].HighRiskISPSignIns.Add($signIn)
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
                    UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
                    SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
                    SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
                    ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    MFAStatus = $null
                    FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
                    RiskScore = 0
                }
            }
            
            if ($auditLog.RiskLevel -eq "High") {
                $users[$userId].HighRiskOps.Add($auditLog)
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
                $userId = $rule.Mailbox
                if ([string]::IsNullOrEmpty($userId)) { continue }
                
                if (-not $users.ContainsKey($userId)) {
                    $users[$userId] = @{
                        UserDisplayName = $rule.DisplayName
                        UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
                        SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
                        SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
                        ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        MFAStatus = $null
                        FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousRules.Add($rule)
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
                        UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
                        SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
                        SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
                        ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        MFAStatus = $null
                        FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousDelegations.Add($delegation)
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
                        UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
                        SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
                        SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
                        ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
                        HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        MFAStatus = $null
                        FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
                        PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
                        RiskScore = 0
                    }
                }
                
                $users[$systemUser].HighRiskAppRegs.Add($appReg)
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
                    UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
                    SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
                    SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
                    ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
                    HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    MFAStatus = $null
                    FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
                    PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
                    RiskScore = 0
                }
            }

            $users[$userId].ETRSpamActivity.Add($etrRecord)
            
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
					UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
					FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
					HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
					SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
					SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
					HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
					ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
					HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
					MFAStatus = $null
					FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
					PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
					RiskScore = 0
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
			if ($details -match "User\s+(\S+@\S+)") {
				$userId = $Matches[1]
				
				if (-not $users.ContainsKey($userId)) {
					$users[$userId] = @{
						UserDisplayName = $userId
						UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
						FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
						HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
						SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
						SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
						HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
						ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
						HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
						MFAStatus = $null
						FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
						PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
						RiskScore = 0
					}
				}
				
				# STORE the pattern data
				$users[$userId].FailedLoginPatterns.Add($pattern)
				
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
					UnusualSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
					FailedSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
					HighRiskOps = [System.Collections.Generic.List[PSCustomObject]]::new()
					SuspiciousRules = [System.Collections.Generic.List[PSCustomObject]]::new()
					SuspiciousDelegations = [System.Collections.Generic.List[PSCustomObject]]::new()
					HighRiskAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
					ETRSpamActivity = [System.Collections.Generic.List[PSCustomObject]]::new()
					HighRiskISPSignIns = [System.Collections.Generic.List[PSCustomObject]]::new()
					MFAStatus = $null
					FailedLoginPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()
					PasswordChangeIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
					RiskScore = 0
				}
			}
			
			# STORE the password change data
			$users[$userId].PasswordChangeIssues.Add($pwChange)
			
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
    
    $results = [System.Collections.Generic.List[PSCustomObject]]::new($users.Count)
    
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
        
        $results.Add($resultObject)
    }
    
    $results = @($results | Sort-Object -Property RiskScore -Descending)
    
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

#region HTML report: embedded template + payload builder

# Report template (single-file by design so the script stays auto-updatable). It is dependency-free,
# reads the JSON payload injected at __REPORT_DATA_JSON__ and renders everything client-side.
# ASCII only: non-ASCII glyphs are written as \uXXXX escapes inside the JavaScript.
$script:ReportTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft 365 Security Report</title>
<style>
/* Tokens. PowerShell may swap [data-theme] default via meta.darkMode. */
:root,[data-theme="dark"]{--bg:#0c0e11;--surface:#14171b;--surface2:#1b1f25;--line:#282d35;--text:#eceff3;--muted:#98a1ae;--accent:#ff6600;--crit:#ff5c5c;--high:#ffa033;--med:#f2c94c;--low:#4cc38a;--ok:#4cc38a;--on-accent:#1a0d00;--shadow:rgba(0,0,0,.35)}
[data-theme="light"]{--bg:#f3f1ed;--surface:#fff;--surface2:#f7f5f1;--line:#e2ded6;--text:#1b1d21;--muted:#5f6670;--accent:#e85d00;--crit:#c62828;--high:#b45f00;--med:#8a6d00;--low:#1f7a4d;--ok:#1f7a4d;--shadow:rgba(0,0,0,.15)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:400 14px/1.5 'IBM Plex Sans','Segoe UI',system-ui,sans-serif;padding:28px 20px 60px}
a{color:var(--accent)}a:hover{color:var(--high)}
h1,h2,h3{margin:0}
.wrap{max-width:1180px;margin:0 auto}
.mono{font-family:'IBM Plex Mono',Consolas,monospace}
.kick{font:500 11px 'IBM Plex Mono',Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}
.lbl{font:500 10.5px 'IBM Plex Mono',Consolas,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.crit{color:var(--crit)}.high{color:var(--high)}.med{color:var(--med)}.low{color:var(--low)}.ok{color:var(--ok)}.muted{color:var(--muted)}
.btn{background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font:500 13px 'IBM Plex Sans','Segoe UI',sans-serif;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--accent)}
.seg{display:flex;gap:4px;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:4px}
.seg button{border:0;border-radius:7px;padding:8px 16px;background:transparent;color:var(--muted);font:500 13px 'IBM Plex Sans','Segoe UI',sans-serif;cursor:pointer;white-space:nowrap}
.seg button.on{background:var(--accent);color:var(--on-accent)}
.row{display:grid;gap:14px;padding:11px 20px;align-items:center;border-top:1px solid var(--line);font-size:13px}
.row.click{cursor:pointer}.row.click:hover{background:var(--surface2)}
.row.head{background:var(--surface2);border-top:0;font:500 10.5px 'IBM Plex Mono',Consolas,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.row>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pill{font:600 11px 'IBM Plex Mono',Consolas,monospace;border:1px solid currentColor;border-radius:99px;padding:2px 9px;white-space:nowrap}
.chip{font-size:12px;padding:2px 9px;border-radius:99px;border:1px solid var(--line);white-space:nowrap}
.sec>button{all:unset;box-sizing:border-box;width:100%;cursor:pointer;display:flex;align-items:center;gap:14px;padding:16px 20px;flex-wrap:wrap}
.sec>button:hover{background:var(--surface2)}
.more{all:unset;display:block;box-sizing:border-box;width:100%;cursor:pointer;text-align:center;padding:12px;border-top:1px solid var(--line);color:var(--accent);font-weight:500}
.more:hover{background:var(--surface2)}
#drawer-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:50}
#drawer{position:fixed;top:0;right:0;bottom:0;width:min(540px,100%);background:var(--surface);border-left:1px solid var(--line);z-index:51;overflow-y:auto;box-shadow:-20px 0 60px var(--shadow)}
.rel{all:unset;box-sizing:border-box;width:100%;cursor:pointer;display:flex;justify-content:space-between;gap:12px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:6px;font-size:13px}
.rel:hover{border-color:var(--accent);background:var(--surface2)}
.rel span:first-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
pre{margin:8px 0 0;white-space:pre-wrap;overflow-wrap:anywhere;font:400 12px/1.5 'IBM Plex Mono',Consolas,monospace;background:var(--surface2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;max-height:280px;overflow:auto}
input[type=search]{background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 12px;font:13px 'IBM Plex Sans','Segoe UI',sans-serif;width:200px;outline:none}
input[type=search]:focus{border-color:var(--accent)}
.scroll-x{overflow-x:auto}.scroll-x>div{min-width:760px}
@media (max-width:820px){.two{grid-template-columns:1fr!important}}
@media print{body{background:#fff;color:#000}#drawer,#drawer-bg,.noprint{display:none!important}}
</style>
</head>
<body>
<div class="wrap" id="app"></div>
<div id="drawer-host"></div>
<script id="report-data" type="application/json">__REPORT_DATA_JSON__</script>
<script>
(function () {
'use strict';
var raw = document.getElementById('report-data').textContent.trim(), D;
try { D = JSON.parse(raw); } catch (e) { document.getElementById('app').innerHTML = '<p>Report data was not injected (placeholder still present).</p>'; return; }
var M = D.meta, PREV = 8;
var S = { dark: M.darkMode !== false, filter: 'All', q: '', allIds: false, open: {}, showAll: {}, stack: [] };
var $ = function (s) { return document.querySelector(s); };
var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
var LC = { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low' };
var lc = function (l) { return LC[l] || 'muted'; };
var by = function (a, f) { var r = {}; a.forEach(function (x) { var k = f(x); r[k] = (r[k] || 0) + 1; }); return r; };
var hk = function (k) { return k.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2'); };
var pl = function (a) { return (a || '').split('; ').length; };
var NAMES = { audit: 'audit', app: 'apps', fail: 'fails', mfa: 'mfa', pw: 'pw', ca: 'ca', rule: 'rules', deleg: 'deleg', trace: 'trace', loc: 'locs', id: 'identities', pat: 'pat', unus: 'unus', etr: 'etr' };
var KINDS = { audit: 'Admin operation', app: 'App registration', fail: 'Failed sign-in', mfa: 'MFA status', pw: 'Password change', ca: 'Conditional access policy', rule: 'Inbox rule', deleg: 'Mailbox delegation', trace: 'Message trace', loc: 'Sign-in location', id: 'Identity', pat: 'Attack pattern', unus: 'Unusual sign-in', etr: 'ETR spam activity' };
var arr = function (k) { return D[NAMES[k]] || []; };

/* Evidence section definitions: cols/grid/cells per dataset */
var cell = function (t, c, m) { return { t: t == null || t === '' ? '\u2014' : String(t), c: c || '', m: !!m }; };
var rlBadges = function (a) { var r = by(a, function (x) { return x.RiskLevel; }); return ['Critical', 'High', 'Medium', 'Low'].filter(function (k) { return r[k]; }).map(function (k) { return [r[k] + ' ' + k.toLowerCase(), lc(k)]; }); };
var DEFS = [
 { key: 'audit', title: 'High-risk admin operations', sub: 'Entra directory audit \u00b7 High and Medium first', cols: ['Time', 'Actor', 'Activity', 'Target', 'Result', 'Risk'], grid: '150px 1.1fr 1.5fr 1.2fr 80px 70px', badges: function (a) { return rlBadges(a); },
   cells: function (o) { return [cell(o.Timestamp, 'muted', 1), cell(o.UserDisplayName || o.UserId), cell(o.Activity), cell((o.targets || []).join(', ')), cell(o.Result, o.Result === 'success' ? 'ok' : 'crit'), cell(o.RiskLevel, lc(o.RiskLevel), 1)]; } },
 { key: 'app', title: 'High-risk app registrations', sub: 'Permissions and consent \u00b7 open a row for the full permission list', cols: ['Application', 'Created', 'Permissions', 'Consent', 'Why flagged'], grid: '1.3fr 150px 110px 110px 2fr', badges: function (a) { return [[a.filter(function (x) { return x.AdminConsentAllUsers === 'True'; }).length + ' tenant-wide consent', 'high']]; },
   cells: function (o) { var t = o.AdminConsentAllUsers === 'True'; return [cell(o.DisplayName), cell(o.CreatedDateTime, 'muted', 1), cell(pl(o.RequestedPermissions) + ' requested', '', 1), cell(t ? 'Tenant-wide' : 'Limited', t ? 'high' : 'muted'), cell((o.RiskReasons || '').replace('High-privilege permissions: ', ''), 'muted')]; } },
 { key: 'fail', title: 'Failed sign-ins', sub: 'Interactive sign-ins that did not complete', cols: ['Time', 'User', 'Reason', 'IP', 'Location', 'App'], grid: '150px 1.2fr 1.6fr 150px 1fr 1fr', badges: function (a) { return [[Object.keys(by(a, function (x) { return x.IP; })).length + ' source IPs', 'high']]; },
   cells: function (o) { return [cell(o.CreationTime, 'muted', 1), cell(o.UserId || 'unknown'), cell(o.Status), cell(o.IP, '', 1), cell([o.City, o.Country].filter(Boolean).join(', ')), cell(o.AppDisplayName)]; } },
 { key: 'mfa', title: 'MFA coverage', sub: 'Enforcement and registered methods per account', cols: ['Account', 'Type', 'MFA', 'Admin', 'Methods', 'Risk'], grid: '1.6fr 80px 90px 1.2fr 80px 80px', badges: function (a) { var r = by(a, function (x) { return x.HasMFA; }); return [['No', 'crit'], ['Partial', 'high'], ['Capable', 'muted']].filter(function (x) { return r[x[0]]; }).map(function (x) { return [r[x[0]] + ' ' + x[0].toLowerCase(), x[1]]; }); },
   cells: function (o) { return [cell(o.DisplayName), cell(o.UserType, 'muted'), cell(o.HasMFA, o.HasMFA === 'No' ? 'crit' : o.HasMFA === 'Partial' ? 'high' : ''), cell(o.IsAdmin === 'True' ? (o.AdminRoles || 'Admin') : 'No', o.IsAdmin === 'True' ? 'high' : 'muted'), cell(o.MethodCount, '', 1), cell(o.RiskLevel, lc(o.RiskLevel), 1)]; } },
 { key: 'pw', title: 'Password changes', sub: 'Rapid or repeated resets', cols: ['User', 'Changes', 'Span (h)', 'Self / admin', 'Risk'], grid: '1.6fr 90px 90px 110px 90px', badges: function (a) { return rlBadges(a); },
   cells: function (o) { return [cell(o.User), cell(o.ChangeCount, '', 1), cell(o.TimeSpanHours, '', 1), cell(o.SelfResets + ' / ' + o.AdminResets, '', 1), cell(o.RiskLevel, lc(o.RiskLevel), 1)]; } },
 { key: 'ca', title: 'Conditional access policies', sub: 'Grants, exclusions and enforcement state', cols: ['Policy', 'State', 'Grants', 'Excluded', 'Flags'], grid: '2fr 190px 90px 150px 1.5fr', badges: function () { return []; },
   cells: function (o) { var s = o.summary || {}; return [cell(o.DisplayName), cell(o.State, o.State === 'enabled' ? 'ok' : 'high', 1), cell(s.grant, '', 1), cell((s.exUsers || 0) + ' users \u00b7 ' + (s.exGroups || 0) + ' groups', '', 1), cell(o.SuspiciousReasons, 'muted')]; } },
 { key: 'rule', title: 'Inbox rules', sub: 'Forwarding, redirect and delete rules', cols: ['Mailbox', 'Rule', 'Enabled', 'Type', 'Suspicious'], grid: '1.6fr 1.2fr 80px 130px 90px', badges: function (a) { return [[a.filter(function (x) { return x.IsSuspicious === 'True'; }).length + ' suspicious', 'ok']]; },
   cells: function (o) { return [cell(o.PrimarySmtpAddress), cell(o.RuleName), cell(o.Enabled, '', 1), cell(o.MailboxType, 'muted'), cell(o.IsSuspicious, o.IsSuspicious === 'True' ? 'crit' : 'muted', 1)]; } },
 { key: 'deleg', title: 'Mailbox delegation', sub: 'Full access and Send As grants', cols: ['Mailbox', 'Delegate', 'Permissions', 'Flagged'], grid: '1.5fr 1.5fr 1fr 90px', badges: function () { return []; },
   cells: function (o) { return [cell(o.PrimarySmtpAddress), cell(o.DelegateEmail || o.DelegateName), cell(o.Permissions), cell(o.IsSuspicious, o.IsSuspicious === 'True' ? 'crit' : 'muted', 1)]; } },
 { key: 'trace', title: 'Message trace', sub: 'Mail flow in the window', cols: ['Received', 'From', 'To', 'Subject', 'Status'], grid: '150px 1.2fr 1.2fr 1.6fr 90px', badges: function (a) { var r = by(a, function (x) { return x.status; }); return Object.keys(r).map(function (k) { return [r[k] + ' ' + k.toLowerCase(), 'muted']; }); },
   cells: function (o) { return [cell(o.received, 'muted', 1), cell(o.sender_address), cell(o.recipient_address), cell(o.subject), cell(o.status)]; } },
 { key: 'loc', title: 'Sign-in locations', sub: 'Unique user, IP and place combinations', cols: ['User', 'IP', 'Location', 'ISP', 'Sign-ins'], grid: '1.3fr 170px 1fr 1.3fr 80px', badges: function (a) { return [[a.filter(function (x) { return x.IsUnusualLocation === 'True'; }).length + ' unusual', 'ok']]; },
   cells: function (o) { return [cell(o.UserId || 'unknown'), cell(o.IP, '', 1), cell([o.City, o.Country].filter(Boolean).join(', ')), cell(o.ISP), cell(o.SignInCount, '', 1)]; } },
 { key: 'pat', opt: true, title: 'Brute-force patterns', sub: 'Password spray and repeated credential failures', cols: ['User', 'Pattern', 'Source IP', 'Attempts', 'Breach', 'Risk'], grid: '1.4fr 1.3fr 150px 90px 90px 80px', badges: function (a) { var b = a.filter(function (x) { return x.SuccessfulBreach === 'True'; }).length; return (b ? [[b + ' confirmed breach', 'crit']] : []).concat(rlBadges(a)); },
   cells: function (o) { var b = o.SuccessfulBreach === 'True'; return [cell(o.UserId), cell(o.PatternType), cell(o.SourceIP, '', 1), cell(o.FailedAttempts, '', 1), cell(b ? 'Breached' : 'No', b ? 'crit' : 'muted'), cell(o.RiskLevel, lc(o.RiskLevel), 1)]; } },
 { key: 'unus', opt: true, title: 'Unusual and high-risk sign-ins', sub: 'Unexpected countries and high-risk ISPs', cols: ['Time', 'User', 'IP', 'Location', 'ISP', 'Flag'], grid: '150px 1.2fr 150px 1fr 1.2fr 120px', badges: function (a) { var h = a.filter(function (x) { return x.IsHighRiskISP === 'True'; }).length, u = a.filter(function (x) { return x.IsUnusualLocation === 'True'; }).length; return [[h + ' high-risk ISP', 'high'], [u + ' unusual location', 'med']]; },
   cells: function (o) { var h = o.IsHighRiskISP === 'True'; return [cell(o.CreationTime, 'muted', 1), cell(o.UserId || 'unknown'), cell(o.IP, '', 1), cell([o.City, o.Country].filter(Boolean).join(', ')), cell(o.ISP), cell(h ? 'High-risk ISP' : 'Unusual location', h ? 'high' : 'med')]; } },
 { key: 'etr', opt: true, title: 'ETR spam activity', sub: 'Excessive volume, failed deliveries and risky senders', cols: ['Sender', 'Type', 'Messages', 'Detail', 'Risk'], grid: '1.4fr 1.2fr 90px 2fr 80px', badges: function (a) { return rlBadges(a); },
   cells: function (o) { return [cell(o.SenderAddress), cell(o.RiskType), cell(o.MessageCount, '', 1), cell(o.Description, 'muted'), cell(o.RiskLevel, lc(o.RiskLevel), 1)]; } }
];
/* Sections flagged opt are hidden when their dataset is empty. */
var LIVE = function () { return DEFS.filter(function (d) { return !d.opt || arr(d.key).length; }); };
var DK = { audit: 'audit', app: 'app', fail: 'fail', mfa: 'mfa', pw: 'pw', ca: 'ca', rule: 'rule', deleg: 'deleg', trace: 'trace', loc: 'loc' };

/* Renderers */
function renderTop() {
  var ids = D.identities, cnt = by(ids, function (x) { return x.level; }), n = ids.length, c = cnt.Critical || 0, h = cnt.High || 0, m = cnt.Medium || 0, l = cnt.Low || 0;
  var pct = function (v) { return (v / n * 100).toFixed(1) + '%'; };
  var th = M.threats || {};
  var threats = [['Accounts under attack', th.accountsUnderAttack, ''], ['Failed sign-ins', th.failedSignIns, 'high'], ['High-risk app registrations', th.highRiskApps, 'crit'], ['Priority accounts', c + h, 'crit']];
  var cov = (D.cov || []).map(function (x) { var bad = x.Complete === 'False'; return '<div style="border:1px solid var(--line);border-radius:8px;padding:10px 12px;display:flex;flex-direction:column;gap:3px"><span style="font-weight:500;display:flex;align-items:center;gap:7px"><span style="width:7px;height:7px;border-radius:50%;background:var(--' + (bad ? 'crit' : 'ok') + ')"></span>' + esc(x.Source) + '</span><span class="mono muted" style="font-size:12px">' + esc(x.Records) + ' records</span></div>'; }).join('');
  var notes = (D.notes || []).map(function (x) { var inc = /incomplete|missing/i.test(x.level); return '<div style="display:flex;gap:12px;align-items:baseline;line-height:1.5"><span class="mono" style="flex:none;font-weight:600;font-size:10.5px;padding:2px 8px;border-radius:99px;background:' + (inc ? 'var(--crit);color:#fff' : 'var(--surface2);color:var(--text)') + '">' + esc(String(x.level).toUpperCase()) + '</span><span><strong>' + esc(x.source) + '</strong> \u2014 ' + esc(x.message) + '</span></div>'; }).join('');
  $('#app').innerHTML =
   '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px" class="noprint"><span class="mono muted" style="font-size:12px">' + esc(M.toolName || 'M365 Security Analysis') + ' v' + esc(M.toolVersion) + '</span><button class="btn" data-act="theme">' + (S.dark ? 'Light mode' : 'Dark mode') + '</button></div>' +
   '<div style="border-bottom:2px solid var(--accent);padding-bottom:26px;display:flex;justify-content:space-between;align-items:flex-end;gap:20px;flex-wrap:wrap"><div><div class="kick" style="margin-bottom:10px">' + esc(M.brand || 'Yeyland Wutani') + ' \u00b7 Threat detection &amp; risk assessment</div><h1 style="font-size:38px;font-weight:600;letter-spacing:-.02em;line-height:1.1">Microsoft 365 Security Report</h1></div><div class="mono muted" style="font-size:12.5px;line-height:1.8;text-align:right">' + esc(M.tenant) + '<br>' + esc(M.generated) + ' \u00b7 ' + esc(M.days) + '-day window<br>' + n + ' identities \u00b7 Tool v' + esc(M.toolVersion) + '</div></div>' +
   '<div class="two" style="margin-top:28px;display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:20px"><div class="card" style="padding:28px"><div class="lbl">Verdict</div><div style="font-size:26px;font-weight:600;line-height:1.25;margin:10px 0 22px;text-wrap:pretty">' + (c + h) + ' of ' + n + ' identities need action.' + (c ? ' <span class="crit">' + c + ' are critical.</span>' : '') + '</div>' +
   '<div style="display:flex;height:14px;border-radius:99px;overflow:hidden;gap:2px"><div style="width:' + pct(c) + ';background:var(--crit)"></div><div style="width:' + pct(h) + ';background:var(--high)"></div><div style="width:' + pct(m) + ';background:var(--med)"></div><div style="width:' + pct(l) + ';background:var(--low)"></div></div>' +
   '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:22px">' + [['Critical', c, 'crit'], ['High', h, 'high'], ['Medium', m, 'med'], ['Low', l, 'low']].map(function (x) { return '<div><div class="' + x[2] + '" style="font-size:34px;font-weight:600;line-height:1">' + x[1] + '</div><div class="muted" style="font-size:12.5px;margin-top:4px">' + x[0] + '</div></div>'; }).join('') + '</div></div>' +
   '<div class="card" style="padding:28px"><div class="lbl" style="margin-bottom:8px">Active threats</div>' + threats.map(function (t) { return '<div style="display:flex;justify-content:space-between;align-items:baseline;padding:10px 0;border-top:1px solid var(--line)"><span class="muted">' + t[0] + '</span><span class="' + t[2] + '" style="font-size:20px;font-weight:600">' + (t[1] == null ? 0 : t[1]) + '</span></div>'; }).join('') + '</div></div>' +
   '<div class="card" style="margin-top:20px;padding:24px 28px"><div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px"><h2 style="font-size:18px;font-weight:600">Data coverage</h2><span class="muted" style="font-size:13px">A missing finding may simply be outside the collected data.</span></div><div style="margin-top:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px">' + cov + '</div><div style="margin-top:16px;display:flex;flex-direction:column;gap:8px;font-size:13.5px">' + notes + '</div></div>' +
   '<div style="margin-top:36px" id="evidence"></div><div style="margin-top:36px" id="identities"></div><div class="mono muted" style="margin-top:22px;font-size:12px;text-align:center">Generated by Get-M365SecurityAnalysis v' + esc(M.toolVersion) + ' \u00b7 ' + esc(M.brand || 'Yeyland Wutani') + '</div>';
  document.body.setAttribute('data-theme', S.dark ? 'dark' : 'light');
  renderEvidence(); renderIdentities();
}
function renderEvidence() {
  var allOpen = LIVE().every(function (d) { return S.open[d.key]; });
  $('#evidence').innerHTML = '<div style="display:flex;justify-content:space-between;align-items:flex-end;gap:14px;flex-wrap:wrap"><div><h2 style="font-size:22px;font-weight:600">Evidence</h2><div class="muted" style="margin-top:4px;max-width:620px">Every record behind the scores. Sections start collapsed; open a row for the full record.</div></div><button class="btn noprint" data-act="allsecs">' + (allOpen ? 'Collapse all' : 'Expand all') + '</button></div><div style="margin-top:14px;display:flex;flex-direction:column;gap:10px">' +
  LIVE().map(function (d) {
    var a = arr(d.key), open = !!S.open[d.key], all = !!S.showAll[d.key];
    var head = '<button data-act="sec" data-a="' + d.key + '"><span style="font-size:15px;font-weight:600">' + d.title + '</span><span class="muted" style="flex:1;min-width:160px">' + d.sub + '</span><span style="display:flex;gap:6px;flex-wrap:wrap">' + d.badges(a).map(function (b) { return '<span class="pill ' + b[1] + '">' + esc(b[0]) + '</span>'; }).join('') + '</span><span class="mono muted" style="min-width:34px;text-align:right">' + a.length + '</span><span class="muted" style="font-size:12px;width:12px">' + (open ? '\u25b2' : '\u25bc') + '</span></button>';
    var body = '';
    if (open) {
      var g = 'grid-template-columns:' + d.grid.split(' ').map(function (x) { return 'minmax(0,' + x + ')'; }).join(' ');
      body = '<div class="scroll-x" style="border-top:1px solid var(--line)"><div><div class="row head" style="' + g + '">' + d.cols.map(function (c) { return '<span>' + c + '</span>'; }).join('') + '</div>' +
        (all ? a : a.slice(0, PREV)).map(function (o) { return '<div class="row click" style="' + g + '" data-act="open" data-k="' + d.key + '" data-i="' + a.indexOf(o) + '">' + d.cells(o).map(function (c) { return '<span class="' + c.c + (c.m ? ' mono' : '') + '" title="' + esc(c.t) + '">' + esc(c.t) + '</span>'; }).join('') + '</div>'; }).join('') +
        (a.length > PREV ? '<button class="more" data-act="all" data-a="' + d.key + '">' + (all ? 'Show fewer' : 'Show all ' + a.length) + '</button>' : '') + '</div></div>';
    }
    return '<div class="card sec" style="overflow:hidden">' + head + body + '</div>';
  }).join('') + '</div>';
}
function chipsFor(u) {
  var c = [], m = u.rel.mfa.length ? D.mfa[u.rel.mfa[0]] : null;
  if (u.f) c.push(u.f + ' failed sign-ins'); if (u.o) c.push(u.o + ' high-risk ops'); if (u.a) c.push(u.a + ' risky app regs'); if (u.rel.pw.length) c.push('Password changes'); if (u.unusual) c.push(u.unusual + ' unusual sign-ins'); if (u.spam) c.push(u.spam + ' ETR spam flags'); if (u.rel.pat && u.rel.pat.length) c.push('Attack pattern');
  if (m) { if (m.HasMFA === 'No') c.push('No MFA'); else if (m.HasMFA === 'Partial') c.push('MFA partial'); else if (m.MFAEnforced === 'False' && m.RiskLevel !== 'Low') c.push('MFA not enforced'); if (m.IsAdmin === 'True') c.push('Admin'); }
  return c.length ? c : ['No findings'];
}
function idRows() {
  var q = S.q.toLowerCase(), g = 'grid-template-columns:78px minmax(0,1.4fr) minmax(0,1fr) 110px 14px';
  var all = D.identities.map(function (u, i) { return [u, i]; }).filter(function (p) { return (S.filter === 'All' || p[0].level === S.filter) && (!q || (p[0].id + p[0].name).toLowerCase().indexOf(q) >= 0); });
  var shown = (S.allIds || q ? all : all.slice(0, 25));
  return shown.map(function (p) { var u = p[0]; return '<div class="row click" style="padding:13px 20px;' + g + '" data-act="open" data-k="id" data-i="' + p[1] + '"><span class="mono ' + lc(u.level) + '" style="font-weight:600;font-size:11px">\u25a0 ' + u.level + '</span><span><div style="font-size:14px;font-weight:500;overflow:hidden;text-overflow:ellipsis" title="' + esc(u.name) + '">' + esc(u.name) + '</div><div class="mono muted" style="font-size:12px;overflow:hidden;text-overflow:ellipsis">' + esc(u.id) + '</div></span><span style="display:flex;gap:6px;flex-wrap:wrap;overflow:visible;white-space:normal">' + chipsFor(u).map(function (c) { return '<span class="chip">' + esc(c) + '</span>'; }).join('') + '</span><span style="display:flex;align-items:center;gap:8px;overflow:visible"><span style="flex:1;height:5px;background:var(--line);border-radius:9px;overflow:hidden"><span class="' + lc(u.level) + '" style="display:block;height:100%;width:' + Math.min(100, u.score / 60 * 100) + '%;background:currentColor"></span></span><span class="mono" style="font-size:13px;width:28px;text-align:right">' + u.score + '</span></span><span class="muted">\u203a</span></div>'; }).join('') +
    (!q && all.length > 25 ? '<button class="more" data-act="ids">' + (S.allIds ? 'Show fewer' : 'Show all identities') + '</button>' : '') + (all.length ? '' : '<div class="muted" style="padding:30px 20px;text-align:center">No identities match.</div>');
}
function renderIdentities() {
  var cnt = by(D.identities, function (x) { return x.level; });
  var f = [['All', D.identities.length]].concat(['Critical', 'High', 'Medium', 'Low'].filter(function (k) { return cnt[k]; }).map(function (k) { return [k, cnt[k]]; }));
  $('#identities').innerHTML = '<div style="display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:14px"><div><h2 style="font-size:22px;font-weight:600">Identities</h2><div class="muted" style="margin-top:4px">All ' + D.identities.length + ' sorted by score. Select a row for every related record.</div></div><div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center" class="noprint"><button class="btn" data-act="export">Export CSV</button><input type="search" id="q" placeholder="Search name or UPN" value="' + esc(S.q) + '"><div class="seg" id="filters">' + f.map(function (x) { return '<button data-act="filter" data-a="' + x[0] + '" class="' + (S.filter === x[0] ? 'on' : '') + '">' + x[0] + ' \u00b7 ' + x[1] + '</button>'; }).join('') + '</div></div></div>' +
   '<div class="card" style="margin-top:14px;overflow:hidden"><div class="row head" style="grid-template-columns:78px minmax(0,1.4fr) minmax(0,1fr) 110px 14px"><span>Level</span><span>Identity</span><span>Findings</span><span>Score</span><span></span></div><div id="idrows">' + idRows() + '</div></div>';
  $('#q').addEventListener('input', function (e) { S.q = e.target.value; $('#idrows').innerHTML = idRows(); });
}

/* Detail drawer */
function label(k, i) { var o = arr(k)[i]; switch (k) { case 'audit': return o.Timestamp + ' \u00b7 ' + o.Activity; case 'app': return o.DisplayName; case 'fail': return o.CreationTime + ' \u00b7 ' + o.Status; case 'mfa': return o.DisplayName + ' \u00b7 ' + o.HasMFA + ' MFA'; case 'pw': return o.ChangeCount + ' changes \u00b7 ' + o.RiskLevel; case 'rule': return o.RuleName + ' \u00b7 ' + o.Mailbox; case 'deleg': return o.DelegateName + ' \u2192 ' + o.DisplayName; case 'pat': return o.PatternType + ' \u00b7 ' + o.SourceIP; case 'unus': return o.CreationTime + ' \u00b7 ' + o.IP; case 'etr': return o.RiskType + ' \u00b7 ' + o.MessageCount + ' msgs'; } return k; }
function rec(k, i) {
  var o = arr(k)[i]; if (!o) return null;
  var title, sub, level = o.RiskLevel || '', rel = [], f = [];
  var add = function (a, b) { if (b !== undefined && b !== null && b !== '') f.push([a, String(b)]); };
  if (k === 'id') {
    title = o.name; sub = o.id; level = o.level;
    add('Risk score', o.score); add('Failed sign-ins', o.f); add('High-risk operations', o.o); add('High-risk app registrations', o.a); add('Unusual sign-ins', o.unusual); add('Suspicious inbox rules', o.rules); add('Suspicious delegations', o.deleg); add('ETR spam activity', o.spam);
    var nm = { audit: 'Directory audit events', fails: 'Failed sign-ins', mfa: 'MFA status', pw: 'Password changes', apps: 'App registrations', rules: 'Inbox rules', deleg: 'Delegations', pat: 'Attack patterns', unus: 'Unusual sign-ins', etr: 'ETR spam activity' }, kk = { audit: 'audit', fails: 'fail', mfa: 'mfa', pw: 'pw', apps: 'app', rules: 'rule', deleg: 'deleg', pat: 'pat', unus: 'unus', etr: 'etr' };
    Object.keys(o.rel).forEach(function (g) { var ix = o.rel[g]; if (kk[g] && ix.length) rel.push({ t: nm[g] + ' (' + ix.length + ')', items: ix.slice(0, 12).map(function (j) { return [label(kk[g], j), kk[g], j]; }), extra: ix.length > 12 ? '+' + (ix.length - 12) + ' more in the Evidence section' : '' }); });
  } else {
    title = { audit: o.Activity, app: o.DisplayName, fail: o.Status, mfa: o.DisplayName, pw: o.User, ca: o.DisplayName, rule: o.RuleName, deleg: (o.DelegateName || '') + ' \u2192 ' + (o.DisplayName || ''), trace: o.subject, loc: (o.City || '') + ', ' + (o.Country || ''), pat: o.PatternType, unus: (o.City || '') + ', ' + (o.Country || ''), etr: o.RiskType }[k];
    sub = { audit: (o.UserDisplayName || o.UserId) + ' \u00b7 ' + o.Timestamp, app: (o.Source || '') + ' \u00b7 created ' + (o.CreatedDateTime || ''), fail: (o.UserId || 'unknown user') + ' \u00b7 ' + o.CreationTime, mfa: o.UserPrincipalName, pw: o.FirstChange + ' \u2192 ' + o.LastChange, ca: o.State, rule: o.PrimarySmtpAddress, deleg: o.PrimarySmtpAddress, trace: o.sender_address + ' \u2192 ' + o.recipient_address, loc: o.IP, pat: (o.UserId || 'unknown user') + ' \u00b7 ' + o.SourceIP, unus: (o.UserId || 'unknown user') + ' \u00b7 ' + o.CreationTime, etr: o.SenderAddress }[k];
    if (k === 'audit') add('Targets', (o.targets || []).join('\n'));
    if (k === 'ca') Object.keys(o.summary || {}).forEach(function (s) { add('Policy \u00b7 ' + s, o.summary[s]); });
    Object.keys(o).forEach(function (a) { if (a === 'targets' || a === 'summary') return; var v = o[a]; if (/^[\[{]/.test(v)) { try { v = JSON.stringify(JSON.parse(v), null, 2); } catch (e) {} } else if (/^(RequestedPermissions|GrantedDelegated|GrantedApplication)$/.test(a)) v = v.split('; ').join('\n'); add(hk(a), v); });
    var keys = [o.UserId, o.UserPrincipalName, o.User, o.DelegateEmail, o.PrimarySmtpAddress, o.SenderAddress].filter(Boolean).map(function (s) { return s.toLowerCase(); });
    var own = []; D.identities.forEach(function (x, n) { if (keys.indexOf(x.id.toLowerCase()) >= 0 || (k === 'app' && x.id === '[App] ' + o.DisplayName)) own.push([x.name + ' \u00b7 ' + x.level + ' ' + x.score, 'id', n]); });
    if (own.length) rel.push({ t: 'Identity', items: own, extra: '' });
  }
  return { kind: KINDS[k], title: title, sub: sub, level: level, rel: rel, f: f };
}
function renderDrawer() {
  var host = $('#drawer-host'), top = S.stack[S.stack.length - 1], r = top && rec(top.k, top.i);
  if (!r) { host.innerHTML = ''; return; }
  host.innerHTML = '<div id="drawer-bg" data-act="close"></div><aside id="drawer" role="dialog" aria-label="' + esc(r.kind) + '"><div style="position:sticky;top:0;background:var(--surface);border-bottom:1px solid var(--line);padding:16px 24px;display:flex;justify-content:space-between;align-items:center;gap:12px"><span class="kick" style="white-space:nowrap;letter-spacing:.12em">' + esc(r.kind) + '</span><span style="display:flex;gap:8px;flex:none">' + (S.stack.length > 1 ? '<button class="btn" data-act="back">\u2190 Back</button>' : '') + '<button class="btn" data-act="close">Close \u2715</button></span></div><div style="padding:22px 24px 40px"><h3 style="font-size:22px;font-weight:600;line-height:1.25;text-wrap:pretty;overflow-wrap:anywhere">' + esc(r.title) + '</h3><div class="mono muted" style="margin-top:6px;font-size:12.5px;overflow-wrap:anywhere">' + esc(r.sub) + '</div>' +
   (r.level ? '<div class="pill ' + lc(r.level) + '" style="margin-top:12px;display:inline-block;font-size:12px;padding:3px 12px">\u25a0 ' + esc(r.level) + '</div>' : '') +
   r.rel.map(function (g) { return '<div style="margin-top:24px"><div class="lbl" style="margin-bottom:8px">' + esc(g.t) + '</div>' + g.items.map(function (it) { return '<button class="rel" data-act="push" data-k="' + it[1] + '" data-i="' + it[2] + '"><span>' + esc(it[0]) + '</span><span class="muted">\u203a</span></button>'; }).join('') + (g.extra ? '<div class="muted" style="font-size:12px;padding:2px 4px">' + esc(g.extra) + '</div>' : '') + '</div>'; }).join('') +
   '<div class="lbl" style="margin:24px 0 6px">Record</div>' + r.f.map(function (p) { var v = p[1], long = v.length > 110 || v.indexOf('\n') >= 0, nl = v.split('\n').length; return '<div style="padding:9px 0;border-top:1px solid var(--line)"><div class="mono muted" style="font-size:11px;margin-bottom:3px">' + esc(p[0]) + '</div>' + (long ? '<details><summary style="cursor:pointer;color:var(--accent)">' + (nl > 1 ? nl + ' lines \u00b7 show' : 'Show full value') + '</summary><pre>' + esc(v) + '</pre></details>' : '<div style="overflow-wrap:anywhere">' + esc(v) + '</div>') + '</div>'; }).join('') + '</div></aside>';
}

/* Identity summary as CSV (leading = + - @ are neutralised so spreadsheets do not run them as formulas). */
function exportCsv() {
  var q = function (v) { var s = String(v == null ? '' : v); if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  var cols = [['id', 'Identity'], ['name', 'Name'], ['level', 'Risk level'], ['score', 'Risk score'], ['f', 'Failed sign-ins'], ['o', 'High-risk operations'], ['a', 'High-risk app registrations'], ['unusual', 'Unusual sign-ins'], ['rules', 'Suspicious inbox rules'], ['deleg', 'Suspicious delegations'], ['spam', 'ETR spam activity']];
  var lines = [cols.map(function (c) { return q(c[1]); }).join(',')].concat(D.identities.map(function (u) { return cols.map(function (c) { return q(u[c[0]]); }).join(','); }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv' }));
  a.download = 'M365_Security_Summary_' + new Date().toISOString().slice(0, 10) + '.csv';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
}

/* Events */
document.addEventListener('click', function (e) {
  var t = e.target.closest('[data-act]'); if (!t) return;
  var a = t.dataset.act, v = t.dataset.a;
  if (a === 'theme') { S.dark = !S.dark; document.body.setAttribute('data-theme', S.dark ? 'dark' : 'light'); t.textContent = S.dark ? 'Light mode' : 'Dark mode'; return; }
  if (a === 'sec') { S.open[v] = !S.open[v]; renderEvidence(); }
  else if (a === 'all') { S.showAll[v] = !S.showAll[v]; renderEvidence(); }
  else if (a === 'allsecs') { var on = !LIVE().every(function (d) { return S.open[d.key]; }); LIVE().forEach(function (d) { S.open[d.key] = on; }); renderEvidence(); }
  else if (a === 'filter') { S.filter = v; renderIdentities(); }
  else if (a === 'ids') { S.allIds = !S.allIds; $('#idrows').innerHTML = idRows(); }
  else if (a === 'open') { S.stack = [{ k: t.dataset.k, i: +t.dataset.i }]; renderDrawer(); }
  else if (a === 'push') { S.stack.push({ k: t.dataset.k, i: +t.dataset.i }); renderDrawer(); }
  else if (a === 'back') { S.stack.pop(); renderDrawer(); }
  else if (a === 'close') { S.stack = []; renderDrawer(); }
  else if (a === 'export') { exportCsv(); }
});
document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && S.stack.length) { S.stack = []; renderDrawer(); } });
/* Printing expands everything so nothing is hidden on paper. */
var saved;
window.addEventListener('beforeprint', function () { saved = [Object.assign({}, S.open), Object.assign({}, S.showAll), S.allIds]; DEFS.forEach(function (d) { S.open[d.key] = true; S.showAll[d.key] = true; }); S.allIds = true; renderEvidence(); $('#idrows').innerHTML = idRows(); });
window.addEventListener('afterprint', function () { if (saved) { S.open = saved[0]; S.showAll = saved[1]; S.allIds = saved[2]; renderEvidence(); $('#idrows').innerHTML = idRows(); } });
renderTop();
})();
</script>
</body>
</html>
'@

function ConvertTo-ReportRecord {
    <#
    .SYNOPSIS
        Flattens one CSV row or result object into an ordered string map for the report payload.

    .DESCRIPTION
        Values are kept as strings exactly as they appear in the CSV ("True", "52", timestamps as
        text) because the report template compares against those literals. Empty values are
        omitted (the template treats a missing field as empty), which keeps the file small.
    #>
    param (
        [Parameter(Mandatory = $true)]
        $Row,

        [string[]]$Exclude = @()
    )

    $record = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        if ($Exclude -contains $property.Name) { continue }
        if ($null -eq $property.Value -or $property.Value -is [System.DBNull]) { continue }
        $text = [string]$property.Value
        if ($text.Length -eq 0) { continue }
        $record[$property.Name] = $text
    }
    return $record
}

function Import-ReportCsv {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $path = Join-Path -Path $ConfigData.WorkDir -ChildPath $FileName
    if (-not (Test-Path -Path $path)) { return @() }
    try {
        return @(Import-Csv -Path $path -ErrorAction Stop)
    }
    catch {
        Write-Log "Report: could not read ${FileName}: $($_.Exception.Message)" -Level "Warning"
        return @()
    }
}

function Sort-ReportByRisk {
    <#
    .SYNOPSIS
        Stable sort of report records by RiskLevel (Critical, High, Medium, Low, anything else).
    #>
    param (
        [object[]]$Items = @(),
        [string]$Property = "RiskLevel"
    )

    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $position = 0
    $decorated = foreach ($item in $Items) {
        $level = "$($item[$Property])"
        [PSCustomObject]@{
            Rank  = $(if ($rank.ContainsKey($level)) { $rank[$level] } else { 9 })
            Index = $position
            Item  = $item
        }
        $position++
    }
    return @($decorated | Sort-Object -Property Rank, Index | ForEach-Object { $_.Item })
}

function Add-ReportIndex {
    param (
        [Parameter(Mandatory = $true)] [hashtable]$Index,
        [string]$Key,
        [Parameter(Mandatory = $true)] [int]$Position
    )

    if ([string]::IsNullOrWhiteSpace($Key)) { return }
    $lookup = $Key.Trim().ToLowerInvariant()
    if (-not $Index.ContainsKey($lookup)) {
        $Index[$lookup] = [System.Collections.Generic.List[int]]::new()
    }
    $list = $Index[$lookup]
    # Positions are added in ascending order, so a repeat can only be the last element
    if ($list.Count -eq 0 -or $list[$list.Count - 1] -ne $Position) { $list.Add($Position) }
}

function Get-ReportRel {
    param (
        [Parameter(Mandatory = $true)] [hashtable]$Index,
        [string[]]$Keys = @()
    )

    $found = [System.Collections.Generic.SortedSet[int]]::new()
    foreach ($key in $Keys) {
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $lookup = $key.Trim().ToLowerInvariant()
        if ($Index.ContainsKey($lookup)) {
            foreach ($position in $Index[$lookup]) { [void]$found.Add($position) }
        }
    }
    # Unary comma keeps a 0/1-element array from collapsing (PowerShell 5.1 ConvertTo-Json)
    return , ([int[]]@($found))
}

function ConvertTo-ReportCaSummary {
    <#
    .SYNOPSIS
        Reduces a Conditional Access policy row to the counts the report shows.
    #>
    param (
        [Parameter(Mandatory = $true)]
        $Row
    )

    $parse = {
        param($Json)
        if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
        try { return ($Json | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
    }
    $conditions = & $parse $Row.Conditions
    $grant = & $parse $Row.GrantControls

    $clean = { param($List) @($List | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" }) }

    $apps = @(& $clean $conditions.Applications.IncludeApplications)
    $appText = if ($apps.Count -eq 0) { "None" } elseif ($apps.Count -eq 1) { $apps[0] } else { "$($apps.Count) apps" }

    $incUsers = @(& $clean $conditions.Users.IncludeUsers)
    $incGroups = @(& $clean $conditions.Users.IncludeGroups)
    $realUsers = @($incUsers | Where-Object { $_ -notin @("None", "All", "GuestsOrExternalUsers") })
    $userText = if ($incUsers -contains "All") { "All" }
                elseif ($realUsers.Count -gt 0 -and $incGroups.Count -gt 0) { "$($realUsers.Count) user(s), $($incGroups.Count) group(s)" }
                elseif ($realUsers.Count -gt 0) { "$($realUsers.Count) user(s)" }
                else { "$($incGroups.Count) group(s)" }

    return [ordered]@{
        apps       = $appText
        incUsers   = $userText
        incRoles   = @(& $clean $conditions.Users.IncludeRoles).Count
        exUsers    = @(& $clean $conditions.Users.ExcludeUsers).Count
        exGroups   = @(& $clean $conditions.Users.ExcludeGroups).Count
        grant      = (@(& $clean $grant.BuiltInControls) -join ", ")
        signInRisk = (@(& $clean $conditions.SignInRiskLevels) -join ", ")
    }
}

function New-ReportPayload {
    <#
    .SYNOPSIS
        Builds the data object the HTML report template renders (see $script:ReportTemplate).

    .DESCRIPTION
        The generator emits no markup: every dataset is shaped here, serialized to JSON by
        Generate-HTMLReport and rendered client-side. Identities link to their evidence by array
        index (identities[].rel), so datasets must be final and sorted before the links are built.

    .PARAMETER Results
        Risk results from Invoke-CompromiseDetection (same objects that feed SecurityReport.csv).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Results
    )

    $rowCap = 1500
    $notes = [System.Collections.Generic.List[object]]::new()
    foreach ($note in @($script:ReportCoverageNotes)) {
        if ($null -eq $note) { continue }
        $notes.Add([ordered]@{ level = [string]$note.Level; source = [string]$note.Source; message = [string]$note.Message })
    }
    $limitRows = {
        param($Rows, $Label, $File)
        if ($Rows.Count -gt $rowCap) {
            $notes.Add([ordered]@{ level = "Note"; source = $Label; message = "Showing the first $rowCap of $($Rows.Count) rows to keep this report a reasonable size. The complete data is in $File." })
            return @($Rows | Select-Object -First $rowCap)
        }
        return @($Rows)
    }

    # ---- Evidence datasets ------------------------------------------------------------------
    $audit = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @(Import-ReportCsv "AdminAuditLogs_HighRisk.csv")) {
        $record = ConvertTo-ReportRecord -Row $row -Exclude @("ActivityDate", "LOGIN")
        $targets = [System.Collections.Generic.List[string]]::new()
        if ($record.Contains("TargetResources")) {
            try {
                foreach ($target in @($record["TargetResources"] | ConvertFrom-Json -ErrorAction Stop)) {
                    foreach ($candidate in @($target.UserPrincipalName, $target.DisplayName, $target.Id)) {
                        if (-not [string]::IsNullOrWhiteSpace($candidate)) { $targets.Add([string]$candidate); break }
                    }
                }
            }
            catch { }
        }
        if ($targets.Count -gt 0) { $record["targets"] = @($targets) }
        $audit.Add($record)
    }
    $audit = @(Sort-ReportByRisk -Items $audit.ToArray())

    $apps = @(Import-ReportCsv "AppRegistrations_HighRisk.csv" | ForEach-Object {
        $record = ConvertTo-ReportRecord -Row $_ -Exclude @("RequiredResourceAccess")
        if ($record.Contains("DisplayName")) { $record["DisplayName"] = $record["DisplayName"].Trim() }
        $record
    })

    $fails = @(Import-ReportCsv "UserLocationData_Failed.csv" | ForEach-Object {
        ConvertTo-ReportRecord -Row $_ -Exclude @("IPVersion", "IsPrivateIP", "GeoLookupFailed", "IsHighRiskISP")
    })
    $fails = @(& $limitRows $fails "FailedSignIns" "UserLocationData_Failed.csv")

    $pw = @(Import-ReportCsv "PasswordChangeAnalysis.csv" | ForEach-Object { ConvertTo-ReportRecord -Row $_ })

    $mfa = @(Import-ReportCsv "MFAStatus.csv" | ForEach-Object { ConvertTo-ReportRecord -Row $_ })
    $mfa = @(Sort-ReportByRisk -Items $mfa)

    $ca = @(Import-ReportCsv "ConditionalAccess.csv" | ForEach-Object {
        $record = ConvertTo-ReportRecord -Row $_ -Exclude @("Conditions", "GrantControls", "SessionControls")
        $record["summary"] = ConvertTo-ReportCaSummary -Row $_
        $record
    })

    $rules = @(Import-ReportCsv "InboxRules.csv" | ForEach-Object { ConvertTo-ReportRecord -Row $_ })
    $deleg = @(Import-ReportCsv "MailboxDelegation.csv" | ForEach-Object { ConvertTo-ReportRecord -Row $_ })

    $trace = @(Import-ReportCsv "MessageTraceResult.csv" | ForEach-Object {
        ConvertTo-ReportRecord -Row $_ -Exclude @("message_trace_id", "message_id", "date", "timestamp", "event_type")
    })
    $trace = @(& $limitRows $trace "MessageTrace" "MessageTraceResult.csv")

    $locs = @(Import-ReportCsv "UniqueSignInLocations.csv" | ForEach-Object { ConvertTo-ReportRecord -Row $_ })
    $locs = @(& $limitRows $locs "SignInLocations" "UniqueSignInLocations.csv")

    # Unusual-country and high-risk-ISP sign-ins (successes and failures)
    $unus = @(Import-ReportCsv "UserLocationData.csv" |
        Where-Object { "$($_.IsUnusualLocation)" -eq "True" -or "$($_.IsHighRiskISP)" -eq "True" } |
        ForEach-Object { ConvertTo-ReportRecord -Row $_ -Exclude @("IPVersion", "IsPrivateIP", "GeoLookupFailed") })
    $unus = @(& $limitRows $unus "UnusualSignIns" "UserLocationData.csv")

    # Brute-force / spray patterns and ETR spam come from the analysis results themselves
    $patRows = [System.Collections.Generic.List[object]]::new()
    $etr = [System.Collections.Generic.List[object]]::new()
    $accountsUnderAttack = 0
    foreach ($result in $Results) {
        $patterns = @($result.FailedLoginPatterns | Where-Object { $null -ne $_ })
        if ($patterns.Count -gt 0) { $accountsUnderAttack++ }
        foreach ($pattern in $patterns) {
            $record = ConvertTo-ReportRecord -Row $pattern
            $record["UserId"] = [string]$result.UserId
            $patRows.Add($record)
        }
        foreach ($spam in @($result.ETRSpamActivity | Where-Object { $null -ne $_ })) {
            $etr.Add((ConvertTo-ReportRecord -Row $spam))
        }
    }
    $riskRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $patPosition = 0
    $pat = @($patRows | ForEach-Object {
        [PSCustomObject]@{
            Rank     = $(if ($riskRank.ContainsKey("$($_['RiskLevel'])")) { $riskRank["$($_['RiskLevel'])"] } else { 9 })
            Attempts = $(if ($_['FailedAttempts'] -as [int]) { [int]$_['FailedAttempts'] } else { 0 })
            Index    = ($patPosition++)
            Item     = $_
        }
    } | Sort-Object -Property Rank, @{ Expression = "Attempts"; Descending = $true }, Index | ForEach-Object { $_.Item })
    $etr = @(Sort-ReportByRisk -Items $etr.ToArray())

    # ---- Identities ---------------------------------------------------------------------------
    $toInt = { param($Value) if ($Value -as [int]) { [int]$Value } else { 0 } }
    $resultPosition = 0
    $sortedResults = @($Results | ForEach-Object {
        [PSCustomObject]@{ Score = (& $toInt $_.RiskScore); Index = ($resultPosition++); Item = $_ }
    } | Sort-Object -Property @{ Expression = "Score"; Descending = $true }, Index | ForEach-Object { $_.Item })

    # ---- Evidence indexes (case-insensitive, O(n)) --------------------------------------------
    $idxAudit = @{}; $idxFails = @{}; $idxMfa = @{}; $idxPw = @{}; $idxApps = @{}
    $idxRules = @{}; $idxDeleg = @{}; $idxPat = @{}; $idxUnus = @{}; $idxEtr = @{}
    for ($i = 0; $i -lt $audit.Count; $i++) {
        Add-ReportIndex $idxAudit ($audit[$i]["UserId"]) $i
        foreach ($target in @($audit[$i]["targets"])) { Add-ReportIndex $idxAudit $target $i }
    }
    for ($i = 0; $i -lt $fails.Count; $i++) { Add-ReportIndex $idxFails ($fails[$i]["UserId"]) $i }
    for ($i = 0; $i -lt $mfa.Count; $i++) { Add-ReportIndex $idxMfa ($mfa[$i]["UserPrincipalName"]) $i }
    for ($i = 0; $i -lt $pw.Count; $i++) { Add-ReportIndex $idxPw ($pw[$i]["User"]) $i }
    for ($i = 0; $i -lt $apps.Count; $i++) {
        $appName = "$($apps[$i]['DisplayName'])"
        Add-ReportIndex $idxApps ("[App] " + $appName) $i
    }
    for ($i = 0; $i -lt $rules.Count; $i++) {
        Add-ReportIndex $idxRules ($rules[$i]["PrimarySmtpAddress"]) $i
        Add-ReportIndex $idxRules ($rules[$i]["Mailbox"]) $i
    }
    for ($i = 0; $i -lt $deleg.Count; $i++) {
        Add-ReportIndex $idxDeleg ($deleg[$i]["DelegateEmail"]) $i
        Add-ReportIndex $idxDeleg ($deleg[$i]["PrimarySmtpAddress"]) $i
    }
    for ($i = 0; $i -lt $pat.Count; $i++) { Add-ReportIndex $idxPat ($pat[$i]["UserId"]) $i }
    for ($i = 0; $i -lt $unus.Count; $i++) { Add-ReportIndex $idxUnus ($unus[$i]["UserId"]) $i }
    for ($i = 0; $i -lt $etr.Count; $i++) { Add-ReportIndex $idxEtr ($etr[$i]["SenderAddress"]) $i }
    $allApps = [int[]]@(0..($apps.Count - 1) | Where-Object { $apps.Count -gt 0 })

    $identities = foreach ($result in $sortedResults) {
        $id = [string]$result.UserId
        $appLinks = if ($id -eq "SYSTEM_WIDE_APPS") { , $allApps } else { Get-ReportRel $idxApps @($id) }
        [ordered]@{
            id      = $id
            name    = [string]$result.UserDisplayName
            score   = & $toInt $result.RiskScore
            level   = [string]$result.RiskLevel
            f       = & $toInt $result.FailedSignInCount
            o       = & $toInt $result.HighRiskOperationsCount
            a       = & $toInt $result.HighRiskAppRegistrationsCount
            unusual = & $toInt $result.UnusualSignInCount
            rules   = & $toInt $result.SuspiciousRulesCount
            deleg   = & $toInt $result.SuspiciousDelegationsCount
            spam    = & $toInt $result.ETRSpamActivityCount
            rel     = [ordered]@{
                audit = Get-ReportRel $idxAudit @($id)
                fails = Get-ReportRel $idxFails @($id)
                mfa   = Get-ReportRel $idxMfa @($id)
                pw    = Get-ReportRel $idxPw @($id)
                apps  = $appLinks
                rules = Get-ReportRel $idxRules @($id)
                deleg = Get-ReportRel $idxDeleg @($id)
                pat   = Get-ReportRel $idxPat @($id)
                unus  = Get-ReportRel $idxUnus @($id)
                etr   = Get-ReportRel $idxEtr @($id)
            }
        }
    }

    $coverage = @(Get-CollectionStatus | ForEach-Object { ConvertTo-ReportRecord -Row $_ })

    return [ordered]@{
        meta       = [ordered]@{
            tenant      = [string]$Global:ConnectionState.TenantName
            generated   = (Get-Date).ToString("MMMM d, yyyy 'at' HH:mm", [System.Globalization.CultureInfo]::InvariantCulture)
            days        = [int]$ConfigData.DateRange
            toolVersion = [string]$ScriptVer
            toolName    = "M365 Security Analysis"
            brand       = "Yeyland Wutani"
            darkMode    = ($script:CurrentTheme -eq "Dark")
            threats     = [ordered]@{
                accountsUnderAttack = $accountsUnderAttack
                failedSignIns       = $fails.Count
                highRiskApps        = $apps.Count
            }
        }
        notes      = @($notes)
        cov        = @($coverage)
        identities = @($identities)
        audit      = @($audit)
        apps       = @($apps)
        fails      = @($fails)
        pw         = @($pw)
        mfa        = @($mfa)
        ca         = @($ca)
        rules      = @($rules)
        deleg      = @($deleg)
        trace      = @($trace)
        locs       = @($locs)
        pat        = @($pat)
        unus       = @($unus)
        etr        = @($etr)
    }
}

function Generate-HTMLReport {
    <#
    .SYNOPSIS
        Builds the HTML security report: shapes the data (New-ReportPayload) and injects it as JSON
        into the embedded template. All layout and behavior live in the template.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Data
    )

    $payload = New-ReportPayload -Results $Data
    $json = ConvertTo-Json -InputObject $payload -Depth 8 -Compress

    # The JSON sits inside a <script> element: no '</script>' or '<!--' and no JS line separators
    # may survive. The escaped form decodes back to the same text in JSON.parse.
    $json = $json.Replace('<', '\u003c').Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')

    # .Replace, not -replace: the JSON must never be interpreted for '$' expansion
    return $script:ReportTemplate.Replace('__REPORT_DATA_JSON__', $json)
}

#endregion

#endregion

#################################################################
#
#  SECTION 4.5: HATZ AI ANALYSIS INTEGRATION
#
#################################################################

function Get-HatzApiKeyForM365 {
    <#
    .SYNOPSIS
        Retrieves the Hatz AI API key from the shared DPAPI credential store,
        environment variable, or interactively prompts the user.
        Uses the same credential file as Invoke-HatzChat.ps1.
    #>
    $credFile = Join-Path $env:APPDATA 'HatzChat\api_key.clixml'

    # Priority 1: DPAPI-encrypted credential file (shared with Invoke-HatzChat.ps1)
    if (Test-Path $credFile) {
        try {
            $secureKey = Import-Clixml -Path $credFile
            $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            if (-not [string]::IsNullOrWhiteSpace($plain)) {
                Write-Log "Hatz AI: API key loaded from encrypted credential store" -Level "Info"
                return $plain
            }
        }
        catch {
            Write-Log "Hatz AI: Failed to read credential file — will prompt" -Level "Warning"
        }
    }

    # Priority 2: Environment variable (User scope, then session)
    $envKey = [Environment]::GetEnvironmentVariable('HATZ_AI_API_KEY', 'User')
    if ([string]::IsNullOrWhiteSpace($envKey)) {
        $envKey = [System.Environment]::GetEnvironmentVariable('HATZ_AI_API_KEY')
    }
    if (-not [string]::IsNullOrWhiteSpace($envKey)) {
        Write-Log "Hatz AI: API key loaded from environment variable" -Level "Info"
        return $envKey
    }

    # Priority 3: Prompt via dialog
    $promptForm = New-Object System.Windows.Forms.Form
    $promptForm.Text          = "Hatz AI API Key Required"
    $promptForm.Size          = New-Object System.Drawing.Size(520, 210)
    $promptForm.StartPosition = "CenterParent"
    $promptForm.FormBorderStyle = "FixedDialog"
    $promptForm.MaximizeBox   = $false
    $promptForm.MinimizeBox   = $false
    $promptForm.BackColor     = Get-ThemeColor -ColorName "Background"

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "No Hatz AI API key found.`nEnter your key to enable AI analysis (saved securely for future sessions):"
    $lbl.Size = New-Object System.Drawing.Size(480, 42)
    $lbl.Location = New-Object System.Drawing.Point(15, 12)
    $lbl.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $promptForm.Controls.Add($lbl)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Size = New-Object System.Drawing.Size(480, 25)
    $txt.Location = New-Object System.Drawing.Point(15, 60)
    $txt.PasswordChar = '*'
    $txt.Font = New-Object System.Drawing.Font("Consolas", 10)
    $txt.BackColor = Get-ThemeColor -ColorName "Surface"
    $txt.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $promptForm.Controls.Add($txt)

    $saveCheck = New-Object System.Windows.Forms.CheckBox
    $saveCheck.Text = "Save key securely (DPAPI-encrypted, per user/machine)"
    $saveCheck.Location = New-Object System.Drawing.Point(15, 93)
    $saveCheck.Size = New-Object System.Drawing.Size(420, 22)
    $saveCheck.Checked = $true
    $saveCheck.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $saveCheck.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $promptForm.Controls.Add($saveCheck)

    $okBtn = New-Object System.Windows.Forms.Button
    $okBtn.Text = "OK"
    $okBtn.DialogResult = "OK"
    $okBtn.Size = New-Object System.Drawing.Size(80, 30)
    $okBtn.Location = New-Object System.Drawing.Point(310, 128)
    $okBtn.BackColor = Get-ThemeColor -ColorName "Primary"
    $okBtn.ForeColor = [System.Drawing.Color]::White
    $okBtn.FlatStyle = "Flat"
    $okBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $promptForm.AcceptButton = $okBtn
    $promptForm.Controls.Add($okBtn)

    $cancelBtn = New-Object System.Windows.Forms.Button
    $cancelBtn.Text = "Cancel"
    $cancelBtn.DialogResult = "Cancel"
    $cancelBtn.Size = New-Object System.Drawing.Size(80, 30)
    $cancelBtn.Location = New-Object System.Drawing.Point(400, 128)
    $cancelBtn.BackColor = Get-ThemeColor -ColorName "Secondary"
    $cancelBtn.ForeColor = [System.Drawing.Color]::White
    $cancelBtn.FlatStyle = "Flat"
    $cancelBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $promptForm.CancelButton = $cancelBtn
    $promptForm.Controls.Add($cancelBtn)

    $dlgResult = $promptForm.ShowDialog()
    if ($dlgResult -ne "OK" -or [string]::IsNullOrWhiteSpace($txt.Text)) {
        return $null
    }

    $apiKey = $txt.Text.Trim()

    if ($saveCheck.Checked) {
        try {
            $credDir = Split-Path $credFile
            if (-not (Test-Path $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
            (ConvertTo-SecureString $apiKey -AsPlainText -Force) | Export-Clixml -Path $credFile
            Write-Log "Hatz AI: API key saved to DPAPI-encrypted credential store" -Level "Info"
        }
        catch {
            Write-Log "Hatz AI: Failed to save API key: $($_.Exception.Message)" -Level "Warning"
        }
    }

    return $apiKey
}

function Invoke-HatzSecurityAnalysis {
    <#
    .SYNOPSIS
        Loads CSV exports from WorkDir and sends them to the Hatz AI API
        requesting identification of critical security findings.
    #>
    param(
        [string]$ApiKey,
        [string]$WorkDir
    )

    $apiBaseUrl      = 'https://ai.hatz.ai/v1'
    $model           = 'anthropic.claude-opus-4-6'
    $maxCharsPerFile = 8000
    $maxTotalChars   = 60000

    # Load CSV files from working directory
    $csvFiles = Get-ChildItem -Path $WorkDir -Filter "*.csv" -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 0 } |
        Sort-Object LastWriteTime -Descending

    if ($csvFiles.Count -eq 0) {
        return $null, "No CSV files found in: $WorkDir`nPlease collect data first."
    }

    Write-Log "Hatz AI: Loading $($csvFiles.Count) CSV files from $WorkDir" -Level "Info"
    $sb = [System.Text.StringBuilder]::new()

    foreach ($file in $csvFiles) {
        if ($sb.Length -ge $maxTotalChars) {
            [void]$sb.Append("`n[Additional files omitted — token limit reached]`n")
            break
        }
        [void]$sb.Append("`n### $($file.Name)`n")
        try {
            $lines   = Get-Content -Path $file.FullName -TotalCount 300 -ErrorAction Stop
            $content = $lines -join "`n"
            if ($content.Length -gt $maxCharsPerFile) {
                $content = $content.Substring(0, $maxCharsPerFile) +
                           "`n[...truncated — $([math]::Round($file.Length/1KB))KB total]"
            }
            [void]$sb.Append($content)
        }
        catch {
            [void]$sb.Append("[Error reading file: $($_.Exception.Message)]")
        }
        [void]$sb.Append("`n")
    }

    $dataContent  = $sb.ToString()
    $systemPrompt = @"
You are a Microsoft 365 security expert performing a security audit. Analyze the provided CSV exports and identify all critical security findings.

=== DATA SCHEMA — READ CAREFULLY BEFORE ANALYSIS ===

FILE: UserLocationData.csv — SUCCESSFUL sign-ins only (StatusCode=0, Status="Success").
FILE: UserLocationData_Failed.csv — Non-success sign-in events. IMPORTANT: most are benign interrupts, NOT credential attacks. Do NOT count these as failed login attempts unless StatusCode is specifically 50126 or 50053.
FILE: UniqueSignInLocations.csv — Aggregated sign-in counts per user+IP across ALL events (successes + non-successes). A high SignInCount from an IP does NOT indicate brute force — it may simply mean the user signs in frequently from that IP (e.g. their office). Do NOT flag high counts as attacks without corroborating 50126/50053 errors.

=== ENTRA SIGN-IN STATUS CODES ===
CREDENTIAL ATTACKS (actual failed credential attempts — flag these):
  50126 = Invalid username or password — credential failure, key brute-force indicator
  50053 = Account locked out — smart lockout triggered by repeated failures
  50055 = Password expired — not an attack, password maintenance needed
  50056 = Weak or null password — account config issue

NORMAL / BENIGN INTERRUPTS (do NOT count as failures or attacks):
  0     = Success
  50140 = Sign-in interrupt / session kept alive — normal browser token refresh, NOT a failure
  50058 = Silent sign-in interrupted — user needs to re-authenticate interactively, normal
  50072 = MFA enrollment required — authentication challenge, normal
  50074 = MFA required (policy) — normal CA enforcement
  65001 = Consent required — normal OAuth permission prompt, NOT an attack
  500011 = Resource principal not found — misconfiguration or app issue, NOT a credential attack
  16003 = Unknown error — transient, not credential-based
  50207 = Unknown error — transient

=== BRUTE-FORCE DETECTION RULES ===
Only flag an IP as conducting a brute-force/password-spray attack if:
  - It has 5+ StatusCode 50126 (invalid password) events against the same account, OR
  - It has 50053 (lockout) events, OR
  - It has a pattern of 50126 across multiple accounts (password spray)
A large SignInCount in UniqueSignInLocations.csv means nothing on its own — verify against _Failed.csv for actual 50126/50053 codes before declaring an attack.

=== OUTPUT FORMAT ===
Structure your response as:
## CRITICAL FINDINGS SUMMARY

For each finding:
**[SEVERITY] Finding Title**
- Affected: <users or objects>
- Detail: <what was found and why it is significant>
- Action: <specific remediation step>

Severity: CRITICAL / HIGH / MEDIUM
Focus areas (priority order):
1. Users without MFA or with only per-user MFA (no Conditional Access coverage)
2. Credential attacks — ONLY based on 50126/50053 codes, not total sign-in volume
3. Suspicious inbox rules (external forwarding, auto-deletion)
4. External or anonymous mailbox delegations
5. Suspicious app registrations or overprivileged OAuth apps
6. Conditional Access policy gaps
7. Unusual geographic patterns only where StatusCode=0 logins come from unexpected countries

Be concise and directly actionable. Skip categories where no issues are present.
"@

    $userMessage = "Analyze this Microsoft 365 security audit data and identify all critical findings:`n`n$dataContent"

    $bodyHash = @{
        model       = $model
        messages    = @(
            @{ role = "system"; content = $systemPrompt },
            @{ role = "user";   content = $userMessage  }
        )
        stream      = $false
        temperature = 0.3
    }

    $bodyJson  = $bodyHash | ConvertTo-Json -Depth 10 -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)

    Write-Log "Hatz AI: Sending $([math]::Round($bodyBytes.Length/1KB))KB request to API ($($csvFiles.Count) files)" -Level "Info"

    try {
        $req               = [System.Net.HttpWebRequest]::Create("$apiBaseUrl/chat/completions")
        $req.Method        = 'POST'
        $req.ContentType   = 'application/json; charset=utf-8'
        $req.ContentLength = $bodyBytes.Length
        $req.Timeout       = 180000   # 3-minute timeout for large analysis
        $req.Headers.Add('X-API-Key', $ApiKey)

        $reqStream = $req.GetRequestStream()
        $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
        $reqStream.Close()

        $resp     = $req.GetResponse()
        $reader   = [System.IO.StreamReader]::new($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $jsonText = $reader.ReadToEnd()
        $reader.Close()
        $resp.Close()

        $parsed       = $jsonText | ConvertFrom-Json
        $analysisText = $parsed.choices[0].message.content

        Write-Log "Hatz AI: Analysis complete — $($analysisText.Length) characters received" -Level "Info"
        return $analysisText, $null
    }
    catch [System.Net.WebException] {
        $statusCode = $null
        $errorBody  = ''
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            try {
                $errReader = [System.IO.StreamReader]::new(
                    $_.Exception.Response.GetResponseStream(),
                    [System.Text.Encoding]::UTF8)
                $errorBody = $errReader.ReadToEnd()
                $errReader.Close()
            } catch {}
        }
        $errMsg = if ($errorBody) { "HTTP $statusCode — $errorBody" } else { $_.Exception.Message }
        Write-Log "Hatz AI: API error — $errMsg" -Level "Error"
        return $null, $errMsg
    }
    catch {
        Write-Log "Hatz AI: Unexpected error — $($_.Exception.Message)" -Level "Error"
        return $null, $_.Exception.Message
    }
}

function Show-HatzAnalysisResult {
    <#
    .SYNOPSIS
        Displays AI analysis results in a resizable dialog with a save option.
    #>
    param(
        [string]$AnalysisText,
        [string]$WorkDir
    )

    $resultForm = New-Object System.Windows.Forms.Form
    $resultForm.Text          = "Hatz AI - M365 Security Analysis"
    $resultForm.ClientSize    = New-Object System.Drawing.Size(920, 720)
    $resultForm.StartPosition = "CenterScreen"
    $resultForm.FormBorderStyle = "Sizable"
    $resultForm.BackColor     = Get-ThemeColor -ColorName "Background"
    $resultForm.MinimumSize   = New-Object System.Drawing.Size(600, 400)
    $resultForm.Font          = Get-GuiFont -Family "Segoe UI" -Size 9

    $headerLbl = New-Object System.Windows.Forms.Label
    $headerLbl.Text     = "$($script:GlyphSparkle)  AI security analysis   |   Powered by Hatz AI (claude-opus-4-6)"
    $headerLbl.Font     = Get-GuiFont -Family "Segoe UI Semibold" -Size 10.5
    $headerLbl.ForeColor = Get-ThemeColor -ColorName "Primary"
    $headerLbl.Size     = New-Object System.Drawing.Size(880, 28)
    $headerLbl.Location = New-Object System.Drawing.Point(15, 10)
    $headerLbl.Anchor   = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $resultForm.Controls.Add($headerLbl)

    # 1px hairline frame: a Border-colored panel with 1px padding around the text box
    $textFrame = New-Object System.Windows.Forms.Panel
    $textFrame.Location  = New-Object System.Drawing.Point(15, 46)
    $textFrame.Size      = New-Object System.Drawing.Size(880, 620)
    $textFrame.Padding   = New-Object System.Windows.Forms.Padding(1)
    $textFrame.BackColor = Get-ThemeColor -ColorName "Border"
    $textFrame.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor `
                           [System.Windows.Forms.AnchorStyles]::Bottom -bor `
                           [System.Windows.Forms.AnchorStyles]::Left -bor `
                           [System.Windows.Forms.AnchorStyles]::Right
    $resultForm.Controls.Add($textFrame)

    $textBox = New-Object System.Windows.Forms.RichTextBox
    $textBox.Text        = $AnalysisText
    $textBox.ReadOnly    = $true
    $textBox.Font        = Get-GuiFont -Family "Consolas" -Size 9.5
    $textBox.BackColor   = Get-ThemeColor -ColorName "Surface"
    $textBox.ForeColor   = Get-ThemeColor -ColorName "TextPrimary"
    $textBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $textBox.ScrollBars  = "Vertical"
    $textBox.WordWrap    = $true
    $textBox.Dock        = [System.Windows.Forms.DockStyle]::Fill
    $textFrame.Controls.Add($textBox)

    $btnSave = New-GuiFlatButton -Text "Save report" -X 15 -Y 674 -Width 130 -Height 32 -Primary $true
    $btnSave.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $btnSave.Add_Click({
        $savePath = Join-Path $WorkDir "AI_SecurityAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        try {
            $AnalysisText | Out-File -FilePath $savePath -Encoding UTF8 -Force
            [System.Windows.Forms.MessageBox]::Show(
                "Analysis saved to:`n$savePath", "Saved", "OK", "Information")
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Save failed: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    })
    $resultForm.Controls.Add($btnSave)

    $btnClose = New-GuiFlatButton -Text "Close" -X 815 -Y 674 -Width 80 -Height 32
    $btnClose.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnClose.Add_Click({ $resultForm.Close() })
    $resultForm.Controls.Add($btnClose)

    [void]$resultForm.ShowDialog()
}

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
        Three numbered steps on neutral surfaces: 01 Connect, 02 Collect (one status tile per
        collector), 03 Analyze. Orange fills mark the primary action of a step; everything else is a
        hairline card. Colors come from the Yeyland Wutani theme tokens (Get-ThemeColor).

    .EXAMPLE
        Show-MainGUI
        # Displays the main application interface

    .NOTES
        All buttons include error handling and visual feedback
        Form cleanup includes proper Microsoft Graph disconnection
    #>

    [CmdletBinding()]
    param()

    #--------------------------------------------------------------
    # ENSURE ASSEMBLIES ARE LOADED
    #--------------------------------------------------------------

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

    [System.Windows.Forms.Application]::EnableVisualStyles()

    #--------------------------------------------------------------
    # CREATE MAIN FORM (1000 x 780 client area, 32 px side margins, 936 px content width)
    #--------------------------------------------------------------

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Microsoft 365 Security Analysis Tool - v$ScriptVer"
    $form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
    $form.Font = Get-GuiFont -Family "Segoe UI" -Size 9
    $form.ClientSize = New-Object System.Drawing.Size(1000, 780)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = Get-ThemeColor -ColorName "Background"

    # Set global form reference
    $Global:MainForm = $form

    $Global:GuiTiles = @{}
    $Global:GuiToolTip = New-Object System.Windows.Forms.ToolTip
    $Global:GuiToolTip.InitialDelay = 400
    $Global:GuiToolTip.AutoPopDelay = 15000
    $Global:GuiToolTip.ShowAlways = $true

    #--------------------------------------------------------------
    # HEADER: kicker, title, theme toggle, connection pill
    #--------------------------------------------------------------

    $kickerLabel = New-Object System.Windows.Forms.Label
    $kickerLabel.Text = "YEYLAND WUTANI $($script:GlyphDot) MS GRAPH POWERSHELL EDITION"
    $kickerLabel.Font = Get-GuiFont -Family "Consolas" -Size 8.5 -Style "Bold"
    $kickerLabel.ForeColor = Get-ThemeColor -ColorName "Primary"
    $kickerLabel.Tag = [PSCustomObject]@{ ColorName = "Primary" }
    $kickerLabel.AutoSize = $false
    $kickerLabel.Size = New-Object System.Drawing.Size(600, 16)
    $kickerLabel.Location = New-Object System.Drawing.Point(32, 24)
    $form.Controls.Add($kickerLabel)

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Microsoft 365 Security Analysis"
    $titleLabel.Font = Get-GuiFont -Family "Segoe UI Semibold" -Size 20
    $titleLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
    $titleLabel.Tag = [PSCustomObject]@{ ColorName = "TextPrimary" }
    $titleLabel.AutoSize = $false
    $titleLabel.Size = New-Object System.Drawing.Size(640, 36)
    $titleLabel.Location = New-Object System.Drawing.Point(32, 42)
    $form.Controls.Add($titleLabel)

    $themeToggle = New-Object System.Windows.Forms.Button
    $themeToggle.Size = New-Object System.Drawing.Size(96, 28)
    $themeToggle.Location = New-Object System.Drawing.Point(692, 30)
    $themeToggle.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $themeToggle.Font = Get-GuiFont -Family "Segoe UI" -Size 9
    $themeToggle.Cursor = [System.Windows.Forms.Cursors]::Hand
    $themeToggle.FlatAppearance.BorderSize = 1
    $themeToggle.UseVisualStyleBackColor = $false
    $themeToggle.Text = $(if ($script:CurrentTheme -eq "Dark") { "Light mode" } else { "Dark mode" })
    $themeToggle.Tag = [PSCustomObject]@{ Variant = "Flat" }
    Set-GuiFlatButtonColors -Button $themeToggle
    $themeToggle.Add_MouseEnter({ $this.FlatAppearance.BorderColor = Get-ThemeColor -ColorName "Primary" })
    $themeToggle.Add_MouseLeave({ Set-GuiFlatButtonColors -Button $this })
    $themeToggle.Add_Click({
        if ($script:CurrentTheme -eq "Dark") {
            Set-Theme -Theme "Light"
            $this.Text = "Dark mode"
        } else {
            Set-Theme -Theme "Dark"
            $this.Text = "Light mode"
        }
        Set-GuiFlatButtonColors -Button $this
    })
    $form.Controls.Add($themeToggle)

    $Global:ConnectionPill = New-GuiConnectionPill -X 800 -Y 30 -Width 168 -Height 28
    $form.Controls.Add($Global:ConnectionPill)

    #--------------------------------------------------------------
    # SESSION BLOCK: 2 x 2 cells (working directory, date range, tenant, account)
    #--------------------------------------------------------------

    $sessionPanel = New-Object System.Windows.Forms.Panel
    $sessionPanel.Size = New-Object System.Drawing.Size(936, 112)
    $sessionPanel.Location = New-Object System.Drawing.Point(32, 96)
    $sessionPanel.BorderStyle = "None"
    $sessionPanel.BackColor = Get-ThemeColor -ColorName "Surface"
    $sessionPanel.Tag = [PSCustomObject]@{ Kind = "surface"; BackRole = "Surface" }
    Enable-GuiPaintStyle -Control $sessionPanel
    $sessionPanel.Add_Paint({
        param($sender, $e)
        $pen = New-Object System.Drawing.Pen((Get-ThemeColor -ColorName "Border"), 1)
        $g = $e.Graphics
        $w = [int]$sender.Width - 1
        $h = [int]$sender.Height - 1
        $g.DrawRectangle($pen, 0, 0, $w, $h)
        $g.DrawLine($pen, [int]($sender.Width / 2), 0, [int]($sender.Width / 2), $h)
        $g.DrawLine($pen, 0, [int]($sender.Height / 2), $w, [int]($sender.Height / 2))
        $pen.Dispose()
    })
    $form.Controls.Add($sessionPanel)

    # Same $Global:*Label names as before, so Update-ConnectionStatus / Update-WorkingDirectoryDisplay keep working
    $Global:WorkDirLabel    = New-GuiSessionCell -Parent $sessionPanel -Caption "Working directory" -Value "$($ConfigData.WorkDir)" -X 0 -Y 0
    $Global:DateRangeLabel  = New-GuiSessionCell -Parent $sessionPanel -Caption "Date range" -Value "$($ConfigData.DateRange) days back" -X 468 -Y 0
    $Global:TenantInfoLabel = New-GuiSessionCell -Parent $sessionPanel -Caption "Tenant" -Value "Not connected" -X 0 -Y 56
    $Global:ConnectionLabel = New-GuiSessionCell -Parent $sessionPanel -Caption "Account" -Value "-" -X 468 -Y 56

    #--------------------------------------------------------------
    # STATUS BAR (created before the buttons: their handlers report into it)
    #--------------------------------------------------------------

    $statusBarPanel = New-Object System.Windows.Forms.Panel
    $statusBarPanel.Size = New-Object System.Drawing.Size(1000, 44)
    $statusBarPanel.Location = New-Object System.Drawing.Point(0, 736)
    $statusBarPanel.BorderStyle = "None"
    $statusBarPanel.BackColor = Get-ThemeColor -ColorName "Surface"
    $statusBarPanel.Tag = [PSCustomObject]@{ Kind = "surface"; BackRole = "Surface" }
    $statusBarPanel.Add_Paint({
        param($sender, $e)
        $pen = New-Object System.Drawing.Pen((Get-ThemeColor -ColorName "Border"), 1)
        $e.Graphics.DrawLine($pen, 0, 0, $sender.Width, 0)
        $pen.Dispose()
    })

    $Global:StatusLabel = New-Object System.Windows.Forms.Label
    $Global:StatusLabel.Text = "[OK] Ready - Please connect to Microsoft Graph to begin"
    $Global:StatusLabel.Font = Get-GuiFont -Family "Consolas" -Size 9
    $Global:StatusLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    $Global:StatusLabel.AutoSize = $false
    $Global:StatusLabel.AutoEllipsis = $true
    $Global:StatusLabel.TextAlign = "MiddleLeft"
    $Global:StatusLabel.Size = New-Object System.Drawing.Size(716, 44)
    $Global:StatusLabel.Location = New-Object System.Drawing.Point(32, 1)
    $statusBarPanel.Controls.Add($Global:StatusLabel)

    # Structured analysis summary: "Analysis complete  12 critical  23 high  0 medium  43 low"
    $Global:StatusSummaryPanel = New-Object System.Windows.Forms.Panel
    $Global:StatusSummaryPanel.Size = New-Object System.Drawing.Size(716, 43)
    $Global:StatusSummaryPanel.Location = New-Object System.Drawing.Point(32, 1)
    $Global:StatusSummaryPanel.BackColor = Get-ThemeColor -ColorName "Surface"
    $Global:StatusSummaryPanel.Visible = $false
    $Global:StatusSummaryPanel.Tag = [PSCustomObject]@{ Kind = "surface"; BackRole = "Surface"; Critical = 0; High = 0; Medium = 0; Low = 0 }
    Enable-GuiPaintStyle -Control $Global:StatusSummaryPanel
    $Global:StatusSummaryPanel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $scale = $sender.DeviceDpi / 96.0
        $font = Get-GuiFont -Family "Consolas" -Size 9
        $flags = [System.Windows.Forms.TextFormatFlags]"NoPadding, SingleLine, Left, VerticalCenter"
        $segments = @(
            @{ Text = "$($script:GlyphBullet) Analysis complete"; Color = (Get-ThemeColor -ColorName "Success") }
            @{ Text = "$($sender.Tag.Critical) critical"; Color = (Get-ThemeColor -ColorName "Danger") }
            @{ Text = "$($sender.Tag.High) high"; Color = (Get-ThemeColor -ColorName "Warning") }
            @{ Text = "$($sender.Tag.Medium) medium"; Color = (Get-ThemeColor -ColorName "Medium") }
            @{ Text = "$($sender.Tag.Low) low"; Color = (Get-ThemeColor -ColorName "Success") }
        )
        $x = 0
        foreach ($segment in $segments) {
            $size = [System.Windows.Forms.TextRenderer]::MeasureText($g, $segment.Text, $font, (New-Object System.Drawing.Size(600, 30)), $flags)
            $rect = New-Object System.Drawing.Rectangle($x, 0, ($size.Width + 2), $sender.Height)
            [System.Windows.Forms.TextRenderer]::DrawText($g, $segment.Text, $font, $rect, $segment.Color, $flags)
            $x += $size.Width + [int](22 * $scale)
        }
    })
    $statusBarPanel.Controls.Add($Global:StatusSummaryPanel)

    $Global:StatusRightLabel = New-Object System.Windows.Forms.Label
    $Global:StatusRightLabel.Text = "Batch $($ConfigData.BatchSize) $($script:GlyphDot) Cache $($ConfigData.CacheTimeout)s"
    $Global:StatusRightLabel.Font = Get-GuiFont -Family "Consolas" -Size 9
    $Global:StatusRightLabel.ForeColor = Get-ThemeColor -ColorName "TextSecondary"
    $Global:StatusRightLabel.Tag = [PSCustomObject]@{ ColorName = "TextSecondary" }
    $Global:StatusRightLabel.AutoSize = $false
    $Global:StatusRightLabel.TextAlign = "MiddleRight"
    $Global:StatusRightLabel.Size = New-Object System.Drawing.Size(220, 43)
    $Global:StatusRightLabel.Location = New-Object System.Drawing.Point(748, 1)
    $statusBarPanel.Controls.Add($Global:StatusRightLabel)
    $form.Controls.Add($statusBarPanel)

    #--------------------------------------------------------------
    # 01 CONNECT
    #--------------------------------------------------------------

    New-GuiSectionHeader -Parent $form -Number "01" -Title "Connect" -Y 232

    $btnWorkDir = New-GuiCardButton -Title "Set working directory" -Hint "Where results are saved" -X 32 -Y 262 -Width 176 -Height 56 -Action {
        $folder = Get-Folder -initialDirectory $ConfigData.WorkDir
        if ($folder) {
            Update-WorkingDirectoryDisplay -NewWorkDir $folder
            Update-GuiStatus "[OK] Working directory updated successfully" (Get-ThemeColor -ColorName "Success")

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

    $btnDateRange = New-GuiCardButton -Title "Change date range" -Hint "$($ConfigData.DateRange) days back" -X 222 -Y 262 -Width 176 -Height 56 -Action {
        $newRange = Get-DateRangeInput -CurrentValue $ConfigData.DateRange
        if ($newRange -ne $null) {
            $oldRange = $ConfigData.DateRange
            $ConfigData.DateRange = $newRange
            $Global:DateRangeLabel.Text = "$($ConfigData.DateRange) days back"
            $Global:DateRangeLabel.Refresh()
            Set-GuiCardHint -Card $btnDateRange -Hint "$($ConfigData.DateRange) days back"
            Update-GuiStatus "[OK] Date range updated from $oldRange to $newRange days" (Get-ThemeColor -ColorName "Success")

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

    $btnConnect = New-GuiCardButton -Title "Connect to Microsoft Graph" -Hint "Sign in to your tenant" -X 412 -Y 262 -Width 176 -Height 56 -TitleSize 9 -Action {
        $btnConnect.Enabled = $false
        $btnConnect.Text = "Connecting..."

        try {
            $connected = Connect-TenantServices

            if ($connected) {
                Update-GuiStatus "[OK] Connected to Microsoft Graph successfully!" (Get-ThemeColor -ColorName "Success")
            } else {
                Update-GuiStatus "[ERROR] Failed to connect to Microsoft Graph" (Get-ThemeColor -ColorName "Danger")
            }
        }
        finally {
            $btnConnect.Enabled = $true
            # Title and hint follow the connection state (Reconnect / Connect to Microsoft Graph)
            Update-ConnectionStatus
        }
    }
    $Global:ConnectButton = $btnConnect
    $form.Controls.Add($btnConnect)

    $btnDisconnect = New-GuiCardButton -Title "Disconnect" -Hint "End session" -X 602 -Y 262 -Width 176 -Height 56 -Action {
        $btnDisconnect.Enabled = $false
        $originalText = $btnDisconnect.Text
        $btnDisconnect.Text = "Disconnecting..."

        try {
            Disconnect-GraphSafely -ShowMessage $true
        }
        finally {
            $btnDisconnect.Enabled = $true
            $btnDisconnect.Text = $originalText
        }
    }
    $form.Controls.Add($btnDisconnect)

    $btnCheckVersion = New-GuiCardButton -Title "Check version" -Hint "Compare with GitHub" -X 792 -Y 262 -Width 176 -Height 56 -Action {
        Test-ScriptVersion -ShowMessageBox $true
    }
    $form.Controls.Add($btnCheckVersion)

    # Reflect any pre-form authentication in the pill, session cells and Connect card
    Update-ConnectionStatus

    #--------------------------------------------------------------
    # 02 COLLECT: one tile per collector, "Run all collection" at the end of the header row
    #--------------------------------------------------------------

    New-GuiSectionHeader -Parent $form -Number "02" -Title "Collect" -Y 342 -RightReserve 176

    $tileX = @(32, 271, 510, 749)
    $tileY = @(382, 470)

    $tileSignIn = New-GuiCollectorTile -Key "SignIns" -Title "Sign-in data" -X $tileX[0] -Y $tileY[0] -Action {
        Invoke-GuiCollectorTile -Key "SignIns" -Collect { Get-TenantSignInData } `
            -Success { param($r) "[OK] Sign-in data collected! Processed $(@($r).Count) records." }
    }
    $form.Controls.Add($tileSignIn)

    $tileAudit = New-GuiCollectorTile -Key "AdminAudit" -Title "Admin audits" -X $tileX[1] -Y $tileY[0] -Action {
        Invoke-GuiCollectorTile -Key "AdminAudit" -Collect { Get-AdminAuditData } `
            -Success { param($r) "[OK] Admin audit data collected! Processed $(@($r).Count) records." }
    }
    $form.Controls.Add($tileAudit)

    $tileRules = New-GuiCollectorTile -Key "InboxRules" -Title "Inbox rules" -X $tileX[2] -Y $tileY[0] -Action {
        Invoke-GuiCollectorTile -Key "InboxRules" -Collect { Get-MailboxRules } `
            -Success { param($r) "[OK] Inbox rules collected! Found $(@($r).Count) rules." }
    }
    $form.Controls.Add($tileRules)

    $tileDelegation = New-GuiCollectorTile -Key "MailboxDelegation" -Title "Delegations" -X $tileX[3] -Y $tileY[0] -Action {
        Invoke-GuiCollectorTile -Key "MailboxDelegation" -Collect { Get-MailboxDelegationData } `
            -Success { param($r) "[OK] Delegation data collected! Found $(@($r).Count) delegations." }
    }
    $form.Controls.Add($tileDelegation)

    $tileApps = New-GuiCollectorTile -Key "AppRegistrations" -Title "App registrations" -X $tileX[0] -Y $tileY[1] -Action {
        Invoke-GuiCollectorTile -Key "AppRegistrations" -Collect { Get-AppRegistrationData } `
            -Success { param($r) "[OK] App registration data collected! Found $(@($r).Count) apps." }
    }
    $form.Controls.Add($tileApps)

    $tileConditionalAccess = New-GuiCollectorTile -Key "ConditionalAccess" -Title "Conditional access" -X $tileX[1] -Y $tileY[1] -Action {
        Invoke-GuiCollectorTile -Key "ConditionalAccess" -Collect { Get-ConditionalAccessData } `
            -Success { param($r) "[OK] Conditional access data collected! Found $(@($r).Count) policies." }
    }
    $form.Controls.Add($tileConditionalAccess)

    $tileETR = New-GuiCollectorTile -Key "ETR" -Title "ETR files" -X $tileX[2] -Y $tileY[1] -Action {
        Invoke-GuiCollectorTile -Key "ETR" -RequireConnection $false -Collect {
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

            $etrStart = Get-Date
            $result = Analyze-ETRData -RiskyIPs $riskyIPs
            if ($result) {
                $criticalCount = ($result | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                $highCount = ($result | Where-Object { $_.RiskLevel -eq "High" }).Count
                Update-GuiStatus "[OK] ETR analysis completed! Found $criticalCount critical and $highCount high-risk patterns." (Get-ThemeColor -ColorName "Success")
            }
            $result
        }
    }
    $form.Controls.Add($tileETR)

    $tileMessageTrace = New-GuiCollectorTile -Key "MessageTrace" -Title "Message trace" -X $tileX[3] -Y $tileY[1] -Action {
        Invoke-GuiCollectorTile -Key "MessageTrace" -RequireConnection $false -Collect {
            $result = Get-MessageTraceExchangeOnline
            if ($result) {
                Update-GuiStatus "[OK] Message trace collected! Processed $(@($result).Count) messages." (Get-ThemeColor -ColorName "Success")

                $runAnalysis = [System.Windows.Forms.MessageBox]::Show(
                    "Message trace collection complete!`n`n$(@($result).Count) messages saved.`n`nRun ETR analysis now?",
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
                            $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" -and -not [string]::IsNullOrEmpty($_.IP) } |
                                       Select-Object -ExpandProperty IP -Unique
                        } catch { }
                    }
                    $etrStart = Get-Date
                    $etrResult = Analyze-ETRData -RiskyIPs $riskyIPs
                    if ($etrResult) { Complete-GuiTile -Key "ETR" -Since $etrStart -Count @($etrResult).Count }
                }
            }
            $result
        }
    }
    $form.Controls.Add($tileMessageTrace)

    $btnRunAll = New-GuiCardButton -Title "Run all collection" -X 808 -Y 338 -Width 160 -Height 30 -Variant Primary -TitleSize 9 -Action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "[ERROR] Please connect to Microsoft Graph first!" (Get-ThemeColor -ColorName "Danger")
            return
        }

        $btnRunAll.Enabled = $false
        $originalText = $btnRunAll.Text
        foreach ($tile in @($Global:GuiTiles.Values)) { $tile.Enabled = $false }

        $tasks = @(
            @{Name="Sign-In Data"; Function="Get-TenantSignInData"; Tile="SignIns"},
            @{Name="Admin Audits"; Function="Get-AdminAuditData"; Tile="AdminAudit"},
            @{Name="Inbox Rules"; Function="Get-MailboxRules"; Tile="InboxRules"},
            @{Name="MFA Status Audit"; Function="Get-MFAStatusAudit"; Tile=$null},
            @{Name="Failed Login Analysis"; Function="Get-FailedLoginPatterns"; Tile=$null},
            @{Name="Password Change Analysis"; Function="Get-RecentPasswordChanges"; Tile=$null},
            @{Name="Delegations"; Function="Get-MailboxDelegationData"; Tile="MailboxDelegation"},
            @{Name="App Registrations"; Function="Get-AppRegistrationData"; Tile="AppRegistrations"},
            @{Name="Conditional Access"; Function="Get-ConditionalAccessData"; Tile="ConditionalAccess"},
            @{Name="Message Trace"; Function="Get-MessageTraceExchangeOnline"; Tile="MessageTrace"},
            @{Name="ETR Analysis"; Function="Analyze-ETRData"; Tile="ETR"}
        )
        $completed = 0

        Update-GuiStatus "Starting comprehensive data collection..." (Get-ThemeColor -ColorName "Warning")

        try {
            foreach ($task in $tasks) {
                $btnRunAll.Text = "Running: $($task.Name)..."
                Update-GuiStatus "Executing: $($task.Name)..." (Get-ThemeColor -ColorName "Warning")
                $taskStart = Get-Date
                if ($task.Tile) { Set-GuiTileState -Key $task.Tile -State "running" -Text "Collecting$($script:GlyphEllipsis)" }

                try {
                    $taskResult = $null
                    switch ($task.Function) {
                        "Get-TenantSignInData" { $taskResult = Get-TenantSignInData }
                        "Get-AdminAuditData" { $taskResult = Get-AdminAuditData }
                        "Get-MailboxRules" { $taskResult = Get-MailboxRules }
                        "Get-MFAStatusAudit" { Get-MFAStatusAudit | Out-Null }
                        "Get-FailedLoginPatterns" { Get-FailedLoginPatterns | Out-Null }
                        "Get-RecentPasswordChanges" { Get-RecentPasswordChanges | Out-Null }
                        "Get-MailboxDelegationData" { $taskResult = Get-MailboxDelegationData }
                        "Get-AppRegistrationData" { $taskResult = Get-AppRegistrationData }
                        "Get-ConditionalAccessData" { $taskResult = Get-ConditionalAccessData }
                        "Get-MessageTraceExchangeOnline" { $taskResult = Get-MessageTraceExchangeOnline }
                        "Analyze-ETRData" {
                            $riskyIPs = @()
                            $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
                            if (Test-Path $signInDataPath) {
                                try {
                                    $signInData = Import-Csv -Path $signInDataPath
                                    $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" -and -not [string]::IsNullOrEmpty($_.IP) } |
                                               Select-Object -ExpandProperty IP -Unique
                                } catch { }
                            }
                            $taskResult = Analyze-ETRData -RiskyIPs $riskyIPs
                        }
                    }
                    $completed++
                    if ($task.Tile) {
                        Complete-GuiTile -Key $task.Tile -Since $taskStart -Count $(if ($taskResult) { @($taskResult).Count } else { $null })
                    }
                    Update-GuiStatus "[OK] Completed: $($task.Name) ($completed/$($tasks.Count))" (Get-ThemeColor -ColorName "Success")
                }
                catch {
                    Write-Log "Error in $($task.Name): $($_.Exception.Message)" -Level "Error"
                    if ($task.Tile) { Set-GuiTileState -Key $task.Tile -State "error" -Text "Failed" -Note $_.Exception.Message }
                    Update-GuiStatus "[ERROR] Error in $($task.Name): $($_.Exception.Message)" (Get-ThemeColor -ColorName "Danger")
                }
            }
        }
        finally {
            foreach ($tile in @($Global:GuiTiles.Values)) { $tile.Enabled = $true }
            $btnRunAll.Enabled = $true
            $btnRunAll.Text = $originalText
        }

        # Determine status based on completion rate
        $allSucceeded = ($completed -eq $tasks.Count)
        if ($allSucceeded) {
            Update-GuiStatus "[OK] Data collection completed! All $($tasks.Count) tasks finished. Check logs for details." (Get-ThemeColor -ColorName "Success")
            $dialogMessage = "Data collection completed!`n`nAll $($tasks.Count) tasks finished.`n`nPlease review the logs for any warnings or errors."
        } else {
            Update-GuiStatus "[WARNING] Data collection finished with errors! $completed of $($tasks.Count) tasks succeeded." (Get-ThemeColor -ColorName "Warning")
            $dialogMessage = "Data collection completed with errors!`n`n$completed out of $($tasks.Count) tasks succeeded.`n`nPlease review the logs for error details."
        }

        [System.Windows.Forms.MessageBox]::Show(
            $dialogMessage,
            "Collection Complete",
            "OK",
            "Information"
        )
    }
    $form.Controls.Add($btnRunAll)

    #--------------------------------------------------------------
    # 03 ANALYZE
    #--------------------------------------------------------------

    New-GuiSectionHeader -Parent $form -Number "03" -Title "Analyze" -Y 568

    $btnAnalyze = New-GuiCardButton -Title "Analyze data" -X 32 -Y 598 -Width 302 -Height 52 -Variant Primary -TitleSize 11 -Action {
        $btnAnalyze.Enabled = $false
        $originalText = $btnAnalyze.Text
        $btnAnalyze.Text = "Analyzing..."

        $reportPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "SecurityReport.html"

        try {
            Update-GuiStatus "Starting comprehensive security analysis..." (Get-ThemeColor -ColorName "Warning")
            $results = Invoke-CompromiseDetection -ReportPath $reportPath

            if ($results) {
                $critical = @($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                $high = @($results | Where-Object { $_.RiskLevel -eq "High" }).Count
                $medium = @($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
                $low = @($results | Where-Object { $_.RiskLevel -eq "Low" }).Count

                Update-GuiRiskSummary -Critical $critical -High $high -Medium $medium -Low $low

                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Security Analysis Completed!`n`n" +
                    "Risk Summary:`n- Critical Risk: $critical users`n- High Risk: $high users`n- Medium Risk: $medium users`n`n" +
                    "Total Users Analyzed: $($results.Count)`n`nOpen the detailed HTML report now?",
                    "Analysis Complete",
                    "YesNo",
                    "Information"
                )

                if ($result -eq "Yes") {
                    Start-Process $reportPath
                }
            } else {
                Update-GuiStatus "[ERROR] Analysis failed - no data available" (Get-ThemeColor -ColorName "Danger")
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

    $btnViewReports = New-GuiCardButton -Title "View reports" -X 349 -Y 598 -Width 302 -Height 52 -TitleSize 11 -Action {
        Update-GuiStatus "Looking for reports in working directory..." (Get-ThemeColor -ColorName "Warning")

        $reports = @(Get-ChildItem -Path $ConfigData.WorkDir -Filter "*.html" -ErrorAction SilentlyContinue)

        if ($reports.Count -eq 0) {
            Update-GuiStatus "[WARNING] No reports found in working directory" (Get-ThemeColor -ColorName "Warning")
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
            Update-GuiStatus "[OK] Opening report: $($reports[0].Name)" (Get-ThemeColor -ColorName "Success")
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
            $reportLabel.Text = "Select a report to open:"
            $reportLabel.Font = Get-GuiFont -Family "Segoe UI Semibold" -Size 10
            $reportLabel.Size = New-Object System.Drawing.Size(560, 30)
            $reportLabel.Location = New-Object System.Drawing.Point(20, 20)
            $reportLabel.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
            $reportForm.Controls.Add($reportLabel)

            $listBox = New-Object System.Windows.Forms.ListBox
            $listBox.Size = New-Object System.Drawing.Size(560, 280)
            $listBox.Location = New-Object System.Drawing.Point(20, 50)
            $listBox.Font = Get-GuiFont -Family "Segoe UI" -Size 9
            $listBox.BackColor = Get-ThemeColor -ColorName "Surface"
            $listBox.ForeColor = Get-ThemeColor -ColorName "TextPrimary"
            $listBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            foreach ($report in $reports) {
                $item = "$($report.Name) ($(Get-Date $report.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))"
                $listBox.Items.Add($item) | Out-Null
            }

            $reportForm.Controls.Add($listBox)

            $openBtn = New-GuiFlatButton -Text "Open selected report" -X 340 -Y 340 -Width 150 -Height 32 -Primary $true
            $openBtn.Add_Click({
                if ($listBox.SelectedIndex -ge 0) {
                    Start-Process $reports[$listBox.SelectedIndex].FullName
                    $reportForm.Close()
                }
            })
            $reportForm.Controls.Add($openBtn)

            $cancelBtn = New-GuiFlatButton -Text "Cancel" -X 500 -Y 340 -Width 80 -Height 32
            $cancelBtn.Add_Click({ $reportForm.Close() })
            $reportForm.Controls.Add($cancelBtn)

            [void]$reportForm.ShowDialog()
        }
    }
    $form.Controls.Add($btnViewReports)

    $btnExit = New-GuiCardButton -Title "Exit" -X 666 -Y 598 -Width 302 -Height 52 -Variant Muted -TitleSize 11 -Action {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to exit the application?`n`n" +
            "This will disconnect from Microsoft Graph and close the tool.",
            "Confirm Exit",
            "YesNo",
            "Question"
        )

        if ($result -eq "Yes") {
            Update-GuiStatus "Shutting down application..." (Get-ThemeColor -ColorName "Warning")

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

    # Hatz AI: send the collected CSVs for AI analysis (optional, full-width row)
    $btnAIAnalysis = New-GuiCardButton -Title "$($script:GlyphSparkle)  AI security analysis   Powered by Hatz AI" -X 32 -Y 666 -Width 936 -Height 52 -Variant Ai -TitleSize 11 -Action {
        $btnAIAnalysis.Enabled = $false
        $originalText = $btnAIAnalysis.Text
        $btnAIAnalysis.Text = "Connecting to Hatz AI..."
        Update-GuiStatus "Hatz AI: Retrieving API key..." (Get-ThemeColor -ColorName "Warning")

        try {
            $apiKey = Get-HatzApiKeyForM365
            if ([string]::IsNullOrWhiteSpace($apiKey)) {
                Update-GuiStatus "[WARNING] Hatz AI: No API key provided - analysis cancelled" (Get-ThemeColor -ColorName "Warning")
                return
            }

            # Count available CSVs so user knows what will be sent
            $csvCount = (Get-ChildItem -Path $ConfigData.WorkDir -Filter "*.csv" -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 }).Count

            if ($csvCount -eq 0) {
                Update-GuiStatus "[WARNING] Hatz AI: No CSV data files found - collect data first" (Get-ThemeColor -ColorName "Warning")
                [System.Windows.Forms.MessageBox]::Show(
                    "No CSV data files found in:`n$($ConfigData.WorkDir)`n`nPlease run data collection first.",
                    "No Data Available", "OK", "Warning")
                return
            }

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Send $csvCount CSV file(s) to Hatz AI for security analysis?`n`n" +
                "Working directory: $($ConfigData.WorkDir)`n`n" +
                "The AI will identify critical findings across MFA, sign-in patterns,`n" +
                "inbox rules, delegations, app registrations and more.`n`n" +
                "This may take 30-90 seconds depending on data volume.",
                "Confirm AI Analysis",
                "YesNo",
                "Question"
            )

            if ($confirm -ne "Yes") {
                Update-GuiStatus "[OK] Hatz AI analysis cancelled" (Get-ThemeColor -ColorName "TextSecondary")
                return
            }

            $btnAIAnalysis.Text = "Analyzing $csvCount files..."
            Update-GuiStatus "Hatz AI: Sending data for analysis - please wait..." (Get-ThemeColor -ColorName "Warning")

            $analysisText, $errorMsg = Invoke-HatzSecurityAnalysis -ApiKey $apiKey -WorkDir $ConfigData.WorkDir

            if ($analysisText) {
                Update-GuiStatus "[OK] Hatz AI analysis complete - displaying results" (Get-ThemeColor -ColorName "Success")
                Show-HatzAnalysisResult -AnalysisText $analysisText -WorkDir $ConfigData.WorkDir
            }
            else {
                Update-GuiStatus "[ERROR] Hatz AI: $errorMsg" (Get-ThemeColor -ColorName "Danger")
                [System.Windows.Forms.MessageBox]::Show(
                    "Hatz AI analysis failed:`n`n$errorMsg",
                    "Analysis Failed", "OK", "Error")
            }
        }
        finally {
            $btnAIAnalysis.Enabled = $true
            $btnAIAnalysis.Text = $originalText
        }
    }
    $form.Controls.Add($btnAIAnalysis)

    #--------------------------------------------------------------
    # FORM EVENT HANDLERS
    #--------------------------------------------------------------

    # Running collectors pulse their status dot (500 ms)
    $Global:GuiPulseTimer = New-Object System.Windows.Forms.Timer
    $Global:GuiPulseTimer.Interval = 500
    $Global:GuiPulseTimer.Add_Tick({
        $script:TilePulseHigh = -not $script:TilePulseHigh
        foreach ($tile in @($Global:GuiTiles.Values)) {
            if ($tile.Tag.State -eq "running") { $tile.Invalidate() }
        }
    })
    $Global:GuiPulseTimer.Start()

    $form.Add_FormClosing({
        param($sender, $e)

        try {
            if ($Global:ConnectionState.IsConnected) {
                Update-GuiStatus "Form closing - disconnecting from Microsoft Graph..." (Get-ThemeColor -ColorName "Warning")
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
            if ($Global:GuiPulseTimer) {
                $Global:GuiPulseTimer.Stop()
                $Global:GuiPulseTimer.Dispose()
            }
        }
        catch { }

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
        Initialize-GuiTileStates

        $versionCheck = Test-ScriptVersion -ShowMessageBox $false
        if ($versionCheck.IsLatest -eq $false) {
            Test-ScriptVersion -ShowMessageBox $true
        }

        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "[OK] Application ready - Using existing Microsoft Graph connection" (Get-ThemeColor -ColorName "Success")
        } else {
            Update-GuiStatus "[INFO] Application ready - Please connect to Microsoft Graph to begin" (Get-ThemeColor -ColorName "Warning")
        }
    })

    #--------------------------------------------------------------
    # SHOW THE FORM
    #--------------------------------------------------------------

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

Write-Host ""
Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Authenticating before launching GUI..." -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Running authentication now (before the window opens)" -ForegroundColor Yellow
Write-Host "to ensure WAM/interactive login works correctly." -ForegroundColor Gray
Write-Host ""

# ── Pre-form authentication ──────────────────────────────────────────────────
# Connect before the WinForms message loop starts.  This avoids the
# WindowsFormsSynchronizationContext that newer MSAL/EXO (3.9.2+) dereferences
# inside RuntimeBroker..ctor, causing a NullReferenceException with WAM.
#
# Belt-and-suspenders: explicitly null out any SynchronizationContext that an
# earlier control/MessageBox may have installed on this thread, so all auth runs
# context-free. Form.ShowDialog() re-establishes its own context for the GUI later,
# so this does not affect the running application.
try {
    [System.Threading.SynchronizationContext]::SetSynchronizationContext($null)
} catch {}

$preAuthSuccess = $false
$preAuthAttempts = 0
$maxPreAuthAttempts = 3

while (-not $preAuthSuccess -and $preAuthAttempts -lt $maxPreAuthAttempts) {
    $preAuthAttempts++
    Write-Host "Authentication attempt $preAuthAttempts of $maxPreAuthAttempts..." -ForegroundColor Yellow

    try {
        $connected = Connect-TenantServices
        if ($connected) {
            $preAuthSuccess = $true
            Write-Host ""
            Write-Host "✓ Authentication successful." -ForegroundColor Green
            Write-Host "  Tenant : $($Global:ConnectionState.TenantName)" -ForegroundColor Green
            Write-Host "  Account: $($Global:ConnectionState.Account)" -ForegroundColor Green
        } else {
            Write-Host "[WARNING] Connect-TenantServices returned false on attempt $preAuthAttempts." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[ERROR] Authentication error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Pre-form auth error (attempt $preAuthAttempts): $($_.Exception.Message)" -Level "Error"
    }

    if (-not $preAuthSuccess -and $preAuthAttempts -lt $maxPreAuthAttempts) {
        Write-Host "Retrying..." -ForegroundColor Gray
        Write-Host ""
    }
}

if (-not $preAuthSuccess) {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  Authentication failed after $maxPreAuthAttempts attempts." -ForegroundColor Red
    Write-Host "  The GUI will still open — use the Connect" -ForegroundColor Yellow
    Write-Host "  button inside the window to try again." -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
}

Write-Host ""
Write-Host "Launching graphical user interface..." -ForegroundColor Yellow
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
    Write-Host "[WARNING] Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
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
    Write-Host "[WARNING] Exchange cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
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
