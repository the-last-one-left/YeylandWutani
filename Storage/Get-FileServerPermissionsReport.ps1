<#
.SYNOPSIS
    Yeyland Wutani LLC -- Windows File Server Storage & Permissions Report

.DESCRIPTION
    Audits a Windows file server (local or remote).  When a server name is
    supplied with -Server the script enumerates all non-hidden SMB shares
    via WMI automatically; -Path lets you target specific paths instead.

    Default mode: full permissions + size audit.
    Use -StorageOnly for a fast storage-only report (skips ACL collection).

    For each folder (up to -MaxDepth levels deep) the report captures:
      - Recursive size and file count (single-pass file walk per share)
      - Per-share size breakdown with visual bars
      - Top largest folders across all shares
      [Full mode only]
      - Full ACL: explicit + inherited ACEs, with SID-to-account translation
      - Permission anomalies (broad-access accounts with write rights)

    Performance: ACL collection runs in a RunspacePool (PS 5.1-compatible).
    File sizes use a single recursive pass per root to minimise disk hits.

    Output: a self-contained HTML report + companion CSV, both Pacific Office
    Automation branded.

.PARAMETER Server
    Remote server hostname or IP.  The script enumerates its SMB shares via WMI
    and builds UNC paths automatically.
    Mutually exclusive with -Path.

.PARAMETER Path
    One or more explicit paths to scan (local or UNC).
    Mutually exclusive with -Server.

.PARAMETER OutputDir
    Folder where the HTML and CSV are saved.  Default: current directory.

.PARAMETER ClientName
    Client name shown in the report header.  Default: "Client".

.PARAMETER MaxDepth
    Maximum folder recursion depth (0 = root only).  Default: 4.

.PARAMETER MaxRunspaces
    Parallel ACL-collection threads (full mode only).  Default: 8.

.PARAMETER StorageOnly
    Skip ACL collection entirely.  Produces a fast storage report with
    per-share breakdown, top folders, and full folder tree.  Recommended
    for large servers or when permissions are not needed.

.PARAMETER ExcludeBuiltin
    Hide well-known built-in accounts (SYSTEM, TrustedInstaller, Administrators,
    CREATOR OWNER) from HTML badges; they still appear in the CSV.

.PARAMETER AnomalyGroupsOnly
    Show only anomalous folders in the HTML detail table (full data in CSV).

.PARAMETER FromCsv
    Path to an existing CSV produced by a previous run of this script.
    Rebuilds the HTML report from that data without re-scanning the server.
    Use with -ClientName and optionally -StorageOnly (auto-detected if the
    CSV has no permission columns populated).

.PARAMETER IncludeHiddenShares
    Include administrative hidden shares (ending in $) in share enumeration.

.EXAMPLE
    # Rebuild HTML from an existing CSV (storage view):
    .\Get-FileServerPermissionsReport.ps1 -FromCsv "C:\Temp\Acme_FileServerReport_20260414_1450.csv" -ClientName "Acme Corp" -StorageOnly

.EXAMPLE
    # Rebuild HTML from an existing CSV (full permissions view):
    .\Get-FileServerPermissionsReport.ps1 -FromCsv "C:\Temp\Acme_FileServerReport_20260414_1450.csv" -ClientName "Acme Corp"

.EXAMPLE
    # Fast storage report -- no ACL collection:
    .\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -ClientName "Acme Corp" -StorageOnly

.EXAMPLE
    # Scan all shares on a remote server (full permissions + size):
    .\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -ClientName "Acme Corp"

.EXAMPLE
    # Scan specific paths, suppress built-in noise, 3 levels deep:
    .\Get-FileServerPermissionsReport.ps1 -Path "\\fs1\Finance","\\fs1\HR" `
        -ClientName "Contoso" -MaxDepth 3 -ExcludeBuiltin

.EXAMPLE
    # Remote server, show only problem folders in HTML:
    .\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -AnomalyGroupsOnly `
        -IncludeHiddenShares
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = "ByPath")]
param(
    [Parameter(ParameterSetName = "ByServer", Mandatory)]
    [string]   $Server,

    [Parameter(ParameterSetName = "ByPath")]
    [string[]] $Path              = @($PWD.Path),

    [Parameter(ParameterSetName = "FromCsv", Mandatory)]
    [string]   $FromCsv,

    [string]   $OutputDir         = $PWD.Path,
    [string]   $ClientName        = "Client",
    [int]      $MaxDepth          = 4,
    [int]      $MaxRunspaces      = 8,
    [switch]   $StorageOnly,
    [switch]   $ExcludeBuiltin,
    [switch]   $AnomalyGroupsOnly,
    [switch]   $IncludeHiddenShares
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Web   # for HtmlEncode

# ── Console helpers ───────────────────────────────────────────────────────────

function Write-Banner {
    $bar = "=" * 64
    Write-Host ""
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host "    YEYLAND WUTANI LLC  //  File Server Permissions Report" -ForegroundColor Cyan
    Write-Host "    Pacific Office Automation -- Problem Solved." -ForegroundColor DarkGray
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Step  ([string]$Msg) {
    Write-Host ("  [{0}]  {1}" -f (Get-Date -F "HH:mm:ss"), $Msg) -ForegroundColor Cyan
}
function Write-Info  ([string]$Key, [string]$Val) {
    Write-Host ("    {0,-24}" -f "${Key}:") -NoNewline -ForegroundColor DarkGray
    Write-Host $Val -ForegroundColor White
}
function Write-Warn  ([string]$Msg) {
    Write-Host "  [WARN]  $Msg" -ForegroundColor Yellow
}
function Write-Ok    ([string]$Msg) {
    Write-Host "  [OK]    $Msg" -ForegroundColor Green
}

# ── SID translation cache ─────────────────────────────────────────────────────
# Translates SID strings (S-1-5-...) to NTAccount display names.
# Results (hits and misses) are cached so each SID is looked up only once.

$Script:SidCache = @{}

function Resolve-Identity([string]$IdentityRef) {
    # If it doesn't start with S- it's already a name
    if ($IdentityRef -notmatch '^S-\d') { return $IdentityRef }

    if ($Script:SidCache.ContainsKey($IdentityRef)) {
        return $Script:SidCache[$IdentityRef]
    }

    try {
        $sid      = [System.Security.Principal.SecurityIdentifier]::new($IdentityRef)
        $resolved = $sid.Translate([System.Security.Principal.NTAccount]).Value
        $Script:SidCache[$IdentityRef] = $resolved
        return $resolved
    } catch {
        # SID not resolvable (deleted account, orphaned SID, etc.)
        $Script:SidCache[$IdentityRef] = "$IdentityRef (orphaned)"
        return "$IdentityRef (orphaned)"
    }
}

# ── Anomaly detection ─────────────────────────────────────────────────────────

$BroadPatterns = @(
    "Everyone",
    "Authenticated Users",
    "BUILTIN\\Users",
    "NT AUTHORITY\\Authenticated Users",
    "NT AUTHORITY\\Everyone",
    "Domain Users"
)

$BuiltinNoise = @(
    "NT AUTHORITY\\SYSTEM",
    "NT SERVICE\\TrustedInstaller",
    "BUILTIN\\Administrators",
    "CREATOR OWNER"
)

$WriteRightWords = @(
    "FullControl","Modify","Write","WriteData","AppendData",
    "CreateFiles","CreateDirectories","WriteAttributes",
    "WriteExtendedAttributes","ChangePermissions","TakeOwnership"
)

function Test-IsBroad([string]$Identity) {
    foreach ($p in $BroadPatterns) {
        if ($Identity -like "*$p*") { return $true }
    }
    return $false
}

function Test-HasWriteRight([string]$RightsStr) {
    foreach ($w in $WriteRightWords) {
        if ($RightsStr -like "*$w*") { return $true }
    }
    return $false
}

function Test-IsAnomaly([hashtable]$Ace) {
    return ($Ace.Type -eq "Allow") -and
           (Test-IsBroad $Ace.Identity) -and
           (Test-HasWriteRight $Ace.Rights)
}

# ── Formatting helpers ────────────────────────────────────────────────────────

function Format-Bytes([long]$b) {
    if ($b -ge 1TB) { return "{0:N2} TB" -f ($b/1TB) }
    if ($b -ge 1GB) { return "{0:N2} GB" -f ($b/1GB) }
    if ($b -ge 1MB) { return "{0:N2} MB" -f ($b/1MB) }
    if ($b -ge 1KB) { return "{0:N2} KB" -f ($b/1KB) }
    return "$b B"
}

function Escape-Html([string]$s) {
    [System.Web.HttpUtility]::HtmlEncode($s)
}

# ── Share enumeration ─────────────────────────────────────────────────────────

function Get-ServerShares([string]$ServerName) {
    Write-Step "Enumerating SMB shares on $ServerName"
    try {
        # Win32_Share works both locally and remotely without RSAT
        $shares = Get-WmiObject -Class Win32_Share `
                                -ComputerName $ServerName `
                                -ErrorAction Stop |
                  Where-Object { $_.Type -eq 0 }    # 0 = Disk Drive

        if (-not $IncludeHiddenShares) {
            $shares = $shares | Where-Object { $_.Name -notlike '*$' }
        }

        $paths = $shares | ForEach-Object {
            "\\$ServerName\$($_.Name)"
        }
        Write-Info "  Shares found" $shares.Count
        return @($paths)
    } catch {
        Write-Warn "WMI share enumeration failed: $_"
        Write-Warn "Falling back to net share output..."
        try {
            $raw = Invoke-Command -ComputerName $ServerName -ScriptBlock {
                net share
            } -ErrorAction Stop
            # Parse the tabular output
            $paths = @()
            foreach ($line in $raw) {
                if ($line -match '^(\S+)\s+((?:[A-Z]:\\|\\\\)\S+)') {
                    $name = $Matches[1]
                    $path = "\\$ServerName\$name"
                    if (-not $IncludeHiddenShares -and $name -like '*$') { continue }
                    $paths += $path
                }
            }
            return $paths
        } catch {
            Write-Warn "Remote net share also failed: $_"
            return @()
        }
    }
}

# ── Parallel ACL collection via RunspacePool (PS 5.1) ─────────────────────────
#
# Each runspace gets a folder path and returns a serialisable hashtable with
# the ACE list. SID translation happens back in the main thread (using the
# shared SidCache) after all runspaces complete.

$AclScriptBlock = {
    param([string]$FolderPath)

    $result = @{
        Path    = $FolderPath
        AceList = @()
        Error   = $null
    }

    try {
        $acl  = [System.IO.Directory]::GetAccessControl($FolderPath)
        $aces = $acl.Access
        $list = foreach ($ace in $aces) {
            @{
                RawIdentity      = $ace.IdentityReference.Value
                Type             = $ace.AccessControlType.ToString()
                Rights           = $ace.FileSystemRights.ToString()
                IsInherited      = $ace.IsInherited
                InheritanceFlags = $ace.InheritanceFlags.ToString()
                PropagationFlags = $ace.PropagationFlags.ToString()
            }
        }
        $result.AceList = @($list)
    } catch {
        $result.Error = $_.ToString()
    }

    return $result
}

function Get-AclsParallel {
    param(
        [string[]] $FolderPaths,
        [int]      $MaxRunspaces
    )

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(
        1, $MaxRunspaces,
        [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault(),
        $Host
    )
    $pool.Open()

    $jobs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fp in $FolderPaths) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($AclScriptBlock).AddArgument($fp)
        $handle = $ps.BeginInvoke()
        $jobs.Add(@{ PS = $ps; Handle = $handle; Path = $fp })
    }

    $aclMap = @{}
    $done   = 0
    $total  = $jobs.Count

    foreach ($job in $jobs) {
        try {
            $res = $job.PS.EndInvoke($job.Handle)
            if ($res -and $res.Count -gt 0) {
                $aclMap[$res[0].Path] = $res[0]
            }
        } catch {
            $aclMap[$job.Path] = @{ Path = $job.Path; AceList = @(); Error = $_.ToString() }
        } finally {
            $job.PS.Dispose()
            $done++
            $pct = [int](($done / $total) * 100)
            if (($done % 2500) -eq 0 -or $done -eq $total) {
                Write-Host ("    ACLs collected: {0:N0}/{1:N0}  ({2}%)" -f $done, $total, $pct) `
                    -ForegroundColor DarkGray
            }
        }
    }

    $pool.Close()
    $pool.Dispose()
    return $aclMap
}

# ── Folder enumeration + size ─────────────────────────────────────────────────
# Strategy: walk ALL files once per root with a single Get-ChildItem -Recurse,
# then aggregate sizes bottom-up.  This is far faster than calling
# Get-ChildItem recursively on every individual folder.

function Get-AllFolders {
    param(
        [string] $RootPath,
        [int]    $MaxDepth
    )

    # 1. Collect all directories up to MaxDepth
    $folders = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new()
    $folders.Add((Get-Item -LiteralPath $RootPath -Force))

    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@{ Path = $RootPath; Depth = 0 })

    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($cur.Depth -ge $MaxDepth) { continue }
        try {
            $subs = [System.IO.Directory]::GetDirectories($cur.Path)
            foreach ($s in $subs) {
                try {
                    $di = [System.IO.DirectoryInfo]::new($s)
                    $folders.Add($di)
                    $queue.Enqueue(@{ Path = $s; Depth = $cur.Depth + 1 })
                } catch { }
            }
        } catch { }
    }

    # 2. One-pass file walk for sizes
    # Map: folderPath -> [totalBytes, fileCount]  (case-insensitive keys for UNC paths)
    $sizeMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $folders) {
        $sizeMap[$f.FullName.TrimEnd('\')] = @{ Bytes = [long]0; Files = 0 }
    }

    Write-Host "    Walking files (one pass)..." -ForegroundColor DarkGray
    try {
        $allFiles = [System.IO.Directory]::EnumerateFiles($RootPath, "*", "AllDirectories")
        foreach ($filePath in $allFiles) {
            try {
                $len    = ([System.IO.FileInfo]::new($filePath)).Length
                $parent = [System.IO.Path]::GetDirectoryName($filePath)

                # Add to every ancestor folder up to root
                $cur2 = $parent
                while ($cur2 -ne $null -and $cur2.Length -ge $RootPath.Length) {
                    if ($sizeMap.ContainsKey($cur2)) {
                        $sizeMap[$cur2].Bytes += $len
                        $sizeMap[$cur2].Files += 1
                    }
                    $parent2 = [System.IO.Path]::GetDirectoryName($cur2)
                    if ($parent2 -eq $cur2) { break }
                    $cur2 = $parent2
                }
            } catch { }
        }
    } catch {
        Write-Warn "Partial file walk for $RootPath : $_"
    }

    # 3. Build result objects, compute depth per path
    $rootNorm = $RootPath.TrimEnd('\')

    $result = foreach ($di in $folders) {
        $fp    = $di.FullName.TrimEnd('\')
        $depth = if ($fp -eq $rootNorm) { 0 }
                 else { ($fp.Substring($rootNorm.Length).TrimStart('\') -split '\\').Length }

        $sz = if ($sizeMap.ContainsKey($di.FullName)) { $sizeMap[$di.FullName] }
              else { @{ Bytes = [long]0; Files = 0 } }

        $subCnt = 0
        try { $subCnt = ([System.IO.Directory]::GetDirectories($di.FullName)).Count } catch { }

        [PSCustomObject]@{
            Path            = $di.FullName
            Depth           = $depth
            TotalSizeBytes  = [long]$sz.Bytes
            TotalFiles      = $sz.Files
            Subfolders      = $subCnt
            AceList         = @()         # filled later
            HasAnomaly      = $false      # filled later
        }
    }

    return @($result)
}

# ── Build final folder objects (merge ACLs, resolve SIDs) ────────────────────

function Merge-AclData {
    param(
        [PSObject[]] $Folders,
        [hashtable]  $AclMap
    )

    foreach ($f in $Folders) {
        $entry = $AclMap[$f.Path]
        if (-not $entry) { continue }
        if ($entry.Error) {
            Write-Warn "ACL error on $($f.Path): $($entry.Error)"
            continue
        }

        $resolvedAces = foreach ($ace in $entry.AceList) {
            $displayName = Resolve-Identity $ace.RawIdentity
            $resolved = @{
                Identity         = $displayName
                RawIdentity      = $ace.RawIdentity
                Type             = $ace.Type
                Rights           = $ace.Rights
                IsInherited      = $ace.IsInherited
                InheritanceFlags = $ace.InheritanceFlags
                PropagationFlags = $ace.PropagationFlags
            }
            $resolved.IsAnomaly = Test-IsAnomaly $resolved
            $resolved
        }

        $f.AceList    = @($resolvedAces)
        $f.HasAnomaly = ($f.AceList | Where-Object { $_.IsAnomaly }).Count -gt 0
    }
}

# ── CSV import (rebuild from previous run) ────────────────────────────────────

function Import-FoldersFromCsv([string]$CsvPath) {
    Write-Step "Loading CSV: $CsvPath"
    $rows = Import-Csv -Path $CsvPath -Encoding UTF8

    if (-not $rows -or $rows.Count -eq 0) {
        throw "CSV is empty or could not be read: $CsvPath"
    }

    # Detect whether this CSV has permissions data
    $hasPermissions = ($rows | Where-Object {
        $_.Identity -and $_.Identity -ne "" -and $_.Identity -ne "(no ACEs read)"
    }).Count -gt 0

    Write-Info "  Rows loaded"       $rows.Count
    Write-Info "  Has permissions"   $hasPermissions

    # Group by path -- each path may have multiple ACE rows
    $byPath = $rows | Group-Object -Property Path

    $folders = foreach ($grp in $byPath) {
        $first = $grp.Group[0]

        # Parse numeric fields safely
        $sizeBytes  = [long]0
        $totalFiles = [int]0
        $depth      = [int]0
        $subfolders = [int]0

        if ($first.TotalSizeBytes) { [long]::TryParse($first.TotalSizeBytes, [ref]$sizeBytes)  | Out-Null }
        if ($first.TotalFiles)     { [int]::TryParse($first.TotalFiles,      [ref]$totalFiles) | Out-Null }
        if ($first.Depth)          { [int]::TryParse($first.Depth,           [ref]$depth)      | Out-Null }
        if ($first.Subfolders)     { [int]::TryParse($first.Subfolders,      [ref]$subfolders) | Out-Null }

        # Rebuild ACE list
        $aceList = if ($hasPermissions) {
            foreach ($row in $grp.Group) {
                if (-not $row.Identity -or $row.Identity -eq "(no ACEs read)") { continue }
                $isInherited = $row.Inherited -eq "True"
                $ace = @{
                    Identity         = $row.Identity
                    RawIdentity      = $row.RawIdentity
                    Type             = $row.AccessType
                    Rights           = $row.Rights
                    IsInherited      = $isInherited
                    InheritanceFlags = $row.InheritanceFlags
                    PropagationFlags = $row.PropagationFlags
                }
                $ace.IsAnomaly = Test-IsAnomaly $ace
                $ace
            }
        } else { @() }

        $hasAnomaly = ($first.Anomaly -eq "True") -or
                      ($aceList | Where-Object { $_.IsAnomaly }).Count -gt 0

        [PSCustomObject]@{
            Path            = $first.Path
            Depth           = $depth
            TotalSizeBytes  = $sizeBytes
            TotalFiles      = $totalFiles
            Subfolders      = $subfolders
            AceList         = @($aceList)
            HasAnomaly      = $hasAnomaly
        }
    }

    # Sort by path so the tree renders in order
    $sorted = @($folders | Sort-Object Path)
    Write-Info "  Folders loaded"  $sorted.Count
    return $sorted, $hasPermissions
}

# ── CSV export ────────────────────────────────────────────────────────────────

function Export-PermissionsCsv([PSObject[]]$Folders, [string]$CsvPath) {
    $rows = foreach ($f in $Folders) {
        if ($f.AceList.Count -eq 0) {
            [PSCustomObject]@{
                Path             = $f.Path
                Depth            = $f.Depth
                TotalSize        = Format-Bytes $f.TotalSizeBytes
                TotalSizeBytes   = $f.TotalSizeBytes
                TotalFiles       = $f.TotalFiles
                Identity         = "(no ACEs read)"
                RawIdentity      = ""
                AccessType       = ""
                Rights           = ""
                Inherited        = ""
                InheritanceFlags = ""
                PropagationFlags = ""
                Anomaly          = $f.HasAnomaly
            }
        } else {
            foreach ($ace in $f.AceList) {
                [PSCustomObject]@{
                    Path             = $f.Path
                    Depth            = $f.Depth
                    TotalSize        = Format-Bytes $f.TotalSizeBytes
                    TotalSizeBytes   = $f.TotalSizeBytes
                    TotalFiles       = $f.TotalFiles
                    Identity         = $ace.Identity
                    RawIdentity      = $ace.RawIdentity
                    AccessType       = $ace.Type
                    Rights           = $ace.Rights
                    Inherited        = $ace.IsInherited
                    InheritanceFlags = $ace.InheritanceFlags
                    PropagationFlags = $ace.PropagationFlags
                    Anomaly          = $f.HasAnomaly
                }
            }
        }
    }
    $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
}

# ── HTML generation ───────────────────────────────────────────────────────────

function Build-HtmlReport {
    param(
        [PSObject[]] $Folders,
        [string]     $ClientName,
        [string]     $ReportDate,
        [string[]]   $ScannedPaths,
        [string]     $CsvFilename,
        [bool]       $AnomalyOnly,
        [bool]       $ExcludeBuiltinFlag
    )

    # ── Stats ──────────────────────────────────────────────────────────────────
    $roots          = $Folders | Where-Object { $_.Depth -eq 0 }
    $grandSizeB     = ($roots | Measure-Object TotalSizeBytes -Sum).Sum
    $grandFiles     = ($roots | Measure-Object TotalFiles     -Sum).Sum
    $totalFolders   = $Folders.Count
    $anomalyFolders = ($Folders | Where-Object { $_.HasAnomaly }).Count
    $topFolders     = $Folders | Sort-Object TotalSizeBytes -Descending | Select-Object -First 10
    $anomalies      = $Folders | Where-Object { $_.HasAnomaly }
    $detailFolders  = if ($AnomalyOnly) { $anomalies } else { $Folders }

    $maxSize = ($Folders | Measure-Object TotalSizeBytes -Maximum).Maximum
    if (-not $maxSize -or $maxSize -le 0) { $maxSize = 1 }

    # ── Inner helpers ──────────────────────────────────────────────────────────

    function Size-Bar([long]$bytes) {
        $pct = [Math]::Max(1, [int](($bytes / $maxSize) * 100))
        $col = if ($bytes -gt ($maxSize * 0.75)) { "#c0392b" }
               elseif ($bytes -gt ($maxSize * 0.40)) { "#e67e22" }
               else { "#00A0D9" }
        "<div style=`"background:#eee;border-radius:3px;height:8px;width:100%;min-width:60px;`">" +
        "<div style=`"background:$col;height:8px;border-radius:3px;width:$pct%;`"></div></div>"
    }

    function Short-Rights([string]$r) {
        $r = $r -replace "FullControl",    "Full"
        $r = $r -replace "ReadAndExecute", "R+X"
        $r = $r -replace "Read, Write",    "R+W"
        $r
    }

    function Ace-Badges([hashtable[]]$aces, [bool]$noBuiltin) {
        $sb = [System.Text.StringBuilder]::new()
        foreach ($ace in $aces) {
            $id = $ace.Identity
            if ($noBuiltin -and ($BuiltinNoise | Where-Object { $id -like "*$_*" })) { continue }

            $rights  = Short-Rights $ace.Rights
            $isAllow = $ace.Type -eq "Allow"
            $inh     = $ace.IsInherited
            $anom    = $ace.IsAnomaly

            $bg   = if ($anom)           { "#c0392b" }
                    elseif (-not $isAllow){ "#7f8c8d" }
                    elseif ($inh)         { "#2980b9" }
                    else                  { "#27ae60" }

            $lbl  = if ($isAllow) { "A" } else { "D" }
            $itag = if ($inh)     { "I" } else { "E" }

            $tip  = (Escape-Html $id) + "&#10;" + $ace.Type + ": " + (Escape-Html $ace.Rights) +
                    "&#10;Inherited: " + $inh.ToString()
            if ($ace.RawIdentity -ne $id) { $tip += "&#10;SID: " + (Escape-Html $ace.RawIdentity) }

            $null = $sb.Append(
                "<span title=`"$tip`" style=`"display:inline-block;margin:1px 2px;padding:2px 5px;" +
                "border-radius:3px;background:$bg;color:#fff;font-size:10px;white-space:nowrap;`">" +
                "$lbl$itag&nbsp;" + (Escape-Html $id) + "&nbsp;&bull;&nbsp;" + (Escape-Html $rights) +
                "</span>"
            )
        }
        if ($sb.Length -eq 0) {
            return '<span style="color:#aaa;font-size:10px;">— none shown —</span>'
        }
        $sb.ToString()
    }

    # ── Build row HTML ─────────────────────────────────────────────────────────

    $anomalyRowsHtml = if ($anomalies -and $anomalies.Count -gt 0) {
        $sb2 = [System.Text.StringBuilder]::new()
        foreach ($f in ($anomalies | Sort-Object TotalSizeBytes -Descending | Select-Object -First 50)) {
            $badAces = $f.AceList | Where-Object { $_.IsAnomaly }
            foreach ($ace in $badAces) {
                $null = $sb2.Append(
                    "<tr>" +
                    "<td style='font-family:monospace;font-size:11px;word-break:break-all;'>" + (Escape-Html $f.Path) + "</td>" +
                    "<td>" + (Escape-Html $ace.Identity) +
                        $(if ($ace.RawIdentity -ne $ace.Identity) { " <span style='color:#aaa;font-size:10px;'>(" + (Escape-Html $ace.RawIdentity) + ")</span>" } else { "" }) +
                    "</td>" +
                    "<td>" + (Escape-Html $ace.Rights) + "</td>" +
                    "<td>" + $(if ($ace.IsInherited) { "<span style='color:#2980b9;'>Inherited</span>" } else { "<span style='color:#e67e22;font-weight:bold;'>Explicit</span>" }) + "</td>" +
                    "<td style='text-align:right;white-space:nowrap;'>" + (Format-Bytes $f.TotalSizeBytes) + "</td>" +
                    "</tr>"
                )
            }
        }
        $sb2.ToString()
    } else {
        "<tr><td colspan='5' style='text-align:center;color:#27ae60;padding:16px;'>&#10003; No broad-access anomalies detected.</td></tr>"
    }

    $topRowsHtml = ($topFolders | ForEach-Object {
        "<tr>" +
        "<td style='font-family:monospace;font-size:11px;word-break:break-all;'>" + (Escape-Html $_.Path) + "</td>" +
        "<td style='text-align:right;white-space:nowrap;font-weight:bold;'>" + (Format-Bytes $_.TotalSizeBytes) + "</td>" +
        "<td style='min-width:80px;'>" + (Size-Bar $_.TotalSizeBytes) + "</td>" +
        "<td style='text-align:right;'>" + ("{0:N0}" -f $_.TotalFiles) + "</td>" +
        "</tr>"
    }) -join "`n"

    $detailRowsHtml = ($detailFolders | ForEach-Object {
        $f      = $_
        $aStyle = if ($f.HasAnomaly) { "background:#fff8f6;border-left:3px solid #c0392b;" } else { "" }
        $flag   = if ($f.HasAnomaly) { " &#9888;" } else { "" }
        $indent = 4 + $f.Depth * 16
        $leaf   = Split-Path $f.Path -Leaf
        if (-not $leaf) { $leaf = $f.Path }

        "<tr style='$aStyle'>" +
        "<td style='font-family:monospace;font-size:11px;word-break:break-all;padding-left:${indent}px;'>" +
        (Escape-Html $leaf) + $flag + "</td>" +
        "<td style='text-align:right;white-space:nowrap;'>" + (Format-Bytes $f.TotalSizeBytes) + "</td>" +
        "<td style='min-width:70px;'>" + (Size-Bar $f.TotalSizeBytes) + "</td>" +
        "<td style='text-align:right;'>" + ("{0:N0}" -f $f.TotalFiles) + "</td>" +
        "<td style='text-align:right;'>" + $f.Subfolders + "</td>" +
        "<td style='padding:4px 6px;'>" + (Ace-Badges $f.AceList $ExcludeBuiltinFlag) + "</td>" +
        "</tr>"
    }) -join "`n"

    $pathListHtml  = ($ScannedPaths | ForEach-Object { "<code>" + (Escape-Html $_) + "</code>" }) -join ", "
    $anomalyNote   = if ($AnomalyOnly) {
        "<p style='color:#e67e22;font-style:italic;margin:0 0 8px;'>Showing only anomalous folders. Full tree is in the CSV.</p>"
    } else { "" }
    $builtinNote   = if ($ExcludeBuiltinFlag) {
        "&nbsp;&bull;&nbsp;<em>Built-in system accounts hidden from badges (still in CSV).</em>"
    } else { "" }

    $grandSizeFmt  = Format-Bytes $grandSizeB
    $grandFilesFmt = "{0:N0}" -f $grandFiles
    $totalFoldersFmt = "{0:N0}" -f $totalFolders
    $anomalyTileClass = if ($anomalyFolders -gt 0) { "warn" } else { "" }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>File Server Permissions Report &mdash; $(Escape-Html $ClientName)</title>
<style>
*, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
body  { font-family:'Segoe UI',Arial,sans-serif; font-size:13px; color:#222; background:#f4f6f9; }
a     { color:#00A0D9; }
.header { background:#00A0D9; color:#fff; padding:26px 40px 18px; }
.header h1 { font-size:22px; font-weight:700; letter-spacing:.5px; margin-bottom:4px; }
.header .sub { font-size:13px; opacity:.85; }
.content { max-width:1400px; margin:22px auto; padding:0 22px 48px; }
.card { background:#fff; border-radius:6px; box-shadow:0 1px 4px rgba(0,0,0,.08); margin-bottom:18px; overflow:hidden; }
.card-head { background:#0090c4; color:#fff; padding:9px 16px; font-weight:600; font-size:13px; letter-spacing:.3px; }
.card-head.warn    { background:#c0392b; }
.card-head.neutral { background:#555; }
.card-body { padding:14px 16px; }
.tiles { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
.tile { flex:1 1 150px; background:#fff; border-radius:6px; padding:16px 18px;
        box-shadow:0 1px 4px rgba(0,0,0,.08); border-top:4px solid #00A0D9; }
.tile.warn { border-top-color:#c0392b; }
.tile .num { font-size:26px; font-weight:700; color:#00A0D9; }
.tile.warn .num { color:#c0392b; }
.tile .lbl { font-size:11px; color:#666; margin-top:4px; text-transform:uppercase; letter-spacing:.5px; }
table { border-collapse:collapse; width:100%; font-size:12px; }
th    { background:#f0f4f8; color:#444; font-weight:600; padding:7px 9px;
        text-align:left; border-bottom:2px solid #dde3ea; white-space:nowrap; }
td    { padding:5px 9px; border-bottom:1px solid #eef0f3; vertical-align:top; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:#f7fbfd; }
.legend { display:flex; gap:14px; flex-wrap:wrap; font-size:11px; padding:8px 0 2px; }
.legend span { display:inline-flex; align-items:center; gap:5px; }
.dot { display:inline-block; width:11px; height:11px; border-radius:2px; }
.footer { text-align:center; padding:18px; color:#888; font-size:11px; }
.footer strong { color:#00A0D9; }
</style>
</head>
<body>

<div class="header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px;">
    <div>
      <div style="font-size:10px;opacity:.7;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px;">Pacific Office Automation</div>
      <h1>File Server Permissions &amp; Size Report</h1>
      <div class="sub">Client: <strong>$(Escape-Html $ClientName)</strong> &nbsp;&bull;&nbsp; $ReportDate</div>
      <div class="sub" style="margin-top:3px;font-size:11px;opacity:.8;">Scanned: $pathListHtml</div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:20px;font-weight:800;letter-spacing:1px;">POA</div>
      <div style="font-size:11px;opacity:.7;">Problem Solved.</div>
    </div>
  </div>
</div>

<div class="content">

<div class="tiles">
  <div class="tile"><div class="num">$grandSizeFmt</div><div class="lbl">Total Size Used</div></div>
  <div class="tile"><div class="num">$grandFilesFmt</div><div class="lbl">Total Files</div></div>
  <div class="tile"><div class="num">$totalFoldersFmt</div><div class="lbl">Folders Scanned</div></div>
  <div class="tile $anomalyTileClass"><div class="num">$anomalyFolders</div><div class="lbl">Permission Anomalies</div></div>
</div>

<div class="card">
  <div class="card-head neutral">ACE Badge Legend</div>
  <div class="card-body">
    <div class="legend">
      <span><span class="dot" style="background:#c0392b;"></span> Anomaly Allow (broad write)</span>
      <span><span class="dot" style="background:#27ae60;"></span> Explicit Allow</span>
      <span><span class="dot" style="background:#2980b9;"></span> Inherited Allow</span>
      <span><span class="dot" style="background:#7f8c8d;"></span> Deny</span>
    </div>
    <div style="font-size:11px;color:#666;margin-top:7px;">
      Format: <strong>A</strong>=Allow, <strong>D</strong>=Deny &nbsp;|&nbsp;
      <strong>E</strong>=Explicit, <strong>I</strong>=Inherited &nbsp;|&nbsp;
      Hover a badge for full details. Resolved SIDs shown in tooltip.$builtinNote
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head warn">&#9888; Permission Anomalies &mdash; Broad-Access Entries</div>
  <div class="card-body" style="padding:0;">
    <table>
      <thead><tr>
        <th>Folder Path</th><th>Identity</th><th>Rights</th><th>Inherited?</th><th>Folder Size</th>
      </tr></thead>
      <tbody>$anomalyRowsHtml</tbody>
    </table>
  </div>
</div>

<div class="card">
  <div class="card-head">Top 10 Largest Folders</div>
  <div class="card-body" style="padding:0;">
    <table>
      <thead><tr>
        <th>Folder</th><th style="text-align:right;">Total Size</th><th style="min-width:100px;"></th><th style="text-align:right;">Files</th>
      </tr></thead>
      <tbody>$topRowsHtml</tbody>
    </table>
  </div>
</div>

<div class="card">
  <div class="card-head">Folder Permissions &amp; Size Detail</div>
  <div class="card-body">
    $anomalyNote
    <p style="font-size:11px;color:#666;margin-bottom:8px;">
      Full ACE data (all accounts, all folders) exported to: <strong>$(Escape-Html $CsvFilename)</strong>
    </p>
  </div>
  <div style="overflow-x:auto;">
    <table>
      <thead><tr>
        <th>Folder</th>
        <th style="text-align:right;">Total Size</th>
        <th style="min-width:80px;"></th>
        <th style="text-align:right;">Files</th>
        <th style="text-align:right;">Subfolders</th>
        <th>Permissions (hover for details)</th>
      </tr></thead>
      <tbody>$detailRowsHtml</tbody>
    </table>
  </div>
</div>

</div>

<div class="footer">
  <strong>Pacific Office Automation</strong> &mdash; Problem Solved.<br>
  Report prepared by Yeyland Wutani LLC &nbsp;&bull;&nbsp; $ReportDate<br>
  <span style="font-size:10px;color:#bbb;">Confidential &mdash; intended solely for $(Escape-Html $ClientName).</span>
</div>

</body></html>
"@
}

# ── Storage-only HTML report ──────────────────────────────────────────────────

function Build-StorageHtmlReport {
    param(
        [PSObject[]] $Folders,
        [string]     $ClientName,
        [string]     $ReportDate,
        [string[]]   $ScannedPaths,
        [string]     $CsvFilename
    )

    # ── Stats ──────────────────────────────────────────────────────────────────
    $roots        = @($Folders | Where-Object { $_.Depth -eq 0 })
    $grandSizeB   = ($roots | Measure-Object TotalSizeBytes -Sum).Sum
    $grandFiles   = ($roots | Measure-Object TotalFiles     -Sum).Sum
    $totalFolders = $Folders.Count
    $shareCount   = $roots.Count

    if (-not $grandSizeB) { $grandSizeB = [long]0 }
    if (-not $grandFiles)  { $grandFiles  = 0 }

    $maxShareSize = ($roots | Measure-Object TotalSizeBytes -Maximum).Maximum
    if (-not $maxShareSize -or $maxShareSize -le 0) { $maxShareSize = 1 }

    $maxFolderSize = ($Folders | Measure-Object TotalSizeBytes -Maximum).Maximum
    if (-not $maxFolderSize -or $maxFolderSize -le 0) { $maxFolderSize = 1 }

    $top25 = $Folders | Sort-Object TotalSizeBytes -Descending | Select-Object -First 25

    # ── Per-share summary rows ─────────────────────────────────────────────────
    $shareRowsHtml = ($roots | Sort-Object TotalSizeBytes -Descending | ForEach-Object {
        $pct  = [Math]::Max(1, [int](($_.TotalSizeBytes / $maxShareSize) * 100))
        $col  = if ($_.TotalSizeBytes -gt ($maxShareSize * 0.75)) { "#c0392b" }
                elseif ($_.TotalSizeBytes -gt ($maxShareSize * 0.40)) { "#e67e22" }
                else { "#00A0D9" }
        $shareName = Split-Path $_.Path -Leaf
        if (-not $shareName) { $shareName = $_.Path }
        "<tr>" +
        "<td style='font-weight:600;'>" + (Escape-Html $shareName) + "</td>" +
        "<td style='font-family:monospace;font-size:11px;color:#888;'>" + (Escape-Html $_.Path) + "</td>" +
        "<td style='text-align:right;white-space:nowrap;font-weight:700;font-size:13px;'>" + (Format-Bytes $_.TotalSizeBytes) + "</td>" +
        "<td style='min-width:120px;padding:8px 10px;'>" +
          "<div style='background:#eee;border-radius:3px;height:10px;'>" +
          "<div style='background:$col;height:10px;border-radius:3px;width:$pct%;'></div></div></td>" +
        "<td style='text-align:right;'>" + ("{0:N0}" -f $_.TotalFiles) + "</td>" +
        "<td style='text-align:right;'>" + $_.Subfolders + "</td>" +
        "</tr>"
    }) -join "`n"

    # ── Top 25 largest folders rows ────────────────────────────────────────────
    $topRowsHtml = ($top25 | ForEach-Object {
        $pct = [Math]::Max(1, [int](($_.TotalSizeBytes / $maxFolderSize) * 100))
        $col = if ($_.TotalSizeBytes -gt ($maxFolderSize * 0.75)) { "#c0392b" }
               elseif ($_.TotalSizeBytes -gt ($maxFolderSize * 0.40)) { "#e67e22" }
               else { "#00A0D9" }
        "<tr>" +
        "<td style='font-family:monospace;font-size:11px;word-break:break-all;'>" + (Escape-Html $_.Path) + "</td>" +
        "<td style='text-align:right;white-space:nowrap;font-weight:700;'>" + (Format-Bytes $_.TotalSizeBytes) + "</td>" +
        "<td style='min-width:100px;padding:8px 10px;'>" +
          "<div style='background:#eee;border-radius:3px;height:8px;'>" +
          "<div style='background:$col;height:8px;border-radius:3px;width:$pct%;'></div></div></td>" +
        "<td style='text-align:right;'>" + ("{0:N0}" -f $_.TotalFiles) + "</td>" +
        "</tr>"
    }) -join "`n"

    # ── Folder tree rows ───────────────────────────────────────────────────────
    $treeRowsHtml = ($Folders | ForEach-Object {
        $f    = $_
        $pct  = [Math]::Max(1, [int](($f.TotalSizeBytes / $maxFolderSize) * 100))
        $col  = if ($f.TotalSizeBytes -gt ($maxFolderSize * 0.75)) { "#c0392b" }
                elseif ($f.TotalSizeBytes -gt ($maxFolderSize * 0.40)) { "#e67e22" }
                else { "#00A0D9" }
        $leaf = Split-Path $f.Path -Leaf
        if (-not $leaf) { $leaf = $f.Path }
        $pad  = 4 + $f.Depth * 16

        "<tr>" +
        "<td style='font-family:monospace;font-size:11px;word-break:break-all;padding-left:${pad}px;'>" + (Escape-Html $leaf) + "</td>" +
        "<td style='text-align:right;white-space:nowrap;font-weight:" + $(if ($f.Depth -le 1) {"600"} else {"400"}) + ";'>" + (Format-Bytes $f.TotalSizeBytes) + "</td>" +
        "<td style='min-width:80px;padding:7px 10px;'>" +
          "<div style='background:#eee;border-radius:3px;height:7px;'>" +
          "<div style='background:$col;height:7px;border-radius:3px;width:$pct%;'></div></div></td>" +
        "<td style='text-align:right;color:#888;'>" + ("{0:N0}" -f $f.TotalFiles) + "</td>" +
        "<td style='text-align:right;color:#888;'>" + $f.Subfolders + "</td>" +
        "</tr>"
    }) -join "`n"

    $pathListHtml = ($ScannedPaths | ForEach-Object { "<code>" + (Escape-Html $_) + "</code>" }) -join ", "

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Storage Report &mdash; $(Escape-Html $ClientName)</title>
<style>
*, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
body  { font-family:'Segoe UI',Arial,sans-serif; font-size:13px; color:#222; background:#f4f6f9; }
.header { background:#00A0D9; color:#fff; padding:26px 40px 18px; }
.header h1 { font-size:22px; font-weight:700; letter-spacing:.5px; margin-bottom:4px; }
.header .sub { font-size:13px; opacity:.85; }
.content { max-width:1300px; margin:22px auto; padding:0 22px 48px; }
.card { background:#fff; border-radius:6px; box-shadow:0 1px 4px rgba(0,0,0,.08); margin-bottom:18px; overflow:hidden; }
.card-head { background:#0090c4; color:#fff; padding:9px 16px; font-weight:600; font-size:13px; }
.card-body { padding:14px 16px; }
.tiles { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
.tile { flex:1 1 150px; background:#fff; border-radius:6px; padding:16px 18px;
        box-shadow:0 1px 4px rgba(0,0,0,.08); border-top:4px solid #00A0D9; }
.tile .num { font-size:26px; font-weight:700; color:#00A0D9; }
.tile .lbl { font-size:11px; color:#666; margin-top:4px; text-transform:uppercase; letter-spacing:.5px; }
table { border-collapse:collapse; width:100%; font-size:12px; }
th    { background:#f0f4f8; color:#444; font-weight:600; padding:7px 10px;
        text-align:left; border-bottom:2px solid #dde3ea; white-space:nowrap; }
td    { padding:5px 10px; border-bottom:1px solid #eef0f3; vertical-align:middle; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:#f7fbfd; }
.footer { text-align:center; padding:18px; color:#888; font-size:11px; }
.footer strong { color:#00A0D9; }
</style>
</head>
<body>

<div class="header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px;">
    <div>
      <div style="font-size:10px;opacity:.7;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px;">Pacific Office Automation</div>
      <h1>File Server Storage Report</h1>
      <div class="sub">Client: <strong>$(Escape-Html $ClientName)</strong> &nbsp;&bull;&nbsp; $ReportDate</div>
      <div class="sub" style="margin-top:3px;font-size:11px;opacity:.8;">Scanned: $pathListHtml</div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:20px;font-weight:800;letter-spacing:1px;">POA</div>
      <div style="font-size:11px;opacity:.7;">Problem Solved.</div>
    </div>
  </div>
</div>

<div class="content">

<div class="tiles">
  <div class="tile"><div class="num">$(Format-Bytes $grandSizeB)</div><div class="lbl">Total Storage Used</div></div>
  <div class="tile"><div class="num">$("{0:N0}" -f $grandFiles)</div><div class="lbl">Total Files</div></div>
  <div class="tile"><div class="num">$("{0:N0}" -f $totalFolders)</div><div class="lbl">Folders Scanned</div></div>
  <div class="tile"><div class="num">$shareCount</div><div class="lbl">Shares</div></div>
</div>

<div class="card">
  <div class="card-head">Storage by Share</div>
  <div style="overflow-x:auto;">
    <table>
      <thead><tr>
        <th>Share</th><th>Path</th>
        <th style="text-align:right;">Total Size</th>
        <th style="min-width:130px;"></th>
        <th style="text-align:right;">Files</th>
        <th style="text-align:right;">Subfolders</th>
      </tr></thead>
      <tbody>$shareRowsHtml</tbody>
    </table>
  </div>
</div>

<div class="card">
  <div class="card-head">Top 25 Largest Folders</div>
  <div style="overflow-x:auto;">
    <table>
      <thead><tr>
        <th>Folder Path</th>
        <th style="text-align:right;">Total Size</th>
        <th style="min-width:110px;"></th>
        <th style="text-align:right;">Files</th>
      </tr></thead>
      <tbody>$topRowsHtml</tbody>
    </table>
  </div>
</div>

<div class="card">
  <div class="card-head">Folder Size Tree</div>
  <div class="card-body" style="padding-bottom:0;">
    <p style="font-size:11px;color:#666;margin-bottom:8px;">Full folder data exported to: <strong>$(Escape-Html $CsvFilename)</strong></p>
  </div>
  <div style="overflow-x:auto;">
    <table>
      <thead><tr>
        <th>Folder</th>
        <th style="text-align:right;">Total Size</th>
        <th style="min-width:90px;"></th>
        <th style="text-align:right;">Files</th>
        <th style="text-align:right;">Subfolders</th>
      </tr></thead>
      <tbody>$treeRowsHtml</tbody>
    </table>
  </div>
</div>

</div>

<div class="footer">
  <strong>Pacific Office Automation</strong> &mdash; Problem Solved.<br>
  Report prepared by Yeyland Wutani LLC &nbsp;&bull;&nbsp; $ReportDate<br>
  <span style="font-size:10px;color:#bbb;">Confidential &mdash; intended solely for $(Escape-Html $ClientName).</span>
</div>

</body></html>
"@
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

Write-Banner

if (-not (Test-Path $OutputDir -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$reportDate  = (Get-Date).ToString("yyyy-MM-dd HH:mm")
$safeName    = ($ClientName -replace '[^\w\-]', '_')
$ts          = (Get-Date).ToString("yyyyMMdd_HHmm")
$htmlFile    = Join-Path $OutputDir "${safeName}_FileServerReport_${ts}.html"
$csvFile     = Join-Path $OutputDir "${safeName}_FileServerReport_${ts}.csv"
$csvBasename = Split-Path $csvFile -Leaf

Write-Info "Client"  $ClientName
Write-Info "HTML output"  $htmlFile
Write-Info "CSV output"   $csvFile
Write-Host ""

# ══ FROM-CSV PATH ══════════════════════════════════════════════════════════════
if ($PSCmdlet.ParameterSetName -eq "FromCsv") {

    if (-not (Test-Path $FromCsv -PathType Leaf)) {
        Write-Host "`n  [ERROR] CSV file not found: $FromCsv`n" -ForegroundColor Red
        exit 1
    }

    $importResult    = Import-FoldersFromCsv -CsvPath $FromCsv
    $allFolders      = $importResult[0]
    $csvHasPerms     = $importResult[1]

    # Auto-detect storage-only if CSV has no permission data
    if (-not $csvHasPerms -and -not $StorageOnly) {
        Write-Info "  Auto-mode" "StorageOnly (no permission data in CSV)"
        $StorageOnly = $true
    }

    # Derive scanned paths from the depth-0 folder entries
    $scanPaths = @($allFolders | Where-Object { $_.Depth -eq 0 } | ForEach-Object { $_.Path })
    # Use the source CSV filename for the report reference
    $csvBasename = Split-Path $FromCsv -Leaf

    Write-Host ""

} else {
# ══ LIVE SCAN PATH ═════════════════════════════════════════════════════════════

Write-Info "Mode"      $(if ($StorageOnly) { "Storage only (no ACL collection)" } else { "Full (storage + permissions)" })
Write-Info "Max depth" $MaxDepth
if (-not $StorageOnly) { Write-Info "Runspaces" $MaxRunspaces }
Write-Host ""

# ── Determine scan paths ──────────────────────────────────────────────────────
if ($PSCmdlet.ParameterSetName -eq "ByServer") {
    $scanPaths = @(Get-ServerShares -ServerName $Server)
    if ($scanPaths.Count -eq 0) {
        Write-Host "`n  [ERROR] No shares found on $Server.`n" -ForegroundColor Red
        exit 1
    }
} else {
    $scanPaths = $Path
}

Write-Info "Scan paths" ($scanPaths -join "; ")
Write-Host ""

# ── Phase 1: Enumerate folders + sizes ───────────────────────────────────────
$allFolders = [System.Collections.Generic.List[PSObject]]::new()

foreach ($p in $scanPaths) {
    if (-not (Test-Path $p -PathType Container -ErrorAction SilentlyContinue)) {
        Write-Warn "Path not accessible, skipping: $p"
        continue
    }
    Write-Step "Enumerating folders + sizes: $p"
    $scan = Get-AllFolders -RootPath $p -MaxDepth $MaxDepth
    foreach ($item in $scan) { $allFolders.Add($item) }
    Write-Info "  Folders found" $scan.Count
}

if ($allFolders.Count -eq 0) {
    Write-Host "`n  [ERROR] No folders scanned. Check paths and permissions.`n" -ForegroundColor Red
    exit 1
}

# ── Phase 2: Collect ACLs (full mode only) ────────────────────────────────────
if (-not $StorageOnly) {
    Write-Step ("Collecting ACLs for {0:N0} folders using {1} runspaces..." -f $allFolders.Count, $MaxRunspaces)
    $folderPaths = $allFolders | ForEach-Object { $_.Path }
    $aclMap      = Get-AclsParallel -FolderPaths $folderPaths -MaxRunspaces $MaxRunspaces

    # ── Phase 3: Merge ACLs + resolve SIDs ───────────────────────────────────
    Write-Step "Resolving SIDs and merging ACL data..."
    Merge-AclData -Folders $allFolders -AclMap $aclMap

    $anomalyCount = ($allFolders | Where-Object { $_.HasAnomaly }).Count
    $sidCount     = ($Script:SidCache.Keys | Where-Object { $_ -match '^S-\d' }).Count
    Write-Info "Anomalous folders" $anomalyCount
    Write-Info "SIDs resolved"     $sidCount
    Write-Host ""
}

Write-Info "Total folders" $allFolders.Count
Write-Host ""

} # end live-scan path

# ── Phase 4: Export ───────────────────────────────────────────────────────────
if ($PSCmdlet.ParameterSetName -ne "FromCsv") {
    Write-Step "Writing CSV..."
    Export-PermissionsCsv -Folders $allFolders -CsvPath $csvFile
} else {
    Write-Step "Skipping CSV write (using source CSV)"
}

Write-Step "Building HTML report..."
$html = if ($StorageOnly) {
    Build-StorageHtmlReport `
        -Folders      $allFolders `
        -ClientName   $ClientName `
        -ReportDate   $reportDate `
        -ScannedPaths $scanPaths `
        -CsvFilename  $csvBasename
} else {
    Build-HtmlReport `
        -Folders            $allFolders `
        -ClientName         $ClientName `
        -ReportDate         $reportDate `
        -ScannedPaths       $scanPaths `
        -CsvFilename        $csvBasename `
        -AnomalyOnly        $AnomalyGroupsOnly.IsPresent `
        -ExcludeBuiltinFlag $ExcludeBuiltin.IsPresent
}

[System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
Write-Host "  Report complete." -ForegroundColor Green
Write-Host "    HTML : $htmlFile" -ForegroundColor White
Write-Host "    CSV  : $csvFile"  -ForegroundColor White
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
Write-Host ""

if ([Environment]::UserInteractive) {
    $open = Read-Host "  Open report in browser? [Y/n]"
    if ($open -ne 'n' -and $open -ne 'N') { Start-Process $htmlFile }
}
