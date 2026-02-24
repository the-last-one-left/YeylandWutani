#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Online Archive mailboxes by temporarily licensing users to access archive data.

.DESCRIPTION
    Iterates through mailboxes in a source tenant post-migration to audit Online Archive
    mailbox data. For each user:
      1. Dynamically identifies a tenant license that includes Exchange Online archiving
      2. Assigns the license temporarily
      3. Waits for archive mailbox provisioning
      4. Retrieves primary mailbox statistics (size, item count, last logon)
      5. Retrieves archive mailbox statistics (size, item count, dates)
      6. Removes the temporary license
      7. Exports results to CSV (incremental) and a YW-branded HTML report

    Designed for scenarios where archive mailboxes did not migrate and need auditing
    before decommissioning the source tenant. License detection is dynamic - the script
    identifies any available SKU containing Exchange Online (Plan 2) capability rather
    than requiring a specific license SKU.

.PARAMETER InputCsv
    Optional. Path to CSV file containing a UserPrincipalName column.
    If not specified, processes all enabled member accounts in the tenant.

.PARAMETER OutputPath
    Base path for output files (without extension).
    Defaults to ArchiveMailboxAudit_<timestamp> in the current directory.
    The script appends .csv and .html automatically.

.PARAMETER WaitTimeSeconds
    Seconds to wait for archive provisioning after license assignment.
    Default: 180 (3 minutes). Microsoft states provisioning can take up to 30 minutes.

.PARAMETER MaxRetries
    Maximum retry attempts when checking for archive mailbox after the initial wait.
    Default: 3 retries at 60-second intervals.

.NOTES
    Author:      Yeyland Wutani LLC
    Tagline:     Building Better Systems
    Version:     2.1
    Requires:    Microsoft.Graph.Users module
                 ExchangeOnlineManagement module
    Permissions: User.ReadWrite.All, Organization.Read.All (Graph)
                 Exchange Administrator or Global Administrator role

.EXAMPLE
    .\Audit-ArchiveMailboxes.ps1 -OutputPath "C:\Reports\ArchiveAudit"

    Processes all user mailboxes. Outputs C:\Reports\ArchiveAudit.csv and
    C:\Reports\ArchiveAudit.html.

.EXAMPLE
    .\Audit-ArchiveMailboxes.ps1 -InputCsv "C:\Users.csv" -WaitTimeSeconds 240

    Processes users from CSV with a 4-minute provisioning wait.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\ArchiveMailboxAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(Mandatory = $false)]
    [ValidateRange(60, 1800)]
    [int]$WaitTimeSeconds = 180,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3
)

#region Banner

function Show-YWBanner {
    $banner = @"
  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___
  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|
   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || |
    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|

                        B U I L D I N G   B E T T E R   S Y S T E M S
"@
    $border = "=" * 84
    Write-Host ""
    Write-Host $border -ForegroundColor Gray
    Write-Host $banner -ForegroundColor DarkYellow
    Write-Host $border -ForegroundColor Gray
    Write-Host ""
}

#endregion Banner

#region Logging

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        Info    = "Cyan"
        Warning = "Yellow"
        Error   = "Red"
        Success = "Green"
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

#endregion Logging

#region HTML Report

function New-HtmlReport {
    <#
    .SYNOPSIS
        Generates a Yeyland Wutani branded HTML report from audit results.

    .PARAMETER Results
        Array of result objects from the audit run.

    .PARAMETER HtmlPath
        Output path for the HTML file.

    .PARAMETER TenantDomain
        Tenant domain name displayed in the report header.

    .PARAMETER LicenseSkuUsed
        License SKU name used during the audit run.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $false)]
        [string]$TenantDomain = "Unknown Tenant",

        [Parameter(Mandatory = $false)]
        [string]$LicenseSkuUsed = "N/A"
    )

    # Summary stats
    $totalUsers    = $Results.Count
    $withArchive   = ($Results | Where-Object { $_.HasArchive }).Count
    $noArchive     = $totalUsers - $withArchive
    $licenseErrors = ($Results | Where-Object { -not $_.LicenseAssigned }).Count
    $totalPrimGB   = [math]::Round(($Results | Where-Object { $_.PrimaryTotalItemSizeGB } |
                        Measure-Object -Property PrimaryTotalItemSizeGB -Sum).Sum, 2)
    $totalArchGB   = [math]::Round(($Results | Where-Object { $_.ArchiveTotalItemSizeGB } |
                        Measure-Object -Property ArchiveTotalItemSizeGB -Sum).Sum, 2)
    $reportDate    = Get-Date -Format "MMMM dd, yyyy HH:mm"

    # Top 10 archive sizes for bar chart
    $top10 = $Results |
        Where-Object { $_.ArchiveTotalItemSizeGB -gt 0 } |
        Sort-Object ArchiveTotalItemSizeGB -Descending |
        Select-Object -First 10

    $maxGB = if ($top10) { ($top10 | Measure-Object -Property ArchiveTotalItemSizeGB -Maximum).Maximum } else { 1 }

    $barRows = foreach ($r in $top10) {
        $pct   = [math]::Round(($r.ArchiveTotalItemSizeGB / $maxGB) * 100, 1)
        $label = if ($r.DisplayName) { $r.DisplayName } else { $r.UserPrincipalName }
        "                <div class=`"bar-item`">
                    <div class=`"bar-label`" title=`"$($r.UserPrincipalName)`">$label</div>
                    <div class=`"bar-track`">
                        <div class=`"bar-fill`" style=`"width:$pct%`">
                            <span class=`"bar-value`">$($r.ArchiveTotalItemSizeGB) GB</span>
                        </div>
                    </div>
                </div>"
    }

    # Table rows - sorted by archive size descending, no-archive users at bottom
    $tableRows = foreach ($r in ($Results | Sort-Object @{E={if($_.HasArchive){1}else{0}};D=$true}, ArchiveTotalItemSizeGB -Descending)) {
        $rowClass = if ($r.HasArchive) { "row-archive" } elseif (-not $r.LicenseAssigned) { "row-error" } else { "row-none" }

        $archiveBadge = if ($r.HasArchive) {
            '<span class="badge badge-success">Yes</span>'
        } elseif (-not $r.LicenseAssigned) {
            '<span class="badge badge-danger">License Error</span>'
        } else {
            '<span class="badge badge-none">No</span>'
        }

        $primGB     = if ($null -ne $r.PrimaryTotalItemSizeGB) { $r.PrimaryTotalItemSizeGB } else { "&#8212;" }
        $primItems  = if ($null -ne $r.PrimaryItemCount)       { '{0:N0}' -f $r.PrimaryItemCount } else { "&#8212;" }
        $primLogon  = if ($r.PrimaryLastLogonTime)             { ([datetime]$r.PrimaryLastLogonTime).ToString("yyyy-MM-dd") } else { "&#8212;" }
        $archGB     = if ($null -ne $r.ArchiveTotalItemSizeGB) { $r.ArchiveTotalItemSizeGB } else { "&#8212;" }
        $archItems  = if ($null -ne $r.ArchiveItemCount)       { '{0:N0}' -f $r.ArchiveItemCount } else { "&#8212;" }
        $archOldest = if ($r.ArchiveOldestItemDate)            { ([datetime]$r.ArchiveOldestItemDate).ToString("yyyy-MM-dd") } else { "&#8212;" }
        $archNewest = if ($r.ArchiveNewestItemDate)            { ([datetime]$r.ArchiveNewestItemDate).ToString("yyyy-MM-dd") } else { "&#8212;" }
        $archLogon  = if ($r.ArchiveLastLogonTime)             { ([datetime]$r.ArchiveLastLogonTime).ToString("yyyy-MM-dd") } else { "&#8212;" }
        $noteIcon   = if ($r.Notes) { " <span class=`"note-icon`" title=`"$([System.Web.HttpUtility]::HtmlEncode($r.Notes))`">&#9432;</span>" } else { "" }

        "        <tr class=`"$rowClass`">
            <td class=`"upn-cell`">
                <div class=`"upn-wrap`" title=`"$($r.UserPrincipalName)`">$($r.UserPrincipalName)</div>
                <div class=`"dn-wrap`">$($r.DisplayName)</div>
            </td>
            <td>$archiveBadge$noteIcon</td>
            <td class=`"num`">$primGB</td>
            <td class=`"num`">$primItems</td>
            <td class=`"date`">$primLogon</td>
            <td class=`"num`">$archGB</td>
            <td class=`"num`">$archItems</td>
            <td class=`"date`">$archOldest</td>
            <td class=`"date`">$archNewest</td>
            <td class=`"date`">$archLogon</td>
        </tr>"
    }

    $barSection = if ($top10) {
        @"
    <div class="panel">
        <div class="panel-header"><span class="accent">&#9646;</span> Top Archive Mailboxes by Size</div>
        <div class="panel-body">
$($barRows -join "`n")
        </div>
    </div>
"@
    } else { "" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Archive Mailbox Audit - Yeyland Wutani LLC</title>
    <style>
        :root {
            --yw-orange:       #FF6600;
            --yw-dark-orange:  #CC5200;
            --yw-light-orange: #FFF3E6;
            --yw-grey:         #6B7280;
            --yw-dark:         #1F2937;
            --yw-light:        #F3F4F6;
            --yw-white:        #FFFFFF;
            --success:         #10B981;
            --warning:         #F59E0B;
            --danger:          #EF4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--yw-light);
            color: var(--yw-dark);
            line-height: 1.5;
            font-size: 13px;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--yw-dark) 0%, #374151 100%);
            color: var(--yw-white);
            padding: 1.75rem 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 4px solid var(--yw-orange);
        }
        .header h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.2rem; }
        .header .subtitle { color: var(--yw-grey); font-size: 0.82rem; }
        .company-block { text-align: right; }
        .company-name { font-size: 1.05rem; font-weight: 700; color: var(--yw-orange); }
        .tagline-text { font-size: 0.68rem; letter-spacing: 2px; text-transform: uppercase; color: var(--yw-grey); margin-top: 2px; }
        .report-date { font-size: 0.78rem; color: #9CA3AF; margin-top: 4px; }

        /* Container */
        .container { max-width: 1440px; margin: 0 auto; padding: 1.75rem 2rem; }

        /* Summary cards */
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .card {
            background: var(--yw-white);
            border-radius: 8px;
            padding: 1.1rem 1rem;
            text-align: center;
            box-shadow: 0 1px 4px rgba(0,0,0,0.07);
            border-top: 4px solid var(--yw-orange);
        }
        .card.success { border-top-color: var(--success); }
        .card.warning { border-top-color: var(--warning); }
        .card.danger  { border-top-color: var(--danger); }
        .card.grey    { border-top-color: var(--yw-grey); }
        .card .num-big { font-size: 2.1rem; font-weight: 700; line-height: 1; margin-bottom: 0.35rem; color: var(--yw-dark); }
        .card .card-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 1px; color: var(--yw-grey); font-weight: 600; }

        /* Panels */
        .panel { background: var(--yw-white); border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.07); margin-bottom: 1.5rem; overflow: hidden; }
        .panel-header {
            background: var(--yw-dark);
            color: var(--yw-white);
            padding: 0.75rem 1.2rem;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .panel-header .accent { color: var(--yw-orange); }
        .panel-body { padding: 1.2rem; }

        /* Run info grid */
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.4rem 1.5rem; }
        .meta-row { display: flex; gap: 0.5rem; font-size: 0.82rem; padding: 0.25rem 0; border-bottom: 1px solid #F3F4F6; }
        .meta-label { color: var(--yw-grey); font-weight: 600; min-width: 155px; }
        .meta-value { color: var(--yw-dark); }
        .meta-value.yw { color: var(--yw-orange); font-weight: 700; }

        /* Bar chart */
        .bar-item { display: flex; align-items: center; gap: 10px; margin-bottom: 7px; }
        .bar-label { width: 190px; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 500; flex-shrink: 0; }
        .bar-track { flex: 1; height: 21px; background: var(--yw-light); border-radius: 4px; overflow: hidden; }
        .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--yw-orange), var(--yw-dark-orange));
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 8px;
            min-width: 44px;
        }
        .bar-value { font-size: 10px; color: white; font-weight: 700; white-space: nowrap; }

        /* Filter bar */
        .filter-bar { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.9rem; }
        .filter-bar label { font-size: 0.8rem; font-weight: 600; color: var(--yw-grey); white-space: nowrap; }
        .filter-bar input[type="text"] {
            flex: 1; min-width: 180px; padding: 0.4rem 0.7rem;
            border: 1px solid #D1D5DB; border-radius: 6px; font-size: 0.82rem; outline: none;
        }
        .filter-bar input[type="text"]:focus { border-color: var(--yw-orange); box-shadow: 0 0 0 2px var(--yw-light-orange); }
        .filter-bar select {
            padding: 0.4rem 0.7rem; border: 1px solid #D1D5DB; border-radius: 6px;
            font-size: 0.82rem; background: var(--yw-white); outline: none; cursor: pointer;
        }
        .filter-bar select:focus { border-color: var(--yw-orange); }
        #row-count { font-size: 0.78rem; color: var(--yw-grey); margin-left: auto; white-space: nowrap; }

        /* Table */
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        thead th {
            background: var(--yw-dark);
            color: var(--yw-white);
            padding: 0.6rem 0.7rem;
            text-align: left;
            font-weight: 600;
            white-space: nowrap;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 1;
        }
        thead th:hover { background: #374151; }
        thead th .si { opacity: 0.35; font-size: 9px; margin-left: 3px; }
        thead th.asc  .si::after { content: " \25B2"; opacity: 1; }
        thead th.desc .si::after { content: " \25BC"; opacity: 1; }
        tbody tr { border-bottom: 1px solid #F3F4F6; }
        tbody tr:hover { background: var(--yw-light-orange) !important; }
        tbody td { padding: 0.5rem 0.7rem; vertical-align: middle; }

        tr.row-archive { background: #F0FDF4; }
        tr.row-none    { background: var(--yw-white); }
        tr.row-error   { background: #FEF2F2; }

        .num  { text-align: right; font-variant-numeric: tabular-nums; }
        .date { white-space: nowrap; }

        .upn-cell { max-width: 260px; }
        .upn-wrap { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .dn-wrap  { color: var(--yw-grey); font-size: 11px; }

        .badge { display: inline-block; padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }
        .badge-success { background: #D1FAE5; color: #065F46; }
        .badge-none    { background: #F3F4F6; color: #6B7280; }
        .badge-danger  { background: #FEE2E2; color: #991B1B; }

        .note-icon { color: var(--yw-orange); cursor: help; font-size: 13px; vertical-align: middle; margin-left: 3px; }

        /* Footer */
        .footer { text-align: center; padding: 1.75rem; color: var(--yw-grey); font-size: 11px; }
        .footer .ft { color: var(--yw-orange); font-weight: 700; font-size: 12px; letter-spacing: 1px; margin-bottom: 4px; }

        @media print { .filter-bar { display: none; } body { background: white; } }
    </style>
</head>
<body>

<div class="header">
    <div>
        <h1>Archive Mailbox Audit</h1>
        <div class="subtitle">Tenant: $TenantDomain</div>
    </div>
    <div class="company-block">
        <div class="company-name">Yeyland Wutani LLC</div>
        <div class="tagline-text">Building Better Systems</div>
        <div class="report-date">Generated: $reportDate</div>
    </div>
</div>

<div class="container">

    <div class="cards">
        <div class="card">
            <div class="num-big">$totalUsers</div>
            <div class="card-label">Users Processed</div>
        </div>
        <div class="card success">
            <div class="num-big">$withArchive</div>
            <div class="card-label">Archives Found</div>
        </div>
        <div class="card grey">
            <div class="num-big">$noArchive</div>
            <div class="card-label">No Archive</div>
        </div>
        <div class="card $(if ($licenseErrors -gt 0) { 'danger' } else { 'success' })">
            <div class="num-big">$licenseErrors</div>
            <div class="card-label">License Errors</div>
        </div>
        <div class="card">
            <div class="num-big">$totalPrimGB</div>
            <div class="card-label">Primary Size (GB)</div>
        </div>
        <div class="card warning">
            <div class="num-big">$totalArchGB</div>
            <div class="card-label">Archive Size (GB)</div>
        </div>
    </div>

    <div class="panel">
        <div class="panel-header"><span class="accent">&#9432;</span> Audit Run Details</div>
        <div class="panel-body">
            <div class="meta-grid">
                <div class="meta-row"><span class="meta-label">Tenant</span><span class="meta-value">$TenantDomain</span></div>
                <div class="meta-row"><span class="meta-label">License SKU Used</span><span class="meta-value yw">$LicenseSkuUsed</span></div>
                <div class="meta-row"><span class="meta-label">Provisioning Wait</span><span class="meta-value">$WaitTimeSeconds seconds</span></div>
                <div class="meta-row"><span class="meta-label">Max Retries</span><span class="meta-value">$MaxRetries</span></div>
                <div class="meta-row"><span class="meta-label">Report Generated</span><span class="meta-value">$reportDate</span></div>
                <div class="meta-row"><span class="meta-label">Script Version</span><span class="meta-value">2.1</span></div>
            </div>
        </div>
    </div>

$barSection

    <div class="panel">
        <div class="panel-header"><span class="accent">&#9776;</span> All Results</div>
        <div class="panel-body">
            <div class="filter-bar">
                <label>Search:</label>
                <input type="text" id="searchInput" placeholder="Filter by UPN or display name..." onkeyup="applyFilters()">
                <label>Archive:</label>
                <select id="archiveFilter" onchange="applyFilters()">
                    <option value="all">All Users</option>
                    <option value="yes">Has Archive</option>
                    <option value="no">No Archive</option>
                    <option value="error">License Error</option>
                </select>
                <span id="row-count"></span>
            </div>
            <div class="table-wrap">
                <table id="tbl">
                    <thead>
                        <tr>
                            <th onclick="sortBy(0)">User <span class="si"></span></th>
                            <th onclick="sortBy(1)">Archive <span class="si"></span></th>
                            <th onclick="sortBy(2)" class="num">Primary (GB) <span class="si"></span></th>
                            <th onclick="sortBy(3)" class="num">Primary Items <span class="si"></span></th>
                            <th onclick="sortBy(4)">Primary Last Logon <span class="si"></span></th>
                            <th onclick="sortBy(5)" class="num">Archive (GB) <span class="si"></span></th>
                            <th onclick="sortBy(6)" class="num">Archive Items <span class="si"></span></th>
                            <th onclick="sortBy(7)">Oldest Item <span class="si"></span></th>
                            <th onclick="sortBy(8)">Newest Item <span class="si"></span></th>
                            <th onclick="sortBy(9)">Archive Last Logon <span class="si"></span></th>
                        </tr>
                    </thead>
                    <tbody id="tbody">
$($tableRows -join "`n")
                    </tbody>
                </table>
            </div>
        </div>
    </div>

</div>

<div class="footer">
    <div class="ft">BUILDING BETTER SYSTEMS</div>
    <div>Yeyland Wutani LLC &mdash; Archive Mailbox Audit &mdash; $reportDate</div>
</div>

<script>
(function () {
    var sd = {};

    function updateCount() {
        var rows    = document.getElementById('tbody').rows;
        var visible = 0;
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].style.display !== 'none') visible++;
        }
        document.getElementById('row-count').textContent = visible + ' of ' + rows.length + ' users';
    }

    window.applyFilters = function () {
        var search  = document.getElementById('searchInput').value.toLowerCase();
        var archive = document.getElementById('archiveFilter').value;
        var rows    = document.getElementById('tbody').rows;

        for (var i = 0; i < rows.length; i++) {
            var r   = rows[i];
            var txt = r.textContent.toLowerCase();
            var cls = r.className;

            var matchClass = true;
            if (archive === 'yes')   matchClass = cls.indexOf('row-archive') > -1;
            if (archive === 'no')    matchClass = cls.indexOf('row-none')    > -1;
            if (archive === 'error') matchClass = cls.indexOf('row-error')   > -1;

            r.style.display = (matchClass && txt.indexOf(search) > -1) ? '' : 'none';
        }
        updateCount();
    };

    window.sortBy = function (col) {
        var dir  = sd[col] === 'asc' ? 'desc' : 'asc';
        sd       = {};
        sd[col]  = dir;

        var ths = document.getElementById('tbl').querySelectorAll('thead th');
        ths.forEach(function (th, i) {
            th.classList.remove('asc', 'desc');
            if (i === col) th.classList.add(dir);
        });

        var tbody = document.getElementById('tbody');
        var rows  = Array.from(tbody.rows);

        rows.sort(function (a, b) {
            var av = a.cells[col] ? a.cells[col].textContent.trim().replace(/,/g, '') : '';
            var bv = b.cells[col] ? b.cells[col].textContent.trim().replace(/,/g, '') : '';
            var an = parseFloat(av), bn = parseFloat(bv);

            if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;

            if (av === '\u2014' || av === '-') av = '';
            if (bv === '\u2014' || bv === '-') bv = '';

            return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
        });

        rows.forEach(function (r) { tbody.appendChild(r); });
    };

    window.onload = updateCount;
}());
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $HtmlPath -Encoding UTF8 -Force
    Write-Log "HTML report saved: $HtmlPath" -Level Success
}

#endregion HTML Report

#region Service Functions

function Connect-RequiredServices {
    Write-Log "Checking Microsoft Graph connection..." -Level Info
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $graphContext) {
        Write-Log "Connecting to Microsoft Graph..." -Level Info
        try {
            Connect-MgGraph -Scopes "User.ReadWrite.All", "Organization.Read.All" -ErrorAction Stop
            Write-Log "Connected to Microsoft Graph." -Level Success
        }
        catch {
            Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
            throw
        }
    }
    else {
        Write-Log "Already connected to Microsoft Graph as: $($graphContext.Account)" -Level Info
    }

    Write-Log "Checking Exchange Online connection..." -Level Info
    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
        Write-Log "Already connected to Exchange Online." -Level Info
    }
    catch {
        Write-Log "Connecting to Exchange Online..." -Level Info
        try {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            Write-Log "Connected to Exchange Online." -Level Success
        }
        catch {
            Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level Error
            throw
        }
    }
}

function Get-ArchiveCapableLicense {
    <#
    .SYNOPSIS
        Dynamically identifies a tenant license SKU with Exchange Online archiving capability.

    .DESCRIPTION
        Searches subscribed SKUs for service plans that include Exchange Online (Plan 2)
        or Exchange Online Archiving. Selects the SKU with the most available licenses.

        Plans checked in priority order:
          EXCHANGE_S_ENTERPRISE     - Exchange Online Plan 2 (E3, E5, Business Premium, etc.)
          EXCHANGE_S_ARCHIVE_ADDON  - Exchange Online Archiving standalone add-on
          EXCHANGE_S_ARCHIVE        - Generic Exchange archiving plan
    #>
    $archivePlans = @(
        "EXCHANGE_S_ENTERPRISE",
        "EXCHANGE_S_ARCHIVE_ADDON",
        "EXCHANGE_S_ARCHIVE"
    )

    Write-Log "Scanning tenant SKUs for Exchange Online archiving capability..." -Level Info
    $allSkus = Get-MgSubscribedSku -All -ErrorAction Stop

    $candidates = foreach ($sku in $allSkus) {
        $available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
        if ($available -lt 1) { continue }

        $matchedPlan = $null
        foreach ($planName in $archivePlans) {
            $hit = $sku.ServicePlans | Where-Object {
                $_.ServicePlanName -eq $planName -and $_.ProvisioningStatus -eq "Success"
            }
            if ($hit) { $matchedPlan = $planName; break }
        }

        if ($matchedPlan) {
            [PSCustomObject]@{
                SkuId             = $sku.SkuId
                SkuPartNumber     = $sku.SkuPartNumber
                AvailableLicenses = $available
                MatchedPlan       = $matchedPlan
            }
        }
    }

    if (-not $candidates) {
        Write-Log "No archive-capable SKUs with available licenses found." -Level Error
        $allSkus | Select-Object SkuPartNumber, @{N='Available';E={$_.PrepaidUnits.Enabled - $_.ConsumedUnits}} |
            Format-Table -AutoSize | Out-String | Write-Host
        throw "No archive-capable license found. Verify tenant licensing."
    }

    $selected = $candidates | Sort-Object AvailableLicenses -Descending | Select-Object -First 1
    Write-Log "Selected: $($selected.SkuPartNumber) | Plan: $($selected.MatchedPlan) | Available: $($selected.AvailableLicenses)" -Level Success

    if ($candidates.Count -gt 1) {
        $others = ($candidates | Where-Object { $_.SkuId -ne $selected.SkuId } | Select-Object -ExpandProperty SkuPartNumber) -join ", "
        Write-Log "Other archive-capable SKUs found: $others" -Level Info
    }

    return $selected
}

function Get-UsersToProcess {
    param([string]$CsvPath)

    if ($CsvPath) {
        Write-Log "Loading users from CSV: $CsvPath" -Level Info
        $users = Import-Csv -Path $CsvPath
        if (-not ($users | Get-Member -Name "UserPrincipalName" -ErrorAction SilentlyContinue)) {
            throw "CSV must contain a 'UserPrincipalName' column."
        }
        Write-Log "Loaded $($users.Count) users from CSV." -Level Info
        return $users
    }

    Write-Log "Retrieving all enabled member accounts from Microsoft Graph..." -Level Info
    $allUsers = Get-MgUser -All `
        -Filter "userType eq 'Member' and accountEnabled eq true" `
        -Property UserPrincipalName, DisplayName, Mail, Id |
        Where-Object { $_.UserPrincipalName -notlike "*#EXT#*" } |
        Where-Object { $_.UserPrincipalName -notmatch "^(admin|sync|svc|service|system|health|discovery)" }

    Write-Log "Found $($allUsers.Count) user accounts." -Level Info

    return $allUsers | Select-Object `
        @{N = 'UserPrincipalName'; E = { $_.UserPrincipalName } },
        @{N = 'DisplayName';       E = { $_.DisplayName } },
        @{N = 'PrimarySmtpAddress';E = { $_.Mail } }
}

function Add-UserLicense {
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$SkuId
    )

    try {
        $existing = Get-MgUserLicenseDetail -UserId $UserId -ErrorAction SilentlyContinue
        if ($existing | Where-Object { $_.SkuId -eq $SkuId }) {
            Write-Log "$UserId already holds this license - will not remove on completion." -Level Warning
            return @{ Success = $true; AlreadyLicensed = $true }
        }

        Set-MgUserLicense -UserId $UserId -AddLicenses @(@{ SkuId = $SkuId }) -RemoveLicenses @() -ErrorAction Stop
        Write-Log "License assigned to $UserId." -Level Success
        return @{ Success = $true; AlreadyLicensed = $false }
    }
    catch {
        Write-Log "Failed to assign license to $UserId`: $($_.Exception.Message)" -Level Error
        return @{ Success = $false; AlreadyLicensed = $false; Error = $_.Exception.Message }
    }
}

function Remove-UserLicense {
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$SkuId,
        [Parameter(Mandatory = $false)][bool]$SkipRemoval = $false
    )

    if ($SkipRemoval) {
        Write-Log "Skipping license removal for $UserId (pre-existing license retained)." -Level Info
        return $true
    }

    try {
        Set-MgUserLicense -UserId $UserId -AddLicenses @() -RemoveLicenses @($SkuId) -ErrorAction Stop
        Write-Log "License removed from $UserId." -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to remove license from $UserId`: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-PrimaryMailboxData {
    param(
        [Parameter(Mandatory = $true)][string]$UserPrincipalName
    )

    try {
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
        $stats   = Get-MailboxStatistics -Identity $UserPrincipalName -ErrorAction Stop

        $sizeBytes = 0
        if ($stats.TotalItemSize.ToString() -match "\(([0-9,]+) bytes\)") {
            $sizeBytes = [int64]($Matches[1] -replace ",", "")
        }
        $delBytes = 0
        if ($stats.TotalDeletedItemSize.ToString() -match "\(([0-9,]+) bytes\)") {
            $delBytes = [int64]($Matches[1] -replace ",", "")
        }

        return [PSCustomObject]@{
            PrimaryMailboxExists     = $true
            PrimaryTotalItemSizeGB   = [math]::Round($sizeBytes / 1GB, 3)
            PrimaryItemCount         = $stats.ItemCount
            PrimaryDeletedItemCount  = $stats.DeletedItemCount
            PrimaryDeletedItemSizeGB = [math]::Round($delBytes / 1GB, 3)
            PrimaryLastLogonTime     = $stats.LastLogonTime
            PrimaryLastLogoffTime    = $stats.LastLogoffTime
            MailboxCreatedDate       = $mailbox.WhenMailboxCreated
            RecipientTypeDetail      = $mailbox.RecipientTypeDetails
            ProhibitSendQuota        = $mailbox.ProhibitSendQuota
            ProhibitSendReceiveQuota = $mailbox.ProhibitSendReceiveQuota
            PrimaryErrorMessage      = $null
        }
    }
    catch {
        Write-Log "Could not retrieve primary mailbox data for $UserPrincipalName`: $($_.Exception.Message)" -Level Warning
        return [PSCustomObject]@{
            PrimaryMailboxExists     = $false
            PrimaryTotalItemSizeGB   = $null
            PrimaryItemCount         = $null
            PrimaryDeletedItemCount  = $null
            PrimaryDeletedItemSizeGB = $null
            PrimaryLastLogonTime     = $null
            PrimaryLastLogoffTime    = $null
            MailboxCreatedDate       = $null
            RecipientTypeDetail      = $null
            ProhibitSendQuota        = $null
            ProhibitSendReceiveQuota = $null
            PrimaryErrorMessage      = $_.Exception.Message
        }
    }
}

function Get-ArchiveMailboxData {
    param(
        [Parameter(Mandatory = $true)][string]$UserPrincipalName,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)][int]$RetryIntervalSeconds = 60
    )

    $emptyGuid  = "00000000-0000-0000-0000-000000000000"
    $retryCount = 0

    do {
        try {
            $mailbox    = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
            $hasArchive = ($mailbox.ArchiveGuid -and $mailbox.ArchiveGuid -ne $emptyGuid)

            if (-not $hasArchive) {
                if ($retryCount -lt $MaxRetries) {
                    Write-Log "No archive GUID for $UserPrincipalName. Retry $($retryCount + 1)/$MaxRetries in $RetryIntervalSeconds seconds..." -Level Warning
                    Start-Sleep -Seconds $RetryIntervalSeconds
                    $retryCount++
                    continue
                }
                return [PSCustomObject]@{
                    HasArchive           = $false
                    ArchiveStatus        = $mailbox.ArchiveStatus
                    ArchiveState         = $mailbox.ArchiveState
                    ArchiveGuid          = $mailbox.ArchiveGuid
                    ArchiveName          = $null
                    TotalItemSizeGB      = $null
                    ItemCount            = $null
                    DeletedItemCount     = $null
                    DeletedItemSizeGB    = $null
                    OldestItemDate       = $null
                    NewestItemDate       = $null
                    ArchiveLastLogonTime = $null
                    ArchiveErrorMessage  = "No archive GUID present after provisioning wait"
                }
            }

            Write-Log "Archive GUID confirmed for $UserPrincipalName - retrieving statistics..." -Level Info

            try {
                $archiveStats = Get-MailboxStatistics -Identity $UserPrincipalName -Archive -ErrorAction Stop
            }
            catch {
                if ($retryCount -lt $MaxRetries) {
                    Write-Log "Archive GUID exists but stats unavailable. Retry $($retryCount + 1)/$MaxRetries..." -Level Warning
                    Start-Sleep -Seconds $RetryIntervalSeconds
                    $retryCount++
                    continue
                }
                return [PSCustomObject]@{
                    HasArchive           = $false
                    ArchiveStatus        = $mailbox.ArchiveStatus
                    ArchiveState         = $mailbox.ArchiveState
                    ArchiveGuid          = $mailbox.ArchiveGuid
                    ArchiveName          = $mailbox.ArchiveName -join ", "
                    TotalItemSizeGB      = $null
                    ItemCount            = $null
                    DeletedItemCount     = $null
                    DeletedItemSizeGB    = $null
                    OldestItemDate       = $null
                    NewestItemDate       = $null
                    ArchiveLastLogonTime = $null
                    ArchiveErrorMessage  = "Archive GUID exists but stats unavailable: $($_.Exception.Message)"
                }
            }

            $folderStats = Get-MailboxFolderStatistics -Identity $UserPrincipalName -Archive -ErrorAction SilentlyContinue
            $oldestDate  = $null
            $newestDate  = $null
            if ($folderStats) {
                $dated = $folderStats | Where-Object { $_.OldestItemReceivedDate }
                if ($dated) {
                    $oldestDate = ($dated | Sort-Object OldestItemReceivedDate | Select-Object -First 1).OldestItemReceivedDate
                    $newestDate = ($dated | Sort-Object NewestItemReceivedDate -Descending | Select-Object -First 1).NewestItemReceivedDate
                }
            }

            $sizeBytes = 0
            if ($archiveStats.TotalItemSize.ToString() -match "\(([0-9,]+) bytes\)") {
                $sizeBytes = [int64]($Matches[1] -replace ",", "")
            }
            $delBytes = 0
            if ($archiveStats.TotalDeletedItemSize.ToString() -match "\(([0-9,]+) bytes\)") {
                $delBytes = [int64]($Matches[1] -replace ",", "")
            }

            Write-Log "Archive confirmed: $([math]::Round($sizeBytes/1GB,2)) GB, $($archiveStats.ItemCount) items." -Level Success

            return [PSCustomObject]@{
                HasArchive           = $true
                ArchiveStatus        = $mailbox.ArchiveStatus
                ArchiveState         = $mailbox.ArchiveState
                ArchiveGuid          = $mailbox.ArchiveGuid
                ArchiveName          = $mailbox.ArchiveName -join ", "
                TotalItemSizeGB      = [math]::Round($sizeBytes / 1GB, 3)
                ItemCount            = $archiveStats.ItemCount
                DeletedItemCount     = $archiveStats.DeletedItemCount
                DeletedItemSizeGB    = [math]::Round($delBytes / 1GB, 3)
                OldestItemDate       = $oldestDate
                NewestItemDate       = $newestDate
                ArchiveLastLogonTime = $archiveStats.LastLogonTime
                ArchiveErrorMessage  = $null
            }
        }
        catch {
            if ($retryCount -lt $MaxRetries) {
                Write-Log "Error on $UserPrincipalName. Retry $($retryCount + 1)/$MaxRetries`: $($_.Exception.Message)" -Level Warning
                Start-Sleep -Seconds $RetryIntervalSeconds
                $retryCount++
            }
            else {
                Write-Log "Failed to retrieve archive data for $UserPrincipalName after all retries: $($_.Exception.Message)" -Level Error
                return [PSCustomObject]@{
                    HasArchive           = $false
                    ArchiveStatus        = "Error"
                    ArchiveState         = $null
                    ArchiveGuid          = $null
                    ArchiveName          = $null
                    TotalItemSizeGB      = $null
                    ItemCount            = $null
                    DeletedItemCount     = $null
                    DeletedItemSizeGB    = $null
                    OldestItemDate       = $null
                    NewestItemDate       = $null
                    ArchiveLastLogonTime = $null
                    ArchiveErrorMessage  = $_.Exception.Message
                }
            }
        }
    } while ($retryCount -le $MaxRetries)
}

#endregion Service Functions

#region Main

try {
    Show-YWBanner

    # Strip extension if provided - we control both output files
    $basePath = $OutputPath -replace '\.(csv|html)$', ''
    $csvPath  = "$basePath.csv"
    $htmlPath = "$basePath.html"

    Write-Log "Archive Mailbox Audit - Starting" -Level Info
    Write-Log "CSV output  : $csvPath"           -Level Info
    Write-Log "HTML output : $htmlPath"           -Level Info
    Write-Log "Wait time   : $WaitTimeSeconds seconds" -Level Info
    Write-Log "Max retries : $MaxRetries"         -Level Info

    Connect-RequiredServices

    # Resolve tenant display name for the HTML report header
    $tenantDomain = "Unknown"
    try {
        $orgConfig    = Get-OrganizationConfig -ErrorAction SilentlyContinue
        $tenantDomain = if ($orgConfig.Name) { $orgConfig.Name } else { (Get-MgContext).TenantId }
    }
    catch { <# non-fatal - header will show Unknown #> }

    $selectedLicense = Get-ArchiveCapableLicense
    $usersToProcess  = Get-UsersToProcess -CsvPath $InputCsv
    $totalUsers      = $usersToProcess.Count
    $currentUser     = 0

    Write-Log "Processing $totalUsers user(s) using SKU: $($selectedLicense.SkuPartNumber)" -Level Info

    $results = [System.Collections.ArrayList]::new()

    foreach ($user in $usersToProcess) {
        $currentUser++
        $upn = $user.UserPrincipalName

        Write-Log "---- [$currentUser/$totalUsers] $upn ----" -Level Info

        $userResult = [PSCustomObject]@{
            UserPrincipalName          = $upn
            DisplayName                = $user.DisplayName
            ProcessedDateTime          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            LicenseSkuUsed             = $selectedLicense.SkuPartNumber
            LicenseAssigned            = $false
            LicenseRemoved             = $false
            PrimaryMailboxExists       = $false
            PrimaryTotalItemSizeGB     = $null
            PrimaryItemCount           = $null
            PrimaryDeletedItemCount    = $null
            PrimaryDeletedItemSizeGB   = $null
            PrimaryLastLogonTime       = $null
            PrimaryLastLogoffTime      = $null
            MailboxCreatedDate         = $null
            RecipientTypeDetail        = $null
            ProhibitSendQuota          = $null
            ProhibitSendReceiveQuota   = $null
            HasArchive                 = $false
            ArchiveStatus              = $null
            ArchiveState               = $null
            ArchiveGuid                = $null
            ArchiveName                = $null
            ArchiveTotalItemSizeGB     = $null
            ArchiveItemCount           = $null
            ArchiveDeletedItemCount    = $null
            ArchiveDeletedItemSizeGB   = $null
            ArchiveOldestItemDate      = $null
            ArchiveNewestItemDate      = $null
            ArchiveLastLogonTime       = $null
            Notes                      = $null
        }

        # Step 1 - License assignment
        Write-Log "Step 1: Assigning $($selectedLicense.SkuPartNumber) to $upn..." -Level Info
        $licenseResult = Add-UserLicense -UserId $upn -SkuId $selectedLicense.SkuId

        if (-not $licenseResult.Success) {
            $userResult.Notes = "License assignment failed: $($licenseResult.Error)"
            $null = $results.Add($userResult)
            $results | Export-Csv -Path $csvPath -NoTypeInformation -Force
            continue
        }

        $userResult.LicenseAssigned = $true
        $skipRemoval = $licenseResult.AlreadyLicensed
        if ($skipRemoval) { $userResult.Notes = "Pre-existing license detected - retained on completion" }

        # Step 2 - Provisioning wait
        Write-Log "Step 2: Waiting $WaitTimeSeconds seconds for mailbox provisioning..." -Level Info
        $waitEnd = (Get-Date).AddSeconds($WaitTimeSeconds)
        while ((Get-Date) -lt $waitEnd) {
            $remaining = [math]::Ceiling(($waitEnd - (Get-Date)).TotalSeconds)
            Write-Progress -Activity "Provisioning wait" -Status $upn -SecondsRemaining $remaining
            Start-Sleep -Seconds 10
        }
        Write-Progress -Activity "Provisioning wait" -Completed

        # Step 3a - Primary mailbox
        Write-Log "Step 3a: Retrieving primary mailbox statistics..." -Level Info
        $primary = Get-PrimaryMailboxData -UserPrincipalName $upn

        $userResult.PrimaryMailboxExists     = $primary.PrimaryMailboxExists
        $userResult.PrimaryTotalItemSizeGB   = $primary.PrimaryTotalItemSizeGB
        $userResult.PrimaryItemCount         = $primary.PrimaryItemCount
        $userResult.PrimaryDeletedItemCount  = $primary.PrimaryDeletedItemCount
        $userResult.PrimaryDeletedItemSizeGB = $primary.PrimaryDeletedItemSizeGB
        $userResult.PrimaryLastLogonTime     = $primary.PrimaryLastLogonTime
        $userResult.PrimaryLastLogoffTime    = $primary.PrimaryLastLogoffTime
        $userResult.MailboxCreatedDate       = $primary.MailboxCreatedDate
        $userResult.RecipientTypeDetail      = $primary.RecipientTypeDetail
        $userResult.ProhibitSendQuota        = $primary.ProhibitSendQuota
        $userResult.ProhibitSendReceiveQuota = $primary.ProhibitSendReceiveQuota
        if ($primary.PrimaryErrorMessage) {
            $userResult.Notes = if ($userResult.Notes) { "$($userResult.Notes); $($primary.PrimaryErrorMessage)" } else { $primary.PrimaryErrorMessage }
        }

        # Step 3b - Archive mailbox
        Write-Log "Step 3b: Checking archive mailbox..." -Level Info
        $archive = Get-ArchiveMailboxData -UserPrincipalName $upn -MaxRetries $MaxRetries -RetryIntervalSeconds 60

        $userResult.HasArchive              = $archive.HasArchive
        $userResult.ArchiveStatus           = $archive.ArchiveStatus
        $userResult.ArchiveState            = $archive.ArchiveState
        $userResult.ArchiveGuid             = $archive.ArchiveGuid
        $userResult.ArchiveName             = $archive.ArchiveName
        $userResult.ArchiveTotalItemSizeGB  = $archive.TotalItemSizeGB
        $userResult.ArchiveItemCount        = $archive.ItemCount
        $userResult.ArchiveDeletedItemCount = $archive.DeletedItemCount
        $userResult.ArchiveDeletedItemSizeGB = $archive.DeletedItemSizeGB
        $userResult.ArchiveOldestItemDate   = $archive.OldestItemDate
        $userResult.ArchiveNewestItemDate   = $archive.NewestItemDate
        $userResult.ArchiveLastLogonTime    = $archive.ArchiveLastLogonTime
        if ($archive.ArchiveErrorMessage) {
            $userResult.Notes = if ($userResult.Notes) { "$($userResult.Notes); $($archive.ArchiveErrorMessage)" } else { $archive.ArchiveErrorMessage }
        }

        if ($archive.HasArchive) {
            Write-Log "Archive confirmed - $($archive.TotalItemSizeGB) GB, $($archive.ItemCount) items." -Level Success
        } else {
            Write-Log "No archive found for $upn." -Level Warning
        }

        # Step 4 - License removal
        Write-Log "Step 4: Removing temporary license from $upn..." -Level Info
        $removed = Remove-UserLicense -UserId $upn -SkuId $selectedLicense.SkuId -SkipRemoval $skipRemoval
        $userResult.LicenseRemoved = ($removed -or $skipRemoval)

        $null = $results.Add($userResult)

        # Incremental CSV save
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Force
        Write-Log "Progress saved. ($currentUser/$totalUsers complete)" -Level Info
    }

    # Final outputs
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Force

    New-HtmlReport `
        -Results         $results.ToArray() `
        -HtmlPath        $htmlPath `
        -TenantDomain    $tenantDomain `
        -LicenseSkuUsed  $selectedLicense.SkuPartNumber

    # Console summary
    $withArchive = ($results | Where-Object { $_.HasArchive }).Count
    $noArchive   = $totalUsers - $withArchive
    $totalPrimGB = [math]::Round(($results | Where-Object { $_.PrimaryTotalItemSizeGB } | Measure-Object -Property PrimaryTotalItemSizeGB -Sum).Sum, 2)
    $totalArchGB = [math]::Round(($results | Where-Object { $_.ArchiveTotalItemSizeGB } | Measure-Object -Property ArchiveTotalItemSizeGB -Sum).Sum, 2)

    Write-Host ""
    Write-Host ("=" * 84) -ForegroundColor Gray
    Write-Host " AUDIT COMPLETE - Yeyland Wutani LLC" -ForegroundColor DarkYellow
    Write-Host ("=" * 84) -ForegroundColor Gray
    Write-Log "Users processed    : $totalUsers"    -Level Info
    Write-Log "Archives found     : $withArchive"   -Level Success
    Write-Log "No archive         : $noArchive"     -Level Warning
    Write-Log "Total primary size : $totalPrimGB GB" -Level Info
    Write-Log "Total archive size : $totalArchGB GB" -Level Info
    Write-Log "CSV report         : $csvPath"       -Level Success
    Write-Log "HTML report        : $htmlPath"      -Level Success
    Write-Host ("=" * 84) -ForegroundColor Gray
    Write-Host ""

    $results | Where-Object { $_.HasArchive } |
        Select-Object UserPrincipalName, PrimaryTotalItemSizeGB, PrimaryLastLogonTime,
                      ArchiveTotalItemSizeGB, ArchiveItemCount, ArchiveOldestItemDate, ArchiveNewestItemDate |
        Format-Table -AutoSize
}
catch {
    Write-Log "Script terminated with error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}
finally {

    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

#endregion Main