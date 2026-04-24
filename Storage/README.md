# Storage

PowerShell tools for storage management, capacity reporting, and file server auditing across Windows infrastructure and Microsoft 365.

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `Get-SPOStorageReport.ps1` | SharePoint Online storage management report: site storage metrics, top consumers, stale storage identification, quota alerts, optional per-library breakdown, and OneDrive usage — generates HTML report and CSV exports |
| `Get-FileServerPermissionsReport.ps1` | Windows file server storage and permissions audit: enumerates SMB shares, collects recursive folder sizes with visual comparisons, audits full NTFS ACLs with SID translation and anomaly flagging — generates HTML report and companion CSV |

---

## Get-SPOStorageReport.ps1 (v1.0)

**Purpose:** MSP-friendly SharePoint Online storage management report. Identifies where storage is concentrated, surfaces cleanup opportunities, flags stale data, and highlights sites approaching quota limits. Uses delegated permissions with interactive sign-in — no app registration required.

**What's Reported:**

| Area | Details |
|------|---------|
| **All Sites** | Storage used, quota, last modified, site type — ranked by size |
| **Top Consumers** | Highest-storage sites with visual size comparison bars |
| **Stale Storage** | Sites with significant data not modified within the stale threshold |
| **Quota Warnings** | Sites approaching or exceeding their individual quota |
| **Library Deep Dive** | Per-library breakdown within each site (optional, slower) |
| **Tenant Summary** | Overall quota usage across the entire tenant |
| **OneDrive** | Included by default — personal storage is often the largest component |

**Usage:**

```powershell
# Full storage report including OneDrive (default)
.\Get-SPOStorageReport.ps1 -TenantName "contoso"

# SharePoint sites only, saved to C:\Reports
.\Get-SPOStorageReport.ps1 -TenantName "contoso" -ExcludeOneDrive -OutputPath "C:\Reports"

# Full report with per-library breakdown (slower, more detail)
.\Get-SPOStorageReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive

# Flag sites with 100+ MB unused for over a year
.\Get-SPOStorageReport.ps1 -TenantName "contoso" -StaleThresholdDays 365 -StaleMinimumMB 100

# Scope to sites matching a URL pattern
.\Get-SPOStorageReport.ps1 -TenantName "contoso" -SiteUrlFilter "*project*"
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-TenantName` | Required | SharePoint tenant name (e.g., `contoso` for `contoso.sharepoint.com`) |
| `-OutputPath` | Current directory | Directory for HTML report and CSV exports |
| `-ExcludeOneDrive` | $false | Exclude OneDrive for Business sites from the report |
| `-IncludeLibraryDeepDive` | $false | Per-library storage breakdown via Graph drives API |
| `-SiteUrlFilter` | None | URL pattern filter (supports wildcards) |
| `-MaxSites` | 0 (unlimited) | Cap number of sites processed (useful for testing) |
| `-SkipTenantSettings` | $false | Skip tenant quota collection (for non-Global Admins) |
| `-StaleThresholdDays` | 180 | Days since last modification to flag storage as stale |
| `-StaleMinimumMB` | 50 | Minimum site storage (MB) to include in stale report |

**Requirements:**
- PowerShell 5.1+
- Microsoft.Graph PowerShell SDK
- Microsoft.Online.SharePoint.PowerShell (SPO Management Shell)
- SharePoint Administrator or Global Administrator role

---

## Get-FileServerPermissionsReport.ps1

**Purpose:** Audits a Windows file server for both storage consumption and NTFS permission health. Automatically enumerates all SMB shares when a server name is provided, or scans explicit paths. Outputs a self-contained HTML report and companion CSV.

**What's Reported:**

| Mode | Details |
|------|---------|
| **Full (default)** | Recursive folder sizes + full NTFS ACL collection with SID translation, anomaly flagging, and permission complexity scoring |
| **Storage Only** | Recursive folder sizes, per-share breakdown with visual bars, and top largest folders — skips ACL collection for fast runs on large servers |

**Key Capabilities:**

- **Auto share enumeration** — when `-Server` is provided, discovers all non-hidden SMB shares via WMI automatically
- **Parallel ACL collection** — RunspacePool-based for performance on PS 5.1
- **SID translation** — resolves orphaned/deleted account SIDs in ACLs
- **Anomaly detection** — flags broad-access groups (Everyone, Authenticated Users, Domain Users) with write permissions
- **Rebuild from CSV** — regenerate the HTML report from a previous run's CSV without re-scanning
- **Hidden share support** — optionally include administrative `$` shares

**Usage:**

```powershell
# Audit all shares on a remote server (full permissions + storage)
.\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -ClientName "Contoso"

# Fast storage-only report — no ACL collection
.\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -ClientName "Contoso" -StorageOnly

# Scan specific paths, suppress built-in noise, 3 levels deep
.\Get-FileServerPermissionsReport.ps1 -Path "\\fs1\Finance","\\fs1\HR" `
    -ClientName "Contoso" -MaxDepth 3 -ExcludeBuiltin

# Show only anomalous folders in HTML (full data still in CSV)
.\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -AnomalyGroupsOnly

# Rebuild HTML report from a previous run's CSV
.\Get-FileServerPermissionsReport.ps1 -FromCsv "C:\Temp\Contoso_FileServerReport_20260414.csv" `
    -ClientName "Contoso" -StorageOnly

# Include hidden administrative shares (C$, ADMIN$, etc.)
.\Get-FileServerPermissionsReport.ps1 -Server fileserver01 -IncludeHiddenShares
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Server` | — | Remote server hostname/IP — auto-enumerates SMB shares via WMI |
| `-Path` | Current directory | One or more explicit paths to scan (local or UNC) |
| `-FromCsv` | — | Rebuild HTML from a previous run's CSV without re-scanning |
| `-OutputDir` | Current directory | Directory for HTML report and CSV |
| `-ClientName` | `Client` | Client name shown in the report header |
| `-MaxDepth` | 4 | Maximum folder recursion depth (0 = root only) |
| `-MaxRunspaces` | 8 | Parallel ACL-collection threads |
| `-StorageOnly` | $false | Skip ACL collection — fast storage-only report |
| `-ExcludeBuiltin` | $false | Hide built-in accounts (SYSTEM, Administrators) from HTML badges |
| `-AnomalyGroupsOnly` | $false | Show only anomalous folders in HTML detail table |
| `-IncludeHiddenShares` | $false | Include administrative `$` shares in enumeration |

**Requirements:**
- PowerShell 5.1+
- WMI access to target server (for `-Server` share enumeration)
- Read access to target paths and their ACLs
- Network access to target file server

---

## Requirements

- PowerShell 5.1+
- **Get-SPOStorageReport**: Microsoft.Graph PowerShell SDK, SPO Management Shell, SharePoint Administrator or Global Administrator role
- **Get-FileServerPermissionsReport**: WMI access to target server, read rights on all scanned paths

---

**Yeyland Wutani LLC** · Building Better Systems

[← Back to Repository](../README.md)
