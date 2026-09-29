# Get-M365SecurityAnalysis.ps1 - Changelog

Versions follow Major.Minor (`$ScriptVer` in the script). Newest first.

## 12.0 - 2026-09-29
Redesigned window and HTML report (Yeyland Wutani design handoff).

**Changed**
- Main window rebuilt as three numbered steps: 01 Connect, 02 Collect, 03 Analyze. Neutral hairline surfaces, one orange fill for the primary action of each step, new dark and light tokens (`Surface2`, `OnPrimary`, `Medium`, `Ai` added to `Get-ThemeColor`). Client size is now 1000 x 780 with DPI scaling.
- Each collector is a status tile (Not collected / Collecting / `<n>` records / incomplete / error) filled from `CollectionStatus.csv` on load and updated as collectors run; the collector's gap note is the tile tooltip. `Run all collection` moves to the Collect header.
- Connection state is a pill in the header; session block shows working directory, date range, tenant and account. Batch size and cache timeout moved to the status bar; the status bar shows a colored critical/high/medium/low summary after an analysis.
- `Show-HatzAnalysisResult` restyled; its Save and Close buttons were clipped below the window edge and now fit.
- The HTML report is now one dependency-free page rendered client-side from an embedded JSON payload (`New-ReportPayload`, `$script:ReportTemplate`): verdict and risk bar, data coverage, ten collapsible evidence sections, a detail drawer with related records, identity search and filter, light and dark themes, print expands everything. The generator no longer emits markup, so record values are HTML-escaped by the template only.

**Added**
- Report sections for brute-force patterns, unusual and high-risk sign-ins and ETR spam activity (hidden when empty), linked to identities; Export CSV of the identity list.
- Report tables are capped at 1500 rows for failed sign-ins, unusual sign-ins, message trace and sign-in locations, with a note pointing to the full CSV.

## 11.18 - 2026-09-29
- Version bump and this changelog. No functional change.

## 11.17 - 2026-09-29
Closes the remaining data gaps and adds coverage tracking.

**Added**
- `CollectionStatus.csv`: every collector records its gaps (skipped mailboxes, truncated pulls, fallback sources, unreadable APIs). Analyze Data shows incomplete, stale (over 2 days) and never-collected sources in the log and in a Data Coverage section at the top of the HTML report.
- `-IncludeNonInteractive` on `Get-TenantSignInData` (Graph returns interactive sign-ins only unless filtered).
- `GeoLookupFailed` column on sign-in data; `InboxRules_Skipped.csv`.
- "Password Guessed - MFA Held" pattern (50074/50076 after repeated failures from the same IP).

**Changed**
- Inbox rules: `-IncludeHidden`; external forwarding compares whole domains against accepted domains for `ForwardTo`, `ForwardAsAttachmentTo` and `RedirectTo`; `Mailbox` is the UPN.
- Apps: all app registrations plus consented third-party enterprise apps; risk by resolved permission name (requested, delegated, application); risk never downgrades.
- Conditional Access: `ExcludeRoles` GUIDs resolved to role names; recently modified policies flagged.
- Sign-ins: on a licensed tenant a Graph timeout or 403 fails loudly instead of silently falling back to 10 days of Exchange data; UTC filter; IPv6 unique-local range fix.
- Exchange audit-log fallback: pages until empty, splits windows that hit the 50,000-record ceiling; unmapped failures are `UNKNOWN` instead of 50126; CA and risk reported as `notAvailable`.
- Message trace: pages past the 5000-record cap; `-MaxMessages` default 50000; hitting the cap is recorded as incomplete.
- Failed logins: timestamps parsed as dates (text sorting broke the breach window); risk sort fixed; IP-less failures reported as a gap.
- MFA audit: API failures reported as `Unknown` instead of "no MFA"; transitive group membership; CA credit respects roles, apps, platforms, risk and grant operator; `compliantDevice` and email no longer count as MFA; admin detection from directory roles including PIM-eligible.
- Admin audit: consent, credential, federation, domain and CA-policy operations rated High.
- Each collector removes its own previous output before writing, so a run that finds nothing cannot leave old data behind.

## 11.16 - 2026-09-29
- `Get-MailboxDelegationData` rebuilt on Exchange Online (`Get-MailboxPermission`, `Get-RecipientPermission`, `GrantSendOnBehalfTo`) across user and shared mailboxes. The old Graph mailbox-settings source carried no delegate data. Flags external delegates, orphaned SIDs and delegated access on user mailboxes; unreadable mailboxes go to `MailboxDelegation_Skipped.csv`.

## 11.15 - 2026-09-29
- Analysis sign-in loader kept `StatusCode` and `IsHighRiskISP` (every sign-in had counted as a success; high-risk ISP scoring never fired).
- `Get-RecentPasswordChanges` derives target and initiator from the audit data (it read columns that did not exist and always reported nothing).
- `Get-AdminAuditData` no longer excludes the current day; app-initiated events are attributed as `[App] <name>`.

## 11.14 - 2026-09-29
- `Get-MailboxRules` checks every user and shared mailbox regardless of sign-in activity. Removed the inactive-user skip and the unused `-IncludeInactive` / `-DaysInactive` parameters, so rules added to dormant mailboxes by a compromised admin are reported.
