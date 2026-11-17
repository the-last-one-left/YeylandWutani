# Get-M365SecurityAnalysis.ps1 - Changelog

Versions follow Major.Minor (`$ScriptVer` in the script). Newest first.

## 12.1 - 2026-11-16
Review fixes: wrong results (A) and behaviour bugs (B). Verified offline only (`Security/tests/Test-M365SecurityAnalysis.ps1`); not yet run against a live tenant.

**Fixed**
- Conditional Access MFA credit was inverted. Graph SDK models never return `$null` for nested objects, so "Require MFA" policies (operator OR, `mfa`) were not credited while device-only and session-only policies were. Logic now lives in `Test-CaPolicyRequiresMfa` and `Test-CaPolicyUserInScope`, which test real values only (authentication strength needs an `Id`; guest include/exclude needs `GuestOrExternalUserTypes`; `GuestsOrExternalUsers` in `IncludeUsers` counts).
- An Exchange Online session from a previous tenant was reused after reconnecting Graph to another tenant. The EXO session is now reused only when `Get-ConnectionInformation` reports the same tenant id as `Get-MgContext`, otherwise it is disconnected and re-established. Disconnect, Reconnect, window close and final cleanup now drop the EXO session too (EXO v3 never creates a `Microsoft.Exchange` PSSession, so the old checks never fired). `$Global:ExchangeOnlineState` is updated in place, so `LastCollectionComplete` and `LastCollectionWarning` survive reconnects. `Disconnect-ExchangeOnlineSafely` (never called) was removed.
- The tool's own `MessageTraceResult.csv` was filtered out of ETR analysis because direction was written as "Unknown". The collector now derives Outbound / Internal / Inbound from the accepted domains (blank, plus a coverage note, if they cannot be read) and `Analyze-ETRData` treats blank and "Unknown" as possibly outbound, counts Internal, and never analyses Inbound.
- Private and unknown IPs could be flagged as unusual locations. One classifier (`Get-IPClassification`) is now used by both the geolocator and the sign-in loop: IPv4-mapped IPv6 is unmapped and classified as IPv4, fe80::/10 and fec0::/10 are tested on the real prefix, 100.64.0.0/10 (CGNAT) is private. `Test-UnusualCountry` never flags empty, Unknown, Private Network or Invalid IP. The duplicate unique-location block in `Invoke-CompromiseDetection` (it overwrote `UniqueSignInLocations.csv` without the `IPVersion` column) was removed, and the collector's version now groups once instead of rescanning per location.
- Failed-login analysis no longer reports a password spray, breach or MFA-held pattern from sign-ins whose IP is the "Unknown" placeholder.
- A failed collector left the previous run's status row looking complete. MFA audit, inbox rules, delegations, app registrations, Conditional Access and message trace (exceptions and the "no Exchange Online connection" early returns) now record an Incomplete row, `Analyze-ETRData` records an `ETRAnalysis` row on every exit and clears its previous output first, and inbox rules with zero mailboxes is recorded as incomplete. A message trace error only marks Exchange Online disconnected when it is a connection or authentication error.
- `-IncludeNonInteractive` was unreachable (the script has no param block and the GUI called the collector with no arguments). It is now `$ConfigData.IncludeNonInteractive` (default off) with an "Include non-interactive sign-ins" checkbox on the Collect header; the header and coverage texts no longer point at a switch nobody can pass.
- Working directory: one `Set-TenantWorkDir` builds `<root>\<tenant>\<yyyyMMdd_HHmm>` from the configured or user-picked root (it was hardcoded to `C:\Temp\`), does nothing when the current directory is already inside the tenant's folder, and the window's Shown handler no longer re-runs the connection check after a pre-GUI sign-in (a minute rollover created a second empty folder and moved `WorkDir` away from the transcript). **Folder names change**: the stamp is now `yyyyMMdd_HHmm` (sortable) instead of `HHmmddMMyy`.
- Cancelling the sign-in (or declining a module install, update or reinstall) no longer re-prompts three times: `Connect-TenantServices` sets `$script:ConnectCancelled` and the pre-GUI loop stops.
- IPStack: a quota or key rejection (HTTP 200 with `success = false`) now disables IPStack for the session after one call and goes straight to ip-api.com instead of burning three calls per IP. The rate-limit sleep only follows lookups that made a web call (private and cached addresses no longer wait), and the sign-in coverage note names the geolocation source used.
- OData filter injection by apostrophe: a UPN such as `o'brien@contoso.com` no longer breaks the MFA sign-in query.
- `SkipGuests` was read but never defined; it is now in the config block (default off).
- "Run all collection" counted a task as completed even when its collector failed (collectors swallow their own exceptions). It now judges each task by the status row the collector wrote this run, so the summary no longer says "All 11 tasks finished" after a failure.
- The failed sign-in threat metric in the report was the capped row count (1500); it now counts every failure. Risky-IP correlation emits one indicator per sender instead of a comma-joined sender that became a bogus identity. Failed-login patterns have a `TargetUser` column and the analysis uses it instead of parsing the `Details` text (the text is still the fallback for old CSVs). `SecurityReport.csv` gains `MFAStatus`, `HighRiskISPCount`, `FailedLoginPatternCount` and `PasswordChangeIssuesCount`. `Invoke-CompromiseDetection` is now a wrapper that logs and returns `$null` on failure so the Analyze button reaches its failure dialog.
- Password-change false positives: one admin reset writes several directory audit events; events for the same target with the same `CorrelationId`, or the same initiator within 2 minutes, now count once. The off-hours window includes 22:00-22:59 and the reason names the analysis machine's time zone.
- Hatz AI: the schema text claimed `UserLocationData.csv` held successful sign-ins only (it holds all); files are sent in priority order (SecurityReport, CollectionStatus, then suspicious / high-risk / no-MFA / breach / critical findings) and the raw message trace is never sent; the API key is read with `PtrToStringBSTR`; the model id lives in one variable; the consent dialog says plainly that user names, IP addresses and mailbox rule contents leave the machine.
- Module self-heal no longer uninstalls every Microsoft.Graph module without asking (Yes/No prompt first), and a failed `Update-Module` is reported instead of "updated successfully".

**Changed**
- The Exchange Online sign-in fallback now honours the requested range up to 180 days (default Audit (Standard) retention, per Microsoft Learn) instead of 10 days; the 10-day limit belongs to message trace. The coverage note states the range used. `Search-UnifiedAuditLog` is called with explicit UTC dates.
- `ConvertFrom-UalSignInRecord` extracted from `Get-SignInDataFromExchangeOnline` so the record parsing can be tested offline. Behaviour unchanged.

**Not changed (could not be confirmed)**
- The audit record's failure code is still read from `ErrorCode`. Microsoft's schema documents `ErrorCode` and describes `LogonError` as free text, and does not document `ErrorNumber`; the claim that real records carry `ErrorNumber` and a `LogonError` name could not be confirmed from documentation, so the parsing is untouched. Confirm against one real record before changing it.
- `Get-MessageTraceV2` `-StartDate` / `-EndDate`: the documentation does not state how a value without a time zone is read, so those calls are untouched.

**Added**
- `Security/tests/Test-M365SecurityAnalysis.ps1`: offline harness (AST extraction, no tenant connection, no Pester).
- Mailbox-level forwarding (`ForwardingSmtpAddress`, `ForwardingAddress`, `DeliverToMailboxAndForward`) is emitted into `InboxRules.csv` as a `[Mailbox forwarding]` row using the same external-domain test, so the report and scoring pick it up with no template change.

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
