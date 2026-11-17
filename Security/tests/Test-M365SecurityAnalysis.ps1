#Requires -Version 7.0
<#
.SYNOPSIS
    Offline test harness for Security/Get-M365SecurityAnalysis.ps1.

.DESCRIPTION
    The tool cannot be dot-sourced (top-level startup code, WinForms GUI), so this
    harness parses it with the PowerShell AST, extracts every top-level function plus
    the config assignments, and evaluates them into this script's scope. Write-Log and
    Update-GuiStatus are stubbed. Every external call (Graph, Exchange Online, web
    geolocation) is mocked inside the individual test. Nothing here connects to a tenant.

    Plain PowerShell, no Pester. Exit code 1 on any failure.

.PARAMETER ScriptPath
    Script under test. Default: ../Get-M365SecurityAnalysis.ps1

.PARAMETER BaseRef
    Git ref used to find the merge base for the "no new non-ASCII lines" check.

.PARAMETER Only
    Wildcard filter(s) on test names.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot '..\Get-M365SecurityAnalysis.ps1'),
    [string]$BaseRef = 'main',
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
$ScriptPath = (Resolve-Path -Path $ScriptPath).Path
$script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("m365test_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

#region Framework
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:LogLines = [System.Collections.Generic.List[string]]::new()

function Assert-True {
    param($Condition, [string]$Message = 'expected true')
    if (-not $Condition) { throw "ASSERT: $Message" }
}
function Assert-Equal {
    param($Actual, $Expected, [string]$Message = '')
    $a = if ($null -eq $Actual) { '<null>' } else { ($Actual | ConvertTo-Json -Compress -Depth 4) }
    $e = if ($null -eq $Expected) { '<null>' } else { ($Expected | ConvertTo-Json -Compress -Depth 4) }
    if ($a -ne $e) { throw "ASSERT: $Message expected $e but got $a" }
}
function Assert-Match {
    param([string]$Actual, [string]$Pattern, [string]$Message = '')
    if ($Actual -notmatch $Pattern) { throw "ASSERT: $Message '$Actual' does not match /$Pattern/" }
}

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    if ($Only -and -not ($Only | Where-Object { $Name -like $_ })) { return }
    $script:LogLines.Clear()
    try {
        & $Body
        $script:Results.Add([pscustomobject]@{ Name = $Name; Status = 'PASS'; Detail = '' })
        Write-Host "  PASS  $Name" -ForegroundColor Green
    }
    catch {
        $detail = ($_.Exception.Message -replace '\s+', ' ')
        $script:Results.Add([pscustomobject]@{ Name = $Name; Status = 'FAIL'; Detail = $detail })
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        $detail" -ForegroundColor DarkRed
    }
}
function Skip-Case {
    param([string]$Name, [string]$Reason)
    $script:Results.Add([pscustomobject]@{ Name = $Name; Status = 'SKIP'; Detail = $Reason })
    Write-Host "  SKIP  $Name ($Reason)" -ForegroundColor Yellow
}

# Fresh work dir for a test; sets $ConfigData.WorkDir
function New-TestWorkDir {
    $d = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    $ConfigData.WorkDir = $d
    return $d
}

# Runs a script block in a clean child pwsh and returns its stdout lines.
function Invoke-ChildPwsh {
    param([string]$Code)
    $f = Join-Path $script:TestRoot ("child_" + [guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -Path $f -Value $Code -Encoding utf8
    $out = & pwsh -NoProfile -NonInteractive -File $f 2>&1
    return @($out)
}
#endregion

#region Load script under test (AST extraction)
Write-Host "Script under test: $ScriptPath" -ForegroundColor Cyan
$tokens = $null; $parseErrors = $null
$script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
$script:ParseErrors = @($parseErrors)

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Stubs. Real versions touch the console, transcript and GUI.
$script:StubbedFunctions = @('Write-Log', 'Update-GuiStatus')
# A static call cannot be mocked, and a real MessageBox would block a headless run. While
# extracting, every [System.Windows.Forms.MessageBox]::Show( call is rewritten to this stub,
# which receives the original argument list as one array and records it.
function Show-HarnessMessageBox {
    param([object[]]$Arguments)
    $script:LogLines.Add("[Dialog] " + (($Arguments | ForEach-Object { "$_" }) -join ' | '))
    return 'OK'
}
function Write-Log {
    param([string]$Message, [string]$Level = 'Info', [switch]$NoNewLine)
    $script:LogLines.Add("[$Level] $Message")
}
function Update-GuiStatus {
    param([string]$Message, [string]$Color = 'Black')
    $script:LogLines.Add("[Gui] $Message")
}
$Global:StatusLabel = $null
$Global:MainForm = $null

$script:FunctionAsts = @{}
foreach ($stmt in $script:Ast.EndBlock.Statements) {
    if ($stmt -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        if ($script:StubbedFunctions -contains $stmt.Name) { continue }
        $script:FunctionAsts[$stmt.Name] = $stmt
    }
}
# Theme / GUI paint helpers are not under test and some run code at definition time.
$script:SkipPrefixes = @('New-Gui', 'Invoke-Gui', 'Set-Gui', 'Get-Gui', 'Complete-Gui', 'Initialize-Gui', 'Enable-Gui', 'Update-Gui', 'Apply-Theme', 'New-Theme', 'Set-Theme', 'Show-YW')
foreach ($name in $script:FunctionAsts.Keys) {
    if ($script:SkipPrefixes | Where-Object { $name -like "$_*" }) { continue }
    $fnText = $script:FunctionAsts[$name].Extent.Text -replace '\[System\.Windows\.Forms\.MessageBox\]::Show\(', 'Show-HarnessMessageBox ('
    Invoke-Expression $fnText
}

# Config and state assignments evaluated verbatim
$wanted = '$ConfigData', '$ConfigData.ETRAnalysis', '$script:HighRiskISPs', '$script:HatzModelId', '$Global:ConnectionState', '$Global:ExchangeOnlineState', '$Global:IPStackKeyState'
foreach ($stmt in $script:Ast.EndBlock.Statements) {
    if ($stmt -is [System.Management.Automation.Language.AssignmentStatementAst] -and $wanted -contains $stmt.Left.Extent.Text) {
        Invoke-Expression $stmt.Extent.Text
    }
}
$script:ScriptVerMatch = [regex]::Match([System.IO.File]::ReadAllText($ScriptPath), '(?m)^\$ScriptVer\s*=\s*"([^"]+)"')

# Source text of a function by name (for child-process tests)
function Get-FunctionSource {
    param([string[]]$Name)
    ($Name | ForEach-Object {
        if (-not $script:FunctionAsts.ContainsKey($_)) { throw "Function $_ not found in script under test" }
        $script:FunctionAsts[$_].Extent.Text
    }) -join "`n`n"
}
function Test-FunctionExists { param([string]$Name) $script:FunctionAsts.ContainsKey($Name) }
#endregion

#region Static checks
Write-Host "`n== Static checks ==" -ForegroundColor Cyan

Test-Case 'static: zero parse errors' {
    Assert-Equal $script:ParseErrors.Count 0 ("parse errors: " + (($script:ParseErrors | Select-Object -First 3 | ForEach-Object { $_.Message }) -join '; '))
}
Test-Case 'static: UTF-8 BOM present' {
    $b = [System.IO.File]::ReadAllBytes($ScriptPath)[0..2]
    Assert-True (($b[0] -eq 0xEF) -and ($b[1] -eq 0xBB) -and ($b[2] -eq 0xBF)) 'first three bytes must be EF BB BF'
}
Test-Case 'static: CRLF only, no bare LF' {
    $bytes = [System.IO.File]::ReadAllBytes($ScriptPath)
    $bare = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 10 -and ($i -eq 0 -or $bytes[$i - 1] -ne 13)) { $bare++ }
    }
    Assert-Equal $bare 0 'bare LF count'
}
Test-Case 'static: no non-ASCII on added or changed lines' {
    Push-Location (Split-Path -Parent $ScriptPath)
    try {
        $base = (& git merge-base HEAD $BaseRef 2>$null)
        if (-not $base) { throw "cannot find merge base with $BaseRef" }
        $prev = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $diff = & git diff -U0 --no-color $base -- (Split-Path -Leaf $ScriptPath)
        [Console]::OutputEncoding = $prev
        $bad = @($diff | Where-Object { $_ -match '^\+(?!\+\+)' -and $_ -match '[^\x00-\x7F]' })
        # The BOM on line 1 only shows up if line 1 itself changed; ignore that line.
        $bad = @($bad | Where-Object { $_ -notmatch '^\+﻿#{10,}' })
        Assert-Equal $bad.Count 0 ("added lines with non-ASCII, first: " + (($bad | Select-Object -First 1) -replace '[^\x00-\x7F]', '?'))
    }
    finally { Pop-Location }
}
Test-Case 'static: ScriptVer is 12.1' {
    Assert-Equal $script:ScriptVerMatch.Groups[1].Value '12.1' 'ScriptVer'
}
Test-Case 'static: changelog has a 12.1 entry' {
    $cl = Join-Path (Split-Path -Parent $ScriptPath) 'CHANGELOG-Get-M365SecurityAnalysis.md'
    Assert-True ((Get-Content -Raw -Path $cl) -match '(?m)^#+\s*(\[?v?12\.1\]?)') 'no 12.1 heading in changelog'
}
#endregion

#region 2.1 Conditional Access MFA credit
Write-Host "`n== 2.1 Conditional Access MFA credit ==" -ForegroundColor Cyan

# These need the real Graph SDK model types, because the bug is that SDK getters never
# return null for nested objects. Run in a child pwsh so this session stays clean.
$script:SdkModule = Get-Module -ListAvailable -Name Microsoft.Graph.Identity.SignIns | Sort-Object Version -Descending | Select-Object -First 1

function New-CaPolicyJson {
    param([string]$GrantControlsJson, [string]$UsersJson = '{"includeUsers":["All"]}')
    $gc = if ($GrantControlsJson) { ',"grantControls":' + $GrantControlsJson } else { '' }
    return '{"displayName":"t","state":"enabled","conditions":{"users":' + $UsersJson + ',"applications":{"includeApplications":["All"]}}' + $gc + '}'
}

function Invoke-CaSdkChild {
    # $Cases: array of @{ Name; Json; User = @{Id;UserType} } -> returns hashtable Name -> result
    param([object[]]$Cases, [string]$Call, [string[]]$Functions = @('Test-CaPolicyRequiresMfa', 'Test-CaPolicyUserInScope'))
    $fn = Get-FunctionSource -Name $Functions
    $caseJson = ($Cases | ConvertTo-Json -Depth 6 -Compress)
    $caseFile = Join-Path $script:TestRoot ("cases_" + [guid]::NewGuid().ToString('N') + '.json')
    Set-Content -Path $caseFile -Value $caseJson -Encoding utf8
    $code = @"
`$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Identity.SignIns -RequiredVersion '$($script:SdkModule.Version)' -ErrorAction Stop
$fn
`$cases = Get-Content -Raw -Path '$caseFile' | ConvertFrom-Json
`$out = [ordered]@{}
foreach (`$c in @(`$cases)) {
    `$policy = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphConditionalAccessPolicy]::FromJsonString(`$c.Json)
    $Call
}
'RESULT:' + (`$out | ConvertTo-Json -Compress)
"@
    $lines = Invoke-ChildPwsh -Code $code
    $line = $lines | Where-Object { "$_" -like 'RESULT:*' } | Select-Object -Last 1
    if (-not $line) { throw ("child pwsh produced no result: " + ($lines -join ' | ')) }
    return ((("$line").Substring(7)) | ConvertFrom-Json -AsHashtable)
}

if (-not $script:SdkModule) {
    Skip-Case '2.1 CA grant-control table' 'Microsoft.Graph.Identity.SignIns not installed'
    Skip-Case '2.1 CA guest scoping' 'Microsoft.Graph.Identity.SignIns not installed'
}
else {
    Test-Case '2.1 CA grant-control table (real SDK models)' {
        $cases = @(
            @{ Name = 'OR [mfa]';                    Json = (New-CaPolicyJson '{"operator":"OR","builtInControls":["mfa"]}');                            Expect = $true }
            @{ Name = 'AND [compliantDevice,domainJoined]'; Json = (New-CaPolicyJson '{"operator":"AND","builtInControls":["compliantDevice","domainJoinedDevice"]}'); Expect = $false }
            @{ Name = 'OR [block]';                  Json = (New-CaPolicyJson '{"operator":"OR","builtInControls":["block"]}');                          Expect = $false }
            @{ Name = 'no grantControls';            Json = (New-CaPolicyJson '');                                                                       Expect = $false }
            @{ Name = 'auth strength (OR)';          Json = (New-CaPolicyJson '{"operator":"OR","authenticationStrength":{"id":"00000000-0000-0000-0000-000000000002"}}'); Expect = $true }
            @{ Name = 'OR [mfa,compliantDevice]';    Json = (New-CaPolicyJson '{"operator":"OR","builtInControls":["mfa","compliantDevice"]}');         Expect = $false }
            @{ Name = 'AND [mfa,compliantDevice]';   Json = (New-CaPolicyJson '{"operator":"AND","builtInControls":["mfa","compliantDevice"]}');        Expect = $true }
            @{ Name = 'OR [compliantDevice] only';   Json = (New-CaPolicyJson '{"operator":"OR","builtInControls":["compliantDevice"]}');              Expect = $false }
        )
        $res = Invoke-CaSdkChild -Cases $cases -Call '$out[$c.Name] = [bool](Test-CaPolicyRequiresMfa -Policy $policy)'
        $wrong = @($cases | Where-Object { $res[$_.Name] -ne $_.Expect } | ForEach-Object { "$($_.Name) expected $($_.Expect) got $($res[$_.Name])" })
        Assert-Equal $wrong.Count 0 ($wrong -join '; ')
    }

    Test-Case '2.1 CA guest scoping (real SDK models)' {
        $mfa = '{"operator":"OR","builtInControls":["mfa"]}'
        $guestInc = '{"includeGuestsOrExternalUsers":{"guestOrExternalUserTypes":"b2bCollaborationGuest","externalTenants":{"@odata.type":"#microsoft.graph.conditionalAccessAllExternalTenants","membershipKind":"all"}}}'
        $guestExc = '{"includeUsers":["All"],"excludeGuestsOrExternalUsers":{"guestOrExternalUserTypes":"b2bCollaborationGuest","externalTenants":{"@odata.type":"#microsoft.graph.conditionalAccessAllExternalTenants","membershipKind":"all"}}}'
        $guestInUsers = '{"includeUsers":["GuestsOrExternalUsers"]}'
        $cases = @(
            # A guest is NOT in scope of a members-only policy (include list does not name guests)
            @{ Name = 'guest vs include specific user';   Json = (New-CaPolicyJson $mfa '{"includeUsers":["11111111-1111-1111-1111-111111111111"]}'); User = @{ Id = '22222222-2222-2222-2222-222222222222'; UserType = 'Guest' }; Expect = $false }
            @{ Name = 'guest vs includeGuests set';       Json = (New-CaPolicyJson $mfa $guestInc);   User = @{ Id = '22222222-2222-2222-2222-222222222222'; UserType = 'Guest' }; Expect = $true }
            @{ Name = 'guest vs includeUsers GuestsOrExternalUsers'; Json = (New-CaPolicyJson $mfa $guestInUsers); User = @{ Id = '22222222-2222-2222-2222-222222222222'; UserType = 'Guest' }; Expect = $true }
            @{ Name = 'guest vs All + excludeGuests set'; Json = (New-CaPolicyJson $mfa $guestExc);   User = @{ Id = '22222222-2222-2222-2222-222222222222'; UserType = 'Guest' }; Expect = $false }
            @{ Name = 'guest vs All (no guest props)';    Json = (New-CaPolicyJson $mfa);             User = @{ Id = '22222222-2222-2222-2222-222222222222'; UserType = 'Guest' }; Expect = $true }
            @{ Name = 'member vs All + excludeGuests set';Json = (New-CaPolicyJson $mfa $guestExc);   User = @{ Id = '33333333-3333-3333-3333-333333333333'; UserType = 'Member' }; Expect = $true }
            @{ Name = 'member vs includeGuests only';     Json = (New-CaPolicyJson $mfa $guestInc);   User = @{ Id = '33333333-3333-3333-3333-333333333333'; UserType = 'Member' }; Expect = $false }
            @{ Name = 'member excluded by id';            Json = (New-CaPolicyJson $mfa '{"includeUsers":["All"],"excludeUsers":["33333333-3333-3333-3333-333333333333"]}'); User = @{ Id = '33333333-3333-3333-3333-333333333333'; UserType = 'Member' }; Expect = $false }
        )
        $call = '$out[$c.Name] = [bool](Test-CaPolicyUserInScope -Policy $policy -UserId $c.User.Id -IsGuest ($c.User.UserType -eq "Guest") -RoleTemplateIds $null -GroupMembershipCache @{})'
        $res = Invoke-CaSdkChild -Cases $cases -Call $call
        $wrong = @($cases | Where-Object { $res[$_.Name] -ne $_.Expect } | ForEach-Object { "$($_.Name) expected $($_.Expect) got $($res[$_.Name])" })
        Assert-Equal $wrong.Count 0 ($wrong -join '; ')
    }
}
#endregion

#region 2.2 Exchange Online session vs Graph tenant
Write-Host "`n== 2.2 Exchange Online tenant binding ==" -ForegroundColor Cyan

# Shared mock world for the EXO tests. Stubs are defined inside each test body so they
# shadow real cmdlets only for that test.
function Initialize-ExoMock {
    param([string]$ExoTenant, [string]$GraphTenant)
    $script:Mock = @{ ExoTenant = $ExoTenant; GraphTenant = $GraphTenant; Calls = [System.Collections.Generic.List[string]]::new() }
    $Global:ExchangeOnlineState = @{
        IsConnected = [bool]$ExoTenant; LastChecked = $null; ConnectionAttempts = 0
        LastCollectionComplete = $false; LastCollectionWarning = 'previous gap'
    }
    $Global:ConnectionState = @{ IsConnected = $true; TenantId = $GraphTenant; TenantName = 't'; Account = 'a@b.c'; ConnectedAt = $null }
}

Test-Case '2.2 EXO session of another tenant is dropped and replaced' {
    Initialize-ExoMock -ExoTenant 'aaaaaaaa-0000-0000-0000-000000000001' -GraphTenant 'bbbbbbbb-0000-0000-0000-000000000002'
    function Get-Module { param($Name, [switch]$ListAvailable) [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } }
    function Import-Module { param($Name, [switch]$Force) }
    function Get-MgContext { [pscustomobject]@{ TenantId = $script:Mock.GraphTenant; Account = 'admin@b.example' } }
    function Get-ConnectionInformation { if ($script:Mock.ExoTenant) { [pscustomobject]@{ State = 'Connected'; TenantID = $script:Mock.ExoTenant } } }
    function Get-AcceptedDomain { if ($script:Mock.ExoTenant) { [pscustomobject]@{ DomainName = 'x.example' } } else { throw 'no session' } }
    function Disconnect-ExchangeOnline { param([switch]$Confirm, $ErrorAction) $script:Mock.Calls.Add('disconnect'); $script:Mock.ExoTenant = $null }
    function Connect-ExchangeOnline { param($UserPrincipalName, [switch]$ShowBanner, [switch]$DisableWAM, [switch]$Device, $ErrorAction) $script:Mock.Calls.Add('connect'); $script:Mock.ExoTenant = $script:Mock.GraphTenant }

    $ok = Connect-ExchangeOnlineIfNeeded
    Assert-True $ok 'should end up connected'
    Assert-Equal @($script:Mock.Calls) @('disconnect', 'connect') 'call order'
    Assert-Equal $script:Mock.ExoTenant $script:Mock.GraphTenant 'EXO tenant now matches Graph'
    Assert-Equal $Global:ExchangeOnlineState.LastCollectionComplete $false 'LastCollectionComplete must survive'
    Assert-Equal $Global:ExchangeOnlineState.LastCollectionWarning 'previous gap' 'LastCollectionWarning must survive'
    Assert-True $Global:ExchangeOnlineState.IsConnected 'state IsConnected'
}

Test-Case '2.2 EXO session of the same tenant is reused' {
    Initialize-ExoMock -ExoTenant 'BBBBBBBB-0000-0000-0000-000000000002' -GraphTenant 'bbbbbbbb-0000-0000-0000-000000000002'
    function Get-Module { param($Name, [switch]$ListAvailable) [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } }
    function Import-Module { param($Name, [switch]$Force) }
    function Get-MgContext { [pscustomobject]@{ TenantId = $script:Mock.GraphTenant; Account = 'admin@b.example' } }
    function Get-ConnectionInformation { if ($script:Mock.ExoTenant) { [pscustomobject]@{ State = 'Connected'; TenantID = $script:Mock.ExoTenant } } }
    function Get-AcceptedDomain { if ($script:Mock.ExoTenant) { [pscustomobject]@{ DomainName = 'x.example' } } else { throw 'no session' } }
    function Disconnect-ExchangeOnline { param([switch]$Confirm, $ErrorAction) $script:Mock.Calls.Add('disconnect') }
    function Connect-ExchangeOnline { param($UserPrincipalName, [switch]$ShowBanner, [switch]$DisableWAM, [switch]$Device, $ErrorAction) $script:Mock.Calls.Add('connect') }

    $ok = Connect-ExchangeOnlineIfNeeded
    Assert-True $ok 'should be connected'
    Assert-Equal $script:Mock.Calls.Count 0 'no disconnect/connect when tenants match (case-insensitive)'
    Assert-Equal $Global:ExchangeOnlineState.LastCollectionWarning 'previous gap' 'LastCollectionWarning must survive'
}

Test-Case '2.2 Disconnect-GraphSafely also drops the Exchange Online session' {
    Initialize-ExoMock -ExoTenant 'aaaaaaaa-0000-0000-0000-000000000001' -GraphTenant 'aaaaaaaa-0000-0000-0000-000000000001'
    function Get-ConnectionInformation { if ($script:Mock.ExoTenant) { [pscustomobject]@{ State = 'Connected'; TenantID = $script:Mock.ExoTenant } } }
    function Disconnect-ExchangeOnline { param([switch]$Confirm, $ErrorAction) $script:Mock.Calls.Add('disconnect-exo'); $script:Mock.ExoTenant = $null }
    function Disconnect-MgGraph { param($ErrorAction) $script:Mock.Calls.Add('disconnect-graph') }
    function Update-ConnectionStatus { }
    Disconnect-GraphSafely
    Assert-True ($script:Mock.Calls -contains 'disconnect-graph') 'graph disconnected'
    Assert-True ($script:Mock.Calls -contains 'disconnect-exo') 'EXO disconnected'
    Assert-Equal $Global:ExchangeOnlineState.IsConnected $false 'EXO state reset'
    Assert-Equal $Global:ExchangeOnlineState.LastCollectionWarning 'previous gap' 'LastCollectionWarning must survive'
}

Test-Case '2.2 no leftover Get-PSSession Microsoft.Exchange checks' {
    $src = [System.IO.File]::ReadAllText($ScriptPath)
    Assert-True ($src -notmatch 'ConfigurationName\s+-eq\s+"Microsoft\.Exchange"') 'EXO v3 never creates a Microsoft.Exchange PSSession'
}
#endregion

#region 2.3 Message trace direction
Write-Host "`n== 2.3 Message trace direction ==" -ForegroundColor Cyan

function New-TraceCsv {
    # Writes MessageTraceResult.csv exactly as Get-MessageTraceExchangeOnline lays it out.
    param([string]$Dir, [int]$Count, [string]$Sender, [string]$RecipientFormat, [string]$Direction, [string]$Subject = 'Quarterly invoice attached')
    $rows = 1..$Count | ForEach-Object {
        [pscustomobject]@{
            message_trace_id = [guid]::NewGuid().ToString(); sender_address = $Sender
            recipient_address = ($RecipientFormat -f $_); subject = $Subject; status = 'Delivered'
            to_ip = ''; from_ip = '203.0.113.9'; message_size = 1000; received = '2026-11-10T10:00:00Z'
            message_direction = $Direction; message_id = "<$_@x>"; event_type = 'MessageTraceV2'
            timestamp = '2026-11-10T10:00:00Z'; date = '2026-11-10T10:00:00Z'
        }
    }
    $rows | Export-Csv -Path (Join-Path $Dir 'MessageTraceResult.csv') -NoTypeInformation -Force
}

Test-Case '2.3 analyzer: tool-written rows with direction Unknown are analysed' {
    $d = New-TestWorkDir
    New-TraceCsv -Dir $d -Count 60 -Sender 'user@contoso.com' -RecipientFormat 'r{0}@ext.example' -Direction 'Unknown'
    $res = @(Analyze-ETRData)
    $ind = @($res | Where-Object { $_.RiskType -eq 'IdenticalSubjects' })
    Assert-Equal $ind.Count 1 'IdenticalSubjects indicator count'
}
Test-Case '2.3 analyzer: Internal rows count, Inbound rows do not' {
    $d = New-TestWorkDir
    New-TraceCsv -Dir $d -Count 60 -Sender 'user@contoso.com' -RecipientFormat 'r{0}@contoso.com' -Direction 'Internal'
    $internal = @(Analyze-ETRData | Where-Object { $_.RiskType -eq 'IdenticalSubjects' })
    Assert-Equal $internal.Count 1 'Internal spam must be detected'

    $d = New-TestWorkDir
    New-TraceCsv -Dir $d -Count 60 -Sender 'news@ext.example' -RecipientFormat 'r{0}@contoso.com' -Direction 'Inbound'
    $inbound = @(Analyze-ETRData | Where-Object { $_.RiskType -eq 'IdenticalSubjects' })
    Assert-Equal $inbound.Count 0 'Inbound bulk mail is not a compromised-account signal'
}

function Initialize-TraceMock {
    param([bool]$DomainsAvailable)
    $script:Mock = @{ Domains = $DomainsAvailable }
}
Test-Case '2.3 collector: direction is derived from accepted domains' {
    $d = New-TestWorkDir
    Initialize-TraceMock -DomainsAvailable $true
    function Connect-ExchangeOnlineIfNeeded { $true }
    function Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'contoso.com' }; [pscustomobject]@{ DomainName = 'Contoso.onmicrosoft.com' } }
    function Get-MessageTraceV2 {
        param($StartDate, $EndDate, $ResultSize, $StartingRecipientAddress, $ErrorAction)
        $mk = { param($s, $r, $i) [pscustomobject]@{ MessageTraceId = [guid]::NewGuid(); SenderAddress = $s; RecipientAddress = $r; Subject = 's'; Status = 'Delivered'; ToIP = ''; FromIP = ''; Size = 1; Received = [datetime]::UtcNow.AddMinutes(-$i); MessageId = "<$i@x>" } }
        & $mk 'a@contoso.com' 'x@ext.example' 1
        & $mk 'a@contoso.com' 'b@contoso.com' 2
        & $mk 'ext@ext.example' 'a@contoso.com' 3
        & $mk 'A@CONTOSO.COM' 'y@ext.example' 4
    }
    $null = Get-MessageTraceExchangeOnline -DaysBack 1
    $rows = @(Import-Csv -Path (Join-Path $d 'MessageTraceResult.csv'))
    Assert-Equal $rows.Count 4 'row count'
    Assert-Equal @($rows | ForEach-Object { $_.message_direction }) @('Outbound', 'Internal', 'Inbound', 'Outbound') 'directions'
}
Test-Case '2.3 collector: unreadable accepted domains leaves direction empty and records a gap' {
    $d = New-TestWorkDir
    function Connect-ExchangeOnlineIfNeeded { $true }
    function Get-AcceptedDomain { throw 'Access denied' }
    function Get-MessageTraceV2 {
        param($StartDate, $EndDate, $ResultSize, $StartingRecipientAddress, $ErrorAction)
        [pscustomobject]@{ MessageTraceId = [guid]::NewGuid(); SenderAddress = 'a@contoso.com'; RecipientAddress = 'x@ext.example'; Subject = 's'; Status = 'Delivered'; ToIP = ''; FromIP = ''; Size = 1; Received = [datetime]::UtcNow.AddMinutes(-1); MessageId = '<1@x>' }
    }
    $null = Get-MessageTraceExchangeOnline -DaysBack 1
    $rows = @(Import-Csv -Path (Join-Path $d 'MessageTraceResult.csv'))
    Assert-Equal $rows[0].message_direction '' 'direction must stay empty'
    $st = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'MessageTrace' })[0]
    Assert-Equal $st.Complete 'False' 'status must be incomplete'
    Assert-Match $st.Note 'direction' 'note must mention direction'
}
#endregion

#region 2.4 IP classification and unusual-location flags
Write-Host "`n== 2.4 IP classification ==" -ForegroundColor Cyan

Test-Case '2.4 Get-IPClassification address table' {
    $table = @(
        @{ Ip = '10.1.1.1';             Valid = $true;  Private = $true;  Eff = '10.1.1.1' }
        @{ Ip = '100.64.0.1';           Valid = $true;  Private = $true;  Eff = '100.64.0.1' }
        @{ Ip = '100.128.0.1';          Valid = $true;  Private = $false; Eff = '100.128.0.1' }
        @{ Ip = '172.16.5.5';           Valid = $true;  Private = $true;  Eff = '172.16.5.5' }
        @{ Ip = '172.32.0.1';           Valid = $true;  Private = $false; Eff = '172.32.0.1' }
        @{ Ip = '192.168.1.1';          Valid = $true;  Private = $true;  Eff = '192.168.1.1' }
        @{ Ip = '169.254.1.1';          Valid = $true;  Private = $true;  Eff = '169.254.1.1' }
        @{ Ip = '127.0.0.1';            Valid = $true;  Private = $true;  Eff = '127.0.0.1' }
        @{ Ip = '8.8.8.8';              Valid = $true;  Private = $false; Eff = '8.8.8.8' }
        @{ Ip = '::1';                  Valid = $true;  Private = $true;  Eff = '::1' }
        @{ Ip = 'fe80::1';              Valid = $true;  Private = $true;  Eff = 'fe80::1' }
        @{ Ip = 'fea0::1';              Valid = $true;  Private = $true;  Eff = 'fea0::1' }
        @{ Ip = 'febf::1';              Valid = $true;  Private = $true;  Eff = 'febf::1' }
        @{ Ip = 'fec0::1';              Valid = $true;  Private = $true;  Eff = 'fec0::1' }
        @{ Ip = 'fd00::1';              Valid = $true;  Private = $true;  Eff = 'fd00::1' }
        @{ Ip = '2001:4860:4860::8888'; Valid = $true;  Private = $false; Eff = '2001:4860:4860::8888' }
        @{ Ip = '::ffff:8.8.8.8';       Valid = $true;  Private = $false; Eff = '8.8.8.8' }
        @{ Ip = '::ffff:10.0.0.1';      Valid = $true;  Private = $true;  Eff = '10.0.0.1' }
        @{ Ip = 'garbage';              Valid = $false; Private = $false; Eff = 'garbage' }
        @{ Ip = '1';                    Valid = $false; Private = $false; Eff = '1' }
        @{ Ip = '';                     Valid = $false; Private = $false; Eff = '' }
    )
    $wrong = foreach ($t in $table) {
        $c = Get-IPClassification -IPAddress $t.Ip
        if ($c.IsValid -ne $t.Valid -or $c.IsPrivate -ne $t.Private -or "$($c.EffectiveAddress)" -ne $t.Eff) {
            "$($t.Ip): valid=$($c.IsValid) private=$($c.IsPrivate) eff=$($c.EffectiveAddress)"
        }
    }
    Assert-Equal @($wrong).Count 0 (@($wrong) -join ' | ')
}

Test-Case '2.4 Test-UnusualCountry' {
    $ConfigData.ExpectedCountries = @('United States', 'Canada')
    $cases = @(
        @{ C = 'Germany';         E = $true }
        @{ C = 'United States';   E = $false }
        @{ C = 'Canada';          E = $false }
        @{ C = '';                E = $false }
        @{ C = $null;             E = $false }
        @{ C = 'Unknown';         E = $false }
        @{ C = 'Private Network'; E = $false }
        @{ C = 'Invalid IP';      E = $false }
    )
    $wrong = foreach ($c in $cases) { if ((Test-UnusualCountry -Country $c.C) -ne $c.E) { "'$($c.C)' expected $($c.E)" } }
    Assert-Equal @($wrong).Count 0 (@($wrong) -join ' | ')
}

Test-Case '2.4 sign-in collector: private and unknown IPs are never unusual' {
    $d = New-TestWorkDir
    $ConfigData.ExpectedCountries = @('United States', 'Canada')
    $ConfigData.GeolocationRateLimit = 0
    $script:Web = [System.Collections.Generic.List[string]]::new()
    $script:IpCacheProbe = $null
    function Import-Module { param($Name, [switch]$Force, [switch]$DisableNameChecking, $ErrorAction) }
    function Test-PremiumSignInLicense { $true }
    function Get-ValidatedIPStackKey { $null }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    function Invoke-RestMethod {
        param($Uri, $Method, $TimeoutSec, $ErrorAction)
        $script:Web.Add($Uri)
        if ($Uri -match '203\.0\.113\.5')  { return [pscustomobject]@{ status = 'success'; query = '203.0.113.5'; country = 'Germany'; city = 'Berlin'; regionName = 'BE'; isp = 'Example ISP'; lat = 1; lon = 1 } }
        if ($Uri -match '8\.8\.8\.8')      { return [pscustomobject]@{ status = 'success'; query = '8.8.8.8'; country = 'United States'; city = 'Mountain View'; regionName = 'CA'; isp = 'Google LLC'; lat = 1; lon = 1 } }
        throw 'simulated lookup failure'
    }
    function New-SignIn { param($Ip, $N) [pscustomobject]@{
        Id = "id$N"; UserPrincipalName = 'user@contoso.com'; UserDisplayName = 'User'; CreatedDateTime = ([datetime]'2026-11-10T10:00:00Z').AddMinutes($N)
        UserAgent = 'ua'; IpAddress = $Ip; Status = [pscustomobject]@{ ErrorCode = 0 }; ConditionalAccessStatus = 'success'
        RiskLevelDuringSignIn = 'none'; DeviceDetail = [pscustomobject]@{ OperatingSystem = 'Windows'; Browser = 'Edge' }
        IsInteractive = $true; AppDisplayName = 'Portal' } }
    $ips = '10.0.0.1', '100.64.0.1', '::ffff:10.0.0.1', 'fe80::1', 'fea0::1', 'fec0::1', 'fd00::1', '::1', 'Unknown', '', '198.51.100.7', '::ffff:8.8.8.8', '203.0.113.5'
    $script:SignIns = @(); $n = 0
    foreach ($ip in $ips) { $n++; $script:SignIns += (New-SignIn -Ip $ip -N $n) }
    function Get-MgBetaAuditLogSignIn { param($Filter, [switch]$All, $ErrorAction) $script:SignIns }

    $res = @(Get-TenantSignInData -DaysBack 7)
    Assert-Equal $res.Count $ips.Count 'row count'
    $unusual = @($res | Where-Object { $_.IsUnusualLocation -eq $true } | ForEach-Object { $_.IP })
    Assert-Equal $unusual @('203.0.113.5') 'only the German public IP is unusual'
    $mapped = $res | Where-Object { $_.IP -eq '::ffff:8.8.8.8' }
    Assert-Equal $mapped.Country 'United States' 'mapped public IPv4 is geolocated as IPv4'
    $mappedPriv = $res | Where-Object { $_.IP -eq '::ffff:10.0.0.1' }
    Assert-Equal $mappedPriv.IsPrivateIP $true 'mapped private IPv4 is private'
    $privWeb = @($script:Web | Where-Object { $_ -match '10\.0\.0\.1|100\.64|fe80|fea0|fec0|fd00|::1' })
    Assert-Equal $privWeb.Count 0 'no web lookups for private addresses'
    $uniqPath = Join-Path $d 'UniqueSignInLocations.csv'
    Assert-True (Test-Path $uniqPath) 'UniqueSignInLocations.csv written'
    $uniq = @(Import-Csv $uniqPath)
    Assert-True ($uniq[0].PSObject.Properties.Name -contains 'IPVersion') 'IPVersion column present'
    $uniqUnusual = @($uniq | Where-Object { $_.IsUnusualLocation -eq 'True' } | ForEach-Object { $_.IP })
    Assert-Equal $uniqUnusual @('203.0.113.5') 'unique-location file flags only the German IP'
}

Test-Case '2.4 Invoke-CompromiseDetection does not rewrite UniqueSignInLocations.csv' {
    $src = (@('Invoke-CompromiseDetection', 'Invoke-CompromiseDetectionCore') | Where-Object { $script:FunctionAsts.ContainsKey($_) } | ForEach-Object { $script:FunctionAsts[$_].Extent.Text }) -join "`n"
    Assert-True ($src -notmatch 'UniqueSignInLocations\.csv') 'duplicate unique-location block must be removed from the analyzer'
}
#endregion

#region 2.5 Audit-log sign-in fallback and failed-login patterns
Write-Host "`n== 2.5 UAL fallback / failed-login patterns ==" -ForegroundColor Cyan

function New-SignInCsv {
    # Rows shaped like UserLocationData.csv. $Rows: array of hashtables (IP, User, Code, Minute).
    param([string]$Dir, [object[]]$Rows)
    $out = foreach ($r in $Rows) {
        [pscustomobject]@{
            CreationTime = ([datetime]'2026-11-10T10:00:00Z').AddMinutes($r.Minute).ToString('o'); UserId = $r.User; UserDisplayName = $r.User
            IP = $r.IP; IPVersion = 'IPv4'; IsPrivateIP = 'False'; City = 'X'; RegionName = 'X'; Country = 'Germany'; ISP = 'ISP'
            IsHighRiskISP = 'False'; IsUnusualLocation = 'True'; GeoLookupFailed = 'False'; StatusCode = $r.Code; Status = 'x'
        }
    }
    $out | Export-Csv -Path (Join-Path $Dir 'UserLocationData.csv') -NoTypeInformation -Force
}

Test-Case '2.5 failed logins with IP "Unknown" never form spray, breach or MFA-held patterns' {
    $d = New-TestWorkDir
    $rows = @()
    $m = 0
    foreach ($u in 1..5) { foreach ($k in 1..3) { $m++; $rows += @{ IP = 'Unknown'; User = "u$u@contoso.com"; Code = '50126'; Minute = $m } } }
    # successes and MFA challenges for the same "Unknown" source, to tempt breach / MFA-held matching
    foreach ($u in 1..5) { $m += 5; $rows += @{ IP = 'Unknown'; User = "u$u@contoso.com"; Code = '0'; Minute = $m }; $rows += @{ IP = 'Unknown'; User = "u$u@contoso.com"; Code = '50074'; Minute = $m + 1 } }
    New-SignInCsv -Dir $d -Rows $rows
    $res = @(Get-FailedLoginPatterns)
    $bad = @($res | Where-Object { $_.PatternType -in @('Password Spray', 'Successful Breach', 'Password Guessed - MFA Held') })
    Assert-Equal $bad.Count 0 ("unexpected patterns: " + (($bad | ForEach-Object { "$($_.PatternType)/$($_.SourceIP)" }) -join ', '))
}

Test-Case '2.5 control: a real source IP still produces a spray pattern' {
    $d = New-TestWorkDir
    $rows = @(); $m = 0
    foreach ($u in 1..5) { foreach ($k in 1..2) { $m++; $rows += @{ IP = '203.0.113.9'; User = "u$u@contoso.com"; Code = '50126'; Minute = $m } } }
    New-SignInCsv -Dir $d -Rows $rows
    $res = @(Get-FailedLoginPatterns)
    Assert-Equal @($res | Where-Object { $_.PatternType -eq 'Password Spray' }).Count 1 'spray from a real IP'
}

Test-Case '2.5 ConvertFrom-UalSignInRecord keeps documented ErrorCode handling' {
    # Fields per the Office 365 Management Activity API schema for AzureActiveDirectoryStsLogon:
    # ErrorCode ("0" = success), LogonError (free-text description), Operation.
    $mk = { param($json) [pscustomobject]@{ AuditData = $json; CreationDate = [datetime]'2026-11-10'; UserIds = 'fallback@contoso.com'; Operations = 'UserLoggedIn' } }
    $ok   = ConvertFrom-UalSignInRecord -Log (& $mk '{"CreationTime":"2026-11-10T10:00:00","Operation":"UserLoggedIn","UserId":"a@contoso.com","ClientIP":"203.0.113.9","ErrorCode":"0"}')
    $fail = ConvertFrom-UalSignInRecord -Log (& $mk '{"CreationTime":"2026-11-10T10:01:00","Operation":"UserLoginFailed","UserId":"a@contoso.com","ClientIP":"203.0.113.9","ErrorCode":"50126","LogonError":"Invalid username or password"}')
    $lock = ConvertFrom-UalSignInRecord -Log (& $mk '{"CreationTime":"2026-11-10T10:02:00","Operation":"UserLoginFailed","UserId":"a@contoso.com","IPAddress":"203.0.113.9","ErrorCode":"50053"}')
    $none = ConvertFrom-UalSignInRecord -Log (& $mk '{"CreationTime":"2026-11-10T10:03:00","Operation":"UserLoginFailed","UserId":"a@contoso.com","UserAgent":"curl/8"}')
    Assert-Equal $ok.StatusCode '0' 'success code'
    Assert-Equal $fail.StatusCode '50126' 'failure code'
    Assert-Equal $lock.StatusCode '50053' 'lockout code'
    Assert-Equal $lock.IpAddress '203.0.113.9' 'IPAddress field read'
    Assert-Equal $none.IpAddress 'Unknown' 'missing IP placeholder'
    Assert-Equal $none.StatusCode '50126' 'UserLoginFailed without a code defaults to 50126 (unchanged behaviour)'
}

Test-Case '2.5 UAL fallback honours ranges beyond 10 days and passes UTC dates' {
    $d = New-TestWorkDir
    $script:Mock = @{ Calls = [System.Collections.Generic.List[object]]::new() }
    function Connect-ExchangeOnlineIfNeeded { $true }
    function Search-UnifiedAuditLog {
        param($StartDate, $EndDate, $RecordType, $ResultSize, $SessionId, $SessionCommand, $ErrorAction)
        $script:Mock.Calls.Add(@{ Start = $StartDate; End = $EndDate })
        @()
    }
    $null = Get-SignInDataFromExchangeOnline -DaysBack 30
    Assert-True ($script:Mock.Calls.Count -gt 0) 'Search-UnifiedAuditLog was called'
    $first = $script:Mock.Calls[0]; $last = $script:Mock.Calls[-1]
    Assert-Equal $first.Start.Kind ([System.DateTimeKind]::Utc) 'StartDate must be explicit UTC'
    Assert-Equal $first.End.Kind ([System.DateTimeKind]::Utc) 'EndDate must be explicit UTC'
    $span = ($last.End - $first.Start).TotalDays
    Assert-True ($span -gt 29 -and $span -lt 31) "range covered should be about 30 days, got $span"
}

Test-Case '2.5 Get-TenantSignInData asks the fallback for the full requested range (up to 180 days)' {
    $d = New-TestWorkDir
    $ConfigData.GeolocationRateLimit = 0
    $script:Mock = @{ Days = $null }
    function Import-Module { param($Name, [switch]$Force, [switch]$DisableNameChecking, $ErrorAction) }
    function Test-PremiumSignInLicense { $false }
    function Get-ValidatedIPStackKey { $null }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    function Invoke-RestMethod { param($Uri, $Method, $TimeoutSec, $ErrorAction) throw 'offline' }
    function Get-SignInDataFromExchangeOnline {
        param($DaysBack)
        $script:Mock.Days = $DaysBack
        [pscustomobject]@{ CreatedDateTime = [datetime]'2026-11-10'; UserPrincipalName = 'a@contoso.com'; UserDisplayName = 'a'; IpAddress = '203.0.113.9'
            Status = @{ ErrorCode = '0' }; StatusCode = '0'; UserAgent = 'x'; IsInteractive = $true; AppDisplayName = 'x'; ConditionalAccessStatus = 'notAvailable'
            RiskLevelDuringSignIn = 'notAvailable'; DeviceDetail = @{ OperatingSystem = 'Unknown'; Browser = 'Unknown' } }
    }
    $null = Get-TenantSignInData -DaysBack 90
    Assert-Equal $script:Mock.Days 90 'fallback DaysBack for a 90 day request'
    $null = Get-TenantSignInData -DaysBack 300
    Assert-Equal $script:Mock.Days 180 'fallback is capped at the 180 day audit retention, not 10'
    $st = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'SignIns' })[0]
    Assert-Match $st.Note '180 day' 'coverage note must state the range used'
}
#endregion

#region 2.6 Failed collectors must not leave the previous run looking current
Write-Host "`n== 2.6 Collector failure status ==" -ForegroundColor Cyan

# $Mode: 'throw'  -> the first external call throws (collector's outer catch)
#        'false'  -> Connect-ExchangeOnlineIfNeeded returns $false (collector's early return)
function Assert-CollectorFailsLoudly {
    param([string]$Source, [scriptblock]$Invoke, [ValidateSet('throw', 'false')][string]$Mode = 'throw')
    $d = New-TestWorkDir
    $oldFile = Join-Path $d 'OLD.csv'
    Set-CollectionStatus -Source $Source -Complete $true -Records 5 -Note ''
    $script:Mock = @{ Mode = $Mode }
    $sim = 'simulated outage'
    function Connect-ExchangeOnlineIfNeeded { if ($script:Mock.Mode -eq 'throw') { throw 'simulated outage' } else { $false } }
    function Get-MgUser { throw 'simulated outage' }
    function Get-MgIdentityConditionalAccessPolicy { throw 'simulated outage' }
    function Get-MgApplication { throw 'simulated outage' }
    function Get-MgServicePrincipal { throw 'simulated outage' }
    function Invoke-MgGraphRequest { throw 'simulated outage' }
    function Get-AdminRoleMap { throw 'simulated outage' }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    function Import-Module { param($Name, [switch]$Force, [switch]$DisableNameChecking, $ErrorAction) }
    $null = & $Invoke
    $row = @(Get-CollectionStatus | Where-Object { $_.Source -eq $Source })
    Assert-Equal $row.Count 1 "exactly one status row for $Source"
    Assert-Equal $row[0].Complete 'False' "$Source must be marked incomplete (was: $($row[0].Note))"
    Assert-Match $row[0].Note 'FAILED|EARLIER run' "$Source note must say the run failed"
}

Test-Case '2.6 MFAAudit failure is recorded'            { Assert-CollectorFailsLoudly -Source 'MFAAudit' -Invoke { Get-MFAStatusAudit } }
Test-Case '2.6 InboxRules failure (exception) is recorded'   { Assert-CollectorFailsLoudly -Source 'InboxRules' -Mode throw -Invoke { Get-MailboxRules } }
Test-Case '2.6 InboxRules failure (no EXO connection) is recorded' { Assert-CollectorFailsLoudly -Source 'InboxRules' -Mode false -Invoke { Get-MailboxRules } }
Test-Case '2.6 MailboxDelegation failure (exception) is recorded' { Assert-CollectorFailsLoudly -Source 'MailboxDelegation' -Mode throw -Invoke { Get-MailboxDelegationData } }
Test-Case '2.6 MailboxDelegation failure (no EXO connection) is recorded' { Assert-CollectorFailsLoudly -Source 'MailboxDelegation' -Mode false -Invoke { Get-MailboxDelegationData } }
Test-Case '2.6 AppRegistrations failure is recorded'    { Assert-CollectorFailsLoudly -Source 'AppRegistrations' -Invoke { Get-AppRegistrationData } }
Test-Case '2.6 ConditionalAccess failure is recorded'   { Assert-CollectorFailsLoudly -Source 'ConditionalAccess' -Invoke { Get-ConditionalAccessData } }
Test-Case '2.6 MessageTrace failure (exception) is recorded' { Assert-CollectorFailsLoudly -Source 'MessageTrace' -Mode throw -Invoke { Get-MessageTraceExchangeOnline } }
Test-Case '2.6 MessageTrace failure (no EXO connection) is recorded' { Assert-CollectorFailsLoudly -Source 'MessageTrace' -Mode false -Invoke { Get-MessageTraceExchangeOnline } }

Test-Case '2.6 InboxRules with zero mailboxes is recorded as incomplete and clears old output' {
    $d = New-TestWorkDir
    Set-CollectionStatus -Source 'InboxRules' -Complete $true -Records 9
    'old' | Set-Content (Join-Path $d 'InboxRules.csv')
    function Connect-ExchangeOnlineIfNeeded { $true }
    function Get-Mailbox { param($ResultSize, $RecipientTypeDetails, $ErrorAction) @() }
    $null = Get-MailboxRules
    $row = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'InboxRules' })[0]
    Assert-Equal $row.Complete 'False' 'incomplete'
    Assert-True (-not (Test-Path (Join-Path $d 'InboxRules.csv'))) 'old InboxRules.csv must be removed'
}

Test-Case '2.6 ETR analysis records its outcome and removes stale output' {
    $d = New-TestWorkDir
    Set-CollectionStatus -Source 'ETRAnalysis' -Complete $true -Records 3
    'old' | Set-Content (Join-Path $d 'ETRSpamAnalysis.csv')
    'old' | Set-Content (Join-Path $d 'ETRSpamAnalysis_MessageRecallReport.csv')
    $null = Analyze-ETRData   # no ETR file in the work dir
    Assert-True (-not (Test-Path (Join-Path $d 'ETRSpamAnalysis.csv'))) 'old ETRSpamAnalysis.csv removed'
    Assert-True (-not (Test-Path (Join-Path $d 'ETRSpamAnalysis_MessageRecallReport.csv'))) 'old recall report removed'
    $row = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'ETRAnalysis' })
    Assert-Equal $row.Count 1 'one ETRAnalysis row'
    Assert-Equal $row[0].Complete 'False' 'no ETR file means the analysis did not run'
}

Test-Case '2.6 ETR analysis success is recorded as complete' {
    $d = New-TestWorkDir
    New-TraceCsv -Dir $d -Count 60 -Sender 'user@contoso.com' -RecipientFormat 'r{0}@ext.example' -Direction 'Outbound'
    $null = Analyze-ETRData
    $row = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'ETRAnalysis' })
    Assert-Equal $row.Count 1 'one ETRAnalysis row'
    Assert-Equal $row[0].Complete 'True' 'complete after a good run'
    Assert-Equal $row[0].Records '60' 'records analysed'
}

Test-Case '2.6 message trace: only connection errors mark Exchange Online disconnected' {
    $d = New-TestWorkDir
    function Connect-ExchangeOnlineIfNeeded { $true }
    function Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'contoso.com' } }
    $script:Mock = @{ Err = 'Cannot bind parameter StartDate: value out of range' }
    function Get-MessageTraceV2 { param($StartDate, $EndDate, $ResultSize, $StartingRecipientAddress, $ErrorAction) throw $script:Mock.Err }
    $Global:ExchangeOnlineState = @{ IsConnected = $true; LastCollectionComplete = $true; LastCollectionWarning = $null; ConnectionAttempts = 0 }
    $null = Get-MessageTraceExchangeOnline
    Assert-Equal $Global:ExchangeOnlineState.IsConnected $true 'a non-connection error must not flag EXO as disconnected'
    $script:Mock.Err = 'The remote server returned an error: (401) Unauthorized. The access token has expired'
    $null = Get-MessageTraceExchangeOnline
    Assert-Equal $Global:ExchangeOnlineState.IsConnected $false 'a connection/auth error does'
}
#endregion

#region 3.x Phase B: behaviour bugs and detection gaps
Write-Host "`n== Phase B ==" -ForegroundColor Cyan

# --- shared sign-in fixture helpers (premium path) ---
function New-FixtureSignIn {
    param($Ip, $N, $User = 'user@contoso.com')
    [pscustomobject]@{
        Id = "id$N"; UserPrincipalName = $User; UserDisplayName = 'User'; CreatedDateTime = ([datetime]'2026-11-10T10:00:00Z').AddMinutes($N)
        UserAgent = 'ua'; IpAddress = $Ip; Status = [pscustomobject]@{ ErrorCode = 0 }; ConditionalAccessStatus = 'success'
        RiskLevelDuringSignIn = 'none'; DeviceDetail = [pscustomobject]@{ OperatingSystem = 'Windows'; Browser = 'Edge' }
        IsInteractive = $true; AppDisplayName = 'Portal'
    }
}

# 3.1 -IncludeNonInteractive reachable from the GUI/config
Test-Case '3.1 IncludeNonInteractive config key exists, defaults to false' {
    Assert-True $ConfigData.ContainsKey('IncludeNonInteractive') 'config key missing'
    Assert-Equal $ConfigData.IncludeNonInteractive $false 'default'
}
Test-Case '3.1 config switch makes the collector query non-interactive sign-ins' {
    $d = New-TestWorkDir
    $ConfigData.GeolocationRateLimit = 0
    $ConfigData.IncludeNonInteractive = $true
    $script:Filters = [System.Collections.Generic.List[string]]::new()
    function Import-Module { param($Name, [switch]$Force, [switch]$DisableNameChecking, $ErrorAction) }
    function Test-PremiumSignInLicense { $true }
    function Get-ValidatedIPStackKey { $null }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    function Invoke-RestMethod { param($Uri, $Method, $TimeoutSec, $ErrorAction) throw 'offline' }
    function Get-MgBetaAuditLogSignIn { param($Filter, [switch]$All, $ErrorAction) $script:Filters.Add($Filter); New-FixtureSignIn -Ip '10.0.0.1' -N $script:Filters.Count }
    try { $null = Get-TenantSignInData -DaysBack 3 } finally { $ConfigData.IncludeNonInteractive = $false }
    Assert-Equal $script:Filters.Count 2 'interactive + non-interactive queries'
    Assert-Match $script:Filters[1] 'nonInteractiveUser' 'second filter'
    $st = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'SignIns' })[0]
    Assert-True ($st.Note -notmatch 'interactive sign-ins only') 'coverage note must not claim interactive-only'
}
Test-Case '3.1 texts no longer point at an unreachable parameter' {
    $src = [System.IO.File]::ReadAllText($ScriptPath)
    Assert-True ($src -notmatch 'unless -IncludeNonInteractive is used') 'coverage note still tells the user to use an unreachable switch'
}

# 3.2 working directory
Test-Case '3.2 Set-TenantWorkDir: sortable stamp, configured root, idempotent, tenant switch' {
    $root = New-TestWorkDir
    $script:TenantWorkDirRoot = $null; $script:TenantWorkDirLast = $null
    $a = Set-TenantWorkDir -TenantName 'Contoso: A/B'
    Assert-True ($a -like "$root*") "must be under the configured root, got $a"
    Assert-True (Test-Path $a) 'folder created'
    Assert-Match (Split-Path -Leaf $a) '^\d{8}_\d{4}$' 'yyyyMMdd_HHmm stamp'
    Assert-Match (Split-Path -Leaf (Split-Path -Parent $a)) '^Contoso_ A_B$' 'tenant folder name cleaned'
    $again = Set-TenantWorkDir -TenantName 'Contoso: A/B'
    Assert-Equal $again $a 'second call for the same tenant is a no-op'
    Assert-Equal $ConfigData.WorkDir $a 'WorkDir stays on the first folder'
    $b = Set-TenantWorkDir -TenantName 'Fabrikam'
    Assert-True ($b -like "$root*" -and $b -notlike "*Contoso*") "tenant B must sit beside tenant A under the root, got $b"
    $other = Join-Path $script:TestRoot ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $other | Out-Null
    Update-WorkingDirectoryDisplay -NewWorkDir $other
    $c = Set-TenantWorkDir -TenantName 'Fabrikam'
    Assert-True ($c -like "$other*") "a folder the user picked becomes the new root, got $c"
    $script:TenantWorkDirRoot = $null; $script:TenantWorkDirLast = $null
}
Test-Case '3.2 Shown handler no longer re-runs the connection check blindly' {
    $src = $script:FunctionAsts['Show-MainGUI'].Extent.Text
    Assert-True ($src -match 'Add_Shown\(\{\s*(#[^\r\n]*\s*)*if \(-not \$Global:ConnectionState\.IsConnected\) \{\s*Test-ExistingGraphConnection') 'Shown must only call Test-ExistingGraphConnection when not already connected'
}

# 3.3 cancelling must not re-prompt
Test-Case '3.3 cancel and declined-module paths set ConnectCancelled; the pre-GUI loop stops on it' {
    $src = [System.IO.File]::ReadAllText($ScriptPath)
    $sets = [regex]::Matches($src, '\$script:ConnectCancelled\s*=\s*\$true').Count
    Assert-True ($sets -ge 3) "expected the flag at the cancel, module-decline and update-decline paths, found $sets"
    Assert-True ($src -match '(?s)\$script:ConnectCancelled\)\s*\{[^}]*\bbreak\b') 'pre-GUI loop must break when cancelled'
    Assert-True ($src -match '(?s)\$script:ConnectCancelled\s*=\s*\$false\s*\r?\n\s*\$connected\s*=\s*Connect-TenantServices') 'flag must be reset before each attempt'
}

# 3.7 Run all
Test-Case '3.7 Test-CollectorTaskFailed trusts a fresh status row over the return value' {
    $d = New-TestWorkDir
    $start = [datetime]::UtcNow
    Start-Sleep -Milliseconds 20
    Set-CollectionStatus -Source 'InboxRules' -Complete $false -Records 0 -Note 'Inbox rule collection FAILED (x); any CSV is from an EARLIER run.'
    Assert-Equal (Test-CollectorTaskFailed -Source 'InboxRules' -Result @('something') -StartedUtc $start) $true 'FAILED note wins over a non-null result'
    Set-CollectionStatus -Source 'InboxRules' -Complete $true -Records 0 -Note ''
    Assert-Equal (Test-CollectorTaskFailed -Source 'InboxRules' -Result $null -StartedUtc $start) $false 'a clean status row means an empty result is not a failure'
    Set-CollectionStatus -Source 'InboxRules' -Complete $false -Records 4 -Note '2 mailboxes skipped'
    Assert-Equal (Test-CollectorTaskFailed -Source 'InboxRules' -Result @('x') -StartedUtc $start) $false 'partial coverage is incomplete, not failed'
    $later = [datetime]::UtcNow.AddMinutes(5)
    Assert-Equal (Test-CollectorTaskFailed -Source 'InboxRules' -Result $null -StartedUtc $later) $true 'stale row ignored: null result with no fresh row is a failure'
    Assert-Equal (Test-CollectorTaskFailed -Source 'InboxRules' -Result @('x') -StartedUtc $later) $false 'stale row ignored: a result with no fresh row is not'
    Assert-Equal (Test-CollectorTaskFailed -Source '' -Result $null -StartedUtc $start) $true 'no source: fall back to the result'
}

# 3.11 self-heal
Test-Case '3.11 module self-heal asks before uninstalling; update failures are reported' {
    $src = $script:FunctionAsts['Connect-TenantServices'].Extent.Text
    $iUninstall = $src.IndexOf('Uninstall-Module')
    $iPrompt = $src.IndexOf('Reinstall Microsoft Graph modules?')
    Assert-True ($iPrompt -gt 0 -and $iUninstall -gt $iPrompt) 'a Yes/No prompt must come before Uninstall-Module'
    Assert-True ($src -notmatch 'Update-Module[^\r\n]*SilentlyContinue') 'Update-Module must not hide its errors'
    Assert-True ($src -match 'Update Incomplete') 'update failures must be reported to the user'
}

# 3.12 Hatz AI
Test-Case '3.12 Hatz CSV selection is by priority and never includes the raw message trace' {
    $d = New-TestWorkDir
    $names = 'ZZ_other.csv', 'MessageTraceResult.csv', 'FailedLoginAnalysis.csv', 'X_Critical.csv', 'X_Breaches.csv', 'MFAStatus_NoMFA.csv', 'AppRegistrations_HighRisk.csv', 'InboxRules_Suspicious.csv', 'CollectionStatus.csv', 'SecurityReport.csv', 'AA_other_newer.csv'
    $t = [datetime]::UtcNow
    foreach ($n in $names) { 'a,b' | Set-Content (Join-Path $d $n); $t = $t.AddSeconds(1); (Get-Item (Join-Path $d $n)).LastWriteTime = $t }
    $order = @(Select-HatzCsvFiles -WorkDir $d | ForEach-Object { $_.Name })
    Assert-True ($order -notcontains 'MessageTraceResult.csv') 'raw message trace must not be sent'
    Assert-Equal $order[0] 'SecurityReport.csv' 'first'
    Assert-Equal $order[1] 'CollectionStatus.csv' 'second'
    Assert-Equal @($order[2..7]) @('InboxRules_Suspicious.csv', 'AppRegistrations_HighRisk.csv', 'MFAStatus_NoMFA.csv', 'X_Breaches.csv', 'X_Critical.csv', 'FailedLoginAnalysis.csv') 'findings in priority order'
    Assert-Equal @($order[8..9]) @('AA_other_newer.csv', 'ZZ_other.csv') 'everything else newest first'
}
Test-Case '3.12 Hatz prompt, model id, key handling and consent text' {
    $src = [System.IO.File]::ReadAllText($ScriptPath)
    Assert-True ($src -notmatch 'SUCCESSFUL sign-ins only') 'UserLocationData.csv contains all sign-ins, not successes only'
    Assert-True ($src -notmatch 'PtrToStringAuto') 'SecureStringToBSTR must be read with PtrToStringBSTR'
    Assert-Equal ([regex]::Matches($src, 'claude-opus-4-6').Count) 1 'the model id appears once (one variable)'
    Assert-True ($src -match 'LEAVE THIS MACHINE') 'consent dialog must say plainly that data leaves the machine'
}

# 3.4 IPStack
Test-Case '3.4 IPStack success=false disables the key for the session and goes straight to the fallback' {
    $ConfigData.GeolocationRateLimit = 0
    $Global:IPStackKeyState = @{ IsValid = $true; KeySource = 'Environment'; LastChecked = Get-Date }
    $script:Web = [System.Collections.Generic.List[string]]::new()
    function Get-IPStackAPIKey { 'TESTKEY' }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    function Invoke-RestMethod {
        param($Uri, $Method, $TimeoutSec, $ErrorAction)
        $script:Web.Add($Uri)
        if ($Uri -match 'ipstack') { return [pscustomobject]@{ success = $false; error = [pscustomobject]@{ code = 104; type = 'usage_limit_reached'; info = 'quota' } } }
        return [pscustomobject]@{ status = 'success'; query = ($Uri -replace '.*/json/', ''); country = 'Germany'; city = 'Berlin'; regionName = 'BE'; isp = 'X'; lat = 1; lon = 1 }
    }
    $cache = @{}
    $r1 = Invoke-IPGeolocation -IPAddress '203.0.113.1' -Cache $cache
    $r2 = Invoke-IPGeolocation -IPAddress '203.0.113.2' -Cache $cache
    $r3 = Invoke-IPGeolocation -IPAddress '203.0.113.3' -Cache $cache
    $ipstackCalls = @($script:Web | Where-Object { $_ -match 'ipstack' }).Count
    Assert-Equal $ipstackCalls 1 'IPStack must be called once, then never again this session'
    Assert-Equal $Global:IPStackKeyState.IsValid $false 'key marked unusable'
    Assert-Equal $r1.country_name 'Germany' 'fallback result used'
    Assert-Equal $r3.country_name 'Germany' 'later lookups go straight to the fallback'
    Assert-Equal $r1.called_out $true 'result reports that a web call was made'
    Assert-Equal (Get-ValidatedIPStackKey) $null 'Get-ValidatedIPStackKey must not re-validate a disabled key'
    $Global:IPStackKeyState = @{ IsValid = $false; KeySource = $null; LastChecked = $null }
}
Test-Case '3.4 rate-limit sleep only follows lookups that made a web call; source is noted' {
    $d = New-TestWorkDir
    $ConfigData.GeolocationRateLimit = 1.5
    $ConfigData.ExpectedCountries = @('United States', 'Canada')
    $script:Sleeps = 0
    function Import-Module { param($Name, [switch]$Force, [switch]$DisableNameChecking, $ErrorAction) }
    function Test-PremiumSignInLicense { $true }
    function Get-ValidatedIPStackKey { $null }
    function Start-Sleep { param($Seconds, $Milliseconds) $script:Sleeps++ }
    function Invoke-RestMethod { param($Uri, $Method, $TimeoutSec, $ErrorAction) [pscustomobject]@{ status = 'success'; query = 'x'; country = 'United States'; city = 'c'; regionName = 'r'; isp = 'i'; lat = 1; lon = 1 } }
    $script:SI = @(); $n = 0
    foreach ($ip in '8.8.8.8', '10.0.0.1', '10.0.0.2', '198.51.100.9') { $n++; $script:SI += (New-FixtureSignIn -Ip $ip -N $n) }
    function Get-MgBetaAuditLogSignIn { param($Filter, [switch]$All, $ErrorAction) $script:SI }
    $null = Get-TenantSignInData -DaysBack 3
    Assert-Equal $script:Sleeps 1 'one sleep: after the first web lookup only (private IPs and the last IP do not sleep)'
    $st = @(Get-CollectionStatus | Where-Object { $_.Source -eq 'SignIns' })[0]
    Assert-Match $st.Note 'ip-api\.com' 'coverage note names the geolocation source'
}

# 3.5 apostrophes in UPNs
Test-Case "3.5 OData filter escapes apostrophes in a UPN" {
    $script:Seen = $null
    function Get-MgBetaAuditLogSignIn { param($Filter, $Top, $ErrorAction) $script:Seen = $Filter; @() }
    $null = Get-MFAStatusFromSignIns -UserPrincipalName "o'brien@contoso.com"
    Assert-Match $script:Seen "o''brien@contoso\.com" 'apostrophe must be doubled'
}

# 3.8 report and analysis data errors
Test-Case '3.8 failed sign-in threat metric counts all rows, not the 1500-row display cap' {
    $d = New-TestWorkDir
    $script:ReportCoverageNotes = @()
    $rows = 1..1600 | ForEach-Object { [pscustomobject]@{ CreationTime = '2026-11-10'; UserId = "u$($_ % 7)@contoso.com"; IP = '203.0.113.9'; StatusCode = '50126'; Status = 'x'; IPVersion = 'IPv4'; IsPrivateIP = 'False'; GeoLookupFailed = 'False'; IsHighRiskISP = 'False' } }
    $rows | Export-Csv -Path (Join-Path $d 'UserLocationData_Failed.csv') -NoTypeInformation
    $payload = New-ReportPayload -Results @()
    Assert-Equal @($payload.fails).Count 1500 'displayed rows are capped'
    Assert-Equal $payload.meta.threats.failedSignIns 1600 'metric reports the real total'
}
Test-Case '3.8 risky-IP correlation emits one indicator per sender' {
    $d = New-TestWorkDir
    $rows = @()
    foreach ($s in 'a@contoso.com', 'b@contoso.com') {
        foreach ($i in 1..3) { $rows += [pscustomobject]@{ message_trace_id = [guid]::NewGuid().ToString(); sender_address = $s; recipient_address = "r$i@ext.example"; subject = "hello $i"; status = 'Delivered'; to_ip = ''; from_ip = '203.0.113.9'; message_size = 1; received = '2026-11-10T10:00:00Z'; message_direction = 'Outbound'; message_id = "<$i@x>"; event_type = 'x'; timestamp = ''; date = '' } }
    }
    $rows | Export-Csv -Path (Join-Path $d 'MessageTraceResult.csv') -NoTypeInformation
    $res = @(Analyze-ETRData -RiskyIPs @('203.0.113.9') | Where-Object { $_.RiskType -eq 'RiskyIPCorrelation' })
    Assert-Equal $res.Count 2 'one indicator per sender'
    Assert-Equal @($res | ForEach-Object { $_.SenderAddress } | Sort-Object) @('a@contoso.com', 'b@contoso.com') 'single sender per indicator'
}
Test-Case '3.8 failed-login patterns carry TargetUser; analysis uses it instead of parsing Details' {
    $d = New-TestWorkDir
    $rows = @(); $m = 0
    foreach ($k in 1..6) { $m++; $rows += @{ IP = '203.0.113.9'; User = 'victim@contoso.com'; Code = '50126'; Minute = $m } }
    New-SignInCsv -Dir $d -Rows $rows
    $p = @(Get-FailedLoginPatterns | Where-Object { $_.PatternType -eq 'Brute Force' })
    Assert-Equal $p.Count 1 'brute force pattern'
    Assert-Equal $p[0].TargetUser 'victim@contoso.com' 'TargetUser column'
    # an analysis input whose Details text has no parsable user
    $d2 = New-TestWorkDir
    [pscustomobject]@{ PatternType = 'Brute Force'; SourceIP = '1.2.3.4'; SourceIPs = '1.2.3.4'; Location = 'x'; ISP = 'x'; TargetedUsers = 1; FailedAttempts = 9; TimeSpan = 1; FirstSeen = ''; LastSeen = ''; RiskLevel = 'Critical'; SuccessfulBreach = 'False'; Details = 'Brute force against one account'; TargetUser = 'victim@contoso.com' } |
        Export-Csv -Path (Join-Path $d2 'FailedLoginAnalysis.csv') -NoTypeInformation
    function Generate-HTMLReport { param($Data) '<html></html>' }
    $res = @(Invoke-CompromiseDetection)
    $u = @($res | Where-Object { $_.UserId -eq 'victim@contoso.com' })
    Assert-Equal $u.Count 1 'victim must appear'
    Assert-Equal $u[0].RiskScore 30 'Critical pattern scores 30'
}
Test-Case '3.8 SecurityReport.csv includes MFA, high-risk ISP, failed-login and password-change columns' {
    $d = New-TestWorkDir
    [pscustomobject]@{ PatternType = 'Brute Force'; SourceIP = '1.2.3.4'; SourceIPs = '1.2.3.4'; Location = 'x'; ISP = 'x'; TargetedUsers = 1; FailedAttempts = 9; TimeSpan = 1; FirstSeen = ''; LastSeen = ''; RiskLevel = 'High'; SuccessfulBreach = 'False'; Details = 'x'; TargetUser = 'victim@contoso.com' } |
        Export-Csv -Path (Join-Path $d 'FailedLoginAnalysis.csv') -NoTypeInformation
    function Generate-HTMLReport { param($Data) '<html></html>' }
    $null = Invoke-CompromiseDetection
    $hdr = (Import-Csv (Join-Path $d 'SecurityReport.csv'))[0].PSObject.Properties.Name
    foreach ($c in 'MFAStatus', 'HighRiskISPCount', 'FailedLoginPatternCount', 'PasswordChangeIssuesCount', 'UserId', 'RiskScore') {
        Assert-True ($hdr -contains $c) "missing column $c"
    }
}
Test-Case '3.8 Invoke-CompromiseDetection returns $null with a logged error instead of throwing' {
    $d = New-TestWorkDir
    [pscustomobject]@{ PatternType = 'Brute Force'; SourceIP = '1.2.3.4'; SourceIPs = '1.2.3.4'; Location = 'x'; ISP = 'x'; TargetedUsers = 1; FailedAttempts = 9; TimeSpan = 1; FirstSeen = ''; LastSeen = ''; RiskLevel = 'High'; SuccessfulBreach = 'False'; Details = 'x'; TargetUser = 'victim@contoso.com' } |
        Export-Csv -Path (Join-Path $d 'FailedLoginAnalysis.csv') -NoTypeInformation
    function Generate-HTMLReport { param($Data) throw 'simulated report failure' }
    $res = Invoke-CompromiseDetection
    Assert-Equal $res $null 'must return $null'
    Assert-True (@($script:LogLines | Where-Object { $_ -match '^\[Error\].*simulated report failure' }).Count -ge 1) 'error must be logged'
}

# 3.9 mailbox-level forwarding
Test-Case '3.9 mailbox-level forwarding is emitted as a suspicious row' {
    $d = New-TestWorkDir
    function Connect-ExchangeOnlineIfNeeded { $true }
    function Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'contoso.com' } }
    function Get-InboxRule { param($Mailbox, [switch]$IncludeHidden, $ErrorAction) @() }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    function Get-Mailbox {
        param($ResultSize, $RecipientTypeDetails, $ErrorAction)
        $mk = { param($n, $smtp, $addr, $keep) [pscustomobject]@{ UserPrincipalName = "$n@contoso.com"; PrimarySmtpAddress = "$n@contoso.com"; RecipientTypeDetails = 'UserMailbox'; DisplayName = $n; ForwardingSmtpAddress = $smtp; ForwardingAddress = $addr; DeliverToMailboxAndForward = $keep } }
        & $mk 'ext' 'smtp:evil@attacker.example' $null $false
        & $mk 'int' 'smtp:boss@contoso.com' $null $true
        & $mk 'plain' $null $null $false
    }
    $res = @(Get-MailboxRules)
    $rows = @($res | Where-Object { $_.RuleName -eq '[Mailbox forwarding]' })
    Assert-Equal $rows.Count 2 'two mailboxes forward at mailbox level'
    $ext = $rows | Where-Object { $_.Mailbox -eq 'ext@contoso.com' }
    Assert-Equal $ext.IsSuspicious $true 'external forward is suspicious'
    Assert-Match $ext.ExternalTargets 'attacker\.example' 'external target recorded'
    Assert-Match $ext.SuspiciousReasons 'External forwarding' 'reason'
    Assert-Match $ext.ForwardTo 'evil@attacker\.example' 'ForwardTo column carries the target'
    $int = $rows | Where-Object { $_.Mailbox -eq 'int@contoso.com' }
    Assert-Equal $int.ExternalTargets '' 'internal target is not external'
    Assert-True (Test-Path (Join-Path $d 'InboxRules_Forwarding.csv')) 'forwarding file written'
}

# 3.10 password change false positives
function New-PwAuditCsv {
    param([string]$Dir, [object[]]$Events)
    $rows = foreach ($e in $Events) {
        [pscustomobject]@{
            ActivityDate = $e.Time; Timestamp = $e.Time; Activity = $e.Activity; UserId = $e.By; CorrelationId = $e.Corr
            TargetResources = (ConvertTo-Json -Compress @(@{ Type = 'User'; UserPrincipalName = $e.Target; DisplayName = 'x'; Id = 'id' }))
        }
    }
    $rows | Export-Csv -Path (Join-Path $Dir 'AdminAuditLogs_HighRisk.csv') -NoTypeInformation
}
Test-Case '3.10 one admin reset writing several audit events is one change' {
    $d = New-TestWorkDir
    New-PwAuditCsv -Dir $d -Events @(
        @{ Time = '2026-11-10 10:00:00'; Activity = 'Reset user password'; By = 'admin@contoso.com'; Corr = 'c-1'; Target = 'user@contoso.com' }
        @{ Time = '2026-11-10 10:00:05'; Activity = 'Change user password'; By = 'admin@contoso.com'; Corr = 'c-1'; Target = 'user@contoso.com' }
        @{ Time = '2026-11-10 10:00:09'; Activity = 'Update StsRefreshTokenValidFrom (password)'; By = 'Microsoft'; Corr = 'c-1'; Target = 'user@contoso.com' }
    )
    $res = @(Get-RecentPasswordChanges)
    Assert-Equal $res.Count 0 'a single admin reset must not be flagged'
}
Test-Case '3.10 same initiator within two minutes without a correlation id is one change' {
    $d = New-TestWorkDir
    New-PwAuditCsv -Dir $d -Events @(
        @{ Time = '2026-11-10 10:00:00'; Activity = 'Reset user password'; By = 'admin@contoso.com'; Corr = ''; Target = 'user@contoso.com' }
        @{ Time = '2026-11-10 10:01:30'; Activity = 'Change user password'; By = 'admin@contoso.com'; Corr = ''; Target = 'user@contoso.com' }
    )
    Assert-Equal @(Get-RecentPasswordChanges).Count 0 'collapsed'
}
Test-Case '3.10 control: two genuine resets by different people are still flagged' {
    $d = New-TestWorkDir
    New-PwAuditCsv -Dir $d -Events @(
        @{ Time = '2026-11-10 10:00:00'; Activity = 'Reset user password'; By = 'admin1@contoso.com'; Corr = 'c-1'; Target = 'user@contoso.com' }
        @{ Time = '2026-11-10 11:00:00'; Activity = 'Reset user password'; By = 'admin2@contoso.com'; Corr = 'c-2'; Target = 'user@contoso.com' }
    )
    Assert-Equal @(Get-RecentPasswordChanges).Count 1 'flagged'
}
Test-Case '3.10 off-hours window includes 22:00-22:59 and names the time zone' {
    $d = New-TestWorkDir
    New-PwAuditCsv -Dir $d -Events @(
        @{ Time = '2026-11-10 22:10:00'; Activity = 'Reset user password'; By = 'admin1@contoso.com'; Corr = 'c-1'; Target = 'user@contoso.com' }
        @{ Time = '2026-11-10 22:40:00'; Activity = 'Reset user password'; By = 'admin2@contoso.com'; Corr = 'c-2'; Target = 'user@contoso.com' }
    )
    $res = @(Get-RecentPasswordChanges)
    Assert-Equal $res.Count 1 'pattern'
    Assert-Equal $res[0].OffHoursChanges 2 'both 22:xx events are off-hours'
    Assert-Match $res[0].SuspiciousReasons ([regex]::Escape([System.TimeZoneInfo]::Local.Id)) 'time zone named in the reason'
}

# 3.6 SkipGuests is a defined setting
Test-Case '3.6 SkipGuests is defined in the config block' {
    Assert-True $ConfigData.ContainsKey('SkipGuests') 'config key missing'
    Assert-Equal $ConfigData.SkipGuests $false 'default'
}
#endregion

#region 5.x Phase D: cleanup
Write-Host "`n== Phase D ==" -ForegroundColor Cyan

Test-Case '5.x unescaped regex dots in -replace patterns are gone' {
    $src = [System.IO.File]::ReadAllText($ScriptPath)
    $bad = [regex]::Matches($src, "-replace\s+'\.(csv|html)\`$'")
    Assert-Equal $bad.Count 0 'every .csv / .html suffix pattern must escape the dot'
}
Test-Case '5.x unused code removed; no dead PowerShell 5.1 leftovers' {
    $src = [System.IO.File]::ReadAllText($ScriptPath)
    Assert-True ($src -notmatch 'isPowerShell51') '$isPowerShell51'
    Assert-True (-not (Test-FunctionExists 'Test-SecurityDefaults')) 'Test-SecurityDefaults'
    foreach ($k in 'HighRiskOperations', 'MaxConcurrentGeolookups') { Assert-True (-not $ConfigData.ContainsKey($k)) "config key $k" }
    Assert-True (-not $ConfigData.ETRAnalysis.ContainsKey('MaxSameSubjectPerHour')) 'config key MaxSameSubjectPerHour'
    Assert-True ($src -notmatch '\$loginActivities') 'LOGIN classification in the directory audit collector'
    Assert-Equal ([regex]::Matches($src, 'Add-Type -AssemblyName System\.Web').Count) 1 'System.Web is loaded once'
    Assert-True ($src -notmatch 'PowerShell 5\.1 compatibility') 'stale PowerShell 5.1 comment'
}
Test-Case '5.x per-user entry is built in one place' {
    $core = $script:FunctionAsts['Invoke-CompromiseDetectionCore'].Extent.Text
    Assert-Equal ([regex]::Matches($core, 'UnusualSignIns = \[System\.Collections\.Generic\.List').Count) 1 'the 13-key hashtable must exist once'
    Assert-True ($core -match '\$newUserEntry') 'newUserEntry scriptblock'
}
Test-Case '5.x no array += in the ETR grouping loops or password pattern list' {
    $etr = $script:FunctionAsts['Analyze-ETRData'].Extent.Text
    Assert-True ($etr -notmatch '\+=\s*@\(\$msg\)') 'ETR groups must use List.Add'
    $pw = $script:FunctionAsts['Get-RecentPasswordChanges'].Extent.Text
    Assert-True ($pw -notmatch '\$suspiciousPatterns\s*\+=') 'suspiciousPatterns must use List.Add'
}
Test-Case '5.x Get-ETRColumnMapping maps one header even when several match' {
    $m = Get-ETRColumnMapping -Headers @('Message ID', 'message_id', 'Sender', 'Subject')
    Assert-True ($m.MessageId -is [string]) "MessageId mapping must be a single header, got $($m.MessageId.GetType().Name)"
    Assert-Equal $m.MessageId 'Message ID' 'first match wins'
}
Test-Case '5.x ETR keyword match is a whole-word match' {
    $d = New-TestWorkDir
    $rows = @()
    foreach ($i in 1..8) { $rows += [pscustomobject]@{ message_trace_id = "a$i"; sender_address = 'freedom@contoso.com'; recipient_address = "r$i@ext.example"; subject = "Freedom of speech newsletter $i"; status = 'Delivered'; to_ip = ''; from_ip = ''; message_size = 1; received = '2026-11-10T10:00:00Z'; message_direction = 'Outbound'; message_id = "<a$i>"; event_type = 'x'; timestamp = ''; date = '' } }
    foreach ($i in 1..8) { $rows += [pscustomobject]@{ message_trace_id = "b$i"; sender_address = 'spammer@contoso.com'; recipient_address = "r$i@ext.example"; subject = "Free gift inside $i"; status = 'Delivered'; to_ip = ''; from_ip = ''; message_size = 1; received = '2026-11-10T10:00:00Z'; message_direction = 'Outbound'; message_id = "<b$i>"; event_type = 'x'; timestamp = ''; date = '' } }
    $rows | Export-Csv -Path (Join-Path $d 'MessageTraceResult.csv') -NoTypeInformation
    $hits = @(Analyze-ETRData | Where-Object { $_.RiskType -eq 'SpamKeywords' -and $_.DetectedKeyword -eq 'free' })
    Assert-Equal @($hits | ForEach-Object { $_.SenderAddress }) @('spammer@contoso.com') '"free" must match "Free gift" but not "Freedom"'
}
Test-Case '5.x Test-ScriptVersion compares versions, so a newer local build is not offered an update' {
    $ScriptVer = '12.1'
    function Invoke-WebRequest { param($Uri, [switch]$UseBasicParsing, $TimeoutSec, $ErrorAction) [pscustomobject]@{ Content = "`$ScriptVer = `"$($script:Mock.Remote)`"" } }
    $script:Mock = @{ Remote = '12.0' }
    $older = Test-ScriptVersion -ShowMessageBox $false
    Assert-Equal $older.IsLatest $true 'GitHub 12.0 vs local 12.1: nothing to update'
    $script:Mock.Remote = '12.2'
    Assert-Equal (Test-ScriptVersion -ShowMessageBox $false).IsLatest $false 'GitHub 12.2 vs local 12.1: update available'
    $script:Mock.Remote = '12.1'
    Assert-Equal (Test-ScriptVersion -ShowMessageBox $false).IsLatest $true 'same version'
    $script:Mock.Remote = '12.10'
    Assert-Equal (Test-ScriptVersion -ShowMessageBox $false).IsLatest $false '12.10 is newer than 12.9 (not a string compare)'
    $ScriptVer = '12.9'
    Assert-Equal (Test-ScriptVersion -ShowMessageBox $false).IsLatest $false '12.10 vs local 12.9'
}
Test-Case '5.x startup version check fetches once and only prompts when a newer version exists' {
    $ScriptVer = '12.1'
    $script:Mock = @{ Remote = '12.1'; Fetches = 0 }
    function Invoke-WebRequest { param($Uri, [switch]$UseBasicParsing, $TimeoutSec, $ErrorAction) $script:Mock.Fetches++; [pscustomobject]@{ Content = "`$ScriptVer = `"$($script:Mock.Remote)`"" } }
    $null = Test-ScriptVersion -ShowMessageBox $true -PromptOnlyIfNewer
    Assert-Equal $script:Mock.Fetches 1 'one fetch'
    Assert-Equal @($script:LogLines | Where-Object { $_ -like '[[]Dialog]*' }).Count 0 'no dialog when up to date'
    $script:Mock.Remote = '12.5'
    $null = Test-ScriptVersion -ShowMessageBox $true -PromptOnlyIfNewer
    Assert-Equal @($script:LogLines | Where-Object { $_ -like '[[]Dialog]*Update Available*' }).Count 1 'dialog when a newer version exists'
    $src = $script:FunctionAsts['Show-MainGUI'].Extent.Text
    Assert-Equal ([regex]::Matches($src, 'Test-ScriptVersion').Count) 2 'Show-MainGUI: the Check version button and one startup check'
}
Test-Case '5.x MFA method pattern includes hardware OATH and platform credentials' {
    foreach ($t in '#microsoft.graph.hardwareOathAuthenticationMethod', '#microsoft.graph.platformCredentialAuthenticationMethod', '#microsoft.graph.fido2AuthenticationMethod', '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod') {
        Assert-True (Test-MfaMethodType -MethodType $t) "$t counts as MFA"
    }
    foreach ($t in '#microsoft.graph.emailAuthenticationMethod', '#microsoft.graph.passwordAuthenticationMethod', '#microsoft.graph.temporaryAccessPassAuthenticationMethod') {
        Assert-True (-not (Test-MfaMethodType -MethodType $t)) "$t is not MFA"
    }
}
if ($script:SdkModule) {
    Test-Case '5.x Conditional Access narrowing: locations, device filters, excluded apps' {
        $mkRaw = { param($apps, $extra) '{"displayName":"t","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]' + $apps + '}' + $extra + '},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}' }
        $cases = @(
            @{ Name = 'baseline: everything, everywhere'; Json = (& $mkRaw '' ''); Expect = 0 }
            @{ Name = 'specific locations'; Json = (& $mkRaw '' ',"locations":{"includeLocations":["11111111-1111-1111-1111-111111111111"]}'); Expect = 1 }
            @{ Name = 'all locations is not narrowing'; Json = (& $mkRaw '' ',"locations":{"includeLocations":["All"]}'); Expect = 0 }
            @{ Name = 'device filter'; Json = (& $mkRaw '' ',"devices":{"deviceFilter":{"mode":"include","rule":"device.trustType -eq \"ServerAD\""}}'); Expect = 1 }
            @{ Name = 'excluded apps'; Json = (& $mkRaw ',"excludeApplications":["22222222-2222-2222-2222-222222222222"]' ''); Expect = 1 }
            @{ Name = 'risk-conditioned'; Json = (& $mkRaw '' ',"userRiskLevels":["high"]'); Expect = 1 }
        )
        $res = Invoke-CaSdkChild -Cases $cases -Functions 'Get-CaPolicyNarrowing' -Call '$out[$c.Name] = @(Get-CaPolicyNarrowing -Policy $policy).Count'
        $wrong = @($cases | Where-Object { $res[$_.Name] -ne $_.Expect } | ForEach-Object { "$($_.Name) expected $($_.Expect) got $($res[$_.Name])" })
        Assert-Equal $wrong.Count 0 ($wrong -join '; ')
    }
}
#endregion

#region TESTS-PLACEHOLDER
#endregion

#region Summary
Write-Host "`n== Summary ==" -ForegroundColor Cyan
$pass = @($script:Results | Where-Object Status -eq 'PASS').Count
$fail = @($script:Results | Where-Object Status -eq 'FAIL').Count
$skip = @($script:Results | Where-Object Status -eq 'SKIP').Count
Write-Host "Passed: $pass  Failed: $fail  Skipped: $skip" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) {
    $script:Results | Where-Object Status -eq 'FAIL' | ForEach-Object { Write-Host "  FAILED: $($_.Name)" -ForegroundColor Red }
}
Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
if ($fail) { exit 1 }
exit 0
#endregion
