<#
.SYNOPSIS
    Generates a comprehensive branded HTML report of all Power Automate flows
    including full action trees, trigger details, connections, run history,
    and error handling configuration.

.DESCRIPTION
    Uses the Power Platform Admin module to retrieve every available detail
    about Power Automate flows across the tenant:
      - Flow metadata (state, sharing, solution-awareness, suspension)
      - Full trigger configuration (type, recurrence, connector, inputs)
      - Complete action tree with nested scopes, conditions, loops
      - Connection references and their status
      - Run history (last N runs per flow)
      - Error handling (runAfter / Configure Run After settings)
      - Variables and expressions
      - DLP classification hints (premium vs standard connectors)

    Output is a Yeyland Wutani branded HTML report with collapsible
    per-flow detail panels, plus a companion CSV export.

    KEY FIX (v2.1): Get-AdminFlow bulk list does NOT return the flow definition.
    Each flow is individually re-fetched to obtain the full definition containing
    triggers and actions. This is the expected behavior of the admin API.

.PARAMETER EnvironmentName
    Optional. Scope to a specific environment GUID.

.PARAMETER LogoPath
    Optional. Path to a PNG/JPG logo file to embed in the report header.

.PARAMETER OutputPath
    Optional. Directory for output files. Defaults to Desktop.

.PARAMETER IncludeDeleted
    Optional. Include soft-deleted flows in the report.

.PARAMETER MaxRunHistory
    Optional. Number of recent runs to retrieve per flow. Default 10.

.NOTES
    Author  : Escalations Team - Pacific Office Automation
    Client  : Yeyland Wutani LLC
    Date    : 2026-03-13
    Version : 2.2
    Module  : Microsoft.PowerApps.Administration.PowerShell

    CHANGELOG v2.2:
      - Fixed: Trigger type, connector, and action count now populated for all flows
      - Fixed: Root cause 1 - admin API does not return properties.definition at all
               (hard API limitation; full definition only available to flow owners)
      - Fixed: Root cause 2 - bulk Get-AdminFlow omits definitionSummary and
               connectionReferences; individual flow GET is now fetched as fallback
      - Fixed: definitionSummary trigger parsing now extracts connector name from
               id path (/providers/.../shared_xyz → xyz) and handles Recurrence/Request
      - Fixed: Simplified Get-FlowDefinitionViaRest; removed non-functional token
               extraction approach from v2.2-beta

    CHANGELOG v2.1:
      - Fixed: Individual per-flow re-fetch to populate definition (triggers/actions)
      - Fixed: Definition deserialization when returned as JSON string
      - Fixed: Nested Sort-ByDependency replaced with iterative Kahn topological sort
      - Fixed: IsSolutionAware detection no longer false-positives on all flows
      - Fixed: UniqueConnectors deduplication pipeline error
      - Fixed: Owner DisplayName fallback for service principals
      - Fixed: Added System.Web assembly load for HtmlEncode
      - Fixed: Progress reporting now reflects re-fetch vs parse phases
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$EnvironmentName,
    [string]$LogoPath,
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
    [switch]$IncludeDeleted,
    [int]$MaxRunHistory = 10
)

# ============================================================================
# REGION: Assembly & Module Setup
# ============================================================================

# Required for HtmlEncode in report generation
Add-Type -AssemblyName System.Web

# Ensure TLS 1.2 for PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Admin module - provides Get-AdminFlow, Get-AdminFlowOwnerRole, etc.
# Its nested Microsoft.PowerApps.AuthModule also provides InvokeApi, which
# we call via module scope rather than importing the maker module separately.
# The maker module (Microsoft.PowerApps.PowerShell) shares the same AuthModule
# dependency but causes MSAL assembly version conflicts when both are loaded.
if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell')) {
    Write-Host "[INFO] Installing Microsoft.PowerApps.Administration.PowerShell..." -ForegroundColor Yellow
    Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop

# Authenticate
Write-Host "[INFO] Authenticating to Power Platform..." -ForegroundColor Yellow
Add-PowerAppsAccount -Endpoint prod -ErrorAction Stop
Write-Host "[OK]   Authenticated.`n" -ForegroundColor Green

# Resolve the module reference once - used to call InvokeApi in its scope
$script:adminModule = Get-Module 'Microsoft.PowerApps.Administration.PowerShell'
if (-not $script:adminModule) {
    Write-Error "Admin module not found after import - cannot continue."
    return
}


# ============================================================================
# REGION: Helper Functions
# ============================================================================

function Resolve-FlowDefinition {
    <#
    .SYNOPSIS
        Ensures a flow definition object is a deserialized PSCustomObject.
        The admin API sometimes returns the definition as a compressed JSON string.
    .PARAMETER Definition
        The raw definition value from Internal.properties.definition.
    #>
    param([object]$Definition)

    if (-not $Definition) { return $null }

    # If it came back as a string, try to deserialize it
    if ($Definition -is [string]) {
        $trimmed = $Definition.Trim()
        if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
            try {
                return ($trimmed | ConvertFrom-Json)
            }
            catch {
                Write-Warning "  Could not deserialize definition JSON string: $_"
                return $null
            }
        }
        return $null
    }

    return $Definition
}


function Get-FlowDefinitionViaRest {
    <#
    .SYNOPSIS
        Attempts to fetch a flow's full definition (triggers + actions) via the
        admin REST endpoint with $expand=properties.definition.

        NOTE: The admin endpoint does not reliably return properties.definition
        for flows not owned by the authenticated account. This is an API limitation.
        When this returns $null the caller should fall back to definitionSummary,
        which is populated by a separate individual-flow fetch in the main loop.
    .PARAMETER EnvironmentName
        The environment GUID (e.g. Default-xxxx-xxxx).
    .PARAMETER FlowName
        The flow GUID.
    #>
    param(
        [string]$EnvironmentName,
        [string]$FlowName
    )

    $uri = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/$EnvironmentName/flows/$FlowName`?api-version=2016-11-01&`$expand=properties.definition"

    try {
        $response = & $script:adminModule {
            param($u)
            InvokeApi -Method GET -Route $u
        } $uri

        if (-not $response) { return $null }

        $rawDef = $response.properties.definition
        if (-not $rawDef) { return $null }

        return Resolve-FlowDefinition -Definition $rawDef
    }
    catch {
        Write-Verbose "  REST fetch failed for $FlowName : $_"
        return $null
    }
}


function Get-TopologicalOrder {
    <#
    .SYNOPSIS
        Returns action names in topological execution order using Kahn's algorithm.
        Avoids nested function scope issues by operating purely on parameters.
    .PARAMETER Actions
        Hashtable of action name -> action object.
    #>
    param([hashtable]$Actions)

    if (-not $Actions -or $Actions.Count -eq 0) { return @() }

    $names    = @($Actions.Keys)
    $inDegree = @{}
    $graph    = @{}   # name -> list of names that depend on it

    foreach ($n in $names) {
        $inDegree[$n] = 0
        $graph[$n]    = [System.Collections.Generic.List[string]]::new()
    }

    foreach ($n in $names) {
        $ra = $Actions[$n].runAfter
        if ($ra -is [PSCustomObject]) {
            $ra.PSObject.Properties | ForEach-Object {
                $dep = $_.Name
                if ($inDegree.ContainsKey($dep)) {
                    $inDegree[$n]++
                    $graph[$dep].Add($n)
                }
            }
        }
    }

    $queue  = [System.Collections.Generic.Queue[string]]::new()
    $result = [System.Collections.Generic.List[string]]::new()

    foreach ($n in $names) {
        if ($inDegree[$n] -eq 0) { $queue.Enqueue($n) }
    }

    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        $result.Add($cur)
        foreach ($next in $graph[$cur]) {
            $inDegree[$next]--
            if ($inDegree[$next] -eq 0) { $queue.Enqueue($next) }
        }
    }

    # Append any remaining nodes (cycles or disconnected)
    foreach ($n in $names) {
        if (-not $result.Contains($n)) { $result.Add($n) }
    }

    return $result
}


function Get-ActionTree {
    <#
    .SYNOPSIS
        Recursively parses a flow definition's actions into a flat ordered list
        with nesting depth, action type, connector info, and configuration.
    .PARAMETER Actions
        The actions object from the flow definition.
    .PARAMETER Depth
        Current nesting depth (0 = top level).
    .PARAMETER ParentPath
        Dot-notation path of the parent container.
    #>
    param(
        [object]$Actions,
        [int]$Depth = 0,
        [string]$ParentPath = ''
    )

    if (-not $Actions) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    # Normalize to hashtable
    if ($Actions -is [PSCustomObject]) {
        $hash = @{}
        $Actions.PSObject.Properties | ForEach-Object { $hash[$_.Name] = $_.Value }
        $Actions = $hash
    }

    if ($Actions -isnot [hashtable] -or $Actions.Count -eq 0) { return @() }

    # Sort actions by runAfter dependency graph
    $sorted = Get-TopologicalOrder -Actions $Actions

    foreach ($actionName in $sorted) {
        $action = $Actions[$actionName]
        $currentPath = if ($ParentPath) { "$ParentPath > $actionName" } else { $actionName }

        # Core fields
        $actionType   = if ($action.type) { $action.type } else { 'Unknown' }
        $connector    = ''
        $operation    = ''
        $inputSummary = ''
        $runAfterInfo = ''
        $expression   = ''

        # --- Connector / Operation parsing ---

        if ($action.inputs) {
            $inputs = $action.inputs

            # API Connection (SharePoint, Outlook, Teams, etc.)
            if ($inputs.host) {
                $apiId = if ($inputs.host.apiId) { $inputs.host.apiId.Split('/')[-1] } else { '' }
                if ($apiId) { $connector = $apiId }
                $operation = if ($inputs.host.operationId) { $inputs.host.operationId } else { '' }
            }

            # HTTP
            if ($inputs.method -and $inputs.uri) {
                $connector = 'HTTP'
                $operation = "$($inputs.method) $($inputs.uri)"
                if ($operation.Length -gt 120) { $operation = $operation.Substring(0, 117) + '...' }
            }

            # Data Operations
            switch ($actionType) {
                'Compose' {
                    $connector = 'Data Operations'; $operation = 'Compose'
                    if ($inputs -is [string] -and $inputs.Length -le 100) { $inputSummary = $inputs }
                }
                'Table'   { $connector = 'Data Operations'; $operation = 'Create HTML/CSV Table' }
                'Query'   { $connector = 'Data Operations'; $operation = 'Filter Array' }
                'Select'  { $connector = 'Data Operations'; $operation = 'Select' }
                'Join'    { $connector = 'Data Operations'; $operation = 'Join' }
                'ParseJson' { $connector = 'Data Operations'; $operation = 'Parse JSON' }
            }

            # Variables
            switch ($actionType) {
                'InitializeVariable' {
                    $connector = 'Variables'
                    $varName = if ($action.inputs.variables) { $action.inputs.variables[0].name } else { '' }
                    $varType = if ($action.inputs.variables) { $action.inputs.variables[0].type } else { '' }
                    $operation = "Initialize: $varName ($varType)"
                }
                'SetVariable'       { $connector = 'Variables'; $operation = "Set: $($action.inputs.name)" }
                'IncrementVariable' { $connector = 'Variables'; $operation = "Increment: $($action.inputs.name)" }
                'AppendToStringVariable' { $connector = 'Variables'; $operation = "Append: $($action.inputs.name)" }
                'AppendToArrayVariable'  { $connector = 'Variables'; $operation = "Append: $($action.inputs.name)" }
            }
        }

        # Control flow
        switch ($actionType) {
            'If' {
                $connector = 'Control'; $operation = 'Condition'
                if ($action.expression) {
                    $expression = ($action.expression | ConvertTo-Json -Depth 5 -Compress)
                    if ($expression.Length -gt 200) { $expression = $expression.Substring(0, 197) + '...' }
                }
            }
            'Switch' {
                $connector = 'Control'; $operation = 'Switch'
                if ($action.expression) {
                    $expression = ($action.expression | ConvertTo-Json -Depth 3 -Compress)
                    if ($expression.Length -gt 200) { $expression = $expression.Substring(0, 197) + '...' }
                }
            }
            'Scope'     { $connector = 'Control'; $operation = 'Scope' }
            'Foreach'   {
                $connector = 'Control'
                $operation = "Apply to each: $($action.foreach)"
                if ($operation.Length -gt 150) { $operation = $operation.Substring(0, 147) + '...' }
            }
            'Until'     { $connector = 'Control'; $operation = 'Do until' }
            'Terminate' { $connector = 'Control'; $operation = "Terminate: $($action.inputs.runStatus)" }
            'Wait'      { $connector = 'Control'; $operation = 'Delay' }
            'Response'  { $connector = 'Request';  $operation = "Response (Status $($action.inputs.statusCode))" }
        }

        # Run After (error handling config)
        if ($action.runAfter) {
            $raObj = $action.runAfter
            if ($raObj -is [PSCustomObject]) {
                $raParts = @()
                $raObj.PSObject.Properties | ForEach-Object {
                    $statuses = ($_.Value -join ', ')
                    $raParts += "$($_.Name) [$statuses]"
                }
                $runAfterInfo = $raParts -join '; '
            }
        }

        $results.Add([PSCustomObject]@{
            ActionName   = $actionName
            ActionType   = $actionType
            Connector    = $connector
            Operation    = $operation
            Depth        = $Depth
            Path         = $currentPath
            RunAfter     = $runAfterInfo
            Expression   = $expression
            InputSummary = $inputSummary
        })

        # Recurse: Scope / Foreach / Until -> .actions
        if ($action.actions) {
            $nested = Get-ActionTree -Actions $action.actions -Depth ($Depth + 1) -ParentPath $currentPath
            $nested | ForEach-Object { $results.Add($_) }
        }

        # Condition (If) branches
        if ($actionType -eq 'If') {
            if ($action.actions) {
                $results.Add([PSCustomObject]@{
                    ActionName = '(True Branch)'; ActionType = 'Branch'; Connector = 'Control'
                    Operation = 'If Yes'; Depth = ($Depth + 1); Path = "$currentPath > True"
                    RunAfter = ''; Expression = ''; InputSummary = ''
                })
                $nested = Get-ActionTree -Actions $action.actions -Depth ($Depth + 2) -ParentPath "$currentPath > True"
                $nested | ForEach-Object { $results.Add($_) }
            }
            if ($action.else -and $action.else.actions) {
                $results.Add([PSCustomObject]@{
                    ActionName = '(False Branch)'; ActionType = 'Branch'; Connector = 'Control'
                    Operation = 'If No'; Depth = ($Depth + 1); Path = "$currentPath > False"
                    RunAfter = ''; Expression = ''; InputSummary = ''
                })
                $nested = Get-ActionTree -Actions $action.else.actions -Depth ($Depth + 2) -ParentPath "$currentPath > False"
                $nested | ForEach-Object { $results.Add($_) }
            }
        }

        # Switch cases
        if ($actionType -eq 'Switch') {
            if ($action.cases) {
                $casesObj = $action.cases
                if ($casesObj -is [PSCustomObject]) {
                    $casesObj.PSObject.Properties | ForEach-Object {
                        $caseName  = $_.Name
                        $caseValue = if ($_.Value.case) { $_.Value.case } else { $caseName }
                        $results.Add([PSCustomObject]@{
                            ActionName = "(Case: $caseValue)"; ActionType = 'Branch'; Connector = 'Control'
                            Operation = 'Switch Case'; Depth = ($Depth + 1); Path = "$currentPath > Case_$caseName"
                            RunAfter = ''; Expression = ''; InputSummary = ''
                        })
                        if ($_.Value.actions) {
                            $nested = Get-ActionTree -Actions $_.Value.actions -Depth ($Depth + 2) -ParentPath "$currentPath > Case_$caseName"
                            $nested | ForEach-Object { $results.Add($_) }
                        }
                    }
                }
            }
            if ($action.default -and $action.default.actions) {
                $results.Add([PSCustomObject]@{
                    ActionName = '(Default Case)'; ActionType = 'Branch'; Connector = 'Control'
                    Operation = 'Switch Default'; Depth = ($Depth + 1); Path = "$currentPath > Default"
                    RunAfter = ''; Expression = ''; InputSummary = ''
                })
                $nested = Get-ActionTree -Actions $action.default.actions -Depth ($Depth + 2) -ParentPath "$currentPath > Default"
                $nested | ForEach-Object { $results.Add($_) }
            }
        }
    }

    return $results
}


function Get-TriggerDetail {
    <#
    .SYNOPSIS
        Extracts comprehensive trigger information from a flow definition.
    .PARAMETER Triggers
        The triggers object from the flow definition.
    #>
    param([object]$Triggers)

    if (-not $Triggers) {
        return [PSCustomObject]@{
            Name = 'Unknown'; Type = 'Unknown'; Connector = '-'
            Operation = '-'; Recurrence = '-'; Description = '-'; Inputs = '-'
        }
    }

    if ($Triggers -is [PSCustomObject]) {
        $hash = @{}
        $Triggers.PSObject.Properties | ForEach-Object { $hash[$_.Name] = $_.Value }
        $Triggers = $hash
    }

    if ($Triggers -isnot [hashtable] -or $Triggers.Count -eq 0) {
        return [PSCustomObject]@{
            Name = 'Unknown'; Type = 'Unknown'; Connector = '-'
            Operation = '-'; Recurrence = '-'; Description = '-'; Inputs = '-'
        }
    }

    $triggerName = ($Triggers.Keys | Select-Object -First 1)
    $trigger     = $Triggers[$triggerName]
    $type        = if ($trigger.type) { $trigger.type } else { 'Unknown' }
    $connector   = ''
    $operation   = ''
    $recurrence  = '-'
    $description = ''
    $inputDetail = ''

    # Connector / operation from host
    if ($trigger.inputs -and $trigger.inputs.host) {
        $apiId = if ($trigger.inputs.host.apiId) { $trigger.inputs.host.apiId.Split('/')[-1] } else { '' }
        $connector = $apiId
        $operation = if ($trigger.inputs.host.operationId) { $trigger.inputs.host.operationId } else { '' }
    }

    # Manual / HTTP Request
    if ($type -eq 'Request') {
        $connector = 'Request'
        $operation = 'Manual / HTTP Request'
        if ($trigger.inputs -and $trigger.inputs.schema) {
            $inputDetail = 'Has input schema'
        }
    }

    # Recurrence
    if ($trigger.recurrence) {
        $rec      = $trigger.recurrence
        $freq     = if ($rec.frequency) { $rec.frequency } else { '' }
        $interval = if ($rec.interval)  { $rec.interval }  else { '' }
        $startTime = if ($rec.startTime) { $rec.startTime } else { '' }
        $timeZone  = if ($rec.timeZone)  { $rec.timeZone }  else { '' }
        $schedule  = ''
        if ($rec.schedule) {
            $parts = @()
            if ($rec.schedule.hours)     { $parts += "Hours: $($rec.schedule.hours -join ',')" }
            if ($rec.schedule.minutes)   { $parts += "Minutes: $($rec.schedule.minutes -join ',')" }
            if ($rec.schedule.weekDays)  { $parts += "Days: $($rec.schedule.weekDays -join ',')" }
            if ($rec.schedule.monthDays) { $parts += "MonthDays: $($rec.schedule.monthDays -join ',')" }
            $schedule = $parts -join ' | '
        }
        $recurrence = "Every $interval $freq"
        if ($schedule)   { $recurrence += " ($schedule)" }
        if ($startTime)  { $recurrence += " starting $startTime" }
        if ($timeZone)   { $recurrence += " [$timeZone]" }
    }

    if ($type -eq 'Recurrence' -and -not $connector) {
        $connector = 'Schedule'
        $operation = 'Recurrence'
    }

    # Polling trigger parameters
    if ($trigger.inputs -and $trigger.inputs.parameters) {
        $paramParts = @()
        $trigger.inputs.parameters.PSObject.Properties | ForEach-Object {
            $val = if ($_.Value -is [string] -and $_.Value.Length -le 80) { $_.Value } else { '(complex)' }
            $paramParts += "$($_.Name): $val"
        }
        $inputDetail = $paramParts -join ' | '
        if ($inputDetail.Length -gt 300) { $inputDetail = $inputDetail.Substring(0, 297) + '...' }
    }

    # SplitOn (batching)
    if ($trigger.splitOn) {
        $description += "SplitOn: $($trigger.splitOn) "
    }

    # Filter conditions
    if ($trigger.conditions) {
        $condParts = $trigger.conditions | ForEach-Object { $_.expression }
        $description += "Conditions: $($condParts -join '; ')"
    }

    [PSCustomObject]@{
        Name        = $triggerName
        Type        = $type
        Connector   = $connector
        Operation   = $operation
        Recurrence  = $recurrence
        Description = $description
        Inputs      = $inputDetail
    }
}


function Get-ConnectionReferences {
    <#
    .SYNOPSIS
        Extracts all connection references from a flow's properties.
    .PARAMETER FlowProps
        The flow's Internal.properties object.
    #>
    param([object]$FlowProps)

    $connections = [System.Collections.Generic.List[object]]::new()

    if ($FlowProps.connectionReferences) {
        $refs = $FlowProps.connectionReferences
        if ($refs -is [PSCustomObject]) {
            $refs.PSObject.Properties | ForEach-Object {
                $ref = $_.Value
                $connections.Add([PSCustomObject]@{
                    Name         = $_.Name
                    DisplayName  = if ($ref.displayName)    { $ref.displayName }    else { $_.Name }
                    ConnectorId  = if ($ref.id)             { $ref.id.Split('/')[-1] } else { '-' }
                    ConnectionId = if ($ref.connectionName) { $ref.connectionName } else { '-' }
                    Status       = if ($ref.statuses) {
                        ($ref.statuses | ForEach-Object { $_.status }) -join ', '
                    } else { '-' }
                    Tier         = if ($ref.tier) { $ref.tier } else { '-' }
                })
            }
        }
    }

    return $connections
}


function Get-FlowRunHistory {
    <#
    .SYNOPSIS
        Retrieves recent run history via the Flow REST API called through the
        admin module's scope (same InvokeApi pattern as definition fetch).
        Get-FlowRun lives in the maker module which we do not load due to
        MSAL version conflicts; the REST endpoint is equivalent.
    .PARAMETER EnvironmentName
        The environment GUID.
    .PARAMETER FlowName
        The flow GUID.
    .PARAMETER Top
        Number of runs to retrieve.
    #>
    param(
        [string]$EnvironmentName,
        [string]$FlowName,
        [int]$Top = 10
    )

    # Use /scopes/admin/ path - same ownership restriction applies to run history.
    # The non-scoped endpoint returns runs only for flows the caller owns.
    $uri = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/$EnvironmentName/flows/$FlowName/runs`?api-version=2016-11-01&`$top=$Top"

    try {
        $response = & $script:adminModule {
            param($u)
            InvokeApi -Method GET -Route $u
        } $uri

        if (-not $response -or -not $response.value) {
            return @()
        }

        $results = foreach ($run in ($response.value | Select-Object -First $Top)) {
            $startTime = $run.properties.startTime
            $endTime   = $run.properties.endTime
            $status    = $run.properties.status

            $dur = '-'
            if ($startTime -and $endTime) {
                try { $dur = (([DateTime]$endTime) - ([DateTime]$startTime)).ToString('hh\:mm\:ss') }
                catch { $dur = '-' }
            }

            $trigName = '-'
            if ($run.properties.trigger -and $run.properties.trigger.name) {
                $trigName = $run.properties.trigger.name
            }

            [PSCustomObject]@{
                RunName     = $run.name
                Status      = $status
                StartTime   = $startTime
                EndTime     = $endTime
                Duration    = $dur
                TriggerName = $trigName
            }
        }
        return $results
    }
    catch {
        Write-Warning "  Could not retrieve run history for $FlowName : $_"
        return @()
    }
}


# ============================================================================
# REGION: Data Collection
# ============================================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Collecting Flow Data (Full Detail Mode)   " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Environment name map
Write-Host "[INFO] Retrieving environments..." -ForegroundColor Yellow
$environments = Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue
$envMap = @{}
if ($environments) {
    foreach ($env in $environments) {
        $envMap[$env.EnvironmentName] = if ($env.DisplayName) { $env.DisplayName } else { $env.EnvironmentName }
    }
}
Write-Host "[OK]   Found $($envMap.Count) environment(s).`n" -ForegroundColor Green

# Get all flows (basic metadata only - no definition at this stage)
Write-Host "[INFO] Retrieving flow list..." -ForegroundColor Yellow
$flowParams = @{}
if ($EnvironmentName)  { $flowParams['EnvironmentName'] = $EnvironmentName }
if ($IncludeDeleted)   { $flowParams['IncludeDeleted']  = $true }

$flows = Get-AdminFlow @flowParams
if (-not $flows -or $flows.Count -eq 0) {
    Write-Error "No flows found. Verify permissions and parameters."
    return
}
Write-Host "[OK]   Found $($flows.Count) flow(s). Re-fetching each for full definition...`n" -ForegroundColor Green

# Build detailed flow objects
$flowData = [System.Collections.Generic.List[object]]::new()
$counter  = 0

foreach ($flow in $flows) {
    $counter++
    $pct = [math]::Round(($counter / $flows.Count) * 100)
    Write-Host "[$pct%] ($counter/$($flows.Count)) $($flow.DisplayName)" -ForegroundColor Yellow

    # -------------------------------------------------------------------
    # Get-AdminFlow never returns Internal.properties.definition regardless
    # of parameters - the PowerShell module omits the $expand query string.
    # Fetch the definition directly via REST with $expand=properties.definition.
    # Props for metadata still come from the bulk list object.
    # -------------------------------------------------------------------
    $props = $flow.Internal.properties

    Write-Host "       Fetching definition via REST..." -ForegroundColor DarkGray
    $def = Get-FlowDefinitionViaRest `
        -EnvironmentName $flow.EnvironmentName `
        -FlowName        $flow.FlowName

    $defFallback = $false
    if (-not $def) {
        Write-Warning "  No parseable definition for $($flow.DisplayName). Falling back to definitionSummary."
        $defFallback = $true

        # The bulk Get-AdminFlow list omits definitionSummary and connectionReferences.
        # Fetch the individual flow via the admin endpoint (no expand needed) - this
        # single-flow GET reliably returns both fields, enabling the fallback to work.
        $singleUri = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/$($flow.EnvironmentName)/flows/$($flow.FlowName)`?api-version=2016-11-01"
        try {
            $singleResponse = & $script:adminModule {
                param($u)
                InvokeApi -Method GET -Route $u
            } $singleUri
            if ($singleResponse -and $singleResponse.properties) {
                $props = $singleResponse.properties
            }
        }
        catch {
            Write-Verbose "  Could not fetch individual flow properties: $_"
        }
    } else {
        Write-Host "       Definition parsed OK." -ForegroundColor DarkGray
    }

    # --- Trigger ---
    # Inline if-expressions are not valid in PS 5.1 function arguments.
    # Evaluate to a variable first, then pass.
    if (-not $defFallback) {
        $triggerSrc = $def.triggers
    } else {
        $triggerSrc = $null
    }
    $triggerDetail = Get-TriggerDetail -Triggers $triggerSrc

    # Partial fallback from definitionSummary when REST fetch failed.
    # The individual flow fetch (above) populates $props.definitionSummary with
    # trigger type, connector ID, and operation from the admin endpoint.
    if ($defFallback -and $props.definitionSummary -and $props.definitionSummary.triggers) {
        $summaryTrigger = $props.definitionSummary.triggers | Select-Object -First 1
        if ($summaryTrigger) {
            $sumType = if ($summaryTrigger.type) { $summaryTrigger.type } else { 'Unknown' }

            # id is a full API path (/providers/Microsoft.PowerApps/apis/shared_xyz)
            # or a short name (manual). Extract the meaningful last segment.
            $sumConnector = '-'
            if ($summaryTrigger.id) {
                $idParts = ($summaryTrigger.id -split '/')
                $rawId = $idParts[-1]                     # e.g. shared_office365users or manual
                $sumConnector = $rawId -replace '^shared_', ''  # strip shared_ prefix
            }

            # For built-in trigger types, override with friendlier names
            switch ($sumType) {
                'Recurrence' { $sumConnector = 'Schedule' }
                'Request'    { $sumConnector = 'Request' }
                'OpenApiConnection' {
                    if ($summaryTrigger.swaggerOperationId) {
                        $sumConnector = if ($sumConnector -and $sumConnector -ne '-') { $sumConnector } else { '-' }
                    }
                }
            }

            $sumOperation = if ($summaryTrigger.swaggerOperationId) { $summaryTrigger.swaggerOperationId } else { $sumType }

            $triggerDetail = [PSCustomObject]@{
                Name        = $sumType
                Type        = $sumType
                Connector   = $sumConnector
                Operation   = $sumOperation
                Recurrence  = '-'
                Description = '(definitionSummary - full definition unavailable via admin API)'
                Inputs      = '-'
            }
        }
    }

    # --- Actions ---
    if (-not $defFallback) {
        $actionSrc = $def.actions
    } else {
        $actionSrc = $null
    }
    $actionTree   = Get-ActionTree -Actions $actionSrc
    $totalActions = ($actionTree | Where-Object { $_.ActionType -ne 'Branch' }).Count

    # Count from definitionSummary when REST parse failed
    if ($defFallback -and $totalActions -eq 0 -and $props.definitionSummary -and $props.definitionSummary.actions) {
        $totalActions = ($props.definitionSummary.actions | Measure-Object).Count
    }

    # --- Connection References ---
    $connRefs = Get-ConnectionReferences -FlowProps $props

    # --- Owners ---
    $owners = @()
    try {
        $ownerRoles = Get-AdminFlowOwnerRole `
            -EnvironmentName $flow.EnvironmentName `
            -FlowName        $flow.FlowName `
            -ErrorAction     SilentlyContinue

        $owners = foreach ($o in $ownerRoles) {
            # PrincipalDisplayName may be empty for service principals / app registrations;
            # fall back to email then object ID.
            $displayName = $o.PrincipalDisplayName
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                $displayName = if ($o.PrincipalEmail)    { $o.PrincipalEmail }
                               elseif ($o.PrincipalObjectId) { "[$($o.PrincipalObjectId)]" }
                               else { '[Unknown Principal]' }
            }
            [PSCustomObject]@{
                DisplayName = $displayName
                ObjectId    = $o.PrincipalObjectId
                Email       = $o.PrincipalEmail
                Type        = $o.PrincipalType
                Role        = $o.RoleType
            }
        }
    }
    catch { $owners = @() }

    # --- Run History ---
    $runHistory = Get-FlowRunHistory `
        -EnvironmentName $flow.EnvironmentName `
        -FlowName        $flow.FlowName `
        -Top             $MaxRunHistory

    # --- Variables (extracted from InitializeVariable actions) ---
    $variables = $actionTree |
        Where-Object { $_.ActionType -eq 'InitializeVariable' } |
        ForEach-Object { $_.Operation }

    # --- Unique connectors summary ---
    # Collect from action tree, then prepend trigger connector; deduplicate properly.
    $connectorList = [System.Collections.Generic.List[string]]::new()
    if ($triggerDetail.Connector -and $triggerDetail.Connector -notin @('-', '')) {
        $connectorList.Add($triggerDetail.Connector)
    }
    $actionTree |
        Where-Object { $_.Connector -and $_.Connector -notin @('', 'Control', 'Variables') } |
        Select-Object -ExpandProperty Connector -Unique |
        ForEach-Object { if (-not $connectorList.Contains($_)) { $connectorList.Add($_) } }

    $uniqueConnectors = $connectorList -join ', '

    # --- Suspension ---
    $suspensionReason = if ($props.flowSuspensionReason) { $props.flowSuspensionReason } else { 'None' }
    $suspensionTime   = if ($props.flowSuspensionTime)   { $props.flowSuspensionTime }   else { '' }

    # --- IsSolutionAware ---
    # A flow is solution-aware when it has a solutionContext property OR isManaged is true.
    # Do NOT use $props.environment.name - that is always populated.
    $isSolutionAware  = if ($props.isManaged -eq $true -or $props.solutionContext) { 'Yes' } else { 'No' }

    # --- Environment friendly name ---
    $envFriendly = if ($envMap[$flow.EnvironmentName]) { $envMap[$flow.EnvironmentName] } else { $flow.EnvironmentName }

    $flowData.Add([PSCustomObject]@{
        DisplayName      = $flow.DisplayName
        FlowId           = $flow.FlowName
        EnvironmentId    = $flow.EnvironmentName
        EnvironmentName  = $envFriendly
        State            = $props.state
        Enabled          = $flow.Enabled
        CreatedTime      = $flow.CreatedTime
        LastModifiedTime = $flow.LastModifiedTime
        CreatorObjectId  = $props.creator.objectId
        CreatorType      = $props.creator.userType
        Sharing          = if ($props.sharingType) { $props.sharingType } else { 'Personal' }
        IsSolutionAware  = $isSolutionAware
        SuspensionReason = $suspensionReason
        SuspensionTime   = $suspensionTime
        TriggerDetail    = $triggerDetail
        ActionTree       = $actionTree
        TotalActions     = $totalActions
        ConnectionRefs   = $connRefs
        Owners           = $owners
        RunHistory       = $runHistory
        Variables        = $variables
        UniqueConnectors = $uniqueConnectors
        DefinitionParsed = (-not $defFallback)
        TemplateId       = if ($props.templateName) { $props.templateName } else { '-' }
    })
}

Write-Host "`n[OK]   All flow data collected.`n" -ForegroundColor Green


# ============================================================================
# REGION: HTML Report Generation
# ============================================================================

Write-Host "[INFO] Generating HTML report..." -ForegroundColor Yellow

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$fileStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Logo: embed file if provided, otherwise render text wordmark
$logoHtml = '<span style="font-size:26px;font-weight:900;letter-spacing:2px;color:white;">YEYLAND WUTANI</span><span style="color:rgba(255,255,255,0.7);font-size:12px;margin-left:6px;letter-spacing:1px;">LLC</span>'
if ($LogoPath -and (Test-Path $LogoPath)) {
    $logoBytes  = [System.IO.File]::ReadAllBytes($LogoPath)
    $logoBase64 = [Convert]::ToBase64String($logoBytes)
    $ext = [System.IO.Path]::GetExtension($LogoPath).TrimStart('.').ToLower()
    if ($ext -eq 'jpg') { $ext = 'jpeg' }
    $logoHtml = "<img src='data:image/$ext;base64,$logoBase64' alt='Yeyland Wutani' style='height:50px;' />"
}

# --- Per-flow detail HTML ---
$flowDetailSections = [System.Text.StringBuilder]::new()

foreach ($fd in $flowData) {
    $stateClass = switch ($fd.State) {
        'Started'   { 'badge-success' }
        'Stopped'   { 'badge-danger' }
        'Suspended' { 'badge-warning' }
        default     { 'badge-neutral' }
    }
    $cardClass = switch ($fd.State) {
        'Started'   { 'card-started' }
        'Stopped'   { 'card-stopped' }
        'Suspended' { 'card-suspended' }
        default     { '' }
    }
    $enabledIcon  = if ($fd.Enabled) { 'Enabled' }  else { 'Disabled' }
    $enabledClass = if ($fd.Enabled) { 'badge-success' } else { 'badge-danger' }
    $shortId      = $fd.FlowId.Substring(0, [Math]::Min(10, $fd.FlowId.Length)) + '...'
    $parseWarning = if (-not $fd.DefinitionParsed) { '<span class="badge badge-warn">No Definition</span> ' } else { '' }

    [void]$flowDetailSections.Append(@"
    <div class="flow-card $cardClass" data-state="$($fd.State)" data-enabled="$($fd.Enabled)">
        <div class="flow-header" onclick="toggleDetail('$($fd.FlowId)')">
            <div class="flow-header-left">
                <span class="flow-toggle" id="toggle-$($fd.FlowId)">&#9654;</span>
                <span class="flow-title">$([System.Web.HttpUtility]::HtmlEncode($fd.DisplayName))</span>
                $parseWarning<span class="badge $stateClass">$($fd.State)</span>
                <span class="badge $enabledClass">$enabledIcon</span>
                <span class="badge badge-actions">$($fd.TotalActions) actions</span>
            </div>
            <div class="flow-header-right">
                <span class="flow-meta">$($fd.EnvironmentName)</span>
                <span class="flow-meta">Modified: $($fd.LastModifiedTime)</span>
                <span class="flow-meta" title="$($fd.FlowId)">$shortId</span>
            </div>
        </div>
        <div class="flow-detail" id="detail-$($fd.FlowId)" style="display:none;">
"@)

    # Metadata + Trigger panels (side by side)
    [void]$flowDetailSections.Append(@"
            <div class="detail-grid">
                <div class="detail-section">
                    <h4>Flow Metadata</h4>
                    <table class="detail-table">
                        <tr><td class="dt-label">Flow ID</td><td>$($fd.FlowId)</td></tr>
                        <tr><td class="dt-label">Environment</td><td>$($fd.EnvironmentName)</td></tr>
                        <tr><td class="dt-label">State</td><td><span class="badge $stateClass">$($fd.State)</span></td></tr>
                        <tr><td class="dt-label">Enabled</td><td>$($fd.Enabled)</td></tr>
                        <tr><td class="dt-label">Created</td><td>$($fd.CreatedTime)</td></tr>
                        <tr><td class="dt-label">Modified</td><td>$($fd.LastModifiedTime)</td></tr>
                        <tr><td class="dt-label">Creator</td><td>$($fd.CreatorObjectId) ($($fd.CreatorType))</td></tr>
                        <tr><td class="dt-label">Sharing</td><td>$($fd.Sharing)</td></tr>
                        <tr><td class="dt-label">Solution-Aware</td><td>$($fd.IsSolutionAware)</td></tr>
                        <tr><td class="dt-label">Template</td><td>$($fd.TemplateId)</td></tr>
                        <tr><td class="dt-label">Suspension</td><td>$($fd.SuspensionReason)$(if($fd.SuspensionTime){" ($($fd.SuspensionTime))"})</td></tr>
                        <tr><td class="dt-label">Definition</td><td>$(if($fd.DefinitionParsed){'<span class="badge badge-success">Parsed</span>'}else{'<span class="badge badge-warning">Summary Only</span>'})</td></tr>
                    </table>
                </div>
"@)

    $t = $fd.TriggerDetail
    [void]$flowDetailSections.Append(@"
                <div class="detail-section">
                    <h4>Trigger</h4>
                    <table class="detail-table">
                        <tr><td class="dt-label">Name</td><td>$($t.Name)</td></tr>
                        <tr><td class="dt-label">Type</td><td>$($t.Type)</td></tr>
                        <tr><td class="dt-label">Connector</td><td>$($t.Connector)</td></tr>
                        <tr><td class="dt-label">Operation</td><td>$($t.Operation)</td></tr>
                        <tr><td class="dt-label">Recurrence</td><td>$($t.Recurrence)</td></tr>
                        <tr><td class="dt-label">Inputs</td><td>$([System.Web.HttpUtility]::HtmlEncode($t.Inputs))</td></tr>
                        <tr><td class="dt-label">Info</td><td>$([System.Web.HttpUtility]::HtmlEncode($t.Description))</td></tr>
                    </table>
                </div>
            </div>
"@)

    # Owners
    if ($fd.Owners -and $fd.Owners.Count -gt 0) {
        [void]$flowDetailSections.Append('<div class="detail-section full-width"><h4>Owners &amp; Permissions</h4><table class="action-table"><tr><th>Display Name</th><th>Email</th><th>Object ID</th><th>Type</th><th>Role</th></tr>')
        foreach ($o in $fd.Owners) {
            [void]$flowDetailSections.Append("<tr><td>$([System.Web.HttpUtility]::HtmlEncode($o.DisplayName))</td><td>$($o.Email)</td><td>$($o.ObjectId)</td><td>$($o.Type)</td><td>$($o.Role)</td></tr>")
        }
        [void]$flowDetailSections.Append('</table></div>')
    }

    # Connection References
    if ($fd.ConnectionRefs -and $fd.ConnectionRefs.Count -gt 0) {
        [void]$flowDetailSections.Append('<div class="detail-section full-width"><h4>Connection References</h4><table class="action-table"><tr><th>Connector</th><th>Display Name</th><th>Connection ID</th><th>Status</th><th>Tier</th></tr>')
        foreach ($c in $fd.ConnectionRefs) {
            $tierClass = if ($c.Tier -eq 'Premium') { 'tier-premium' } else { '' }
            [void]$flowDetailSections.Append("<tr><td>$($c.ConnectorId)</td><td>$([System.Web.HttpUtility]::HtmlEncode($c.DisplayName))</td><td>$($c.ConnectionId)</td><td>$($c.Status)</td><td class='$tierClass'>$($c.Tier)</td></tr>")
        }
        [void]$flowDetailSections.Append('</table></div>')
    }

    # Variables
    if ($fd.Variables -and $fd.Variables.Count -gt 0) {
        [void]$flowDetailSections.Append('<div class="detail-section full-width"><h4>Variables</h4><ul class="var-list">')
        foreach ($v in $fd.Variables) {
            [void]$flowDetailSections.Append("<li>$([System.Web.HttpUtility]::HtmlEncode($v))</li>")
        }
        [void]$flowDetailSections.Append('</ul></div>')
    }

    # Action Tree
    [void]$flowDetailSections.Append('<div class="detail-section full-width"><h4>Action Tree</h4>')
    if ($fd.ActionTree -and $fd.ActionTree.Count -gt 0) {
        [void]$flowDetailSections.Append('<table class="action-table"><tr><th style="width:4%">#</th><th style="width:22%">Action Name</th><th style="width:10%">Type</th><th style="width:12%">Connector</th><th style="width:20%">Operation</th><th style="width:16%">Run After</th><th style="width:16%">Expression</th></tr>')
        $actionNum = 0
        foreach ($a in $fd.ActionTree) {
            $actionNum++
            $indent   = '&nbsp;&nbsp;&nbsp;&nbsp;' * $a.Depth
            $rowClass = switch ($a.ActionType) {
                'Branch'    { 'row-branch' }
                'If'        { 'row-condition' }
                'Switch'    { 'row-condition' }
                'Scope'     { 'row-scope' }
                'Foreach'   { 'row-loop' }
                'Until'     { 'row-loop' }
                'Terminate' { 'row-terminate' }
                default     { '' }
            }
            $nameDisplay = "$indent$([System.Web.HttpUtility]::HtmlEncode($a.ActionName))"
            $opDisplay   = [System.Web.HttpUtility]::HtmlEncode($a.Operation)
            $exprDisplay = [System.Web.HttpUtility]::HtmlEncode($a.Expression)
            $raDisplay   = [System.Web.HttpUtility]::HtmlEncode($a.RunAfter)
            [void]$flowDetailSections.Append("<tr class='$rowClass'><td>$actionNum</td><td>$nameDisplay</td><td>$($a.ActionType)</td><td>$($a.Connector)</td><td>$opDisplay</td><td class='ra-cell'>$raDisplay</td><td class='expr-cell'>$exprDisplay</td></tr>")
        }
        [void]$flowDetailSections.Append('</table>')
    } else {
        [void]$flowDetailSections.Append('<p class="info-note">Action tree unavailable - flow definition could not be parsed via the admin API. Trigger and action counts are sourced from definitionSummary where available.</p>')
    }
    [void]$flowDetailSections.Append('</div>')

    # Run History
    if ($fd.RunHistory -and $fd.RunHistory.Count -gt 0) {
        [void]$flowDetailSections.Append("<div class='detail-section full-width'><h4>Run History (Last $MaxRunHistory)</h4><table class='action-table'><tr><th>Status</th><th>Start Time</th><th>End Time</th><th>Duration</th><th>Trigger</th><th>Run ID</th></tr>")
        foreach ($r in $fd.RunHistory) {
            $runStatusClass = switch ($r.Status) {
                'Succeeded' { 'run-success' }
                'Failed'    { 'run-failed' }
                'Cancelled' { 'run-cancelled' }
                'Running'   { 'run-running' }
                default     { '' }
            }
            [void]$flowDetailSections.Append("<tr><td class='$runStatusClass'>$($r.Status)</td><td>$($r.StartTime)</td><td>$($r.EndTime)</td><td>$($r.Duration)</td><td>$($r.TriggerName)</td><td>$($r.RunName)</td></tr>")
        }
        [void]$flowDetailSections.Append('</table></div>')
    }

    [void]$flowDetailSections.Append('</div></div>')
}

# --- Executive summary stats ---
$totalFlows     = $flowData.Count
$enabledCount   = ($flowData | Where-Object { $_.Enabled }).Count
$disabledCount  = $totalFlows - $enabledCount
$startedCount   = ($flowData | Where-Object { $_.State -eq 'Started' }).Count
$suspendedCount = ($flowData | Where-Object { $_.State -eq 'Suspended' }).Count
$envCount       = ($flowData | Select-Object -ExpandProperty EnvironmentName -Unique).Count
$creatorCount   = ($flowData | Select-Object -ExpandProperty CreatorObjectId -Unique | Where-Object { $_ }).Count
$solutionCount  = ($flowData | Where-Object { $_.IsSolutionAware -eq 'Yes' }).Count
$totalActions   = ($flowData | Measure-Object -Property TotalActions -Sum).Sum
$premiumCount   = ($flowData | Where-Object { $_.ConnectionRefs | Where-Object { $_.Tier -eq 'Premium' } }).Count
$parsedCount    = ($flowData | Where-Object { $_.DefinitionParsed }).Count

# Environment breakdown
$envBreakdown  = $flowData | Group-Object -Property EnvironmentName | Sort-Object Count -Descending
$envRows = ($envBreakdown | ForEach-Object {
    "<tr><td>$($_.Name)</td><td class='num-cell'>$($_.Count)</td></tr>"
}) -join "`n"

# State breakdown
$stateBreakdown = $flowData | Group-Object -Property State | Sort-Object Count -Descending
$stateRows = ($stateBreakdown | ForEach-Object {
    $sc = switch ($_.Name) {
        'Started'   { 'badge-success' }
        'Stopped'   { 'badge-danger' }
        'Suspended' { 'badge-warning' }
        default     { 'badge-neutral' }
    }
    "<tr><td><span class='badge $sc'>$($_.Name)</span></td><td class='num-cell'>$($_.Count)</td></tr>"
}) -join "`n"


# --- Full HTML assembly ---
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Power Automate Flow Report - Yeyland Wutani</title>
<style>
    :root { --yw-orange: #FF6600; --yw-dark-orange: #CC5200; --yw-light-orange: #FFF3E6; --yw-grey: #6B7280; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #F5F5F5; color: #333; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 13px; line-height: 1.5; }
    a { color: var(--yw-orange); }

    /* Header */
    .header { display: flex; justify-content: space-between; align-items: center; padding: 20px 30px; background: linear-gradient(135deg, var(--yw-orange), var(--yw-dark-orange)); color: white; }
    .header-left { display: flex; align-items: center; gap: 14px; }
    .header-right { text-align: right; }
    .report-title { font-size: 18px; font-weight: 700; color: white; }
    .report-sub { font-size: 11px; color: rgba(255,255,255,0.75); margin-top: 3px; }

    .container { max-width: 1800px; margin: 0 auto; padding: 24px 30px; }

    .section-title { color: var(--yw-dark-orange); font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px; margin-top: 24px; padding-bottom: 6px; border-bottom: 2px solid var(--yw-orange); }

    /* Summary cards */
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .summary-card { background: white; border-radius: 8px; padding: 14px; text-align: center; box-shadow: 0 2px 6px rgba(0,0,0,0.08); border-left: 4px solid var(--yw-orange); }
    .summary-card.warning { border-left-color: #f0ad4e; }
    .summary-card.danger  { border-left-color: #dc3545; }
    .summary-card .num { font-size: 28px; font-weight: 800; color: var(--yw-orange); }
    .summary-card .label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #666; margin-top: 4px; }

    /* Breakdown tables */
    .breakdown-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
    .breakdown-box { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
    .breakdown-box .bb-title { background: var(--yw-light-orange); color: var(--yw-dark-orange); font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; padding: 10px 16px; border-bottom: 2px solid var(--yw-orange); }
    .breakdown-box table { width: 100%; border-collapse: collapse; }
    .breakdown-box td { padding: 7px 16px; border-top: 1px solid #eee; }
    .num-cell { text-align: right; font-weight: 700; color: var(--yw-orange); }

    /* Filter bar */
    .filter-bar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
    .filter-bar input, .filter-bar select { background: white; color: #333; border: 1px solid #ddd; border-radius: 4px; padding: 6px 10px; font-size: 12px; }
    .filter-bar input:focus, .filter-bar select:focus { outline: none; border-color: var(--yw-orange); }
    .filter-bar input { width: 280px; }
    .flow-count { margin-left: auto; color: #888; font-size: 12px; }
    .btn { border-radius: 4px; padding: 5px 14px; cursor: pointer; font-size: 12px; font-weight: 600; border: none; }
    .btn-primary { background: var(--yw-orange); color: white; }
    .btn-secondary { background: white; color: #555; border: 1px solid #ddd; }
    .btn:hover { opacity: 0.85; }

    /* Flow cards */
    .flow-card { background: white; border-radius: 8px; margin-bottom: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.06); border-left: 4px solid #ddd; }
    .flow-card.card-started   { border-left-color: #28a745; }
    .flow-card.card-stopped   { border-left-color: #dc3545; }
    .flow-card.card-suspended { border-left-color: #f0ad4e; }
    .flow-header { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px; cursor: pointer; transition: background 0.15s; }
    .flow-header:hover { background: #FFF7F2; }
    .flow-header-left { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .flow-header-right { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    .flow-toggle { color: var(--yw-orange); font-size: 11px; transition: transform 0.2s; display: inline-block; }
    .flow-toggle.open { transform: rotate(90deg); }
    .flow-title { font-weight: 600; color: #222; font-size: 13px; }
    .flow-meta { color: #888; font-size: 11px; }

    /* Badges */
    .badge { display: inline-block; font-size: 10px; padding: 2px 8px; border-radius: 4px; font-weight: 600; white-space: nowrap; }
    .badge-success { background: #d4edda; color: #155724; }
    .badge-danger  { background: #f8d7da; color: #721c24; }
    .badge-warning { background: #fff3cd; color: #856404; }
    .badge-neutral { background: #e2e3e5; color: #383d41; }
    .badge-actions { background: #e8eaf0; color: #555; }
    .badge-warn    { background: #fff3cd; color: #856404; }

    /* Info note */
    .info-note { background: var(--yw-light-orange); border-left: 3px solid var(--yw-orange); padding: 10px 14px; font-size: 12px; color: var(--yw-dark-orange); border-radius: 0 4px 4px 0; margin: 4px 0; }

    /* Detail panel */
    .flow-detail { padding: 16px; border-top: 1px solid #eee; background: #FAFAFA; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    .detail-section { background: white; border: 1px solid #eee; border-radius: 6px; padding: 14px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .detail-section.full-width { grid-column: 1 / -1; }
    .detail-section h4 { color: var(--yw-dark-orange); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; padding-bottom: 4px; border-bottom: 2px solid var(--yw-light-orange); }

    .detail-table { width: 100%; border-collapse: collapse; }
    .detail-table td { padding: 5px 0; vertical-align: top; }
    .dt-label { color: #666; font-weight: 600; width: 130px; padding-right: 12px; }

    /* Action table */
    .action-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .action-table th { background: var(--yw-light-orange); color: var(--yw-dark-orange); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; padding: 7px 10px; text-align: left; position: sticky; top: 0; border-bottom: 2px solid var(--yw-orange); }
    .action-table td { padding: 5px 10px; border-top: 1px solid #f0f0f0; vertical-align: top; word-break: break-word; }
    .action-table tr:hover { background: #FFF7F2; }

    .row-branch td    { background: #F8F8F8; color: #888; font-style: italic; }
    .row-condition td { border-left: 3px solid #f0ad4e; }
    .row-scope td     { border-left: 3px solid #4a90d9; }
    .row-loop td      { border-left: 3px solid #9B59B6; }
    .row-terminate td { border-left: 3px solid #dc3545; }
    .ra-cell, .expr-cell { font-size: 11px; color: #888; max-width: 200px; }

    .run-success   { color: #28a745; font-weight: 600; }
    .run-failed    { color: #dc3545; font-weight: 600; }
    .run-cancelled { color: #f0ad4e; font-weight: 600; }
    .run-running   { color: #4a90d9; font-weight: 600; }
    .tier-premium  { color: #f0ad4e; font-weight: 700; }

    .var-list { list-style: none; padding: 0; }
    .var-list li { padding: 3px 0; color: #555; }
    .var-list li::before { content: '> '; color: var(--yw-orange); }

    /* Footer */
    .footer { text-align: center; padding: 24px; color: #888; font-size: 11px; margin-top: 20px; border-top: 1px solid #ddd; }
    .footer .tagline { color: var(--yw-orange); font-weight: 600; font-size: 13px; margin-bottom: 4px; }

    @media print {
        body { background: #FFF; }
        .flow-detail { display: block !important; }
        .filter-bar { display: none; }
    }
</style>
</head>
<body>

<div class="header">
    <div class="header-left">$logoHtml</div>
    <div class="header-right">
        <div class="report-title">Power Automate Flow Report</div>
        <div class="report-sub">Generated $timestamp</div>
    </div>
</div>

<div class="container">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
        <div class="summary-card"><div class="num">$totalFlows</div><div class="label">Total Flows</div></div>
        <div class="summary-card"><div class="num">$enabledCount</div><div class="label">Enabled</div></div>
        <div class="summary-card danger"><div class="num">$disabledCount</div><div class="label">Disabled</div></div>
        <div class="summary-card"><div class="num">$startedCount</div><div class="label">Running</div></div>
        <div class="summary-card warning"><div class="num">$suspendedCount</div><div class="label">Suspended</div></div>
        <div class="summary-card"><div class="num">$totalActions</div><div class="label">Total Actions</div></div>
        <div class="summary-card"><div class="num">$envCount</div><div class="label">Environments</div></div>
        <div class="summary-card"><div class="num">$creatorCount</div><div class="label">Unique Creators</div></div>
        <div class="summary-card"><div class="num">$solutionCount</div><div class="label">Solution-Aware</div></div>
        <div class="summary-card warning"><div class="num">$premiumCount</div><div class="label">Premium Connector</div></div>
        <div class="summary-card"><div class="num">$parsedCount</div><div class="label">Definitions Parsed</div></div>
    </div>

    <div class="breakdown-grid">
        <div class="breakdown-box"><div class="bb-title">Flows by Environment</div><table>$envRows</table></div>
        <div class="breakdown-box"><div class="bb-title">Flows by State</div><table>$stateRows</table></div>
    </div>

    <div class="section-title">Flow Details (Click to Expand)</div>
    <div class="filter-bar">
        <input type="text" id="searchBox" placeholder="Search flows by name, connector, action..." onkeyup="filterFlows()" />
        <select id="stateFilter" onchange="filterFlows()">
            <option value="">All States</option>
            <option value="Started">Started</option>
            <option value="Stopped">Stopped</option>
            <option value="Suspended">Suspended</option>
        </select>
        <select id="enabledFilter" onchange="filterFlows()">
            <option value="">All</option>
            <option value="True">Enabled</option>
            <option value="False">Disabled</option>
        </select>
        <button class="btn btn-primary" onclick="expandAll()">Expand All</button>
        <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
        <span class="flow-count" id="flowCount">$totalFlows flow(s)</span>
    </div>

    $($flowDetailSections.ToString())
</div>

<div class="footer">
    <div class="tagline">Building Better Systems</div>
    Yeyland Wutani LLC &mdash; Power Automate Flow Report &mdash; Generated $timestamp
</div>

<script>
function toggleDetail(id) {
    var el  = document.getElementById('detail-' + id);
    var tog = document.getElementById('toggle-' + id);
    if (el.style.display === 'none') {
        el.style.display = 'block';
        tog.classList.add('open');
    } else {
        el.style.display = 'none';
        tog.classList.remove('open');
    }
}
function expandAll() {
    document.querySelectorAll('.flow-detail').forEach(function(el) { el.style.display = 'block'; });
    document.querySelectorAll('.flow-toggle').forEach(function(el) { el.classList.add('open'); });
}
function collapseAll() {
    document.querySelectorAll('.flow-detail').forEach(function(el) { el.style.display = 'none'; });
    document.querySelectorAll('.flow-toggle').forEach(function(el) { el.classList.remove('open'); });
}
function filterFlows() {
    var search  = document.getElementById('searchBox').value.toLowerCase();
    var state   = document.getElementById('stateFilter').value;
    var enabled = document.getElementById('enabledFilter').value;
    var cards   = document.querySelectorAll('.flow-card');
    var visible = 0;
    cards.forEach(function(card) {
        var text    = card.textContent.toLowerCase();
        var cardState   = card.getAttribute('data-state')   || '';
        var cardEnabled = card.getAttribute('data-enabled') || '';
        var show = true;
        if (search  && text.indexOf(search) === -1)              show = false;
        if (state   && cardState !== state)                      show = false;
        if (enabled && cardEnabled.toLowerCase() !== enabled.toLowerCase()) show = false;
        card.style.display = show ? 'block' : 'none';
        if (show) visible++;
    });
    document.getElementById('flowCount').textContent = visible + ' flow(s)';
}
</script>

</body>
</html>
"@

# Write HTML
$htmlPath = Join-Path $OutputPath "FlowReport_YW_$fileStamp.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
Write-Host "[OK]   HTML report: $htmlPath" -ForegroundColor Green


# ============================================================================
# REGION: CSV Export
# ============================================================================

$csvData = foreach ($fd in $flowData) {
    [PSCustomObject]@{
        FlowName          = $fd.DisplayName
        FlowId            = $fd.FlowId
        State             = $fd.State
        Enabled           = $fd.Enabled
        Environment       = $fd.EnvironmentName
        Created           = $fd.CreatedTime
        Modified          = $fd.LastModifiedTime
        Creator           = $fd.CreatorObjectId
        DefinitionParsed  = $fd.DefinitionParsed
        TotalActions      = $fd.TotalActions
        TriggerType       = $fd.TriggerDetail.Type
        TriggerConnector  = $fd.TriggerDetail.Connector
        TriggerOperation  = $fd.TriggerDetail.Operation
        TriggerRecurrence = $fd.TriggerDetail.Recurrence
        Connectors        = $fd.UniqueConnectors
        Sharing           = $fd.Sharing
        SolutionAware     = $fd.IsSolutionAware
        SuspensionReason  = $fd.SuspensionReason
        Variables         = ($fd.Variables -join '; ')
        Owners            = ($fd.Owners | ForEach-Object { "$($_.DisplayName) <$($_.Email)> ($($_.Role))" }) -join '; '
        ActionList        = ($fd.ActionTree | Where-Object { $_.ActionType -ne 'Branch' } |
                             ForEach-Object { "$($_.ActionName) [$($_.Connector)]" }) -join '; '
        ConnectionCount   = $fd.ConnectionRefs.Count
        LastRunStatus     = if ($fd.RunHistory -and $fd.RunHistory.Count -gt 0) { $fd.RunHistory[0].Status } else { 'No runs' }
        LastRunTime       = if ($fd.RunHistory -and $fd.RunHistory.Count -gt 0) { $fd.RunHistory[0].StartTime } else { '' }
    }
}

$csvPath = Join-Path $OutputPath "FlowReport_YW_$fileStamp.csv"
$csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "[OK]   CSV export:   $csvPath" -ForegroundColor Green

Write-Host "`n[INFO] Opening report in browser..." -ForegroundColor Yellow
Start-Process $htmlPath

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Report complete: $totalFlows flows analyzed" -ForegroundColor Cyan
Write-Host " Definitions parsed: $parsedCount / $totalFlows" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

return $flowData
