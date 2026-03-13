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
    Version : 2.1
    Module  : Microsoft.PowerApps.Administration.PowerShell

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
        Fetches a flow's full definition via InvokeApi called in the admin
        module's scope. InvokeApi is defined in Microsoft.PowerApps.AuthModule,
        which is a nested dependency of the admin module. Calling it via
        & $adminModule { } runs it with access to the module's internal session.

        We do NOT import the maker module (Microsoft.PowerApps.PowerShell)
        because it causes a Microsoft.Identity.Client version conflict when
        both modules are loaded in the same session.
    .PARAMETER EnvironmentName
        The environment GUID (e.g. Default-xxxx-xxxx).
    .PARAMETER FlowName
        The flow GUID.
    #>
    param(
        [string]$EnvironmentName,
        [string]$FlowName
    )

    # Use the /scopes/admin/ path - the non-scoped endpoint only returns
    # the full definition for flows owned by the calling user. Other users'
    # flows return metadata only, which is why flows owned by a different
    # account silently return without a definition node.
    $uri = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/$EnvironmentName/flows/$FlowName`?api-version=2016-11-01&`$expand=properties.definition"

    try {
        # Call InvokeApi inside the admin module's scope so it can access
        # the module-internal session and token. Arguments passed via param().
        $response = & $script:adminModule {
            param($u)
            InvokeApi -Method GET -Route $u
        } $uri

        if (-not $response) {
            Write-Warning "  REST: null response for $FlowName."
            return $null
        }

        $rawDef = $response.properties.definition
        if (-not $rawDef) {
            Write-Warning "  REST: definition node absent for $FlowName."
            return $null
        }

        return Resolve-FlowDefinition -Definition $rawDef
    }
    catch {
        Write-Warning "  REST fetch failed for $FlowName : $_"
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

    # Partial fallback from definitionSummary when REST fetch failed
    if ($defFallback -and $props.definitionSummary -and $props.definitionSummary.triggers) {
        $summaryTrigger = $props.definitionSummary.triggers | Select-Object -First 1
        if ($summaryTrigger) {
            $triggerConnector = if ($summaryTrigger.swaggerOperationId) {
                $summaryTrigger.swaggerOperationId
            } else { '-' }
            $triggerDetail = [PSCustomObject]@{
                Name        = if ($summaryTrigger.id)   { $summaryTrigger.id }   else { 'Unknown' }
                Type        = if ($summaryTrigger.type) { $summaryTrigger.type } else { 'Unknown' }
                Connector   = $triggerConnector
                Operation   = '-'
                Recurrence  = '-'
                Description = '(definitionSummary only - REST fetch failed or token expired)'
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
$logoHtml = '<span style="font-size:26px;font-weight:900;letter-spacing:2px;color:#FF6600;">YEYLAND WUTANI</span><span style="color:#8899AA;font-size:12px;margin-left:6px;letter-spacing:1px;">LLC</span>'
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
        'Started'   { 'state-started' }
        'Stopped'   { 'state-stopped' }
        'Suspended' { 'state-suspended' }
        default     { '' }
    }
    $enabledIcon  = if ($fd.Enabled) { 'Enabled' }  else { 'Disabled' }
    $enabledClass = if ($fd.Enabled) { 'enabled-yes' } else { 'enabled-no' }
    $shortId      = $fd.FlowId.Substring(0, [Math]::Min(10, $fd.FlowId.Length)) + '...'
    $parseWarning = if (-not $fd.DefinitionParsed) { '<span class="badge badge-warn">No Definition</span> ' } else { '' }

    [void]$flowDetailSections.Append(@"
    <div class="flow-card" data-state="$($fd.State)" data-enabled="$($fd.Enabled)">
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
                        <tr><td class="dt-label">State</td><td><span class="$stateClass">$($fd.State)</span></td></tr>
                        <tr><td class="dt-label">Enabled</td><td>$($fd.Enabled)</td></tr>
                        <tr><td class="dt-label">Created</td><td>$($fd.CreatedTime)</td></tr>
                        <tr><td class="dt-label">Modified</td><td>$($fd.LastModifiedTime)</td></tr>
                        <tr><td class="dt-label">Creator</td><td>$($fd.CreatorObjectId) ($($fd.CreatorType))</td></tr>
                        <tr><td class="dt-label">Sharing</td><td>$($fd.Sharing)</td></tr>
                        <tr><td class="dt-label">Solution-Aware</td><td>$($fd.IsSolutionAware)</td></tr>
                        <tr><td class="dt-label">Template</td><td>$($fd.TemplateId)</td></tr>
                        <tr><td class="dt-label">Suspension</td><td>$($fd.SuspensionReason)$(if($fd.SuspensionTime){" ($($fd.SuspensionTime))"})</td></tr>
                        <tr><td class="dt-label">Definition</td><td>$(if($fd.DefinitionParsed){'Parsed'}else{'<span style="color:#FBBF24;">Unavailable (summary only)</span>'})</td></tr>
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
        [void]$flowDetailSections.Append('<p style="color:#FBBF24;padding:10px;">Action tree unavailable - flow definition could not be parsed. This may occur for flows in restricted environments or with non-standard definitions.</p>')
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
        'Started'   { 'state-started' }
        'Stopped'   { 'state-stopped' }
        'Suspended' { 'state-suspended' }
        default     { '' }
    }
    "<tr><td><span class='$sc'>$($_.Name)</span></td><td class='num-cell'>$($_.Count)</td></tr>"
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
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0A0E1A; color: #C8D0DC; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 13px; }
    a { color: #FF6600; }

    /* Header */
    .header { display: flex; justify-content: space-between; align-items: center; padding: 18px 30px; background: linear-gradient(135deg, #0D1224 0%, #131A2E 100%); border-bottom: 2px solid #FF6600; }
    .header-left { display: flex; align-items: center; gap: 14px; }
    .header-right { text-align: right; }
    .report-title { font-size: 18px; font-weight: 700; color: #FF6600; }
    .report-sub { font-size: 11px; color: #667788; margin-top: 3px; }

    .container { max-width: 1800px; margin: 0 auto; padding: 20px 30px; }

    .section-title { color: #FF6600; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px; margin-top: 24px; padding-bottom: 4px; border-bottom: 1px solid #1E2740; }

    /* Summary cards */
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .summary-card { background: #111827; border: 1px solid #1E2740; border-radius: 6px; padding: 14px; text-align: center; }
    .summary-card .num { font-size: 28px; font-weight: 800; color: #FF6600; }
    .summary-card .label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #667788; margin-top: 4px; }

    /* Breakdown tables */
    .breakdown-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
    .breakdown-box { background: #111827; border: 1px solid #1E2740; border-radius: 6px; overflow: hidden; }
    .breakdown-box .bb-title { background: #1A2236; color: #FF6600; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; padding: 8px 14px; }
    .breakdown-box table { width: 100%; border-collapse: collapse; }
    .breakdown-box td { padding: 6px 14px; border-top: 1px solid #1A2236; }
    .num-cell { text-align: right; font-weight: 700; color: #FF6600; }

    /* Filter bar */
    .filter-bar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
    .filter-bar input, .filter-bar select { background: #111827; color: #C8D0DC; border: 1px solid #1E2740; border-radius: 4px; padding: 6px 10px; font-size: 12px; }
    .filter-bar input { width: 280px; }
    .flow-count { margin-left: auto; color: #667788; font-size: 12px; }

    /* Flow cards */
    .flow-card { background: #111827; border: 1px solid #1E2740; border-radius: 6px; margin-bottom: 6px; overflow: hidden; }
    .flow-header { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px; cursor: pointer; transition: background 0.15s; }
    .flow-header:hover { background: #1A2236; }
    .flow-header-left { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .flow-header-right { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    .flow-toggle { color: #FF6600; font-size: 11px; transition: transform 0.2s; display: inline-block; }
    .flow-toggle.open { transform: rotate(90deg); }
    .flow-title { font-weight: 600; color: #E0E6EE; font-size: 13px; }
    .flow-meta { color: #556677; font-size: 11px; }

    /* Badges */
    .badge { font-size: 10px; padding: 2px 8px; border-radius: 3px; font-weight: 600; }
    .state-started   { background: #0D3320; color: #34D399; }
    .state-stopped   { background: #3B1111; color: #F87171; }
    .state-suspended { background: #3B2E11; color: #FBBF24; }
    .enabled-yes     { color: #34D399; }
    .enabled-no      { color: #F87171; }
    .badge-actions   { background: #1A2236; color: #8899AA; }
    .badge-warn      { background: #3B2E11; color: #FBBF24; }

    /* Detail panel */
    .flow-detail { padding: 16px; border-top: 1px solid #1E2740; background: #0D1224; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    .detail-section { background: #111827; border: 1px solid #1E2740; border-radius: 6px; padding: 14px; margin-bottom: 12px; }
    .detail-section.full-width { grid-column: 1 / -1; }
    .detail-section h4 { color: #FF6600; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; padding-bottom: 4px; border-bottom: 1px solid #1E2740; }

    .detail-table { width: 100%; border-collapse: collapse; }
    .detail-table td { padding: 4px 0; vertical-align: top; }
    .dt-label { color: #667788; font-weight: 600; width: 130px; padding-right: 12px; }

    /* Action table */
    .action-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .action-table th { background: #1A2236; color: #FF6600; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; padding: 7px 10px; text-align: left; position: sticky; top: 0; }
    .action-table td { padding: 5px 10px; border-top: 1px solid #1A2236; vertical-align: top; word-break: break-word; }
    .action-table tr:hover { background: #151D30; }

    .row-branch td    { background: #0F1A2A; color: #6B8DB5; font-style: italic; }
    .row-condition td { border-left: 3px solid #FBBF24; }
    .row-scope td     { border-left: 3px solid #60A5FA; }
    .row-loop td      { border-left: 3px solid #A78BFA; }
    .row-terminate td { border-left: 3px solid #F87171; }
    .ra-cell, .expr-cell { font-size: 11px; color: #8899AA; max-width: 200px; }

    .run-success   { color: #34D399; font-weight: 600; }
    .run-failed    { color: #F87171; font-weight: 600; }
    .run-cancelled { color: #FBBF24; font-weight: 600; }
    .run-running   { color: #60A5FA; font-weight: 600; }
    .tier-premium  { color: #FBBF24; font-weight: 700; }

    .var-list { list-style: none; padding: 0; }
    .var-list li { padding: 3px 0; color: #A0AABB; }
    .var-list li::before { content: '> '; color: #FF6600; }

    @media print {
        body { background: #FFF; color: #222; }
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
        <div class="report-sub">Generated $timestamp | Building Better Systems</div>
    </div>
</div>

<div class="container">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
        <div class="summary-card"><div class="num">$totalFlows</div><div class="label">Total Flows</div></div>
        <div class="summary-card"><div class="num">$enabledCount</div><div class="label">Enabled</div></div>
        <div class="summary-card"><div class="num">$disabledCount</div><div class="label">Disabled</div></div>
        <div class="summary-card"><div class="num">$startedCount</div><div class="label">Running</div></div>
        <div class="summary-card"><div class="num">$suspendedCount</div><div class="label">Suspended</div></div>
        <div class="summary-card"><div class="num">$totalActions</div><div class="label">Total Actions</div></div>
        <div class="summary-card"><div class="num">$envCount</div><div class="label">Environments</div></div>
        <div class="summary-card"><div class="num">$creatorCount</div><div class="label">Unique Creators</div></div>
        <div class="summary-card"><div class="num">$solutionCount</div><div class="label">Solution-Aware</div></div>
        <div class="summary-card"><div class="num">$premiumCount</div><div class="label">Premium Connector</div></div>
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
        <button onclick="expandAll()" style="background:#1A2236;color:#FF6600;border:1px solid #FF6600;border-radius:4px;padding:5px 12px;cursor:pointer;font-size:11px;">Expand All</button>
        <button onclick="collapseAll()" style="background:#1A2236;color:#8899AA;border:1px solid #1E2740;border-radius:4px;padding:5px 12px;cursor:pointer;font-size:11px;">Collapse All</button>
        <span class="flow-count" id="flowCount">$totalFlows flow(s)</span>
    </div>

    $($flowDetailSections.ToString())
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
