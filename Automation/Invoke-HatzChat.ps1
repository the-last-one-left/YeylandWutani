<#
.SYNOPSIS
    Interactive chat client for the Hatz AI API.

.DESCRIPTION
    Connects to https://ai.hatz.ai/v1, manages API key persistence via
    environment variable, allows model selection from available models,
    and provides a multi-turn chat session with conversation history.

.PARAMETER ApiBaseUrl
    Override the default API base URL. Default: https://ai.hatz.ai/v1

.PARAMETER EnvVarName
    Name of the environment variable used to store the API key.
    Default: HATZ_AI_API_KEY

.PARAMETER ApiKey
    Pass the API key directly (skips environment variable lookup/prompt).

.EXAMPLE
    .\Invoke-HatzChat.ps1
    # Prompts for key on first run, remembers it after

.EXAMPLE
    .\Invoke-HatzChat.ps1 -ApiKey "your-key-here"
    # Pass API key directly

.NOTES
    Author  : Zachary / Pacific Office Automation - Escalations
    Requires: PowerShell 5.1+ (native Invoke-RestMethod)
    API Docs: https://api-docs.hatz.ai/
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ApiBaseUrl   = 'https://ai.hatz.ai/v1',
    [string]$EnvVarName   = 'HATZ_AI_API_KEY',
    [string]$ApiKey,
    # Model to use without prompting; falls back to interactive selection if not found.
    [string]$DefaultModel = 'anthropic.claude-opus-4-6',
    # Max non-system messages kept in history (0 = unlimited).
    [int]$MaxHistory      = 40
)

# --- Region: TLS Configuration -----------------------------------------------
# Ensure TLS 1.2 is available for HTTPS connections
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- Region: Console Encoding -------------------------------------------------
# Prevent garbled characters (â, â€, etc.) from UTF-8 API responses
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding          = [System.Text.Encoding]::UTF8

# --- Region: Constants --------------------------------------------------------
# DPAPI-encrypted credential file (per-user, per-machine via Export-Clixml)
$script:CredFile = Join-Path $env:APPDATA 'HatzChat\api_key.clixml'

# --- Region: API Key Management -----------------------------------------------

function Get-HatzApiKey {
    <#
    .SYNOPSIS
        Retrieves or prompts for the Hatz AI API key and persists it securely.
    .NOTES
        Storage priority:
          1. -ApiKey parameter (not persisted)
          2. DPAPI-encrypted XML file ($script:CredFile) via Export-Clixml
          3. Legacy plaintext env var (auto-migrated to encrypted file then cleared)
          4. Session environment variable (not persisted)
          5. Interactive prompt (persisted to encrypted file)
        DPAPI encrypts per-user/per-machine — the file cannot be decrypted on
        another machine or by another Windows user account.
    #>
    param(
        [string]$EnvVarName,
        [string]$ProvidedKey
    )

    # Priority 1: Key passed as parameter
    if (-not [string]::IsNullOrWhiteSpace($ProvidedKey)) {
        Write-Host '[*] Using API key provided via parameter.' -ForegroundColor Cyan
        return $ProvidedKey
    }

    # Priority 2: DPAPI-encrypted credential file
    if (Test-Path $script:CredFile) {
        try {
            $secureKey = Import-Clixml -Path $script:CredFile
            $bstr      = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
            $plainKey  = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            if (-not [string]::IsNullOrWhiteSpace($plainKey)) {
                Write-Host '[*] API key loaded from encrypted credential store.' -ForegroundColor Cyan
                return $plainKey
            }
        }
        catch {
            Write-Host '[!] Failed to read credential file — prompting for key.' -ForegroundColor Yellow
        }
    }

    # Priority 3: Legacy plaintext env var — migrate to encrypted file, then clear it
    $legacyKey = [Environment]::GetEnvironmentVariable($EnvVarName, 'User')
    if ([string]::IsNullOrWhiteSpace($legacyKey)) {
        $legacyKey = [System.Environment]::GetEnvironmentVariable($EnvVarName)
    }
    if (-not [string]::IsNullOrWhiteSpace($legacyKey)) {
        Write-Host '[*] Migrating plaintext API key to encrypted credential store...' -ForegroundColor DarkYellow
        $credDir = Split-Path $script:CredFile
        if (-not (Test-Path $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
        (ConvertTo-SecureString $legacyKey -AsPlainText -Force) | Export-Clixml -Path $script:CredFile
        [Environment]::SetEnvironmentVariable($EnvVarName, $null, 'User')
        Write-Host ('[+] Migrated to: {0}' -f $script:CredFile) -ForegroundColor Green
        Write-Host '    Plaintext registry entry cleared.' -ForegroundColor Green
        return $legacyKey
    }

    # Priority 4: Session environment variable (not persisted)
    $sessionKey = [System.Environment]::GetEnvironmentVariable($EnvVarName)
    if (-not [string]::IsNullOrWhiteSpace($sessionKey)) {
        Write-Host '[*] API key loaded from session environment (not persisted).' -ForegroundColor Cyan
        return $sessionKey
    }

    # Priority 5: Prompt the user and save to DPAPI file
    Write-Host ''
    Write-Host '+==========================================================' -ForegroundColor Yellow
    Write-Host '|  No Hatz AI API key found.                               ' -ForegroundColor Yellow
    Write-Host '|  Enter your key to save it securely for future sessions. ' -ForegroundColor Yellow
    Write-Host '|  Generate keys at: Hatz Admin Dashboard > Settings       ' -ForegroundColor Yellow
    Write-Host '+==========================================================' -ForegroundColor Yellow
    Write-Host ''

    $secureInput = Read-Host -Prompt 'Enter your Hatz AI API key' -AsSecureString
    $bstr        = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput)
    $plainKey    = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    if ([string]::IsNullOrWhiteSpace($plainKey)) {
        Write-Error 'API key cannot be empty. Exiting.'
        exit 1
    }

    $credDir = Split-Path $script:CredFile
    if (-not (Test-Path $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
    $secureInput | Export-Clixml -Path $script:CredFile
    Write-Host ('[+] API key saved (DPAPI-encrypted): {0}' -f $script:CredFile) -ForegroundColor Green
    Write-Host '    It will persist across PowerShell sessions.' -ForegroundColor Green
    Write-Host ''

    return $plainKey
}

# --- Region: API Helper Functions ---------------------------------------------

function Get-HatzModels {
    <#
    .SYNOPSIS
        Retrieves available models from /v1/chat/models.
    #>
    param(
        [string]$ApiBaseUrl,
        [string]$ApiKey,
        [string]$EnvVarName    # Passed explicitly — no implicit parent-scope capture
    )

    # Hatz API uses X-API-Key header for authentication
    $headers = @{
        'X-API-Key' = $ApiKey
    }

    try {
        # Hatz models endpoint is /v1/chat/models (not /v1/models)
        $response = Invoke-RestMethod -Uri "$ApiBaseUrl/chat/models" `
                                       -Method Get `
                                       -Headers $headers `
                                       -ErrorAction Stop

        return $response.data
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        Write-Error ('Failed to retrieve models (HTTP {0}): {1}' -f $statusCode, $_.Exception.Message)

        if ($statusCode -eq 401) {
            Write-Host ''
            Write-Host '[!] Invalid API key. Reset it by deleting the credential file and re-running:' -ForegroundColor Red
            Write-Host ('    Remove-Item "{0}"' -f $script:CredFile) -ForegroundColor Yellow
            Write-Host ''
        }
        exit 1
    }
}

function Get-HatzAgents {
    <#
    .SYNOPSIS
        Retrieves available agents from /v1/chat/agents.
    #>
    param(
        [string]$ApiBaseUrl,
        [string]$ApiKey
    )

    $headers = @{
        'X-API-Key' = $ApiKey
    }

    try {
        $response = Invoke-RestMethod -Uri "$ApiBaseUrl/chat/agents" `
                                       -Method Get `
                                       -Headers $headers `
                                       -ErrorAction Stop

        return $response.data
    }
    catch {
        # Agents endpoint may not be available; return empty array
        return @()
    }
}

function Invoke-HatzChatCompletion {
    <#
    .SYNOPSIS
        Sends a chat completion request to /v1/chat/completions.
    .PARAMETER ApiBaseUrl
        The base URL of the API.
    .PARAMETER ApiKey
        The API key for authentication (sent via X-API-Key header).
    .PARAMETER Model
        The model name or agent-{id} to use.
    .PARAMETER Messages
        Array of message objects (role + content).
    .PARAMETER Temperature
        Sampling temperature (0.0 - 2.0). Lower = more deterministic.
    .PARAMETER ToolsToUse
        Optional array of tool names to enable (e.g., google_search, tavily_search).
    .PARAMETER AutoToolSelection
        Let the API automatically select relevant tools.
    #>
    param(
        [string]$ApiBaseUrl,
        [string]$ApiKey,
        [string]$Model,
        [array]$Messages,
        [double]$Temperature = 0.7,
        [string[]]$ToolsToUse = @(),
        [bool]$AutoToolSelection = $false,
        [int]$TimeoutMs = 120000    # Override for large requests (e.g. /edit on big files)
    )

    # Build request body per Hatz API spec
    $bodyHash = @{
        model       = $Model
        messages    = $Messages
        stream      = $false
        temperature = $Temperature
    }
    if ($ToolsToUse.Count -gt 0) { $bodyHash['tools_to_use']      = $ToolsToUse }
    if ($AutoToolSelection)       { $bodyHash['auto_tool_selection'] = $true      }

    # Serialize and encode as UTF-8 bytes.
    # Using HttpWebRequest (not Invoke-RestMethod) so we own encoding on BOTH
    # send and receive — this prevents PS 5.1's broken surrogate-pair JSON escapes
    # from corrupting emoji/special chars and causing 400 errors on subsequent turns.
    $bodyJson  = $bodyHash | ConvertTo-Json -Depth 10 -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)

    $maxRetries = 2
    $retryWait  = 3   # seconds; doubles each attempt (3 → 6)

    for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
        try {
            $req               = [System.Net.HttpWebRequest]::Create("$ApiBaseUrl/chat/completions")
            $req.Method        = 'POST'
            $req.ContentType   = 'application/json; charset=utf-8'
            $req.ContentLength = $bodyBytes.Length
            $req.Timeout       = $TimeoutMs
            $req.Headers.Add('X-API-Key', $ApiKey)

            $reqStream = $req.GetRequestStream()
            $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
            $reqStream.Close()

            $resp     = $req.GetResponse()
            $reader   = [System.IO.StreamReader]::new($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $jsonText = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()

            return ($jsonText | ConvertFrom-Json)
        }
        catch [System.Net.WebException] {
            $statusCode = $null
            $errorBody  = ''
            $isTimeout  = $_.Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout

            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                try {
                    $errReader = [System.IO.StreamReader]::new(
                        $_.Exception.Response.GetResponseStream(),
                        [System.Text.Encoding]::UTF8)
                    $errorBody = $errReader.ReadToEnd()
                    $errReader.Close()
                }
                catch { }
            }

            # Retry only on transient failures: 5xx server errors or request timeout
            $isTransient = $isTimeout -or ($null -ne $statusCode -and $statusCode -ge 500)
            if ($isTransient -and $attempt -lt $maxRetries) {
                $wait    = $retryWait * [math]::Pow(2, $attempt)   # 3s, 6s
                $errDesc = if ($isTimeout) { 'timeout' } else { "HTTP $statusCode" }
                Write-Host ('[~] Transient error ({0}), retrying in {1}s... ({2}/{3})' -f $errDesc, $wait, ($attempt + 1), $maxRetries) -ForegroundColor DarkYellow
                Start-Sleep -Seconds $wait
                continue
            }

            # Non-retryable or out of retries — surface the error
            Write-Host ''
            Write-Host ('[!] API Error (HTTP {0})' -f $statusCode) -ForegroundColor Red
            if ($errorBody) {
                Write-Host ('    {0}' -f $errorBody) -ForegroundColor DarkRed
            }
            else {
                Write-Host ('    {0}' -f $_.Exception.Message) -ForegroundColor DarkRed
            }
            Write-Host ''
            return $null
        }
    }
    return $null   # exhausted retries without returning
}

# --- Region: File Helpers -----------------------------------------------------

function Test-IsBinaryFile {
    <#
    .SYNOPSIS
        Returns $true when a file should not be injected as text context.
        Fast path: extension allow-list. Fallback: null-byte sniff on first 512 bytes.
    #>
    param([string]$Path)

    $binaryExt = @(
        '.exe','.dll','.pdb','.lib','.obj','.o','.a','.so','.dylib',
        '.zip','.gz','.tar','.rar','.7z','.bz2','.xz','.cab','.msi','.nupkg','.whl',
        '.iso','.img',
        '.jpg','.jpeg','.png','.gif','.bmp','.ico','.tiff','.webp',
        '.mp3','.mp4','.avi','.mov','.wav','.flac','.ogg','.mkv','.wmv',
        '.pdf','.docx','.xlsx','.pptx','.doc','.xls','.ppt','.odt','.ods',
        '.db','.sqlite','.mdb','.accdb',
        '.pyc','.pyo','.class',
        '.lnk','.bin','.dat','.pfx','.cer','.key'
    )

    $ext = [System.IO.Path]::GetExtension($Path).ToLower()
    if ($binaryExt -contains $ext) { return $true }

    # Null-byte sniff (catches unlisted binaries)
    try {
        $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $buf    = New-Object byte[] 512
        $read   = $stream.Read($buf, 0, 512)
        $stream.Close()
        for ($i = 0; $i -lt $read; $i++) { if ($buf[$i] -eq 0) { return $true } }
    }
    catch { return $true }   # unreadable → treat as binary

    return $false
}

function Show-LineDiff {
    <#
    .SYNOPSIS
        Displays a line-by-line positional diff with line numbers.
        Returns $true if any differences were found.
    .NOTES
        Uses a direct index-for-index comparison so insertions/deletions are
        visible at the correct line (unlike Compare-Object's set-based mode).
    #>
    param(
        [string]$Original,
        [string]$Updated
    )
    $origLines  = $Original -split "`r?`n"
    $newLines   = $Updated  -split "`r?`n"
    $maxLen     = [Math]::Max($origLines.Count, $newLines.Count)
    $hasChanges = $false

    for ($i = 0; $i -lt $maxLen; $i++) {
        $o = if ($i -lt $origLines.Count) { $origLines[$i] } else { $null }
        $n = if ($i -lt $newLines.Count)  { $newLines[$i]  } else { $null }
        if ($o -ne $n) {
            $hasChanges = $true
            if ($null -ne $o) { Write-Host ('-L{0,4}: {1}' -f ($i + 1), $o) -ForegroundColor Red   }
            if ($null -ne $n) { Write-Host ('+L{0,4}: {1}' -f ($i + 1), $n) -ForegroundColor Green }
        }
    }
    return $hasChanges
}

# --- Region: Model Selection --------------------------------------------------

function Select-HatzModel {
    <#
    .SYNOPSIS
        Displays available models/agents and prompts the user to select one.
    #>
    param(
        [array]$Models,
        [array]$Agents
    )

    if ((-not $Models -or $Models.Count -eq 0) -and (-not $Agents -or $Agents.Count -eq 0)) {
        Write-Error 'No models or agents available from the API.'
        exit 1
    }

    # Sort models alphabetically by name
    $sortedModels = @()
    if ($Models -and $Models.Count -gt 0) {
        $sortedModels = @($Models | Sort-Object -Property name)
    }

    # Build combined selection list: models first, then agents
    $selectionList = [System.Collections.ArrayList]::new()

    foreach ($m in $sortedModels) {
        [void]$selectionList.Add(@{
            DisplayName = ('{0} ({1})' -f $m.display_name, $m.developer)
            ModelId     = $m.name
            Type        = 'Model'
        })
    }

    if ($Agents -and $Agents.Count -gt 0) {
        foreach ($a in $Agents) {
            [void]$selectionList.Add(@{
                DisplayName = ('{0} (Agent)' -f $a.name)
                ModelId     = ('agent-{0}' -f $a.id)
                Type        = 'Agent'
            })
        }
    }

    Write-Host ''
    Write-Host '+==========================================================' -ForegroundColor Cyan
    Write-Host '|  Available Models                                        ' -ForegroundColor Cyan
    Write-Host '+==========================================================' -ForegroundColor Cyan

    # Pattern used to flag image generation models (web-only via Hatz API)
    $imgModelPattern = '(?i)(image|imgen|dall.?e|imagen|flux|stable.diffusion)'

    for ($i = 0; $i -lt $selectionList.Count; $i++) {
        $num     = ($i + 1).ToString().PadLeft(3)
        $display = $selectionList[$i].DisplayName
        if ($display.Length -gt 54) { $display = $display.Substring(0, 51) + '...' }
        $isImg = $selectionList[$i].ModelId -match $imgModelPattern
        $tag   = if ($isImg) { ' [web only]' } else { '' }
        $color = if ($isImg) { 'DarkYellow'  } else { 'Cyan' }
        Write-Host ('|  {0}. {1}{2}' -f $num, $display, $tag) -ForegroundColor $color
    }

    Write-Host '+==========================================================' -ForegroundColor Cyan
    Write-Host '   [web only] = image generation (not returned via API)    ' -ForegroundColor DarkGray
    Write-Host ''

    while ($true) {
        $selection  = Read-Host -Prompt ('Select a model (1-{0}) or type a model name' -f $selectionList.Count)
        $chosenItem = $null

        # Match by model ID string
        $matchedItem = $selectionList | Where-Object { $_.ModelId -eq $selection }
        if ($matchedItem) {
            if ($matchedItem -is [array]) { $matchedItem = $matchedItem[0] }
            $chosenItem = $matchedItem
        }

        # Match by numeric index
        $parsed = 0
        if (-not $chosenItem -and [int]::TryParse($selection, [ref]$parsed)) {
            $index = $parsed - 1
            if ($index -ge 0 -and $index -lt $selectionList.Count) {
                $chosenItem = $selectionList[$index]
            }
        }

        if ($chosenItem) {
            Write-Host ('[*] Selected: {0}' -f $chosenItem.DisplayName) -ForegroundColor Green
            if ($chosenItem.ModelId -match $imgModelPattern) {
                Write-Host ''
                Write-Host '  [!] Image generation models are not supported via the Hatz API.' -ForegroundColor DarkYellow
                Write-Host '      Images are generated but only viewable in the Hatz web UI —' -ForegroundColor DarkYellow
                Write-Host '      the API does not return URLs or image data.' -ForegroundColor DarkYellow
                Write-Host ''
            }
            return $chosenItem.ModelId
        }

        Write-Host ('[!] Invalid selection. Enter a number 1-{0} or a model name.' -f $selectionList.Count) -ForegroundColor Yellow
    }
}

# --- Region: Chat Session -----------------------------------------------------

function Start-HatzChat {
    <#
    .SYNOPSIS
        Runs an interactive multi-turn chat session with conversation history.
    #>
    param(
        [string]$ApiBaseUrl,
        [string]$ApiKey,
        [string]$Model,
        [int]$MaxHistory = 40    # Max non-system messages before sliding window trims oldest
    )

    $modelDisplay = $Model
    if ($modelDisplay.Length -gt 48) {
        $modelDisplay = $modelDisplay.Substring(0, 45) + '...'
    }

    Write-Host ''
    Write-Host '+==========================================================' -ForegroundColor Green
    Write-Host '|  Hatz AI Chat Session                                    ' -ForegroundColor Green
    Write-Host ('|  Model    : {0}' -f $modelDisplay) -ForegroundColor Green
    Write-Host '|  Autotools: ON  (use /autotools to toggle)               ' -ForegroundColor Green
    $histNote = if ($MaxHistory -gt 0) { 'last {0} messages' -f $MaxHistory } else { 'unlimited' }
    Write-Host ('|  History  : {0,-43}|' -f $histNote) -ForegroundColor Green
    Write-Host '+==========================================================' -ForegroundColor Green
    Write-Host '|  Commands:                                               ' -ForegroundColor Green
    Write-Host '|    /quit       - Exit the chat                           ' -ForegroundColor Green
    Write-Host '|    /clear      - Clear conversation history              ' -ForegroundColor Green
    Write-Host '|    /model      - Switch to a different model             ' -ForegroundColor Green
    Write-Host '|    /system     - Set a system prompt                     ' -ForegroundColor Green
    Write-Host '|    /history    - Show conversation message count         ' -ForegroundColor Green
    Write-Host '|    /tools      - Toggle tools (search, code, etc.)       ' -ForegroundColor Green
    Write-Host '|    /autotools  - Toggle auto tool selection              ' -ForegroundColor Green
    Write-Host '|  Local folder commands:                                  ' -ForegroundColor Green
    Write-Host '|    /file <path>      - Inject file into next message     ' -ForegroundColor Green
    Write-Host '|    /folder <path>    - Inject folder tree / files        ' -ForegroundColor Green
    Write-Host '|    /run <cmd>        - Run command, inject output        ' -ForegroundColor Green
    Write-Host '|    /edit <path>      - Ask model to edit a file          ' -ForegroundColor Green
    Write-Host '|    /workspace <path> - Set base folder for rel. paths    ' -ForegroundColor Green
    Write-Host '|    /context          - Show pending context size         ' -ForegroundColor Green
    Write-Host '|    /help             - Show these commands               ' -ForegroundColor Green
    Write-Host '+==========================================================' -ForegroundColor Green
    Write-Host ''

    # Initialize state
    $conversationHistory = [System.Collections.ArrayList]::new()
    $currentModel        = $Model
    $toolsToUse          = @()
    $autoToolSelection   = $true    # ON by default
    $pendingContext      = ''       # Accumulated file/folder/run output injected into next message
    $workspacePath       = ''       # Base folder for resolving relative paths
    $totalInputTokens    = 0        # Running session totals for budget visibility
    $totalOutputTokens   = 0

    # Main chat loop
    while ($true) {
        Write-Host 'You: ' -ForegroundColor Yellow -NoNewline
        $userInput = Read-Host

        # Skip empty input
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            continue
        }

        $trimmedInput = $userInput.Trim()

        # -- Slash commands --
        if ($trimmedInput -eq '/quit') {
            Write-Host ''
            Write-Host '[*] Chat session ended.' -ForegroundColor Cyan
            return
        }
        elseif ($trimmedInput -eq '/clear') {
            $conversationHistory.Clear()
            $pendingContext = ''
            Write-Host '[*] Conversation history and pending context cleared.' -ForegroundColor Cyan
            Write-Host ''
            continue
        }
        elseif ($trimmedInput -eq '/model') {
            Write-Host '[*] Fetching available models...' -ForegroundColor Cyan
            $models = Get-HatzModels -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey
            $agents = Get-HatzAgents -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey
            $currentModel = Select-HatzModel -Models $models -Agents $agents
            Write-Host ('[*] Switched to: {0}' -f $currentModel) -ForegroundColor Green
            Write-Host ''
            continue
        }
        elseif ($trimmedInput -match '^/system\s*(.*)$') {
            $sysPrompt = $Matches[1]
            if ([string]::IsNullOrWhiteSpace($sysPrompt)) {
                $sysPrompt = Read-Host -Prompt 'Enter system prompt'
            }
            $toRemove = @($conversationHistory | Where-Object { $_.role -eq 'system' })
            foreach ($msg in $toRemove) { $conversationHistory.Remove($msg) }
            $conversationHistory.Insert(0, @{ role = 'system'; content = $sysPrompt })
            Write-Host '[*] System prompt set.' -ForegroundColor Cyan
            Write-Host ''
            continue
        }
        elseif ($trimmedInput -eq '/history') {
            $userMsgCount = @($conversationHistory | Where-Object { $_.role -eq 'user' }).Count
            $asstMsgCount = @($conversationHistory | Where-Object { $_.role -eq 'assistant' }).Count
            $sysMsgCount  = @($conversationHistory | Where-Object { $_.role -eq 'system' }).Count
            $limitNote    = if ($MaxHistory -gt 0) { " (window: $MaxHistory)" } else { ' (unlimited)' }
            Write-Host ('[*] History: {0} system, {1} user, {2} assistant{3}.' -f $sysMsgCount, $userMsgCount, $asstMsgCount, $limitNote) -ForegroundColor Cyan
            if ($totalInputTokens -gt 0) {
                Write-Host ('    Session tokens used: {0:N0} in, {1:N0} out.' -f $totalInputTokens, $totalOutputTokens) -ForegroundColor DarkGray
            }
            Write-Host ''
            continue
        }
        elseif ($trimmedInput -eq '/tools') {
            Write-Host ''
            Write-Host 'Available tools (comma-separated to enable, or "none" to clear):' -ForegroundColor Cyan
            Write-Host '  Search : google_search, firecrawl_search, firecrawl_scrape' -ForegroundColor Gray
            Write-Host '           firecrawl_extract, tavily_search, tavily_qna' -ForegroundColor Gray
            Write-Host '           exa_search, exa_answer, perplexity_search, perplexity_ask' -ForegroundColor Gray
            Write-Host '  Code   : daytona_code_execution' -ForegroundColor Gray
            Write-Host '  Maps   : google_maps_text_search, google_maps_directions' -ForegroundColor Gray
            Write-Host '  Weather: google_weather_current, google_weather_forecast' -ForegroundColor Gray
            Write-Host ''
            if ($toolsToUse.Count -gt 0) {
                Write-Host ('  Currently enabled: {0}' -f ($toolsToUse -join ', ')) -ForegroundColor DarkCyan
            }
            else {
                Write-Host '  Currently enabled: none' -ForegroundColor DarkCyan
            }
            Write-Host ''
            $toolInput = Read-Host -Prompt 'Enter tool names (comma-separated) or "none"'
            if ($toolInput.Trim().ToLower() -eq 'none') {
                $toolsToUse = @()
                Write-Host '[*] Tools cleared.' -ForegroundColor Cyan
            }
            else {
                $toolsToUse = @($toolInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                Write-Host ('[*] Tools enabled: {0}' -f ($toolsToUse -join ', ')) -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }
        elseif ($trimmedInput -eq '/autotools') {
            $autoToolSelection = -not $autoToolSelection
            if ($autoToolSelection) {
                Write-Host '[*] Auto tool selection: ON' -ForegroundColor Cyan
            }
            else {
                Write-Host '[*] Auto tool selection: OFF' -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }
        # -- /workspace <path> --
        elseif ($trimmedInput -match '^/workspace(?:\s+(.+))?$') {
            if ($Matches[1]) {
                $wsCandidate = $Matches[1].Trim().Trim('"')
                if (Test-Path $wsCandidate -PathType Container) {
                    $workspacePath = $wsCandidate
                    Write-Host ('[*] Workspace set to: {0}' -f $workspacePath) -ForegroundColor Cyan
                }
                else {
                    Write-Host ('[!] Path not found: {0}' -f $wsCandidate) -ForegroundColor Red
                }
            }
            else {
                $wsDisplay = if ($workspacePath) { $workspacePath } else { '(none)' }
                Write-Host ('[*] Current workspace: {0}' -f $wsDisplay) -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }

        # -- /file <path> --
        elseif ($trimmedInput -match '^/file\s+(.+)$') {
            $rawPath = $Matches[1].Trim().Trim('"')
            $resolvedFile = if ($workspacePath -and -not [System.IO.Path]::IsPathRooted($rawPath)) {
                Join-Path $workspacePath $rawPath
            } else { $rawPath }

            if (Test-Path $resolvedFile -PathType Leaf) {
                if (Test-IsBinaryFile -Path $resolvedFile) {
                    Write-Host ('[!] Binary file detected: {0}' -f $resolvedFile) -ForegroundColor DarkYellow
                    Write-Host '    Injecting binary content will corrupt context. Skip? (y/n)' -ForegroundColor DarkGray
                    if ((Read-Host -Prompt 'Skip').Trim().ToLower() -ne 'n') {
                        Write-Host '[*] Skipped.' -ForegroundColor Cyan
                        Write-Host ''
                        continue
                    }
                }
                $fileContent = Get-Content $resolvedFile -Raw -Encoding UTF8
                $ext = [System.IO.Path]::GetExtension($resolvedFile).TrimStart('.')
                $lineCount = ($fileContent -split "`n").Count
                $pendingContext += "`n`n[File: $resolvedFile]`n``````$ext`n$fileContent`n```````n"
                Write-Host ('[*] Injected: {0} ({1} bytes, {2} lines)' -f $resolvedFile, $fileContent.Length, $lineCount) -ForegroundColor Cyan
            }
            else {
                Write-Host ('[!] File not found: {0}' -f $resolvedFile) -ForegroundColor Red
            }
            Write-Host ''
            continue
        }

        # -- /folder <path> --
        elseif ($trimmedInput -match '^/folder(?:\s+(.+))?$') {
            $rawFolder = if ($Matches[1]) { $Matches[1].Trim().Trim('"') } else { '.' }
            $resolvedFolder = if ($workspacePath -and -not [System.IO.Path]::IsPathRooted($rawFolder)) {
                Join-Path $workspacePath $rawFolder
            } else { $rawFolder }

            if (Test-Path $resolvedFolder -PathType Container) {
                $folderFiles = @(Get-ChildItem $resolvedFolder -File -Recurse | Sort-Object FullName)
                Write-Host ('+-- Folder: {0} ({1} files) --' -f $resolvedFolder, $folderFiles.Count) -ForegroundColor Cyan
                for ($fi = 0; $fi -lt $folderFiles.Count; $fi++) {
                    $rel    = $folderFiles[$fi].FullName.Substring($resolvedFolder.Length).TrimStart('\', '/')
                    $binTag = if (Test-IsBinaryFile -Path $folderFiles[$fi].FullName) { ' [binary]' } else { '' }
                    Write-Host ('  {0,3}. {1} ({2} bytes){3}' -f ($fi + 1), $rel, $folderFiles[$fi].Length, $binTag) -ForegroundColor DarkCyan
                }
                Write-Host ''
                Write-Host '"all" to read all files, comma-separated numbers (e.g. 1,3) to select, or Enter for tree only' -ForegroundColor Gray
                $folderChoice = (Read-Host -Prompt 'Select').Trim()

                # Always inject the tree
                $treeLines = $folderFiles | ForEach-Object {
                    '  ' + $_.FullName.Substring($resolvedFolder.Length).TrimStart('\', '/')
                }
                $pendingContext += "`n`n[Folder tree: $resolvedFolder]`n``````text`n$($treeLines -join "`n")`n```````n"

                if ($folderChoice.ToLower() -eq 'all') {
                    $injected = 0; $skipped = 0
                    foreach ($ff in $folderFiles) {
                        if (Test-IsBinaryFile -Path $ff.FullName) { $skipped++; continue }
                        $fc = Get-Content $ff.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($fc) {
                            $fext = $ff.Extension.TrimStart('.')
                            $frel = $ff.FullName.Substring($resolvedFolder.Length).TrimStart('\', '/')
                            $pendingContext += "`n[File: $frel]`n``````$fext`n$fc`n```````n"
                            $injected++
                        }
                    }
                    $skipNote = if ($skipped -gt 0) { ", $skipped binary skipped" } else { '' }
                    Write-Host ('[*] Injected tree + {0} text file(s){1}.' -f $injected, $skipNote) -ForegroundColor Cyan
                }
                elseif ($folderChoice -ne '') {
                    $picks = $folderChoice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
                    $pickCount = 0
                    foreach ($p in $picks) {
                        $pidx = [int]$p - 1
                        if ($pidx -ge 0 -and $pidx -lt $folderFiles.Count) {
                            $ff = $folderFiles[$pidx]
                            if (Test-IsBinaryFile -Path $ff.FullName) {
                                Write-Host ('  [!] {0} is binary — skipped.' -f $ff.Name) -ForegroundColor DarkYellow
                                continue
                            }
                            $fc = Get-Content $ff.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                            if ($fc) {
                                $fext = $ff.Extension.TrimStart('.')
                                $frel = $ff.FullName.Substring($resolvedFolder.Length).TrimStart('\', '/')
                                $pendingContext += "`n[File: $frel]`n``````$fext`n$fc`n```````n"
                                $pickCount++
                            }
                        }
                    }
                    Write-Host ('[*] Injected tree + {0} selected file(s).' -f $pickCount) -ForegroundColor Cyan
                }
                else {
                    Write-Host '[*] Injected folder tree only.' -ForegroundColor Cyan
                }
            }
            else {
                Write-Host ('[!] Folder not found: {0}' -f $resolvedFolder) -ForegroundColor Red
            }
            Write-Host ''
            continue
        }

        # -- /run <command> --
        elseif ($trimmedInput -match '^/run\s+(.+)$') {
            $cmdToRun = $Matches[1].Trim()

            # Guard against obviously destructive operations — require explicit "yes"
            $destructivePattern = '(?i)(\bRemove-Item\b|\bri\b\s|\brm\b\s|\bdel\b\s|\brd\b\s|\brmdir\b|' +
                                  '\bClear-Content\b|\bClear-Item\b|\bFormat-Volume\b|\bFormat-Disk\b|' +
                                  '\bStop-Process\b|\bkill\b\s|\bStop-Service\b|\bnet\s+stop\b|' +
                                  '\bRemove-Service\b|\bClear-RecycleBin\b|\bReset-\w+)'
            if ($cmdToRun -match $destructivePattern) {
                Write-Host ''
                Write-Host '[!] Potentially destructive command:' -ForegroundColor Red
                Write-Host ('    {0}' -f $cmdToRun) -ForegroundColor Red
                Write-Host ''
                $confirm = (Read-Host -Prompt 'Type "yes" to execute, anything else to cancel').Trim()
                if ($confirm -ne 'yes') {
                    Write-Host '[*] Cancelled.' -ForegroundColor Cyan
                    Write-Host ''
                    continue
                }
            }

            Write-Host ('[>] Running: {0}' -f $cmdToRun) -ForegroundColor DarkYellow
            try {
                $runOutput = Invoke-Expression $cmdToRun 2>&1 | Out-String
                Write-Host $runOutput -ForegroundColor DarkGray
                $pendingContext += ("`n`n[Command: {0}]`n``````text`n{1}``````" -f $cmdToRun, $runOutput)
                Write-Host '[*] Command output injected into context.' -ForegroundColor Cyan
            }
            catch {
                Write-Host ('[!] Error: {0}' -f $_) -ForegroundColor Red
            }
            Write-Host ''
            continue
        }

        # -- /context --
        elseif ($trimmedInput -eq '/context') {
            if ($pendingContext) {
                $ctxLines = ($pendingContext -split "`n").Count
                Write-Host ('[*] Pending context: {0} chars, {1} lines — will be prepended to your next message.' -f $pendingContext.Length, $ctxLines) -ForegroundColor Cyan
                Write-Host '    Use /clear to also discard pending context.' -ForegroundColor DarkGray
            }
            else {
                Write-Host '[*] No pending context.' -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }

        # -- /edit <path> --
        elseif ($trimmedInput -match '^/edit\s+(.+)$') {
            $rawEditPath = $Matches[1].Trim().Trim('"')
            $resolvedEdit = if ($workspacePath -and -not [System.IO.Path]::IsPathRooted($rawEditPath)) {
                Join-Path $workspacePath $rawEditPath
            } else { $rawEditPath }

            if (-not (Test-Path $resolvedEdit -PathType Leaf)) {
                Write-Host ('[!] File not found: {0}' -f $resolvedEdit) -ForegroundColor Red
                Write-Host ''
                continue
            }

            $origContent  = Get-Content $resolvedEdit -Raw -Encoding UTF8
            $editExt      = [System.IO.Path]::GetExtension($resolvedEdit).TrimStart('.')
            $editLineCount = ($origContent -split "`r?`n").Count
            Write-Host ('[*] Edit: {0}  ({1} lines)' -f $resolvedEdit, $editLineCount) -ForegroundColor Cyan
            if ($editLineCount -gt 300) {
                Write-Host ('  [!] Large file ({0} lines). The model must regenerate the entire file.' -f $editLineCount) -ForegroundColor DarkYellow
                Write-Host '      Consider targeting a specific function or section with a narrower' -ForegroundColor DarkYellow
                Write-Host '      instruction (e.g. "in function Foo, change X to Y").' -ForegroundColor DarkYellow
                Write-Host '      Proceeding with a 5-minute timeout...' -ForegroundColor DarkGray
            }
            $editInstruction = (Read-Host -Prompt 'Describe the change').Trim()
            if ([string]::IsNullOrWhiteSpace($editInstruction)) {
                Write-Host '[!] No instruction given — cancelled.' -ForegroundColor Yellow
                Write-Host ''
                continue
            }

            $editPrompt = @"
File: $resolvedEdit
``````$editExt
$origContent
``````

Instruction: $editInstruction

Reply with ONLY the complete updated file inside a single code block. No explanation before or after.
"@
            # Do NOT include conversation history — sending history + a large file
            # causes KeepAliveFailure because the payload becomes too large.
            $editMsgs = @(@{ role = 'user'; content = $editPrompt })
            Write-Host '[*] Requesting edit from model...' -ForegroundColor Cyan
            $editResp = Invoke-HatzChatCompletion -ApiBaseUrl $ApiBaseUrl `
                                                   -ApiKey $ApiKey `
                                                   -Model $currentModel `
                                                   -Messages $editMsgs `
                                                   -Temperature 0.2 `
                                                   -TimeoutMs 300000

            if ($null -eq $editResp) {
                Write-Host '[!] Edit request failed.' -ForegroundColor Red
                Write-Host ''
                continue
            }

            $rawReply = $editResp.choices[0].message.content

            # Pick the *largest* code block — handles responses where the model
            # thinks aloud before the final code fence, or has nested fences.
            $codeMatches = [regex]::Matches($rawReply, '(?s)```[^\n]*\n(.*?)```')
            if ($codeMatches.Count -gt 0) {
                $best       = $codeMatches |
                                Sort-Object { $_.Groups[1].Value.Length } -Descending |
                                Select-Object -First 1
                $newContent = $best.Groups[1].Value
            } else {
                $newContent = $rawReply
            }

            # Show diff with actual line numbers (positional, not set-based)
            Write-Host ''
            Write-Host '+-- Proposed diff (- original  + new) -------------------------' -ForegroundColor Yellow
            $hasChanges = Show-LineDiff -Original $origContent -Updated $newContent
            if (-not $hasChanges) {
                Write-Host '  (No changes detected)' -ForegroundColor DarkGray
            }
            Write-Host '+--------------------------------------------------------------' -ForegroundColor Yellow
            Write-Host ''

            $applyChoice = (Read-Host -Prompt 'Apply changes? (y/n)').Trim().ToLower()
            if ($applyChoice -eq 'y') {
                [System.IO.File]::WriteAllText($resolvedEdit, $newContent, [System.Text.Encoding]::UTF8)
                Write-Host ('[+] Saved: {0}' -f $resolvedEdit) -ForegroundColor Green
                # Add the exchange to history so context carries forward
                [void]$conversationHistory.Add(@{ role = 'user';      content = $editPrompt })
                [void]$conversationHistory.Add(@{ role = 'assistant'; content = $rawReply   })
            } else {
                Write-Host '[*] Edit cancelled.' -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }

        elseif ($trimmedInput -eq '/help') {
            Write-Host '  /quit             - Exit the chat' -ForegroundColor Gray
            Write-Host '  /clear            - Clear conversation history' -ForegroundColor Gray
            Write-Host '  /model            - Switch to a different model' -ForegroundColor Gray
            Write-Host '  /system           - Set a system prompt' -ForegroundColor Gray
            Write-Host '  /history          - Show conversation message count' -ForegroundColor Gray
            Write-Host '  /tools            - Toggle tools (search, code, etc.)' -ForegroundColor Gray
            Write-Host '  /autotools        - Toggle auto tool selection' -ForegroundColor Gray
            Write-Host '  Local folder:' -ForegroundColor Gray
            Write-Host '  /file <path>      - Inject file content into next message' -ForegroundColor Gray
            Write-Host '  /folder <path>    - Inject folder tree and/or files' -ForegroundColor Gray
            Write-Host '  /run <cmd>        - Run a command, inject output into context' -ForegroundColor Gray
            Write-Host '  /edit <path>      - Model edits a local file (shows diff, confirms)' -ForegroundColor Gray
            Write-Host '  /workspace <path> - Set base folder for relative paths' -ForegroundColor Gray
            Write-Host '  /context          - Show pending context size' -ForegroundColor Gray
            Write-Host '  /help             - Show these commands' -ForegroundColor Gray
            Write-Host ''
            continue
        }

        # -- Append user message to history (prepend any pending context) --
        $finalContent = if ($pendingContext) {
            $pendingContext.TrimStart() + "`n`n" + $userInput
        } else {
            $userInput
        }
        $pendingContext = ''
        [void]$conversationHistory.Add(@{
            role    = 'user'
            content = $finalContent
        })

        # -- Send request to API --
        # Image generation models don't support temperature, tools, or conversation history.
        # Sending those params can cause the upstream provider to reject the request.
        $isImageModel = $currentModel -match '(?i)(image|imgen|dall.?e|imagen|flux|stable.diffusion)'
        if ($isImageModel) {
            # Image models: send only the latest user message — no history, no tools
            $imageMsgs = @(@{ role = 'user'; content = $finalContent })
            $response  = Invoke-HatzChatCompletion -ApiBaseUrl $ApiBaseUrl `
                                                   -ApiKey $ApiKey `
                                                   -Model $currentModel `
                                                   -Messages $imageMsgs `
                                                   -Temperature 1.0 `
                                                   -AutoToolSelection $false
        } else {
            $isImageModel = $false
            $response = Invoke-HatzChatCompletion -ApiBaseUrl $ApiBaseUrl `
                                                   -ApiKey $ApiKey `
                                                   -Model $currentModel `
                                                   -Messages $conversationHistory.ToArray() `
                                                   -Temperature 0.7 `
                                                   -ToolsToUse $toolsToUse `
                                                   -AutoToolSelection $autoToolSelection
        }

        if ($null -eq $response) {
            # Remove failed message so it can be retried
            $conversationHistory.RemoveAt($conversationHistory.Count - 1)
            Write-Host '[!] Request failed. Your message was not added to history.' -ForegroundColor Yellow
            Write-Host ''
            continue
        }

        # -- Extract and display the assistant reply --
        # content can be a plain string (chat) or an array of parts (image models
        # may use [{type:"image_url",image_url:{url:"..."}}, {type:"text",...}]).
        $rawContent = $response.choices[0].message.content
        if ($rawContent -is [string]) {
            $assistantMessage = $rawContent
        } elseif ($rawContent -is [System.Array]) {
            # Multi-part content — join text parts, collect image URLs
            $textParts  = @($rawContent | Where-Object { $_.type -eq 'text' }  | ForEach-Object { $_.text })
            $imageParts = @($rawContent | Where-Object { $_.type -eq 'image_url' } | ForEach-Object { $_.image_url.url })
            $assistantMessage = ($textParts -join "`n").Trim()
            if ($imageParts.Count -gt 0) {
                $assistantMessage += ("`n[image_url] " + ($imageParts -join "`n[image_url] "))
            }
        } else {
            $assistantMessage = [string]$rawContent
        }

        Write-Host ''
        Write-Host 'Assistant:' -ForegroundColor Green
        Write-Host $assistantMessage
        Write-Host ''

        # For image models: scan the ENTIRE response JSON for URLs (the image URL may
        # live outside choices[0].message.content — e.g. in tool_calls, data, etc.)
        if ($isImageModel) {
            $fullJson = $response | ConvertTo-Json -Depth 15 -Compress

            # Find every https URL in the whole JSON blob (strips trailing JSON punctuation)
            $urlMatches = [regex]::Matches($fullJson, 'https?://[^\s"\\>]+') |
                            Select-Object -ExpandProperty Value |
                            Sort-Object -Unique
            if ($urlMatches.Count -gt 0) {
                Write-Host '  [image URLs found in response]' -ForegroundColor Cyan
                foreach ($u in $urlMatches) { Write-Host ('    {0}' -f $u) -ForegroundColor DarkCyan }
                $openChoice = (Read-Host -Prompt '  Open in browser? (y/n)').Trim().ToLower()
                if ($openChoice -eq 'y') { foreach ($u in $urlMatches) { Start-Process $u } }
                Write-Host ''
            } elseif ($assistantMessage -eq 'Task completed successfully.' -and
                      $response.usage.output_tokens -eq 0) {
                # Hatz ran the image model but is not returning the result via the API.
                # The generated image is only viewable in the Hatz web UI.
                Write-Host '  [!] Image was generated but Hatz did not return a URL.' -ForegroundColor DarkYellow
                Write-Host '      The result is only accessible through the Hatz web UI.' -ForegroundColor DarkYellow
                Write-Host '      This is a known Hatz API limitation for image models.' -ForegroundColor DarkGray
                Write-Host ''
            } else {
                Write-Host '  [!] No image URL found in response. Check the debug file above.' -ForegroundColor Yellow
                Write-Host ''
            }
        }

        # -- Append assistant reply to history --
        [void]$conversationHistory.Add(@{
            role    = 'assistant'
            content = $assistantMessage
        })

        # -- Token tracking and budget warning --
        if ($response.usage) {
            $inputTok           = $response.usage.input_tokens
            $outputTok          = $response.usage.output_tokens
            $totalInputTokens  += $inputTok
            $totalOutputTokens += $outputTok
            Write-Host ('  [tokens: in={0:N0} out={1:N0} | session: in={2:N0} out={3:N0}]' -f `
                $inputTok, $outputTok, $totalInputTokens, $totalOutputTokens) -ForegroundColor DarkGray
            # Warn when the context window is getting large
            if ($inputTok -gt 150000) {
                Write-Host ('  [!] Large context ({0:N0} tokens). Consider /clear to free space.' -f $inputTok) -ForegroundColor DarkYellow
            }
            Write-Host ''
        }

        # -- Sliding window: drop oldest user/assistant pairs when over MaxHistory --
        if ($MaxHistory -gt 0) {
            $nonSysMsgs = @($conversationHistory | Where-Object { $_.role -ne 'system' })
            if ($nonSysMsgs.Count -gt $MaxHistory) {
                $sysMsgs = @($conversationHistory | Where-Object { $_.role -eq 'system' })
                $keep    = $nonSysMsgs | Select-Object -Last $MaxHistory
                $conversationHistory.Clear()
                foreach ($s in $sysMsgs) { [void]$conversationHistory.Add($s) }
                foreach ($m in $keep)    { [void]$conversationHistory.Add($m) }
                Write-Host ('  [~] History trimmed to last {0} messages.' -f $MaxHistory) -ForegroundColor DarkGray
            }
        }
    }
}

# --- Region: Main Execution ---------------------------------------------------

# Banner - Yeyland Wutani (matches branding across all YW scripts)
$ywLogo = @(
    "  __   _______   ___      _    _  _ ___   __      ___   _ _____ _   _  _ ___ "
    "  \ \ / / __\ \ / / |    /_\  | \| |   \  \ \    / / | | |_   _/_\ | \| |_ _|"
    "   \ V /| _| \ V /| |__ / _ \ | .`` | |) |  \ \/\/ /| |_| | | |/ _ \| .`` || | "
    "    |_| |___| |_| |____/_/ \_\|_|\_|___/    \_/\_/  \___/  |_/_/ \_\_|\_|___|"
)
$ywTagline = "B U I L D I N G   B E T T E R   S Y S T E M S"
$ywBorder  = "=" * 81
Write-Host ''
Write-Host $ywBorder -ForegroundColor Gray
foreach ($line in $ywLogo) { Write-Host $line -ForegroundColor DarkYellow }
Write-Host ''
Write-Host $ywTagline.PadLeft(62) -ForegroundColor Gray
Write-Host $ywBorder -ForegroundColor Gray
Write-Host '  Hatz AI Chat Interface  |  v2.0' -ForegroundColor DarkGray
Write-Host ''

# Step 1: Retrieve or set the API key
$resolvedKey = Get-HatzApiKey -EnvVarName $EnvVarName -ProvidedKey $ApiKey

# Step 2: Fetch available models and agents
Write-Host ('[*] Connecting to {0} ...' -f $ApiBaseUrl) -ForegroundColor Cyan
$models = Get-HatzModels -ApiBaseUrl $ApiBaseUrl -ApiKey $resolvedKey -EnvVarName $EnvVarName
$agents = Get-HatzAgents -ApiBaseUrl $ApiBaseUrl -ApiKey $resolvedKey

$totalCount = 0
if ($models) { $totalCount += $models.Count }
if ($agents) { $totalCount += $agents.Count }
Write-Host ('[+] Connected. Found {0} model(s) and {1} agent(s).' -f $models.Count, $agents.Count) -ForegroundColor Green

# Step 3: Auto-select default model, or prompt if not found
$defaultModelId = $DefaultModel
$selectedModel  = $null
if ($models) {
    $defMatch = @($models | Where-Object { $_.name -eq $defaultModelId })
    if ($defMatch.Count -gt 0) {
        $selectedModel = $defaultModelId
        Write-Host ('[*] Default model: {0} ({1})' -f $defMatch[0].display_name, $defMatch[0].developer) -ForegroundColor Green
        Write-Host ''
    }
}
if (-not $selectedModel) {
    $selectedModel = Select-HatzModel -Models $models -Agents $agents
}

# Step 4: Start the interactive chat
Start-HatzChat -ApiBaseUrl $ApiBaseUrl -ApiKey $resolvedKey -Model $selectedModel -MaxHistory $MaxHistory

Write-Host 'Goodbye!' -ForegroundColor Cyan