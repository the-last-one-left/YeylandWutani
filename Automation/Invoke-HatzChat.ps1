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
# Persisted system prompt (plain text — not sensitive)
$script:SystemPromptFile = Join-Path $env:APPDATA 'HatzChat\system_prompt.txt'
# Session save/load directory
$script:SessionDir = Join-Path $env:APPDATA 'HatzChat\sessions'
# Track original file states for /diff (populated on first /edit or /file per path)
$script:OriginalFileStates = @{}

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
                Write-Host ('[~] Transient error ({0}), attempt {1}/{2}' -f $errDesc, ($attempt + 1), $maxRetries) -ForegroundColor DarkYellow
                Show-RetryCountdown -Seconds $wait
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

# --- Region: Search/Replace Diff Engine --------------------------------------

function ConvertFrom-SearchReplaceBlocks {
    <#
    .SYNOPSIS
        Parses model output for SEARCH/REPLACE blocks.
        Returns an array of @{ Search = '...'; Replace = '...' } pairs.
    .NOTES
        Format (inspired by Aider / git conflict markers):
            <<<<<<< SEARCH
            exact original text
            =======
            new replacement text
            >>>>>>> REPLACE

        The model may include explanation text outside the blocks - it's ignored.
    #>
    param([string]$Text)

    $blocks  = [System.Collections.ArrayList]::new()

    # Strip an optional outer code fence that wraps all the blocks.
    # Models sometimes wrap everything in ```diff ... ``` or ```text ... ```
    $stripped = $Text -replace '(?s)\A\s*```[^\n]*\n(.*)\n```\s*\z', '$1'

    $pattern = '(?sm)^<{6,7}\s*SEARCH\s*\r?\n(.*?)^={6,7}\s*\r?\n(.*?)^>{6,7}\s*REPLACE\s*$'
    $matches = [regex]::Matches($stripped, $pattern)

    foreach ($m in $matches) {
        # Trim exactly one trailing newline from each group (the marker's own linebreak)
        $searchText  = $m.Groups[1].Value -replace '\r?\n$', ''
        $replaceText = $m.Groups[2].Value -replace '\r?\n$', ''
        [void]$blocks.Add(@{
            Search  = $searchText
            Replace = $replaceText
        })
    }

    return $blocks
}

function Invoke-ApplySearchReplace {
    <#
    .SYNOPSIS
        Applies an ordered list of SEARCH/REPLACE blocks to file content.
    .DESCRIPTION
        For each block, finds the SEARCH text in the current content and replaces
        it with the REPLACE text. Blocks are applied sequentially (each sees the
        result of the previous).

        If an exact match fails, tries whitespace-normalized matching (collapse
        runs of whitespace, trim lines) as a fallback - models sometimes
        reformat indentation.

        Returns @{ Success = $bool; Content = '...'; Errors = @('...') }
    #>
    param(
        [string]$OriginalContent,
        [array]$Blocks
    )

    $content = $OriginalContent
    $errors  = [System.Collections.ArrayList]::new()
    $applied = 0

    foreach ($block in $Blocks) {
        $search  = $block.Search
        $replace = $block.Replace

        # --- Attempt 1: Exact substring match ---
        $idx = $content.IndexOf($search, [StringComparison]::Ordinal)
        if ($idx -ge 0) {
            $content = $content.Remove($idx, $search.Length).Insert($idx, $replace)
            $applied++
            continue
        }

        # --- Attempt 2: Normalize line endings then retry ---
        $contentNorm = $content -replace "`r`n", "`n"
        $searchNorm  = $search  -replace "`r`n", "`n"
        $idx = $contentNorm.IndexOf($searchNorm, [StringComparison]::Ordinal)
        if ($idx -ge 0) {
            $replaceNorm = $replace -replace "`r`n", "`n"
            $content = $contentNorm.Remove($idx, $searchNorm.Length).Insert($idx, $replaceNorm)
            $applied++
            continue
        }

        # --- Attempt 3: Whitespace-normalized fuzzy match ---
        # Collapse each line's leading/trailing whitespace for matching,
        # but apply using original indentation from the REPLACE block.
        $found = $false
        $contentLines = $content -split "`r?`n"
        $searchLines  = $search  -split "`r?`n"

        if ($searchLines.Count -le $contentLines.Count) {
            for ($i = 0; $i -le ($contentLines.Count - $searchLines.Count); $i++) {
                $match = $true
                for ($j = 0; $j -lt $searchLines.Count; $j++) {
                    $cLine = $contentLines[$i + $j].Trim()
                    $sLine = $searchLines[$j].Trim()
                    if ($cLine -ne $sLine) { $match = $false; break }
                }
                if ($match) {
                    # Replace those lines with the REPLACE block's lines
                    $replaceLines = $replace -split "`r?`n"
                    $before = $contentLines[0..([Math]::Max(0, $i - 1))]
                    if ($i -eq 0) { $before = @() }
                    $after  = if (($i + $searchLines.Count) -lt $contentLines.Count) {
                        $contentLines[($i + $searchLines.Count)..($contentLines.Count - 1)]
                    } else { @() }
                    $contentLines = @($before) + @($replaceLines) + @($after)
                    $content = $contentLines -join "`n"
                    $applied++
                    $found = $true
                    break
                }
            }
        }

        if (-not $found) {
            $preview = if ($search.Length -gt 80) { $search.Substring(0, 77) + '...' } else { $search }
            [void]$errors.Add("Could not locate SEARCH block: $preview")
        }
    }

    return @{
        Success = ($errors.Count -eq 0)
        Content = $content
        Applied = $applied
        Errors  = $errors
    }
}

function Show-SearchReplacePlan {
    <#
    .SYNOPSIS
        Displays a colored preview of what each SEARCH/REPLACE block will do.
    #>
    param([array]$Blocks)

    for ($i = 0; $i -lt $Blocks.Count; $i++) {
        Write-Host ('  --- Change {0}/{1} ---' -f ($i + 1), $Blocks.Count) -ForegroundColor Yellow
        $sLines = $Blocks[$i].Search  -split "`r?`n"
        $rLines = $Blocks[$i].Replace -split "`r?`n"
        foreach ($l in $sLines) { Write-Host ('  - {0}' -f $l) -ForegroundColor Red }
        foreach ($l in $rLines) { Write-Host ('  + {0}' -f $l) -ForegroundColor Green }
        Write-Host ''
    }
}

# --- Region: UX Helper Functions ----------------------------------------------

function Invoke-HatzChatWithSpinner {
    <#
    .SYNOPSIS
        Calls the chat completion API in a background runspace while showing
        an animated spinner on the main thread.
    .DESCRIPTION
        Provides visual feedback during API calls by running the HTTP request
        in a background runspace while displaying an animated spinner with
        elapsed time on the main thread.
    .PARAMETER ApiBaseUrl
        The base URL of the API.
    .PARAMETER ApiKey
        The API key for authentication.
    .PARAMETER Model
        The model name or agent-{id} to use.
    .PARAMETER Messages
        Array of message objects (role + content).
    .PARAMETER Temperature
        Sampling temperature (0.0 - 2.0).
    .PARAMETER ToolsToUse
        Optional array of tool names to enable.
    .PARAMETER AutoToolSelection
        Let the API automatically select relevant tools.
    .PARAMETER TimeoutMs
        Request timeout in milliseconds.
    .PARAMETER SpinnerMessage
        Message displayed alongside the spinner.
    #>
    param(
        [string]$ApiBaseUrl,
        [string]$ApiKey,
        [string]$Model,
        [array]$Messages,
        [double]$Temperature = 0.7,
        [string[]]$ToolsToUse = @(),
        [bool]$AutoToolSelection = $false,
        [int]$TimeoutMs = 120000,
        [string]$SpinnerMessage = 'Thinking'
    )

    $frames = @('⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏')
    $fallbackFrames = @('|','/','-','\')
    $useUnicode = -not ($Host.UI.RawUI.WindowTitle -match 'cmd\.exe')
    $spinFrames = if ($useUnicode) { $frames } else { $fallbackFrames }

    # --- Pre-serialize the request on the main thread (has access to everything) ---
    $bodyHash = @{
        model       = $Model
        messages    = $Messages
        stream      = $false
        temperature = $Temperature
    }
    if ($ToolsToUse.Count -gt 0) { $bodyHash['tools_to_use']       = $ToolsToUse }
    if ($AutoToolSelection)       { $bodyHash['auto_tool_selection'] = $true       }

    $bodyJson  = $bodyHash | ConvertTo-Json -Depth 10 -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
    $uri       = "$ApiBaseUrl/chat/completions"

    # --- Launch the HTTP call in a background runspace ---
    $rs = [RunspaceFactory]::CreateRunspace()
    $rs.Open()
    $ps = [PowerShell]::Create().AddScript({
        param($uri, $bodyBytes, $ApiKey, $TimeoutMs)

        $maxRetries = 2
        $retryWait  = 3
        $lastError  = $null

        for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
            try {
                $req               = [System.Net.HttpWebRequest]::Create($uri)
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

                return @{ Success = $true; Json = $jsonText; Error = $null }
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
                    } catch { }
                }

                $isTransient = $isTimeout -or ($null -ne $statusCode -and $statusCode -ge 500)
                if ($isTransient -and $attempt -lt $maxRetries) {
                    Start-Sleep -Seconds ($retryWait * [math]::Pow(2, $attempt))
                    continue
                }

                $lastError = if ($errorBody) { "HTTP $statusCode : $errorBody" } else { $_.Exception.Message }
            }
        }
        return @{ Success = $false; Json = $null; Error = $lastError }
    }).AddArgument($uri).AddArgument($bodyBytes).AddArgument($ApiKey).AddArgument($TimeoutMs)

    $ps.Runspace = $rs
    $handle = $ps.BeginInvoke()

    # --- Spin on the main thread until the background call finishes ---
    $i  = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while (-not $handle.IsCompleted) {
        $elapsed = '{0:F1}s' -f $sw.Elapsed.TotalSeconds
        $frame   = $spinFrames[$i % $spinFrames.Count]
        Write-Host ("`r  {0} {1} ({2})  " -f $frame, $SpinnerMessage, $elapsed) -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds 100
        $i++
    }
    $sw.Stop()

    # --- Collect result ---
    $result = $ps.EndInvoke($handle)
    $ps.Dispose()
    $rs.Close()

    $checkmark = if ($useUnicode) { '✓' } else { '+' }
    $elapsedSec = $sw.Elapsed.TotalSeconds

    if ($result -and $result.Success) {
        Write-Host ("`r  {0} Response received ({1:F1}s)          " -f $checkmark, $elapsedSec) -ForegroundColor Green
        return [PSCustomObject]@{
            Response = ($result.Json | ConvertFrom-Json)
            Elapsed  = $elapsedSec
        }
    }
    else {
        $errMsg = if ($result) { $result.Error } else { 'Unknown error' }
        Write-Host ("`r  [!] API Error ({0:F1}s)                    " -f $elapsedSec) -ForegroundColor Red
        Write-Host ('      {0}' -f $errMsg) -ForegroundColor DarkRed
        Write-Host ''
        return $null
    }
}

function Read-MultilineInput {
    <#
    .SYNOPSIS
        Reads multiline input from the user interactively.
    .DESCRIPTION
        Prompts the user for multiline input. Type a line containing only "."
        to finish input. Returns the combined text or $null if cancelled.
    .PARAMETER Prompt
        Optional prompt message to display before entering multiline mode.
    #>
    param(
        [string]$Prompt = 'Enter text (type "." on its own line to finish, or leave empty to cancel)'
    )

    Write-Host "[*] $Prompt" -ForegroundColor Cyan
    $lines = [System.Collections.ArrayList]::new()
    while ($true) {
        Write-Host '... ' -ForegroundColor DarkYellow -NoNewline
        $line = Read-Host
        if ($line.Trim() -eq '.') { break }
        [void]$lines.Add($line)
    }
    
    if ($lines.Count -eq 0) {
        return $null
    }
    
    Write-Host ('[*] {0} lines captured.' -f $lines.Count) -ForegroundColor Cyan
    return ($lines -join "`n")
}

function Show-TokenBar {
    <#
    .SYNOPSIS
        Displays a visual progress bar showing context window usage.
    .DESCRIPTION
        Renders a colored bar indicating how much of the model's context
        window has been consumed. Color changes based on usage percentage.
    .PARAMETER Used
        Number of tokens currently used.
    .PARAMETER Max
        Maximum context window size for the model.
    #>
    param(
        [int]$Used,
        [int]$Max = 200000
    )

    $pct    = [math]::Min(100, [math]::Floor(($Used / $Max) * 100))
    $filled = [math]::Floor($pct / 2)
    $empty  = 50 - $filled
    
    # Color based on usage level
    $color = if ($pct -ge 80) { 
        'Red' 
    } elseif ($pct -ge 60) { 
        'DarkYellow' 
    } elseif ($pct -ge 40) {
        'Yellow'
    } else { 
        'DarkCyan' 
    }
    
    # Use block characters for the bar (fallback to # and - for legacy consoles)
    $fillChar  = [char]0x2588  # █
    $emptyChar = [char]0x2591  # ░
    
    $bar = ($fillChar.ToString() * $filled) + ($emptyChar.ToString() * $empty)
    
    Write-Host ('  Context: [{0}] {1}% ({2:N0}/{3:N0})' -f $bar, $pct, $Used, $Max) -ForegroundColor $color
}

function Write-HighlightedResponse {
    <#
    .SYNOPSIS
        Outputs assistant response with syntax highlighting for code blocks.
    .DESCRIPTION
        Detects fenced code blocks in the response and applies basic
        syntax highlighting for PowerShell/common languages.
        Falls back to plain output on legacy consoles.
    .PARAMETER Text
        The response text to display.
    #>
    param([string]$Text)
    
    # Check if console supports ANSI escape codes (PS7+, Windows Terminal)
    $supportsAnsi = $false
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $supportsAnsi = $true
    } elseif ($env:WT_SESSION) {
        $supportsAnsi = $true  # Windows Terminal
    }
    
    $inCodeBlock = $false
    $codeLanguage = ''
    
    foreach ($line in ($Text -split "`r?`n")) {
        # Detect code fence start/end
        if ($line -match '^```(.*)$') {
            $inCodeBlock = -not $inCodeBlock
            if ($inCodeBlock) {
                $codeLanguage = $Matches[1].Trim().ToLower()
            }
            Write-Host $line -ForegroundColor DarkGray
            continue
        }
        
        if ($inCodeBlock -and $supportsAnsi) {
            # Apply syntax highlighting based on language
            $highlighted = $line
            
            # PowerShell / general keywords
            if ($codeLanguage -in @('powershell', 'ps1', 'pwsh', '')) {
                # Keywords (cyan)
                $highlighted = $highlighted -replace '\b(function|param|if|else|elseif|foreach|while|for|return|try|catch|finally|throw|switch|break|continue|begin|process|end|filter)\b', "`e[96m`$1`e[0m"
                # Variables (yellow)
                $highlighted = $highlighted -replace '(\$[\w]+)', "`e[93m`$1`e[0m"
                # Comments (dark gray)
                $highlighted = $highlighted -replace '(#.*)$', "`e[90m`$1`e[0m"
                # Strings (green)
                $highlighted = $highlighted -replace "('[^']*')", "`e[92m`$1`e[0m"
                $highlighted = $highlighted -replace '("[^"]*")', "`e[92m`$1`e[0m"
            }
            elseif ($codeLanguage -in @('python', 'py')) {
                $highlighted = $highlighted -replace '\b(def|class|if|else|elif|for|while|return|import|from|try|except|finally|with|as|lambda|yield|raise|pass|break|continue)\b', "`e[96m`$1`e[0m"
                $highlighted = $highlighted -replace '(#.*)$', "`e[90m`$1`e[0m"
                $highlighted = $highlighted -replace "('[^']*')", "`e[92m`$1`e[0m"
                $highlighted = $highlighted -replace '("[^"]*")', "`e[92m`$1`e[0m"
            }
            
            [Console]::WriteLine($highlighted)
        }
        elseif ($inCodeBlock) {
            # No ANSI support - use Write-Host with color for entire code block
            Write-Host $line -ForegroundColor DarkCyan
        }
        else {
            Write-Host $line
        }
    }
}

function Show-RetryCountdown {
    <#
    .SYNOPSIS
        Displays a live countdown timer before retrying an operation.
    .PARAMETER Seconds
        Number of seconds to count down.
    .PARAMETER Message
        Optional message prefix.
    #>
    param(
        [int]$Seconds,
        [string]$Message = 'Retrying in'
    )
    
    for ($sec = $Seconds; $sec -gt 0; $sec--) {
        Write-Host ("`r[~] {0} {1}s...  " -f $Message, $sec) -NoNewline -ForegroundColor DarkYellow
        Start-Sleep -Seconds 1
    }
    Write-Host "`r[~] Retrying now...            " -ForegroundColor DarkYellow
}

# Context window limits by model (for token budget bar)
$script:ContextLimits = @{
    'anthropic.claude-opus-4-6'       = 200000
    'anthropic.claude-sonnet-4-5'     = 200000
    'anthropic.claude-sonnet-4-20250514' = 200000
    'anthropic.claude-3-5-sonnet'     = 200000
    'anthropic.claude-3-5-haiku'      = 200000
    'anthropic.claude-3-opus'         = 200000
    'anthropic.claude-3-sonnet'       = 200000
    'anthropic.claude-3-haiku'        = 200000
    'openai.gpt-4o'                   = 128000
    'openai.gpt-4o-mini'              = 128000
    'openai.gpt-4-turbo'              = 128000
    'openai.o1'                       = 200000
    'openai.o1-mini'                  = 128000
    'openai.o1-preview'               = 128000
    'openai.o3-mini'                  = 200000
    'google.gemini-2.0-flash'         = 1000000
    'google.gemini-1.5-pro'           = 2000000
    'google.gemini-1.5-flash'         = 1000000
    'mistral.mistral-large'           = 128000
    'xai.grok-2'                      = 131072
    'deepseek.deepseek-chat'          = 64000
    'deepseek.deepseek-reasoner'      = 64000
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

    # Session-level temperature (overridable via /temp)
    $temperature = 0.7

    # Load persisted system prompt if one exists
    $loadedSystemPrompt = $null
    if (Test-Path $script:SystemPromptFile) {
        try {
            $loadedSystemPrompt = Get-Content $script:SystemPromptFile -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($loadedSystemPrompt)) {
                $loadedSystemPrompt = $loadedSystemPrompt.Trim()
            } else {
                $loadedSystemPrompt = $null
            }
        }
        catch {
            Write-Host '[!] Failed to load saved system prompt.' -ForegroundColor Yellow
            $loadedSystemPrompt = $null
        }
    }

    # Build truncated display for the banner
    $sysPromptDisplay = if ($loadedSystemPrompt) {
        $truncLen = 42
        if ($loadedSystemPrompt.Length -gt $truncLen) {
            $loadedSystemPrompt.Substring(0, $truncLen - 3) + '...'
        } else {
            $loadedSystemPrompt
        }
    } else { '(none)' }

    $histNote = if ($MaxHistory -gt 0) { 'last {0} messages' -f $MaxHistory } else { 'unlimited' }

    Write-Host ''
    Write-Host ('+== Hatz AI Chat | {0} | History: {1} | Autotools: ON ==' -f $modelDisplay, $histNote) -ForegroundColor Green
    if ($loadedSystemPrompt) {
        Write-Host ('    SysPrompt: {0}' -f $sysPromptDisplay) -ForegroundColor DarkGray
    }
    Write-Host '    /help for commands | /quit to exit' -ForegroundColor DarkGray
    Write-Host ''

    # Initialize state
    $conversationHistory = [System.Collections.ArrayList]::new()

    # Apply loaded system prompt to conversation history
    if ($loadedSystemPrompt) {
        [void]$conversationHistory.Add(@{ role = 'system'; content = $loadedSystemPrompt })
        Write-Host '[*] System prompt loaded from saved profile.' -ForegroundColor Cyan
    }

    $currentModel        = $Model
    $toolsToUse          = @()
    $autoToolSelection   = $true    # ON by default
    $pendingContext      = ''       # Accumulated file/folder/run output injected into next message
    $workspacePath       = ''       # Base folder for resolving relative paths
    $totalInputTokens    = 0        # Running session totals for budget visibility
    $totalOutputTokens   = 0

    # Main chat loop
    while ($true) {
        # Build contextual prompt with turn number and state indicators
        $promptParts = @()
        if ($pendingContext) {
            $ctxKB = [math]::Round($pendingContext.Length / 1024, 1)
            $promptParts += '{0}KB ctx' -f $ctxKB
        }
        if ($toolsToUse.Count -gt 0) { $promptParts += 'tools' }
        if ($temperature -ne 0.7) { $promptParts += 't={0}' -f $temperature }

        $promptSuffix = if ($promptParts.Count -gt 0) { ' [{0}]' -f ($promptParts -join '|') } else { '' }
        $turnNumber   = @($conversationHistory | Where-Object { $_.role -eq 'user' }).Count + 1

        Write-Host ('[{0}] You{1}: ' -f $turnNumber, $promptSuffix) -ForegroundColor Yellow -NoNewline
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
                $sysPrompt = Read-Host -Prompt 'Enter system prompt (or "clear" to remove)'
            }
            $toRemove = @($conversationHistory | Where-Object { $_.role -eq 'system' })
            foreach ($msg in $toRemove) { $conversationHistory.Remove($msg) }

            if ($sysPrompt.Trim().ToLower() -eq 'clear') {
                # Remove persisted system prompt
                if (Test-Path $script:SystemPromptFile) {
                    Remove-Item $script:SystemPromptFile -Force -ErrorAction SilentlyContinue
                }
                Write-Host '[*] System prompt cleared and removed from profile.' -ForegroundColor Cyan
            }
            else {
                $conversationHistory.Insert(0, @{ role = 'system'; content = $sysPrompt })
                # Persist to profile
                $promptDir = Split-Path $script:SystemPromptFile
                if (-not (Test-Path $promptDir)) { New-Item -ItemType Directory -Path $promptDir -Force | Out-Null }
                [System.IO.File]::WriteAllText($script:SystemPromptFile, $sysPrompt, [System.Text.Encoding]::UTF8)
                Write-Host '[*] System prompt set and saved to profile.' -ForegroundColor Cyan
            }
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
                
                # Show progress while scanning large folders
                $total = $folderFiles.Count
                for ($fi = 0; $fi -lt $total; $fi++) {
                    if ($total -gt 20) {
                        $pct = [math]::Floor(($fi / $total) * 100)
                        Write-Progress -Activity 'Scanning files' -Status ('{0}/{1}' -f ($fi + 1), $total) -PercentComplete $pct
                    }
                    $rel    = $folderFiles[$fi].FullName.Substring($resolvedFolder.Length).TrimStart('\\', '/')
                    $binTag = if (Test-IsBinaryFile -Path $folderFiles[$fi].FullName) { ' [binary]' } else { '' }
                    Write-Host ('  {0,3}. {1} ({2} bytes){3}' -f ($fi + 1), $rel, $folderFiles[$fi].Length, $binTag) -ForegroundColor DarkCyan
                }
                if ($total -gt 20) { Write-Progress -Activity 'Scanning files' -Completed }
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
                    $total = $folderFiles.Count
                    for ($fi = 0; $fi -lt $total; $fi++) {
                        $ff = $folderFiles[$fi]
                        $pct = [math]::Floor((($fi + 1) / $total) * 100)
                        Write-Progress -Activity 'Injecting files' -Status ('{0}/{1} - {2}' -f ($fi + 1), $total, $ff.Name) -PercentComplete $pct
                        
                        if (Test-IsBinaryFile -Path $ff.FullName) { $skipped++; continue }
                        $fc = Get-Content $ff.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($fc) {
                            $fext = $ff.Extension.TrimStart('.')
                            $frel = $ff.FullName.Substring($resolvedFolder.Length).TrimStart('\', '/')
                            $pendingContext += "`n[File: $frel]`n``````$fext`n$fc`n```````n"
                            $injected++
                        }
                    }
                    Write-Progress -Activity 'Injecting files' -Completed
                    $skipNote = if ($skipped -gt 0) { ", $skipped binary skipped" } else { '' }
                    Write-Host ('[*] Injected tree + {0} text file(s){1}.' -f $injected, $skipNote) -ForegroundColor Cyan
                    
                    # Context size warning
                    $ctxChars = $pendingContext.Length
                    $estTokens = [math]::Ceiling($ctxChars / 4)
                    $maxCtx = if ($script:ContextLimits.ContainsKey($currentModel)) {
                        $script:ContextLimits[$currentModel]
                    } else { 200000 }
                    if ($estTokens -gt ($maxCtx * 0.5)) {
                        Write-Host ('[!] Warning: injected context is ~{0:N0} tokens ({1}% of context window)' -f $estTokens, [math]::Floor(($estTokens/$maxCtx)*100)) -ForegroundColor Red
                        Write-Host '    Consider selecting fewer files or using /clear first.' -ForegroundColor DarkYellow
                    }
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
                    
                    # Context size warning
                    $ctxChars = $pendingContext.Length
                    $estTokens = [math]::Ceiling($ctxChars / 4)
                    $maxCtx = if ($script:ContextLimits.ContainsKey($currentModel)) {
                        $script:ContextLimits[$currentModel]
                    } else { 200000 }
                    if ($estTokens -gt ($maxCtx * 0.5)) {
                        Write-Host ('[!] Warning: injected context is ~{0:N0} tokens ({1}% of context window)' -f $estTokens, [math]::Floor(($estTokens/$maxCtx)*100)) -ForegroundColor Red
                        Write-Host '    Consider selecting fewer files or using /clear first.' -ForegroundColor DarkYellow
                    }
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
                Write-Host '+-- Command Output ----------------------------------------' -ForegroundColor DarkYellow
                Write-Host $runOutput -ForegroundColor DarkGray
                Write-Host '+----------------------------------------------------------' -ForegroundColor DarkYellow
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
        # -- /copy --
        elseif ($trimmedInput -eq '/copy') {
            $lastAssistant = $conversationHistory | Where-Object { $_.role -eq 'assistant' } | Select-Object -Last 1
            if ($lastAssistant) {
                $lastAssistant.content | Set-Clipboard
                Write-Host '[*] Last response copied to clipboard.' -ForegroundColor Cyan
            } else {
                Write-Host '[*] No assistant response to copy.' -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }

        # -- /retry [extra instruction] --
        elseif ($trimmedInput -match '^/retry\s*(.*)$') {
            $extraInstruction = $Matches[1].Trim()
            # Need at least one assistant + one user message to retry
            if ($conversationHistory.Count -ge 2) {
                $lastRole = $conversationHistory[$conversationHistory.Count - 1].role
                if ($lastRole -eq 'assistant') {
                    $conversationHistory.RemoveAt($conversationHistory.Count - 1)  # remove assistant
                    $prevUser = $conversationHistory[$conversationHistory.Count - 1]
                    if ($extraInstruction) {
                        $prevUser.content += "`n`nAdditional instruction: $extraInstruction"
                    }
                    $userInput = $prevUser.content
                    Write-Host '[*] Retrying last message...' -ForegroundColor Cyan
                    # Remove the user message too — it will be re-added in the send logic below
                    $conversationHistory.RemoveAt($conversationHistory.Count - 1)
                    # Fall through to message processing
                } else {
                    Write-Host '[!] Last message is not from the assistant. Nothing to retry.' -ForegroundColor Yellow
                    Write-Host ''
                    continue
                }
            } else {
                Write-Host '[!] No conversation to retry.' -ForegroundColor Yellow
                Write-Host ''
                continue
            }
        }

        # -- /undo <path> --
        elseif ($trimmedInput -match '^/undo\s+(.+)$') {
            $undoPath = $Matches[1].Trim().Trim('"')
            $resolvedUndo = if ($workspacePath -and -not [System.IO.Path]::IsPathRooted($undoPath)) {
                Join-Path $workspacePath $undoPath
            } else { $undoPath }

            $bakDir = Join-Path (Split-Path $resolvedUndo) '.hatz-backups'
            $leaf   = Split-Path $resolvedUndo -Leaf
            $baks   = @(Get-ChildItem $bakDir -Filter "$leaf.*.bak" -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending)

            if ($baks.Count -eq 0) {
                Write-Host '[!] No backups found.' -ForegroundColor Yellow
            } else {
                Write-Host ('  Backups for {0}:' -f $leaf) -ForegroundColor Cyan
                for ($bi = 0; $bi -lt $baks.Count; $bi++) {
                    Write-Host ('  {0}. {1}  ({2})' -f ($bi+1), $baks[$bi].Name, $baks[$bi].LastWriteTime) -ForegroundColor Gray
                }
                $pick = Read-Host -Prompt 'Restore which backup? (number or Enter to cancel)'
                $parsed = 0
                if ([int]::TryParse($pick, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $baks.Count) {
                    Copy-Item $baks[$parsed-1].FullName $resolvedUndo -Force
                    Write-Host ('[+] Restored from {0}' -f $baks[$parsed-1].Name) -ForegroundColor Green
                }
            }
            Write-Host ''
            continue
        }

        # -- /diff <path> --
        elseif ($trimmedInput -match '^/diff\s+(.+)$') {
            $rawDiffPath = $Matches[1].Trim().Trim('"')
            $resolvedDiff = if ($workspacePath -and -not [System.IO.Path]::IsPathRooted($rawDiffPath)) {
                Join-Path $workspacePath $rawDiffPath
            } else { $rawDiffPath }

            if ($script:OriginalFileStates.ContainsKey($resolvedDiff)) {
                $currentContent = Get-Content $resolvedDiff -Raw -Encoding UTF8
                Write-Host ('+-- Changes since session start: {0} --' -f $resolvedDiff) -ForegroundColor Yellow
                $hasChanges = Show-LineDiff -Original $script:OriginalFileStates[$resolvedDiff] -Updated $currentContent
                if (-not $hasChanges) {
                    Write-Host '  (No changes from baseline)' -ForegroundColor DarkGray
                }
                Write-Host '+--------------------------------------------------------------' -ForegroundColor Yellow
            } else {
                Write-Host '[*] No baseline recorded for this file. Use /edit or /file first.' -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }

        # -- /save [name] --
        elseif ($trimmedInput -match '^/save\s*(.*)$') {
            $sessionName = if ($Matches[1].Trim()) { $Matches[1].Trim() } else {
                'session-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
            }
            if (-not (Test-Path $script:SessionDir)) {
                New-Item -ItemType Directory -Path $script:SessionDir -Force | Out-Null
            }
            $sessionFile = Join-Path $script:SessionDir "$sessionName.json"
            $sessionData = @{
                model       = $currentModel
                temperature = $temperature
                messages    = $conversationHistory.ToArray()
                saved       = (Get-Date -Format 'o')
            }
            $sessionData | ConvertTo-Json -Depth 10 |
                Set-Content -Path $sessionFile -Encoding UTF8
            Write-Host ('[+] Session saved: {0}' -f $sessionFile) -ForegroundColor Green
            Write-Host ''
            continue
        }

        # -- /load [name] --
        elseif ($trimmedInput -match '^/load\s*(.*)$') {
            $loadName = $Matches[1].Trim()
            if (-not (Test-Path $script:SessionDir)) {
                Write-Host '[!] No saved sessions found.' -ForegroundColor Yellow
                Write-Host ''
                continue
            }
            if ([string]::IsNullOrWhiteSpace($loadName)) {
                $sessions = @(Get-ChildItem $script:SessionDir -Filter '*.json' -ErrorAction SilentlyContinue |
                              Sort-Object LastWriteTime -Descending)
                if ($sessions.Count -eq 0) {
                    Write-Host '[!] No saved sessions found.' -ForegroundColor Yellow
                    Write-Host ''
                    continue
                }
                Write-Host '  Saved sessions:' -ForegroundColor Cyan
                for ($si = 0; $si -lt $sessions.Count; $si++) {
                    Write-Host ('  {0}. {1}  ({2})' -f ($si+1), $sessions[$si].BaseName, $sessions[$si].LastWriteTime) -ForegroundColor Gray
                }
                $pick = Read-Host -Prompt 'Load which session? (number or Enter to cancel)'
                $parsed = 0
                if ([int]::TryParse($pick, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $sessions.Count) {
                    $loadName = $sessions[$parsed-1].BaseName
                } else {
                    Write-Host '[*] Cancelled.' -ForegroundColor Cyan
                    Write-Host ''
                    continue
                }
            }
            $sessionFile = Join-Path $script:SessionDir "$loadName.json"
            if (-not (Test-Path $sessionFile)) {
                Write-Host ('[!] Session not found: {0}' -f $sessionFile) -ForegroundColor Red
                Write-Host ''
                continue
            }
            try {
                $sessionData = Get-Content $sessionFile -Raw -Encoding UTF8 | ConvertFrom-Json
                $conversationHistory.Clear()
                foreach ($msg in $sessionData.messages) {
                    [void]$conversationHistory.Add(@{ role = $msg.role; content = $msg.content })
                }
                if ($sessionData.model)       { $currentModel = $sessionData.model }
                if ($sessionData.temperature)  { $temperature  = [double]$sessionData.temperature }
                $msgCount = $conversationHistory.Count
                Write-Host ('[+] Loaded session: {0} ({1} messages, model: {2})' -f $loadName, $msgCount, $currentModel) -ForegroundColor Green
            }
            catch {
                Write-Host ('[!] Failed to load session: {0}' -f $_) -ForegroundColor Red
            }
            Write-Host ''
            continue
        }

        # -- /temp <value> --
        elseif ($trimmedInput -match '^/temp(?:erature)?\s+([\d.]+)$') {
            $newTemp = [double]$Matches[1]
            if ($newTemp -ge 0.0 -and $newTemp -le 2.0) {
                $temperature = $newTemp
                Write-Host ('[*] Temperature set to {0}' -f $temperature) -ForegroundColor Cyan
            } else {
                Write-Host '[!] Temperature must be between 0.0 and 2.0' -ForegroundColor Red
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

            $origContent = Get-Content $resolvedEdit -Raw -Encoding UTF8

            # Record baseline for /diff if first time touching this file
            if (-not $script:OriginalFileStates.ContainsKey($resolvedEdit)) {
                $script:OriginalFileStates[$resolvedEdit] = $origContent
            }

            $editExt       = [System.IO.Path]::GetExtension($resolvedEdit).TrimStart('.')
            $editLineCount = ($origContent -split "`r?`n").Count
            Write-Host ('[*] Edit: {0}  ({1} lines)' -f $resolvedEdit, $editLineCount) -ForegroundColor Cyan

            # Support both single-line and multiline instructions
            Write-Host 'Describe the change (or type /multi for multiline):' -ForegroundColor Cyan
            $rawInstruction = (Read-Host).Trim()
            
            if ($rawInstruction -eq '/multi') {
                $editInstruction = Read-MultilineInput -Prompt 'Enter edit instructions (type "." on its own line to finish)'
                if ($null -eq $editInstruction) {
                    Write-Host '[!] No instruction given - cancelled.' -ForegroundColor Yellow
                    Write-Host ''
                    continue
                }
            } else {
                $editInstruction = $rawInstruction
            }
            
            if ([string]::IsNullOrWhiteSpace($editInstruction)) {
                Write-Host '[!] No instruction given - cancelled.' -ForegroundColor Yellow
                Write-Host ''
                continue
            }

            # --- Build the search/replace prompt ---
            $editPrompt = @"
I need you to edit this file. Return ONLY the changes using SEARCH/REPLACE blocks.

Rules:
- Each block must contain the EXACT original text in the SEARCH section
- Copy the original text character-for-character (including indentation and whitespace)
- Include enough surrounding context lines (2-3) to make the match unique
- You may use multiple blocks for multiple changes - they are applied in order
- Do NOT return the entire file. Only return the changed sections.
- No explanation outside the blocks.

Format:
<<<<<<< SEARCH
exact original lines to find
=======
replacement lines
>>>>>>> REPLACE

File: $resolvedEdit
``````$editExt
$origContent
``````

Instruction: $editInstruction
"@

            # Send without conversation history to keep payload small
            $editMsgs = @(@{ role = 'user'; content = $editPrompt })
            $editResult = Invoke-HatzChatWithSpinner -ApiBaseUrl $ApiBaseUrl `
                                                      -ApiKey $ApiKey `
                                                      -Model $currentModel `
                                                      -Messages $editMsgs `
                                                      -Temperature 0.2 `
                                                      -TimeoutMs 180000 `
                                                      -SpinnerMessage 'Generating edit' 

            if ($null -eq $editResult) {
                Write-Host '[!] Edit request failed.' -ForegroundColor Red
                # Record failure in history so user can /retry with context
                [void]$conversationHistory.Add(@{ role = 'user'; content = $editPrompt })
                [void]$conversationHistory.Add(@{ role = 'assistant'; content = '[Edit request failed — no response from API]' })
                Write-Host ''
                continue
            }

            $editResp = $editResult.Response
            $rawReply = $editResp.choices[0].message.content

            # --- Parse SEARCH/REPLACE blocks ---
            $blocks = ConvertFrom-SearchReplaceBlocks -Text $rawReply

            if ($blocks.Count -eq 0) {
                # Fallback: model may have returned a full file in a code block anyway.
                Write-Host '[!] No SEARCH/REPLACE blocks found in response.' -ForegroundColor DarkYellow
                Write-Host '    Falling back to full-file extraction...' -ForegroundColor DarkYellow

                $codeMatches = [regex]::Matches($rawReply, '(?s)```[^\n]*\n(.*?)```')
                if ($codeMatches.Count -gt 0) {
                    $best       = $codeMatches |
                                    Sort-Object { $_.Groups[1].Value.Length } -Descending |
                                    Select-Object -First 1
                    $newContent = $best.Groups[1].Value

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
                        [void]$conversationHistory.Add(@{ role = 'user';      content = $editPrompt })
                        [void]$conversationHistory.Add(@{ role = 'assistant'; content = $rawReply   })
                    } else {
                        Write-Host '[*] Edit cancelled.' -ForegroundColor Cyan
                    }
                } else {
                    Write-Host '[!] Could not parse model response at all. Raw reply:' -ForegroundColor Red
                    Write-Host $rawReply -ForegroundColor DarkGray
                    # Record in history so user can /retry
                    [void]$conversationHistory.Add(@{ role = 'user';      content = $editPrompt })
                    [void]$conversationHistory.Add(@{ role = 'assistant'; content = $rawReply   })
                }
                Write-Host ''
                continue
            }

            # --- Preview the changes ---
            Write-Host ''
            Write-Host ('+-- {0} change(s) proposed ----------------------------------' -f $blocks.Count) -ForegroundColor Yellow
            Show-SearchReplacePlan -Blocks $blocks
            Write-Host '+--------------------------------------------------------------' -ForegroundColor Yellow
            Write-Host ''

            # --- Apply the blocks ---
            $result = Invoke-ApplySearchReplace -OriginalContent $origContent -Blocks $blocks

            if ($result.Errors.Count -gt 0) {
                Write-Host ('[!] {0} block(s) could not be matched:' -f $result.Errors.Count) -ForegroundColor Red
                foreach ($err in $result.Errors) {
                    Write-Host ('    {0}' -f $err) -ForegroundColor DarkRed
                }
                if ($result.Applied -gt 0) {
                    Write-Host ('[*] {0} block(s) matched successfully.' -f $result.Applied) -ForegroundColor DarkYellow
                    $partialChoice = (Read-Host -Prompt 'Apply partial changes? (y/n)').Trim().ToLower()
                    if ($partialChoice -ne 'y') {
                        Write-Host '[*] Edit cancelled.' -ForegroundColor Cyan
                        Write-Host ''
                        continue
                    }
                } else {
                    Write-Host '[!] No blocks could be applied. Edit cancelled.' -ForegroundColor Red
                    Write-Host ''
                    continue
                }
            }

            # Show the final unified diff of original vs patched
            Write-Host ''
            Write-Host '+-- Final diff ------------------------------------------------' -ForegroundColor Yellow
            $hasChanges = Show-LineDiff -Original $origContent -Updated $result.Content
            if (-not $hasChanges) {
                Write-Host '  (No effective changes)' -ForegroundColor DarkGray
                Write-Host '+--------------------------------------------------------------' -ForegroundColor Yellow
                Write-Host ''
                continue
            }
            Write-Host '+--------------------------------------------------------------' -ForegroundColor Yellow
            Write-Host ''

            $applyChoice = (Read-Host -Prompt 'Apply changes? (y/n)').Trim().ToLower()
            if ($applyChoice -eq 'y') {
                # Write a timestamped backup before overwriting (safety net)
                $bakDir  = Join-Path (Split-Path $resolvedEdit) '.hatz-backups'
                if (-not (Test-Path $bakDir)) { New-Item -ItemType Directory -Path $bakDir -Force | Out-Null }
                $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
                $bakName = '{0}.{1}.bak' -f (Split-Path $resolvedEdit -Leaf), $stamp
                $bakPath = Join-Path $bakDir $bakName
                [System.IO.File]::WriteAllText($bakPath, $origContent, [System.Text.Encoding]::UTF8)
                [System.IO.File]::WriteAllText($resolvedEdit, $result.Content, [System.Text.Encoding]::UTF8)
                Write-Host ('[+] Saved: {0}' -f $resolvedEdit) -ForegroundColor Green
                Write-Host ('[+] Backup: {0}' -f $bakPath) -ForegroundColor DarkGray
                [void]$conversationHistory.Add(@{ role = 'user';      content = $editPrompt })
                [void]$conversationHistory.Add(@{ role = 'assistant'; content = $rawReply   })
            } else {
                Write-Host '[*] Edit cancelled.' -ForegroundColor Cyan
            }
            Write-Host ''
            continue
        }

        elseif ($trimmedInput -eq '/help') {
            Write-Host '  Session:' -ForegroundColor Gray
            Write-Host '  /quit             - Exit the chat' -ForegroundColor Gray
            Write-Host '  /clear            - Clear conversation history' -ForegroundColor Gray
            Write-Host '  /model            - Switch to a different model' -ForegroundColor Gray
            Write-Host '  /system           - Set a system prompt' -ForegroundColor Gray
            Write-Host '  /history          - Show conversation message count' -ForegroundColor Gray
            Write-Host '  /tools            - Toggle tools (search, code, etc.)' -ForegroundColor Gray
            Write-Host '  /autotools        - Toggle auto tool selection' -ForegroundColor Gray
            Write-Host '  /temp <0.0-2.0>   - Set sampling temperature' -ForegroundColor Gray
            Write-Host '  /save [name]      - Save conversation to disk' -ForegroundColor Gray
            Write-Host '  /load [name]      - Load a saved conversation' -ForegroundColor Gray
            Write-Host '  /copy             - Copy last response to clipboard' -ForegroundColor Gray
            Write-Host '  /retry [note]     - Resend last message (optionally with edits)' -ForegroundColor Gray
            Write-Host '  Local folder:' -ForegroundColor Gray
            Write-Host '  /file <path>      - Inject file content into next message' -ForegroundColor Gray
            Write-Host '  /folder <path>    - Inject folder tree and/or files' -ForegroundColor Gray
            Write-Host '  /run <cmd>        - Run a command, inject output into context' -ForegroundColor Gray
            Write-Host '  /edit <path>      - Model edits a local file (shows diff, confirms)' -ForegroundColor Gray
            Write-Host '  /undo <path>      - Restore file from timestamped backup' -ForegroundColor Gray
            Write-Host '  /diff <path>      - Show cumulative changes since session start' -ForegroundColor Gray
            Write-Host '  /workspace <path> - Set base folder for relative paths' -ForegroundColor Gray
            Write-Host '  /context          - Show pending context size' -ForegroundColor Gray
            Write-Host '  /multi            - Enter multiline input mode' -ForegroundColor Gray
            Write-Host '  /help             - Show these commands' -ForegroundColor Gray
            Write-Host ''
            continue
        }

        # -- /multi (multiline input mode) --
        elseif ($trimmedInput -eq '/multi') {
            Write-Host '[*] Multiline mode. Type a line with only "." to finish.' -ForegroundColor Cyan
            $multiLines = [System.Collections.ArrayList]::new()
            while ($true) {
                Write-Host '... ' -ForegroundColor DarkYellow -NoNewline
                $ml = Read-Host
                if ($ml.Trim() -eq '.') { break }
                [void]$multiLines.Add($ml)
            }
            if ($multiLines.Count -eq 0) {
                Write-Host '[*] No input captured.' -ForegroundColor Cyan
                Write-Host ''
                continue
            }
            $userInput = $multiLines -join "`n"
            Write-Host ('[*] {0} lines captured.' -f $multiLines.Count) -ForegroundColor Cyan
            # Fall through to message processing below
        }

        # -- Unknown slash command --
        elseif ($trimmedInput.StartsWith('/')) {
            $allCmds = @('/quit','/clear','/model','/system','/history','/tools',
                         '/autotools','/file','/folder','/run','/edit','/undo','/diff',
                         '/workspace','/context','/multi','/help','/copy','/retry',
                         '/save','/load','/temp','/temperature')
            $partial = ($trimmedInput -split ' ')[0]
            $cmdMatches = @($allCmds | Where-Object { $_ -like "$partial*" })
            if ($cmdMatches.Count -eq 1) {
                Write-Host ('[?] Did you mean: {0}' -f $cmdMatches[0]) -ForegroundColor DarkYellow
            }
            elseif ($cmdMatches.Count -gt 1) {
                Write-Host ('[?] Matching commands: {0}' -f ($cmdMatches -join ', ')) -ForegroundColor DarkYellow
            }
            else {
                Write-Host ('[!] Unknown command: {0}  (type /help for list)' -f $partial) -ForegroundColor Red
            }
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
        $apiResult = $null
        if ($isImageModel) {
            # Image models: send only the latest user message — no history, no tools
            $imageMsgs = @(@{ role = 'user'; content = $finalContent })
            $apiResult = Invoke-HatzChatWithSpinner -ApiBaseUrl $ApiBaseUrl `
                                                    -ApiKey $ApiKey `
                                                    -Model $currentModel `
                                                    -Messages $imageMsgs `
                                                    -Temperature 1.0 `
                                                    -AutoToolSelection $false `
                                                    -SpinnerMessage 'Generating image' 
        } else {
            $isImageModel = $false
            $apiResult = Invoke-HatzChatWithSpinner -ApiBaseUrl $ApiBaseUrl `
                                                    -ApiKey $ApiKey `
                                                    -Model $currentModel `
                                                    -Messages $conversationHistory.ToArray() `
                                                    -Temperature $temperature `
                                                    -ToolsToUse $toolsToUse `
                                                    -AutoToolSelection $autoToolSelection `
                                                    -SpinnerMessage 'Thinking'
        }

        if ($null -eq $apiResult) {
            # Remove failed message so it can be retried
            $conversationHistory.RemoveAt($conversationHistory.Count - 1)
            Write-Host '[!] Request failed. Your message was not added to history.' -ForegroundColor Yellow
            Write-Host ''
            continue
        }

        $response    = $apiResult.Response
        $apiElapsed  = $apiResult.Elapsed

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
        Write-HighlightedResponse -Text $assistantMessage
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

        # -- Token tracking, timing, and budget visualization --
        if ($response.usage) {
            $inputTok           = $response.usage.input_tokens
            $outputTok          = $response.usage.output_tokens
            $totalInputTokens  += $inputTok
            $totalOutputTokens += $outputTok
            
            # Include elapsed time if available
            $timeStr = if ($apiElapsed) { ' | {0:F1}s' -f $apiElapsed } else { '' }
            Write-Host ('  [tokens: in={0:N0} out={1:N0}{2} | session: in={3:N0} out={4:N0}]' -f `
                $inputTok, $outputTok, $timeStr, $totalInputTokens, $totalOutputTokens) -ForegroundColor DarkGray
            
            # Show token budget bar
            $maxCtx = if ($script:ContextLimits.ContainsKey($currentModel)) { 
                $script:ContextLimits[$currentModel] 
            } else { 
                200000  # Default assumption
            }
            Show-TokenBar -Used $inputTok -Max $maxCtx
            
            # Additional warning when critically full
            if ($inputTok -gt ($maxCtx * 0.85)) {
                Write-Host ('  [!] Context {0}% full. Consider /clear soon.' -f [math]::Floor(($inputTok / $maxCtx) * 100)) -ForegroundColor Red
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
try {
    Start-HatzChat -ApiBaseUrl $ApiBaseUrl -ApiKey $resolvedKey -Model $selectedModel -MaxHistory $MaxHistory
}
finally {
    Write-Host ''
    Write-Host 'Goodbye!' -ForegroundColor Cyan
}