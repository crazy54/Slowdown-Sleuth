<#
.SYNOPSIS
Collects Windows performance samples, audits logs, and builds slowdown diagnostics.

.DESCRIPTION
SpikeSleuth captures CPU/memory/disk/network activity, event channels, and
application log hits, then writes CSV/JSON/Markdown outputs and an HTML dashboard.
Use `--help` for the full formatted option guide.

.PARAMETER DurationMinutes
How long to collect live samples.

.PARAMETER SampleIntervalSeconds
Live sampling interval in seconds.

.PARAMETER LookbackHours
How far back to read events/app activity.

.PARAMETER OutputDir
Explicit output folder for this run.

.PARAMETER OutputRoot
Root folder where per-run output folders are created.

.PARAMETER RunName
Friendly run folder name.

.PARAMETER AppLogPaths
Application log file paths to scan.

.PARAMETER AppLogTailLines
Maximum lines to read per app log.

.PARAMETER SkipLiveCollection
Skip live sampling and perform log audit only.

.PARAMETER EnableSpikeEtwCapture
Capture ETW traces during detected spikes.

.PARAMETER SpikeEtwDurationSeconds
Length of each ETW spike capture.

.PARAMETER SpikeEtwCooldownMinutes
Cooldown between ETW captures.

.PARAMETER MaxSpikeEtwCaptures
Maximum ETW captures in a run.

.PARAMETER EventReadThreads
Event log read parallelism.

.PARAMETER EventAuditMaxRecordsPerLog
Max event records read per channel.

.PARAMETER NoHtmlReport
Disable dashboard generation.

.PARAMETER EnableHtmlReport
Force dashboard generation.

.PARAMETER OpenDashboard
Open dashboard after run.

.PARAMETER SuppressMissingWheaWarning
Suppress warning if WHEA channel is unavailable.

.PARAMETER EnableFrozenSnapshot
Zip artifacts into a frozen snapshot.

.PARAMETER InteractiveWizard
Launch guided CLI wizard.

.PARAMETER Help
Shows built-in help text. Also supports `--help`, `-h`, and `-?`.

.PARAMETER SaveBaseline
Save current run summary as baseline.

.PARAMETER UseBaseline
Compare run summary against baseline.

.PARAMETER BaselinePath
Path to baseline JSON.

.PARAMETER ServiceMode
Service-style recurring runs with retention.

.PARAMETER ServiceRetentionDays
Days to keep historical service runs.

.PARAMETER EnableGenAiAssist
Generate GenAI review from collected data.

.PARAMETER GenAiProvider
`openai` or `bedrock`.

.PARAMETER GenAiModel
OpenAI model id.

.PARAMETER GenAiApiKey
OpenAI API key value.

.PARAMETER GenAiApiKeyEnvVar
Environment variable name that stores API key.

.PARAMETER GenAiApiKeyPersist
API key persistence scope.

.PARAMETER GenAiApiKeyCachePath
Path for secure key cache.

.PARAMETER UseCachedApiKey
Read cached API key from secure file.

.PARAMETER BedrockRegion
AWS region for Bedrock.

.PARAMETER BedrockModelId
Bedrock model or inference profile id.

.PARAMETER BedrockProfile
AWS CLI profile name.

.PARAMETER BedrockUseSsoProfile
Use SSO-backed profile flow.

.PARAMETER TestBedrockSetup
Validate AWS auth and Bedrock connectivity.

.PARAMETER BedrockTestInvokeModel
Also perform a small Bedrock invoke test.

.PARAMETER SecretSyntheticData
Inject synthetic samples/events for testing UI.

.PARAMETER UserPerspectiveNotes
End-user symptom notes appended to report context.

.PARAMETER ContinuousMode
Run repeatedly until stopped.

.PARAMETER ContinuousCycleMinutes
Minutes per loop in continuous mode.

.EXAMPLE
.\spikesleuth.ps1

.EXAMPLE
.\spikesleuth.ps1 --help

.EXAMPLE
.\spikesleuth.ps1 -DurationMinutes 10 -SampleIntervalSeconds 1 -EnableHtmlReport
#>
[CmdletBinding(PositionalBinding = $false)]
param(
  [int]$DurationMinutes = 20,
  [int]$SampleIntervalSeconds = 5,
  [int]$LookbackHours = 24,
  [string]$OutputDir = '',
  [string]$OutputRoot = '',
  [string]$RunName = '',
  [string[]]$AppLogPaths = @(),
  [int]$AppLogTailLines = 20000,
  [switch]$SkipLiveCollection,
  [switch]$EnableSpikeEtwCapture,
  [int]$SpikeEtwDurationSeconds = 15,
  [int]$SpikeEtwCooldownMinutes = 10,
  [int]$MaxSpikeEtwCaptures = 3,
  [int]$EventReadThreads = 4,
  [int]$EventAuditMaxRecordsPerLog = 8000,
  [switch]$NoHtmlReport,
  [switch]$EnableHtmlReport,
  [switch]$OpenDashboard,
  [switch]$SuppressMissingWheaWarning,
  [switch]$EnableFrozenSnapshot,
  [switch]$InteractiveWizard,
  [Alias('?','h')][switch]$Help,
  [switch]$SaveBaseline,
  [switch]$UseBaseline,
  [string]$BaselinePath = ".\baseline.json",
  [switch]$ServiceMode,
  [int]$ServiceRetentionDays = 7,
  [switch]$EnableGenAiAssist,
  [ValidateSet('openai','bedrock')][string]$GenAiProvider = 'openai',
  [string]$GenAiModel = 'gpt-4.1-mini',
  [string]$GenAiApiKey = '',
  [string]$GenAiApiKeyEnvVar = 'OPENAI_API_KEY',
  [ValidateSet('none','process','user','machine','securefile')][string]$GenAiApiKeyPersist = 'none',
  [string]$GenAiApiKeyCachePath = ".\.secrets\openai_api_key.secure.txt",
  [switch]$UseCachedApiKey,
  [string]$BedrockRegion = 'us-east-1',
  [string]$BedrockModelId = 'anthropic.claude-opus-4-6-v1',
  [string]$BedrockProfile = '',
  [switch]$BedrockUseSsoProfile,
  [switch]$TestBedrockSetup,
  [switch]$BedrockTestInvokeModel,
  [switch]$SecretSyntheticData,
  [string]$UserPerspectiveNotes = '',
  [switch]$ContinuousMode,
  [int]$ContinuousCycleMinutes = 3,
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-ScriptHelp {
  $helpText = @"
SpikeSleuth - Windows slowdown collector and analyzer

USAGE
  .\spikesleuth.ps1
  .\spikesleuth.ps1 -?
  .\spikesleuth.ps1 --help
  .\spikesleuth.ps1 -InteractiveWizard
  .\spikesleuth.ps1 -DurationMinutes 10 -SampleIntervalSeconds 1 -EnableHtmlReport

CORE COLLECTION
  -DurationMinutes <int>            Capture length in minutes (default: 20)
  -SampleIntervalSeconds <int>      Sampling interval in seconds (recommended 1-10)
  -LookbackHours <int>              Event/app log lookback window (default: 24)
  -SkipLiveCollection               Skip sampling, only audit logs/files
  -EnableSpikeEtwCapture            Trigger ETW captures during spike windows
  -SpikeEtwDurationSeconds <int>    ETW capture length for each spike (default: 15)
  -SpikeEtwCooldownMinutes <int>    Cooldown between ETW captures (default: 10)
  -MaxSpikeEtwCaptures <int>        Maximum ETW captures per run (default: 3)
  -SecretSyntheticData              Inject synthetic data for UI/testing

OUTPUT AND REPORTING
  -OutputDir <path>                 Explicit run output folder
  -OutputRoot <path>                Parent folder for generated run folders
  -RunName <name>                   Friendly run name; default is timestamp
  -EnableHtmlReport                 Generate dashboard.html
  -NoHtmlReport                     Skip dashboard generation
  -OpenDashboard                    Open dashboard in default browser
  -EnableFrozenSnapshot             Zip important artifacts for sharing

LOG INPUTS
  -AppLogPaths <paths[]>            One or more app log files to parse
  -AppLogTailLines <int>            Max tail lines to scan per app log (default: 20000)
  -EventReadThreads <int>           Parallelism for event log reads (default: 4)
  -EventAuditMaxRecordsPerLog <int> Max events read per channel (default: 8000)
  -SuppressMissingWheaWarning       Suppress warning when WHEA channel is unavailable

BASELINES AND CONTINUOUS MODE
  -SaveBaseline                     Save current metrics to baseline file
  -UseBaseline                      Compare run to baseline file
  -BaselinePath <path>              Baseline file path (default: .\baseline.json)
  -ContinuousMode                   Run in loop mode until Ctrl+C
  -ContinuousCycleMinutes <int>     Minutes per loop cycle (default: 3)
  During live capture, press Ctrl+Shift+Q (or Ctrl+Q) to stop sampling early but still finish report + GenAI.
  -ServiceMode                      Service-style loop + retention summaries
  -ServiceRetentionDays <int>       Retention for service runs (default: 7)

GENAI ASSIST (OPENAI OR BEDROCK)
  -EnableGenAiAssist                Generate GenAI review files
  -GenAiProvider <openai|bedrock>   Provider selection (default: openai)
  -GenAiModel <id>                  OpenAI model (default: gpt-4.1-mini)
  -GenAiApiKey <key>                OpenAI API key
  -GenAiApiKeyEnvVar <name>         Env var for API key (default: OPENAI_API_KEY)
  -GenAiApiKeyPersist <scope>       none|process|user|machine|securefile
  -GenAiApiKeyCachePath <path>      Secure key cache file path
  -UseCachedApiKey                  Use cached key from secure file

BEDROCK OPTIONS
  -BedrockRegion <region>           AWS region (default: us-east-1)
  -BedrockModelId <id>              Model or inference profile id
  -BedrockProfile <name>            AWS CLI profile to use
  -BedrockUseSsoProfile             Enable profile-based SSO flow
  -TestBedrockSetup                 Validate auth + Bedrock connectivity
  -BedrockTestInvokeModel           Also run a tiny invoke-model/converse test

MISC
  -UserPerspectiveNotes <text>      Notes included in report context
  -InteractiveWizard                Start guided CLI wizard (includes AI review for existing run folders)
  -Help, -h, -?, --help             Show this help and exit
"@
  Write-Host $helpText
}

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Add-Warn($list, [string]$msg) {
  [void]$list.Add([pscustomobject]@{ Time = Get-Date; Message = $msg })
}

function Get-CleanExceptionMessage([System.Management.Automation.ErrorRecord]$err) {
  # Strip PowerShell script context lines ("At C:\...:line N char:N + ...") from exception messages
  # so they don't pollute user-facing reports with internal script details.
  $msg = $err.Exception.Message
  if ([string]::IsNullOrWhiteSpace($msg)) { return 'Unknown error' }
  # Remove everything from "At <path>:" onward (PS adds this for ProcessStartException etc.)
  $msg = ($msg -replace '(?s)\s*At\s+\S+:\d+\s+char:\d+.*','').Trim()
  # Also strip trailing period-only lines
  $msg = ($msg -replace '\.\s*$','').Trim()
  return $msg
}

function Normalize-GenAiPayloadText([string]$rawText) {
  if ([string]::IsNullOrWhiteSpace($rawText)) { return '' }
  $txt = [string]$rawText
  $txt = $txt.Trim()
  # Strip fenced code block markers
  $txt = ($txt -replace '^\s*\*?```(?:json|markdown|md|text)?\s*','')
  $txt = ($txt -replace '\s*```\*?\s*$','')
  $txt = $txt.Trim()
  # Strip AWS CLI --output text metadata header (e.g. "max_tokens\nMETRICS\t...\nMESSAGE\t...\nCONTENT\t\n\n")
  $txt = ($txt -replace '(?m)^(?:[A-Z_]+(?:\t[^\r\n]*)?\r?\n)+\r?\n?', '').Trim()
  # Try to parse as JSON FIRST (before any \n substitution which would break JSON.parse)
  $start = $txt.IndexOf('{')
  $end = $txt.LastIndexOf('}')
  if ($start -ge 0 -and $end -gt $start) {
    $slice = $txt.Substring($start, ($end - $start + 1))
    try {
      $null = $slice | ConvertFrom-Json -ErrorAction Stop
      return $slice
    } catch {}
  }
  # Not JSON — normalize escape sequences for plain text
  $txt = ($txt -replace '\\r','' -replace '\\n',"`n")
  # Fix common UTF-8-as-CP1252 mojibake sequences that survive the AWS CLI pipeline
  $txt = $txt.Replace('ΓÇö','—').Replace('ΓÇô','–').Replace('ΓåÆ','→').Replace('Γåæ','←')
  $txt = $txt.Replace('ΓÇÿ',"'").Replace('ΓÇÖ',"'").Replace('ΓÇ£','"').Replace('ΓÇ¥','"')
  $txt = $txt.Replace('ΓÇó','•').Replace('ΓÇó','·')
  return $txt.Trim()
}

function Convert-GenAiLooseTextToDisplay([string]$text) {
  if ([string]::IsNullOrWhiteSpace($text)) { return '' }
  $linesIn = ($text -replace '\r\n',"`n" -replace '\r',"`n").Split("`n")
  $out = New-Object System.Collections.Generic.List[string]
  $sectionNames = @(
    'Summary','Diagnostic Tests','Fix Plan','Alternative Root Causes','Superuser Improvements','Output Text'
  )
  foreach ($raw in $linesIn) {
    $line = [string]$raw
    $trim = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trim)) { [void]$out.Add(''); continue }

    if ($trim -match '^(?:#{1,6}\s*)?(Summary|Diagnostic Tests|Fix Plan|Alternative Root Causes|Superuser Improvements|Output Text)\s*:?\s*$') {
      [void]$out.Add(("**__{0}__**" -f $matches[1]))
      [void]$out.Add('')
      continue
    }
    if ($trim -match '^(?:#{1,6}\s*)?(Test\s+\d+|Action\s+\d+)\s*:?\s*$') {
      [void]$out.Add(("**__{0}__**" -f $matches[1]))
      [void]$out.Add('')
      continue
    }
    if ($trim -match '^(Test|Why|How To Run|Expected Signal|Priority|Action|Risk|Cause|Confidence|Evidence|Links)\s*:\s*(.*)$') {
      [void]$out.Add(("**__{0}:__**" -f $matches[1]))
      if (-not [string]::IsNullOrWhiteSpace($matches[2])) { [void]$out.Add(("*{0}*" -f $matches[2].Trim())) }
      [void]$out.Add('')
      continue
    }
    if ($trim -match '^\-\s+(.+)$') {
      [void]$out.Add(("- *{0}*" -f $matches[1].Trim()))
      continue
    }
    [void]$out.Add(("*{0}*" -f $trim))
  }
  $final = ($out -join [Environment]::NewLine).Trim()
  if ([string]::IsNullOrWhiteSpace($final)) {
    return (@('**__Output Text__**','',("*{0}*" -f $text.Trim())) -join [Environment]::NewLine)
  }
  if ($sectionNames | Where-Object { $final -match ("\*\*__{0}__\*\*" -f [regex]::Escape($_)) }) { return $final }
  return (@('**__Output Text__**','',$final) -join [Environment]::NewLine)
}

function Format-GenAiTextForDisplay([string]$rawText) {
  if ([string]::IsNullOrWhiteSpace($rawText)) { return '' }
  $rawText = Normalize-GenAiPayloadText -rawText $rawText
  if ($rawText -match '(?m)^\s*##\s+(Summary|Diagnostic Tests|Fix Plan|Alternative Root Causes|Superuser Improvements)\s*$') {
    return $rawText.Trim()
  }
  function Try-Parse-JsonLoose([string]$txt) {
    try { return ($txt | ConvertFrom-Json -ErrorAction Stop) } catch {}
    $start = $txt.IndexOf('{')
    $end = $txt.LastIndexOf('}')
    if ($start -ge 0 -and $end -gt $start) {
      $slice = $txt.Substring($start, ($end - $start + 1))
      try { return ($slice | ConvertFrom-Json -ErrorAction Stop) } catch {}
    }
    return $null
  }
  try {
    $obj = Try-Parse-JsonLoose -txt $rawText
    if ($null -eq $obj) {
      return (Convert-GenAiLooseTextToDisplay -text $rawText)
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $summary = if ($obj.PSObject.Properties.Name -contains 'summary') { [string]$obj.summary } else { '' }
    if (-not [string]::IsNullOrWhiteSpace($summary)) {
      [void]$lines.Add('**__Summary__**')
      [void]$lines.Add('')
      [void]$lines.Add("*$summary*")
      [void]$lines.Add('')
    }

    if ($obj.PSObject.Properties.Name -contains 'diagnostic_tests' -and $obj.diagnostic_tests) {
      [void]$lines.Add('**__Diagnostic Tests__**')
      [void]$lines.Add('')
      $idx = 0
      foreach ($t in @($obj.diagnostic_tests)) {
        $idx++
        [void]$lines.Add("**__Test $idx__**")
        [void]$lines.Add('')
        if ($t.PSObject.Properties.Name -contains 'test' -and $t.test) { [void]$lines.Add("**__Test:__**"); [void]$lines.Add("*$([string]$t.test)*"); [void]$lines.Add('') }
        if ($t.PSObject.Properties.Name -contains 'why' -and $t.why) { [void]$lines.Add("**__Why:__**"); [void]$lines.Add("*$([string]$t.why)*"); [void]$lines.Add('') }
        if ($t.PSObject.Properties.Name -contains 'how_to_run' -and $t.how_to_run) { [void]$lines.Add("**__How To Run:__**"); [void]$lines.Add("*$([string]$t.how_to_run)*"); [void]$lines.Add('') }
        if ($t.PSObject.Properties.Name -contains 'expected_signal' -and $t.expected_signal) { [void]$lines.Add("**__Expected Signal:__**"); [void]$lines.Add("*$([string]$t.expected_signal)*"); [void]$lines.Add('') }
      }
    }

    if ($obj.PSObject.Properties.Name -contains 'fix_plan' -and $obj.fix_plan) {
      [void]$lines.Add('**__Fix Plan__**')
      [void]$lines.Add('')
      $idx = 0
      foreach ($f in @($obj.fix_plan)) {
        $idx++
        [void]$lines.Add("**__Action $idx__**")
        [void]$lines.Add('')
        if ($f.PSObject.Properties.Name -contains 'priority' -and $f.priority) { [void]$lines.Add("**__Priority:__**"); [void]$lines.Add("*$([string]$f.priority)*"); [void]$lines.Add('') }
        if ($f.PSObject.Properties.Name -contains 'action' -and $f.action) { [void]$lines.Add("**__Action:__**"); [void]$lines.Add("*$([string]$f.action)*"); [void]$lines.Add('') }
        if ($f.PSObject.Properties.Name -contains 'risk' -and $f.risk) { [void]$lines.Add("**__Risk:__**"); [void]$lines.Add("*$([string]$f.risk)*"); [void]$lines.Add('') }
      }
    }

    if ($obj.PSObject.Properties.Name -contains 'alternative_root_causes' -and $obj.alternative_root_causes) {
      [void]$lines.Add('**__Alternative Root Causes__**')
      [void]$lines.Add('')
      foreach ($c in @($obj.alternative_root_causes)) {
        if ($c.PSObject.Properties.Name -contains 'cause' -and $c.cause) { [void]$lines.Add("**__Cause:__**"); [void]$lines.Add("*$([string]$c.cause)*"); [void]$lines.Add('') }
        if ($c.PSObject.Properties.Name -contains 'confidence' -and $c.confidence) { [void]$lines.Add("**__Confidence:__**"); [void]$lines.Add("*$([string]$c.confidence)*"); [void]$lines.Add('') }
        if ($c.PSObject.Properties.Name -contains 'evidence' -and $c.evidence) { [void]$lines.Add("**__Evidence:__**"); [void]$lines.Add("*$([string]$c.evidence)*"); [void]$lines.Add('') }
        if ($c.PSObject.Properties.Name -contains 'links' -and $c.links) { [void]$lines.Add("**__Links:__**"); [void]$lines.Add("*$([string]$c.links)*"); [void]$lines.Add('') }
      }
    }

    if ($obj.PSObject.Properties.Name -contains 'superuser_improvements' -and $obj.superuser_improvements) {
      [void]$lines.Add('**__Superuser Improvements__**')
      [void]$lines.Add('')
      foreach ($s in @($obj.superuser_improvements)) {
        [void]$lines.Add("- *$([string]$s)*")
      }
      [void]$lines.Add('')
    }

    if ($lines.Count -eq 0) {
      return (@(
        '**__Output Text__**',
        '',
        ("*{0}*" -f $rawText)
      ) -join [Environment]::NewLine)
    }
    return ($lines -join [Environment]::NewLine)
  } catch {
    return (Convert-GenAiLooseTextToDisplay -text $rawText)
  }
}

function Write-Stage([string]$phase,[string]$message) {
  $stamp = (Get-Date).ToString('o')
  Write-Host ("[{0}] [{1}] {2}" -f $stamp, $phase, $message)
}

function Format-ByteSize([double]$bytes) {
  if ($bytes -lt 1KB) { return ("{0} B" -f [Math]::Round($bytes,0)) }
  if ($bytes -lt 1MB) { return ("{0} KB" -f [Math]::Round(($bytes / 1KB),2)) }
  if ($bytes -lt 1GB) { return ("{0} MB" -f [Math]::Round(($bytes / 1MB),2)) }
  return ("{0} GB" -f [Math]::Round(($bytes / 1GB),2))
}

function Write-Flow([string]$direction,[double]$bytes,[string]$provider,[string]$model,[string]$extra='') {
  $dirGlyph = if ($direction -eq 'OUT') { '>>>>' } else { '<<<<' }
  $sizeTxt = Format-ByteSize -bytes $bytes
  $suffix = if ([string]::IsNullOrWhiteSpace($extra)) { '' } else { " | $extra" }
  Write-Stage ("GENAI-{0}" -f $direction) ("{0} {1} | provider={2} | model={3} | size={4}{5}" -f $dirGlyph, $direction, $provider, $model, $sizeTxt, $suffix)
}

function Start-WaitPhase([string]$phase,[string]$message,[int]$etaSeconds = 0) {
  $ctx = [pscustomobject]@{
    Phase = $phase
    Started = Get-Date
    EtaSeconds = [Math]::Max($etaSeconds,0)
  }
  if ($ctx.EtaSeconds -gt 0) {
    Write-Stage $phase ("{0} | ETA ~{1}s" -f $message, $ctx.EtaSeconds)
  } else {
    Write-Stage $phase $message
  }
  return $ctx
}

function Stop-WaitPhase($ctx,[string]$suffix='Done') {
  if ($null -eq $ctx) { return }
  $elapsed = (Get-Date) - $ctx.Started
  Write-Stage $ctx.Phase ("{0} | elapsed {1:N1}s" -f $suffix, $elapsed.TotalSeconds)
}

function Update-GenAiProgress([int]$percent,[string]$status,[switch]$Done) {
  try {
    if ($Done) {
      Write-Progress -Activity 'GenAI Review' -Status $status -PercentComplete 100 -Completed
      return
    }
    $pct = [Math]::Min([Math]::Max($percent,0),100)
    Write-Progress -Activity 'GenAI Review' -Status $status -PercentComplete $pct
  } catch {}
}

function Format-RemainingClock([timespan]$span) {
  if ($span.TotalSeconds -lt 0) { $span = [timespan]::Zero }
  $hours = [int][Math]::Floor($span.TotalHours)
  return "{0:00}:{1:00}:{2:00}" -f $hours, $span.Minutes, $span.Seconds
}

function Test-RunStopCombo {
  try {
    while ([Console]::KeyAvailable) {
      $key = [Console]::ReadKey($true)
      $isCtrl = (($key.Modifiers -band [ConsoleModifiers]::Control) -ne 0)
      if ($isCtrl -and $key.Key -eq [ConsoleKey]::Q) { return $true }
    }
  } catch {}
  return $false
}

function To-ObjectArray($items) {
  $tmp = New-Object System.Collections.Generic.List[object]
  foreach ($i in $items) {
    [void]$tmp.Add($i)
  }
  return ,($tmp.ToArray())
}

function ConvertTo-JsonArrayText($items, [int]$Depth = 6) {
  $arr = To-ObjectArray $items
  if ($arr.Length -eq 0) { return '[]' }
  return ($arr | ConvertTo-Json -Depth $Depth)
}

function Protect-ForHtmlScript([string]$text) {
  if ($null -eq $text) { return 'null' }
  $t = [string]$text
  $t = $t.Replace('</','<\/')
  $t = $t.Replace([string][char]0x2028,'\u2028')
  $t = $t.Replace([string][char]0x2029,'\u2029')
  return $t
}

function Export-CsvResilient {
  param(
    [Parameter(Mandatory = $true)]$InputObject,
    [Parameter(Mandatory = $true)][string]$Path,
    [int]$Retries = 3,
    [int]$DelayMs = 450
  )

  for ($attempt = 1; $attempt -le $Retries; $attempt++) {
    try {
      $InputObject | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
      return $Path
    }
    catch {
      if ($attempt -lt $Retries) {
        Start-Sleep -Milliseconds $DelayMs
        continue
      }
    }
  }

  $dir = Split-Path -Path $Path -Parent
  $name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
  $ext = [System.IO.Path]::GetExtension($Path)
  $fallback = Join-Path $dir ("{0}-{1}{2}" -f $name, (Get-Date).ToString('yyyyMMdd-HHmmss'), $ext)
  $InputObject | Export-Csv -LiteralPath $fallback -NoTypeInformation -Encoding UTF8
  return $fallback
}

function Safe-Counter([string]$class,[string]$prop,[string]$filter) {
  try {
    $obj = if ($filter) { Get-CimInstance -ClassName $class -Filter $filter -ErrorAction Stop } else { Get-CimInstance -ClassName $class -ErrorAction Stop }
    if ($null -eq $obj) { return $null }
    return [double]($obj.$prop)
  } catch { return $null }
}

function Get-NetworkSnapshot {
  try {
    $nics = @(Get-CimInstance -ClassName Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction Stop)
    if ($nics.Count -eq 0) {
      return [pscustomobject]@{ RecvMbps = 0.0; SendMbps = 0.0; AdapterSummary = ''; TopNetworkProcesses = '' }
    }
    $usable = @($nics | Where-Object { $_.Name -notmatch '(?i)loopback|isatap|teredo' })
    if ($usable.Count -eq 0) { $usable = $nics }
    $recvBps = ($usable | Measure-Object -Property BytesReceivedPersec -Sum).Sum
    $sendBps = ($usable | Measure-Object -Property BytesSentPersec -Sum).Sum
    $topAdapters = @($usable | Sort-Object BytesTotalPersec -Descending | Select-Object -First 3)
    $adapterSummary = ($topAdapters | ForEach-Object {
      $mbps = [Math]::Round((([double]$_.BytesTotalPersec) * 8.0) / 1MB, 2)
      "{0}={1}Mb/s" -f $_.Name, $mbps
    }) -join '; '

    $topNetProcs = ''
    try {
      $tcp = @(Get-NetTCPConnection -State Established -ErrorAction Stop)
      if ($tcp.Count -gt 0) {
        $procMap = @{}
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procMap[$p.Id] = $p.ProcessName }
        $topNetProcs = ($tcp | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
          $pid = [int]$_.Name
          $pname = if ($procMap.ContainsKey($pid)) { $procMap[$pid] } else { "PID$pid" }
          "{0}({1})={2} conn" -f $pname, $pid, $_.Count
        }) -join '; '
      }
    } catch { $topNetProcs = '' }

    return [pscustomobject]@{
      RecvMbps = [Math]::Round((([double]$recvBps) * 8.0) / 1MB, 2)
      SendMbps = [Math]::Round((([double]$sendBps) * 8.0) / 1MB, 2)
      AdapterSummary = $adapterSummary
      TopNetworkProcesses = $topNetProcs
    }
  } catch {
    return [pscustomobject]@{ RecvMbps = 0.0; SendMbps = 0.0; AdapterSummary = ''; TopNetworkProcesses = '' }
  }
}

function Get-TraceEngine {
  if (Get-Command wpr.exe -ErrorAction SilentlyContinue) { return 'wpr' }
  if (Get-Command xperf.exe -ErrorAction SilentlyContinue) { return 'xperf' }
  return 'none'
}

function Capture-SpikeTrace([string]$engine,[string]$dir,[datetime]$ts,[int]$seconds,$warnings) {
  if ($engine -eq 'none') { return $null }
  $etl = Join-Path $dir ("spike-{0}.etl" -f $ts.ToString('yyyyMMdd-HHmmss'))
  try {
    if ($engine -eq 'wpr') {
      & wpr.exe -cancel *> $null
      & wpr.exe -start GeneralProfile -filemode | Out-Null
      Start-Sleep -Seconds $seconds
      & wpr.exe -stop $etl | Out-Null
    } else {
      & xperf.exe -on PROC_THREAD+LOADER+DISK_IO+DISK_IO_INIT+PROFILE -stackwalk Profile -f $etl | Out-Null
      Start-Sleep -Seconds $seconds
      & xperf.exe -d $etl | Out-Null
    }
    return [pscustomobject]@{ TimeCreated = Get-Date; Engine = $engine; Path = $etl; DurationSeconds = $seconds; Status = 'Captured' }
  } catch {
    Add-Warn $warnings "ETW capture failed: $($_.Exception.Message)"
    try { if ($engine -eq 'wpr') { & wpr.exe -cancel *> $null } } catch {}
    return [pscustomobject]@{ TimeCreated = Get-Date; Engine = $engine; Path = $etl; DurationSeconds = $seconds; Status = 'Failed' }
  }
}

function Get-LiveSamples([int]$minutes,[int]$interval,[string]$outDir,[bool]$enableEtw,[string]$traceEngine,[int]$traceSeconds,[int]$traceCooldown,[int]$traceMax,$warnings) {
  $cores = [Math]::Max([Environment]::ProcessorCount,1)
  $samples = New-Object System.Collections.Generic.List[object]
  $hotspots = New-Object System.Collections.Generic.List[object]
  $traces = New-Object System.Collections.Generic.List[object]
  $cpuPrev = @{}
  $ioPrev = @{}
  $lastTrace = $null
  $startedAt = Get-Date
  $deadline = $startedAt.AddMinutes($minutes)
  $warnedEtwNearEnd = $false
  $stopRequested = $false
  $stopReason = ''
  $countdownLineDrawn = $false
  $i = 0

  Write-Host ("Live capture start: {0}" -f $startedAt.ToString('yyyy-MM-dd HH:mm:ss'))
  Write-Host ("Expected live capture end: {0}" -f $deadline.ToString('yyyy-MM-dd HH:mm:ss'))
  Write-Host 'Press Ctrl+Shift+Q (or Ctrl+Q) to stop capture early and continue report + GenAI.'

  while ((Get-Date) -lt $deadline) {
    if (Test-RunStopCombo) {
      $stopRequested = $true
      $stopReason = 'Live capture stopped early by user key combo; continuing with report generation.'
      break
    }

    $i++
    $t = Get-Date
    $cpu = Safe-Counter 'Win32_PerfFormattedData_PerfOS_Processor' 'PercentProcessorTime' "Name='_Total'"
    $q = Safe-Counter 'Win32_PerfFormattedData_PerfOS_System' 'ProcessorQueueLength' $null
    $mem = Safe-Counter 'Win32_PerfFormattedData_PerfOS_Memory' 'AvailableMBytes' $null
    $pages = Safe-Counter 'Win32_PerfFormattedData_PerfOS_Memory' 'PagesInputPersec' $null
    $dq = Safe-Counter 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' 'AvgDiskQueueLength' "Name='_Total'"
    $db = Safe-Counter 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' 'PercentDiskTime' "Name='_Total'"
    $dpc = Safe-Counter 'Win32_PerfFormattedData_PerfOS_Processor' 'PercentDPCTime' "Name='_Total'"
    $isr = Safe-Counter 'Win32_PerfFormattedData_PerfOS_Processor' 'PercentInterruptTime' "Name='_Total'"
    $net = Get-NetworkSnapshot

    $top = ''
    $topMem = ''
    $topIo = ''
    $topNet = $net.TopNetworkProcesses
    try {
      $snap = foreach ($p in (Get-Process | Where-Object { $null -ne $_.CPU })) {
        $prev = if ($cpuPrev.ContainsKey($p.Id)) { $cpuPrev[$p.Id] } else { $null }
        $delta = if ($null -ne $prev) { [Math]::Max($p.CPU-$prev,0) } else { 0 }
        $pct = ($delta / $interval / $cores) * 100
        $cpuPrev[$p.Id] = $p.CPU
        $ioNow = 0
        if ($null -ne $p.PSObject.Properties['IOReadBytes'] -and $null -ne $p.PSObject.Properties['IOWriteBytes']) {
          $ioNow = [double]($p.IOReadBytes + $p.IOWriteBytes)
        }
        $ioPrevVal = if ($ioPrev.ContainsKey($p.Id)) { $ioPrev[$p.Id] } else { $null }
        $ioDelta = if ($null -ne $ioPrevVal) { [Math]::Max($ioNow - $ioPrevVal,0) } else { 0 }
        $ioPrev[$p.Id] = $ioNow
        $ioMBps = if ($interval -gt 0) { ($ioDelta / 1MB) / $interval } else { 0 }
        [pscustomobject]@{
          ProcessName=$p.ProcessName
          Id=$p.Id
          CpuPct=[Math]::Round($pct,2)
          WorkingSetMB=[Math]::Round($p.WorkingSet64/1MB,1)
          IoMBps=[Math]::Round($ioMBps,2)
          Timestamp=$t
        }
      }
      $topRows = $snap | Sort-Object CpuPct -Descending | Select-Object -First 5
      $topMemRows = $snap | Sort-Object WorkingSetMB -Descending | Select-Object -First 5
      $topIoRows = $snap | Sort-Object IoMBps -Descending | Select-Object -First 5
      $top = ($topRows | ForEach-Object { "{0}({1})={2}%" -f $_.ProcessName,$_.Id,$_.CpuPct }) -join '; '
      $topMem = ($topMemRows | ForEach-Object { "{0}({1})={2}MB" -f $_.ProcessName,$_.Id,$_.WorkingSetMB }) -join '; '
      $topIo = ($topIoRows | ForEach-Object { "{0}({1})={2}MB/s" -f $_.ProcessName,$_.Id,$_.IoMBps }) -join '; '
      foreach ($r in $topRows) { [void]$hotspots.Add($r) }
      foreach ($r in $topMemRows) { [void]$hotspots.Add([pscustomobject]@{ Timestamp=$r.Timestamp; ProcessName=$r.ProcessName; Id=$r.Id; ResourceType='Memory'; Value=$r.WorkingSetMB }) }
      foreach ($r in $topIoRows) { [void]$hotspots.Add([pscustomobject]@{ Timestamp=$r.Timestamp; ProcessName=$r.ProcessName; Id=$r.Id; ResourceType='DiskIO'; Value=$r.IoMBps }) }
    } catch { $top = "process sampling failed: $($_.Exception.Message)" }

    $isSpike = ($cpu -ge 85) -or (($dq -ge 2) -and ($db -ge 80)) -or ($pages -ge 1500) -or ($mem -le 700)
    [void]$samples.Add([pscustomobject]@{
      Timestamp=$t
      CpuPct=$cpu
      CpuQueueLength=$q
      MemoryAvailableMB=$mem
      PagesInputPerSec=$pages
      DiskQueueLength=$dq
      DiskBusyPct=$db
      DpcPct=$dpc
      InterruptPct=$isr
      IsSpike=$isSpike
      TopCpuProcesses=$top
      TopMemoryProcesses=$topMem
      TopIoProcesses=$topIo
      TopNetworkProcesses=$topNet
      NetworkRecvMbps=$net.RecvMbps
      NetworkSendMbps=$net.SendMbps
      TopAdapters=$net.AdapterSummary
    })

    if ($enableEtw -and $isSpike) {
      $can = $traces.Count -lt $traceMax
      if ($can -and $null -ne $lastTrace) { $can = ((New-TimeSpan -Start $lastTrace -End $t).TotalMinutes -ge $traceCooldown) }
      if ($can) {
        $remainingSeconds = ($deadline - (Get-Date)).TotalSeconds
        if ($remainingSeconds -ge ($traceSeconds + 1)) {
          $trace = Capture-SpikeTrace $traceEngine $outDir $t $traceSeconds $warnings
          if ($null -ne $trace) { [void]$traces.Add($trace); $lastTrace = $t }
        }
        elseif (-not $warnedEtwNearEnd) {
          Add-Warn $warnings 'Skipped ETW capture near end of run to honor DurationMinutes wall-clock limit.'
          $warnedEtwNearEnd = $true
        }
      }
    }

    $nextTick = $t.AddSeconds($interval)
    while ((Get-Date) -lt $nextTick) {
      if (Test-RunStopCombo) {
        $stopRequested = $true
        $stopReason = 'Live capture stopped early by user key combo; continuing with report generation.'
        break
      }
      $remaining = $deadline - (Get-Date)
      $status = "Countdown: {0} remaining (ETA {1})" -f (Format-RemainingClock $remaining), $deadline.ToString('HH:mm:ss')
      Write-Host ("`r{0}" -f $status.PadRight(76)) -NoNewline
      $countdownLineDrawn = $true
      $sleepMs = [int][Math]::Min(250, [Math]::Max((($nextTick - (Get-Date)).TotalMilliseconds), 1))
      Start-Sleep -Milliseconds $sleepMs
    }
    if ($stopRequested) { break }
  }

  if ($countdownLineDrawn) { Write-Host '' }
  [pscustomobject]@{ Samples=$samples; Hotspots=$hotspots; Traces=$traces; StopRequested=$stopRequested; StopReason=$stopReason }
}

function Get-SpikeWindows($samples) {
  $spikes = @($samples | Where-Object { $_.IsSpike } | Sort-Object Timestamp)
  if ($spikes.Count -eq 0) { return @() }
  $wins = New-Object System.Collections.Generic.List[object]
  $start = $spikes[0].Timestamp.AddMinutes(-1)
  $end = $spikes[0].Timestamp.AddMinutes(1)
  for ($i=1; $i -lt $spikes.Count; $i++) {
    $t = $spikes[$i].Timestamp
    if ($t -le $end.AddMinutes(2)) {
      $c = $t.AddMinutes(1)
      if ($c -gt $end) { $end = $c }
    } else {
      [void]$wins.Add([pscustomobject]@{ Start=$start; End=$end })
      $start = $t.AddMinutes(-1); $end = $t.AddMinutes(1)
    }
  }
  [void]$wins.Add([pscustomobject]@{ Start=$start; End=$end })
  return $wins
}
function Invoke-RunspaceTasks([object[]]$inputs,[scriptblock]$worker,[int]$throttle=4) {
  if ($inputs.Count -eq 0) { return @() }
  $pool = [RunspaceFactory]::CreateRunspacePool(1,[Math]::Max($throttle,1)); $pool.Open()
  $runs = New-Object System.Collections.Generic.List[object]
  $res = New-Object System.Collections.Generic.List[object]
  try {
    foreach ($item in $inputs) {
      $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
      $null = $ps.AddScript($worker.ToString()).AddArgument($item)
      [void]$runs.Add([pscustomobject]@{ PS=$ps; H=$ps.BeginInvoke() })
    }
    foreach ($r in $runs) {
      try { foreach ($o in @($r.PS.EndInvoke($r.H))) { if ($null -ne $o) { [void]$res.Add($o) } } }
      finally { $r.PS.Dispose() }
    }
  } finally { $pool.Close(); $pool.Dispose() }
  return $res
}

function Get-EventAudit([datetime]$start,[datetime]$end,[int]$max,[int]$threads,$warnings,[bool]$suppressMissingWheaWarning=$false) {
  $candidates = @('System','Application','Microsoft-Windows-Diagnostics-Performance/Operational','Microsoft-Windows-WHEA-Logger/Operational')
  $available = New-Object System.Collections.Generic.List[string]
  foreach ($l in $candidates) {
    try {
      $info = Get-WinEvent -ListLog $l -ErrorAction Stop
      if ($info.IsEnabled) { [void]$available.Add($l) }
    } catch {
      if ($suppressMissingWheaWarning -and $l -eq 'Microsoft-Windows-WHEA-Logger/Operational') {
        continue
      }
      Add-Warn $warnings "Event log unavailable: $l"
    }
  }

  $inputs = foreach ($l in $available) { [pscustomobject]@{ LogName=$l; StartTime=$start; EndTime=$end; Max=$max } }
  $worker = {
    param($in)
    try {
      $ev = Get-WinEvent -FilterHashtable @{ LogName=$in.LogName; StartTime=$in.StartTime; EndTime=$in.EndTime } -MaxEvents $in.Max -ErrorAction Stop
      $rows = New-Object System.Collections.Generic.List[object]
      foreach ($e in $ev) {
        if ($e.Level -in 1,2,3 -or $e.Id -in 7,17,18,19,37,41,51,55,129,153,6008,1000,1001,1002) {
          $m = if ($e.Message) { ($e.Message -replace "`r|`n",' ').Trim() } else { '' }
          if ($m.Length -gt 300) { $m = $m.Substring(0,300) + '...' }
          [void]$rows.Add([pscustomobject]@{ TimeCreated=$e.TimeCreated; LogName=$e.LogName; ProviderName=$e.ProviderName; Id=$e.Id; Level=$e.LevelDisplayName; Message=$m })
        }
      }
      return $rows
    } catch {
      return [pscustomobject]@{ TimeCreated=Get-Date; LogName=$in.LogName; ProviderName='AuditTool'; Id=-1; Level='Warning'; Message="Failed to read log '$($in.LogName)': $($_.Exception.Message)" }
    }
  }
  @((Invoke-RunspaceTasks @($inputs) $worker $threads) | Sort-Object TimeCreated)
}

function Parse-AppLogHits([string[]]$paths,[datetime]$start,[datetime]$end,[int]$tail) {
  $hits = New-Object System.Collections.Generic.List[object]
  if (-not $paths -or $paths.Count -eq 0) { return $hits }
  $rx = @('\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?','\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s*[APMapm]{2})?')
  foreach ($p in $paths) {
    if (-not (Test-Path -LiteralPath $p)) {
      [void]$hits.Add([pscustomobject]@{ TimeCreated=Get-Date; Path=$p; Severity='Warning'; Message='Path not found.' }); continue
    }
    $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer) {
      [void]$hits.Add([pscustomobject]@{ TimeCreated=Get-Date; Path=$p; Severity='Warning'; Message='Path is not a file.' }); continue
    }
    try {
      foreach ($line in (Get-Content -LiteralPath $p -Tail $tail -ErrorAction Stop)) {
        if ($line -notmatch '(?i)error|exception|timeout|hang|failed|critical|install|uninstall|update|rollback|msi|winget') { continue }
        $pt = $null
        foreach ($r in $rx) {
          $m = [regex]::Match($line,$r)
          if ($m.Success) { try { $pt = [datetime]::Parse($m.Value); break } catch {} }
        }
        if ($null -eq $pt) { $pt = $item.LastWriteTime }
        if ($pt -lt $start -or $pt -gt $end) { continue }
        [void]$hits.Add([pscustomobject]@{ TimeCreated=$pt; Path=$p; Severity='Signal'; Message=(if ($line.Length -gt 280) { $line.Substring(0,280)+'...' } else { $line }) })
      }
    } catch {
      [void]$hits.Add([pscustomobject]@{ TimeCreated=Get-Date; Path=$p; Severity='Warning'; Message="Failed to parse file: $($_.Exception.Message)" })
    }
  }
  $hits | Sort-Object TimeCreated
}

function Get-WindowsAppActivityHits([datetime]$start,[datetime]$end,[int]$max = 3000) {
  $hits = New-Object System.Collections.Generic.List[object]
  try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$start; EndTime=$end } -MaxEvents $max -ErrorAction Stop
    foreach ($e in $ev) {
      $provider = if ($e.ProviderName) { $e.ProviderName } else { '' }
      $msg = if ($e.Message) { ($e.Message -replace "`r|`n",' ').Trim() } else { '' }
      $isInstaller = ($provider -match 'MsiInstaller|Windows Installer') -or ($e.Id -in 1033,1034,11707,11708,11724)
      $isSignal = $isInstaller -or ($msg -match '(?i)install|uninstall|update|setup|error|failed|exception')
      if (-not $isSignal) { continue }
      if ($msg.Length -gt 280) { $msg = $msg.Substring(0,280) + '...' }
      [void]$hits.Add([pscustomobject]@{
        TimeCreated = $e.TimeCreated
        Path = "EventLog/Application:$provider"
        Severity = if ($e.LevelDisplayName) { $e.LevelDisplayName } else { 'Info' }
        Message = "EventId=$($e.Id) $msg"
      })
    }
  }
  catch {
    [void]$hits.Add([pscustomobject]@{
      TimeCreated = Get-Date
      Path = 'EventLog/Application'
      Severity = 'Warning'
      Message = "Failed to read Application activity events: $($_.Exception.Message)"
    })
  }
  return @($hits | Sort-Object TimeCreated)
}

function Get-SystemContext {
  $ctx = [ordered]@{}
  try {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -First 1
    $ctx['BiosVersion'] = (($bios.SMBIOSBIOSVersion, $bios.Version -join ' ').Trim())
    $ctx['BiosDate'] = $bios.ReleaseDate
  } catch {}
  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop | Select-Object -First 1
    $ctx['Model'] = "$($cs.Manufacturer) $($cs.Model)".Trim()
    $ctx['TotalPhysicalMemoryGB'] = [Math]::Round(([double]$cs.TotalPhysicalMemory/1GB),2)
  } catch {}
  try {
    $gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 2 Name,DriverVersion,DriverDate)
    if ($gpu.Count -gt 0) { $ctx['GpuDrivers'] = ($gpu | ForEach-Object { "$($_.Name) v$($_.DriverVersion)" }) -join '; ' }
  } catch {}
  try {
    $disk = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object -First 4 Model,FirmwareRevision,InterfaceType)
    if ($disk.Count -gt 0) { $ctx['StorageFirmware'] = ($disk | ForEach-Object { "$($_.Model) fw=$($_.FirmwareRevision) [$($_.InterfaceType)]" }) -join '; ' }
  } catch {}
  try {
    $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceClass -in @('Net','SCSIAdapter','HDC') } | Sort-Object DriverDate -Descending | Select-Object -First 20 DeviceName,DriverVersion,DriverDate,DeviceClass)
    if ($drivers.Count -gt 0) { $ctx['CriticalDrivers'] = ($drivers | ForEach-Object { "$($_.DeviceClass):$($_.DeviceName) v$($_.DriverVersion)" }) -join ' | ' }
  } catch {}
  return [pscustomobject]$ctx
}

function Get-CorrelationMarkers([datetime]$start,[datetime]$end,[int]$max=2000) {
  $markers = New-Object System.Collections.Generic.List[object]
  $queries = @(
    @{ Log='System'; Ids=@(12,13,41,42,1074,6005,6006,6008); Kind='Boot/Power' },
    @{ Log='System'; Ids=@(1); Provider='Microsoft-Windows-Power-Troubleshooter'; Kind='Resume' },
    @{ Log='System'; Ids=@(19,20,21,43,44); Provider='Microsoft-Windows-WindowsUpdateClient'; Kind='Windows Update' }
  )
  foreach ($q in $queries) {
    try {
      $fh = @{ LogName=$q.Log; StartTime=$start; EndTime=$end; Id=$q.Ids }
      if ($q.ContainsKey('Provider')) { $fh['ProviderName'] = $q.Provider }
      $ev = Get-WinEvent -FilterHashtable $fh -MaxEvents $max -ErrorAction Stop
      foreach ($e in $ev) {
        $msg = if ($e.Message) { ($e.Message -replace "`r|`n",' ').Trim() } else { '' }
        if ($msg.Length -gt 240) { $msg = $msg.Substring(0,240) + '...' }
        [void]$markers.Add([pscustomobject]@{
          TimeCreated=$e.TimeCreated
          Category=$q.Kind
          Id=$e.Id
          Provider=$e.ProviderName
          Message=$msg
        })
      }
    } catch {}
  }
  return @($markers | Sort-Object TimeCreated)
}

function Get-AppLogSourceHealth([string[]]$paths) {
  $rows = New-Object System.Collections.Generic.List[object]
  foreach ($p in @($paths)) {
    $status = 'Missing'
    $size = 0
    if (Test-Path -LiteralPath $p) {
      $it = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
      if ($it -and -not $it.PSIsContainer) {
        $status = 'OK'
        $size = [Math]::Round(([double]$it.Length/1KB),2)
      } else {
        $status = 'Invalid'
      }
    }
    [void]$rows.Add([pscustomobject]@{ Path=$p; Status=$status; SizeKB=$size })
  }
  return ,($rows.ToArray())
}

function New-SecretSyntheticDataset([datetime]$start,[int]$minutes,[int]$intervalSeconds) {
  $samples = New-Object System.Collections.Generic.List[object]
  $events = New-Object System.Collections.Generic.List[object]
  $apps = New-Object System.Collections.Generic.List[object]
  $count = [Math]::Max(60,[int](($minutes*60)/[Math]::Max($intervalSeconds,1)))
  for ($i=0; $i -lt $count; $i++) {
    $t = $start.AddSeconds($i * [Math]::Max($intervalSeconds,1))
    $cpu = 18 + (Get-Random -Minimum 0 -Maximum 22)
    $disk = Get-Random -Minimum 1 -Maximum 14
    $mem = 5200 - ($i % 120)
    $dpc = [Math]::Round((Get-Random -Minimum 0 -Maximum 4) / 3.0,2)
    $isr = [Math]::Round((Get-Random -Minimum 0 -Maximum 3) / 3.0,2)
    $rx = [Math]::Round((Get-Random -Minimum 2 -Maximum 42),2)
    $tx = [Math]::Round((Get-Random -Minimum 1 -Maximum 18),2)
    $spike = $false
    if ($i -in 80..96 -or $i -in 190..212) {
      $cpu = 92 + (Get-Random -Minimum 0 -Maximum 6)
      $disk = 88 + (Get-Random -Minimum 0 -Maximum 10)
      $mem = 620 + (Get-Random -Minimum 0 -Maximum 120)
      $dpc = 9 + (Get-Random -Minimum 0 -Maximum 5)
      $isr = 6 + (Get-Random -Minimum 0 -Maximum 4)
      $rx = 160 + (Get-Random -Minimum 0 -Maximum 90)
      $tx = 95 + (Get-Random -Minimum 0 -Maximum 50)
      $spike = $true
    }
    $pagesIn = if ($mem -lt 900) { 1800 } else { Get-Random -Minimum 20 -Maximum 180 }
    [void]$samples.Add([pscustomobject]@{
      Timestamp=$t; CpuPct=$cpu; CpuQueueLength=[Math]::Round(($cpu/45),2); MemoryAvailableMB=$mem; PagesInputPerSec=$pagesIn
      DiskQueueLength=[Math]::Round(($disk/22),2); DiskBusyPct=$disk; DpcPct=$dpc; InterruptPct=$isr; IsSpike=$spike
      TopCpuProcesses='chrome(10432)=28%; MsMpEng(2220)=14%; explorer(5400)=7%'
      TopMemoryProcesses='chrome(10432)=1450MB; code(6600)=900MB; dwm(1300)=420MB'
      TopIoProcesses='MsMpEng(2220)=8.1MB/s; OneDrive(7740)=3.4MB/s'
      TopNetworkProcesses='OneDrive(7740)=24 conn; chrome(10432)=16 conn'
      NetworkRecvMbps=$rx; NetworkSendMbps=$tx; TopAdapters='Wi-Fi=182Mb/s; Ethernet=0Mb/s'
    })
  }
  [void]$events.Add([pscustomobject]@{ TimeCreated=$start.AddMinutes(18); LogName='System'; ProviderName='disk'; Id=129; Level='Error'; Message='Reset to device, \\Device\\RaidPort0, was issued.' })
  [void]$events.Add([pscustomobject]@{ TimeCreated=$start.AddMinutes(22); LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; Id=17; Level='Warning'; Message='A corrected hardware error has occurred.' })
  [void]$events.Add([pscustomobject]@{ TimeCreated=$start.AddMinutes(30); LogName='Application'; ProviderName='Application Hang'; Id=1002; Level='Error'; Message='The program explorer.exe version 10.0.26100 stopped interacting with Windows.' })
  [void]$events.Add([pscustomobject]@{ TimeCreated=$start.AddMinutes(40); LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Id=19; Level='Information'; Message='Installation Successful: Windows successfully installed the following update.' })
  [void]$apps.Add([pscustomobject]@{ TimeCreated=$start.AddMinutes(29); Path='EventLog/Application:MsiInstaller'; Severity='Information'; Message='EventId=11707 Product: Test App -- Installation operation completed successfully.' })
  [void]$apps.Add([pscustomobject]@{ TimeCreated=$start.AddMinutes(31); Path='EventLog/Application:Application Error'; Severity='Error'; Message='EventId=1000 Faulting application name: explorer.exe' })
  return [pscustomobject]@{ Samples=$samples.ToArray(); Events=$events.ToArray(); AppHits=$apps.ToArray() }
}

function Get-RootCauseScores($analysis,$events,$samples) {
  $scores = New-Object System.Collections.Generic.List[object]
  $eventsArr = To-ObjectArray $events
  $samplesArr = To-ObjectArray $samples
  $diskSignals = @($eventsArr | Where-Object { $_.Id -in 7,51,55,129,153 }).Count
  $wheaSignals = @($eventsArr | Where-Object { $_.Id -in 17,18,19 }).Count
  $hangSignals = @($eventsArr | Where-Object { $_.Id -eq 1002 }).Count
  $maxCpu = [double]($analysis.MaxCpu)
  $maxDisk = [double]($analysis.MaxDiskBusy)
  $minMem = [double]($analysis.MinAvailMb)
  $maxDpc = if ($samplesArr.Length -gt 0) { [double]((@($samplesArr | ForEach-Object { if ($null -ne $_.PSObject.Properties['DpcPct']) { [double]$_.DpcPct } else { 0.0 } }) | Measure-Object -Maximum).Maximum) } else { 0 }
  $maxInt = if ($samplesArr.Length -gt 0) { [double]((@($samplesArr | ForEach-Object { if ($null -ne $_.PSObject.Properties['InterruptPct']) { [double]$_.InterruptPct } else { 0.0 } }) | Measure-Object -Maximum).Maximum) } else { 0 }
  [void]$scores.Add([pscustomobject]@{ Cause='Storage'; Confidence=[Math]::Min(100,[int](($maxDisk*0.5)+($diskSignals*8))); Evidence="DiskBusy max=$([Math]::Round($maxDisk,1))%, Disk events=$diskSignals"; Link='Findings > Storage' })
  [void]$scores.Add([pscustomobject]@{ Cause='CPU/Contention'; Confidence=[Math]::Min(100,[int](($maxCpu*0.55)+($hangSignals*10))); Evidence="CPU max=$([Math]::Round($maxCpu,1))%, AppHang=$hangSignals"; Link='Findings > CPU' })
  [void]$scores.Add([pscustomobject]@{ Cause='Memory/Paging'; Confidence=[Math]::Min(100,[int](([Math]::Max(0,1200-$minMem)/10))); Evidence="Min free MB=$([Math]::Round($minMem,1))"; Link='Findings > Memory' })
  [void]$scores.Add([pscustomobject]@{ Cause='Driver/DPC-ISR'; Confidence=[Math]::Min(100,[int](($maxDpc*8)+($maxInt*7))); Evidence="DPC max=$([Math]::Round($maxDpc,2))%, ISR max=$([Math]::Round($maxInt,2))%"; Link='Timeline DPC/ISR' })
  [void]$scores.Add([pscustomobject]@{ Cause='Hardware/WHEA'; Confidence=[Math]::Min(100,[int]($wheaSignals*18)); Evidence="WHEA events=$wheaSignals"; Link='Event Signals WHEA' })
  return ,(@($scores | Sort-Object Confidence -Descending))
}

function Get-Playbooks($rootScores) {
  $rows = New-Object System.Collections.Generic.List[object]
  foreach ($r in (To-ObjectArray $rootScores | Select-Object -First 5)) {
    $steps = switch -Regex ($r.Cause) {
      'Storage' { 'Run: chkdsk /scan; check SMART/firmware; validate AV exclusions' ; break }
      'CPU' { 'Check top CPU process in Resource Clues; disable startup offenders; update culprit app' ; break }
      'Memory' { 'Confirm system-managed pagefile on SSD; close RAM-heavy apps; inspect for leaks' ; break }
      'Driver/DPC-ISR' { 'Update NIC/storage/chipset/GPU drivers; test with OEM stable driver set' ; break }
      'Hardware/WHEA' { 'Update BIOS; remove OC/XMP; run memory + CPU diagnostics' ; break }
      default { 'Capture longer reproduction run and compare against baseline' }
    }
    [void]$rows.Add([pscustomobject]@{
      Cause=$r.Cause
      Confidence=$r.Confidence
      Action=$steps
    })
  }
  return ,($rows.ToArray())
}

function Analyze($samples,$events,$appHits,$spikeWindows,$spikeTraces,$warnings) {
  $samplesArr = To-ObjectArray $samples
  $eventsArr = To-ObjectArray $events
  $appHitsArr = To-ObjectArray $appHits
  $spikeTracesArr = To-ObjectArray $spikeTraces
  $warningsArr = To-ObjectArray $warnings
  $f = New-Object System.Collections.Generic.List[object]
  $sampleCount = $samplesArr.Length
  $eventCount = $eventsArr.Length
  $appHitCount = $appHitsArr.Length
  $traceCount = $spikeTracesArr.Length
  $warningCount = $warningsArr.Length
  $counts = @{}
  foreach ($g in ($eventsArr | Group-Object Id)) { $counts[[int]$g.Name] = $g.Count }
  $maxCpu = if ($sampleCount -gt 0) { ($samplesArr | Measure-Object CpuPct -Maximum).Maximum } else { $null }
  $maxQ = if ($sampleCount -gt 0) { ($samplesArr | Measure-Object CpuQueueLength -Maximum).Maximum } else { $null }
  $maxDQ = if ($sampleCount -gt 0) { ($samplesArr | Measure-Object DiskQueueLength -Maximum).Maximum } else { $null }
  $maxDB = if ($sampleCount -gt 0) { ($samplesArr | Measure-Object DiskBusyPct -Maximum).Maximum } else { $null }
  $minMem = if ($sampleCount -gt 0) { ($samplesArr | Measure-Object MemoryAvailableMB -Minimum).Minimum } else { $null }
  $maxPg = if ($sampleCount -gt 0) { ($samplesArr | Measure-Object PagesInputPerSec -Maximum).Maximum } else { $null }
  $maxDpc = if ($sampleCount -gt 0) { (@($samplesArr | ForEach-Object { if ($null -ne $_.PSObject.Properties['DpcPct']) { [double]($_.DpcPct) } else { 0.0 } }) | Measure-Object -Maximum).Maximum } else { $null }
  $maxIsr = if ($sampleCount -gt 0) { (@($samplesArr | ForEach-Object { if ($null -ne $_.PSObject.Properties['InterruptPct']) { [double]($_.InterruptPct) } else { 0.0 } }) | Measure-Object -Maximum).Maximum } else { $null }
  $maxNet = if ($sampleCount -gt 0) { (@($samplesArr | ForEach-Object { $rx = if ($null -ne $_.PSObject.Properties['NetworkRecvMbps']) { [double]$_.NetworkRecvMbps } else { 0.0 }; $tx = if ($null -ne $_.PSObject.Properties['NetworkSendMbps']) { [double]$_.NetworkSendMbps } else { 0.0 }; $rx + $tx }) | Measure-Object -Maximum).Maximum } else { $null }

  $diskEvt = 0; foreach ($id in 7,51,55,129,153) { if ($counts.ContainsKey($id)) { $diskEvt += $counts[$id] } }
  if (($null -ne $maxDQ -and $maxDQ -ge 2 -and $maxDB -ge 85) -or $diskEvt -gt 0) { [void]$f.Add([pscustomobject]@{ Severity='High'; Category='Storage latency or storage stack issue'; Evidence="Max disk queue: $([Math]::Round($maxDQ,2)), max disk busy: $([Math]::Round($maxDB,2))%, disk-related event count: $diskEvt"; Recommendation='Update NVMe/SATA/chipset drivers, check SMART/firmware, run chkdsk /scan, review AV exclusions.' }) }
  $hang = if ($counts.ContainsKey(1002)) { $counts[1002] } else { 0 }
  if (($null -ne $maxCpu -and $maxCpu -ge 90 -and $maxQ -ge 2) -or $hang -gt 0) { [void]$f.Add([pscustomobject]@{ Severity='Medium'; Category='CPU contention and/or app hang'; Evidence="Max CPU: $([Math]::Round($maxCpu,2))%, max CPU queue: $([Math]::Round($maxQ,2)), AppHang(1002): $hang"; Recommendation='Reduce background CPU load, trim startup tasks, update/remove unstable high-CPU processes.' }) }
  if (($null -ne $minMem -and $minMem -le 700) -or ($null -ne $maxPg -and $maxPg -ge 1500)) { [void]$f.Add([pscustomobject]@{ Severity='Medium'; Category='Memory pressure / paging'; Evidence="Min available memory: $([Math]::Round($minMem,2)) MB, max hard page-ins: $([Math]::Round($maxPg,2))/sec"; Recommendation='Reduce RAM-heavy concurrency, verify system-managed pagefile on SSD, check for leaks.' }) }
  if (($null -ne $maxDpc -and $maxDpc -ge 8) -or ($null -ne $maxIsr -and $maxIsr -ge 6)) { [void]$f.Add([pscustomobject]@{ Severity='Medium'; Category='Driver latency (DPC/ISR)'; Evidence="Max DPC: $([Math]::Round($maxDpc,2))%, max ISR: $([Math]::Round($maxIsr,2))%"; Recommendation='Update NIC/storage/chipset/GPU drivers and retest with minimal background services.' }) }
  if (($null -ne $maxNet -and $maxNet -ge 150)) { [void]$f.Add([pscustomobject]@{ Severity='Info'; Category='High network activity during capture'; Evidence="Max combined Rx+Tx throughput: $([Math]::Round($maxNet,2)) Mb/s"; Recommendation='Cross-check network peaks with app installs/updates, cloud sync, and endpoint tools.' }) }
  $whea = 0; foreach ($id in 17,18,19) { if ($counts.ContainsKey($id)) { $whea += $counts[$id] } }
  if ($whea -gt 0) { [void]$f.Add([pscustomobject]@{ Severity='High'; Category='Hardware corrected/uncorrected errors (WHEA)'; Evidence="WHEA events: $whea"; Recommendation='Update BIOS, disable unstable OC/XMP, run memory/CPU diagnostics, verify cooling.' }) }
  if ($traceCount -gt 0) { [void]$f.Add([pscustomobject]@{ Severity='Info'; Category='Spike ETW traces captured'; Evidence="ETW trace files captured: $traceCount"; Recommendation='Open ETL in WPA and inspect CPU sampled, disk by process, DPC/ISR around spikes.' }) }
  if ($warningCount -gt 0) { [void]$f.Add([pscustomobject]@{ Severity='Info'; Category='Collection warnings'; Evidence="Warnings raised: $warningCount"; Recommendation='Review warnings.json and rerun elevated if needed.' }) }
  if ($appHitCount -gt 0) { [void]$f.Add([pscustomobject]@{ Severity='Info'; Category='Application log errors near analysis window'; Evidence="App log signals matched: $appHitCount"; Recommendation='Align app errors with spike windows to isolate the causative app behavior.' }) }
  if ($f.Count -eq 0) { [void]$f.Add([pscustomobject]@{ Severity='Info'; Category='No strong single root-cause signal'; Evidence='No category crossed thresholds with current data.'; Recommendation='Run longer while reproducing issue and include app logs.' }) }

  $root = @(Get-RootCauseScores -analysis ([pscustomobject]@{ MaxCpu=$maxCpu; MaxDiskBusy=$maxDB; MinAvailMb=$minMem }) -events $eventsArr -samples $samplesArr)
  $playbooks = @(Get-Playbooks $root)
  [pscustomobject]@{
    Findings=$f
    RootCauseScores=$root
    Playbooks=$playbooks
    MaxCpu=$maxCpu
    MaxCpuQueue=$maxQ
    MaxDiskQueue=$maxDQ
    MaxDiskBusy=$maxDB
    MinAvailMb=$minMem
    MaxPagesIn=$maxPg
    MaxDpc=$maxDpc
    MaxIsr=$maxIsr
    MaxNet=$maxNet
  }
}
function Write-Markdown([string]$path,$analysis,$samples,$events,$appHits,$wins,$traces,$warnings,[datetime]$start,[datetime]$end,[bool]$isAdmin,[string]$engine,$systemContext,$markers,$baselineDelta,$appSourceHealth) {
  $lines = New-Object System.Collections.Generic.List[string]
  [void]$lines.Add('# SpikeSleuth Audit Report'); [void]$lines.Add('')
  [void]$lines.Add("- Run started: $start"); [void]$lines.Add("- Run ended: $end")
  [void]$lines.Add("- Host: $env:COMPUTERNAME"); [void]$lines.Add("- Elevated session: $isAdmin"); [void]$lines.Add("- ETW engine: $engine")
  [void]$lines.Add(''); [void]$lines.Add('## Summary'); [void]$lines.Add('')
  [void]$lines.Add("- Samples: $($samples.Count)"); [void]$lines.Add("- Spike windows: $($wins.Count)"); [void]$lines.Add("- ETW traces: $($traces.Count)")
  [void]$lines.Add("- Event signals: $($events.Count)"); [void]$lines.Add("- App log hits: $($appHits.Count)"); [void]$lines.Add("- Warnings: $($warnings.Count)")
  [void]$lines.Add(''); [void]$lines.Add('## Findings'); [void]$lines.Add('')
  foreach ($x in $analysis.Findings) { [void]$lines.Add("### [$($x.Severity)] $($x.Category)"); [void]$lines.Add(''); [void]$lines.Add("- Evidence: $($x.Evidence)"); [void]$lines.Add("- Recommendation: $($x.Recommendation)"); [void]$lines.Add('') }
  if (@($analysis.RootCauseScores).Count -gt 0) {
    [void]$lines.Add('## Root Cause Scores'); [void]$lines.Add('')
    foreach ($r in @($analysis.RootCauseScores)) { [void]$lines.Add("- $($r.Cause): $($r.Confidence)% confidence | $($r.Evidence)") }
    [void]$lines.Add('')
  }
  if (@($analysis.Playbooks).Count -gt 0) {
    [void]$lines.Add('## Playbooks'); [void]$lines.Add('')
    foreach ($p in @($analysis.Playbooks)) { [void]$lines.Add("- $($p.Cause): $($p.Action)") }
    [void]$lines.Add('')
  }
  if ($systemContext) {
    [void]$lines.Add('## System Context (Drivers/Firmware)'); [void]$lines.Add('')
    foreach ($prop in $systemContext.PSObject.Properties) { [void]$lines.Add("- $($prop.Name): $($prop.Value)") }
    [void]$lines.Add('')
  }
  if (@($markers).Count -gt 0) {
    [void]$lines.Add('## Correlation Markers (Boot/Resume/Update)'); [void]$lines.Add('')
    foreach ($m in @($markers | Select-Object -First 40)) { [void]$lines.Add("- [$($m.TimeCreated)] [$($m.Category)] EventId=$($m.Id) $($m.Message)") }
    [void]$lines.Add('')
  }
  if ($baselineDelta) {
    [void]$lines.Add('## Baseline Comparison'); [void]$lines.Add('')
    foreach ($prop in $baselineDelta.PSObject.Properties) { [void]$lines.Add("- $($prop.Name): $($prop.Value)") }
    [void]$lines.Add('')
  }
  if (@($appSourceHealth).Count -gt 0) {
    [void]$lines.Add('## App Log Source Health'); [void]$lines.Add('')
    foreach ($s in @($appSourceHealth)) { [void]$lines.Add("- $($s.Path): $($s.Status) ($($s.SizeKB) KB)") }
    [void]$lines.Add('')
  }
  if ($traces.Count -gt 0) { [void]$lines.Add('## ETW Trace Files'); [void]$lines.Add(''); foreach ($t in $traces) { [void]$lines.Add("- $($t.Status): $($t.Path)") }; [void]$lines.Add('') }
  if ($warnings.Count -gt 0) { [void]$lines.Add('## Collection Warnings'); [void]$lines.Add(''); foreach ($w in $warnings) { [void]$lines.Add("- [$($w.Time)] $($w.Message)") }; [void]$lines.Add('') }
  $lines | Set-Content -LiteralPath $path -Encoding UTF8
}

function New-LightweightBundle([string]$outDir,$samples,$events,$markers,$analysis,[string]$reportPath,[string]$findingsCsv,[string]$rootCsv,[string]$playCsv,[string]$warningsPath,[string]$suMd,[string]$suTxt,[string]$genAiMd,[string]$genAiRaw) {
  try {
    $bundleName = "spikesleuth-lite-bundle-{0}.zip" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $bundlePath = Join-Path $outDir $bundleName
    $tmpDir = Join-Path $outDir ("_lite_bundle_{0}" -f ([Guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    foreach ($p in @($reportPath,$findingsCsv,$rootCsv,$playCsv,$warningsPath,$suMd,$suTxt,$genAiMd,$genAiRaw)) {
      if ($p -and (Test-Path -LiteralPath $p)) { Copy-Item -LiteralPath $p -Destination (Join-Path $tmpDir (Split-Path -Path $p -Leaf)) -Force }
    }

    $chartPoints = @($samples | ForEach-Object {
      [pscustomobject]@{
        Timestamp = $_.Timestamp
        CpuPct = $_.CpuPct
        DiskBusyPct = $_.DiskBusyPct
        MemoryAvailableMB = $_.MemoryAvailableMB
        DpcPct = $_.DpcPct
        InterruptPct = $_.InterruptPct
        NetworkRecvMbps = $_.NetworkRecvMbps
        NetworkSendMbps = $_.NetworkSendMbps
        IsSpike = [bool]$_.IsSpike
      }
    })
    $chartPoints | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $tmpDir 'chart_points.json') -Encoding UTF8

    $eventSummary = @($events | Select-Object -First 500 TimeCreated,Id,LogName,Level,Message)
    $eventSummary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $tmpDir 'event_summary_top500.json') -Encoding UTF8

    $markerSummary = @($markers | Select-Object TimeCreated,Category,Id,Provider,Message)
    $markerSummary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $tmpDir 'timeline_markers.json') -Encoding UTF8

    $manifest = [pscustomobject]@{
      CreatedAt = (Get-Date).ToString('o')
      Purpose = 'Lightweight review bundle for sharing. Excludes huge raw datasets.'
      Included = @(
        'report.md','findings.csv','root_cause_scores.csv','playbooks.csv','warnings.json',
        'superuser_draft.md','superuser_draft.txt','genai_review.md','genai_review_raw.txt',
        'chart_points.json','event_summary_top500.json','timeline_markers.json'
      )
      Excluded = @(
        'performance_samples.csv','process_hotspots.csv','event_audit.csv','app_log_hits.csv'
      )
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $tmpDir 'bundle_manifest.json') -Encoding UTF8

    if (Test-Path -LiteralPath $bundlePath) { Remove-Item -LiteralPath $bundlePath -Force }
    Compress-Archive -Path (Join-Path $tmpDir '*') -DestinationPath $bundlePath -Force
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    return $bundleName
  } catch {
    return ''
  }
}

function Write-Html([string]$path,$samples,$events,$appHits,$findings,$warnings,[string]$reportMarkdown,$fileContents,[string]$snapshotZipName='',[string]$lightBundleName='',$rootScores,$playbooks,$markers,$systemContext,$baselineDelta,$appSourceHealth,[string]$genAiText='',[string]$superUserTitle='',[string]$superUserBody='') {
  $sampleRows = New-Object System.Collections.Generic.List[object]
  foreach ($s in (To-ObjectArray $samples)) {
    [void]$sampleRows.Add([pscustomobject]@{
      Timestamp = $s.Timestamp
      CpuPct = $s.CpuPct
      DiskBusyPct = $s.DiskBusyPct
      MemoryAvailableMB = $s.MemoryAvailableMB
      DpcPct = $s.DpcPct
      InterruptPct = $s.InterruptPct
      IsSpike = [bool]$s.IsSpike
      TopCpuProcesses = $s.TopCpuProcesses
      TopMemoryProcesses = $s.TopMemoryProcesses
      TopIoProcesses = $s.TopIoProcesses
      TopNetworkProcesses = $s.TopNetworkProcesses
      NetworkRecvMbps = $s.NetworkRecvMbps
      NetworkSendMbps = $s.NetworkSendMbps
      TopAdapters = $s.TopAdapters
    })
  }
  $eventRows = New-Object System.Collections.Generic.List[object]
  foreach ($e in ((To-ObjectArray $events) | Select-Object -First 250)) {
    [void]$eventRows.Add([pscustomobject]@{ TimeCreated = $e.TimeCreated; Id = $e.Id; LogName = $e.LogName; Level = $e.Level; Message = $e.Message })
  }
  $appRows = New-Object System.Collections.Generic.List[object]
  foreach ($a in ((To-ObjectArray $appHits) | Select-Object -First 250)) {
    [void]$appRows.Add([pscustomobject]@{ TimeCreated = $a.TimeCreated; Path = $a.Path; Severity = $a.Severity; Message = $a.Message })
  }
  $findingRows = New-Object System.Collections.Generic.List[object]
  foreach ($f in (To-ObjectArray $findings)) {
    [void]$findingRows.Add([pscustomobject]@{ Severity = $f.Severity; Category = $f.Category; Evidence = $f.Evidence; Recommendation = $f.Recommendation })
  }
  $rootRows = To-ObjectArray $rootScores
  $playRows = To-ObjectArray $playbooks
  $markerRows = To-ObjectArray $markers
  $ctxObj = if ($systemContext) { $systemContext } else { [pscustomobject]@{} }
  $baseObj = if ($baselineDelta) { $baselineDelta } else { [pscustomobject]@{} }
  $sourceRows = To-ObjectArray $appSourceHealth

  $samplesJson = ConvertTo-JsonArrayText -items $sampleRows -Depth 6
  $eventsJson = ConvertTo-JsonArrayText -items $eventRows -Depth 6
  $appJson = ConvertTo-JsonArrayText -items $appRows -Depth 6
  $findingsJson = ConvertTo-JsonArrayText -items $findingRows -Depth 6
  $rootJson = ConvertTo-JsonArrayText -items $rootRows -Depth 6
  $playJson = ConvertTo-JsonArrayText -items $playRows -Depth 6
  $markerJson = ConvertTo-JsonArrayText -items $markerRows -Depth 6
  $ctxJson = ConvertTo-Json -InputObject $ctxObj -Depth 6
  $baseJson = ConvertTo-Json -InputObject $baseObj -Depth 6
  $sourceJson = ConvertTo-JsonArrayText -items $sourceRows -Depth 6
  $genAiJson = ConvertTo-Json -InputObject $genAiText
  $suTitleJson = ConvertTo-Json -InputObject $superUserTitle
  $suBodyJson = ConvertTo-Json -InputObject $superUserBody
  $reportJson = ConvertTo-Json -InputObject $reportMarkdown
  $filesJson = ConvertTo-Json -InputObject $fileContents -Depth 6
  $snapshotZipJson = ConvertTo-Json -InputObject $snapshotZipName
  $lightBundleJson = ConvertTo-Json -InputObject $lightBundleName

  $samplesJson = Protect-ForHtmlScript $samplesJson
  $eventsJson = Protect-ForHtmlScript $eventsJson
  $appJson = Protect-ForHtmlScript $appJson
  $findingsJson = Protect-ForHtmlScript $findingsJson
  $rootJson = Protect-ForHtmlScript $rootJson
  $playJson = Protect-ForHtmlScript $playJson
  $markerJson = Protect-ForHtmlScript $markerJson
  $ctxJson = Protect-ForHtmlScript $ctxJson
  $baseJson = Protect-ForHtmlScript $baseJson
  $sourceJson = Protect-ForHtmlScript $sourceJson
  $genAiJson = Protect-ForHtmlScript $genAiJson
  $suTitleJson = Protect-ForHtmlScript $suTitleJson
  $suBodyJson = Protect-ForHtmlScript $suBodyJson
  $reportJson = Protect-ForHtmlScript $reportJson
  $filesJson = Protect-ForHtmlScript $filesJson
  $snapshotZipJson = Protect-ForHtmlScript $snapshotZipJson
  $lightBundleJson = Protect-ForHtmlScript $lightBundleJson

  $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SpikeSleuth Dashboard</title>
<style>
:root{--bg:#071320;--bg2:#0b2034;--card:#112d46;--line:#234b6d;--text:#edf4fb;--muted:#9db2c7;--ok:#57d3a4;--warn:#f6bd60;--bad:#ef6f6c;--chip:#173955}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 15% -5%,#194772 0%,transparent 55%),radial-gradient(900px 700px at 95% 10%,#2a315f 0%,transparent 50%),linear-gradient(160deg,var(--bg),var(--bg2));color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.ambient{position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:0}
.ambient:before{content:'';position:absolute;inset:-20%;background:radial-gradient(1000px 600px at 8% 15%,rgba(86,188,255,.12),transparent 52%),radial-gradient(800px 500px at 90% 85%,rgba(112,255,214,.08),transparent 56%);animation:auroraMove 26s ease-in-out infinite alternate}
.ambient:after{content:'';position:absolute;inset:0;background:
linear-gradient(rgba(81,136,182,.08) 1px,transparent 1px) 0 0/56px 56px,
linear-gradient(90deg,rgba(81,136,182,.07) 1px,transparent 1px) 0 0/56px 56px;opacity:.26;animation:gridDrift 24s linear infinite}
.status-glow{position:absolute;inset:0;background:
radial-gradient(700px 300px at 14% 18%,rgba(87,211,164,.14),transparent 60%),
radial-gradient(760px 330px at 85% 22%,rgba(246,189,96,.14),transparent 62%),
radial-gradient(680px 300px at 58% 80%,rgba(239,111,108,.13),transparent 60%);
animation:statusGlowPulse 14s ease-in-out infinite}
.tri-gradient{position:absolute;inset:-18%;opacity:.34;background:
radial-gradient(60% 60% at 20% 25%,rgba(87,211,164,.46),transparent 58%),
radial-gradient(55% 55% at 80% 28%,rgba(246,189,96,.43),transparent 58%),
radial-gradient(58% 58% at 55% 78%,rgba(239,111,108,.41),transparent 60%);
animation:triGradientDrift 18s ease-in-out infinite alternate}
.icons{position:absolute;inset:0}
.ambient .icon{position:absolute;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:999px;font-size:14px;font-weight:700;opacity:.36;filter:saturate(1.12)}
.ambient .icon.ok{color:#57d3a4;background:rgba(87,211,164,.17);border:1px solid rgba(87,211,164,.42);animation:floatOk 7.5s ease-in-out infinite}
.ambient .icon.warn{color:#f6bd60;background:rgba(246,189,96,.18);border:1px solid rgba(246,189,96,.44);animation:floatWarn 6.2s ease-in-out infinite}
.ambient .icon.err{color:#ef6f6c;background:rgba(239,111,108,.2);border:1px solid rgba(239,111,108,.5);animation:floatErr 4.8s ease-in-out infinite}
.ambient.high-alert .icon.err{opacity:.4;box-shadow:0 0 14px rgba(239,111,108,.4)}
.wrap{width:min(96vw,1920px);margin:24px auto;padding:0 16px 40px}
.wrap{position:relative;z-index:1}
.hero{display:flex;justify-content:space-between;align-items:end;gap:12px;margin-bottom:14px}
h1{margin:0;font-size:32px}.sub{color:var(--muted)}
.grid{display:grid;gap:12px}.kpis{grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:12px;position:sticky;top:6px;z-index:35;padding:6px;border-radius:14px;background:rgba(7,19,32,.58);backdrop-filter:blur(6px)}
.kpi{background:linear-gradient(180deg,#153756,#112c46);border:1px solid #245074;border-radius:14px;padding:12px;box-shadow:0 8px 20px rgba(0,0,0,.25);animation:rise .45s ease both,pulseSoft 2.4s ease-in-out infinite}
.kpi.nav{cursor:pointer;transition:transform .18s ease,filter .18s ease}
.kpi.nav:hover{transform:translateY(-1px);filter:brightness(1.08)}
.kpi.info{box-shadow:0 0 12px rgba(87,211,164,.18)}
.kpi.low{box-shadow:0 0 14px rgba(246,189,96,.4)}
.kpi.med{box-shadow:0 0 18px rgba(255,140,66,.55);animation:pulseMed 1.4s ease infinite}
.kpi.high{box-shadow:0 0 20px rgba(239,111,108,.7);animation:pulseHigh 1s ease infinite}
.kpi .v{font-size:30px;font-weight:700}
.card{background:linear-gradient(180deg,#143450,#10263c);border:1px solid #1f4668;border-radius:14px;padding:14px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.card.alert{border:2px solid var(--bad);animation:flash 1.15s infinite}
.report-frame{background:linear-gradient(180deg,#0f2b44,#0d2235);border:0;border-radius:14px;padding:14px;box-shadow:0 14px 34px rgba(0,0,0,.32)}
.report-frame .md{border:0;max-height:none;min-height:620px}
.two{grid-template-columns:2fr 1fr}.title{font-size:18px;font-weight:700;margin:0 0 10px}
.tiny{font-size:12px;color:var(--muted)}
canvas{width:100%;height:320px;background:#0a1b2d;border:1px solid var(--line);border-radius:10px}
.chart-wrap{position:relative}
.tip{position:absolute;display:none;padding:7px 9px;border-radius:8px;background:#0f2b45;border:1px solid #2d628b;color:#dff0ff;font-size:12px;pointer-events:none;transform:translate(8px,-100%)}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{padding:6px 10px;background:var(--chip);border:1px solid #2c5678;border-radius:999px;color:#d9e8f6}
.files{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.showbtn{padding:8px 14px;border-radius:10px;border:1px solid #2c5f86;background:#1c4162;color:#e8f5ff;cursor:pointer}
.bubble-wrap{display:flex;gap:10px;flex-wrap:wrap;max-height:0;overflow:hidden;opacity:0;transition:max-height .45s ease,opacity .35s ease}
.bubble-wrap.open{max-height:300px;opacity:1}
.bubble{display:inline-block;padding:9px 12px;border-radius:999px;background:#1a3f5f;border:1px solid #2e6690;color:#dff1ff;text-decoration:none;transform:translateY(10px) scale(.95);opacity:0;transition:all .35s ease}
.bubble-wrap.open .bubble{transform:translateY(0) scale(1);opacity:1}
.bubble.downloading{animation:pop 600ms ease}
.table-wrap{max-height:480px;overflow:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:8px;border-bottom:1px solid #1f4668;vertical-align:top;text-align:left;word-break:break-word}
th{position:sticky;top:0;background:#12314d}
tbody tr:nth-child(even){background:rgba(20,54,84,.22)}
tr.finding-row:hover{background:#173650;cursor:pointer}
.sev-High{color:var(--bad);font-weight:700}.sev-Medium{color:var(--warn);font-weight:700}.sev-Info{color:var(--ok);font-weight:700}
.md{max-height:460px;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:12px;background:#091a2b;overflow-wrap:anywhere;word-break:break-word}
.md h1,.md h2,.md h3{margin:12px 0 8px}.md code{background:#18324a;padding:2px 5px;border-radius:5px}.md pre{background:#0c2339;padding:10px;border-radius:8px;overflow:auto}
.zoom-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.legend{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
.lg-item{display:inline-flex;align-items:center;gap:7px;padding:5px 9px;border:1px solid #2f628b;border-radius:999px;background:#123452;color:#dbeaf8;font-size:12px}
.lg-dot{width:11px;height:11px;border-radius:50%}
.resource-filters{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 8px}
.resource-filters label{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:999px;background:#123452;border:1px solid #2d6088;font-size:12px;color:#deefff;cursor:pointer}
.pulse{animation:pulse 1s ease infinite}
.focus{border:2px solid var(--bad);box-shadow:0 0 18px rgba(239,111,108,.35);animation:flash 1.1s infinite}
.stack-col{grid-template-columns:1fr}
.side{display:grid;grid-template-columns:180px 1fr;gap:12px}
.cats{display:flex;flex-direction:column;gap:8px}
.cat{background:#143654;border:1px solid #2a5f88;border-radius:10px;padding:8px}
.cat-title{font-weight:700;cursor:pointer;display:flex;justify-content:space-between;align-items:center}
.cat-title:after{content:'▸';opacity:.85;transition:transform .25s ease}
.cat.open .cat-title:after{transform:rotate(90deg)}
.file-list{max-height:0;overflow:hidden;transition:max-height .35s ease, opacity .3s ease;opacity:.2}
.cat.open .file-list{max-height:260px;opacity:1}
.file-btn{display:block;margin-top:6px;padding:7px 9px;border-radius:8px;background:#1b4365;border:1px solid #2f6a95;color:#dff1ff;text-decoration:none;cursor:pointer;transition:transform .22s ease,filter .22s ease,opacity .28s ease}
.file-btn:hover{transform:translateX(2px);filter:brightness(1.1)}
.file-btn.downloading{animation:pop 600ms ease}
.viewer{border:1px solid var(--line);border-radius:10px;background:#0a1e31;min-height:640px;display:flex;flex-direction:column;resize:both;overflow:auto}
.viewer-top{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-bottom:1px solid #1f4668}
.viewer-body{padding:10px;overflow:auto;max-height:760px}
.viewer-body pre{white-space:pre-wrap;word-break:break-word}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes flash{0%,100%{box-shadow:0 0 0 rgba(239,111,108,0)}50%{box-shadow:0 0 18px rgba(239,111,108,.45)}}
@keyframes pop{0%{transform:scale(1)}40%{transform:scale(1.08)}100%{transform:scale(1)}}
@keyframes pulse{0%,100%{filter:brightness(1)}50%{filter:brightness(1.35)}}
@keyframes pulseSoft{0%,100%{box-shadow:0 8px 20px rgba(0,0,0,.25)}50%{box-shadow:0 10px 24px rgba(106,167,255,.24)}}
@keyframes pulseHigh{0%,100%{box-shadow:0 0 8px rgba(239,111,108,.35)}50%{box-shadow:0 0 24px rgba(239,111,108,.85)}}
@keyframes pulseMed{0%,100%{box-shadow:0 0 6px rgba(255,140,66,.28)}50%{box-shadow:0 0 18px rgba(255,140,66,.7)}}
@keyframes auroraMove{0%{transform:translate3d(-2%,0,0) scale(1)}100%{transform:translate3d(2%,2%,0) scale(1.05)}}
@keyframes gridDrift{0%{transform:translate3d(0,0,0)}100%{transform:translate3d(56px,56px,0)}}
@keyframes statusGlowPulse{0%,100%{opacity:.75}50%{opacity:1}}
@keyframes triGradientDrift{0%{transform:translate3d(-2%,-1%,0) scale(1)}50%{transform:translate3d(2%,1.5%,0) scale(1.05)}100%{transform:translate3d(-1.5%,2%,0) scale(1.02)}}
@keyframes floatOk{0%,100%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(14px,-18px,0) scale(1.06)}}
@keyframes floatWarn{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(-16px,10px,0)}}
@keyframes floatErr{0%,100%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(10px,-9px,0) scale(1.08)}}
.empty-ok{display:none;align-items:center;gap:10px;padding:12px;border:1px dashed #2f6a95;border-radius:10px;background:#102a40;cursor:pointer}
.ok-badge{width:34px;height:34px;border-radius:50%;background:#1f9d63;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-weight:700;animation:okPop 1.4s ease infinite}
.ok-text{color:#cfe8d9}
.ok-detail{display:none;margin-top:8px;padding:10px;border-radius:8px;background:#0e2238;border:1px solid #2f6a95;color:#9fd0b6;font-size:12px}
.ts-link{display:inline-flex;align-items:center;gap:4px;padding:0 6px;border-radius:999px;border:1px solid #2d628b;background:#12395b;color:#dff0ff;cursor:pointer;font-size:11px;margin:0 2px}
.ts-link:hover{filter:brightness(1.1)}
@keyframes okPop{0%,100%{transform:scale(1);box-shadow:0 0 0 rgba(31,157,99,0)}50%{transform:scale(1.08);box-shadow:0 0 14px rgba(31,157,99,.6)}}
@media (max-width:960px){.two,.side{grid-template-columns:1fr}}
@media (prefers-reduced-motion: reduce){
  .ambient,.ambient:before,.ambient:after,.ambient .icon{animation:none !important}
}
</style>
</head>
<body>
<div id="ambientField" class="ambient">
  <div class="status-glow"></div>
  <div class="tri-gradient"></div>
  <div id="ambientIcons" class="icons"></div>
</div>
<div class="wrap">
  <div class="hero">
    <div><h1>SpikeSleuth</h1><div class="sub">Interactive run dashboard with zoom, hover details, and embedded markdown.</div></div>
    <div class="tiny" style="display:flex;align-items:center;gap:8px">
      <a id="liteZipBtn" class="showbtn" href="#" download style="display:none">📦 Export Light Bundle</a>
      <span>Generated locally from this run</span>
    </div>
  </div>
  <div id="kpis" class="grid kpis"></div>
  <div id="snapshotBar" class="card" style="margin-top:12px;display:none">
    <div class="title">Frozen In Time Snapshot</div>
    <div class="tiny">Complete run package with dashboard + all generated files preserved together.</div>
    <div style="margin-top:8px"><a id="snapshotLink" class="showbtn" href="#" download>Download Snapshot ZIP</a></div>
  </div>
  <div class="grid stack-col" id="insightsRow" style="margin-top:12px">
    <div class="card" id="findingCard"><div class="title">Findings</div><div class="table-wrap"><table id="findingsTbl"></table></div></div>
    <div class="report-frame" id="reportCard"><div class="title">Embedded report.md</div><div id="markdownView" class="md"></div></div>
  </div>
  <div class="grid two" style="margin-top:12px">
    <div class="card"><div class="title">Root Cause Scores</div><div class="table-wrap" style="max-height:240px"><table id="rootTbl"></table></div></div>
    <div class="card"><div class="title">Playbooks</div><div class="table-wrap" style="max-height:240px"><table id="playTbl"></table></div></div>
  </div>
  <div class="grid two" style="margin-top:12px">
    <div class="card"><div class="title">GenAI Assistant Review</div><div id="genAiView" class="md" style="min-height:220px"></div></div>
    <div class="card">
      <div class="title">Community Escalation (Super User)</div>
      <div class="files">
        <button id="copySuBtn" class="showbtn">Copy Draft</button>
        <button id="openSuBtn" class="showbtn">Open Ask Page</button>
      </div>
      <div class="tiny" style="margin-top:8px">Ask link: https://superuser.com/questions/ask</div>
      <div id="suPreview" class="md" style="margin-top:8px;min-height:220px"></div>
    </div>
  </div>
  <div class="grid two" style="margin-top:12px">
    <div class="card" id="timelineCard">
      <div class="title">Performance Timeline</div>
      <div class="zoom-row"><span class="tiny">Wheel = zoom, drag = pan, brush below for fast range select</span><button id="resetZoom" class="showbtn">Reset Zoom</button><button id="firstEvent" class="showbtn">First Highlight</button><button id="prevEvent" class="showbtn">Prev</button><button id="nextEvent" class="showbtn">Next</button></div>
      <div class="chart-wrap"><canvas id="perfChart" width="980" height="320"></canvas><div id="tip" class="tip"></div></div>
      <div class="chart-wrap" style="margin-top:8px"><canvas id="miniChart" width="980" height="95"></canvas><div id="miniTip" class="tip"></div></div>
      <div id="perfLegend" class="legend"></div>
      <div class="title" style="margin-top:8px">Incident Replay (±5 min)</div>
      <div class="tiny">Click any finding row to focus its nearest sample window and show nearby events/app hits.</div>
      <div class="table-wrap" style="max-height:180px"><table id="replayTbl"></table></div>
      <div class="title" style="margin-top:10px">Resource Process Clues (Synced To Zoom)</div>
      <div id="resourceFilters" class="resource-filters"></div>
      <div class="table-wrap" style="max-height:260px"><table id="resourceTbl"></table></div>
    </div>
    <div class="card">
      <div class="title">Distribution</div>
      <canvas id="eventBars" width="420" height="320"></canvas>
      <div class="chips" id="sevChips"></div>
    </div>
  </div>
  <div class="grid two" id="eventsRow" style="margin-top:12px">
    <div class="card" id="eventCard"><div class="title">Event Signals (top 250)</div><div class="table-wrap"><table id="eventsTbl"></table></div></div>
    <div class="card" id="appCard">
      <div class="title">App Log Hits (top 250)</div>
      <div id="appsEmpty" class="empty-ok"><span class="ok-badge">✓</span><span class="ok-text">No app log hits in this run window. Click for details.</span></div>
      <div id="appsEmptyDetail" class="ok-detail">No matching app/install/uninstall/error entries were found for the selected time range and configured app-log sources. This is not an error.</div>
      <div class="table-wrap"><table id="appsTbl"></table></div>
    </div>
  </div>
  <div class="grid two" style="margin-top:12px">
    <div class="card"><div class="title">Correlation Markers (Boot/Resume/Update)</div><div class="table-wrap" style="max-height:260px"><table id="markerTbl"></table></div></div>
    <div class="card"><div class="title">System Context + Baseline + App Sources</div>
      <div class="table-wrap" style="max-height:160px"><table id="ctxTbl"></table></div>
      <div class="table-wrap" style="max-height:120px;margin-top:8px"><table id="baseTbl"></table></div>
      <div class="table-wrap" style="max-height:160px;margin-top:8px"><table id="sourceTbl"></table></div>
    </div>
  </div>
  <div class="card" id="quickSection" style="margin-top:12px">
    <div class="title">Quick File Access + In-App Viewer</div>
    <div class="tiny">Click a category to expand files, then click a file to open it in this page. Use the top-right link in viewer to download that file.</div>
    <div class="side" style="margin-top:8px">
      <div class="cats" id="cats"></div>
      <div class="viewer">
        <div class="viewer-top"><strong id="viewerName">No file selected</strong><a id="downloadLink" href="#" download>Download Current File</a></div>
        <div id="viewerBody" class="viewer-body"><div class="tiny">Select a file from the left.</div></div>
      </div>
    </div>
  </div>
</div>
<script>
const samplesDataRaw = $samplesJson;
const eventsData = $eventsJson;
const appHitsData = $appJson;
const findingsData = $findingsJson;
const rootScoresData = $rootJson;
const playbooksData = $playJson;
const markerData = $markerJson;
const systemContextData = $ctxJson;
const baselineData = $baseJson;
const appSourceHealthData = $sourceJson;
const genAiText = $genAiJson;
const superUserTitle = $suTitleJson;
const superUserBody = $suBodyJson;
const reportMd = $reportJson;
const fileContents = $filesJson;
const snapshotZipName = $snapshotZipJson;
const lightBundleName = $lightBundleJson;
function asNum(v,def){
  const n=Number(v);
  return Number.isFinite(n) ? n : def;
}
function buildSamplesFallbackFromCsv(){
  const txt=(fileContents && fileContents['performance_samples.csv']) ? fileContents['performance_samples.csv'] : '';
  if(!txt){ return []; }
  const rows=toCsvRows(txt);
  return rows.map(r=>({
    Timestamp:r.Timestamp||'',
    CpuPct:asNum(r.CpuPct,0),
    CpuQueueLength:asNum(r.CpuQueueLength,0),
    MemoryAvailableMB:asNum(r.MemoryAvailableMB,0),
    DpcPct:asNum(r.DpcPct,0),
    InterruptPct:asNum(r.InterruptPct,0),
    PagesInputPerSec:asNum(r.PagesInputPerSec,0),
    DiskQueueLength:asNum(r.DiskQueueLength,0),
    DiskBusyPct:asNum(r.DiskBusyPct,0),
    IsSpike:String(r.IsSpike||'').toLowerCase()==='true',
    TopCpuProcesses:r.TopCpuProcesses||'',
    TopMemoryProcesses:r.TopMemoryProcesses||'',
    TopIoProcesses:r.TopIoProcesses||'',
    TopNetworkProcesses:r.TopNetworkProcesses||'',
    NetworkRecvMbps:asNum(r.NetworkRecvMbps,0),
    NetworkSendMbps:asNum(r.NetworkSendMbps,0),
    TopAdapters:r.TopAdapters||''
  })).filter(r=>r.Timestamp);
}
const samplesData = (Array.isArray(samplesDataRaw) && samplesDataRaw.length>0) ? samplesDataRaw : buildSamplesFallbackFromCsv();
let highlightMode = '';
let hoverIndex = -1;
let viewStart = 0;
let viewCount = Math.max(samplesData.length, 1);
let dragStartX = null;
let dragStartView = 0;
let brushDown = false;
let brushAnchor = 0;
let bandCursor = 0;
let resourceColumnState = { CPU:true, Memory:true, DiskIO:true, Network:true, Adapters:true, DpcIsr:true };

function el(tag, txt){const e=document.createElement(tag);if(txt!==undefined)e.textContent=txt;return e;}
function countBy(arr,key){const m={};arr.forEach(x=>{const k=(x[key]??'').toString();m[k]=(m[k]||0)+1;});return m;}
function topEntries(obj,n){return Object.entries(obj).sort((a,b)=>b[1]-a[1]).slice(0,n);}
function table(id, cols, rows, sevCol, rowClass){
  const t=document.getElementById(id); t.innerHTML=''; const th=el('thead'); const hr=el('tr');
  cols.forEach(c=>hr.appendChild(el('th',c))); th.appendChild(hr); t.appendChild(th); const tb=el('tbody');
  rows.forEach(r=>{const tr=el('tr'); if(rowClass){tr.className=rowClass;} cols.forEach(c=>{const td=el('td',r[c]??''); if(sevCol&&c===sevCol)td.className='sev-'+String(r[c]); tr.appendChild(td);}); tb.appendChild(tr);});
  t.appendChild(tb);
}
function kvTable(id,obj){
  const rows=Object.keys(obj||{}).map(k=>({Key:k,Value:String(obj[k]??'')}));
  table(id,['Key','Value'],rows);
}
function toCsvRows(txt){
  if(!txt) return [];
  const lines=String(txt).split(/\r?\n/).filter(x=>x.trim().length>0);
  if(lines.length<2) return [];
  const headers=lines[0].split(',');
  return lines.slice(1).map(line=>{
    const cells=line.split(',');
    const o={}; headers.forEach((h,i)=>o[h.replace(/^"|"$/g,'')]=(cells[i]||'').replace(/^"|"$/g,'')); return o;
  });
}
function canvasPosX(ev, canvas){
  const rect=canvas.getBoundingClientRect();
  const scaleX=canvas.width/Math.max(rect.width,1);
  return (ev.clientX-rect.left)*scaleX;
}
function canvasToCssX(canvasX, canvas){
  const rect=canvas.getBoundingClientRect();
  return canvasX*(Math.max(rect.width,1)/Math.max(canvas.width,1));
}
function parseTs(v){
  const t=Date.parse(v||'');
  return Number.isFinite(t) ? t : NaN;
}
function findNearestSampleIndex(timeMs){
  let best=0,bestDiff=Infinity;
  samplesData.forEach((s,i)=>{
    const ts=parseTs(s.Timestamp);
    if(Number.isNaN(ts)) return;
    const d=Math.abs(ts-timeMs);
    if(d<bestDiff){bestDiff=d;best=i;}
  });
  return best;
}
function renderReplayAroundMs(centerTs){
  if(Number.isNaN(centerTs)){ table('replayTbl',['Type','Time','Detail'],[]); return; }
  const left=centerTs-(5*60*1000), right=centerTs+(5*60*1000);
  const rows=[];
  eventsData.forEach(e=>{ const t=parseTs(e.TimeCreated); if(!Number.isNaN(t)&&t>=left&&t<=right){ rows.push({Type:'Event',Time:e.TimeCreated,Detail:'['+(e.Id||'')+'] '+(e.Message||'')}); }});
  appHitsData.forEach(a=>{ const t=parseTs(a.TimeCreated); if(!Number.isNaN(t)&&t>=left&&t<=right){ rows.push({Type:'App',Time:a.TimeCreated,Detail:(a.Path||'')+' '+(a.Message||'')}); }});
  rows.sort((a,b)=>parseTs(a.Time)-parseTs(b.Time));
  table('replayTbl',['Type','Time','Detail'],rows.slice(0,80));
}
function jumpToTimestamp(ts){
  const timeMs=parseTs(ts);
  if(Number.isNaN(timeMs) || samplesData.length===0){ return; }
  const idx=findNearestSampleIndex(timeMs);
  if(idx<viewStart || idx>=viewStart+viewCount){
    const keep=Math.max(20,Math.min(samplesData.length,viewCount));
    viewCount=keep;
    viewStart=Math.max(0,Math.min(idx-Math.floor(keep/2),samplesData.length-keep));
  }
  hoverIndex=Math.max(0,Math.min(getViewRows().length-1,idx-viewStart));
  drawLineChart(); drawMiniChart(); renderResourceRows();
  renderReplayAroundMs(timeMs);
  goToSection('timelineCard');
}
function renderMarkdown(md){
  const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const inlineFmt=(txt)=>{
    let s=esc(txt);
    s=s.replace(/`([^`]+)`/g,function(_,g){ return '<code>'+g+'</code>'; });
    s=s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
    s=s.replace(/__([^_]+)__/g,'<u>$1</u>');
    s=s.replace(/\*([^*]+)\*/g,'<em>$1</em>');
    return s;
  };
  const lines=(md||'').replace(/\r\n/g,'\n').split('\n');
  let html=''; let inUl=false; let inOl=false; let inCode=false;
  const closeList=()=>{ if(inUl){html+='</ul>';inUl=false;} if(inOl){html+='</ol>';inOl=false;} };
  for(const line of lines){
    if(line.startsWith('```')){ if(!inCode){closeList();html+='<pre><code>';inCode=true;} else {html+='</code></pre>';inCode=false;} continue; }
    if(inCode){html+=esc(line)+'\n'; continue;}
    if(/^###\s+/.test(line)){ closeList(); html+='<h3>'+inlineFmt(line.replace(/^###\s+/,''))+'</h3>'; continue; }
    if(/^##\s+/.test(line)){ closeList(); html+='<h2>'+inlineFmt(line.replace(/^##\s+/,''))+'</h2>'; continue; }
    if(/^#\s+/.test(line)){ closeList(); html+='<h1>'+inlineFmt(line.replace(/^#\s+/,''))+'</h1>'; continue; }
    if(/^\-\s+/.test(line)){ if(inOl){html+='</ol>';inOl=false;} if(!inUl){html+='<ul>';inUl=true;} html+='<li>'+inlineFmt(line.replace(/^\-\s+/,''))+'</li>'; continue; }
    if(/^\d+\.\s+/.test(line)){ if(inUl){html+='</ul>';inUl=false;} if(!inOl){html+='<ol>';inOl=true;} html+='<li>'+inlineFmt(line.replace(/^\d+\.\s+/,''))+'</li>'; continue; }
    if(line.trim()===''){ closeList(); html+='<p></p>'; continue; }
    closeList();
    html+='<p>'+inlineFmt(line)+'</p>';
  }
  closeList();
  return html;
}
function formatGenAiForDisplay(raw){
  if(raw===null || raw===undefined) return '';
  let txt=String(raw);
  if(!txt.trim()) return '';

  // Strip AWS CLI --output text metadata header if present
  // Format: "max_tokens\r\nMETRICS\t...\r\nMESSAGE\t...\r\nCONTENT\t\r\n\r\n"
  txt=txt.replace(/^(?:[A-Z_]+(?:\t[^\r\n]*)?\r?\n)+\r?\n?/,'');

  // Strip any fenced-code wrappers
  txt=txt.replace(/^\s*```(?:json|markdown|md|text)?\s*/i,'').replace(/\s*```\s*$/i,'').trim();
  if(!txt) return '';

  // Case 1: already clean markdown (has ## headers) — pass straight to renderMarkdown
  if(/^##\s+\S/m.test(txt)) return txt;

  // Case 2: raw JSON object from Bedrock
  function tryParseJson(t){
    try { return JSON.parse(t); } catch {}
    const s=t.indexOf('{'), e=t.lastIndexOf('}');
    if(s>=0 && e>s){ try { return JSON.parse(t.slice(s,e+1)); } catch {} }
    return null;
  }
  function norm(s){ return String(s||'').replace(/\\n/g,'\n').replace(/\\r/g,'').trim(); }

  const obj=tryParseJson(txt);
  if(obj && typeof obj==='object' && !Array.isArray(obj)){
    const out=[];
    const field=(label,val)=>{ const v=norm(val); if(v){ out.push('**'+label+':** '+v); out.push(''); } };
    if(obj.summary){ out.push('## Summary'); out.push(''); out.push(norm(obj.summary)); out.push(''); }
    if(Array.isArray(obj.diagnostic_tests) && obj.diagnostic_tests.length){
      out.push('## Diagnostic Tests'); out.push('');
      obj.diagnostic_tests.forEach((t,i)=>{ out.push('### Test '+(i+1)); out.push(''); field('Test',t.test); field('Why',t.why); field('How To Run',t.how_to_run); field('Expected Signal',t.expected_signal); });
    }
    if(Array.isArray(obj.fix_plan) && obj.fix_plan.length){
      out.push('## Fix Plan'); out.push('');
      obj.fix_plan.forEach((f,i)=>{ out.push('### Action '+(i+1)); out.push(''); field('Priority',f.priority); field('Action',f.action); field('Risk',f.risk); });
    }
    if(Array.isArray(obj.alternative_root_causes) && obj.alternative_root_causes.length){
      out.push('## Alternative Root Causes'); out.push('');
      obj.alternative_root_causes.forEach(c=>{ field('Cause',c.cause); field('Confidence',c.confidence); field('Evidence',c.evidence); field('Links',c.links); });
    }
    if(Array.isArray(obj.superuser_improvements) && obj.superuser_improvements.length){
      out.push('## Superuser Improvements'); out.push('');
      obj.superuser_improvements.forEach(s=>out.push('- '+norm(s)));
      out.push('');
    }
    if(out.length) return out.join('\n');
  }

  // Case 3: plain text — pass through as-is
  return txt;
}
function linkifyMarkdownTimestamps(){
  const host=document.getElementById('markdownView');
  if(!host){ return; }
  const walker=document.createTreeWalker(host, NodeFilter.SHOW_TEXT, null);
  const nodes=[];
  let cur=null;
  while((cur=walker.nextNode())){ if(cur.nodeValue && /\d{4}-\d{2}-\d{2}/.test(cur.nodeValue)){ nodes.push(cur); } }
  const re=/\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\b/g;
  nodes.forEach(node=>{
    const text=node.nodeValue||'';
    re.lastIndex=0;
    let m=null,last=0,changed=false;
    const frag=document.createDocumentFragment();
    while((m=re.exec(text))){
      changed=true;
      if(m.index>last){ frag.appendChild(document.createTextNode(text.slice(last,m.index))); }
      const b=document.createElement('button');
      b.className='ts-link';
      b.type='button';
      b.textContent='⏱ '+m[1];
      b.dataset.ts=m[1];
      frag.appendChild(b);
      last=m.index+m[1].length;
    }
    if(!changed){ return; }
    if(last<text.length){ frag.appendChild(document.createTextNode(text.slice(last))); }
    node.parentNode.replaceChild(frag,node);
  });
  host.querySelectorAll('.ts-link').forEach(btn=>{
    btn.addEventListener('click',()=>jumpToTimestamp(btn.dataset.ts||''));
  });
}
function initAmbientField(sevCounts){
  const ambient=document.getElementById('ambientField');
  const host=document.getElementById('ambientIcons');
  if(!ambient || !host){ return; }
  const high=Number(sevCounts.High||0);
  const med=Number(sevCounts.Medium||0);
  if(high>0){ ambient.classList.add('high-alert'); }
  const total=20;
  const errCount=Math.min(6,Math.max(2,high*2));
  const warnCount=Math.min(6,Math.max(3,med+2));
  const okCount=Math.max(4,total-errCount-warnCount);
  const mk=(cls,sym,n)=>{
    for(let i=0;i<n;i++){
      const d=document.createElement('span');
      d.className='icon '+cls;
      d.textContent=sym;
      d.style.left=(Math.random()*96+1)+'%';
      d.style.top=(Math.random()*92+2)+'%';
      d.style.animationDelay=('-'+(Math.random()*10).toFixed(2)+'s');
      d.style.animationDuration=((cls==='err'?4.8:cls==='warn'?6.2:7.5)+(Math.random()*2.1)).toFixed(1)+'s';
      host.appendChild(d);
    }
  };
  mk('err','✖',errCount);
  mk('warn','⚠',warnCount);
  mk('ok','✓',okCount);
}
function getViewRows(){
  if(samplesData.length===0) return [];
  const start=Math.max(0,Math.min(viewStart,samplesData.length-1));
  const end=Math.min(samplesData.length,start+viewCount);
  return samplesData.slice(start,end);
}
function detectIncidentBands(rows){
  const out=[];
  let open=-1;
  const isIncident = (r)=> (Number(r.CpuPct||0)>=90) || (Number(r.DiskBusyPct||0)>=90) || (Number(r.MemoryAvailableMB||999999)<=700) || (Number(r.DpcPct||0)>=8) || (Number(r.InterruptPct||0)>=6) || !!r.IsSpike;
  for(let i=0;i<rows.length;i++){
    if(isIncident(rows[i])){
      if(open<0) open=i;
    } else if(open>=0){
      out.push([open, i-1]); open=-1;
    }
  }
  if(open>=0) out.push([open, rows.length-1]);
  return out;
}
const globalBands = detectIncidentBands(samplesData);
function seriesDefsForRows(rows){
  const memMax=Math.max(...rows.map(r=>Number(r.MemoryAvailableMB||0)),1);
  const defs=[];
  if(rows.some(r=>Number(r.CpuPct||0)>=0)){ defs.push({name:'CPU %',color:'#57d3a4',mode:'cpu',fn:(r)=>Number(r.CpuPct||0)}); }
  if(rows.some(r=>Number(r.DiskBusyPct||0)>=0)){ defs.push({name:'Disk Busy %',color:'#f6bd60',mode:'disk',fn:(r)=>Number(r.DiskBusyPct||0)}); }
  if(rows.some(r=>Number(r.MemoryAvailableMB||0)>0)){ defs.push({name:'Memory Avail (norm)',color:'#6aa7ff',mode:'memory',fn:(r)=>(Number(r.MemoryAvailableMB||0)/memMax)*100}); }
  if(rows.some(r=>Number(r.DpcPct||0)>0)){ defs.push({name:'DPC %',color:'#ff7ea8',mode:'dpc',fn:(r)=>Math.min(100,Number(r.DpcPct||0))}); }
  if(rows.some(r=>Number(r.InterruptPct||0)>0)){ defs.push({name:'ISR %',color:'#ffa3d1',mode:'isr',fn:(r)=>Math.min(100,Number(r.InterruptPct||0))}); }
  if(rows.some(r=>Number(r.NetworkRecvMbps||0)>0)){ defs.push({name:'Network Rx Mb/s',color:'#b87dff',mode:'network',fn:(r)=>Math.min(100,Number(r.NetworkRecvMbps||0))}); }
  if(rows.some(r=>Number(r.NetworkSendMbps||0)>0)){ defs.push({name:'Network Tx Mb/s',color:'#7ee0ff',mode:'network',fn:(r)=>Math.min(100,Number(r.NetworkSendMbps||0))}); }
  return defs;
}
function renderLegend(){
  const host=document.getElementById('perfLegend');
  if(!host){ return; }
  const items=[];
  const defs=seriesDefsForRows(samplesData);
  defs.forEach(d=>items.push({name:d.name,color:d.color}));
  if(samplesData.some(r=>!!r.IsSpike)){ items.push({name:'Spike Marker',color:'#ef6f6c'}); }
  if(globalBands.length>0){ items.push({name:'Incident Window',color:'#ff8b8b'}); }
  host.innerHTML=items.map(i=>'<span class="lg-item"><span class="lg-dot" style="background:'+i.color+'"></span>'+i.name+'</span>').join('');
}
function renderResourceFilters(){
  const host=document.getElementById('resourceFilters');
  if(!host){ return; }
  const all=[
    {k:'CPU',label:'CPU Processes',show:samplesData.some(r=>String(r.TopCpuProcesses||'').length>0)},
    {k:'Memory',label:'Memory Processes',show:samplesData.some(r=>String(r.TopMemoryProcesses||'').length>0)},
    {k:'DiskIO',label:'Disk I/O Processes',show:samplesData.some(r=>String(r.TopIoProcesses||'').length>0)},
    {k:'Network',label:'Network Processes',show:samplesData.some(r=>String(r.TopNetworkProcesses||'').length>0 || Number(r.NetworkRecvMbps||0)>0 || Number(r.NetworkSendMbps||0)>0)},
    {k:'Adapters',label:'Adapters',show:samplesData.some(r=>String(r.TopAdapters||'').length>0)},
    {k:'DpcIsr',label:'DPC/ISR',show:samplesData.some(r=>Number(r.DpcPct||0)>0 || Number(r.InterruptPct||0)>0)}
  ].filter(x=>x.show);
  if(all.length===0){ host.innerHTML=''; return; }
  host.innerHTML='';
  all.forEach(item=>{
    const label=el('label');
    const cb=document.createElement('input');
    cb.type='checkbox';
    cb.checked=resourceColumnState[item.k]!==false;
    cb.addEventListener('change',()=>{ resourceColumnState[item.k]=cb.checked; renderResourceRows(); });
    label.appendChild(cb);
    label.appendChild(document.createTextNode(item.label));
    host.appendChild(label);
  });
}
function renderResourceRows(){
  const rows=getViewRows();
  const out=rows.slice(0,140).map(r=>{
    let clue='';
    if(Number(r.CpuPct||0)>=90){ clue+='CPU saturation; '; }
    if(Number(r.DiskBusyPct||0)>=90){ clue+='Disk saturation; '; }
    if(Number(r.MemoryAvailableMB||0)<=700){ clue+='Low memory; '; }
    if(Number(r.DpcPct||0)>=8 || Number(r.InterruptPct||0)>=6){ clue+='Driver interrupt latency; '; }
    if((Number(r.NetworkRecvMbps||0)+Number(r.NetworkSendMbps||0))>=150){ clue+='High network throughput; '; }
    if(!clue){ clue='No major pressure at this sample'; }
    return {
      Timestamp:r.Timestamp||'',
      CPU:r.TopCpuProcesses||'',
      Memory:r.TopMemoryProcesses||'',
      DiskIO:r.TopIoProcesses||'',
      Network:r.TopNetworkProcesses||'',
      Adapters:r.TopAdapters||'',
      DpcIsr:('DPC '+Number(r.DpcPct||0).toFixed(2)+'% | ISR '+Number(r.InterruptPct||0).toFixed(2)+'%'),
      Clue:clue.trim()
    };
  });
  const cols=['Timestamp'];
  if(resourceColumnState.CPU){ cols.push('CPU'); }
  if(resourceColumnState.Memory){ cols.push('Memory'); }
  if(resourceColumnState.DiskIO){ cols.push('DiskIO'); }
  if(resourceColumnState.Network){ cols.push('Network'); }
  if(resourceColumnState.Adapters){ cols.push('Adapters'); }
  if(resourceColumnState.DpcIsr){ cols.push('DpcIsr'); }
  cols.push('Clue');
  table('resourceTbl',cols,out);
}
function renderReplayForFinding(idx){
  const f=findingsData[idx]||{};
  const mode=findingToMode(f.Category||'');
  const bandIdx=bandForMode(mode);
  if(bandIdx>=0){ focusBand(bandIdx); }
  const centerIdx=Math.max(0,Math.min(samplesData.length-1,viewStart+Math.floor(viewCount/2)));
  const centerTs=parseTs((samplesData[centerIdx]||{}).Timestamp||'');
  renderReplayAroundMs(centerTs);
}
function goToSection(id){
  const node=document.getElementById(id);
  if(!node){ return; }
  node.scrollIntoView({behavior:'smooth',block:'start'});
  node.classList.add('pulse');
  setTimeout(()=>node.classList.remove('pulse'),1200);
}
function focusBand(idx){
  if(!globalBands.length){ return; }
  bandCursor=Math.max(0,Math.min(globalBands.length-1,idx));
  const b=globalBands[bandCursor];
  const pad=6;
  viewStart=Math.max(0,b[0]-pad);
  viewCount=Math.max(8,Math.min(samplesData.length-viewStart,(b[1]-b[0])+1+(pad*2)));
  drawLineChart(); drawMiniChart(); renderResourceRows();
}
function bandForMode(mode){
  if(!globalBands.length){ return -1; }
  if(!mode){ return 0; }
  let bestIdx=0;
  let bestScore=-1;
  for(let i=0;i<globalBands.length;i++){
    const b=globalBands[i];
    const slice=samplesData.slice(b[0],b[1]+1);
    let score=0;
    if(mode==='cpu'){ score=Math.max.apply(null,slice.map(r=>Number(r.CpuPct||0))); }
    else if(mode==='disk'){ score=Math.max.apply(null,slice.map(r=>Number(r.DiskBusyPct||0))); }
    else if(mode==='network'){ score=Math.max.apply(null,slice.map(r=>Number(r.NetworkRecvMbps||0)+Number(r.NetworkSendMbps||0))); }
    else if(mode==='dpc'){ score=Math.max.apply(null,slice.map(r=>Math.max(Number(r.DpcPct||0),Number(r.InterruptPct||0)))); }
    else if(mode==='memory'){ score=Math.max.apply(null,slice.map(r=>100-Math.min(100,Math.max(0,Number(r.MemoryAvailableMB||0)/100)))); }
    else if(mode==='spike'){ score=slice.some(r=>!!r.IsSpike)?100:0; }
    if(score>bestScore){ bestScore=score; bestIdx=i; }
  }
  return bestIdx;
}
function drawLineChart(){
  const cv=document.getElementById('perfChart'); const ctx=cv.getContext('2d'); const rows=getViewRows(); const tip=document.getElementById('tip');
  ctx.clearRect(0,0,cv.width,cv.height); if(!rows.length){ctx.fillStyle='#9db2c7';ctx.fillText('No live samples.',20,30);return;}
  const p=26,w=cv.width-p*2,h=cv.height-p*2;
  const x=i=>p+(i/(rows.length-1||1))*w; const y=v=>p+h-(Math.max(0,Math.min(100,v))/100)*h;
  const bands = detectIncidentBands(rows);
  const selectedBand = globalBands.length ? globalBands[bandCursor] : null;
  bands.forEach((b)=>{
    const x1=x(b[0]), x2=x(b[1]);
    const absStart=viewStart+b[0], absEnd=viewStart+b[1];
    const isSelected=selectedBand && absStart<=selectedBand[1] && absEnd>=selectedBand[0];
    ctx.fillStyle=isSelected?'rgba(239,111,108,0.24)':'rgba(239,111,108,0.12)';
    ctx.fillRect(x1,p,Math.max(3,x2-x1),h);
    ctx.strokeStyle=isSelected?'rgba(255,120,120,0.95)':'rgba(239,111,108,0.45)';
    ctx.lineWidth=isSelected?2:1;
    ctx.strokeRect(x1,p,Math.max(3,x2-x1),h);
  });
  for(let i=0;i<5;i++){
    if(i%2===0){
      const y1=p+(h*i/5), y2=p+(h*(i+1)/5);
      ctx.fillStyle='rgba(24,61,92,0.22)';
      ctx.fillRect(p,y1,w,y2-y1);
    }
  }
  ctx.strokeStyle='#1c3f5f'; for(let i=0;i<=5;i++){const yy=p+(h*i/5);ctx.beginPath();ctx.moveTo(p,yy);ctx.lineTo(p+w,yy);ctx.stroke();}
  function plot(name,color,fn,modeTag){
    const isHot=highlightMode===modeTag; ctx.strokeStyle=color; ctx.lineWidth=isHot?4:2; ctx.beginPath();
    rows.forEach((r,i)=>{const xx=x(i),yy=y(fn(r)); if(i)ctx.lineTo(xx,yy); else ctx.moveTo(xx,yy);});
    ctx.stroke(); if(isHot){ctx.strokeStyle='rgba(239,111,108,0.45)';ctx.lineWidth=7;ctx.stroke();}
  }
  const defs=seriesDefsForRows(rows);
  defs.forEach(d=>plot(d.name,d.color,d.fn,d.mode));
  ctx.strokeStyle=(highlightMode==='spike')?'#ff4d4d':'#ef6f6c'; ctx.lineWidth=(highlightMode==='spike')?2.5:1;
  rows.forEach((r,i)=>{if(r.IsSpike){const xx=x(i); ctx.beginPath(); ctx.moveTo(xx,p); ctx.lineTo(xx,p+h); ctx.stroke();}});
  if(hoverIndex>=0 && hoverIndex<rows.length){
    const r=rows[hoverIndex], xx=x(hoverIndex); ctx.strokeStyle='#ffffff'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(xx,p); ctx.lineTo(xx,p+h); ctx.stroke();
    const text='CPU '+Number(r.CpuPct||0).toFixed(1)+'% | Disk '+Number(r.DiskBusyPct||0).toFixed(1)+'% | MemAvail '+Number(r.MemoryAvailableMB||0).toFixed(0)+'MB | DPC '+Number(r.DpcPct||0).toFixed(2)+'% | ISR '+Number(r.InterruptPct||0).toFixed(2)+'% | Rx '+Number(r.NetworkRecvMbps||0).toFixed(1)+'Mb/s | Tx '+Number(r.NetworkSendMbps||0).toFixed(1)+'Mb/s';
    tip.style.display='block'; tip.style.left=canvasToCssX(xx,cv)+'px'; tip.style.top=(y(Number(r.CpuPct||0))-6)+'px'; tip.textContent=text;
  } else { tip.style.display='none'; }
}
function drawMiniChart(){
  const cv=document.getElementById('miniChart'); const ctx=cv.getContext('2d'); const rows=samplesData;
  ctx.clearRect(0,0,cv.width,cv.height); if(!rows.length){ctx.fillStyle='#9db2c7';ctx.fillText('No samples.',20,26);return;}
  const p=12,w=cv.width-p*2,h=cv.height-p*2; const x=i=>p+(i/(rows.length-1||1))*w; const y=v=>p+h-(Math.max(0,Math.min(100,v))/100)*h;
  for(let i=0;i<2;i++){
    if(i%2===0){
      const y1=p+(h*i/2), y2=p+(h*(i+1)/2);
      ctx.fillStyle='rgba(24,61,92,0.2)';
      ctx.fillRect(p,y1,w,y2-y1);
    }
  }
  ctx.strokeStyle='#224561'; for(let i=0;i<=2;i++){const yy=p+(h*i/2);ctx.beginPath();ctx.moveTo(p,yy);ctx.lineTo(p+w,yy);ctx.stroke();}
  const defs=seriesDefsForRows(rows).slice(0,4);
  defs.forEach((d,idx)=>{
    ctx.strokeStyle=d.color; ctx.lineWidth=idx===0?1.5:1.2; ctx.beginPath();
    rows.forEach((r,i)=>{const xx=x(i),yy=y(d.fn(r)); i?ctx.lineTo(xx,yy):ctx.moveTo(xx,yy);});
    ctx.stroke();
  });
  const startRatio = viewStart/Math.max(rows.length,1);
  const countRatio = viewCount/Math.max(rows.length,1);
  const sx = p + (startRatio*w);
  const sw = Math.max(8, countRatio*w);
  ctx.fillStyle='rgba(106,167,255,0.2)'; ctx.fillRect(sx,p,sw,h);
  ctx.strokeStyle='#6aa7ff'; ctx.lineWidth=2; ctx.strokeRect(sx,p,sw,h);
}
function drawBars(){
  const cv=document.getElementById('eventBars'); const ctx=cv.getContext('2d'); const idCounts=topEntries(countBy(eventsData,'Id'),8);
  ctx.clearRect(0,0,cv.width,cv.height); if(!idCounts.length){ctx.fillStyle='#9db2c7';ctx.fillText('No event data.',20,30);return;}
  const labels=idCounts.map(x=>x[0]), values=idCounts.map(x=>x[1]); const p=28,w=cv.width-p*2,h=cv.height-p*2,max=Math.max(...values,1),bw=Math.max(18,Math.floor(w/labels.length)-10);
  labels.forEach((label,i)=>{const xx=p+i*(bw+10), bh=(values[i]/max)*h, yy=p+h-bh; ctx.fillStyle='#61a7ff'; ctx.fillRect(xx,yy,bw,bh); ctx.fillStyle='#cfe2f5'; ctx.fillText(label,xx,p+h+14); ctx.fillText(String(values[i]),xx,yy-4);});
}
function findingToMode(cat){
  const c=(cat||'').toLowerCase();
  if(c.indexOf('storage')>=0) return 'disk';
  if(c.indexOf('cpu')>=0) return 'cpu';
  if(c.indexOf('dpc')>=0 || c.indexOf('isr')>=0 || c.indexOf('driver latency')>=0) return 'dpc';
  if(c.indexOf('network')>=0 || c.indexOf('wifi')>=0 || c.indexOf('ethernet')>=0) return 'network';
  if(c.indexOf('memory')>=0 || c.indexOf('paging')>=0) return 'memory';
  if(c.indexOf('whea')>=0 || c.indexOf('thrott')>=0) return 'spike';
  return '';
}

const sampleCount=samplesData.length, eventCount=eventsData.length, appCount=appHitsData.length, spikeCount=samplesData.filter(s=>s.IsSpike).length;
const sevCounts=countBy(findingsData,'Severity');
initAmbientField(sevCounts);
const kpiSpec=[
  {label:'Samples',value:sampleCount,tone:'info',target:'timelineCard'},
  {label:'Events',value:eventCount,tone:'info',target:'eventCard'},
  {label:'App Hits',value:appCount,tone:(appCount===0?'low':'info'),target:'appCard'},
  {label:'Spike Samples',value:spikeCount,tone:(spikeCount>0?'med':'info'),target:'timelineCard',action:'spike'},
  {label:'High Findings',value:(sevCounts.High||0),tone:((sevCounts.High||0)>0?'high':'info'),target:'findingCard'},
  {label:'Medium Findings',value:(sevCounts.Medium||0),tone:((sevCounts.Medium||0)>0?'med':'low'),target:'findingCard'}
];
kpiSpec.forEach((item,idx)=>{
  const c=el('div');
  c.className='kpi '+item.tone+' nav';
  c.style.animationDelay=(idx*0.05)+'s';
  c.appendChild(el('div',item.label));
  const n=el('div',String(item.value)); n.className='v'; c.appendChild(n);
  c.addEventListener('click',()=>{
    if(item.target){ goToSection(item.target); }
    if(item.action==='spike'){
      const spikeIdx=bandForMode('spike');
      if(spikeIdx>=0){ focusBand(spikeIdx); }
      highlightMode='spike';
      drawLineChart();
    }
  });
  document.getElementById('kpis').appendChild(c);
});
if((sevCounts.High||0)>0){document.getElementById('findingCard').classList.add('alert'); document.getElementById('timelineCard').classList.add('alert');}
document.getElementById('sevChips').innerHTML=['High','Medium','Info'].map(s=>'<span class="chip">'+s+': '+(sevCounts[s]||0)+'</span>').join('');
table('findingsTbl',['Severity','Category','Evidence','Recommendation'],findingsData,'Severity','finding-row');
table('rootTbl',['Cause','Confidence','Evidence','Link'],rootScoresData);
table('playTbl',['Cause','Confidence','Action'],playbooksData);
table('eventsTbl',['TimeCreated','Id','LogName','Level','Message'],eventsData);
table('appsTbl',['TimeCreated','Path','Severity','Message'],appHitsData);
table('markerTbl',['TimeCreated','Category','Id','Provider','Message'],markerData);
kvTable('ctxTbl',systemContextData||{});
kvTable('baseTbl',baselineData||{});
table('sourceTbl',['Path','Status','SizeKB'],appSourceHealthData);
if(appHitsData.length===0){
  const empty=document.getElementById('appsEmpty');
  const detail=document.getElementById('appsEmptyDetail');
  empty.style.display='flex';
  detail.style.display='none';
  empty.addEventListener('click',()=>{ detail.style.display = (detail.style.display==='block') ? 'none' : 'block'; });
}
document.getElementById('markdownView').innerHTML=renderMarkdown(reportMd||'No report markdown available.');
linkifyMarkdownTimestamps();
document.getElementById('genAiView').innerHTML=renderMarkdown(formatGenAiForDisplay(genAiText)||'GenAI review not generated for this run. Enable with `-EnableGenAiAssist` and configure OpenAI key auth or AWS Bedrock profile/SSO.');
document.getElementById('suPreview').innerHTML=renderMarkdown('## '+(superUserTitle||'Super User Draft')+'\\n\\n'+(superUserBody||'No draft generated.'));
if(snapshotZipName){
  const bar=document.getElementById('snapshotBar');
  const link=document.getElementById('snapshotLink');
  bar.style.display='block';
  link.href=snapshotZipName;
  link.setAttribute('download', snapshotZipName);
}
if(lightBundleName){
  const b=document.getElementById('liteZipBtn');
  b.style.display='inline-block';
  b.href=lightBundleName;
  b.setAttribute('download', lightBundleName);
}
document.getElementById('copySuBtn').addEventListener('click',async ()=>{
  const payload=(superUserTitle||'')+'\\n\\n'+(superUserBody||'');
  try { await navigator.clipboard.writeText(payload); } catch {}
});
document.getElementById('openSuBtn').addEventListener('click',()=>{
  window.open('https://superuser.com/questions/ask','_blank');
});
renderLegend();
renderResourceFilters();
drawLineChart(); drawBars(); drawMiniChart(); renderResourceRows(); renderReplayForFinding(0);

document.querySelectorAll('#findingsTbl tbody tr').forEach((row,idx)=>{
  row.addEventListener('mouseenter',()=>{
    highlightMode=findingToMode((findingsData[idx]||{}).Category);
    if(highlightMode){document.getElementById('timelineCard').classList.add('pulse');}
    const bandIdx=bandForMode(highlightMode);
    if(bandIdx>=0){ focusBand(bandIdx); }
    drawLineChart();
  });
  row.addEventListener('click',()=>{ renderReplayForFinding(idx); });
  row.addEventListener('mouseleave',()=>{highlightMode=''; document.getElementById('timelineCard').classList.remove('pulse'); drawLineChart();});
});
document.getElementById('perfChart').addEventListener('mousemove',(ev)=>{
  const cv=ev.target; const x=canvasPosX(ev,cv); const rows=getViewRows(); const p=26,w=cv.width-p*2;
  const idx=Math.round(((x-p)/Math.max(w,1))*Math.max(rows.length-1,1)); hoverIndex=Math.max(0,Math.min(rows.length-1,idx)); drawLineChart();
});
document.getElementById('perfChart').addEventListener('mouseleave',()=>{hoverIndex=-1; drawLineChart();});
document.getElementById('perfChart').addEventListener('wheel',(ev)=>{
  ev.preventDefault();
  const dir=ev.deltaY>0?1:-1; const target=Math.max(20,Math.min(samplesData.length,viewCount + (dir*20)));
  viewCount=target; viewStart=Math.max(0,Math.min(viewStart,samplesData.length-viewCount)); drawLineChart(); drawMiniChart(); renderResourceRows();
},{passive:false});
document.getElementById('perfChart').addEventListener('mousedown',(ev)=>{dragStartX=ev.clientX; dragStartView=viewStart;});
window.addEventListener('mouseup',()=>{dragStartX=null;});
window.addEventListener('mousemove',(ev)=>{if(dragStartX===null)return; const dx=ev.clientX-dragStartX; const shift=Math.round((-dx/8)); viewStart=Math.max(0,Math.min(dragStartView+shift,samplesData.length-viewCount)); drawLineChart(); drawMiniChart(); renderResourceRows();});
document.getElementById('resetZoom').addEventListener('click',()=>{viewStart=0; viewCount=Math.max(samplesData.length,1); drawLineChart(); drawMiniChart(); renderResourceRows();});
document.getElementById('firstEvent').addEventListener('click',()=>{focusBand(0);});
document.getElementById('prevEvent').addEventListener('click',()=>{focusBand(bandCursor-1);});
document.getElementById('nextEvent').addEventListener('click',()=>{focusBand(bandCursor+1);});

const mini=document.getElementById('miniChart');
mini.addEventListener('mousedown',(ev)=>{brushDown=true; brushAnchor=canvasPosX(ev,mini);});
window.addEventListener('mouseup',()=>{brushDown=false;});
window.addEventListener('mousemove',(ev)=>{
  if(!brushDown)return;
  const xNow=Math.max(0,Math.min(mini.width,canvasPosX(ev,mini)));
  const x0=Math.max(0,Math.min(mini.width,brushAnchor));
  const left=Math.min(x0,xNow), right=Math.max(x0,xNow);
  const p=12,w=mini.width-p*2;
  const lRatio=Math.max(0,Math.min(1,(left-p)/Math.max(w,1)));
  const rRatio=Math.max(0,Math.min(1,(right-p)/Math.max(w,1)));
  const total=Math.max(samplesData.length,1);
  const s=Math.floor(lRatio*total);
  const e=Math.max(s+5,Math.ceil(rRatio*total));
  viewStart=Math.max(0,Math.min(s,total-1));
  viewCount=Math.max(5,Math.min(total-viewStart,e-viewStart));
  drawLineChart(); drawMiniChart(); renderResourceRows();
});


function renderViewer(name){
  const body=document.getElementById('viewerBody');
  const title=document.getElementById('viewerName');
  const dl=document.getElementById('downloadLink');
  const txt = fileContents[name] || '';
  title.textContent=name;
  const blob = new Blob([txt], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  dl.href=url; dl.download=name;
  body.innerHTML='';

  if(name.toLowerCase().endsWith('.md')){
    body.innerHTML=renderMarkdown(txt);
    return;
  }
  if(name.toLowerCase().endsWith('.csv')){
    const rows=toCsvRows(txt);
    if(rows.length===0){ body.innerHTML='<pre>'+txt+'</pre>'; return; }
    const cols=Object.keys(rows[0]);
    const t=document.createElement('table'); const th=document.createElement('thead'); const hr=document.createElement('tr');
    cols.forEach(c=>{const e=document.createElement('th'); e.textContent=c; hr.appendChild(e);}); th.appendChild(hr); t.appendChild(th);
    const tb=document.createElement('tbody');
    rows.slice(0,300).forEach(r=>{
      const tr=document.createElement('tr');
      cols.forEach(c=>{const td=document.createElement('td'); td.textContent=r[c]||''; tr.appendChild(td);});
      tr.addEventListener('mouseenter',()=>{
        const ts=r.Timestamp || r.TimeCreated;
        if(!ts) return;
        const tMs=Date.parse(ts); if(isNaN(tMs)) return;
        let best=0,bestDiff=Infinity;
        samplesData.forEach((s,i)=>{ const d=Math.abs(Date.parse(s.Timestamp)-tMs); if(d<bestDiff){bestDiff=d;best=i;} });
        hoverIndex=Math.max(0,Math.min(getViewRows().length-1,best-viewStart)); drawLineChart();
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb); body.appendChild(t); return;
  }
  if(name.toLowerCase().endsWith('.json')){
    try{ const obj=JSON.parse(txt); body.innerHTML='<pre>'+JSON.stringify(obj,null,2)+'</pre>'; } catch { body.innerHTML='<pre>'+txt+'</pre>'; }
    return;
  }
  body.innerHTML='<pre>'+txt+'</pre>';
}

const categories=[
  {name:'Main Reports', files:['report.md','findings.csv','root_cause_scores.csv','playbooks.csv','genai_review.md','genai_review_raw.txt','superuser_draft.md','superuser_draft.txt']},
  {name:'Performance Data', files:['performance_samples.csv','process_hotspots.csv']},
  {name:'Logs & Correlation', files:['event_audit.csv','app_log_hits.csv','correlation_markers.csv','app_log_sources.csv','warnings.json']},
  {name:'ETW Traces', files:['spike_etw_traces.csv']}
];
const catHost=document.getElementById('cats');
categories.forEach(cat=>{
  const c=el('div'); c.className='cat';
  const title=el('div',cat.name); title.className='cat-title'; c.appendChild(title);
  const list=el('div'); list.className='file-list';
  cat.files.forEach(f=>{
    const a=el('a',f); a.className='file-btn'; a.href='#';
    a.addEventListener('click',(ev)=>{ev.preventDefault(); renderViewer(f); a.classList.remove('downloading'); void a.offsetWidth; a.classList.add('downloading');});
    list.appendChild(a);
  });
  title.addEventListener('click',()=>{
    const isOpen=c.classList.contains('open');
    document.querySelectorAll('.cat').forEach(x=>x.classList.remove('open'));
    if(!isOpen){ c.classList.add('open'); }
  });
  c.appendChild(list); catHost.appendChild(c);
});
if(catHost.firstElementChild){ catHost.firstElementChild.classList.add('open'); }

if((sevCounts.High||0)>0 || appHitsData.length===0){
  document.getElementById('findingCard').classList.add('focus');
  document.getElementById('timelineCard').classList.add('focus');
}
renderViewer('report.md');
</script>
</body>
</html>
"@
  $html | Set-Content -LiteralPath $path -Encoding UTF8
}

function Read-WizardChoice([string]$title,[object[]]$choices,[int]$default = 1) {
  Write-Host ''
  Write-Host $title -ForegroundColor Cyan
  foreach ($c in $choices) {
    Write-Host ("  {0}. {1}" -f $c.Key, $c.Label) -ForegroundColor White
    Write-Host ("     {0}" -f $c.Desc) -ForegroundColor DarkGray
  }
  $raw = Read-Host ("Select [{0}]" -f $default)
  if ([string]::IsNullOrWhiteSpace($raw)) { $raw = [string]$default }
  $picked = $choices | Where-Object { $_.Key -eq $raw } | Select-Object -First 1
  if (-not $picked) { $picked = $choices | Select-Object -First 1 }
  return $picked
}

function Get-InteractiveGenAiParams([bool]$allowDisable = $true,[int]$defaultEnable = 2) {
  $genaiEnabled = $true
  if ($allowDisable) {
    $genai = Read-WizardChoice '🤖 GenAI Diagnostic Review' @(
      @{ Key='1'; Label='Enabled'; Desc='Uses API key env var to generate diagnostic tests/fixes.'; Enabled=$true },
      @{ Key='2'; Label='Disabled'; Desc='Skip GenAI analysis.'; Enabled=$false }
    ) $defaultEnable
    $genaiEnabled = [bool]$genai.Enabled
  }
  if (-not $genaiEnabled) { return @{ EnableGenAiAssist = $false } }

  $genaiProvider = Read-WizardChoice '🧠 GenAI Provider' @(
    @{ Key='1'; Label='OpenAI API'; Desc='Use OpenAI model + API key auth.'; Provider='openai' },
    @{ Key='2'; Label='AWS Bedrock'; Desc='Use Bedrock model + AWS profile/SSO auth.'; Provider='bedrock' }
  ) 1

  $result = @{
    EnableGenAiAssist = $true
    GenAiProvider = [string]$genaiProvider.Provider
  }

  if ($result['GenAiProvider'] -eq 'openai') {
    $openAiAuth = Read-WizardChoice '🔐 OpenAI Key Auth' @(
      @{ Key='1'; Label='Short-term session'; Desc='Use key now, keep only process env.'; Persist='process'; Cache=$false },
      @{ Key='2'; Label='Long-term secure file'; Desc='Store encrypted key for reuse on this machine account.'; Persist='securefile'; Cache=$true },
      @{ Key='3'; Label='Use existing env/cache'; Desc='Do not prompt for key now.'; Persist='none'; Cache=$true }
    ) 1
    if ($openAiAuth.Key -ne '3') {
      $openAiInlineKey = Read-Host 'Paste OpenAI API key (input hidden recommended by terminal settings)'
      if (-not [string]::IsNullOrWhiteSpace($openAiInlineKey)) { $result['GenAiApiKey'] = $openAiInlineKey }
    }
    $result['GenAiApiKeyPersist'] = [string]$openAiAuth.Persist
    if ($openAiAuth.Cache) { $result['UseCachedApiKey'] = $true }
    return $result
  }

  $bedrockSso = Read-WizardChoice '🪪 AWS Auth Mode' @(
    @{ Key='1'; Label='Use AWS SSO profile'; Desc='Resolve profile from AWS_PROFILE or configured profiles.'; UseSso=$true },
    @{ Key='2'; Label='Manual profile'; Desc='Provide a named AWS profile explicitly.'; UseSso=$false }
  ) 1
  $bedrockProfileInput = Read-Host 'AWS profile name (SSO profile name if using SSO)'
  $bedrockRegionInput = Read-Host 'AWS region for Bedrock [us-east-1]'
  $bedrockModelInput = Read-Host 'Bedrock model ID [anthropic.claude-opus-4-6-v1]'
  $result['BedrockRegion'] = if ([string]::IsNullOrWhiteSpace($bedrockRegionInput)) { 'us-east-1' } else { $bedrockRegionInput }
  $result['BedrockModelId'] = if ([string]::IsNullOrWhiteSpace($bedrockModelInput)) { 'anthropic.claude-opus-4-6-v1' } else { $bedrockModelInput }
  if ($bedrockSso -and $bedrockSso.UseSso) { $result['BedrockUseSsoProfile'] = $true }
  if (-not [string]::IsNullOrWhiteSpace($bedrockProfileInput)) { $result['BedrockProfile'] = $bedrockProfileInput }
  return $result
}

function Get-RunFolderCandidates([string]$root) {
  if ([string]::IsNullOrWhiteSpace($root)) { return @() }
  if (-not (Test-Path -LiteralPath $root)) { return @() }
  $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  $hits = New-Object System.Collections.Generic.List[object]
  foreach ($d in $dirs) {
    $hasData = (Test-Path -LiteralPath (Join-Path $d.FullName 'report.md')) -or
      (Test-Path -LiteralPath (Join-Path $d.FullName 'findings.csv')) -or
      (Test-Path -LiteralPath (Join-Path $d.FullName 'performance_samples.csv')) -or
      (Test-Path -LiteralPath (Join-Path $d.FullName 'event_audit.csv'))
    if ($hasData) {
      [void]$hits.Add([pscustomobject]@{
        Name = $d.Name
        FullName = $d.FullName
        LastWriteTime = $d.LastWriteTime
      })
    }
  }
  return @($hits)
}

function Get-InteractiveRunParams {
  Write-Host ''
  Write-Host '🧭 SpikeSleuth Wizard' -ForegroundColor Magenta
  Write-Host 'Build a run configuration step-by-step with guided options.' -ForegroundColor DarkGray

  $mode = Read-WizardChoice '🔁 Run Mode' @(
    @{ Key='1'; Label='One-time run'; Desc='Collect once and stop.'; Continuous=$false; Cycle=0 },
    @{ Key='2'; Label='Continuous'; Desc='Loop forever with short cycles until Ctrl+C.'; Continuous=$true; Cycle=3 },
    @{ Key='3'; Label='Service style'; Desc='Continuous mode with retention + daily summary.'; Continuous=$true; Service=$true; Cycle=3 },
    @{ Key='4'; Label='AI review existing run'; Desc='Pick a previous run folder and generate/re-generate GenAI review only.'; ExistingAi=$true; Continuous=$false; Cycle=0 }
  ) 1

  if ($mode.PSObject.Properties.Name -contains 'ExistingAi' -and $mode.ExistingAi) {
    $defaultRoot = Join-Path $env:USERPROFILE 'SpikeSleuth'
    $rootInput = Read-Host ("📂 Output root to scan for past runs [{0}]" -f $defaultRoot)
    $scanRoot = if ([string]::IsNullOrWhiteSpace($rootInput)) { $defaultRoot } else { $rootInput }
    $candidates = @(Get-RunFolderCandidates -root $scanRoot)
    Write-Host ''
    Write-Host ("Found {0} run folder(s) with reviewable artifacts in: {1}" -f $candidates.Count, $scanRoot) -ForegroundColor Cyan

    $selectedPath = ''
    if ($candidates.Count -gt 0) {
      $choices = New-Object System.Collections.Generic.List[object]
      $maxChoices = [Math]::Min($candidates.Count, 30)
      for ($idx = 0; $idx -lt $maxChoices; $idx++) {
        $run = $candidates[$idx]
        [void]$choices.Add(@{
          Key = [string]($idx + 1)
          Label = [string]$run.Name
          Desc = ("Updated {0} | {1}" -f $run.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $run.FullName)
          RunPath = $run.FullName
        })
      }
      [void]$choices.Add(@{
        Key = 'M'
        Label = 'Manual path'
        Desc = 'Type a run folder path manually.'
        RunPath = ''
      })
      $pickedRun = Read-WizardChoice '📁 Pick run folder for GenAI review' @($choices) 1
      if ($pickedRun.Key -eq 'M') {
        $selectedPath = Read-Host 'Enter run folder path'
      } else {
        $selectedPath = [string]$pickedRun.RunPath
      }
    } else {
      $selectedPath = Read-Host 'No run folders found automatically. Enter run folder path manually'
    }

    if ([string]::IsNullOrWhiteSpace($selectedPath) -or -not (Test-Path -LiteralPath $selectedPath)) {
      Write-Host ("Run folder not found: {0}" -f $selectedPath) -ForegroundColor Red
      return $null
    }
    $selectedFullPath = [IO.Path]::GetFullPath($selectedPath)
    Write-Host ("Selected run folder: {0}" -f $selectedFullPath) -ForegroundColor Yellow

    $genAiParams = Get-InteractiveGenAiParams -allowDisable $false -defaultEnable 1
    $params = @{
      ExistingRunGenAiOnly = $true
      ExistingRunPath = $selectedFullPath
    }
    foreach ($k in $genAiParams.Keys) { $params[$k] = $genAiParams[$k] }

    Write-Host ''
    Write-Host '✅ Summary' -ForegroundColor Green
    foreach ($k in $params.Keys) { Write-Host ("  {0} = {1}" -f $k, $params[$k]) -ForegroundColor Yellow }
    $go = Read-Host 'Run AI review now? [Y/n]'
    if ([string]::IsNullOrWhiteSpace($go) -or $go -match '^(?i)y') { return $params }
    Write-Host 'Wizard canceled.' -ForegroundColor Red
    return $null
  }

  $sampleInterval = 1
  while ($true) {
    $rawInterval = Read-Host '⏱️ Sample interval in seconds (1-60) [1]'
    if ([string]::IsNullOrWhiteSpace($rawInterval)) { $sampleInterval = 1; break }
    $parsed = 0
    if ([int]::TryParse($rawInterval, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le 60) {
      $sampleInterval = $parsed
      break
    }
    Write-Host 'Please enter a whole number between 1 and 60.' -ForegroundColor Red
  }

  $profile = $null
  $customDurationMinutes = 0
  if (-not $mode.Continuous) {
    $profile = Read-WizardChoice '⚙️ Capture Profile' @(
      @{ Key='1'; Label='Fast (5m)'; Desc='Short run for quick checks. Lower data volume.'; Duration=5 },
      @{ Key='2'; Label='Balanced (10m)'; Desc='Recommended baseline for intermittent slowdowns.'; Duration=10 },
      @{ Key='3'; Label='Deep (20m)'; Desc='Higher fidelity + more evidence for hard issues.'; Duration=20 },
      @{ Key='4'; Label='Custom minutes'; Desc='Enter exactly how many minutes to run.'; Custom=$true; Duration=0 }
    ) 2
    $isCustomProfile = $false
    if ($profile -is [hashtable]) {
      $isCustomProfile = ($profile.ContainsKey('Custom') -and [bool]$profile['Custom'])
    } else {
      $isCustomProfile = [bool]$profile.Custom
    }
    if ($isCustomProfile) {
      while ($true) {
        $rawCustom = Read-Host '🕒 Enter custom duration in minutes (1-1440)'
        $parsedCustom = 0
        if ([int]::TryParse($rawCustom, [ref]$parsedCustom) -and $parsedCustom -ge 1 -and $parsedCustom -le 1440) {
          $customDurationMinutes = $parsedCustom
          break
        }
        Write-Host 'Please enter a whole number from 1 to 1440.' -ForegroundColor Red
      }
    }
  }

  $etw = Read-WizardChoice '🧪 Spike ETW Capture' @(
    @{ Key='1'; Label='Enabled (Recommended)'; Desc='Captures short ETW traces on detected spikes.'; Enabled=$true },
    @{ Key='2'; Label='Disabled'; Desc='No ETW traces. Lighter run.'; Enabled=$false }
  ) 1

  $dash = Read-WizardChoice '📊 HTML Dashboard' @(
    @{ Key='1'; Label='Generate + Open'; Desc='Build dashboard and open in default browser.'; Html=$true; Open=$true },
    @{ Key='2'; Label='Generate only'; Desc='Build dashboard but do not auto-open.'; Html=$true; Open=$false },
    @{ Key='3'; Label='Markdown/CSV only'; Desc='Skip dashboard generation.'; Html=$false; Open=$false }
  ) 1

  $snapshot = Read-WizardChoice '🧊 Frozen In Time Snapshot ZIP' @(
    @{ Key='1'; Label='Enabled'; Desc='Zip dashboard + generated files for portable review.'; Enabled=$true },
    @{ Key='2'; Label='Disabled'; Desc='No zip package.'; Enabled=$false }
  ) 1

  $genAiParams = Get-InteractiveGenAiParams -allowDisable $true -defaultEnable 2

  $baselineChoice = Read-WizardChoice '📐 Baseline Mode' @(
    @{ Key='1'; Label='None'; Desc='No baseline save/compare.'; Save=$false; Use=$false },
    @{ Key='2'; Label='Save baseline'; Desc='Save this run as baseline.json.'; Save=$true; Use=$false },
    @{ Key='3'; Label='Compare to baseline'; Desc='Use baseline.json to flag anomalies.'; Save=$false; Use=$true }
  ) 1
  $runNameInput = Read-Host '🏷️ Run name (optional, default is timestamp)'

  $params = @{
    EnableSpikeEtwCapture = [bool]$etw.Enabled
    EnableHtmlReport = [bool]$dash.Html
    OpenDashboard = [bool]$dash.Open
    EnableFrozenSnapshot = [bool]$snapshot.Enabled
    EnableGenAiAssist = [bool]$(if ($genAiParams.ContainsKey('EnableGenAiAssist')) { $genAiParams['EnableGenAiAssist'] } else { $false })
    GenAiProvider = if ($genAiParams.ContainsKey('GenAiProvider')) { [string]$genAiParams['GenAiProvider'] } else { 'openai' }
    ContinuousMode = [bool]$mode.Continuous
    ServiceMode = [bool]$(if ($null -ne $mode.PSObject.Properties['Service']) { $mode.Service } else { $false })
    SaveBaseline = [bool]$baselineChoice.Save
    UseBaseline = [bool]$baselineChoice.Use
    SampleIntervalSeconds = [int]$sampleInterval
  }
  if (-not [string]::IsNullOrWhiteSpace($runNameInput)) { $params['RunName'] = $runNameInput }
  foreach ($k in $genAiParams.Keys) {
    if ($k -eq 'EnableGenAiAssist' -or $k -eq 'GenAiProvider') { continue }
    $params[$k] = $genAiParams[$k]
  }
  if ($params.ContinuousMode) {
    $params['ContinuousCycleMinutes'] = [int]$mode.Cycle
  } else {
    $params['DurationMinutes'] = if ($customDurationMinutes -gt 0) { [int]$customDurationMinutes } else { [int]$profile.Duration }
  }

  Write-Host ''
  Write-Host '✅ Summary' -ForegroundColor Green
  foreach ($k in $params.Keys) { Write-Host ("  {0} = {1}" -f $k, $params[$k]) -ForegroundColor Yellow }
  $go = Read-Host 'Run now? [Y/n]'
  if ([string]::IsNullOrWhiteSpace($go) -or $go -match '^(?i)y') { return $params }
  Write-Host 'Wizard canceled.' -ForegroundColor Red
  return $null
}

function Invoke-ServiceRetention([string]$root,[int]$days) {
  if (-not (Test-Path -LiteralPath $root)) { return }
  $cut = (Get-Date).AddDays(-1 * [Math]::Max($days,1))
  foreach ($d in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
    if ($d.LastWriteTime -lt $cut) {
      try { Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction Stop } catch {}
    }
  }
}

function Update-ServiceDailySummary([string]$root,$analysis,[datetime]$runTime) {
  try {
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    $file = Join-Path $root ("daily-summary-{0}.md" -f $runTime.ToString('yyyyMMdd'))
    if (-not (Test-Path -LiteralPath $file)) {
      "# Service Daily Summary $($runTime.ToString('yyyy-MM-dd'))`n" | Set-Content -LiteralPath $file -Encoding UTF8
    }
    $top = @($analysis.RootCauseScores | Select-Object -First 3 | ForEach-Object { "$($_.Cause)=$($_.Confidence)%" }) -join ', '
    Add-Content -LiteralPath $file -Value ("- [{0}] Findings={1}, TopRoot={2}" -f $runTime, @($analysis.Findings).Count, $top)
  } catch {}
}

function Save-GenAiApiKeySecure([string]$key,[string]$path) {
  if ([string]::IsNullOrWhiteSpace($key)) { return }
  $dir = Split-Path -Path $path -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $sec = ConvertTo-SecureString -String $key -AsPlainText -Force
  $enc = ConvertFrom-SecureString -SecureString $sec
  $enc | Set-Content -LiteralPath $path -Encoding UTF8
}

function Load-GenAiApiKeySecure([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return '' }
  try {
    $enc = Get-Content -LiteralPath $path -Raw
    if ([string]::IsNullOrWhiteSpace($enc)) { return '' }
    $sec = ConvertTo-SecureString -String $enc
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  } catch { return '' }
}

function Resolve-OpenAiApiKey([string]$explicitKey,[string]$envVar,[bool]$useCache,[string]$cachePath) {
  if (-not [string]::IsNullOrWhiteSpace($explicitKey)) { return $explicitKey }
  $k = [Environment]::GetEnvironmentVariable($envVar, 'Process')
  if ([string]::IsNullOrWhiteSpace($k)) { $k = [Environment]::GetEnvironmentVariable($envVar, 'User') }
  if ([string]::IsNullOrWhiteSpace($k)) { $k = [Environment]::GetEnvironmentVariable($envVar, 'Machine') }
  if ([string]::IsNullOrWhiteSpace($k) -and $useCache) { $k = Load-GenAiApiKeySecure -path $cachePath }
  return $k
}

function Apply-OpenAiApiKeyPersistence([string]$key,[string]$scope,[string]$envVar,[string]$cachePath,$warnings) {
  if ([string]::IsNullOrWhiteSpace($key)) { return }
  try {
    switch ($scope) {
      'process' { [Environment]::SetEnvironmentVariable($envVar,$key,'Process') }
      'user' { [Environment]::SetEnvironmentVariable($envVar,$key,'User') }
      'machine' { [Environment]::SetEnvironmentVariable($envVar,$key,'Machine') }
      'securefile' { Save-GenAiApiKeySecure -key $key -path $cachePath }
      default {}
    }
  } catch {
    Add-Warn $warnings "Failed to persist API key ($scope): $($_.Exception.Message)"
  }
}

function Resolve-BedrockProfile([string]$profile,[bool]$useSso) {
  if (-not [string]::IsNullOrWhiteSpace($profile)) { return $profile }
  if (-not $useSso) { return '' }
  $envProfile = [Environment]::GetEnvironmentVariable('AWS_PROFILE','Process')
  if ([string]::IsNullOrWhiteSpace($envProfile)) { $envProfile = [Environment]::GetEnvironmentVariable('AWS_PROFILE','User') }
  if (-not [string]::IsNullOrWhiteSpace($envProfile)) { return $envProfile }
  try {
    if (Get-Command aws -ErrorAction SilentlyContinue) {
      $profiles = @(& aws configure list-profiles 2>$null)
      if ($profiles.Count -gt 0) { return [string]$profiles[0] }
    }
  } catch {}
  return ''
}

function Validate-BedrockAuth([string]$profile,[string]$region,$warnings) {
  if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Add-Warn $warnings 'AWS CLI is required for Bedrock provider.'
    return $false
  }
  try {
    $args = @('sts','get-caller-identity','--region',$region)
    if (-not [string]::IsNullOrWhiteSpace($profile)) { $args = @('sts','get-caller-identity','--profile',$profile,'--region',$region) }
    & aws @args 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "aws sts get-caller-identity failed with exit code $LASTEXITCODE" }
    return $true
  } catch {
    Add-Warn $warnings ("AWS auth validation failed. Run aws sso login for profile '{0}'. Details: {1}" -f $profile, (Get-CleanExceptionMessage $_))
    return $false
  }
}

function Test-BedrockSetup([string]$profile,[bool]$useSso,[string]$region,[string]$model,[bool]$invokeModelTest,$warnings) {
  Write-Host 'Bedrock setup test starting...'
  if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Host 'FAIL: AWS CLI not found in PATH.' -ForegroundColor Red
    Write-Host 'Install AWS CLI and run aws configure sso / aws sso login.' -ForegroundColor Yellow
    return $false
  }
  $resolvedProfile = Resolve-BedrockProfile -profile $profile -useSso $useSso
  Write-Host "Profile: $(if ($resolvedProfile) { $resolvedProfile } else { '<default>' })"
  Write-Host "Region: $region"
  Write-Host "Model: $model"

  $okAuth = Validate-BedrockAuth -profile $resolvedProfile -region $region -warnings $warnings
  if (-not $okAuth) {
    Write-Host 'FAIL: AWS auth validation failed. Run aws sso login and retry.' -ForegroundColor Red
    return $false
  }
  Write-Host 'PASS: AWS auth is valid.' -ForegroundColor Green

  try {
    $args = @('bedrock','list-foundation-models','--region',$region)
    if ($resolvedProfile) { $args = @('bedrock','list-foundation-models','--profile',$resolvedProfile,'--region',$region) }
    & aws @args 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host 'PASS: Bedrock API reachable (list-foundation-models).' -ForegroundColor Green }
    else { Write-Host 'WARN: Could not list foundation models with current auth/region.' -ForegroundColor Yellow }
  } catch {
    Write-Host 'WARN: list-foundation-models check failed.' -ForegroundColor Yellow
  }

  if ($invokeModelTest) {
    try {
      $tmpOut = [System.IO.Path]::GetTempFileName()
      $msg = '[{"role":"user","content":[{"text":"Reply with BEDROCK_TEST_OK"}]}]'
      $inf = '{"maxTokens":64,"temperature":0}'
      $invokeArgs = @('bedrock-runtime','converse','--model-id',$model,'--region',$region,'--messages',$msg,'--inference-config',$inf,'--output','json')
      if ($resolvedProfile) { $invokeArgs = @('bedrock-runtime','converse','--profile',$resolvedProfile,'--model-id',$model,'--region',$region,'--messages',$msg,'--inference-config',$inf,'--output','json') }
      $stderrFile = [System.IO.Path]::GetTempFileName()
      & aws @invokeArgs 2> $stderrFile | Set-Content -LiteralPath $tmpOut -Encoding UTF8
      if ($LASTEXITCODE -ne 0) {
        $errDetail = ''
        try { $errDetail = (Get-Content -LiteralPath $stderrFile -Raw).Trim() } catch {}
        throw "converse failed with exit code $LASTEXITCODE. $errDetail"
      }
      $txt = Get-Content -LiteralPath $tmpOut -Raw
      if ($txt.Length -gt 0) { Write-Host 'PASS: Model invocation test succeeded.' -ForegroundColor Green }
      else { Write-Host 'WARN: Model invocation returned empty output.' -ForegroundColor Yellow }
      try { Remove-Item -LiteralPath $tmpOut,$stderrFile -Force -ErrorAction SilentlyContinue } catch {}
    } catch {
      Write-Host "FAIL: Model invocation test failed: $($_.Exception.Message)" -ForegroundColor Red
      return $false
    }
  } else {
    Write-Host 'Skipped model invocation test. Use -BedrockTestInvokeModel to run end-to-end invoke.' -ForegroundColor DarkYellow
  }

  Write-Host 'Bedrock setup test complete.' -ForegroundColor Green
  return $true
}

function New-SuperUserDraft($analysis,$systemContext,$samples,$events,$appHits,$markers,[string]$userNotes) {
  $ctxModel = ''
  $ctxBios = ''
  if ($systemContext -and $null -ne $systemContext.PSObject.Properties['Model']) { $ctxModel = [string]$systemContext.Model }
  if ($systemContext -and $null -ne $systemContext.PSObject.Properties['BiosVersion']) { $ctxBios = [string]$systemContext.BiosVersion }
  $cpu = ''
  $ramGb = ''
  $ramSpeed = ''
  $gpu = ''
  $disks = ''
  try {
    $cpuObj = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cpuObj) { $cpu = "$($cpuObj.Name) ($($cpuObj.NumberOfCores)C/$($cpuObj.NumberOfLogicalProcessors)T)" }
  } catch {}
  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cs) { $ramGb = [Math]::Round(([double]$cs.TotalPhysicalMemory/1GB),2) }
    $mem = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Select-Object -First 4 Speed,ConfiguredClockSpeed,Capacity)
    if ($mem.Count -gt 0) {
      $ramSpeed = ($mem | ForEach-Object { if ($_.ConfiguredClockSpeed) { "$($_.ConfiguredClockSpeed)MHz" } elseif ($_.Speed) { "$($_.Speed)MHz" } else { '' } } | Where-Object { $_ }) -join ', '
    }
  } catch {}
  try {
    $gpuRows = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 3 Name)
    if ($gpuRows.Count -gt 0) { $gpu = ($gpuRows | ForEach-Object { $_.Name }) -join '; ' }
  } catch {}
  try {
    $diskRows = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object -First 6 Model,MediaType,Size)
    if ($diskRows.Count -gt 0) {
      $disks = ($diskRows | ForEach-Object {
        $sz = if ($_.Size) { [Math]::Round(([double]$_.Size/1GB),1) } else { 0 }
        "$($_.Model) [$($_.MediaType)] ${sz}GB"
      }) -join '; '
    }
  } catch {}

  $sym = New-Object System.Collections.Generic.List[string]
  foreach ($f in @($analysis.Findings | Select-Object -First 8)) { [void]$sym.Add("- [$($f.Severity)] $($f.Category): $($f.Evidence)") }
  if ($sym.Count -eq 0) { [void]$sym.Add('- Intermittent system-wide slowdowns of 10-30 seconds.') }

  $topScores = @($analysis.RootCauseScores | Select-Object -First 5 | ForEach-Object { "- $($_.Cause): $($_.Confidence)% ($($_.Evidence))" }) -join "`n"
  $markerText = @($markers | Select-Object -First 15 | ForEach-Object { "- [$($_.TimeCreated)] [$($_.Category)] $($_.Message)" }) -join "`n"
  $sampleCount = @($samples).Count
  $eventCount = @($events).Count
  $appCount = @($appHits).Count

  $body = @"
# Windows 11 system-wide slowdowns (10-30s pauses) - diagnostic help needed

## Symptoms
$($sym -join "`n")

## User Perspective
$(if ([string]::IsNullOrWhiteSpace($userNotes)) { '(please fill in reproduction steps, what freezes, how often, and what restores responsiveness)' } else { $userNotes })

## System Information
- Model: $ctxModel
- BIOS: $ctxBios
- CPU: $cpu
- RAM: $ramGb GB
- RAM Speed: $ramSpeed
- GPU: $gpu
- Disks: $disks

## What Was Collected
- Performance samples: $sampleCount
- Event signals: $eventCount
- App log hits: $appCount
- Root-cause model scores:
$topScores

## Correlated Markers (boot/resume/update)
$markerText

## What I already tried
- Updated common drivers and checked event logs.
- Collected ETW/perf snapshots around spikes.

## Request
Please suggest the best next diagnostic tests (in order), and what evidence would confirm or disprove each likely root cause.
"@

  $title = 'Windows 11 intermittent system-wide slowdowns (10-30s pauses) - how to diagnose root cause?'
  [pscustomobject]@{ Title=$title; Body=$body }
}

function Invoke-GenAiReview([string]$provider,[string]$apiKey,[string]$model,[string]$reportMarkdown,[string]$findingsCsv,[string]$samplesCsv,[string]$eventsCsv,[string]$systemJson,[string]$superUserDraft,[string]$outputJsonPath,[string]$bedrockRegion,[string]$bedrockProfile,$warnings) {
  function Convert-ToBedrockCliSafeText([string]$text,[string]$label) {
    if ([string]::IsNullOrEmpty($text)) { return '' }
    $origLen = $text.Length
    $fixed = $text.Replace([string][char]0x2192,'->').Replace([string][char]0x2013,'-').Replace([string][char]0x2014,'-')
    # Keep standard printable ASCII + CR/LF/TAB to avoid AWS CLI charmap failures on some Windows locales.
    $safe = [regex]::Replace($fixed, '[^\u0009\u000A\u000D\u0020-\u007E]', '?')
    if ($safe.Length -eq $origLen -and $safe -eq $text) { return $safe }
    Add-Warn $warnings ("Prompt section '{0}' contained non-ASCII characters; sanitized for AWS CLI compatibility." -f $label)
    return $safe
  }

  function Truncate-ForPrompt([string]$label,[string]$text,[int]$maxChars,[int]$headChars,[int]$tailChars) {
    if ([string]::IsNullOrEmpty($text)) { return '' }
    if ($text.Length -le $maxChars) { return $text }
    $headLen = [Math]::Min($headChars, $text.Length)
    $tailLen = [Math]::Min($tailChars, [Math]::Max(($text.Length - $headLen),0))
    $head = $text.Substring(0, $headLen)
    $tail = if ($tailLen -gt 0) { $text.Substring($text.Length - $tailLen) } else { '' }
    $omitted = [Math]::Max(($text.Length - $headLen - $tailLen),0)
    Add-Warn $warnings ("Prompt section '{0}' was truncated by {1} chars to fit model limits." -f $label, $omitted)
    return "{0}`n`n[...TRUNCATED {1} chars for model context limits...]`n`n{2}" -f $head, $omitted, $tail
  }

  # Keep prompts bounded for large historical run folders.
  $reportPrompt = Convert-ToBedrockCliSafeText -label 'REPORT_MD' -text (Truncate-ForPrompt -label 'REPORT_MD' -text $reportMarkdown -maxChars 40000 -headChars 28000 -tailChars 12000)
  $findingsPrompt = Convert-ToBedrockCliSafeText -label 'FINDINGS_CSV' -text (Truncate-ForPrompt -label 'FINDINGS_CSV' -text $findingsCsv -maxChars 80000 -headChars 70000 -tailChars 10000)
  $samplesPrompt = Convert-ToBedrockCliSafeText -label 'SAMPLES_CSV' -text (Truncate-ForPrompt -label 'SAMPLES_CSV' -text $samplesCsv -maxChars 140000 -headChars 120000 -tailChars 20000)
  $eventsPrompt = Convert-ToBedrockCliSafeText -label 'EVENTS_CSV' -text (Truncate-ForPrompt -label 'EVENTS_CSV' -text $eventsCsv -maxChars 140000 -headChars 120000 -tailChars 20000)
  $systemPrompt = Convert-ToBedrockCliSafeText -label 'SYSTEM_CONTEXT_JSON' -text (Truncate-ForPrompt -label 'SYSTEM_CONTEXT_JSON' -text $systemJson -maxChars 16000 -headChars 12000 -tailChars 4000)
  $superUserPrompt = Convert-ToBedrockCliSafeText -label 'SUPERUSER_DRAFT' -text (Truncate-ForPrompt -label 'SUPERUSER_DRAFT' -text $superUserDraft -maxChars 32000 -headChars 22000 -tailChars 10000)

  $schemaHint = @"
Return markdown only (no JSON, no code fences) using this exact structure:

## Summary
<short paragraph>

## Diagnostic Tests
### Test 1
**Test:** <name>
**Why:** <reason>
**How To Run:** <steps/command>
**Expected Signal:** <what confirms/refutes>

## Fix Plan
### Action 1
**Priority:** <High|Medium|Low>
**Action:** <specific action>
**Risk:** <risk/rollback note>

## Alternative Root Causes
**Cause:** <name>
**Confidence:** <0-100 or Low/Med/High>
**Evidence:** <evidence>
**Links:** <optional>

## Superuser Improvements
- <bullet>
"@
  $prompt = @"
You are an expert Windows performance diagnostician.
Analyze this dataset and propose best next tests/fixes.

REPORT_MD:
$reportPrompt

FINDINGS_CSV:
$findingsPrompt

SAMPLES_CSV:
$samplesPrompt

EVENTS_CSV:
$eventsPrompt

SYSTEM_CONTEXT_JSON:
$systemPrompt

SUPERUSER_DRAFT:
$superUserPrompt

$schemaHint
"@

  if ($provider -eq 'bedrock') {
    Write-Stage 'GENAI' ("Provider=bedrock | model={0}" -f $model)
    Update-GenAiProgress -percent 5 -status 'Preparing Bedrock payload...'
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
      Add-Warn $warnings 'GenAI bedrock provider requested but aws CLI is not found in PATH.'
      Update-GenAiProgress -percent 100 -status 'Bedrock unavailable (aws CLI missing).' -Done
      return $null
    }
    try {
      $tmpOut = [System.IO.Path]::GetTempFileName()
      $messagesObj = @(
        [pscustomobject]@{
          role = 'user'
          content = @(
            [pscustomobject]@{ text = $prompt }
          )
        }
      )
      $messagesJson = ConvertTo-Json -InputObject $messagesObj -Depth 12 -Compress
      $messagesFile = [System.IO.Path]::GetTempFileName()
      [System.IO.File]::WriteAllText($messagesFile, $messagesJson, [System.Text.UTF8Encoding]::new($false))

      $inferenceObj = [pscustomobject]@{ maxTokens = 1200; temperature = 0.2 }
      $inferenceFile = [System.IO.Path]::GetTempFileName()
      $inferenceJson = ConvertTo-Json -InputObject $inferenceObj -Depth 6 -Compress
      [System.IO.File]::WriteAllText($inferenceFile, $inferenceJson, [System.Text.UTF8Encoding]::new($false))
      Write-Flow -direction 'OUT' -bytes ([double]($messagesJson.Length + $inferenceJson.Length)) -provider 'bedrock' -model $model -extra 'payload prepared'
      $bedrockEta = [int][Math]::Min([Math]::Max((($messagesJson.Length + $inferenceJson.Length) / 4500), 15), 300)

      $args = @(
        'bedrock-runtime','converse',
        '--model-id',$model,
        '--region',$bedrockRegion,
        '--messages',("file://{0}" -f $messagesFile),
        '--inference-config',("file://{0}" -f $inferenceFile),
        '--query','output.message.content[0].text',
        '--output','text'
      )
      if (-not [string]::IsNullOrWhiteSpace($bedrockProfile)) {
        $args = @(
          'bedrock-runtime','converse',
          '--profile',$bedrockProfile,
          '--model-id',$model,
          '--region',$bedrockRegion,
          '--messages',("file://{0}" -f $messagesFile),
          '--inference-config',("file://{0}" -f $inferenceFile),
          '--query','output.message.content[0].text',
          '--output','text'
        )
      }
      $stderrFile = [System.IO.Path]::GetTempFileName()
      Write-Stage 'GENAI-OUT' 'Sending prompt payload to Bedrock...'
      Update-GenAiProgress -percent 35 -status 'Data out: sending prompt to Bedrock...'
      $waitCtx = Start-WaitPhase -phase 'GENAI-WAIT' -message 'Waiting for Bedrock model response...' -etaSeconds $bedrockEta
      $prevPyEnc = $env:PYTHONIOENCODING
      $prevCliEnc = $env:AWS_CLI_FILE_ENCODING
      $prevUtf8 = $env:PYTHONUTF8
      $env:PYTHONIOENCODING = 'utf-8'
      $env:AWS_CLI_FILE_ENCODING = 'UTF-8'
      $env:PYTHONUTF8 = '1'
      # Force PowerShell's console output encoding to UTF-8 so the pipeline doesn't mojibake the response
      $prevConsoleEnc = [Console]::OutputEncoding
      [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
      & aws @args 2> $stderrFile | Set-Content -LiteralPath $tmpOut -Encoding UTF8
      [Console]::OutputEncoding = $prevConsoleEnc
      Stop-WaitPhase -ctx $waitCtx -suffix 'Bedrock response returned'
      if ($null -ne $prevPyEnc) { $env:PYTHONIOENCODING = $prevPyEnc } else { Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue }
      if ($null -ne $prevCliEnc) { $env:AWS_CLI_FILE_ENCODING = $prevCliEnc } else { Remove-Item Env:AWS_CLI_FILE_ENCODING -ErrorAction SilentlyContinue }
      if ($null -ne $prevUtf8) { $env:PYTHONUTF8 = $prevUtf8 } else { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue }
      if ($LASTEXITCODE -ne 0) {
        $errDetail = ''
        try { $errDetail = (Get-Content -LiteralPath $stderrFile -Raw).Trim() } catch {}
        throw "aws bedrock converse failed with exit code $LASTEXITCODE. $errDetail"
      }
      Write-Stage 'GENAI-IN' 'Response received from Bedrock. Parsing output...'
      Update-GenAiProgress -percent 80 -status 'Data in: parsing Bedrock response...'
      $respText = (Get-Content -LiteralPath $tmpOut -Encoding UTF8 -Raw)
      Write-Flow -direction 'IN' -bytes ([double]$respText.Length) -provider 'bedrock' -model $model -extra 'raw response'
      $txt = $respText.Trim()
      # Strip AWS CLI --output text metadata header lines (e.g. "max_tokens\nMETRICS\t...\nMESSAGE\t...\nCONTENT\t\n")
      # These appear when --query returns a nested value and CLI emits a tab-delimited table header first.
      $txt = ($txt -replace '(?s)^(?:[A-Z_]+(?:\t[^\r\n]*)?\r?\n)+\r?\n?', '').Trim()
      # Fallback: if CLI did not honor query as plain text, try to unwrap JSON response shape.
      if ($txt.StartsWith('{') -or $txt.StartsWith('[')) {
        try {
          $parsed = $txt | ConvertFrom-Json -ErrorAction Stop
          if ($parsed -and $parsed.output -and $parsed.output.message -and $parsed.output.message.content -and $parsed.output.message.content.Count -gt 0) {
            $txt = [string]$parsed.output.message.content[0].text
          } elseif ($parsed -and $parsed.content -and $parsed.content.Count -gt 0 -and $parsed.content[0].text) {
            $txt = [string]$parsed.content[0].text
          }
        } catch {}
      }
      if ($txt -match '^None\s*$') { $txt = '' }
      if ([string]::IsNullOrWhiteSpace($txt)) {
        Add-Warn $warnings 'Bedrock returned empty text for query path; retrying with JSON output fallback.'
        $fallbackArgs = @(
          'bedrock-runtime','converse',
          '--model-id',$model,
          '--region',$bedrockRegion,
          '--messages',("file://{0}" -f $messagesFile),
          '--inference-config',("file://{0}" -f $inferenceFile),
          '--output','json'
        )
        if (-not [string]::IsNullOrWhiteSpace($bedrockProfile)) {
          $fallbackArgs = @(
            'bedrock-runtime','converse',
            '--profile',$bedrockProfile,
            '--model-id',$model,
            '--region',$bedrockRegion,
            '--messages',("file://{0}" -f $messagesFile),
            '--inference-config',("file://{0}" -f $inferenceFile),
            '--output','json'
          )
        }
        $tmpOut2 = [System.IO.Path]::GetTempFileName()
        $stderr2 = [System.IO.Path]::GetTempFileName()
        & aws @fallbackArgs 2> $stderr2 | Set-Content -LiteralPath $tmpOut2 -Encoding UTF8
        if ($LASTEXITCODE -eq 0) {
          try {
            $resp2 = Get-Content -LiteralPath $tmpOut2 -Raw
            $p2 = $resp2 | ConvertFrom-Json -ErrorAction Stop
            if ($p2 -and $p2.output -and $p2.output.message -and $p2.output.message.content -and $p2.output.message.content.Count -gt 0) {
              $txt = [string]$p2.output.message.content[0].text
            } elseif ($p2 -and $p2.content -and $p2.content.Count -gt 0 -and $p2.content[0].text) {
              $txt = [string]$p2.content[0].text
            }
          } catch {}
        } else {
          try { Add-Warn $warnings ("Bedrock JSON fallback failed: " + (Get-Content -LiteralPath $stderr2 -Raw).Trim()) } catch {}
        }
        try { Remove-Item -LiteralPath $tmpOut2,$stderr2 -Force -ErrorAction SilentlyContinue } catch {}
      }
      $txt | Set-Content -LiteralPath $outputJsonPath -Encoding UTF8
      try { Remove-Item -LiteralPath $tmpOut,$stderrFile,$messagesFile,$inferenceFile -Force -ErrorAction SilentlyContinue } catch {}
      Update-GenAiProgress -percent 100 -status 'GenAI review complete.' -Done
      Write-Stage 'GENAI' ("Completed at {0}" -f (Get-Date).ToString('o'))
      return $txt
    } catch {
      Add-Warn $warnings "GenAI bedrock review failed: $(Get-CleanExceptionMessage $_)"
      Update-GenAiProgress -percent 100 -status 'Bedrock review failed.' -Done
      return $null
    }
  }

  if ([string]::IsNullOrWhiteSpace($apiKey)) {
    Add-Warn $warnings 'GenAI OpenAI provider requested but API key is missing.'
    Update-GenAiProgress -percent 100 -status 'OpenAI key missing.' -Done
    return $null
  }
  try {
    Write-Stage 'GENAI' ("Provider=openai | model={0}" -f $model)
    Update-GenAiProgress -percent 10 -status 'Preparing OpenAI payload...'
    $payload = @{
      model = $model
      input = @(
        @{ role='system'; content='Be concise, technical, and practical. Provide confident but caveated diagnostic guidance.' },
        @{ role='user'; content=$prompt }
      )
      text = @{ format = @{ type='text' } }
    } | ConvertTo-Json -Depth 8
    $headers = @{ Authorization = "Bearer $apiKey"; 'Content-Type'='application/json' }
    Write-Flow -direction 'OUT' -bytes ([double]$payload.Length) -provider 'openai' -model $model -extra 'payload prepared'
    Write-Stage 'GENAI-OUT' 'Sending prompt payload to OpenAI...'
    Update-GenAiProgress -percent 40 -status 'Data out: sending prompt to OpenAI...'
    $openAiEta = [int][Math]::Min([Math]::Max(($payload.Length / 5000), 10), 180)
    $waitCtx = Start-WaitPhase -phase 'GENAI-WAIT' -message 'Waiting for OpenAI model response...' -etaSeconds $openAiEta
    $resp = Invoke-RestMethod -Method Post -Uri 'https://api.openai.com/v1/responses' -Headers $headers -Body $payload -ErrorAction Stop
    Stop-WaitPhase -ctx $waitCtx -suffix 'OpenAI response returned'
    Write-Stage 'GENAI-IN' 'Response received from OpenAI. Parsing output...'
    Update-GenAiProgress -percent 80 -status 'Data in: parsing OpenAI response...'
    $txt = $null
    try { $txt = $resp.output_text } catch {}
    if ([string]::IsNullOrWhiteSpace($txt)) { $txt = ($resp | ConvertTo-Json -Depth 8) }
    Write-Flow -direction 'IN' -bytes ([double]$txt.Length) -provider 'openai' -model $model -extra 'text response'
    $txt | Set-Content -LiteralPath $outputJsonPath -Encoding UTF8
    Update-GenAiProgress -percent 100 -status 'GenAI review complete.' -Done
    Write-Stage 'GENAI' ("Completed at {0}" -f (Get-Date).ToString('o'))
    return $txt
  } catch {
    Add-Warn $warnings "GenAI OpenAI review failed: $(Get-CleanExceptionMessage $_)"
    Update-GenAiProgress -percent 100 -status 'OpenAI review failed.' -Done
    return $null
  }
}

function Invoke-SpikeSleuthInvestigation {
  param(
    [int]$DurationMinutes = 20,[int]$SampleIntervalSeconds = 5,[int]$LookbackHours = 24,[string]$OutputDir,[string]$OutputRoot,[string]$RunName,[string[]]$AppLogPaths,[int]$AppLogTailLines = 20000,
    [switch]$SkipLiveCollection,[switch]$EnableSpikeEtwCapture,[int]$SpikeEtwDurationSeconds = 15,[int]$SpikeEtwCooldownMinutes = 10,[int]$MaxSpikeEtwCaptures = 3,
    [int]$EventReadThreads = 4,[int]$EventAuditMaxRecordsPerLog = 8000,[switch]$NoHtmlReport,[switch]$EnableHtmlReport,[switch]$OpenDashboard,
    [switch]$SuppressMissingWheaWarning,[switch]$EnableFrozenSnapshot,[switch]$InteractiveWizard,[switch]$SaveBaseline,[switch]$UseBaseline,[string]$BaselinePath = ".\baseline.json",
    [switch]$ServiceMode,[int]$ServiceRetentionDays = 7,
    [switch]$EnableGenAiAssist,[ValidateSet('openai','bedrock')][string]$GenAiProvider='openai',[string]$GenAiModel='gpt-4.1-mini',[string]$GenAiApiKey='',[string]$GenAiApiKeyEnvVar='OPENAI_API_KEY',
    [ValidateSet('none','process','user','machine','securefile')][string]$GenAiApiKeyPersist='none',[string]$GenAiApiKeyCachePath='.\.secrets\openai_api_key.secure.txt',[switch]$UseCachedApiKey,
    [string]$BedrockRegion='us-east-1',[string]$BedrockModelId='anthropic.claude-opus-4-6-v1',[string]$BedrockProfile='',[switch]$BedrockUseSsoProfile,[switch]$TestBedrockSetup,[switch]$BedrockTestInvokeModel,[switch]$SecretSyntheticData,
    [string]$UserPerspectiveNotes='',[switch]$ContinuousMode,[int]$ContinuousCycleMinutes = 3
  )

  $started = Get-Date
  $warnings = New-Object System.Collections.Generic.List[object]
  $plannedEnd = $started.AddMinutes([Math]::Max($DurationMinutes,0))
  Write-Host ("Run started: {0}" -f $started.ToString('yyyy-MM-dd HH:mm:ss'))
  Write-Host ("Planned live-capture end: {0}" -f $plannedEnd.ToString('yyyy-MM-dd HH:mm:ss'))
  Write-Stage 'RUN' ("Start ISO timestamp: {0}" -f $started.ToString('o'))
  if ($TestBedrockSetup) {
    [void](Test-BedrockSetup -profile $BedrockProfile -useSso $BedrockUseSsoProfile.IsPresent -region $BedrockRegion -model $BedrockModelId -invokeModelTest $BedrockTestInvokeModel.IsPresent -warnings $warnings)
    return
  }
  $isAdmin = Test-IsAdmin
  if (-not $isAdmin) { Add-Warn $warnings 'Running non-elevated. Some logs or ETW capture may be unavailable.' }

  $engine = Get-TraceEngine
  if ($EnableSpikeEtwCapture -and $engine -eq 'none') { Add-Warn $warnings 'ETW capture requested but wpr/xperf not found in PATH.' }
  $etwEnabled = $EnableSpikeEtwCapture.IsPresent
  if ($etwEnabled -and -not $isAdmin) {
    Add-Warn $warnings 'ETW capture disabled because session is not elevated. Re-run as Administrator to enable ETW traces.'
    $etwEnabled = $false
  }
  if ($etwEnabled -and $engine -eq 'none') {
    $etwEnabled = $false
  }

  $resolvedRoot = if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot } else { Join-Path $env:USERPROFILE 'SpikeSleuth' }
  $resolvedRunName = if (-not [string]::IsNullOrWhiteSpace($RunName)) { $RunName } else { "run-{0}" -f (Get-Date).ToString('yyyyMMdd-HHmmss') }
  $safeRunName = ($resolvedRunName -replace '[\\/:*?"<>|]','-')
  if (-not [string]::IsNullOrWhiteSpace($OutputDir)) {
    $out = [IO.Path]::GetFullPath($OutputDir)
  } else {
    $out = [IO.Path]::GetFullPath((Join-Path $resolvedRoot $safeRunName))
  }
  if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

  Write-Host "Output directory: $out"
  Write-Host "Admin: $isAdmin | Trace engine: $engine"

  $samples=@(); $hotspots=@(); $traces=@()
  if (-not $SkipLiveCollection -and $DurationMinutes -gt 0) {
    Write-Stage 'COLLECT' 'Starting live collection phase.'
    Write-Host "Collecting live data for $DurationMinutes minute(s)..."
    $liveRaw = @(Get-LiveSamples $DurationMinutes $SampleIntervalSeconds $out $etwEnabled $engine $SpikeEtwDurationSeconds $SpikeEtwCooldownMinutes $MaxSpikeEtwCaptures $warnings)
    $live = if ($liveRaw.Count -gt 0) { $liveRaw[$liveRaw.Count - 1] } else { $null }
    if ($null -eq $live -or $null -eq $live.PSObject -or -not ($live.PSObject.Properties.Name -contains 'Samples')) {
      throw 'Live collection completed but no valid result object was returned.'
    }
    $samples = To-ObjectArray $live.Samples
    $hotspots = To-ObjectArray $live.Hotspots
    $traces = To-ObjectArray $live.Traces
    if ($live.PSObject.Properties.Name -contains 'StopRequested' -and $live.StopRequested) {
      $stopMsg = if (($live.PSObject.Properties.Name -contains 'StopReason') -and -not [string]::IsNullOrWhiteSpace([string]$live.StopReason)) { [string]$live.StopReason } else { 'Live capture was stopped early by user request.' }
      Write-Host $stopMsg -ForegroundColor Yellow
      Add-Warn $warnings $stopMsg
    }
  } else { Write-Host 'Skipping live collection.' }

  if ($SecretSyntheticData) {
    Write-Host 'Secret synthetic data mode enabled. Injecting synthetic samples/events/app hits...'
    $seedStart = (Get-Date).AddMinutes(-1 * [Math]::Max($DurationMinutes,10))
    $demo = New-SecretSyntheticDataset -start $seedStart -minutes ([Math]::Max($DurationMinutes,10)) -intervalSeconds $SampleIntervalSeconds
    $samples = To-ObjectArray $demo.Samples
    $syntheticEvents = To-ObjectArray $demo.Events
    $syntheticAppHits = To-ObjectArray $demo.AppHits
  } else {
    $syntheticEvents = @()
    $syntheticAppHits = @()
  }

  $start = if ($samples.Count) { ($samples | Sort-Object Timestamp | Select-Object -First 1).Timestamp.AddMinutes(-10) } else { (Get-Date).AddHours(-$LookbackHours) }
  $end = Get-Date
  $wins = if ($samples.Count) { @(Get-SpikeWindows $samples) } else { @() }

  Write-Host "Auditing event logs from $start to $end ..."
  Write-Stage 'AUDIT' 'Reading event logs and app activity.'
  $auditWait = Start-WaitPhase -phase 'AUDIT-WAIT' -message 'Collecting Windows event signals...' -etaSeconds 45
  $events = @(Get-EventAudit $start $end $EventAuditMaxRecordsPerLog $EventReadThreads $warnings $SuppressMissingWheaWarning.IsPresent)
  Stop-WaitPhase -ctx $auditWait -suffix 'Event signal collection complete'
  $markers = @(Get-CorrelationMarkers $start $end)
  $systemContext = Get-SystemContext
  Write-Host 'Auditing application logs...'
  $defaultLogCandidates = @(
    "$env:ProgramData\chocolatey\logs\chocolatey.log",
    "$env:ProgramData\Microsoft\Windows\PowerShell\Transcripts\transcript.log",
    "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir\*.log"
  )
  $expandedDefaults = New-Object System.Collections.Generic.List[string]
  foreach ($pat in $defaultLogCandidates) {
    foreach ($f in @(Get-ChildItem -Path $pat -File -ErrorAction SilentlyContinue)) { [void]$expandedDefaults.Add($f.FullName) }
  }
  $allAppPaths = @($AppLogPaths + @($expandedDefaults))
  $appSourceHealth = @(Get-AppLogSourceHealth $allAppPaths)
  $appLogWait = Start-WaitPhase -phase 'APPLOG-WAIT' -message 'Scanning app logs for signal hits...' -etaSeconds 20
  $fileAppHits = @(Parse-AppLogHits $allAppPaths $start $end $AppLogTailLines)
  Stop-WaitPhase -ctx $appLogWait -suffix 'App log scan complete'
  $eventAppHits = @(Get-WindowsAppActivityHits $start $end)
  $appHits = To-ObjectArray (@($fileAppHits) + @($eventAppHits))
  if ($SecretSyntheticData) {
    $events = To-ObjectArray (@($events) + @($syntheticEvents))
    $appHits = To-ObjectArray (@($appHits) + @($syntheticAppHits))
  }

  if ($null -eq $events) { $events=@() }; if ($null -eq $appHits) { $appHits=@() }; if ($null -eq $wins) { $wins=@() }
  $analysis = Analyze -samples $samples -events $events -appHits $appHits -spikeWindows $wins -spikeTraces $traces -warnings $warnings
  Write-Stage 'ANALYZE' ("Analysis complete | findings={0} | events={1} | samples={2}" -f @($analysis.Findings).Count, @($events).Count, @($samples).Count)
  Write-Stage 'ANALYZE' 'Scoring root causes and generating recommendations.'
  $superUser = New-SuperUserDraft -analysis $analysis -systemContext $systemContext -samples $samples -events $events -appHits $appHits -markers $markers -userNotes $UserPerspectiveNotes
  $baselineDelta = $null
  if ($UseBaseline -and (Test-Path -LiteralPath $BaselinePath)) {
    try {
      $base = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
      $baselineDelta = [pscustomobject]@{
        CpuMaxDeltaPct = [Math]::Round(([double]$analysis.MaxCpu - [double]$base.MaxCpu),2)
        DiskBusyDeltaPct = [Math]::Round(([double]$analysis.MaxDiskBusy - [double]$base.MaxDiskBusy),2)
        MinMemDeltaMB = [Math]::Round(([double]$analysis.MinAvailMb - [double]$base.MinAvailMb),2)
        DpcDeltaPct = [Math]::Round(([double]$analysis.MaxDpc - [double]$base.MaxDpc),2)
      }
      if ([double]$baselineDelta.CpuMaxDeltaPct -ge 20 -or [double]$baselineDelta.DiskBusyDeltaPct -ge 20 -or [double]$baselineDelta.DpcDeltaPct -ge 5) {
        [void]$analysis.Findings.Add([pscustomobject]@{
          Severity='Medium'; Category='Baseline anomaly detected'
          Evidence="CPU Delta=$($baselineDelta.CpuMaxDeltaPct), DiskBusy Delta=$($baselineDelta.DiskBusyDeltaPct), DPC Delta=$($baselineDelta.DpcDeltaPct)"
          Recommendation='Investigate what changed since baseline (drivers, updates, security tools, startup set).'
        })
      }
    } catch { Add-Warn $warnings "Failed baseline compare: $($_.Exception.Message)" }
  }
  if ($SaveBaseline) {
    try {
      $baselineObj = [pscustomobject]@{
        SavedAt = Get-Date
        MaxCpu = $analysis.MaxCpu
        MaxDiskBusy = $analysis.MaxDiskBusy
        MinAvailMb = $analysis.MinAvailMb
        MaxDpc = $analysis.MaxDpc
      }
      $baselineObj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BaselinePath -Encoding UTF8
    } catch { Add-Warn $warnings "Failed to save baseline: $($_.Exception.Message)" }
  }

  $samplesCsv = Join-Path $out 'performance_samples.csv'
  $hotspotsCsv = Join-Path $out 'process_hotspots.csv'
  $eventsCsv = Join-Path $out 'event_audit.csv'
  $appHitsCsv = Join-Path $out 'app_log_hits.csv'
  $tracesCsv = Join-Path $out 'spike_etw_traces.csv'
  $findingsCsv = Join-Path $out 'findings.csv'
  $rootCsv = Join-Path $out 'root_cause_scores.csv'
  $playCsv = Join-Path $out 'playbooks.csv'
  $markersCsv = Join-Path $out 'correlation_markers.csv'
  $sourcesCsv = Join-Path $out 'app_log_sources.csv'
  $suMd = Join-Path $out 'superuser_draft.md'
  $suTxt = Join-Path $out 'superuser_draft.txt'
  $genAiMd = Join-Path $out 'genai_review.md'
  $genAiRaw = Join-Path $out 'genai_review_raw.txt'

  if ($samples.Count) { $samplesCsv = Export-CsvResilient -InputObject $samples -Path $samplesCsv }
  if ($hotspots.Count) { $hotspotsCsv = Export-CsvResilient -InputObject $hotspots -Path $hotspotsCsv }
  if ($events.Count) { $eventsCsv = Export-CsvResilient -InputObject $events -Path $eventsCsv }
  if ($appHits.Count) { $appHitsCsv = Export-CsvResilient -InputObject $appHits -Path $appHitsCsv }
  if ($traces.Count) { $tracesCsv = Export-CsvResilient -InputObject $traces -Path $tracesCsv }
  if (@($analysis.RootCauseScores).Count) { $rootCsv = Export-CsvResilient -InputObject $analysis.RootCauseScores -Path $rootCsv }
  if (@($analysis.Playbooks).Count) { $playCsv = Export-CsvResilient -InputObject $analysis.Playbooks -Path $playCsv }
  if (@($markers).Count) { $markersCsv = Export-CsvResilient -InputObject $markers -Path $markersCsv }
  if (@($appSourceHealth).Count) { $sourcesCsv = Export-CsvResilient -InputObject $appSourceHealth -Path $sourcesCsv }
  @("# $($superUser.Title)","",$superUser.Body) | Set-Content -LiteralPath $suMd -Encoding UTF8
  @($superUser.Title,"",$superUser.Body) | Set-Content -LiteralPath $suTxt -Encoding UTF8
  if ($warnings.Count) { $warnings | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'warnings.json') -Encoding UTF8 }
  $findingsCsv = Export-CsvResilient -InputObject $analysis.Findings -Path $findingsCsv

  $genAiText = ''
  if ($EnableGenAiAssist) {
    Write-Stage 'GENAI' 'Starting GenAI review phase.'
    $resolvedBedrockProfile = Resolve-BedrockProfile -profile $BedrockProfile -useSso $BedrockUseSsoProfile.IsPresent
    $apiKey = Resolve-OpenAiApiKey -explicitKey $GenAiApiKey -envVar $GenAiApiKeyEnvVar -useCache $UseCachedApiKey.IsPresent -cachePath $GenAiApiKeyCachePath
    Apply-OpenAiApiKeyPersistence -key $apiKey -scope $GenAiApiKeyPersist -envVar $GenAiApiKeyEnvVar -cachePath $GenAiApiKeyCachePath -warnings $warnings
    $reportForAi = ''
    if (Test-Path -LiteralPath $suMd) { $reportForAi = Get-Content -LiteralPath $suMd -Raw }
    $findingsForAi = if (Test-Path -LiteralPath $findingsCsv) { Get-Content -LiteralPath $findingsCsv -Raw } else { '' }
    $samplesForAi = if (Test-Path -LiteralPath $samplesCsv) { Get-Content -LiteralPath $samplesCsv -Raw } else { '' }
    $eventsForAi = if (Test-Path -LiteralPath $eventsCsv) { Get-Content -LiteralPath $eventsCsv -Raw } else { '' }
    $sysForAi = $systemContext | ConvertTo-Json -Depth 6
    if ($GenAiProvider -eq 'bedrock') { [void](Validate-BedrockAuth -profile $resolvedBedrockProfile -region $BedrockRegion -warnings $warnings) }
    $modelToUse = if ($GenAiProvider -eq 'bedrock') { $BedrockModelId } else { $GenAiModel }
    $genAiRawText = Invoke-GenAiReview -provider $GenAiProvider -apiKey $apiKey -model $modelToUse -reportMarkdown $reportForAi -findingsCsv $findingsForAi -samplesCsv $samplesForAi -eventsCsv $eventsForAi -systemJson $sysForAi -superUserDraft $superUser.Body -outputJsonPath $genAiRaw -bedrockRegion $BedrockRegion -bedrockProfile $resolvedBedrockProfile -warnings $warnings
    if ($genAiRawText) {
      $normalizedGenAiRaw = Normalize-GenAiPayloadText -rawText $genAiRawText
      if (-not [string]::IsNullOrWhiteSpace($normalizedGenAiRaw)) {
        $normalizedGenAiRaw | Set-Content -LiteralPath $genAiRaw -Encoding UTF8
      }
      $genAiText = Format-GenAiTextForDisplay -rawText $normalizedGenAiRaw
      $genAiText | Set-Content -LiteralPath $genAiMd -Encoding UTF8
    }
  }

  $md = Join-Path $out 'report.md'
  Write-Markdown -path $md -analysis $analysis -samples $samples -events $events -appHits $appHits -wins $wins -traces $traces -warnings $warnings -start $started -end (Get-Date) -isAdmin $isAdmin -engine $engine -systemContext $systemContext -markers $markers -baselineDelta $baselineDelta -appSourceHealth $appSourceHealth

  $html = Join-Path $out 'dashboard.html'
  $snapshotZipName = ''
  $snapshotZipPath = ''
  $lightBundleName = ''
  if ($EnableFrozenSnapshot) {
    $snapshotZipName = "frozen-in-time-{0}.zip" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $snapshotZipPath = Join-Path $out $snapshotZipName
  }
  $reportMarkdown = ''
  if (Test-Path -LiteralPath $md) { $reportMarkdown = Get-Content -LiteralPath $md -Raw }
  $lightBundleName = New-LightweightBundle -outDir $out -samples $samples -events $events -markers $markers -analysis $analysis -reportPath $md -findingsCsv $findingsCsv -rootCsv $rootCsv -playCsv $playCsv -warningsPath (Join-Path $out 'warnings.json') -suMd $suMd -suTxt $suTxt -genAiMd $genAiMd -genAiRaw $genAiRaw
  if (-not [string]::IsNullOrWhiteSpace($lightBundleName)) {
    Write-Stage 'BUNDLE' ("Lightweight bundle ready: {0}" -f (Join-Path $out $lightBundleName))
  }
  if ($EnableHtmlReport -and -not $NoHtmlReport) {
    Write-Stage 'REPORT' 'Generating HTML dashboard.'
    $fileContents = @{}
    foreach ($f in @($md,$findingsCsv,$eventsCsv,$appHitsCsv,$samplesCsv,$hotspotsCsv,(Join-Path $out 'warnings.json'),$tracesCsv,$rootCsv,$playCsv,$markersCsv,$sourcesCsv,$suMd,$suTxt,$genAiMd,$genAiRaw)) {
      if ($f -and (Test-Path -LiteralPath $f)) {
        $name = Split-Path -Path $f -Leaf
        try { $fileContents[$name] = Get-Content -LiteralPath $f -Raw }
        catch { $fileContents[$name] = '' }
      }
    }
    Write-Html -path $html -samples $samples -events $events -appHits $appHits -findings $analysis.Findings -warnings $warnings -reportMarkdown $reportMarkdown -fileContents $fileContents -snapshotZipName $snapshotZipName -lightBundleName $lightBundleName -rootScores $analysis.RootCauseScores -playbooks $analysis.Playbooks -markers $markers -systemContext $systemContext -baselineDelta $baselineDelta -appSourceHealth $appSourceHealth -genAiText $genAiText -superUserTitle $superUser.Title -superUserBody $superUser.Body
    if ($OpenDashboard) {
      try { Start-Process -FilePath $html | Out-Null }
      catch { Add-Warn $warnings "Unable to open dashboard automatically: $($_.Exception.Message)" }
    }
  }
  if ($EnableFrozenSnapshot) {
    try {
      if (Test-Path -LiteralPath $snapshotZipPath) { Remove-Item -LiteralPath $snapshotZipPath -Force }
      $packFiles = @()
      foreach ($p in @($md,$html,$findingsCsv,$samplesCsv,$hotspotsCsv,$eventsCsv,$appHitsCsv,$tracesCsv,(Join-Path $out 'warnings.json'),$rootCsv,$playCsv,$markersCsv,$sourcesCsv,$suMd,$suTxt,$genAiMd,$genAiRaw)) {
        if ($p -and (Test-Path -LiteralPath $p)) { $packFiles += $p }
      }
      foreach ($tr in @($traces)) {
        if ($tr -and $tr.Path -and (Test-Path -LiteralPath $tr.Path)) { $packFiles += $tr.Path }
      }
      $packFiles = @($packFiles | Sort-Object -Unique)
      if ($packFiles.Count -gt 0) {
        Compress-Archive -LiteralPath $packFiles -DestinationPath $snapshotZipPath -Force
      } else {
        Add-Warn $warnings 'Frozen snapshot requested, but no files were available to package.'
      }
    } catch {
      Add-Warn $warnings "Failed to create frozen snapshot zip: $($_.Exception.Message)"
    }
  }

  if ($warnings.Count) { $warnings | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'warnings.json') -Encoding UTF8 }
  if ($ServiceMode) {
    $serviceRoot = Split-Path -Path $out -Parent
    Invoke-ServiceRetention -root $serviceRoot -days $ServiceRetentionDays
    Update-ServiceDailySummary -root $serviceRoot -analysis $analysis -runTime (Get-Date)
    foreach ($w in @($wins)) {
      try {
        Add-Content -LiteralPath (Join-Path $serviceRoot 'incident-bookmarks.log') -Value ("{0} | {1} - {2}" -f (Get-Date), $w.Start, $w.End)
      } catch {}
    }
  }

  Write-Host ''
  Write-Host 'Audit complete.'
  Write-Host "Report: $md"
  if ($EnableHtmlReport -and -not $NoHtmlReport) { Write-Host "Dashboard: $html" }
  if ($EnableFrozenSnapshot -and $snapshotZipPath -and (Test-Path -LiteralPath $snapshotZipPath)) { Write-Host "Frozen Snapshot: $snapshotZipPath" }
  Write-Host "Findings CSV: $findingsCsv"
  Write-Stage 'RUN' ("Completed ISO timestamp: {0}" -f (Get-Date).ToString('o'))
}

function Invoke-ExistingRunGenAiReview {
  param(
    [Parameter(Mandatory = $true)][string]$RunPath,
    [ValidateSet('openai','bedrock')][string]$GenAiProvider = 'openai',
    [string]$GenAiModel = 'gpt-4.1-mini',
    [string]$GenAiApiKey = '',
    [string]$GenAiApiKeyEnvVar = 'OPENAI_API_KEY',
    [ValidateSet('none','process','user','machine','securefile')][string]$GenAiApiKeyPersist = 'none',
    [string]$GenAiApiKeyCachePath = ".\.secrets\openai_api_key.secure.txt",
    [switch]$UseCachedApiKey,
    [string]$BedrockRegion = 'us-east-1',
    [string]$BedrockModelId = 'anthropic.claude-opus-4-6-v1',
    [string]$BedrockProfile = '',
    [switch]$BedrockUseSsoProfile
  )

  $aiScript = Join-Path $PSScriptRoot 'spikesleuth-ai.ps1'
  if (-not (Test-Path -LiteralPath $aiScript)) { throw "Required helper script not found: $aiScript" }

  $aiParams = @{
    RunPath = $RunPath
    GenAiProvider = $GenAiProvider
    GenAiModel = $GenAiModel
    GenAiApiKey = $GenAiApiKey
    GenAiApiKeyEnvVar = $GenAiApiKeyEnvVar
    GenAiApiKeyPersist = $GenAiApiKeyPersist
    GenAiApiKeyCachePath = $GenAiApiKeyCachePath
    BedrockRegion = $BedrockRegion
    BedrockModelId = $BedrockModelId
    BedrockProfile = $BedrockProfile
  }
  if ($UseCachedApiKey) { $aiParams['UseCachedApiKey'] = $true }
  if ($BedrockUseSsoProfile) { $aiParams['BedrockUseSsoProfile'] = $true }
  & $aiScript @aiParams
}

if ($MyInvocation.InvocationName -ne '.') {
  if ($Help -or ($RemainingArgs -contains '--help')) {
    Show-ScriptHelp
    return
  }

  $entryParams = @{}
  $autoWizard = ($PSBoundParameters.Keys.Count -eq 0)
  if ($InteractiveWizard -or $autoWizard) {
    $wiz = Get-InteractiveRunParams
    if ($null -eq $wiz) { return }
    foreach ($k in $wiz.Keys) { $entryParams[$k] = $wiz[$k] }
    foreach ($k in $PSBoundParameters.Keys) {
      if ($k -ne 'InteractiveWizard') { $entryParams[$k] = $PSBoundParameters[$k] }
    }
  } else {
    foreach ($k in $PSBoundParameters.Keys) {
      if ($k -ne 'InteractiveWizard') { $entryParams[$k] = $PSBoundParameters[$k] }
    }
  }

  if ($entryParams.ContainsKey('ServiceMode') -and $entryParams['ServiceMode']) {
    $entryParams['ContinuousMode'] = $true
    if (-not $entryParams.ContainsKey('ContinuousCycleMinutes')) { $entryParams['ContinuousCycleMinutes'] = 3 }
    if (-not $entryParams.ContainsKey('OutputRoot') -or [string]::IsNullOrWhiteSpace([string]$entryParams['OutputRoot'])) {
      $entryParams['OutputRoot'] = Join-Path $env:USERPROFILE 'SpikeSleuth\service-runs'
    }
  }

  if ($entryParams.ContainsKey('ExistingRunGenAiOnly') -and $entryParams['ExistingRunGenAiOnly']) {
    $aiOnlyParams = @{}
    foreach ($k in @('ExistingRunPath','GenAiProvider','GenAiModel','GenAiApiKey','GenAiApiKeyEnvVar','GenAiApiKeyPersist','GenAiApiKeyCachePath','UseCachedApiKey','BedrockRegion','BedrockModelId','BedrockProfile','BedrockUseSsoProfile')) {
      if ($entryParams.ContainsKey($k)) { $aiOnlyParams[$k] = $entryParams[$k] }
    }
    $callParams = @{ RunPath = [string]$aiOnlyParams['ExistingRunPath'] }
    foreach ($k in @('GenAiProvider','GenAiModel','GenAiApiKey','GenAiApiKeyEnvVar','GenAiApiKeyPersist','GenAiApiKeyCachePath','UseCachedApiKey','BedrockRegion','BedrockModelId','BedrockProfile','BedrockUseSsoProfile')) {
      if ($aiOnlyParams.ContainsKey($k)) { $callParams[$k] = $aiOnlyParams[$k] }
    }
    Invoke-ExistingRunGenAiReview @callParams
    return
  }

  if ($entryParams.ContainsKey('ContinuousMode') -and $entryParams['ContinuousMode']) {
    $cycleMinutes = if ($entryParams.ContainsKey('ContinuousCycleMinutes')) { [int]$entryParams['ContinuousCycleMinutes'] } else { 3 }
    Write-Host "Continuous mode enabled. Cycle minutes: $cycleMinutes. Press Ctrl+C to stop."
    while ($true) {
      $cycleParams = @{}
      foreach ($k in $entryParams.Keys) { if ($k -ne 'ContinuousMode' -and $k -ne 'ContinuousCycleMinutes') { $cycleParams[$k] = $entryParams[$k] } }
      $cycleParams['DurationMinutes'] = $cycleMinutes
      if ($entryParams.ContainsKey('ServiceMode') -and $entryParams['ServiceMode']) {
        $cycleParams['RunName'] = "run-{0}" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
      }
      Invoke-SpikeSleuthInvestigation @cycleParams
      Start-Sleep -Seconds 2
    }
  }
  else {
    Invoke-SpikeSleuthInvestigation @entryParams
  }
}


