[CmdletBinding()]
param(
  [string]$RunPath = '',
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Preserve this script's bound parameters before dot-sourcing core functions.
$boundRunPath = $RunPath
$boundGenAiProvider = $GenAiProvider
$boundGenAiModel = $GenAiModel
$boundGenAiApiKey = $GenAiApiKey
$boundGenAiApiKeyEnvVar = $GenAiApiKeyEnvVar
$boundGenAiApiKeyPersist = $GenAiApiKeyPersist
$boundGenAiApiKeyCachePath = $GenAiApiKeyCachePath
$boundUseCachedApiKey = $UseCachedApiKey
$boundBedrockRegion = $BedrockRegion
$boundBedrockModelId = $BedrockModelId
$boundBedrockProfile = $BedrockProfile
$boundBedrockUseSsoProfile = $BedrockUseSsoProfile

. "$PSScriptRoot\spikesleuth.ps1"

# Restore user-provided values after dot-sourcing (core script has overlapping param names/defaults).
$RunPath = $boundRunPath
$GenAiProvider = $boundGenAiProvider
$GenAiModel = $boundGenAiModel
$GenAiApiKey = $boundGenAiApiKey
$GenAiApiKeyEnvVar = $boundGenAiApiKeyEnvVar
$GenAiApiKeyPersist = $boundGenAiApiKeyPersist
$GenAiApiKeyCachePath = $boundGenAiApiKeyCachePath
$UseCachedApiKey = $boundUseCachedApiKey
$BedrockRegion = $boundBedrockRegion
$BedrockModelId = $boundBedrockModelId
$BedrockProfile = $boundBedrockProfile
$BedrockUseSsoProfile = $boundBedrockUseSsoProfile

$aiStarted = Get-Date
Write-Stage 'AI-RUN' ("Start ISO timestamp: {0}" -f $aiStarted.ToString('o'))

function Resolve-RunPath([string]$requested) {
  if (-not [string]::IsNullOrWhiteSpace($requested)) {
    return [IO.Path]::GetFullPath($requested)
  }
  $root = Join-Path $env:USERPROFILE 'SpikeSleuth'
  if (-not (Test-Path -LiteralPath $root)) { return (Get-Location).Path }
  $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  if ($dirs.Count -gt 0) { return $dirs[0].FullName }
  return (Get-Location).Path
}

$target = Resolve-RunPath -requested $RunPath
if (-not (Test-Path -LiteralPath $target)) { throw "Run path does not exist: $target" }
Write-Stage 'AI-RUN' ("Target run folder: {0}" -f $target)

$warnings = New-Object System.Collections.Generic.List[object]

$reportPath = Join-Path $target 'report.md'
$findingsPath = Join-Path $target 'findings.csv'
$samplesPath = Join-Path $target 'performance_samples.csv'
$eventsPath = Join-Path $target 'event_audit.csv'
$superUserPath = Join-Path $target 'superuser_draft.md'
$outRaw = Join-Path $target 'genai_review_raw.txt'
$outMd = Join-Path $target 'genai_review.md'

$reportText = if (Test-Path -LiteralPath $reportPath) { Get-Content -LiteralPath $reportPath -Raw } else { '' }
$findingsText = if (Test-Path -LiteralPath $findingsPath) { Get-Content -LiteralPath $findingsPath -Raw } else { '' }
$samplesText = if (Test-Path -LiteralPath $samplesPath) { Get-Content -LiteralPath $samplesPath -Raw } else { '' }
$eventsText = if (Test-Path -LiteralPath $eventsPath) { Get-Content -LiteralPath $eventsPath -Raw } else { '' }
$superUserText = if (Test-Path -LiteralPath $superUserPath) { Get-Content -LiteralPath $superUserPath -Raw } else { '' }
Write-Stage 'AI-LOAD' 'Loaded existing run artifacts for AI evaluation.'

$systemContext = Get-SystemContext | ConvertTo-Json -Depth 6

$resolvedBedrockProfile = Resolve-BedrockProfile -profile $BedrockProfile -useSso $BedrockUseSsoProfile.IsPresent
$apiKey = Resolve-OpenAiApiKey -explicitKey $GenAiApiKey -envVar $GenAiApiKeyEnvVar -useCache $UseCachedApiKey.IsPresent -cachePath $GenAiApiKeyCachePath
Apply-OpenAiApiKeyPersistence -key $apiKey -scope $GenAiApiKeyPersist -envVar $GenAiApiKeyEnvVar -cachePath $GenAiApiKeyCachePath -warnings $warnings

if ($GenAiProvider -eq 'bedrock') {
  Write-Stage 'AI-AUTH' ("Validating Bedrock auth profile: {0}" -f $(if ([string]::IsNullOrWhiteSpace($resolvedBedrockProfile)) { '<default>' } else { $resolvedBedrockProfile }))
  [void](Validate-BedrockAuth -profile $resolvedBedrockProfile -region $BedrockRegion -warnings $warnings)
}

$modelToUse = if ($GenAiProvider -eq 'bedrock') { $BedrockModelId } else { $GenAiModel }
Write-Stage 'AI-OUT' ("Submitting dataset to provider={0}, model={1}" -f $GenAiProvider, $modelToUse)
$aiEta = if ($GenAiProvider -eq 'bedrock') { 120 } else { 45 }
$aiWait = Start-WaitPhase -phase 'AI-WAIT' -message 'Waiting for model inference...' -etaSeconds $aiEta
$genAiRawText = Invoke-GenAiReview -provider $GenAiProvider -apiKey $apiKey -model $modelToUse -reportMarkdown $reportText -findingsCsv $findingsText -samplesCsv $samplesText -eventsCsv $eventsText -systemJson $systemContext -superUserDraft $superUserText -outputJsonPath $outRaw -bedrockRegion $BedrockRegion -bedrockProfile $resolvedBedrockProfile -warnings $warnings
Stop-WaitPhase -ctx $aiWait -suffix 'Inference call finished'

if ($genAiRawText) {
  Write-Stage 'AI-IN' 'Model response received. Writing GenAI output files.'
  $normalizedGenAiRaw = Normalize-GenAiPayloadText -rawText $genAiRawText
  if (-not [string]::IsNullOrWhiteSpace($normalizedGenAiRaw)) {
    $normalizedGenAiRaw | Set-Content -LiteralPath $outRaw -Encoding UTF8
  }
  $formattedGenAiText = Format-GenAiTextForDisplay -rawText $normalizedGenAiRaw
  $formattedGenAiText | Set-Content -LiteralPath $outMd -Encoding UTF8
  Write-Host "GenAI review written: $outMd"
  Write-Host "Raw output written: $outRaw"
  $dashPath = Join-Path $target 'dashboard.html'
  if (Test-Path -LiteralPath $dashPath) {
    try {
      $dash = Get-Content -LiteralPath $dashPath -Raw -Encoding UTF8
      # Remove any stale inject script from previous runs
      $dash = [regex]::Replace($dash, '(?s)\r?\n?<script id="spikesleuth-genai-fix">.*?</script>', '')
      # Update the genAiText constant with clean formatted markdown
      $genAiJson = ConvertTo-Json -InputObject $formattedGenAiText
      $genAiJson = Protect-ForHtmlScript $genAiJson
      $updated = [regex]::Replace($dash, '(?s)const genAiText = .*?;(\r?\n)', "const genAiText = $genAiJson;`$1")
      if ($updated -ne $dash) {
        $updated | Set-Content -LiteralPath $dashPath -Encoding UTF8 -NoNewline
        Write-Host "Dashboard updated with GenAI text: $dashPath"
      } else {
        Write-Host 'Dashboard genAiText constant not found; skipping patch.'
      }
    } catch {
      Write-Host "Could not update dashboard.html: $($_.Exception.Message)"
    }
  }
} else {
  Write-Host 'GenAI review did not produce output. Check warnings and auth configuration.'
}

if ($warnings.Count -gt 0) {
  $warningsPath = Join-Path $target 'warnings.json'
  try { $warnings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $warningsPath -Encoding UTF8 } catch {}
  Write-Host "Warnings: $($warnings.Count)"
}

Write-Stage 'AI-RUN' ("Completed ISO timestamp: {0}" -f (Get-Date).ToString('o'))

