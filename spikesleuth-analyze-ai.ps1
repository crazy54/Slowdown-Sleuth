[CmdletBinding(PositionalBinding = $false)]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [object[]]$RemainingArgs
)

& "$PSScriptRoot\spikesleuth-ai.ps1" @RemainingArgs

