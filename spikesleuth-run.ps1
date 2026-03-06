[CmdletBinding(PositionalBinding = $false)]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [object[]]$RemainingArgs
)

& "$PSScriptRoot\spikesleuth.ps1" @RemainingArgs

