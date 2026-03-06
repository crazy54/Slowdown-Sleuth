<p align="center">
  <img src="img/SpikeSleuth-trans.png" alt="SpikeSleuth Logo" width="520" />
</p>

<p align="center">
  <a href="#"><img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white"></a>
  <a href="#"><img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white"></a>
  <a href="#"><img alt="Tests" src="https://img.shields.io/badge/Tests-Pester-1F6FEB"></a>
  <a href="#"><img alt="Status" src="https://img.shields.io/badge/Status-Active-2EA043"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-green"></a>
</p>

<h1 align="center">SpikeSleuth</h1>
<p align="center"><em>Precision diagnostics for intermittent Windows slowdowns, stalls, and spike events.</em></p>

---

## 🚀 What Is SpikeSleuth?
**SpikeSleuth** is a Windows performance diagnostics toolkit built for *real-world intermittent issues*:
- 10-30s hangs
- random app freezes
- bursty disk or driver contention
- "it feels slow but not always" scenarios

It combines **live telemetry**, **event auditing**, **root-cause scoring**, **ETW spike capture**, and optional **GenAI review** into one repeatable workflow.

## ✨ Core Capabilities
- **Live performance sampling**: CPU, memory, paging, disk, DPC/ISR, network.
- **Event log correlation**: high-signal event channels with timeline context.
- **Optional ETW spike capture**: via `wpr`/`xperf` when spikes are detected.
- **Actionable reporting**: markdown + rich HTML dashboard.
- **GenAI assistant mode**: OpenAI or AWS Bedrock recommendations.
- **Graceful run stop**: stop sampling early without killing report generation.

## 🧾 Acronyms and Terms
- **ETW**: *Event Tracing for Windows*; low-level OS tracing used to capture detailed performance activity during spikes.
- **WPR**: *Windows Performance Recorder* (`wpr.exe`); built-in tool used to start/stop ETW captures.
- **Xperf**: Windows Performance Toolkit trace tool (`xperf.exe`) used as an ETW capture alternative.
- **DPC**: *Deferred Procedure Call*; kernel work scheduling that can indicate driver/interrupt pressure when high.
- **ISR**: *Interrupt Service Routine*; hardware interrupt handling time, useful for spotting latency-causing drivers/devices.
- **SSO**: *Single Sign-On*; AWS login flow used for Bedrock authentication.
- **STS**: *Security Token Service*; AWS identity check endpoint (`aws sts get-caller-identity`) to verify profile auth.
- **CLI**: *Command Line Interface* (for example, AWS CLI).
- **CSV**: *Comma-Separated Values* file used for tabular run outputs.
- **HTML**: report/dashboard format viewable in a browser.
- **GenAI**: LLM-assisted analysis layer that suggests diagnostic tests, likely causes, and fix paths.

What SpikeSleuth does in simple terms:
1. Samples system performance over time.
2. Correlates those samples with Windows and app log signals.
3. Optionally captures deeper ETW traces during spikes.
4. Produces reports/dashboards and optional AI recommendations.

## 🧰 Scripts
- `spikesleuth.ps1`: **primary entrypoint** and core engine.
- `spikesleuth-ai.ps1`: AI-only review for an existing run.
- `spikesleuth-run.ps1`: convenience wrapper for `spikesleuth.ps1`.
- `spikesleuth-analyze-ai.ps1`: convenience wrapper for `spikesleuth-ai.ps1`.

## 📋 Requirements
- Windows PowerShell **5.1+** (PowerShell 7 also supported).
- Windows 10/11 or Windows Server.
- Admin shell recommended for full event/ETW visibility.
- Optional dependencies:
  - `wpr.exe` or `xperf.exe` for ETW.
  - AWS CLI for Bedrock mode.

## ⚡ Quick Start
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\spikesleuth.ps1 -DurationMinutes 20 -SampleIntervalSeconds 5 -EnableHtmlReport -OpenDashboard
```

## 🧭 Interactive Wizard
```powershell
.\spikesleuth.ps1 -InteractiveWizard
```

Wizard modes:
- One-time run
- Continuous cycles
- Service-style retention mode
- Existing-run AI review

## ⏱️ Countdown + Graceful Stop
During live collection, SpikeSleuth shows:
- **Run started** timestamp
- **Planned end** timestamp
- **Rolling countdown / ETA**

Early-stop combo:
- `Ctrl+Shift+Q` (fallback: `Ctrl+Q`)

This stops **sampling only**. Reporting and GenAI stages still complete.

## 🤖 Existing Run AI Review
Re-run AI analysis without recollecting telemetry:
```powershell
.\spikesleuth-ai.ps1 -RunPath "C:\Path\To\RunFolder" -GenAiProvider openai
```

If a run folder was already generated but never AI-reviewed, use this flow:
1. Identify the run folder path (it should contain files like `report.md`, `findings.csv`, and `event_audit.csv`).
2. Run AI review against that folder:
```powershell
.\spikesleuth-ai.ps1 -RunPath "C:\Users\YOU\SpikeSleuth\run-20260306-101500" -GenAiProvider openai
```
3. If using Bedrock instead of OpenAI:
```powershell
.\spikesleuth-ai.ps1 -RunPath "C:\Users\YOU\SpikeSleuth\run-20260306-101500" -GenAiProvider bedrock -BedrockProfile YOUR_PROFILE -BedrockRegion us-east-1
```
4. Confirm output files were created in that same run folder:
   - `genai_review.md`
   - `genai_review_raw.txt`

Expected console success output (example):
```text
GenAI review written: C:\Users\YOU\SpikeSleuth\run-20260306-101500\genai_review.md
Raw output written: C:\Users\YOU\SpikeSleuth\run-20260306-101500\genai_review_raw.txt
Dashboard updated with new GenAI text: C:\Users\YOU\SpikeSleuth\run-20260306-101500\dashboard.html
```

## 📦 Outputs
A run folder can include:
- `report.md`
- `dashboard.html`
- `findings.csv`
- `root_cause_scores.csv`
- `playbooks.csv`
- `performance_samples.csv`
- `process_hotspots.csv`
- `event_audit.csv`
- `app_log_hits.csv`
- `correlation_markers.csv`
- `spike_etw_traces.csv`
- `warnings.json`
- `superuser_draft.md`
- `superuser_draft.txt`
- `genai_review.md`
- `genai_review_raw.txt`

## 🛠️ Common Commands
High-fidelity short run:
```powershell
.\spikesleuth.ps1 -DurationMinutes 10 -SampleIntervalSeconds 1 -EnableHtmlReport -OpenDashboard
```

Log-only audit:
```powershell
.\spikesleuth.ps1 -SkipLiveCollection -LookbackHours 48 -EnableHtmlReport
```

Continuous cycles:
```powershell
.\spikesleuth.ps1 -ContinuousMode -ContinuousCycleMinutes 3 -EnableHtmlReport
```

Service-style mode:
```powershell
.\spikesleuth.ps1 -ServiceMode -ServiceRetentionDays 7 -EnableHtmlReport
```

## 📖 Full Help
```powershell
.\spikesleuth.ps1 -Help
```

## 🔐 GenAI Providers
**OpenAI**
- Uses `OPENAI_API_KEY` by default (or inline key).
- Supports secure local key cache.

**AWS Bedrock**
- Uses AWS profile / SSO flow.
- Configure with AWS CLI SSO:
1. Run:
```powershell
aws configure sso
```
2. Generate a name for the SSO session.
3. Enter `SSO start URL` (or reuse the existing value shown).
4. Enter default AWS region for this SSO profile: `us-east-1`.
5. Press Enter for registration scope, or set one if needed.
6. A browser window opens; sign in to your SSO account.
7. Select `Allow access` when `botocore-client` requests access.
8. After credentials are shared, return to terminal and choose the AWS account.
9. Choose the role to assign to this profile.
10. Keep or change the default region when prompted.
11. Select default AWS CLI output format (`json`, `yaml`, `text`, `table`).
12. Create and remember a profile name. You can list profiles with:
```powershell
aws configure list-profiles
```
13. Validate auth with STS:
```powershell
aws sts get-caller-identity --profile NAME
```

You can now use this profile name with SpikeSleuth Bedrock runs.
- Configure `-BedrockRegion` and `-BedrockModelId`.
- Validate setup with `-TestBedrockSetup`.

## ✅ Tests
- Test file: `tests/SpikeSleuth.Tests.ps1`

Install Pester if needed:
```powershell
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

Run all tests:
```powershell
Invoke-Pester -Path .\tests
```

Run the specific SpikeSleuth test file:
```powershell
Invoke-Pester -Path .\tests\SpikeSleuth.Tests.ps1
```

Run with a pass/fail summary object:
```powershell
$result = Invoke-Pester -Path .\tests\SpikeSleuth.Tests.ps1 -PassThru
$result | Select-Object Result, PassedCount, FailedCount, SkippedCount
```

Expected output when tests pass (example):
```text
Describing Get-SpikeWindows
 [+] merges nearby spike samples into windows 120ms
Describing Analyze
 [+] creates storage finding when disk error event exists 95ms
Tests completed in 215ms
Passed: 2 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
```

Expected summary object (example):
```text
Result PassedCount FailedCount SkippedCount
------ ----------- ----------- ------------
Passed           2           0            0
```

If a test fails, you will see `[-]` lines and a non-zero `FailedCount` (example):
```text
Describing Analyze
 [-] creates storage finding when disk error event exists 140ms
   <error details...>
Tests completed in 140ms
Passed: 1 Failed: 1 Skipped: 0 Pending: 0 Inconclusive: 0
```

## 🛡️ Security & Publishing Notes
- Generated artifacts and local secrets are excluded via `.gitignore`.
- Review reports before sharing externally; logs may include sensitive data.
- MIT License: see [`LICENSE`](LICENSE).
