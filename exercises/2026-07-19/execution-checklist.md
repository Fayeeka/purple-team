# Execution Checklist — Screening Serpens Simulation

`/purple-loop` Step 3. Companion to `report.md` (analysis) and `findings.md` (IOCs).

> **⚠️ Two caveats before running anything:**
> 1. **No dedicated lab host** for this project (per `CLAUDE.md`). This checklist supports either **(A)** live Atomic execution on a reachable Windows host, or **(B)** the Module 3/8 sample-EVTX fallback.
> 2. **Unverified Atomic IDs.** The `atomic-mapper` ID remappings (`T1574.002 -> T1574.001`, `T1562.002 -> T1685`, `T1497 -> T1497.001`) are **not confirmed against a local Atomic Red Team checkout**. The `T1685` mapping for the ETW technique is **likely wrong** — verify folder names (`ls atomics/ | grep T15`) before running the ⚠-tagged command.

## 0. Pre-flight (one-time, on the test host)

```powershell
# Elevated PowerShell required
Import-Module Invoke-AtomicRedTeam

# Telemetry prerequisites — confirm all are in place:
#  [ ] Sysmon installed with a config that logs EID 7 (ImageLoad) — REQUIRED for sideloading/AppDomainManager
#  [ ] Audit Process Creation on  -> Security 4688  (+ include command line)
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
#  [ ] Audit "Other Object Access Events" on -> Security 4698 (scheduled task)
auditpol /set /subcategory:"Other Object Access Events" /success:enable
#  [ ] Audit Registry on (for 4657) — optional, Sysmon 13 covers most
auditpol /set /subcategory:"Registry" /success:enable
#  [ ] .NET Framework present (required for T1574.014 / T1562.002 CLR techniques)

# Mark a clean start time so we can scope the EVTX export later:
Get-Date -Format "o" | Tee-Object C:\ART\run-start.txt
```

## 1. Run tests — in kill-chain order

Run `-GetPrereqs` first where listed; run `-Cleanup` after **each** test before the next. (IDs are the `atomic-mapper` set — **verify the ⚠ ones first**.)

```powershell
# --- Phase 1: Delivery & Execution ---
Invoke-AtomicTest T1204.002 -TestNumbers 13                      # Click-Fix BAT
Invoke-AtomicTest T1105     -TestNumbers 7                       # certutil download

# --- Phase 2: Execution & Defense Evasion (crown jewels) ---
Invoke-AtomicTest T1574.001 -TestNumbers 4 -GetPrereqs           # DLL side-load (GUP.exe) [was T1574.002]
Invoke-AtomicTest T1574.001 -TestNumbers 4
Invoke-AtomicTest T1574.001 -TestNumbers 5 -GetPrereqs           # dotnet startup hook (AppDomainManager proxy)
Invoke-AtomicTest T1574.001 -TestNumbers 5
Invoke-AtomicTest T1685     -TestNumbers 69                      # ⚠ Disable .NET ETW — VERIFY ID (likely T1562.002)

# --- Phase 3: Persistence & PrivEsc ---
Invoke-AtomicTest T1053.005 -TestNumbers 2                       # named scheduled task
Invoke-AtomicTest T1036.004 -TestNumbers 1                       # W32Time-lookalike task (elevated)
Invoke-AtomicTest T1548.002 -TestNumbers 3                       # Fodhelper UAC bypass

# --- Phase 4: Discovery, Anti-analysis, Masquerading ---
Invoke-AtomicTest T1057     -TestNumbers 2                       # tasklist
Invoke-AtomicTest T1497.001 -TestNumbers 3                       # VM detect (WMI) [was T1497]
Invoke-AtomicTest T1036.005 -TestNumbers 2                       # masquerade as svchost.exe
Invoke-AtomicTest T1564.001 -TestNumbers 4 -GetPrereqs           # hidden file (attrib +h +s)
Invoke-AtomicTest T1564.001 -TestNumbers 4
Invoke-AtomicTest T1059.003 -TestNumbers 1 -GetPrereqs           # cmd batch script
Invoke-AtomicTest T1059.003 -TestNumbers 1

# Manual (no atomic): T1574.014 AppDomainManager .config repro, T1027.001 binary padding
```

## 2. Expected log locations (where the detections land)

| Channel (EVTX) | Event IDs | Techniques feeding it |
|----------------|-----------|-----------------------|
| `Microsoft-Windows-Sysmon/Operational` | 1, 3, 7, 11, 13 | all — **EID 7** is the sideloading/AppDomainManager signal; **EID 13** for ETW & UAC registry |
| `Security` | 4688, 4698, 4657 | process creation (all), scheduled task (T1053.005/T1036.004), registry (T1562.002/T1548.002) |
| `Microsoft-Windows-TaskScheduler/Operational` | 106, 140, 141, 200 | T1053.005, T1036.004 |
| `Microsoft-Windows-WMI-Activity/Operational` | 11 | T1497.001 |
| `Microsoft-Windows-PowerShell/Operational` | 4103, 4104 | any PowerShell-driven test (if script-block logging on) |

## 3. Export EVTX after execution

```powershell
# On the test host, after all tests + cleanups complete:
$dst = "C:\ART\evtx"; New-Item -ItemType Directory -Force $dst | Out-Null

wevtutil epl Security "$dst\Security.evtx"
wevtutil epl "Microsoft-Windows-Sysmon/Operational"           "$dst\Sysmon.evtx"
wevtutil epl "Microsoft-Windows-TaskScheduler/Operational"    "$dst\TaskScheduler.evtx"
wevtutil epl "Microsoft-Windows-WMI-Activity/Operational"     "$dst\WMI-Activity.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational"       "$dst\PowerShell.evtx"

# Then copy the .evtx files into this exercise:
#   exercises\2026-07-19\evtx\
```

**Path B (no live host):** instead of the above, copy the relevant **Module 3/8 sample EVTX** files into `exercises\2026-07-19\evtx\`. In Step 4 (Detection Analysis) the `hayabusa` MCP server scans whatever lands in that folder either way.

---

## Hand-off to Step 4
Run the tests (or stage the sample EVTX), export logs into `exercises/2026-07-19/evtx/`, then resume `/purple-loop` at **Step 4: Detection Analysis** — `hayabusa` scans the folder and groups detections by severity.
