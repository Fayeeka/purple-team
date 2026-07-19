# Vectr Tracking Summary — Screening Serpens (UNC1549)

`/purple-loop` Step 8. Formatted for entry into Vectr to track detection coverage over time.

## Assessment / Campaign metadata

| Field | Value |
|-------|-------|
| Assessment | Threat-Informed Detection Validation |
| Campaign | Screening Serpens (UNC1549) — MiniUpdate / MiniJunk V2 |
| Date | 2026-07-19 |
| Threat source | Unit 42, Palo Alto Networks |
| Environment | Sample-EVTX (no dedicated lab) |
| Assessed by | purple-team / `/purple-loop` |

**Outcome legend (Vectr):** `Detected` = alert fired · `Logged` = telemetry present, no alert · `Not Detected` = telemetry present, missed · `No Data` = no telemetry collected · `Blocked/Prevented` = stopped pre-execution.

## Test cases (ready for Vectr entry)

| Test Case | Tactic (Phase) | Technique | Outcome | Detection Notes |
|-----------|----------------|-----------|---------|-----------------|
| PowerShell download-cradle (IEX + Net.WebClient) | Command & Control | T1105 | **Detected** | Hayabusa High — "Suspicious PowerShell Invocations - Specific", EID 4104 |
| PowerShell IEX execution | Execution | T1059.001 | **Logged** | EID 4103/4104 scriptblock + pipeline, informational only |
| User execution (interactive host) | Execution | T1204.002 | **Logged** | Captured only as PowerShell host context |
| AppDomainManager hijacking ⭐ | Defense Evasion | T1574.014 | **No Data** | No Sysmon EID 7/13 collected — crown jewel unvalidated |
| DLL side-loading ⭐ | Defense Evasion | T1574.002 | **No Data** | No Sysmon EID 7 collected |
| Disable ETW / event logging ⭐ | Defense Evasion | T1562.002 | **No Data** | No Sysmon EID 13 / Security 4657 collected |
| Scheduled task persistence | Persistence | T1053.005 | **No Data** | No Security 4698 / TaskScheduler channel |
| Masquerade task or service | Defense Evasion | T1036.004 | **No Data** | No telemetry |
| Match legitimate name/location | Defense Evasion | T1036.005 | **No Data** | No telemetry |
| Hidden files and directories | Defense Evasion | T1564.001 | **No Data** | No telemetry |
| Windows command shell | Execution | T1059.003 | **No Data** | Sample was PowerShell (.001), not cmd |
| Bypass UAC | Privilege Escalation | T1548.002 | **No Data** | No telemetry |
| Process discovery | Discovery | T1057 | **No Data** | No telemetry |
| Virtualization/sandbox evasion | Defense Evasion | T1497 | **No Data** | No WMI-Activity channel |
| Binary padding | Defense Evasion | T1027.001 | **No Data** | No telemetry + no packaged atomic |

## Coverage rollup (for trend tracking)

| Metric | Value |
|--------|-------|
| Test cases tracked | 15 |
| Detected | 1 |
| Logged | 2 |
| No Data | 12 |
| Not Detected | 0 |
| Detection rate (Detected / planned-14) | ~7% |
| Crown-jewel coverage | 0 / 3 |

## Reminder
> **Update Vectr with these results to track coverage over time.** Re-running this campaign after closing the telemetry gap (Sysmon EID 7/13, Security 4688/4698) will show the crown-jewel `No Data` rows move to `Detected` / `Not Detected` — the delta is the exercise's real success metric.

## Baseline for next iteration
When repeated, watch these rows flip out of `No Data`:
- T1574.014, T1574.002, T1562.002 (crown jewels — priority)
- T1053.005, T1548.002 (high-signal persistence / privesc)
