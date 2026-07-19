# Gap Analysis — Screening Serpens Exercise

`/purple-loop` Step 6. Compares techniques tested vs. detected, hayabusa vs. SIEM, expected vs. actual telemetry.

## Coverage matrix

| # | Technique | Priority | EVTX available? | Hayabusa detected | SIEM validated | Gap |
|---|-----------|:--:|:--:|:--:|:--:|-----|
| 1 | **T1105** Ingress Tool Transfer | Sim | Yes (PS cradle) | **High** | pending | Detected via PowerShell proxy, not campaign's certutil chain |
| 2 | **T1059.001** PowerShell | bonus | Yes | Info x3 | pending | Logged, not alerted (baseline scriptblock) |
| 3 | T1574.014 AppDomainManager | Sim (crown) | No | — | — | **No telemetry — crown jewel unvalidated** |
| 4 | T1574.002 DLL Side-Loading | Sim (crown) | No | — | — | **No Sysmon EID 7 sample** |
| 5 | T1562.002 Disable ETW | Sim (crown) | No | — | — | **No Sysmon EID 13 / Security 4657** |
| 6 | T1053.005 Scheduled Task | Sim | No | — | — | No Security 4698 / TaskScheduler sample |
| 7 | T1036.004 Masquerade Task | Sim | No | — | — | No telemetry |
| 8 | T1036.005 Match Legit Name | Sim | No | — | — | No telemetry |
| 9 | T1564.001 Hidden Files | Sim | No | — | — | No telemetry |
| 10 | T1059.003 Windows Cmd Shell | Sim | No | — | — | Sample was PowerShell (.001), not cmd (.003) |
| 11 | T1548.002 Bypass UAC | Sim | No | — | — | No telemetry |
| 12 | T1057 Process Discovery | Sim | No | — | — | No telemetry |
| 13 | T1497 Sandbox Evasion | Sim | No | — | — | No WMI-Activity sample |
| 14 | T1204.002 User Execution | Sim | Implied | context | pending | Only as PS-host context |
| 15 | T1027.001 Binary Padding | Sim | No | — | — | No atomic + no telemetry |

Crown = the three highest-value techniques for this campaign per the Unit 42 report.

## The three comparisons

### 1. Techniques tested vs. detected
- Planned to simulate: **14 techniques**.
- Actually had telemetry: **1** (PowerShell download-cradle sample) -> represents T1105 + T1059.001.
- Detected: 1 high-severity (T1105 cradle) + 3 informational (PS logging).
- **Detection rate against the plan: ~1/14 (approx. 7%).** Validated a delivery proxy, not the intrusion core.

### 2. Hayabusa vs. SIEM
- **Hayabusa:** ran, produced a concrete high-severity hit on `fs03vuln` / `admmig`.
- **SIEM:** not run — no SIEM MCP/connection. SPL + KQL staged for manual execution. This half of the validation is unconfirmed.

### 3. Expected vs. actual telemetry
- Expected (per test plan): Sysmon EID **7** (sideloading/AppDomainManager), EID **13** (ETW/UAC registry), Security **4688/4698**, TaskScheduler **106**, WMI **11**.
- Actual: only `PowerShell/Operational` **4103/4104**.
- Verdict: the single most important channel for this campaign — Sysmon Image/Module Load (EID 7) — produced **zero** data. Crown-jewel techniques are entirely dark.

## Gaps identified (prioritized)

1. **CRITICAL — crown-jewel blind spot.** T1574.014 / T1574.002 / T1562.002 have no telemetry at all. These are exactly what Unit 42 says defenders must catch. _Action: obtain Sysmon (EID 7/13) + Security EVTX and re-scan._
2. **HIGH — SIEM correlation unconfirmed.** Half of Step 5 is theoretical. _Action: run the staged SPL against the live SIEM; verify 4104 forwarding + script-block logging fleet-wide._
3. **MEDIUM — proxy != real TTP.** Detected technique (PowerShell IEX cradle) differs from the campaign's actual delivery (certutil / browser chain) and planned execution (cmd .003, not PowerShell .001). _Action: acquire samples matching the real TTPs, or run live Atomics once the unverified IDs are confirmed._
4. **MEDIUM — no packaged atomics** for the two highest-value techniques (T1574.014, T1027.001) -> manual reproduction required regardless.

## Coverage summary
The exercise confirmed the pipeline works end-to-end (ingest -> map -> scan -> record) and caught a PowerShell download-cradle at high severity — but validated **only ~7% of the planned techniques** and **zero of the three crown-jewel techniques**, because the available telemetry was limited to a single PowerShell channel. Detection tooling is proven; campaign coverage is not.
