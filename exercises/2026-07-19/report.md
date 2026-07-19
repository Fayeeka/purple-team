# Threat Intel Analysis: Screening Serpens (UNC1549 / Smoke Sandstorm) — MiniUpdate & MiniJunk V2 RATs

**Source:** [Unit 42, Palo Alto Networks](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
**Activity window:** Feb–Apr 2026 · **Attribution confidence (per report):** moderate-high
**Ingested:** 2026-07-19

**Actor profile:** Iran-nexus espionage APT. Recruitment-themed social engineering against tech/aerospace/defense/telecom personnel; DLL sideloading + AppDomainManager hijacking; Azure-hosted per-target C2.

## Extracted TTPs

| Technique | ID | Confidence | Priority |
|-----------|-----|------------|----------|
| Spearphishing Link (recruitment lures, fake job PDFs, spoofed meeting invites) | T1566.002 | High | Skip |
| Impersonation (air carrier, video-conf brand, job sites) | T1656 | High | Skip |
| User Execution: Malicious File (setup.exe) | T1204.002 | High | Simulate |
| Ingress Tool Transfer (payload from filemail/ONLYOFFICE/Azure) | T1105 | High | Simulate |
| **DLL Side-Loading** (malicious DLL beside legit signed .NET exe) | **T1574.002** | High* | **Simulate** |
| **AppDomainManager Hijacking** (Pre-Main() via .config) | **T1574.014** | High | **Simulate** |
| **Impair Defenses: Disable Windows Event Logging / ETW** (`<etwEnable enabled="false"/>`) | **T1562.002** | High | **Simulate** |
| Subvert Trust Controls (`bypassTrustedAppStrongNames`) | T1553 | Med | Simulate |
| Code Signing — stolen/abused digital signature | T1553.002 | Med | Skip |
| Scheduled Task/Job (daily 09:30; `WindowsSecurityUpdate`; `Synchronize OS`) | T1053.005 | High | Simulate |
| Masquerade Task or Service (task named like Windows update) | T1036.004 | High | Simulate |
| Match Legitimate Name/Location (update.exe, SoftwareLicencing.exe, C2 = Win svc names) | T1036.005 | High | Simulate |
| Hidden Files and Directories (3 hidden files in archive; `\bin\update`) | T1564.001 | High | Simulate |
| Windows Command Shell (`cmd.exe /c`) | T1059.003 | High | Simulate |
| Abuse Elevation Control: Bypass UAC (requests elevation) | T1548.002 | Med | Simulate |
| Process Discovery (enumerate + terminate) | T1057 | High | Simulate |
| Virtualization/Sandbox Evasion (parent = svchost.exe, proc-name check) | T1497 | High | Simulate |
| Execution Guardrails / Time-Based (hard-coded post-date trigger) | T1480 / T1497.003 | High | Partial |
| Obfuscated Files or Information (ROT13+reverse, XOR 0x8A, MBA) | T1027 | High | Skip |
| Binary Padding (junk strings -> ~12 MB, beat sandbox size limits) | T1027.001 | High | Simulate |
| Deobfuscate/Decode Files or Information | T1140 | High | Skip |
| Application Layer Protocol: Web (HTTP GET `/agent/poll`, POST beacons) | T1071.001 | High | Infra |
| Data Encoding: Standard (Base64 command dispatcher) | T1132.001 | Med | Infra |
| Exfiltration Over C2 Channel (+ chunked upload) | T1041 | High | Infra |
| Data Transfer Size Limits (chunking) | T1030 | Med | Infra |

\* Report hyperlinks **T1574.001** in prose, but the described behavior — dropping an unsigned DLL next to a legitimate signed binary and forcing load via `<probing privatePath="."/>` — is textbook **T1574.002 DLL Side-Loading**. Flagging the discrepancy; mapped to the accurate sub-technique.

## Simulation Plan

### Phase 1: Delivery & Execution
- **T1204.002 / T1105:** Stage a benign ZIP (decoy PDFs + `setup.exe` + sideload DLL) pulled from a web host; execute to kick off the chain. Generates process-creation + download telemetry (Sysmon EID 1, 15; 4688).

### Phase 2: Execution & Defense Evasion (the crown jewels)
- **T1574.014 AppDomainManager Hijacking:** Drop a legit .NET exe + attacker `.config` with a custom `AppDomainManager`; observe managed DLL load *before* `Main()`. This is the report's signature evolution — highest-value detection target.
- **T1574.002 DLL Side-Loading:** Legit signed exe loads unsigned DLL from CWD (Sysmon EID 7 — unsigned/unusual module into signed process).
- **T1562.002 Disable ETW:** Reproduce `<etwEnable enabled="false"/>` in the `.config` and confirm the resulting telemetry gap. Pair with EDR/ETW-integrity monitoring.
- **T1553 Strong-name bypass:** `bypassTrustedAppStrongNames` in `.config` loading a tampered assembly.

### Phase 3: Persistence & Privilege Escalation
- **T1053.005 + T1036.004:** Create a daily scheduled task at a fixed time and a logon-triggered task named `WindowsSecurityUpdate` (4698, Microsoft-Windows-TaskScheduler/Operational EID 106/200).
- **T1548.002:** Trigger a UAC elevation request.

### Phase 4: Discovery, Anti-Analysis, Masquerading
- **T1057:** Enumerate + terminate processes.
- **T1497 / T1480:** Parent-process check (svchost), running-process-name check, hard-coded date guardrail.
- **T1036.005 / T1564.001 / T1027.001:** Rename binaries to Windows-like names, set hidden attributes, pad a binary with junk to inflate size.

### Phase 5: Command & Control / Exfil
- **T1071.001 / T1132.001 / T1041 / T1030:** Beacon over HTTPS to a lab-controlled listener with GET `/agent/poll`, Base64 command frames, and chunked file upload.

## Infrastructure Requirements
- **C2 emulation (Phase 5):** Local HTTP(S) listener (e.g., a mock server or C2 framework in an isolated segment) to exercise `T1071.001/T1041/T1030/T1132.001`. Not reproducible with Atomic Red Team alone.
- **.NET runtime** on the test host for the AppDomainManager/ETW/`.config` techniques (`v4.0.30319` per report).
- **Sysmon** with a config that logs **EID 7 (Image/Module Load)** — essential for sideloading and AppDomainManager detection; many default configs suppress it.
- **Lab constraint (per `CLAUDE.md`):** No live domain/isolated workstation is available for this project — Phases 2–4 are validated against **Module 3/8 EVTX samples** rather than live Atomic execution where a lab host isn't reachable. Phase 5 stays theoretical unless a listener host is stood up.

## Detection Opportunities
- **AppDomainManager hijacking (T1574.014):** `APPDOMAIN_MANAGER_ASM` / `APPDOMAIN_MANAGER_TYPE` env vars, or an `.exe.config` containing `<appDomainManagerType>` / `<probing privatePath>` next to a signed binary -> managed assembly loaded pre-Main.
- **ETW tampering (T1562.002):** `.config` files with `etwEnable="false"`; sudden loss of `Microsoft-Windows-DotNETRuntime` ETW events from a process that should emit them.
- **DLL side-loading (T1574.002):** Signed Microsoft/vendor binary loading an **unsigned** DLL from `%LOCALAPPDATA%` or a user-writable dir (Sysmon EID 7, signature status != valid).
- **Scheduled tasks (T1053.005):** New tasks named `WindowsSecurityUpdate` / `Synchronize OS`; task actions pointing at `%LOCALAPPDATA%\...\bin\update\update.exe` (4698 + TaskScheduler/Operational).
- **Masquerading (T1036):** `svchost.exe` as parent of a non-service binary; `update.exe`/`SoftwareLicencing.exe` running from AppData.
- **Network:** Beacons to `*.azurewebsites.net` clusters of 3–5 lookalike domains per host; URIs `/agent/poll`, `/api/app/check|update|comment`; hardcoded Chrome/Edge UAs (`Chrome/146.0.0.0`, `Chrome/144.0.0.0 ... Edg/144.0.0.0`).
- **Hunt IOCs:** see `findings.md` (23 domains + 4 URLs + 13 SHA256).

## Malware Families
- **MiniUpdate** — newly discovered; internal name `UpdateChecker.dll`. AppDomainManager hijack + native ETW/strong-name evasion via `.config`; 16-opcode dispatcher (March) expanding to 18 (April) with chunked exfil. Plaintext strings in `.rdata` (rushed/different dev cell).
- **MiniJunk V2** — evolved from Check Point's MiniJunk. Payloads `unbcl.dll` / `Connection.dll`; heavy MBA + XOR obfuscation and junk-string padding (~12 MB). Sideloads via legit `Setup.exe` / `SoftwareLicencing.exe`.

## Atomic Test Plan

Generated by the `atomic-mapper` agent from the "Simulate"-priority techniques above.

> **⚠️ UNVERIFIED ID REMAPPING.** The agent reported that the Atomic Red Team `master` it inspected uses **renumbered ATT&CK IDs**, and that several requested IDs would fail as `Invoke-AtomicTest` targets. **These remappings have NOT been confirmed against a local Atomic Red Team checkout — none is available in this environment.** Treat the `T1685` / `T1685.001` mapping for the ETW/event-logging technique with particular skepticism: `T1562.002` is a valid, current ATT&CK ID and `T1685` is not a recognized ATT&CK technique. **Before running anything, confirm the actual folder names** in the lab's atomic-red-team checkout (e.g. `ls atomics/ | grep T15`).

| Report ID | Agent's claimed Atomic ID | Verification status |
|-----------|---------------------------|---------------------|
| T1574.002 (DLL Side-Loading) | `T1574.001` #4/#5 | Unverified (plausible — folding) |
| T1562.002 (Disable ETW/logging) | `T1685.001` / `T1685` | **Unverified — likely wrong; verify before use** |
| T1497 (Sandbox Evasion) | `T1497.001` #3 | Unverified (plausible) |
| T1574.014 (AppDomainManager) | no atomic exists → manual | Unverified |
| T1027.001 (Binary Padding) | no atomic exists → manual | Unverified |

### Test matrix (highest → lowest detection value)

| Technique | Test | Invoke command (agent's IDs — see caveat) | Key telemetry |
|-----------|------|-------------------------------------------|---------------|
| **T1574.014** AppDomainManager | *No atomic* — manual `.config`/env-var repro; proxy: T1574.001 #5 (dotnet startup hook) | `Invoke-AtomicTest T1574.001 -TestNumbers 5 -GetPrereqs` | Sysmon 11 (`.exe.config` beside signed EXE), 7 (unsigned assembly load), 13 (`APPDOMAIN_MANAGER_*`) |
| **T1574.002** Side-Loading | #4 Notepad++ GUP.exe loads unsigned libcurl.dll | `Invoke-AtomicTest T1574.001 -TestNumbers 4 -GetPrereqs` | **Sysmon 7** — signed GUP.exe loading unsigned DLL from user path |
| **T1562.002** Disable ETW | #69 Disable .NET ETW via registry | `Invoke-AtomicTest T1685 -TestNumbers 69` **(⚠ ID unverified)** | Sysmon 13 — `...\.NETFramework\ETWEnabled=0` |
| **T1053.005** Scheduled Task | #2 Scheduled task Local | `Invoke-AtomicTest T1053.005 -TestNumbers 2` | **Security 4698**, TaskScheduler/Op 106 |
| **T1036.004** Masquerade Task | #1 W32Time-lookalike task | `Invoke-AtomicTest T1036.004 -TestNumbers 1` (elevated) | 4698 — `win32times` as SYSTEM |
| **T1036.005** Match Legit Name | #2 Masquerade as svchost.exe | `Invoke-AtomicTest T1036.005 -TestNumbers 2` | Sysmon 1 — svchost.exe from `\Windows\Temp` |
| **T1564.001** Hidden Files | #4 attrib +h +s | `Invoke-AtomicTest T1564.001 -TestNumbers 4 -GetPrereqs` | Sysmon 1 — `attrib +h +s` |
| **T1059.003** cmd shell | #1 Batch script | `Invoke-AtomicTest T1059.003 -TestNumbers 1 -GetPrereqs` | Sysmon 1 — `cmd.exe /c *.bat` |
| **T1548.002** Bypass UAC | #3 Fodhelper | `Invoke-AtomicTest T1548.002 -TestNumbers 3` | Sysmon 13 — `ms-settings\shell\open\command`; fodhelper→cmd at High integrity |
| **T1057** Process Discovery | #2 tasklist | `Invoke-AtomicTest T1057 -TestNumbers 2` | Sysmon 1 — `tasklist.exe` (low fidelity) |
| **T1497** Sandbox Evasion | #3 Detect VM (WMI thermal) | `Invoke-AtomicTest T1497.001 -TestNumbers 3` | WMI-Activity/Op 11; powershell WMI query |
| **T1105** Ingress Transfer | #7 certutil download | `Invoke-AtomicTest T1105 -TestNumbers 7` | Sysmon 1 (`certutil -urlcache`), 3 (netconn) |
| **T1204.002** User Execution | #13 Click-Fix BAT | `Invoke-AtomicTest T1204.002 -TestNumbers 13` | Sysmon 1 — powershell→cmd→`click-fix.bat` |
| **T1027.001** Binary Padding | *No atomic* — manual (`fsutil setvaliddata` / null-append) | — | Sysmon 11 (large file), low entropy region |

### Execution notes
- **.NET Framework required** on the test host for the AppDomainManager (T1574.014) and ETW (T1562.002) techniques — they act on the CLR. T1574.001 #5 also needs .NET SDK 6 (auto-installed via winget on `-GetPrereqs`).
- **Elevation** needed for: T1562.002 (HKLM write), T1036.004 (`/ru system`); Fodhelper (T1548.002) runs from a medium-integrity admin account (that is the bypass).
- Run `-GetPrereqs` before any test listing prerequisites; run `-Cleanup` after each.
- **Coverage gap:** the two highest-value techniques for this campaign — **T1574.014** (the report's signature evolution) and **T1027.001** — have **no packaged atomic** and require manual reproduction.

