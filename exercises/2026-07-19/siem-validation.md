# SIEM Validation: PowerShell Download-Cradle Correlation

`/purple-loop` Step 5. Validates that the Step 4 high-severity detection would correlate in the SIEM.

> **Status: PENDING MANUAL EXECUTION.** No SIEM MCP server / live connection is available in this environment (only the `hayabusa` MCP is configured). The queries below are ready to run manually in Splunk (or the KQL equivalent for Sentinel/Defender).

## Query

**Splunk SPL — primary (script-block logging, EID 4104):**
```spl
index=windows (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR sourcetype="XmlWinEventLog") EventCode=4104
| eval sb=lower(ScriptBlockText)
| search (sb="*iex*" OR sb="*invoke-expression*")
    AND (sb="*net.webclient*" OR sb="*downloadstring*" OR sb="*downloadfile*"
         OR sb="*invoke-webrequest*" OR sb="*iwr *" OR sb="*start-bitstransfer*")
| rex field=ScriptBlockText "(?i)(?<url>https?://[^\s'\"\)]+)"
| stats count min(_time) as first_seen max(_time) as last_seen
        values(url) as urls values(ScriptBlockId) as scriptblock_ids
        by Computer, UserID, host
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**Corroborating — pipeline execution (EID 4103):**
```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
    Payload="*downloadString*"
| table _time, Computer, User, Payload
```

**KQL equivalent (Sentinel / Defender):**
```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("DownloadString","Net.WebClient","IEX")
```

## Expected Result
From the Step 4 sample: `Computer=fs03vuln.offsec.lan`, `UserID=OFFSEC\admmig`,
`url=https://miro.medium.com/max/1400/1*FnPDYeZVrGTbuE7Lj7JhgQ.png`, `EventCode=4104`.

- A returned event => PowerShell 4104 ingestion + download-cradle correlation confirmed working.
- Zero results => either the `PowerShell/Operational` channel is not forwarded, or script-block logging is disabled on endpoints (itself a finding).

## ATT&CK Mapping
- Technique: [[T1059.001 - PowerShell]]
- Technique: [[T1105 - Ingress Tool Transfer]]
- Tactic: [[Execution]], [[Command and Control]]

## Investigation Notes
- Created: [[Investigation-2026-07-19-Screening-Serpens]]
- IOC: [[IOC-powershell-download-cradle]] — `Net.WebClient.downloadString` + `.png` payload URL
- Related: [[Exercise-2026-07-19-Screening-Serpens]], [[T1574.014 - AppDomainManager Hijacking]] (crown-jewel, unvalidated)

## Follow-up Actions
- [ ] Run the SPL in the live SIEM and confirm the `fs03vuln`/`admmig` event returns
- [ ] Verify PowerShell script-block logging (4104) is enabled + forwarded fleet-wide
- [ ] Build a saved search / correlation rule for `IEX`+`downloadString` cradles if none exists
- [ ] Coverage gap: obtain Sysmon (EID 7/13) + Security (4688/4698) telemetry to validate the crown-jewel techniques ([[T1574.014]], [[T1574.002]], [[T1562.002]], [[T1053.005]])
