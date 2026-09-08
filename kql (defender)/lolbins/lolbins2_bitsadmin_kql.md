# Bitsadmin.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1197
**Reference:** https://attack.mitre.org/techniques/T1197/

---

## Query 1 — Bitsadmin Job Creation with External URL

This query detects bitsadmin invocations creating BITS transfer jobs referencing external URLs. Legitimate bitsadmin usage in enterprise environments is relatively uncommon and any invocation referencing external URLs outside of approved software deployment processes warrants investigation.

```kql
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("/transfer", "/create", "/addfile")
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Bitsadmin Downloading to Suspicious Paths

This query detects bitsadmin invocations downloading files to temporary directories or user-writable locations commonly used to stage malicious payloads.

```kql
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("/transfer", "/addfile")
| where ProcessCommandLine has_any (@"\temp\", @"\tmp\", @"\appdata\", @"\programdata\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Bitsadmin Spawned by Suspicious Parent Process

This query detects bitsadmin spawned by parent processes not typically associated with legitimate BITS job management. Bitsadmin being launched by scripting engines or Office applications is a strong indicator of malicious activity.

```kql
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe",
    "powershell.exe",
    "cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The two consecutive `has_any` conditions in Queries 1 and 2 act as an AND — both patterns must be present in the command line
- Legitimate bitsadmin usage in enterprise environments is relatively uncommon — any results outside of approved software deployment workflows warrant investigation
- `explorer.exe`, `powershell.exe`, and `cmd.exe` are included in Query 3 as parent processes — these may generate some noise depending on the environment and can be removed individually if needed
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
