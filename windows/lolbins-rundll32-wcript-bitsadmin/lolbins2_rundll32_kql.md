# Rundll32.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1218.011, T1003.001
**Reference:** https://attack.mitre.org/techniques/T1218/011/

---

## Query 1 — Rundll32 Loading DLLs from Non-Standard Paths

This query detects rundll32 invocations referencing DLL files in non-standard locations such as temporary directories, user profile paths, or other user-writable locations. Legitimate rundll32 usage typically involves DLL files in System32 or standard application directories.

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any (@"\temp\", @"\tmp\", @"\appdata\", @"\programdata\", @"\users\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Rundll32 LSASS Memory Dump via Comsvcs.dll

This query detects rundll32 invocations referencing comsvcs.dll alongside the MiniDump function or ordinal 24 — a well documented credential access technique used to dump LSASS memory. Any occurrence of this pattern should be treated as a critical alert.

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "comsvcs"
| where ProcessCommandLine has_any ("MiniDump", "#24")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Rundll32 Executing Script Content

This query detects rundll32 invocations associated with JavaScript or COM scriptlet execution through mshtml.dll or similar mechanisms.

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("mshtml", "javascript", ".sct")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 4 — Rundll32 Spawned by Suspicious Parent Process

This query detects rundll32 spawned by parent processes commonly associated with phishing-based initial access including Office applications and scripting engines.

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Query 2 targets the comsvcs.dll MiniDump technique specifically — both the function name and ordinal 24 are included as attackers sometimes use the ordinal to avoid string matching
- The two consecutive `has` conditions in Query 2 act as an AND — both patterns must be present in the command line
- `explorer.exe` is included as a parent process in Query 4 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
