# Wscript.exe and Cscript.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1059.005, T1059.007
**Reference:** https://attack.mitre.org/techniques/T1059/005/

---

## Query 1 — Wscript or Cscript Executing Scripts from Suspicious Paths

This query detects wscript or cscript executing script files from temporary directories or user-writable locations commonly used to stage malicious scripts delivered through phishing or drive-by download activity.

```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any (@"\temp\", @"\tmp\", @"\appdata\", @"\programdata\", @"\downloads\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Wscript or Cscript Executing Suspicious Script Extensions

This query detects wscript or cscript executing encoded or obfuscated script file types that are less commonly used in legitimate administrative scenarios.

```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any (".vbe", ".jse", ".wsf", ".wsh")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Wscript or Cscript Spawned by Suspicious Parent Process

This query detects wscript or cscript spawned by parent processes commonly associated with phishing-based initial access including Office applications and browser processes.

```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "explorer.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Both wscript.exe and cscript.exe are covered in all queries — they provide equivalent scripting capability and are interchangeable from an attacker perspective
- Query 2 focuses on encoded script extensions — `.vbe` is an encoded VBScript file and `.jse` is an encoded JScript file — these are less commonly used in legitimate automation and warrant investigation
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
