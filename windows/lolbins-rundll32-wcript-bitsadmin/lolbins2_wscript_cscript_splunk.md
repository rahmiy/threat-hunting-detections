# Wscript.exe and Cscript.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1059.005, T1059.007
**Reference:** https://attack.mitre.org/techniques/T1059/005/

---

## Query 1 — Wscript or Cscript Executing Scripts from Suspicious Paths

This query detects wscript or cscript executing script files from temporary directories or user-writable locations commonly used to stage malicious scripts delivered through phishing or drive-by download activity.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
(Image="*\wscript.exe" OR Image="*\cscript.exe")
(CommandLine="*\temp\*" OR
CommandLine="*\tmp\*" OR
CommandLine="*\appdata\*" OR
CommandLine="*\programdata\*" OR
CommandLine="*\downloads\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Wscript or Cscript Executing Suspicious Script Extensions

This query detects wscript or cscript executing encoded or obfuscated script file types that are less commonly used in legitimate administrative scenarios.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
(Image="*\wscript.exe" OR Image="*\cscript.exe")
(CommandLine="*.vbe*" OR
CommandLine="*.jse*" OR
CommandLine="*.wsf*" OR
CommandLine="*.wsh*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Wscript or Cscript Spawned by Suspicious Parent Process

This query detects wscript or cscript spawned by parent processes commonly associated with phishing-based initial access. Script Host engines being launched by Office applications or browser processes is a strong indicator of malicious document or file execution.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
(Image="*\wscript.exe" OR Image="*\cscript.exe")
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\mshta.exe" OR
ParentImage="*\explorer.exe" OR
ParentImage="*\chrome.exe" OR
ParentImage="*\msedge.exe" OR
ParentImage="*\firefox.exe" OR
ParentImage="*\iexplore.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Both wscript.exe and cscript.exe are covered in all queries — they provide equivalent scripting capability and are interchangeable from an attacker perspective
- Query 2 focuses on encoded script extensions — `.vbe` is an encoded VBScript file and `.jse` is an encoded JScript file — these are less commonly used in legitimate automation and warrant investigation
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
