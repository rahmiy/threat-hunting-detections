# Rundll32.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1218.011, T1003.001
**Reference:** https://attack.mitre.org/techniques/T1218/011/

---

## Query 1 — Rundll32 Loading DLLs from Non-Standard Paths

This query detects rundll32 invocations referencing DLL files in non-standard locations such as temporary directories, user profile paths, or other user-writable locations. Legitimate rundll32 usage typically involves DLL files in System32 or standard application directories.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\rundll32.exe"
(CommandLine="*\temp\*" OR
CommandLine="*\tmp\*" OR
CommandLine="*\appdata\*" OR
CommandLine="*\programdata\*" OR
CommandLine="*\users\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Rundll32 LSASS Memory Dump via Comsvcs.dll

This query detects rundll32 invocations referencing comsvcs.dll alongside the MiniDump function or ordinal 24 — a well documented credential access technique used to dump LSASS memory. Any occurrence of this pattern should be treated as a critical alert.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\rundll32.exe"
CommandLine="*comsvcs*"
(CommandLine="*MiniDump*" OR CommandLine="*#24*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Rundll32 Executing Script Content

This query detects rundll32 invocations associated with JavaScript or COM scriptlet execution through mshtml.dll or similar mechanisms.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\rundll32.exe"
(CommandLine="*mshtml*" OR CommandLine="*javascript*" OR CommandLine="*.sct*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 4 — Rundll32 Spawned by Suspicious Parent Process

This query detects rundll32 spawned by parent processes commonly associated with phishing-based initial access including Office applications and scripting engines.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\rundll32.exe"
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\mshta.exe" OR
ParentImage="*\wscript.exe" OR
ParentImage="*\cscript.exe" OR
ParentImage="*\explorer.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Query 2 targets the comsvcs.dll MiniDump technique specifically — both the function name and ordinal 24 are included as attackers sometimes use the ordinal to avoid string matching
- `explorer.exe` is included as a parent process in Query 4 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
