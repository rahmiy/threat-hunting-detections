# Bitsadmin.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1197
**Reference:** https://attack.mitre.org/techniques/T1197/

---

## Query 1 — Bitsadmin Job Creation with External URL

This query detects bitsadmin invocations creating BITS transfer jobs referencing external URLs. Legitimate bitsadmin usage in enterprise environments is relatively uncommon and any invocation referencing external URLs outside of approved software deployment processes warrants investigation.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\bitsadmin.exe"
(CommandLine="*/transfer*" OR CommandLine="*/create*" OR CommandLine="*/addfile*")
(CommandLine="*http://*" OR CommandLine="*https://*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Bitsadmin Downloading to Suspicious Paths

This query detects bitsadmin invocations downloading files to temporary directories or user-writable locations commonly used to stage malicious payloads.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\bitsadmin.exe"
(CommandLine="*/transfer*" OR CommandLine="*/addfile*")
(CommandLine="*\temp\*" OR
CommandLine="*\tmp\*" OR
CommandLine="*\appdata\*" OR
CommandLine="*\programdata\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Bitsadmin Spawned by Suspicious Parent Process

This query detects bitsadmin spawned by parent processes not typically associated with legitimate BITS job management. Bitsadmin being launched by scripting engines or Office applications is a strong indicator of malicious activity.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\bitsadmin.exe"
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\mshta.exe" OR
ParentImage="*\wscript.exe" OR
ParentImage="*\cscript.exe" OR
ParentImage="*\explorer.exe" OR
ParentImage="*\powershell.exe" OR
ParentImage="*\cmd.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Legitimate bitsadmin usage in enterprise environments is relatively uncommon — any results outside of approved software deployment workflows warrant investigation
- `explorer.exe`, `powershell.exe`, and `cmd.exe` are included in Query 3 as parent processes — these may generate some noise depending on the environment and can be removed individually if needed
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
