# Living off the Land Binary Abuse — Rundll32, Wscript, Cscript, and Bitsadmin

## Overview

This document continues the exploration of Living off the Land Binary abuse in Windows environments, focusing on three additional categories of commonly abused system utilities — rundll32.exe, the Windows Script Host engines wscript.exe and cscript.exe, and the Background Intelligent Transfer Service utility bitsadmin.exe. Like the binaries covered in the first installment of this series, these utilities are legitimate signed Windows components that are trusted by default across enterprise environments and present in virtually every modern Windows installation.

Each of these utilities provides attackers with distinct capabilities that complement and extend their ability to execute malicious code, download additional tooling, and maintain persistence while blending into the background noise of normal administrative activity. Understanding how these tools are commonly abused, and what behavioral indicators their misuse produces, is essential for building detection capability against the broad range of threat actors that rely on living off the land techniques.

---

## Why Attackers Abuse These Binaries

The same core advantages that make all LOLBins attractive to attackers apply equally to rundll32, the Windows Script Host engines, and bitsadmin. These binaries are signed by Microsoft, present on every Windows endpoint, and trusted by application allowlisting controls that would block unknown executables. They require no delivery, installation, or compilation — an attacker who has achieved any level of code execution has immediate access to all of them.

Beyond these common advantages, each binary in this set offers specific capabilities that are difficult to replicate through other means. Rundll32 provides a mechanism for executing arbitrary code embedded in DLL files, including both attacker-supplied DLLs and the abuse of legitimate system DLLs for unintended purposes. The Windows Script Host engines provide a full scripting runtime capable of executing complex VBScript and JScript code that can interact with the Windows API, file system, registry, and network. Bitsadmin exposes the Windows Background Intelligent Transfer Service — a network file transfer mechanism built into Windows — that can be abused to download payloads in a way that may evade network-based controls by leveraging a trusted system service.

---

## Commonly Abused Binaries

The following represents a sampling of abuse techniques associated with these utilities as observed in security incidents and threat intelligence reporting. This is not an exhaustive list, as attacker tradecraft continues to evolve.

**rundll32.exe**

Rundll32 is a legitimate Windows utility designed to execute functions exported by DLL files. It is used routinely by the operating system and applications to invoke specific DLL functionality without requiring a standalone executable. Attackers abuse rundll32 in several ways. The most straightforward abuse involves loading attacker-controlled DLL files and invoking exported functions that execute malicious code. Rundll32 can also be used to execute JavaScript and VBScript code embedded in specially crafted scriptlet files, providing a script execution capability similar to mshta and regsvr32. Perhaps most notably, rundll32 is commonly used to invoke the MiniDump function exported by the legitimate Windows DLL comsvcs.dll to dump the memory of the LSASS process — a well-documented credential access technique observed across a wide range of threat actor groups. The versatility of rundll32 abuse makes it one of the most frequently observed LOLBins across all categories of intrusion activity.

**wscript.exe and cscript.exe**

The Windows Script Host provides a scripting runtime built into Windows that supports execution of VBScript and JScript files. Wscript.exe is the windowed version that can display graphical user interface elements, while cscript.exe is the command-line version that outputs to the console. Both engines are capable of executing the same script content and provide equivalent functionality for attackers. The Windows Script Host is deeply integrated into the Windows ecosystem and is used legitimately by a wide range of administrative scripts and applications. Attackers abuse the Script Host engines primarily through phishing campaigns that deliver malicious .vbs or .js files as email attachments or through drive-by download scenarios. These scripts may execute directly as a first stage payload, download and execute additional tooling, establish persistence through registry modifications or scheduled tasks, or serve as a loader for more sophisticated malware. The Script Host engines provide attackers with a full-featured scripting environment that can interact with COM objects, the Windows API, the file system, and the network — making them extremely versatile for post-exploitation activity.

**bitsadmin.exe**

Bitsadmin is a command-line tool for managing Background Intelligent Transfer Service jobs — a Windows component designed to transfer files asynchronously using idle network bandwidth. BITS was originally designed for Windows Update and other Microsoft services to download content in the background without disrupting user activity. Attackers abuse bitsadmin to create BITS transfer jobs that download payloads from attacker-controlled infrastructure. Because BITS transfers are performed by a legitimate Windows service rather than a user-initiated process, this technique can evade network monitoring tools that focus on process-initiated connections and may bypass firewall rules that restrict outbound connections from unknown processes. BITS jobs also persist across reboots by default, making bitsadmin abuse a viable persistence mechanism — an attacker can create a BITS job that downloads and executes a payload on a recurring schedule or after each reboot. The use of bitsadmin for payload delivery has been observed across a range of threat actor groups and is documented in multiple publicly available threat intelligence reports.

---

## The Operational Problem

Detection of abuse across these three binary categories shares the same fundamental challenge as all LOLBin detection — the binaries are legitimate and expected, and their execution alone is not sufficient to distinguish malicious from benign usage. The volume of legitimate rundll32, wscript, and cscript activity in most enterprise environments can be significant, and bitsadmin activity may be relatively rare but still legitimate in environments that use BITS for software deployment.

Rundll32 presents a particular challenge because it is invoked by Windows itself and by a wide range of applications for legitimate purposes. The key discriminator is what DLL and function are being invoked and from where — rundll32 loading system DLLs from System32 for documented purposes is expected, while rundll32 loading DLLs from temporary directories or network shares, or invoking functions not associated with normal system activity, is suspicious.

The Windows Script Host engines present detection challenges because .vbs and .js files are common in enterprise environments for legitimate administrative automation. Command-line argument visibility is essential for distinguishing malicious from legitimate script execution — specifically the path of the script file being executed and whether that script was delivered through a suspicious mechanism such as email attachment or download.

Bitsadmin is relatively straightforward to hunt because its legitimate use in enterprise environments is less common than rundll32 or the Script Host engines, and the creation of BITS jobs for payload download has few legitimate explanations outside of specific software deployment scenarios.

---

## Detection Opportunities

The following represents a sampling of practical starting points for hunting and detecting abuse of these utilities — this is not an exhaustive list.

**Monitor for rundll32 executing from non-standard paths or invoking suspicious functions**

Rundll32 invocations that reference DLL files in temporary directories, user profile paths, or network shares are strong indicators of malicious activity. Additionally, rundll32 invocations referencing comsvcs.dll with the MiniDump function or ordinal 24 are highly indicative of LSASS memory dumping activity and should be treated as a critical alert.

**Detect rundll32 executing JavaScript or scriptlet content**

Rundll32 can be used to execute JavaScript through the mshtml.dll rundll entry point and COM scriptlets through similar mechanisms. Invocations referencing these execution paths or containing JavaScript or script content in the command line should be investigated.

**Hunt for wscript and cscript executing scripts from suspicious locations**

Script Host invocations executing .vbs or .js files from temporary directories, user profile paths, downloads folders, or email attachment staging locations are strong indicators of phishing-based initial access. Monitoring for these parent-child relationships — particularly wscript or cscript spawned by email clients or browser processes — can surface early stage execution.

**Monitor for bitsadmin job creation referencing external URLs**

Bitsadmin invocations containing the `/transfer` or `/create` flags alongside external URLs are strong indicators of payload download activity. BITS job creation outside of approved software deployment processes warrants investigation regardless of the URL referenced.

**Identify anomalous parent process relationships**

Rundll32, wscript, and cscript spawned by Office applications, browser processes, or archive utilities are strong indicators of phishing-based initial access. Monitoring for these parent-child relationships can surface LOLBin abuse early in the attack chain before further payload execution occurs.

---

## MITRE ATT&CK Mapping

- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1197** — BITS Jobs
- **T1003.001** — OS Credential Dumping: LSASS Memory

---

## Sources

- https://attack.mitre.org/techniques/T1218/011/
- https://attack.mitre.org/techniques/T1059/005/
- https://attack.mitre.org/techniques/T1197/
- https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- https://lolbas-project.github.io/lolbas/Binaries/Wscript/
- https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
- https://redcanary.com/threat-detection-report/techniques/
