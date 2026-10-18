# Threat Profile: FIN7 (G0046)

**Analyst:** Umair Haider  **Source:** MITRE ATT&CK Enterprise  **Date:** September 2026

## Overview

|Attribute|Detail|
|-|-|
|**Motivation**|Financially motivated|
|**Active since**|2013|
|**Target sectors**|Retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud services, media, food and beverage, transportation, pharmaceutical, utilities|

## Summary

FIN7 typically gains access through spearphishing — malicious Office/RTF attachments or typosquatted links — then executes obfuscated scripts (PowerShell, VBS, JavaScript) launched from those documents.

## Initial Access — How They Get In

|Technique|ID|Procedure (what FIN7 actually did)|
|-|-|-|
|Spearphishing Attachment|T1566.001|Sent spearphishing emails with malicious Microsoft Office documents or RTF files attached.|
|Spearphishing Link|T1566.002|Conducted broad phishing campaigns using malicious links, including emails containing a typosquatted link to `ip-sccanner[.]com`.|

## Execution — How They Run Code

|Technique|ID|Procedure (what FIN7 actually did)|
|-|-|-|
|Command and Scripting Interpreter|T1059|Used SQL scripts to perform tasks on victim machines.|
|PowerShell|T1059.001|Used a PowerShell script to launch shellcode that retrieved an additional payload; executed POWERTRASH, a custom obfuscation of the PowerSploit shellcode invoker.|
|Windows Command Shell|T1059.003|Used the command prompt to launch commands; also used malicious USB devices acting as virtual keyboards to send Win+R and open the Run dialog.|
|Visual Basic|T1059.005|Used VBS scripts to perform tasks on victim machines.|
|JavaScript|T1059.007|Used JavaScript scripts to perform tasks on victim machines.|

## Coverage Gap Analysis

|Metric|Value|
|-|-|
|FIN7 techniques total|34|
|FIN7 techniques I can detect (any confidence)|4|
|Coverage|~12% (all partial confidence; none reliable)|

### Priority Gaps and Data Sources to Close Them

|Priority|Gap|ID|Data source that closes it|
|-|-|-|-|
|1|Spearphishing Attachment|T1566.001|Email gateway logs (attachment type, sender); plus 4688/Sysmon parent-child detection of Office apps spawning shells (`winword.exe → powershell.exe`)|
|2|PowerShell (obfuscated)|T1059.001|Script Block Logging, Event ID 4104 — records deobfuscated code, defeating POWERTRASH-style obfuscation|
|3|Windows Command Shell|T1059.003|Partial via 4688 with command line; strengthen with Sysmon Event ID 1 (adds hashes and richer parent-process data)|
|Bonus|USB virtual keyboard (T1059.003 procedure)|—|Event ID 6416 (new external device recognized); requires Audit PNP Activity, off by default|

### Key Findings

* **Initial Access is the highest-value gap.** No current visibility into email; it is the earliest point to stop FIN7.
* **Execution-stage detection partially compensates.** Malicious documents must spawn child processes, which 4688 parent-child data can reveal even without email visibility.
* **One data source covers many techniques.** Enabling 4688 with command-line capture provides partial visibility across every T1059 sub-technique.
* **Much of the needed telemetry is off by default** (4104, 4698, 6416). Coverage depends on deliberate logging configuration, not just tooling.

## MITRE ATT&CK Navigator Layers

* `fin7-layer.json` — FIN7 technique set
* `my-coverage-layer.json` — current detection coverage, scored by confidence (1 = partial, 2 = reliable)

