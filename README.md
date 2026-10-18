# Splunk Incident Investigation — Suspicious Execution and Data Staging

**SOC Analyst Tier 1 portfolio project | Training/lab telemetry**

> Draft based on the supplied incident report. Add approved, redacted original screenshots/query results before treating this project as evidence-complete. The source report is marked confidential; publish a sanitized derivative only if permission explicitly covers public release.

## Overview
The report describes `cod.3aka3.scr`, a process chain through `cmd.exe` and PowerShell, recursive searches for documents/archives and credential-related terms, and creation of `Draft.Zip`. A connection from `10.0.1.4:59835` to `192.168.0.5:1234` was recorded before archive creation.

**Important:** The source report explicitly says data exfiltration was not confirmed.

## Skills
- SIEM alert triage and event correlation
- Process-tree reconstruction using process and ProcessGuid fields
- Windows endpoint telemetry review
- PowerShell activity analysis
- File discovery and archive/staging investigation
- Timeline construction and evidence-aware MITRE ATT&CK mapping

## Key observations from the source report
- `explorer.exe` spawned `cod.3aka3.scr` at 22:55:56.
- The executable connected to `192.168.0.5:1234` at 22:56:00.
- It spawned `cmd.exe`, followed by `powershell.exe`.
- PowerShell searched the user profile for documents, archives, and terms such as `pass`, `login`, and `admin`.
- Collected files were compressed into `Draft.Zip`.
- A duplicated network event was treated as duplicate ingestion, not two independent connections.
- Exfiltration was not confirmed.

## ATT&CK mapping in the source report
- `T1059.001` — PowerShell
- `T1059.003` — Windows Command Shell
- `T1083` — File and Directory Discovery
- `T1560` — Archive Collected Data
- `T1071` — explicitly unconfirmed in the source report

## Assessment
The source report supports malicious execution, targeted file discovery/collection, archive staging, and suspicious network activity. It does not establish that `Draft.Zip` was transferred out of the environment.

## Recommended Tier 1 actions
1. Preserve and validate original process events and correlation fields.
2. Search for the executable/hash across the environment.
3. Review network, firewall, DNS, and proxy telemetry around the connection.
4. Determine whether `192.168.0.5` is an expected asset.
5. Look for evidence of transfer after archive creation before assessing exfiltration.
6. Follow the approved incident-response procedure.

## Evidence limitations
This draft is based on a supplied report, not independently queried Splunk data. Raw event exports, dataset, and verified executed queries are not included. Do not publish the original confidential report, raw datasets, executable, or archive unless explicitly authorized.

## Author
Ziad Mohamed — IT Student | Aspiring SOC Analyst  
GitHub: https://github.com/ZiadMohamed79  
LinkedIn: https://www.linkedin.com/in/ziad-mohamed-44bb73335/
