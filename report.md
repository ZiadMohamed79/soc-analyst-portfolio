# Splunk Incident Investigation — Suspicious Execution and Data Staging

**Environment:** Training/lab telemetry  
**Status:** Sanitized portfolio draft; original event evidence should be reviewed before publication

## Executive summary
The supplied report describes execution of `cod.3aka3.scr`, followed by `cmd.exe` and PowerShell. PowerShell searched the user's profile for documents, archives, and credential-related terms, then compressed collected files into `Draft.Zip`. A network connection to `192.168.0.5:1234` was recorded before the archive was created.

**Exfiltration was not confirmed.** The connection is suspicious in context, but the described evidence does not prove that the archive was transferred.

## Timeline

| Time | Observed event | Interpretation |
|---|---|---|
| 22:55:56 | `explorer.exe` spawned `cod.3aka3.scr` | Suspicious executable launched in user session |
| 22:56:00 | Connection to `192.168.0.5:1234` | Suspicious network activity; purpose/protocol unconfirmed |
| 22:56:04 | Executable spawned `cmd.exe` | Command-shell activity |
| 22:56:14 | `cmd.exe` spawned `powershell.exe` | PowerShell used in subsequent activity |
| After 22:56:14 | Recursive search for files and terms `pass`, `login`, `admin` | File discovery/collection behavior |
| Following collection | `Compress-Archive` created `Draft.Zip` | Data staging observed; transfer not confirmed |

Times are reproduced from the supplied report; validate timezone and raw timestamps before correlating with other sources.

## Findings
- **F-01 — Suspicious executable:** Source report identifies `cod.3aka3.scr` and says its SHA-256 received strong antivirus detections. Exact hash omitted from this public-facing draft.
- **F-02 — Process chain:** Report describes correlation linking the executable to `cmd.exe` and `powershell.exe`.
- **F-03 — Archive staging:** `Draft.Zip` was created with `Compress-Archive`.
- **F-04 — Network activity:** Connection from `10.0.1.4:59835` to `192.168.0.5:1234`; source report notes duplicate ingestion.
- **F-05 — Exfiltration:** Not confirmed; no available telemetry in the source report links the archive to an outbound transfer.

## ATT&CK mapping from source report

| Technique | Evidence described | Status |
|---|---|---|
| `T1059.001` | PowerShell | Mapped |
| `T1059.003` | `cmd.exe` | Mapped |
| `T1083` | Recursive file discovery | Mapped |
| `T1560` | Archive creation | Mapped |
| `T1071` | Possible application-layer protocol/C2 | Explicitly unconfirmed |

## Recommended follow-up
1. Validate original Sysmon/endpoint records, process IDs, ProcessGuid values, timestamps, and command lines.
2. Search for the executable and hash using approved procedures.
3. Determine whether the destination is expected and review network/firewall/DNS/proxy records.
4. Search for archive creation and subsequent network activity.
5. Do not call this confirmed exfiltration without telemetry proving transfer.

## Evidence limitations
This draft is based on a supplied report, not independent Splunk searches. The source report is marked confidential; publish only a derivative if permission covers public release. No raw events or executable/archive are included.

## Evidence checklist
- [ ] Redacted initial alert and search results
- [ ] Process creation events and ProcessGuid correlation
- [ ] PowerShell command-line evidence
- [ ] Archive creation event/path
- [ ] Network connection event and duplicate-ingestion handling
- [ ] Follow-on transfer check
- [ ] Screenshots redacted and approved for public release
