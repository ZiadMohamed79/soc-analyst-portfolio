# Splunk query ideas — not executed

The source report identifies Splunk and Sysmon/endpoint telemetry but does not include the original index, sourcetype, or queries. These are templates only.

## Search for executable
```spl
index=<index> "cod.3aka3.scr"
| table _time host user Image ParentImage ProcessId ParentProcessId ProcessGuid ParentProcessGuid CommandLine
| sort _time
```

## Pivot to PowerShell/archive activity
```spl
index=<index> ("powershell.exe" OR "Compress-Archive" OR "Draft.Zip")
| table _time host user Image CommandLine ParentImage ProcessGuid
| sort _time
```

## Search destination indicator
```spl
index=<index> "192.168.0.5" "1234"
| table _time host src_ip src_port dest_ip dest_port process_name
| sort _time
```

Replace placeholders/fields to match the dataset. Validate these searches before publishing results.
