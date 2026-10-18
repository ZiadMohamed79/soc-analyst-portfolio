# Search templates

The original notes identify a source-IP search and `session-id` as a correlation field. The exact SIEM, index, sourcetype, and field names were not confirmed. These are illustrative Splunk-style templates, not verified queries from the lab.

## Search by source IP
```spl
index=<your_index> "185.211.245.170"
| table _time host source sourcetype session-id src_ip sender recipient subject
| sort _time
```

## Correlate by session identifier
```spl
index=<your_index> "185.211.245.170"
| stats count values(src_ip) values(sender) values(recipient) values(subject) by session-id
```

## Search for attachment evidence
```spl
index=<your_index> "Quarter_Report.docm"
| table _time host user file_name file_hash signature action
| sort _time
```

Replace `<your_index>` and field names with the actual data model. Do not claim these queries were executed until you run them against the lab dataset and save the results.
