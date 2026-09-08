# Detection Rule: SMB Brute Force

## Rule Logic
Detect a burst of failed SMB authentication attempts (Event ID 4625) against the same target account from the same source IP, followed by a successful authentication (Event ID 4624) from that same source within a short time window.

## Windows Event Log Query (PowerShell)

```powershell
# Detect failed logon bursts (potential brute force in progress)
$failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-10)} |
    Select-Object TimeCreated,
        @{N='SourceIP';E={($_.Message -split "Source Network Address:\s+")[1].Split("`n")[0].Trim()}},
        @{N='TargetAccount';E={($_.Message -split "Account Name:\s+")[2].Split("`n")[0].Trim()}}

$failedLogons | Group-Object SourceIP, TargetAccount |
    Where-Object { $_.Count -ge 5 } |
    Select-Object Name, Count
```

## Detection Threshold
- **Trigger:** 5 or more Event ID 4625 events for the same (Source IP, Target Account) pair within a 60-second window.
- **Escalate to High severity if:** An Event ID 4624 (successful logon) occurs from the same Source IP within 5 minutes following the failed attempts — this confirms the brute force succeeded, not just was attempted.

## Validated Against (This Lab)
- 6× Event ID 4625, source `10.10.1.3`, account `svc_test`, all within 1 second
- 1× Event ID 4624, source `10.10.1.3`, account `svc_test`, immediately following
- **Result:** Correctly flags as a confirmed, successful brute-force compromise

## False Positive Considerations
- Legitimate users mistyping passwords repeatedly (rare to exceed 5 in under a minute)
- Service accounts with outdated cached credentials attempting repeated authentication (common cause of false positives in production — investigate account context before declaring an incident)
- Password spray tools targeting many accounts with few attempts each will NOT be caught by this account-specific rule; a complementary rule grouping by Source IP alone (regardless of target account) is recommended for spray detection.

## Recommended SIEM/EDR Rule (Sigma-style pseudocode)
```yaml
title: SMB Brute Force - Failed then Successful Logon
logsource:
  product: windows
  service: security
detection:
  failed:
    EventID: 4625
    LogonType: 3
  success:
    EventID: 4624
    LogonType: 3
  condition: failed | count(SourceIP, TargetAccount) >= 5 within 60s followed_by success same SourceIP within 5m
level: high
```
