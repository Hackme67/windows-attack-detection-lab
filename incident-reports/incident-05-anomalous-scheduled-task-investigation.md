# Incident #5: Anomalous Scheduled Task Investigation (Investigated — Benign, with Least-Privilege Finding)

## Summary
During Sysmon log review, a recurring PowerShell process executing every 60 seconds under the SYSTEM account was identified and investigated as a potential persistence mechanism before being confirmed benign. The investigation nonetheless surfaced a legitimate least-privilege violation worth remediating.

## Details

| Field | Value |
|---|---|
| **Source** | Local (host: CLIENT, 10.10.1.7) — not attacker-originated |
| **Account Context** | NT AUTHORITY\SYSTEM |
| **Timestamp Identified** | 2026-09-08, ~12:00–12:06 IST (during log review; task runs continuously every minute) |
| **Severity** | Informational / Low (confirmed benign, but flags a privilege-hygiene issue) |
| **MITRE ATT&CK Technique (why it was investigated)** | T1053.005 – Scheduled Task; T1059.001 – PowerShell (pattern-matched during triage, ruled out as malicious) |

## What Happened
While reviewing Sysmon Event ID 1 logs for evidence of the WMI-based attack (Incident #3), a separate, unrelated process pattern was observed: a PowerShell process launching every 60 seconds with the following command line:
```
powershell.exe -exec bypass -nop C:\DevTools\CleanUp.ps1
```
running as `NT AUTHORITY\SYSTEM`. This combination of indicators — `-exec bypass` (ExecutionPolicy Bypass), SYSTEM-level execution, and a minute-level recurrence — matches patterns commonly associated with attacker persistence mechanisms, so it was treated as a finding requiring investigation rather than dismissed.

### Investigation Findings
- The task was traced to a custom Scheduled Task named `CleanUp`, located at the task root path (`\`) rather than under a Microsoft-owned path, confirming it as a user/administrator-created task, not a Windows default.
- The script content was reviewed directly (without execution):
  ```powershell
  # This script will clean up all your old dev logs every minute.
  # To avoid permissions issues, run as SYSTEM (should probably fix this later)
  Remove-Item C:\DevTools\*.log
  ```
- The script performs a single, narrowly-scoped file deletion operation and contains a developer comment acknowledging the SYSTEM-level execution was a shortcut, not a deliberate security decision.

**Conclusion: Benign.** This is legitimate lab/development housekeeping automation, not attacker activity.

## Evidence
- Sysmon Event ID 1 entries showing the recurring process (multiple timestamps at 60-second intervals)
- `Get-ScheduledTask` output identifying the `CleanUp` task at root path
- Script content of `C:\DevTools\CleanUp.ps1`, including the developer's own comment on the privilege shortcut

## Investigation Steps
1. Noticed anomalous recurring SYSTEM-level PowerShell execution while reviewing logs for unrelated attack evidence.
2. Did not assume benign or malicious — followed a structured triage process instead.
3. Identified the owning Scheduled Task and its location in the task tree.
4. Reviewed script contents directly rather than executing it, to safely determine its behavior.
5. Checked file metadata (creation/modification time) for consistency with a pre-existing/legitimate script versus a newly-dropped malicious one.
6. Documented findings and closed the investigation as benign, while flagging the least-privilege issue for remediation.

## Detection
- Sysmon Event ID 1 filtering on `-exec bypass` or `-nop` flags combined with `User: NT AUTHORITY\SYSTEM` is a reasonable low-noise hunting query for identifying SYSTEM-context PowerShell activity worth reviewing — most of what it surfaces will be legitimate automation, but it should always be triaged rather than ignored by default.

## Recommended Response
- **Least-privilege remediation:** Reconfigure the `CleanUp` scheduled task to run under a dedicated low-privilege local service account with write/delete permissions scoped only to `C:\DevTools\`, rather than SYSTEM.
- **Documentation:** Maintain an inventory of custom scheduled tasks (owner, purpose, required privilege level) to speed up future triage and avoid re-investigating the same benign activity repeatedly.
- **General practice:** This incident is a good example of why alert fatigue and under-investigation are risks — analysts should have a fast, repeatable process (as demonstrated here) for ruling activity in or out without either ignoring anomalies or treating every anomaly as a confirmed incident.
