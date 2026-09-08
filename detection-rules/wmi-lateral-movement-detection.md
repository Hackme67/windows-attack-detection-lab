# Detection Rule: WMI-Based Remote Command Execution (wmiexec-style)

## Rule Logic
Detect process creation events where `WmiPrvSE.exe` (WMI Provider Host) is the parent process of `cmd.exe` or `powershell.exe` — a strong indicator of remote command execution via WMI, commonly used by tools like Impacket's `wmiexec.py` and netexec's `-x` execution method.

## Sysmon Event Log Query (PowerShell)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
    Where-Object { $_.Message -match "ParentImage:\s+C:\\Windows\\System32\\wbem\\WmiPrvSE\.exe" } |
    Where-Object { $_.Message -match "Image:\s+C:\\Windows\\System32\\(cmd|WindowsPowerShell\\v1\.0\\powershell)\.exe" } |
    Format-List TimeCreated, Id, Message
```

## Detection Threshold
- **Trigger:** Any occurrence of `WmiPrvSE.exe` spawning `cmd.exe` or `powershell.exe` on an endpoint workstation. Legitimate administrative WMI usage on end-user workstations is comparatively rare, making this a low-noise, high-confidence indicator.
- **Escalate to Critical if:** The command line matches the output-redirection pattern used by wmiexec-family tools: `/Q /c .* 1> \\Windows\\Temp\\[A-Za-z0-9]+ 2>&1`

## Validated Against (This Lab)
Three Sysmon Event ID 1 entries, all matching the pattern:
```
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
ParentUser:  NT AUTHORITY\NETWORK SERVICE
Image:       C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /Q /c <net user|whoami /all|whoami> 1> \Windows\Temp\<random> 2>&1
User:        CLIENT\svc_test
IntegrityLevel: High
```
**Result:** All three attacker commands correctly identified with full command-line and process-hash evidence.

## False Positive Considerations
- Legitimate enterprise systems management tools (SCCM, some RMM/patch management platforms) use WMI extensively and may trigger this rule — maintain an allowlist of known-legitimate management infrastructure IPs/service accounts.
- On servers specifically configured as WMI management endpoints, this pattern may be expected — tune thresholds per-asset-role (workstation vs. server vs. management server).

## Recommended SIEM/EDR Rule (Sigma-style pseudocode)
```yaml
title: WMI Spawning Command Shell (Potential wmiexec Lateral Movement)
logsource:
  product: windows
  service: sysmon
  definition: 'Event ID 1 (Process Creation)'
detection:
  selection:
    ParentImage: '*\wbem\WmiPrvSE.exe'
    Image:
      - '*\cmd.exe'
      - '*\powershell.exe'
  high_confidence:
    CommandLine|re: '/Q /c .* 1> \\\\Windows\\\\Temp\\\\[A-Za-z0-9]+ 2>&1'
  condition: selection
level: high
```
