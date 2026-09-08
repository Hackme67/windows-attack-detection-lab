# Attack Chain Analysis & IOC Summary

## Full Attack Chain (MITRE ATT&CK Mapped)

| Stage | Technique | Technique ID | Tool Used | Evidence |
|---|---|---|---|---|
| Reconnaissance | Network Service Discovery | T1046 | Nmap | Full port scan, NSE scripts |
| Reconnaissance | Gather Victim Host Information | T1592 | Nmap NSE | OS/hostname/workgroup disclosure |
| Credential Access | Brute Force (Password Guessing) | T1110.001 | Hydra | Event ID 4625 ×6, 4624 ×1 |
| Initial Access | Valid Accounts | T1078 | Hydra (cracked creds) | Event ID 4624 |
| Privilege Escalation | Valid Accounts (privilege misuse) | T1078 | Manual (simulated misconfig) | Local group membership change |
| Execution | Windows Management Instrumentation | T1047 | netexec (wmiexec) | Sysmon Event ID 1 |
| Execution | Command and Scripting Interpreter | T1059 | netexec (wmiexec) | Sysmon Event ID 1 |
| Discovery | System Information Discovery | T1082 | whoami /all | netexec output |
| Discovery | Local Account Discovery | T1087.001 | net user | netexec output |
| (Exploitable, not exploited) | Exploitation of Remote Services | T1210 | — | SMBv1 enabled finding |
| (Exploitable, not exploited) | Adversary-in-the-Middle | T1557 | — | SMB signing disabled, NTLMv1 finding |

## Indicators of Compromise (IOC) Table

| IOC Type | Value | First Observed | Context |
|---|---|---|---|
| Attacker Source IP | `10.10.1.3` | 10:41 IST | All attack traffic origin |
| Target IP | `10.10.1.7` | — | Windows 10 victim, hostname CLIENT |
| Compromised Account | `svc_test` (CLIENT\svc_test) | 11:29:03 IST | Weak password, later privilege-escalated |
| Cracked Credential | `Password123` | 11:29:03 IST | Found via Hydra dictionary attack (7-word list) |
| Attack Tool: Hydra | User-Agent/behavior: rapid sequential SMB auth attempts | 11:29:02–03 IST | Brute force tool signature |
| Attack Tool: netexec/wmiexec | Process pattern: `cmd.exe /Q /c [cmd] 1> \Windows\Temp\[random] 2>&1` | 11:58–12:02 IST | Remote execution signature |
| Suspicious Parent Process | `WmiPrvSE.exe` → `cmd.exe`, User: NETWORK SERVICE | 11:58–12:02 IST | WMI-based execution vector |
| File Hash (cmd.exe — legitimate baseline) | `SHA256: 9023F8AAEDA4A1DA45AC477A81B5BBE4128E413F19A0ABFA3715465AD66ED5CD` | — | Legitimate Windows binary; included for completeness, not malicious itself |
| Vulnerable Configuration | SMB signing: disabled; SMBv1: enabled; NTLM: v1 in use | 10:45 IST | Root-cause weaknesses enabling the attack |

## Attack Timeline (Consolidated)

```
10:41 ─┬─ Nmap full port scan begins
10:44 ─┤  (completes: ports 135, 139, 445, 5040, dynamic RPC range identified)
10:45 ─┤  Nmap NSE script scan: SMB signing disabled, guest auth accepted
10:48 ─┴─ Wireshark capture of recon traffic saved

11:29:02 ─┬─ Hydra brute force begins against svc_test (SMB)
11:29:03 ─┴─ 6 failed attempts (4625) + 1 success (4624) — Password123 confirmed

~11:35   ─── svc_test added to local Administrators (simulated misconfiguration)

11:58:08 ─┬─ wmiexec: "whoami" executed remotely (Sysmon Event ID 1)
11:59:54 ─┤  wmiexec: "whoami /all" executed remotely (Sysmon Event ID 1)
12:00-06 ─┤  [Unrelated: CleanUp.ps1 scheduled task noticed during log review,
           │   investigated, confirmed benign]
12:02:30 ─┴─ wmiexec: "net user" executed remotely (Sysmon Event ID 1)
```

## Root Cause Analysis

The successful compromise chain was enabled by three compounding weaknesses:
1. **Weak, dictionary-guessable password** on a local account with no account lockout policy in place.
2. **Excessive account privilege** — a service-style account (`svc_test`) held local Administrator rights it did not need, turning a single credential compromise into full remote code execution.
3. **Legacy protocol exposure** — SMBv1 and NTLMv1 remaining enabled increases both the attack surface and the ease of credential-based attacks (relay, downgrade).

No single fix would have fully prevented this chain; the incident demonstrates why defense-in-depth (strong credentials + least privilege + modern protocols + monitoring) matters more than any single control.
