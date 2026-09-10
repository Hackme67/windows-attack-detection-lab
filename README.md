# Windows Endpoint Attack Detection & Incident Investigation Lab

A hands-on SOC analyst lab simulating a realistic attack chain against a Windows 10 endpoint, using native Windows logging and Sysmon for detection — investigated end-to-end from reconnaissance through post-exploitation, with full MITRE ATT&CK mapping.

## Objective

Simulate a real-world intrusion from an attacker-controlled Linux host against a Windows 10 target, then investigate the activity exactly as a SOC analyst would: correlating network traffic, Windows Security Event Logs, and Sysmon telemetry to reconstruct the attack timeline, identify indicators of compromise, and produce actionable remediation guidance.

## Lab Environment

| Component | Details |
|---|---|
| Attacker Host | Parrot OS (VirtualBox VM), IP `10.10.1.3` |
| Target Host | Windows 10 Pro, Build 17763.1 (1809, unpatched), IP `10.10.1.7` |
| Network | VirtualBox NAT Network (isolated from host LAN, VMs can reach each other) |
| Hypervisor | Oracle VirtualBox |

> **Note:** The Windows target is intentionally unpatched (RTM build, zero cumulative updates) to provide a realistic, exploitable attack surface for lab purposes. This is a fully isolated lab environment — no activity in this project touched any network or system outside the two VMs described above.

## Architecture

```
┌─────────────────────┐         NAT Network          ┌──────────────────────┐
│   Parrot OS (VM)     │◄─────────10.10.1.0/24───────►│  Windows 10 Pro (VM)  │
│   10.10.1.3          │                               │  10.10.1.7            │
│                       │                               │  Build 17763.1        │
│  - Nmap               │        Attack Traffic         │                       │
│  - Wireshark          │───────────────────────────►  │  - Sysmon             │
│  - Hydra              │                               │    (SwiftOnSecurity   │
│  - netexec            │                               │     config)           │
│                       │                               │  - Advanced Audit     │
│                       │                               │    Policy             │
│                       │                               │  - Windows Security   │
│                       │                               │    Event Log          │
└─────────────────────┘                               └──────────────────────┘
```

See [`architecture/`](./architecture) for the detailed network and detection-stack diagram.

## Detection Stack

A SIEM platform (Wazuh) was evaluated for this lab but **not deployed**, due to hardware constraints (2.4GB allocated VM RAM — below Wazuh's minimum recommended footprint for its indexer/dashboard components). Instead, native Windows telemetry was used:

- **Windows Advanced Audit Policy** — Logon/Logoff, Account Lockout, and Special Logon auditing enabled (Success + Failure) prior to attack simulation
- **Sysmon** (Microsoft Sysinternals) — installed with the industry-standard [SwiftOnSecurity configuration](https://github.com/SwiftOnSecurity/sysmon-config), providing process creation (Event ID 1), and other high-fidelity telemetry
- **Windows Security Event Log** — native logon/logoff auditing (Event IDs 4624, 4625)

This reflects a real-world constraint faced by resource-limited security teams and small SOC environments that rely on native OS telemetry rather than a full SIEM stack.

## Attack Narrative

The simulated attack followed a realistic chain, each stage detected and evidenced independently:

1. **Reconnaissance** — Full port scan and service enumeration via Nmap identified SMB (445) exposed with signing disabled and guest authentication accepted.
2. **Credential Access** — Hydra performed a dictionary-based brute-force attack against a local account (`svc_test`) over SMB, succeeding after 6 failed attempts.
3. **Privilege Escalation** *(simulated misconfiguration)* — The compromised account was granted local Administrator rights to model a common real-world finding: over-privileged service accounts.
4. **Execution & Discovery** — Using the compromised, now-privileged account, commands were executed remotely via WMI (`wmiexec`-style), and local accounts were enumerated for further targeting.
5. **Detection & Investigation** — All of the above was independently confirmed via Windows Security Event Log (4625/4624) and Sysmon (Event ID 1) telemetry, demonstrating full detection coverage of the attack chain.

Full timeline below; full technical writeups in [`incident-reports/`](./incident-reports).

## Incident Timeline

| Time (IST) | Event | MITRE ATT&CK |
|---|---|---|
| 10:41–10:44 | Full Nmap port scan (all 65,535 ports) against 10.10.1.7 | T1046 |
| 10:45 | NSE script scan reveals SMB signing disabled, guest auth accepted | T1046, T1592 |
| 10:48 | Wireshark capture of SYN scan traffic | — |
| 11:29:02–11:29:03 | Hydra brute force: 6 failed + 1 successful SMB login (`svc_test`) | T1110, T1078 |
| ~11:35 | `svc_test` added to local Administrators (simulated misconfiguration) | T1078 |
| 11:58:08 | Remote command execution: `whoami` via wmiexec | T1047, T1059 |
| 11:59:54 | Remote command execution: `whoami /all` via wmiexec | T1047, T1059, T1082 |
| 12:00–12:06 | Unrelated scheduled task (`CleanUp.ps1`) investigated during log review — confirmed benign | T1053.005 (ruled out) |
| 12:02:30 | Remote command execution: `net user` via wmiexec | T1047, T1087.001 |

## Incident Reports

| # | Incident | Severity | MITRE ATT&CK |
|---|---|---|---|
| 1 | [Network Reconnaissance & Service Enumeration](./incident-reports/incident-01-network-reconnaissance.md) | Low | T1046 |
| 2 | [SMB Brute Force — Successful Credential Compromise](./incident-reports/incident-02-smb-brute-force.md) | High | T1110, T1078 |
| 3 | [Privilege Escalation & Remote Command Execution via WMI](./incident-reports/incident-03-privilege-escalation-remote-execution.md) | Critical | T1047, T1059, T1082, T1087.001 |
| 4 | [Anomalous Scheduled Task Investigation (Benign)](./incident-reports/incident-05-anomalous-scheduled-task-investigation.md) | Informational | T1053.005 |

## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IP | `10.10.1.3` |
| Target IP | `10.10.1.7` |
| Compromised Account | `svc_test` |
| Cracked Credential | `Password123` |
| Malicious Process Pattern | `cmd.exe /Q /c [cmd] 1> \Windows\Temp\[random].tmp 2>&1` |
| Suspicious Parent Process | `WmiPrvSE.exe` spawning `cmd.exe` |

Full IOC table with hashes in [`attack-analysis/`](./attack-analysis).

## Key Findings & Remediation

| Finding | Remediation |
|---|---|
| Weak password on `svc_test` account | Enforce strong password policy; disable/rotate unused service accounts |
| No account lockout policy | Enable lockout after 5 failed attempts |
| SMB signing disabled | Enforce via `Set-SmbServerConfiguration -RequireSecuritySignature $true` |
| SMBv1 enabled | Disable via `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol` |
| NTLMv1 in use | Set LAN Manager auth level to NTLMv2-only via Group Policy |
| Over-privileged service account | Apply least-privilege principle; audit local group membership regularly |
| Unrestricted WMI access | Restrict WMI/DCOM via host firewall rules from untrusted network segments |

Full remediation detail in [`remediation/`](./remediation).

## Detection Rules

Sysmon and Windows Event Log-based detection logic developed during this investigation is documented in [`detection-rules/`](./detection-rules), including:
- Brute-force detection (5+ Event ID 4625 + 1 Event ID 4624, same source/account, short window)
- WMI-based lateral movement detection (`WmiPrvSE.exe` → `cmd.exe`/`powershell.exe` parent-child relationship)

## Repository Structure

```
windows-attack-detection-lab/
├── README.md                  # This file
├── architecture/               # Network & detection architecture diagrams
├── screenshots/                 # Evidence screenshots, organized by incident
├── incident-reports/            # Full technical writeup per incident
├── detection-rules/             # Sysmon/Event Log detection logic
├── attack-analysis/             # Consolidated IOC tables, attack chain analysis
└── remediation/                 # Remediation guidance and hardening steps
```

## Reproducing This Lab

1. Set up two VMs (Linux attacker + Windows 10 target) on an isolated VirtualBox NAT Network.
2. On Windows: enable Advanced Audit Policy (`auditpol /set /subcategory:"Logon" /success:enable /failure:enable`, plus Account Lockout and Special Logon) and install Sysmon with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config).
3. Create a test account with a deliberately weak password (`net user svc_test Password123 /add`).
4. From the attacker VM, run Nmap recon (`nmap -sS -sV -O -p- <target>`), then Hydra against SMB (`hydra -l svc_test -P <wordlist> <target> smb`).
5. Escalate the test account's privileges (`net localgroup Administrators svc_test /add`) to simulate a misconfigured service account, then use `netexec`/`nxc` to execute remote commands (`nxc smb <target> -u svc_test -p <password> -x "whoami"`).
6. Investigate using `Get-WinEvent` against the Security log (Event IDs 4624/4625) and the Sysmon Operational log (Event ID 1), correlating timestamps, source IPs, and process chains.

Full step-by-step commands with expected output are in each [incident report](./incident-reports).

## Tools Used

Nmap · Wireshark · Hydra · netexec (nxc) · Sysmon · Windows Advanced Audit Policy · PowerShell / Get-WinEvent

## Disclaimer

This project was conducted entirely within an isolated, self-owned lab environment (VirtualBox NAT Network) against systems owned and controlled by the author. No external networks, third-party systems, or production environments were accessed or affected at any point.
