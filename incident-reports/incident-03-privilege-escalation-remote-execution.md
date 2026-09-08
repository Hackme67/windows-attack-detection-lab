# Incident #3: Privilege Escalation & Remote Command Execution via WMI

## Summary
The compromised `svc_test` account was granted local Administrator rights (simulating a common real-world misconfiguration: an over-privileged service account) and subsequently used to execute commands remotely on the target via WMI (Windows Management Instrumentation), a documented "living-off-the-land" technique. Sysmon captured full process-level telemetry of this activity.

## Details

| Field | Value |
|---|---|
| **Source IP** | 10.10.1.3 |
| **Destination IP** | 10.10.1.7 |
| **Compromised Account** | CLIENT\svc_test (local Administrator) |
| **Timestamp** | 2026-09-08, 11:58:08–12:02:30 IST |
| **Severity** | Critical — remote code execution with administrative privileges |
| **MITRE ATT&CK Technique** | T1078 – Valid Accounts (privilege misuse); T1047 – Windows Management Instrumentation; T1059 – Command and Scripting Interpreter; T1082 – System Information Discovery; T1087.001 – Local Account Discovery |

## Lab Note on Methodology
For demonstration purposes, `svc_test` was manually added to the local Administrators group to simulate a common real-world misconfiguration — over-privileged service/local accounts are a frequent finding in real security assessments. This step enabled analysis of post-exploitation command execution and Sysmon detection telemetry, which is the primary technical objective of this incident.

## What Happened
Using `netexec` (nxc), the attacker authenticated with the cracked `svc_test` credentials and executed three commands remotely via WMI:

1. `whoami` — confirmed code execution and identity (11:58:08)
2. `whoami /all` — enumerated full privilege/group membership, revealing high-value privileges including `SeDebugPrivilege` and `SeImpersonatePrivilege` (11:59:54)
3. `net user` — enumerated all local accounts on the host for potential further targeting (12:02:30)

Each command followed the same execution pattern, visible in Sysmon Event ID 1 (Process Creation):
```
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
ParentUser:  NT AUTHORITY\NETWORK SERVICE
Image:       C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /Q /c <command> 1> \Windows\Temp\<random>.tmp 2>&1
User:        CLIENT\svc_test
IntegrityLevel: High
```
This is the well-documented signature of `wmiexec`-style tools: WMI spawns `cmd.exe`, which redirects command output to a randomly-named temp file that is then read back over SMB to return results to the attacker — no binary is dropped to disk, making this a low-footprint execution method.

## Evidence
- netexec terminal output for all three commands, including the `(Pwn3d!)` admin-confirmation tag and `[+] Executed command via wmiexec` status lines
- Sysmon Event ID 1 log entries (×3) showing the WmiPrvSE.exe → cmd.exe process chain, full command lines, and process hashes
- `whoami /all` output showing full privilege list (SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeRestorePrivilege, and 20 total enabled privileges) and confirmed BUILTIN\Administrators group membership
- `net user` output enumerating all 8 local accounts on the host

**Screenshots:**
| File | Description |
|---|---|
| `screenshots/incident03_netexec_initial_auth.png` | Initial netexec SMB authentication check (pre-privesc), confirms signing:False, SMBv1:True |
| `screenshots/incident03_netexec_whoami_exec.png` | Successful remote command execution — `(Pwn3d!)` tag, `whoami` returns `client\svc_test` |
| `screenshots/incident03_netexec_whoamiall_usergroup.png` | `whoami /all` — user/group information, confirms BUILTIN\Administrators membership |
| `screenshots/incident03_netexec_whoamiall_privileges.png` | `whoami /all` — full privilege list including SeDebugPrivilege, SeImpersonatePrivilege |
| `screenshots/incident03_netexec_netuser_discovery.png` | `net user` — account discovery enumerating all 8 local accounts |
| **`screenshots/incident03_sysmon_wmiexec_processchain.png`** | **Key evidence** — Sysmon Event ID 1 (×3) showing WmiPrvSE.exe → cmd.exe execution chain with full command lines, hashes, and CLIENT\svc_test user context for all three commands |

## Investigation Steps
1. Queried Sysmon Operational log for Event ID 1 (Process Creation) events following the confirmed brute-force compromise timestamp.
2. Filtered for `WmiPrvSE.exe` as parent process — a known indicator of WMI-based remote execution.
3. Identified three matching events, each showing `cmd.exe` spawned by WMI, running as `CLIENT\svc_test` with High integrity level.
4. Correlated command lines and output-redirection filenames (`\Windows\Temp\<random>.tmp`) against known `wmiexec` tooling behavior.
5. Cross-referenced timestamps against attacker-side netexec output to confirm 1:1 correlation between commands issued and processes created.

## Detection
- **Primary rule:** Sysmon Event ID 1 where `ParentImage` = `C:\Windows\System32\wbem\WmiPrvSE.exe` AND `Image` = `cmd.exe` or `powershell.exe` — this parent/child relationship is a strong, low-false-positive indicator of WMI-based lateral movement/remote execution (legitimate WMI administrative activity is comparatively rare on endpoint workstations).
- **Secondary rule:** `cmd.exe` command lines matching the pattern `/Q /c .* 1> \\Windows\\Temp\\[A-Za-z]{6} 2>&1` — highly specific to `wmiexec`/Impacket-family tooling.
- Monitor for unexpected additions to the local Administrators group (Event ID 4732) as an upstream indicator that would have preceded this activity.

## Recommended Response
- **Immediate:** Remove `svc_test` from the local Administrators group; disable the account pending investigation.
- **Restrict WMI usage:** Apply Windows Firewall rules to block inbound WMI (DCOM/RPC, ports 135 + dynamic range) from untrusted network segments.
- **Enable Event ID 4732 alerting** (member added to a security-enabled local group) to catch privilege escalation attempts in near-real-time.
- **Audit all local accounts for group membership** — verify no other service/utility accounts have excessive privileges.
- **Deploy Sysmon fleet-wide** (already validated as effective in this lab) with alerting on the WmiPrvSE.exe → cmd.exe/powershell.exe pattern via a SIEM or log-forwarding pipeline.
