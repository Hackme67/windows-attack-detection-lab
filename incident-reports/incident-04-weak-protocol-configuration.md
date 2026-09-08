# Incident #4: Weak SMB Protocol Configuration (SMBv1 Enabled, NTLMv1 in Use)

## Summary
Independent confirmation across two tools (Nmap NSE and netexec) identified that the target host has legacy, high-risk protocol configurations enabled: SMBv1 (associated with EternalBlue/WannaCry-class exploits) and NTLMv1 authentication (deprecated, cryptographically weak). While not directly exploited in this lab, these findings represent significant latent risk and are documented as a standalone configuration-based finding.

## Details

| Field | Value |
|---|---|
| **Source (Detection)** | 10.10.1.3 (via Nmap NSE and netexec scans) |
| **Affected Host** | 10.10.1.7 |
| **Timestamp Identified** | 2026-09-08, 10:45 IST (Nmap) and 11:29 IST (netexec, corroborated) |
| **Severity** | Medium-High (latent risk — no exploitation performed in this lab, but well-documented CVE exposure if left unpatched, e.g., MS17-010/EternalBlue class vulnerabilities) |
| **MITRE ATT&CK Technique** | T1210 – Exploitation of Remote Services (enabled by SMBv1); T1557 – Adversary-in-the-Middle (enabled by disabled SMB signing + NTLMv1) |

## What Happened
Two independent tools confirmed the same set of weak configurations:
- **Nmap NSE (`smb-security-mode`)**: SMB message signing disabled ("dangerous, but default")
- **netexec SMB banner**: `signing:False`, `SMBv1:True`
- **Windows Security Log (Event ID 4624, Incident #2)**: Authentication Package `NTLM`, Package Name `NTLM V1` used during the successful brute-force login

Additionally, Windows Task Scheduler was found to contain built-in tasks (`UninstallSMB1ClientTask`, `UninstallSMB1ServerTask`) designed to auto-remove SMBv1 after 15 days of disuse — indicating SMBv1 has been actively used or recently enabled on this host, preventing automatic remediation.

## Evidence
- `nmap_scripts_scan.txt` — `smb-security-mode` and `smb2-security-mode` script output
- netexec banner output: `(name:CLIENT) (domain:Client) (signing:False) (SMBv1:True)`
- Windows Event ID 4624 detail showing `Package Name (NTLM only): NTLM V1`
- Scheduled Task listing showing SMBv1 removal tasks present but not yet triggered

## Investigation Steps
1. Cross-referenced SMB configuration findings between two independent tools (Nmap, netexec) for confidence.
2. Confirmed the practical impact by observing NTLMv1 actually being used during a real authentication event (Incident #2).
3. Checked Task Scheduler for the built-in SMBv1 auto-removal tasks to determine why SMBv1 remains active.

## Detection
- Periodic configuration scanning (Nmap NSE `smb-security-mode`/`smb2-security-mode`, or PowerShell `Get-SmbServerConfiguration`) should be run on a schedule to catch protocol drift.
- Monitor Event ID 4624 `Package Name (NTLM only)` field for `NTLM V1` occurrences — each one represents a live use of the weak protocol and should be investigated/inventoried.

## Recommended Response
- **Disable SMBv1** entirely: `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`
- **Enforce SMB signing**: Set `RequireSecuritySignature` via Group Policy or `Set-SmbServerConfiguration -RequireSecuritySignature $true`
- **Disable NTLMv1**: Set `Network security: LAN Manager authentication level` to "Send NTLMv2 response only, refuse LM & NTLM" via Group Policy or registry (`LmCompatibilityLevel = 5`)
- Re-scan post-remediation to confirm `signing:True` and `SMBv1:False` in future assessments.
