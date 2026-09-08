# Incident #1: Network Reconnaissance & Service Enumeration

## Summary
An external host performed comprehensive network reconnaissance against the target Windows endpoint, including host discovery, a full 65,535-port TCP scan, OS fingerprinting, and NSE (Nmap Scripting Engine) service enumeration. This activity identified critical SMB misconfigurations that were later exploited in Incident #2.

## Details

| Field | Value |
|---|---|
| **Source IP** | 10.10.1.3 (Parrot OS attacker) |
| **Destination IP** | 10.10.1.7 (Windows 10 target, hostname: CLIENT) |
| **Timestamp** | 2026-09-08, 10:41–10:45 IST |
| **Severity** | Low (recon only, no exploitation) — but critical as a precursor event |
| **MITRE ATT&CK Technique** | T1046 – Network Service Discovery; T1592 – Gather Victim Host Information |

## What Happened
1. Host discovery scan (`nmap -sn`) confirmed the target was live on the subnet.
2. A full TCP port scan (`-sS -sV -O -p-`) identified open ports: 135 (msrpc), 139 (netbios-ssn), 445 (microsoft-ds/SMB), 5040 (unknown), and a range of dynamic RPC ports (49664–49673).
3. OS fingerprinting identified the target as Windows 10 (build range 1709–1909), consistent with the actual host (build 17763).
4. An NSE default script scan (`-sC -sV`) enumerated SMB configuration in detail, revealing:
   - **SMB message signing disabled** (dangerous, but default) — enables SMB relay attacks
   - **Guest account usable for SMB authentication**
   - Full OS/hostname/workgroup disclosure via `smb-os-discovery`

## Evidence
- `nmap_full_scan.txt` — full port scan output
- `nmap_scripts_scan.txt` — NSE script scan output showing SMB signing and guest auth findings
- `nmap_recon_capture.pcapng` — Wireshark packet capture showing the SYN scan pattern (rapid SYN packets across multiple ports, met with RST/ACK responses for closed ports and a SYN-ACK on port 139)

**Screenshots:**
| File | Description |
|---|---|
| `screenshots/incident01_nmap_hostdiscovery.png` | Host discovery scan (`nmap -sn`) confirming target is live |
| `screenshots/incident01_nmap_fullportscan.png` | Full 65535-port TCP scan with OS fingerprinting |
| `screenshots/incident01_nmap_nsescriptscan.png` | NSE script scan showing SMB signing disabled, guest auth accepted |
| `screenshots/incident01_wireshark_capturestart.png` | Wireshark capture initialization on interface enp0s3 |
| `screenshots/incident01_wireshark_synscan_filtered.png` | Filtered packet view (`ip.addr == 10.10.1.7`) showing SYN/RST scan pattern, 137,290 packets captured |

## Investigation Steps
1. Reviewed Nmap scan output for open ports and identified services.
2. Cross-referenced OS fingerprint against known target configuration.
3. Analyzed Wireshark capture filtered on `ip.addr == 10.10.1.7` to visually confirm the scanning pattern (137,290 packets captured, high volume of SYN/RST pairs consistent with a full-port sweep).
4. Flagged SMB signing status and guest authentication as actionable misconfigurations for remediation.

## Detection
This activity would be detectable via:
- A high volume of SYN packets from a single source IP across many destination ports within a short time window (classic port-scan signature)
- Windows Defender Firewall logging (if enabled) recording repeated connection attempts across ports
- Network IDS/IPS signature matching on Nmap's default packet characteristics (e.g., TCP window size, TTL patterns)

## Recommended Response
- Enable Windows Firewall logging to capture inbound connection attempts for future scan detection.
- Consider network segmentation/host-based firewall rules to restrict which hosts can reach SMB (445) and RPC (135) ports.
- Treat this event as an early-warning indicator — recon frequently precedes exploitation attempts (as demonstrated in Incident #2).
