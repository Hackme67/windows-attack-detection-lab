# Incident #2: SMB Brute Force Attack — Successful Credential Compromise

## Summary
Following reconnaissance, the attacker launched a dictionary-based brute-force attack against SMB authentication (port 445) targeting a local account (`svc_test`). Six failed login attempts were followed immediately by a successful authentication, fully captured in Windows Security Event Logs.

## Details

| Field | Value |
|---|---|
| **Source IP** | 10.10.1.3 |
| **Destination IP** | 10.10.1.7 (SMB / port 445) |
| **Target Account** | svc_test (local account, domain: CLIENT) |
| **Timestamp** | 2026-09-08, 11:29:02–11:29:03 IST |
| **Severity** | High — successful unauthorized authentication |
| **MITRE ATT&CK Technique** | T1110 – Brute Force; T1110.001 – Password Guessing; T1078 – Valid Accounts |

## What Happened
Using Hydra, the attacker ran a 7-password dictionary attack against the `svc_test` account over SMB. The tool completed the full attack in under 2 seconds, trying all 7 candidate passwords sequentially. The 7th password attempted (`Password123`) succeeded.

Windows Security Log captured this precisely:
- **6× Event ID 4625** (failed logon) — Status `0xC000006D`, Sub Status `0xC000006A` ("Unknown user name or bad password"), Logon Type 3 (Network), Source Network Address `10.10.1.3`
- **1× Event ID 4624** (successful logon) — Logon Type 3, Authentication Package: NTLM, Package Name: **NTLM V1** (deprecated/weak protocol version), Source Network Address `10.10.1.3`

All 8 events (6 failures + 1 success, plus a redundant capture) were correlated by identical source IP, target account name, and a timestamp window of under 2 seconds — a strong high-confidence brute-force signature.

## Evidence
- Hydra terminal output showing all 7 attempts and the final successful credential line: `[445][smb] host: 10.10.1.7 login: svc_test password: Password123`
- Windows Security Event Log export: Event ID 4625 (×6) and Event ID 4624 (×1), full detail view
- `bruteforce_capture.pcapng` — Wireshark capture of the SMB authentication traffic during the attack

**Screenshots:**
| File | Description |
|---|---|
| `screenshots/incident02_hydra_bruteforce_output.png` | Hydra full output: 7 attempts tried, `Password123` confirmed valid |
| `screenshots/incident02_wireshark_bruteforce_traffic.png` | Live Wireshark capture showing repeated SMB Session Setup requests with `STATUS_LOGON_FAILURE`, then success |
| `screenshots/incident02_event4625_failedlogon.png` | Event ID 4625 full detail — failed logon, Status 0xC000006D/Sub Status 0xC000006A |
| `screenshots/incident02_event4624_successlogon.png` | Event ID 4624 full detail — successful logon, Logon Type 3, NTLM V1, source 10.10.1.3 |
| `screenshots/incident02_event4625_count_verification.png` | PowerShell count query confirming all 6 failed attempts were logged with zero gaps |

## Investigation Steps
1. Queried Windows Security Log for Event ID 4625 within the suspected time window: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=...; EndTime=...}`
2. Identified 6 failed logon attempts, all from `10.10.1.3`, all targeting `svc_test`, all within the same second.
3. Queried Event ID 4624 for the same window and found a single successful logon immediately following the failures, same source IP and account.
4. Verified failure count matched Hydra's exact wordlist size (6 failures out of 7 total attempts = 1 success), confirming no gaps in logging.
5. Noted the use of NTLM V1 authentication — a known-weak, deprecated protocol — as a contributing risk factor.

## Detection
- **Primary detection rule:** Multiple Event ID 4625 events (5+) for the same target account from the same source IP within a short window (e.g., under 60 seconds), followed by an Event ID 4624 from the same source — this pattern has near-zero false positive rate for genuine brute-force activity.
- Logon Type 3 (Network) combined with NTLM V1 authentication package is itself a lower-priority but useful secondary signal, since NTLM V1 is deprecated and its use may indicate legacy/misconfigured systems or relay-style attacks.

## Recommended Response
- **Immediate:** Disable or reset the `svc_test` account; investigate why it had a weak, dictionary-guessable password.
- **Account lockout policy:** Enable account lockout after a small number of failed attempts (e.g., 5) to prevent rapid dictionary attacks from succeeding within seconds.
- **Disable NTLM v1** domain/system-wide in favor of NTLMv2 or Kerberos, via Group Policy (`Network security: LAN Manager authentication level`).
- **Enable SMB signing** (identified as disabled in Incident #1) to reduce the impact of credential-based attacks by preventing relay/tampering.
- Implement a SIEM/log-forwarding solution with an alert rule for the failed→success brute-force pattern described above.
