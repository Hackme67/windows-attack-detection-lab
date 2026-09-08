# LinkedIn Post

I built a hands-on SOC investigation lab: simulated a realistic attack chain against a Windows 10 endpoint, then investigated it myself — end to end.

The setup: an isolated two-VM lab (Parrot OS as attacker, Windows 10 as target). The chain: Nmap recon → SMB brute force with Hydra → simulated privilege escalation → remote command execution via WMI. Every stage mapped to MITRE ATT&CK.

The part I actually care about sharing: I configured Windows Advanced Audit Policy and Sysmon *before* running any attack, so I had real telemetry to investigate — not just attack tooling output. Then I reconstructed the full timeline purely from Windows Security Event Logs (4624/4625) and Sysmon process-creation events, correlating source IPs, timestamps, and process chains.

One decision I'm glad I made: I originally planned to deploy Wazuh as a SIEM, but my lab hardware couldn't support it without real instability risk. Rather than force it, I documented the trade-off and used native Windows telemetry instead — which, it turns out, is exactly how a lot of resource-constrained security teams actually operate in the real world.

I also caught myself almost over-reacting to a false positive: a recurring SYSTEM-level PowerShell process that looked like it could be persistence. Traced it, read the script, confirmed it was benign log-cleanup automation — but still flagged the least-privilege issue behind it. Investigating properly instead of assuming either way felt like the most "real SOC analyst" moment of the whole project.

Full write-up, incident reports, detection rules, and evidence are on GitHub: https://github.com/Hackme67/windows-attack-detection-lab

#CyberSecurity #SOC #BlueTeam #IncidentResponse #MITREATT&CK #InfoSec
