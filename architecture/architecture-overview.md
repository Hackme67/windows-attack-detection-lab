# Lab Architecture

## Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                     VirtualBox NAT Network                        │
│                        10.10.1.0/24                                │
│                                                                     │
│   ┌───────────────────────┐          ┌───────────────────────┐  │
│   │   Parrot OS (Attacker)  │          │  Windows 10 Pro (Target)│  │
│   │   10.10.1.3              │          │  10.10.1.7               │  │
│   │                          │          │  Build 17763.1 (1809)    │  │
│   │  Tools:                 │  Attack  │                         │  │
│   │  - Nmap 7.92             │  Traffic │  Exposed Services:      │  │
│   │  - Wireshark              │─────────►│  - 135/tcp (msrpc)      │  │
│   │  - Hydra 9.1               │          │  - 139/tcp (netbios)    │  │
│   │  - netexec (nxc) 1.3.0     │          │  - 445/tcp (SMB)        │  │
│   │                          │          │                         │  │
│   └───────────────────────┘          │  Detection Stack:       │  │
│                                        │  - Sysmon 15.21          │  │
│                                        │    (SwiftOnSecurity cfg) │  │
│                                        │  - Advanced Audit Policy │  │
│                                        │  - Security Event Log    │  │
│                                        └───────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ (host-only, no external LAN exposure)
                                ▼
                     ┌─────────────────────┐
                     │   Windows Host         │
                     │   (Hypervisor: Oracle    │
                     │    VirtualBox)           │
                     └─────────────────────┘
```

## Detection Data Flow

```
Attacker Action (Parrot)          Windows Telemetry Source           Event Captured
─────────────────────────         ──────────────────────────         ──────────────────
Nmap port scan            ───►    Network traffic (Wireshark)   ───► SYN/RST packet pattern
Hydra SMB brute force      ───►    Security Event Log             ───► Event ID 4625 (fail) x6
                                                                        Event ID 4624 (success) x1
netexec remote command      ───►    Sysmon Operational Log          ───► Event ID 1 (Process Create)
  execution (wmiexec)                                                    WmiPrvSE.exe → cmd.exe chain
```

## Why No SIEM (Wazuh) Was Deployed

Wazuh was evaluated as the detection platform for this lab. The all-in-one single-node installation (manager + indexer + dashboard) has a documented minimum requirement of ~4GB RAM. The Parrot OS VM in this lab was allocated 2.4GB, with the host machine having only ~8GB total RAM shared across host OS, Windows VM, and Parrot VM — insufficient headroom to increase the allocation without destabilizing the lab.

Rather than force an unstable SIEM deployment, native Windows telemetry (Advanced Audit Policy + Sysmon) was used instead — a legitimate, real-world approach used by smaller security teams and resource-constrained environments. This decision and its trade-offs are documented as part of the project's engineering process, not hidden.

## Design Principles

- **Isolation first:** All attack traffic confined to an isolated VirtualBox NAT Network, never touching the host's real LAN.
- **Log before you leap:** Audit policy and Sysmon were configured and verified *before* any attack simulation, ensuring no telemetry gaps.
- **Independent verification:** Key findings (e.g., SMB signing disabled, SMBv1 enabled) were confirmed via two independent tools (Nmap NSE and netexec) rather than trusting a single source.
- **Evidence-driven:** Every incident report is backed by actual captured screenshots, log exports, and packet captures — no fabricated or assumed data.
