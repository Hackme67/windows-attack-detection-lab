# Windows Endpoint Attack Detection & Incident Investigation Lab

A hands-on **SOC and blue-team lab** demonstrating Windows endpoint attack detection, security-event analysis, incident investigation, IOC identification, MITRE ATT&CK mapping, and security remediation.

The project simulates an authorized attack against an isolated Windows 10 virtual machine from a Parrot OS attacker VM. The investigation combines **Windows Security Event Logs, Sysmon telemetry, network analysis, and process-level evidence** to reconstruct the attack timeline and identify security weaknesses.

---

## 🎯 Objective

The objective of this lab was to simulate and investigate a multi-stage attack against a Windows endpoint from the perspective of a SOC analyst.

The investigation covered:

* Network reconnaissance and service enumeration
* SMB authentication attacks
* Credential compromise
* Over-privileged account investigation
* WMI-based remote command execution
* Windows Security Event Log analysis
* Sysmon process telemetry analysis
* IOC identification
* Attack timeline reconstruction
* MITRE ATT&CK technique mapping
* Detection logic development
* Security remediation and hardening

---

## 🏗️ Lab Environment

| Component     | Details                         |
| ------------- | ------------------------------- |
| Attacker      | Parrot OS VM                    |
| Attacker IP   | `10.10.1.3`                     |
| Target        | Windows 10 Pro VM               |
| Target IP     | `10.10.1.7`                     |
| Windows Build | `17763.1`                       |
| Network       | Isolated VirtualBox NAT Network |
| Hypervisor    | Oracle VirtualBox               |

> **Lab Safety:** The environment was isolated and used only for authorized security testing against self-owned virtual machines. No production systems, third-party systems, or external networks were targeted.

The Windows endpoint was intentionally configured with security weaknesses to support controlled attack simulation and investigation.

---

## 🗺️ Architecture

```text
┌─────────────────────────┐
│      Parrot OS VM       │
│      Attacker Host      │
│       10.10.1.3         │
│                         │
│  • Nmap                 │
│  • Wireshark            │
│  • Hydra                │
│  • NetExec               │
└────────────┬────────────┘
             │
             │ Isolated NAT Network
             │ 10.10.1.0/24
             │
             │ Simulated Attack Traffic
             ▼
┌─────────────────────────┐
│     Windows 10 VM       │
│       10.10.1.7         │
│                         │
│  • Sysmon               │
│  • Windows Event Logs   │
│  • Advanced Audit       │
│    Policy               │
│  • PowerShell           │
└─────────────────────────┘
```

Detailed architecture diagrams are available in [`architecture/`](architecture/).

---

## 🛡️ Detection & Investigation Stack

### Windows Telemetry

**Windows Advanced Audit Policy**

Configured auditing for relevant authentication and account activity, including successful and failed logons.

**Windows Security Event Log**

Key events investigated included:

* `4624` — Successful logon
* `4625` — Failed logon

**Sysmon**

Sysmon was deployed using the [SwiftOnSecurity Sysmon configuration](https://github.com/SwiftOnSecurity/sysmon-config) to provide enhanced endpoint telemetry.

The investigation primarily used:

* `Event ID 1` — Process creation
* Parent-child process relationships
* Process command-line information

### Network Analysis

**Wireshark** was used to inspect and validate network activity associated with the simulated attack.

### SIEM Note

Wazuh was evaluated as a possible SIEM component but was not deployed because of the available lab hardware resources. The investigation therefore relied on native Windows telemetry and Sysmon.

---

## 🔎 Attack & Investigation Workflow

```text
Reconnaissance
      ↓
Service Enumeration
      ↓
SMB Authentication Attack
      ↓
Credential Compromise
      ↓
Privilege Misconfiguration
      ↓
WMI Remote Execution
      ↓
Windows/Sysmon Telemetry
      ↓
Event Correlation
      ↓
IOC Identification
      ↓
Incident Investigation
      ↓
Detection Logic
      ↓
Remediation
```

---

## 🚨 Attack Narrative

### 1. Reconnaissance

Nmap was used from the Parrot OS VM to perform network and service reconnaissance against the Windows endpoint.

The assessment identified exposed services, including SMB.

Relevant observations included:

* SMB exposed on TCP/445
* SMB signing configuration weakness
* Guest authentication configuration

**MITRE ATT&CK:** `T1046 – Network Service Scanning`

---

### 2. SMB Authentication Attack

Hydra was used in the isolated lab to perform a dictionary-based SMB authentication attack against the intentionally weak test account.

The investigation identified:

* Multiple failed authentication attempts
* A subsequent successful authentication
* The affected test account
* Source and destination IP addresses
* Authentication timestamps

Relevant Windows Security Events:

* `4625` — Failed logon
* `4624` — Successful logon

**MITRE ATT&CK:**

* `T1110 – Brute Force`
* `T1078 – Valid Accounts`

---

### 3. Privilege Misconfiguration

The compromised test account was intentionally placed in the local Administrators group to simulate an **over-privileged service account**.

This was a controlled lab configuration used to demonstrate the security impact of excessive privileges.

The investigation evaluated:

* Account privileges
* Local group membership
* Potential impact of credential compromise
* Least-privilege violations

---

### 4. WMI-Based Remote Command Execution

The compromised account was subsequently used to execute commands remotely through WMI.

Commands investigated included:

```text
whoami
whoami /all
net user
```

Sysmon process telemetry was used to investigate suspicious process relationships involving:

```text
WmiPrvSE.exe
      ↓
cmd.exe
```

**MITRE ATT&CK:**

* `T1047 – Windows Management Instrumentation`
* `T1059 – Command and Scripting Interpreter`
* `T1087.001 – Account Discovery: Local Account`

---

## 📅 Incident Timeline

| Time              | Activity                                                                  | ATT&CK                |
| ----------------- | ------------------------------------------------------------------------- | --------------------- |
| 10:41–10:44       | Full Nmap port scan against Windows endpoint                              | T1046                 |
| 10:45             | SMB configuration enumeration                                             | T1046                 |
| 10:48             | Wireshark analysis of reconnaissance traffic                              | —                     |
| 11:29:02–11:29:03 | SMB authentication attack: 6 failed attempts followed by successful login | T1110, T1078          |
| ~11:35            | Test account configured with local Administrator privileges               | Lab configuration     |
| 11:58:08          | Remote `whoami` execution through WMI                                     | T1047, T1059          |
| 11:59:54          | Remote `whoami /all` execution through WMI                                | T1047, T1059          |
| 12:00–12:06       | Scheduled task reviewed and determined to be benign                       | T1053.005 — ruled out |
| 12:02:30          | Remote `net user` execution through WMI                                   | T1047, T1087.001      |

---

## 🔬 Incident Reports

Detailed investigation reports are available in [`incident-reports/`](incident-reports/).

| Incident                                     | Severity      | Techniques              |
| -------------------------------------------- | ------------- | ----------------------- |
| Network Reconnaissance & Service Enumeration | Low           | T1046                   |
| SMB Brute Force & Credential Compromise      | High          | T1110, T1078            |
| WMI Remote Command Execution                 | Critical      | T1047, T1059, T1087.001 |
| Weak SMB Protocol Configuration              | Medium–High   | Configuration weakness  |
| Benign Scheduled Task Investigation          | Informational | T1053.005               |

Each report contains investigation evidence, observations, analysis, and recommended remediation.

---

## 🧪 What I Demonstrated

* Investigated Windows authentication activity using Event IDs `4624` and `4625`
* Used Sysmon telemetry for endpoint process investigation
* Analyzed parent-child process relationships
* Investigated WMI-based remote command execution
* Correlated timestamps, accounts, source IPs, and process activity
* Reconstructed a multi-stage attack timeline
* Identified indicators of compromise
* Mapped observed activity to MITRE ATT&CK
* Developed basic detection logic for suspicious authentication activity
* Investigated potentially suspicious activity and determined when an event was benign
* Documented security findings and remediation recommendations

---

## 🧠 Detection Logic

Detection logic developed during the investigation is documented in [`detection-rules/`](detection-rules/).

### SMB Brute-Force Detection

A basic correlation approach was developed around:

```text
Multiple Event ID 4625
        +
Same source/account
        +
Short time window
        +
Followed by Event ID 4624
```

This can indicate a potential brute-force attack followed by successful credential compromise.

### WMI Process Detection

The investigation also examined suspicious process relationships such as:

```text
WmiPrvSE.exe
      ↓
cmd.exe / powershell.exe
```

Such parent-child relationships can provide useful detection opportunities when investigating WMI-based remote execution.

---

## 🔐 Indicators of Compromise

| IOC Type            | Value                             |
| ------------------- | --------------------------------- |
| Attacker IP         | `10.10.1.3`                       |
| Target IP           | `10.10.1.7`                       |
| Compromised Account | `svc_test`                        |
| Credential          | Intentionally weak lab credential |
| Suspicious Process  | `cmd.exe`                         |
| Parent Process      | `WmiPrvSE.exe`                    |

Additional IOC analysis and investigation artifacts are available in [`attack-analysis/`](attack-analysis/).

> Credentials used in this project were created exclusively for the isolated laboratory environment and are not production credentials.

---

## 🛠️ Security Findings & Remediation

| Finding                         | Recommended Remediation                                                 |
| ------------------------------- | ----------------------------------------------------------------------- |
| Weak test account password      | Enforce strong password policies and rotate/remove unnecessary accounts |
| No account lockout policy       | Implement appropriate account lockout and authentication controls       |
| SMB signing disabled            | Require SMB signing where appropriate                                   |
| SMBv1 enabled                   | Disable SMBv1 on supported systems                                      |
| Legacy NTLM configuration       | Prefer modern authentication and restrict legacy protocols              |
| Over-privileged service account | Apply least privilege and regularly review group membership             |
| Broad WMI access                | Restrict WMI/DCOM access using appropriate firewall and access controls |

Detailed hardening guidance is available in [`remediation/`](remediation/).

---

## 📂 Repository Structure

```text
Windows-Attack-Detection-Incident-Investigation-Lab/
│
├── README.md
│
├── architecture/
│   └── Network and detection architecture diagrams
│
├── screenshots/
│   └── Investigation evidence
│
├── incident-reports/
│   └── Detailed incident investigation reports
│
├── detection-rules/
│   └── Detection logic and investigation queries
│
├── attack-analysis/
│   └── IOC and attack-chain analysis
│
└── remediation/
    └── Security hardening recommendations
```

---

## 🔁 Reproducing the Lab

This project can be reproduced in an isolated virtual environment.

### 1. Build the Lab

Create:

* One Parrot OS attacker VM
* One Windows 10 target VM
* One isolated VirtualBox NAT Network

### 2. Configure Windows Telemetry

Enable relevant Windows auditing and install Sysmon using the selected Sysmon configuration.

Example:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Configure additional audit categories as required by the investigation.

### 3. Create a Test Account

Create a dedicated test account with a deliberately weak password **only inside the isolated lab**.

Do not reuse laboratory credentials on real systems.

### 4. Perform Controlled Reconnaissance

From the attacker VM, perform service discovery against the laboratory Windows endpoint.

Example:

```bash
nmap -sS -sV -O -p- <target>
```

### 5. Simulate Authentication Attacks

Use the controlled lab account and authorized wordlist to simulate SMB authentication attempts.

### 6. Simulate Privilege Misconfiguration

Configure the test account with elevated local privileges to model an over-privileged service account.

### 7. Simulate Remote Execution

Use the compromised test account to execute controlled commands through WMI.

### 8. Investigate the Endpoint

Review Windows Security Event Logs and Sysmon telemetry.

Example:

```powershell
Get-WinEvent -LogName Security
```

Correlate:

* Timestamp
* Username
* Source IP
* Authentication result
* Process creation
* Parent process
* Command line
* Attack stage

Detailed commands and expected results are documented within the individual incident reports.

---

## 🧰 Tools & Technologies

**SOC / Detection**

`Sysmon` `Windows Event Logs` `Windows Advanced Audit Policy` `PowerShell` `Get-WinEvent`

**Network Security**

`Nmap` `Wireshark` `TCP/IP` `SMB`

**Offensive Security**

`Hydra` `NetExec (nxc)` `WMI`

**Frameworks**

`MITRE ATT&CK`

**Lab Environment**

`Parrot OS` `Windows 10` `Oracle VirtualBox`

---

## 📸 Evidence

Investigation screenshots and supporting evidence are available in [`screenshots/`](screenshots/).

The evidence demonstrates:

* Network reconnaissance
* Authentication failures and success
* Sysmon process creation
* WMI activity
* Investigation workflow
* Detection analysis
* Remediation validation

---

## 📚 Key Learning Outcomes

This lab strengthened practical experience in:

* SOC investigation methodology
* Windows endpoint telemetry
* Authentication event analysis
* Sysmon-based detection
* Network traffic analysis
* Attack-chain reconstruction
* IOC identification
* MITRE ATT&CK mapping
* Detection engineering fundamentals
* Incident documentation
* Security hardening

---

## ⚠️ Disclaimer

This project was conducted entirely within an **authorized, isolated laboratory environment** using self-owned virtual machines and intentionally configured security weaknesses.

No production systems, third-party systems, or unauthorized networks were accessed.

The techniques and commands documented in this repository are provided for **educational, defensive-security, and authorized testing purposes only**.

---

## 👤 Author

**Vijay Bhaskar S**

Cybersecurity | SOC | Penetration Testing | Ethical Hacking

GitHub: [Hackme67](https://github.com/Hackme67)

LinkedIn: [Vijay Bhaskar S](https://www.linkedin.com/in/vijay-bhaskar-s-03b6b9287/)
