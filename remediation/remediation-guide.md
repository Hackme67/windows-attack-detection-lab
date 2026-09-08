# Remediation Guide

Consolidated hardening steps addressing every finding from this investigation, in priority order.

## Priority 1 — Critical (Address Immediately)

### 1. Disable/reset the compromised account
```powershell
# Disable immediately pending investigation
Disable-LocalUser -Name "svc_test"

# Or, if the account must remain active, reset with a strong password:
net user svc_test <StrongRandomPassword> 
```

### 2. Remove excessive privileges
```powershell
net localgroup Administrators svc_test /remove
```
**General practice:** Audit all local accounts for group membership regularly. Service/utility accounts should run with the minimum privilege required for their function — never local Administrator unless explicitly justified and documented.
```powershell
net localgroup Administrators
```

## Priority 2 — High (Address This Week)

### 3. Enforce SMB signing
```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```
Confirm:
```powershell
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
```

### 4. Disable SMBv1
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
```

### 5. Disable NTLMv1
Via Group Policy (`Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`):
- **Network security: LAN Manager authentication level** → "Send NTLMv2 response only, refuse LM & NTLM"

Or via registry:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
```

### 6. Implement account lockout policy
```powershell
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```
Locks an account after 5 failed attempts within a 15-minute window, for 15 minutes — sufficient to stop rapid dictionary attacks like the one demonstrated in Incident #2 without unduly impacting legitimate users.

## Priority 3 — Medium (Ongoing Hardening)

### 7. Restrict WMI/DCOM access via firewall
```powershell
# Example: restrict WMI to a specific management subnet only
New-NetFirewallRule -DisplayName "Restrict WMI-In" -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress <TrustedManagementSubnet> -Action Allow
New-NetFirewallRule -DisplayName "Block WMI-In Default" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block
```

### 8. Enable Windows Firewall logging (for future scan/recon detection)
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
```

### 9. Deploy the developed detection rules
See [`detection-rules/`](../detection-rules) for the brute-force and WMI lateral-movement detection logic developed during this investigation — deploy these as scheduled queries or SIEM correlation rules in production environments.

## Priority 4 — Process / Hygiene

### 10. Least-privilege for scheduled tasks
The `CleanUp` scheduled task (Incident #5) runs as SYSTEM when it only requires file-delete permission on one folder. Reconfigure to run under a dedicated low-privilege service account:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec bypass -nop C:\DevTools\CleanUp.ps1"
$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc_cleanup" -LogonType Password -RunLevel Limited
Set-ScheduledTask -TaskName "CleanUp" -Action $action -Principal $principal
```

### 11. Maintain a scheduled task inventory
Document owner, purpose, and required privilege level for all custom scheduled tasks to speed up future SOC triage and avoid repeated investigation of the same benign activity.

## Verification Checklist

After applying remediations, re-run the original assessment tools to confirm fixes:

```bash
# From attacker host - confirm SMB hardening
nmap -sC -sV -p 445 <target>
nxc smb <target>
```
Expected result post-remediation: `signing:True`, `SMBv1:False`

```powershell
# On target - confirm lockout policy
net accounts

# Confirm no unexpected local admins
net localgroup Administrators
```
