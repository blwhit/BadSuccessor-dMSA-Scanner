# BadSuccessor dMSA Scanner
<br>

**A PowerShell tool to detect BadSuccessor attack paths in Active Directory**

<br>

## ⚠️ About BadSuccessor


BadSuccessor is a critical privilege escalation vulnerability in Active Directory that allows attackers with dMSA creation or modification rights to impersonate ANY Active Directory user account.

<br>

### Details:
- Affects Windows Server 2025 environments only
- Currently has no available patch
- Enables takeover and credential theft of ANY AD user account (e.g. Domain Admins)
- Requires privilege to create/modify dMSA object

<br>

### BadSuccessor TLDR;
1. Attacker creates/modifies a dMSA account
2. Sets two attributes to "link" it to a target/victim user (e.g., Domain Admin)
3. Authenticates as the dMSA and gains _all target user's privileges_

<br>

###### *Credit to [Akamai Security Research Team](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)*

<br>

## 🔍 What This Scanner Finds

This tool identifies who can exploit BadSuccessor by checking:

- **Direct dMSA Permissions**: Accounts with explicit rights to create/modify dMSAs
- **Group-Based Permissions**: Users who inherit dMSA rights through group membership (including nested groups)
- **OU-Level Creation Rights**: Permissions allowing dMSA creation in organizational units
- **Existing dMSA Modification Rights**: Write access to current dMSA objects
- **Environment Assessment**: Windows Server 2025 domain controller detection

<br>

## 🚀 Quick Start

```powershell
# Scan entire domain (recommended)
.\BadSuccessor-dMSA-Scanner.ps1

# Check specific user
.\BadSuccessor-dMSA-Scanner.ps1 -User jdoe

# Export to CSV
.\BadSuccessor-dMSA-Scanner.ps1 -CSV

# Fast scan (skip groups)
.\BadSuccessor-dMSA-Scanner.ps1 -SkipGroups
```
<br>

## 📋 Options

| Option | Description |
|--------|-------------|
| `-User <name>` | Check specific user |
| `-All` | Scan all users (default) |
| `-CSV` | Export results to file |
| `-SkipGroups` | Skip group analysis (faster) |
| `-h` | Show help |

<br>

## 📊 Sample Output

```
[ BadSuccessor dMSA Attack Path Scanner ]

Checking domain environment...
[!] CRITICAL: Found 2 Windows Server 2025 domain controller(s)
[!] BadSuccessor exploitation is POSSIBLE in this environment

[*] Found 156 OUs and 0 existing dMSA objects to audit

Scanning for BadSuccessor attack paths...

[!] ATTACK PATH DETECTED
    Object: OU=ServiceAccounts,DC=contoso,DC=com
    Principal: CONTOSO\ServiceDesk
    Permissions: CreateChild, GenericWrite
    Risk: Create new dMSA

[ BADSUCCESSOR VULNERABILITY SUMMARY ]

[!] ATTACK PATHS FOUND: 3
    Direct Permissions: 2
    Group Memberships: 1
    OU Creation Risks: 3

[*] PRINCIPALS WITH BADSUCCESSOR CAPABILITY:
    - CONTOSO\john.doe
    - CONTOSO\ServiceDesk

[*] Results exported to: BadSuccessor_dMSA_Audit_20250812_143022.csv
```
<br>

## 🛡️ Requirements

- Active Directory PowerShell module (RSAT)
- Read access to Active Directory Domain

<br>

## 🔗 References

- [Akamai BadSuccessor Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Tarlogic Analysis](https://www.tarlogic.com/blog/badsuccessor/)
- [Unit42 Deep Dive](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)

---
