# BadSuccessor dMSA Scanner

**A PowerShell tool to detect ALL BadSuccessor attack paths in Active Directory _(including nested/group privileges)_.**

## ⚠️ About BadSuccessor

BadSuccessor is a critical privilege escalation vulnerability in Active Directory that allows attackers with dMSA creation or modification rights to impersonate ANY Active Directory user account.

### Details:
- Affects Windows Server 2025 environments only
- Currently has no available patch
- Enables takeover and credential theft of ANY AD user account (e.g. Domain Admins)
- Attack requires privilege to create/modify dMSA object

### BadSuccessor TLDR:
1. Attacker creates/modifies a dMSA account
2. Sets two attributes to "link" it to a target/victim user (e.g., Domain Admin)
3. Authenticates as the dMSA and gains *all target user's privileges*

###### *Credit to [Akamai Security Research Team](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)*

## 🔍 What This Scanner Finds

This tool identifies who can exploit BadSuccessor by checking:

- **Direct dMSA Permissions**: Accounts with explicit rights to create/modify dMSAs
- **Group-Based Permissions**: Users who inherit dMSA rights through group membership (including nested groups)
- **OU-Level Creation Rights**: Permissions allowing dMSA creation in organizational units
- **Container-Level Creation Rights**: Permissions allowing dMSA creation in containers
- **Existing dMSA Modification Rights**: Write access to current dMSA objects
- **Environment Assessment**: Windows Server 2025 domain controller detection

  ###### _NOTE: Highly privileged pricipals are automatically filtered (e.g. Domain Admins, Enterprise Admins, Domain Controllers, etc...)._

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

## 📋 Options

| Option | Description |
|--------|-------------|
| `-User <name>` | Check specific user |
| `-All` | Scan all users (default) |
| `-CSV` | Export results to file |
| `-SkipGroups` | Skip group analysis (faster) |
| `-h` | Show help |

## 📊 Sample Output

```
[ BadSuccessor dMSA Attack Path Scanner ]
[ https://github.com/blwhit/BadSuccessor-dMSA-Scanner ]

Checking domain environment...
[!] CRITICAL: Found 2 Windows Server 2025 domain controller(s)
[!] BadSuccessor exploitation is POSSIBLE in this environment

Enumerating OUs, Containers, and dMSA objects...
[*] Found 156 OUs
[*] Found 23 Containers
[*] Found 0 existing dMSA objects

Scanning for BadSuccessor attack paths...
[*] Total objects to audit: 179

[!] ATTACK PATH DETECTED
    Object: OU=ServiceAccounts,DC=contoso,DC=com
    Principal: CONTOSO\ServiceDesk
    Permissions: CreateChild, GenericWrite
    Scope: All child objects
    Exploit Type: Create new dMSA

[!] ATTACK PATH DETECTED
    Object: CN=Users,DC=contoso,DC=com
    Principal: CONTOSO\john.doe
    User: john.doe (via IT-Admins)
    Permissions: GenericAll
    Scope: All child objects
    Exploit Type: Create new dMSA

[!] ATTACK PATH DETECTED
    Object: OU=ITDepartment,DC=contoso,DC=com
    Principal: CONTOSO\BackupOperators
    Permissions: CreateChild
    Scope: dMSA objects only
    Exploit Type: Create new dMSA
.
.
.
.
.
---------------

[X] ATTACK PATHS FOUND: 3
    Direct Permissions: 2
    Group Memberships: 1
    Existing dMSA Risks: 0
    OU Creation Risks: 2
    Container Creation Risks: 1

[*] PRINCIPALS WITH BADSUCCESSOR CAPABILITY:
    - CONTOSO\BackupOperators
    - CONTOSO\john.doe
    - CONTOSO\ServiceDesk

[*] Results exported to: BadSuccessor_dMSA_Audit_20250812_143022.csv
```

## 🛡️ Requirements

- Active Directory PowerShell module (RSAT)
- Read access to Active Directory Domain

## 🔗 References

- [Akamai Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Tarlogic Research](https://www.tarlogic.com/blog/badsuccessor/)
- [Unit42 Research](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)

---
