# BadSuccessor dMSA Scanner

A PowerShell security audit tool designed to detect potential attack paths for the **BadSuccessor** vulnerability.

## About BadSuccessor

BadSuccessor is a critical privilege escalation vulnerability in Active Directory that allows attackers with dMSA creation or modification rights to impersonate ANY Active Directory user account. 

**Attack Details:**
- Affects Windows Server 2025 environments only
- Currently has **no available patch**
- Enables compromise of ANY AD user account (e.g. Domain Admins)
- Requires privilege to create/modify dMSA object

Credit to original researchers: https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory

## What This Tool Detects

This scanner identifies BadSuccessor attack vectors by auditing:

- **Direct dMSA Permissions**: Accounts with explicit rights to create/modify dMSAs
- **Group-Based Permissions**: Users who inherit dMSA rights through group membership (including nested groups)
- **OU-Level Creation Rights**: Permissions allowing dMSA creation in organizational units
- **Existing dMSA Modification Rights**: Write access to current dMSA objects
- **Environment Assessment**: Windows Server 2025 domain controller detection

## Quick Start

```powershell
# Full environment audit (recommended)
.\Audit-dMSA-Permissions.ps1

# Audit specific user
.\Audit-dMSA-Permissions.ps1 -User jdoe

# Export results to CSV
.\Audit-dMSA-Permissions.ps1 -CSV

# Fast scan (skip group analysis)
.\Audit-dMSA-Permissions.ps1 -SkipGroups
```

## Command Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-User <sAMAccountName>` | Audit specific user for dMSA exploit risk | All users |
| `-All` | Audit all users/groups with dMSA capabilities | `True` |
| `-CSV` | Export detailed results to CSV file | `False` |
| `-SkipGroups` | Skip group membership analysis for faster execution | `False` |
| `-h` | Show help message | `False` |

## Sample Output

```
Checking domain environment...

  [+] [!] CRITICAL: Found 4 Windows Server 2025 domain controller(s)
  [*] [!] BadSuccessor exploitation is POSSIBLE in this environment...

Enumerating organizational units and dMSA objects...

  [*] Found 678 OUs and 2 existing dMSA objects to audit

Scanning for BadSuccessor attack paths...

 [!] BADSUCCESSOR ATTACK PATH DETECTED:
     Object: OU=Computers,DC=ad,DC=contoso,DC=com
     Principal: CONTOSO\Admins
     Vulnerable User: john.doe (via group: Admins)
     Permissions: WriteProperty, GenericWrite, GenericAll
     Exploit Type: Create new dMSA
     Match Reason: Group Membership
.
.
.
.
.

[ BADSUCCESOR ATTACK PATH SUMMARY ]

 [!] ATTACK PATHS FOUND:
     Total Findings: 3
     Direct Permissions: 0
     Group Memberships: 2
     Existing dMSA Risks: 0
     OU Creation Risks: 1

 [*] PRINCIPALS WITH BADSUCCESSOR CAPABILITY:
     - CONTOSO\john.doe
     - CONTOSO\Admins
     - CONTOSO\svc-sql

```

## Technical Details

**Dangerous Permissions Checked:**
- `CreateChild` - Create new dMSA objects
- `WriteProperty` - Modify dMSA attributes  
- `WriteDacl` - Change security permissions
- `WriteOwner` - Take ownership
- `GenericWrite` - General write access
- `GenericAll` - Full control

**dMSA Object Detection:**
- Uses dMSA GUID: `7B8B558A-93A5-4AF7-ADCA-C017E67F1057`
- Scans for object class: `msDS-DelegatedManagedServiceAccount`

### Requirements

- Active Directory PowerShell module (RSAT)
- Read permissions to Active Directory

## References

- [Akamai BadSuccessor Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft dMSA Documentation](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts)
