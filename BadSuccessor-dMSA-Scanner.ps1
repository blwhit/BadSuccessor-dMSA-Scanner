param (
    [string]$User,         # sAMAccountName of specific user to audit
    [switch]$All,          # Audit all users/groups with dMSA creation/modification rights (DEFAULT: ON)
    [switch]$CSV,          # Save results to CSV
    [switch]$SkipGroups,   # Skip group membership analysis (faster but less comprehensive)
    [switch]$h             # Show help
)

if ($h) {
    Write-Host @"

USAGE:
------
.\BadSuccessor-dMSA-Scanner.ps1 [options]

OPTIONS:
  -User <sAMAccountName>   Audit dMSA exploit risk for a specific user
  -All                     Audit ALL users/groups with dMSA exploit capabilities (DEFAULT: ON)
  -CSV                     Export results to CSV file
  -SkipGroups              Skip group membership analysis for faster execution
  -h                       Show this help message

EXAMPLES:
  Full BadSuccessor attack path audit:
    .\BadSuccessor-dMSA-Scanner.ps1

  Audit specific user:
    .\BadSuccessor-dMSA-Scanner.ps1 -User jdoe

  Full audit with CSV export:
    .\BadSuccessor-dMSA-Scanner.ps1 -CSV

WHAT THIS SCRIPT CHECKS:
- Direct permissions for dMSA creation/modification
- Group membership permissions (unless -SkipGroups is used)
- Modification rights to existing dMSA objects  
- Windows Server 2025 presence (required for BadSuccessor)
- Container objects (in addition to OUs) for dMSA creation

"@ 
    exit
}

# Banner
Write-Host "`n[ BadSuccessor dMSA Attack Path Scanner ]" -ForegroundColor Cyan
Write-Host "[ https://github.com/blwhit/BadSuccessor-dMSA-Scanner ]`n" -ForegroundColor Cyan

# Import required module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "[!] Active Directory PowerShell module not found. Please install RSAT tools." -ForegroundColor Red
    exit 1
}

# Set default behavior
if (-not $User -and -not $All.IsPresent) {
    $All = $true
}

# Initialize variables
$ReportFile = "BadSuccessor_dMSA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$script:Report = @()
$UserGroupCache = @{}
$HighPrivilegeSIDs = @()

# Required GUIDs
$dMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765" # msDS-DelegatedManagedServiceAccount 
$AllChild_GUID = "00000000-0000-0000-0000-000000000000"  # All child objects

# Define dangerous permissions for BadSuccessor exploitation
$DangerousRights = @(
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
)

# Check for Windows Server 2025 domain controllers
Write-Host "Checking domain environment..." -ForegroundColor Yellow
try {
    $AllDCs = Get-ADDomainController -Filter * -ErrorAction Stop
    $Server2025DCs = $AllDCs | Where-Object { $_.OperatingSystem -like "*2025*" }
    
    if ($Server2025DCs.Count -gt 0) {
        Write-Host "[!] CRITICAL: Found $($Server2025DCs.Count) Windows Server 2025 domain controller(s)" -ForegroundColor Red
        Write-Host "[!] BadSuccessor exploitation is POSSIBLE in this environment" -ForegroundColor Red
    } else {
        Write-Host "[+] No Windows Server 2025 DCs found - BadSuccessor NOT currently exploitable" -ForegroundColor Green
        Write-Host "[*] Still auditing potential attack surface..." 
    }
} catch {
    Write-Host "[!] Warning: Could not enumerate domain controllers: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Build list of high-privilege SIDs to filter out (false positives)
$HighPrivilegeSIDs = @(
    'S-1-5-18',  # NT AUTHORITY\SYSTEM
    'S-1-5-9',   # NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
    'S-1-5-32-544'  # BUILTIN\Administrators
)

try {
    # Add domain-specific high privilege groups
    $DomainSID = (Get-ADDomain).DomainSID.Value
    $HighPrivilegeSIDs += @(
        "$DomainSID-512",  # Domain Admins
        "$DomainSID-519",  # Enterprise Admins (if exists in this domain)
        "$DomainSID-518"   # Schema Admins
    )
    
    # Try to get Enterprise Admins from root domain if we're in a child domain
    try {
        $RootDomain = (Get-ADForest).RootDomain
        if ($RootDomain -ne (Get-ADDomain).DNSRoot) {
            $RootDomainSID = (Get-ADDomain -Server $RootDomain).DomainSID.Value
            $HighPrivilegeSIDs += "$RootDomainSID-519"  # Root domain Enterprise Admins
        }
    } catch {
        Write-Verbose "Could not determine root domain Enterprise Admins SID"
    }
    
    Write-Host "[*] Filtering out $($HighPrivilegeSIDs.Count) known high-privilege principals" -ForegroundColor Gray
    
} catch {
    Write-Host "[!] Warning: Could not build complete high-privilege filter: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Function to check if principal is high-privilege (false positive)
function Test-HighPrivilegePrincipal {
    param([string]$PrincipalSID)
    
    # Check against known high-privilege SIDs
    if ($HighPrivilegeSIDs -contains $PrincipalSID) {
        return $true
    }
    
    # Check for other built-in high privilege SIDs
    if ($PrincipalSID -match '^S-1-5-32-5(44|48|49|51|52)$') {  # Built-in admin groups
        return $true
    }
    
    return $false
}

# Function to get user group memberships with caching
function Get-UserGroupMemberships {
    param([string]$UserSID)
    
    if ($UserGroupCache.ContainsKey($UserSID)) {
        return $UserGroupCache[$UserSID]
    }
    
    try {
        $User = Get-ADUser -Filter "SID -eq '$UserSID'" -Properties MemberOf -ErrorAction Stop
        $AllGroups = @()
        
        # Use tokenGroups for accurate nested group membership
        try {
            $UserDN = $User.DistinguishedName
            $UserObject = [ADSI]"LDAP://$UserDN"
            $UserObject.RefreshCache("tokenGroups")
            $TokenGroups = $UserObject.tokenGroups
            
            foreach ($TokenGroup in $TokenGroups) {
                try {
                    $SID = New-Object System.Security.Principal.SecurityIdentifier($TokenGroup, 0)
                    $Group = Get-ADGroup -Filter "SID -eq '$($SID.Value)'" -Properties SID -ErrorAction Stop
                    if ($Group) { $AllGroups += $Group }
                } catch {
                    # Skip built-in or unresolvable SIDs
                }
            }
        } catch {
            # Fallback to direct group enumeration
            if ($User.MemberOf) {
                $AllGroups = $User.MemberOf | ForEach-Object {
                    try {
                        Get-ADGroup -Identity $_ -Properties SID -ErrorAction Stop
                    } catch { 
                        Write-Verbose "Could not resolve group: $_"
                        $null
                    }
                } | Where-Object { $_ -ne $null }
            }
        }
        
        $UniqueGroups = $AllGroups | Sort-Object SID -Unique
        $UserGroupCache[$UserSID] = $UniqueGroups
        return $UniqueGroups
        
    } catch {
        Write-Verbose "Could not get group memberships for SID: $UserSID - $($_.Exception.Message)"
        $UserGroupCache[$UserSID] = @()
        return @()
    }
}

# Function to check if user has permission through group membership
function Test-UserGroupPermissions {
    param($UserSID, $ACE_SID)
    
    if ($SkipGroups) { return $false }
    
    $UserGroups = Get-UserGroupMemberships -UserSID $UserSID
    foreach ($Group in $UserGroups) {
        if ($Group.SID.Value -eq $ACE_SID) {
            return $Group
        }
    }
    return $false
}

# Function to check if permission is relevant for BadSuccessor
function Test-BadSuccessorRelevantPermission {
    param($ACE, $ObjectTypeGuid, $IsExistingdMSA = $false)
    
    # Check if has dangerous rights
    $HasDangerousRight = $false
    $DangerousRightsPresent = @()
    
    foreach ($Right in $DangerousRights) {
        if ($ACE.ActiveDirectoryRights -band $Right) {
            $HasDangerousRight = $true
            $DangerousRightsPresent += $Right
        }
    }
    
    if (-not $HasDangerousRight) { 
        return $false, @(), "No dangerous rights"
    }
    
    # For existing dMSA objects, focus on modification rights
    if ($IsExistingdMSA) {
        $ModificationRights = @(
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        )
        
        $HasModificationRight = $false
        foreach ($Right in $ModificationRights) {
            if ($ACE.ActiveDirectoryRights -band $Right) {
                $HasModificationRight = $true
                break
            }
        }
        
        return $HasModificationRight, $DangerousRightsPresent, $null
    }
    
    # For OU/Container objects, check for dMSA creation rights
    $RelevantForCreation = (
        # Specific dMSA object creation permission
        ($ObjectTypeGuid.ToUpper() -eq $dMSA_GUID.ToUpper()) -or
        # All child objects (includes dMSA)
        ($ObjectTypeGuid -eq $AllChild_GUID) -or
        # CreateChild without object type restriction (applies to all child types)
        (($ACE.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -and ($ACE.ObjectType -eq [System.Guid]::Empty))
    )
    
    return $RelevantForCreation, $DangerousRightsPresent, $null
}

# Function to get permission description
function Get-PermissionDescription {
    param($ACE)
    
    $permissions = @()
    foreach ($Right in $DangerousRights) {
        if ($ACE.ActiveDirectoryRights -band $Right) {
            $permissions += $Right.ToString()
        }
    }
    
    return ($permissions -join ", ")
}

# Resolve target user if specified
if ($User) {
    try {
        $ADUser = Get-ADUser -Identity $User -Properties DistinguishedName, SID -ErrorAction Stop
        $TargetPrincipal = $ADUser.SID.Value
        $TargetFriendly = $ADUser.SamAccountName
        Write-Host "[*] Target User: $TargetFriendly ($TargetPrincipal)" 
    } catch {
        Write-Host "[!] User '$User' not found in Active Directory." -ForegroundColor Red
        exit 1
    }
}

# Get all OUs, Containers, and existing dMSA objects
Write-Host "`nEnumerating OUs, Containers, and dMSA objects..." -ForegroundColor Yellow
try {
    $OUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName -ErrorAction Stop
    Write-Host "[*] Found $($OUs.Count) OUs" -ForegroundColor Gray
    
    $Containers = Get-ADObject -Filter { objectClass -eq "container" } -Properties DistinguishedName -ErrorAction Stop
    Write-Host "[*] Found $($Containers.Count) Containers" -ForegroundColor Gray
    
    # Look for existing dMSA objects
    $dMSAObjects = @()
    try {
        $dMSAObjects = @(Get-ADObject -Filter { objectClass -eq "msDS-DelegatedManagedServiceAccount" } -Properties DistinguishedName -ErrorAction Stop)
        Write-Host "[*] Found $($dMSAObjects.Count) existing dMSA objects" -ForegroundColor Gray
    } catch [Microsoft.ActiveDirectory.Management.ADException] {
        if ($_.Exception.Message -like "*does not exist*" -or $_.Exception.Message -like "*unknown object class*") {
            Write-Verbose "dMSA object class not found - normal for non-Server 2025 environments"
            $dMSAObjects = @()
            Write-Host "[*] dMSA object class not available (normal for pre-Server 2025)" -ForegroundColor Gray
        } else {
            Write-Host "[!] Error querying dMSA objects: $($_.Exception.Message)" -ForegroundColor Yellow
            $dMSAObjects = @()
        }
    } catch {
        Write-Host "[!] Unexpected error querying dMSA objects: $($_.Exception.Message)" -ForegroundColor Yellow
        $dMSAObjects = @()
    }
    
} catch {
    Write-Host "[!] Failed to retrieve objects from Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$TotalObjects = $OUs.Count + $Containers.Count + $dMSAObjects.Count
$CurrentObject = 0

Write-Host "`nScanning for BadSuccessor attack paths..." -ForegroundColor Yellow
Write-Host "[*] Total objects to audit: $TotalObjects" -ForegroundColor Gray

# Function to process ACL and report findings
function Process-ObjectACL {
    param($Object, $ObjectType, $IsExistingdMSA = $false)
    
    try {
        $ADSIPath = "LDAP://" + $Object.DistinguishedName
        $DirectoryEntry = [ADSI]$ADSIPath
        $ACL = $DirectoryEntry.ObjectSecurity.Access

        foreach ($ACE in $ACL) {
            if ($ACE.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }

            # Handle empty ObjectType (treats as All Child Objects)
            $ObjectTypeGuid = if ($ACE.ObjectType -and $ACE.ObjectType.ToString() -ne "00000000-0000-0000-0000-000000000000") { 
                $ACE.ObjectType.ToString().ToUpper() 
            } else { 
                $AllChild_GUID 
            }
            
            # Check if permission is relevant for BadSuccessor
            $IsRelevant, $DangerousRightsPresent, $ReasonNotRelevant = Test-BadSuccessorRelevantPermission -ACE $ACE -ObjectTypeGuid $ObjectTypeGuid -IsExistingdMSA $IsExistingdMSA
            
            if (-not $IsRelevant) { 
                Write-Verbose "Skipping ACE - $ReasonNotRelevant"
                continue 
            }

            # Simple SID translation with error handling
            try {
                $ACE_SID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                Write-Verbose "Could not translate SID for: $($ACE.IdentityReference.Value) - $($_.Exception.Message)"
                continue
            }

            # Filter out high-privilege principals (false positives)
            if (Test-HighPrivilegePrincipal -PrincipalSID $ACE_SID) {
                Write-Verbose "Skipping high-privilege principal: $($ACE.IdentityReference.Value)"
                continue
            }

            $IsMatch = $false
            $MatchReason = ""
            $VulnerableUser = ""
            $GroupMembership = $null

            # Check for matches
            if ($All) {
                $IsMatch = $true
                $MatchReason = "Direct Permission"
                $VulnerableUser = $ACE.IdentityReference.Value
            } elseif ($User -and $ACE_SID -eq $TargetPrincipal) {
                $IsMatch = $true
                $MatchReason = "Direct Permission"
                $VulnerableUser = $TargetFriendly
            } elseif ($User -and -not $SkipGroups) {
                $GroupMatch = Test-UserGroupPermissions -UserSID $TargetPrincipal -ACE_SID $ACE_SID
                if ($GroupMatch) {
                    # Additional check: don't report if user is member of high-privilege group
                    if (Test-HighPrivilegePrincipal -PrincipalSID $GroupMatch.SID.Value) {
                        Write-Verbose "Skipping - user is member of high-privilege group: $($GroupMatch.Name)"
                        continue
                    }
                    $IsMatch = $true
                    $MatchReason = "Group Membership"
                    $VulnerableUser = $TargetFriendly
                    $GroupMembership = $GroupMatch
                }
            }

            if ($IsMatch) {
                # Determine permission scope
                $AppliesTo = if ($ObjectTypeGuid.ToUpper() -eq $dMSA_GUID.ToUpper()) {
                    "dMSA objects only"
                } elseif ($ObjectTypeGuid -eq $AllChild_GUID) {
                    "All child objects"
                } else {
                    "Object-specific"
                }

                $PermissionDesc = Get-PermissionDescription -ACE $ACE
                $ExploitType = if ($IsExistingdMSA) { "Modify existing dMSA" } else { "Create new dMSA" }
                
                # Output finding
                Write-Host "`n[!] ATTACK PATH DETECTED" -ForegroundColor Red
                Write-Host "    Object: $($Object.DistinguishedName)" -ForegroundColor White
                Write-Host "    Principal: $($ACE.IdentityReference)" -ForegroundColor White
                if ($GroupMembership) {
                    Write-Host "    User: $VulnerableUser (via $($GroupMembership.Name))" -ForegroundColor Yellow
                }
                Write-Host "    Permissions: $PermissionDesc" -ForegroundColor White
                Write-Host "    Scope: $AppliesTo" -ForegroundColor Gray
                Write-Host "    Exploit Type: $ExploitType" -ForegroundColor Red

                # Add to report
                $script:Report += [PSCustomObject]@{
                    ObjectType      = $ObjectType
                    Target          = $Object.DistinguishedName
                    Principal       = $ACE.IdentityReference.Value
                    PrincipalSID    = $ACE_SID
                    VulnerableUser  = $VulnerableUser
                    MatchReason     = $MatchReason
                    GroupName       = if ($GroupMembership) { $GroupMembership.Name } else { "N/A" }
                    Permissions     = $PermissionDesc
                    AppliesTo       = $AppliesTo
                    Inherited       = $ACE.IsInherited
                    ExploitType     = $ExploitType
                    ObjectGUID      = $ObjectTypeGuid
                    Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
    } catch {
        Write-Host "[!] Warning: Could not audit $($ObjectType): $($Object.DistinguishedName) - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Audit OU permissions for dMSA creation
foreach ($OU in $OUs) {
    $CurrentObject++
    if ($TotalObjects -gt 50) {
        Write-Progress -Activity "BadSuccessor Audit" -Status "Auditing OU $CurrentObject of $TotalObjects" -PercentComplete (($CurrentObject / $TotalObjects) * 100)
    }
    Process-ObjectACL -Object $OU -ObjectType "OU"
}

# Audit Container permissions for dMSA creation
foreach ($Container in $Containers) {
    $CurrentObject++
    if ($TotalObjects -gt 50) {
        Write-Progress -Activity "BadSuccessor Audit" -Status "Auditing Container $CurrentObject of $TotalObjects" -PercentComplete (($CurrentObject / $TotalObjects) * 100)
    }
    Process-ObjectACL -Object $Container -ObjectType "Container"
}

# Audit existing dMSA object permissions
foreach ($dMSA in $dMSAObjects) {
    $CurrentObject++
    if ($TotalObjects -gt 50) {
        Write-Progress -Activity "BadSuccessor Audit" -Status "Auditing dMSA $CurrentObject of $TotalObjects" -PercentComplete (($CurrentObject / $TotalObjects) * 100)
    }
    Process-ObjectACL -Object $dMSA -ObjectType "Existing dMSA" -IsExistingdMSA $true
}

if ($TotalObjects -gt 50) {
    Write-Progress -Completed -Activity "BadSuccessor Audit"
}

# Generate summary report
Write-Host "`n" -NoNewline
Write-Host "[X] BADSUCCESSOR VULNERABILITY SUMMARY [X]" -ForegroundColor Red -BackgroundColor Black

if ($script:Report.Count -gt 0) {
    Write-Host "`n[!] ACTIONABLE ATTACK PATHS FOUND: $($script:Report.Count)" -ForegroundColor Red
    Write-Host "[*] (High-privilege principals filtered out)" -ForegroundColor Gray
    
    $DirectRisks = $script:Report | Where-Object { $_.MatchReason -eq "Direct Permission" }
    $GroupBasedRisks = $script:Report | Where-Object { $_.MatchReason -eq "Group Membership" }
    $ExistingdMSARisks = $script:Report | Where-Object { $_.ObjectType -eq "Existing dMSA" }
    $OURisks = $script:Report | Where-Object { $_.ObjectType -eq "OU" }
    $ContainerRisks = $script:Report | Where-Object { $_.ObjectType -eq "Container" }
    
    Write-Host "    Direct Permissions: $($DirectRisks.Count)" -ForegroundColor White
    if (-not $SkipGroups) {
        Write-Host "    Group Memberships: $($GroupBasedRisks.Count)" -ForegroundColor White
    }
    Write-Host "    Existing dMSA Risks: $($ExistingdMSARisks.Count)" -ForegroundColor White
    Write-Host "    OU Creation Risks: $($OURisks.Count)" -ForegroundColor White
    Write-Host "    Container Creation Risks: $($ContainerRisks.Count)" -ForegroundColor White
    
    # Show unique principals with exploit capability
    $UniquePrincipals = $script:Report | Select-Object -ExpandProperty Principal -Unique | Sort-Object
    Write-Host "`n[*] NON-PRIVILEGED PRINCIPALS WITH BADSUCCESSOR CAPABILITY:" -ForegroundColor Cyan
    foreach ($Principal in $UniquePrincipals) {
        Write-Host "    - $Principal" -ForegroundColor White
    }
    
} else {
    Write-Host "`n[+] No BadSuccessor attack paths found" -ForegroundColor Green
}

# Export results if requested
if ($CSV) {
    if ($script:Report.Count -gt 0) {
        try {
            $script:Report | Export-Csv -Path $ReportFile -NoTypeInformation -ErrorAction Stop
            Write-Host "`n[*] Results exported to: $ReportFile" -ForegroundColor Yellow
        } catch {
            Write-Host "[!] Error: Failed to export CSV report: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "`n[*] No findings to export" -ForegroundColor Gray
    }
}

Write-Host "`n"
