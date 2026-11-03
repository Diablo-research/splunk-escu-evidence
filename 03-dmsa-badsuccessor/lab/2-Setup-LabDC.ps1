#Requires -RunAsAdministrator
# In the VM. -Phase 1: promotes a new forest lab.local (reboots). -Phase 2: KDS root key, audit policy, lab OU and auditing SACLs.
param([Parameter(Mandatory)][ValidateSet(1,2)][int]$Phase)
$ErrorActionPreference = 'Stop'
if ($Phase -eq 1) {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    $dsrm = Read-Host -AsSecureString 'Choose a DSRM (directory restore) password'
    # New isolated forest lab.local. The VM reboots automatically when promotion finishes.
    Install-ADDSForest -DomainName 'lab.local' -DomainNetbiosName 'LAB' -InstallDns -SafeModeAdministratorPassword $dsrm -Force
    return
}
Import-Module ActiveDirectory
$domain = (Get-ADDomain).DistinguishedName
# KDS root key (required for gMSA/dMSA). Back-dated so it is usable immediately in a single-DC lab only.
if (-not (Get-KdsRootKey)) { Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null }
# Audit policy: directory object create/modify events (5136/5137/5141).
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Directory Service Access" /success:enable | Out-Null
# Lab OU with an auditing SACL so changes inside it always generate 5136/5137.
$ouName = 'LabServiceAccounts'
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'")) {
    New-ADOrganizationalUnit -Name $ouName -Path $domain -ProtectedFromAccidentalDeletion $false
}
$ouDn = "OU=$ouName,$domain"
$acl = Get-Acl -Path "AD:\$ouDn" -Audit
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty,CreateChild,DeleteChild'
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, $rights, [System.Security.AccessControl.AuditFlags]::Success, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
$acl.AddAuditRule($rule)
Set-Acl -Path "AD:\$ouDn" -AclObject $acl
# Also audit writes on the domain root (dMSAs can be created in any OU/container).
$acl2 = Get-Acl -Path "AD:\$domain" -Audit
$acl2.AddAuditRule((New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, $rights, [System.Security.AccessControl.AuditFlags]::Success, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)))
Set-Acl -Path "AD:\$domain" -AclObject $acl2
Write-Output "Domain: $((Get-ADDomain).DNSRoot)  DC: $env:COMPUTERNAME  OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Output "KDS root key: $(@(Get-KdsRootKey).Count)  Audit: $(auditpol /get /subcategory:'Directory Service Changes' | Select-String 'Directory Service Changes')"
Write-Output 'Phase 2 done.'
