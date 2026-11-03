#Requires -RunAsAdministrator
# In the DC VM as a domain administrator: generates the directory-change audit events (5136/5137/5141) for each test case.
# Every action is an ordinary administrator change to throw-away lab objects in OU=LabServiceAccounts. Nothing outside that OU is touched.
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = (Get-ADDomain).DistinguishedName
$ou     = "OU=LabServiceAccounts,$domain"
$dns    = (Get-ADDomain).DNSRoot
$tag    = Get-Date -Format 'HHmm'                       # keeps names unique and <= 15 chars across reruns
$run    = "C:\DmsaLab\run-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force -Path $run | Out-Null
$start  = (Get-Date).AddSeconds(-2)
$log    = New-Object System.Collections.Generic.List[object]
function Step($name, [scriptblock]$action) {
    Write-Host "Running $name ..."
    $t = Get-Date
    try { & $action; $ok = 'ok' } catch { $ok = 'ERROR: ' + $_.Exception.Message }
    $log.Add([pscustomobject]@{ Case = $name; Time = $t.ToString('HH:mm:ss'); Result = $ok })
    Start-Sleep -Seconds 2
}
$gmsa = "gmsa$tag"; $d1 = "dmsa$tag" + 'a'; $d2 = "dmsa$tag" + 'b'
$u1 = "legacy$tag" + 'a'; $u2 = "legacy$tag" + 'b'

Step 'negative_user_create'       { New-ADUser -Name $u1 -Path $ou -Enabled $false; New-ADUser -Name $u2 -Path $ou -Enabled $false }
Step 'negative_gmsa_create'       { New-ADServiceAccount -Name $gmsa -DNSHostName "$gmsa.$dns" -Path $ou -PrincipalsAllowedToRetrieveManagedPassword 'Domain Controllers' }
Step 'dmsa_create'                { New-ADServiceAccount -Name $d1 -DNSHostName "$d1.$dns" -Path $ou -CreateDelegatedServiceAccount -KerberosEncryptionType AES256 }
Step 'negative_dmsa_description'  { Set-ADServiceAccount -Identity $d1 -Description 'lab dMSA' }
Step 'dmsa_link_direct_write'     { Set-ADServiceAccount -Identity $d1 -Replace @{ 'msDS-ManagedAccountPrecededByLink' = (Get-ADUser $u1).DistinguishedName } }
Step 'dmsa_state_direct_write'    { Set-ADServiceAccount -Identity $d1 -Replace @{ 'msDS-DelegatedMSAState' = 2 } }
# Microsoft's supported migration path, for comparison with the direct attribute writes above.
Step 'dmsa_create_for_migration'  { New-ADServiceAccount -Name $d2 -DNSHostName "$d2.$dns" -Path $ou -CreateDelegatedServiceAccount -KerberosEncryptionType AES256 }
Step 'legit_migration_start'      { Start-ADServiceAccountMigration -Identity $d2 -SupersededAccount (Get-ADUser $u2).DistinguishedName }
Step 'legit_migration_complete'   { Complete-ADServiceAccountMigration -Identity $d2 -SupersededAccount (Get-ADUser $u2).DistinguishedName }

Start-Sleep -Seconds 5
# Attribute snapshot: what the direct writes vs Microsoft's migration cmdlets left on each object.
$snap = foreach ($n in @($d1, $d2)) {
    $o = Get-ADServiceAccount $n -Properties * -ErrorAction SilentlyContinue
    if ($o) { $o.PSObject.Properties | Where-Object { $_.Name -like 'msDS-*' -and $_.Value } |
        ForEach-Object { [pscustomobject]@{ Object = $n; Attribute = $_.Name; Value = ($_.Value -join '; ') } } }
}
$snap += foreach ($n in @($u1, $u2)) {
    $o = Get-ADUser $n -Properties * -ErrorAction SilentlyContinue
    if ($o) { $o.PSObject.Properties | Where-Object { $_.Name -like 'msDS-Supersed*' -and $_.Value } |
        ForEach-Object { [pscustomobject]@{ Object = $n; Attribute = $_.Name; Value = ($_.Value -join '; ') } } }
}
$events =@(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5136, 5137, 5141; StartTime = $start } -ErrorAction SilentlyContinue)
$rows = foreach ($e in $events) {
    $d = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{ Time = $e.TimeCreated.ToString('HH:mm:ss'); EventID = $e.Id; ObjectClass = $d['ObjectClass']
        Attribute = $d['AttributeLDAPDisplayName']; Value = $d['AttributeValue']; Op = $d['OperationType']
        Object = ($d['ObjectDN'] -split ',')[0]; Subject = $d['SubjectUserName'] }
}
$log | Format-Table -AutoSize
$rows | Sort-Object Time | Format-Table -AutoSize -Wrap
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($events.Count) { [IO.File]::WriteAllLines("$run\dmsa-security.log", [string[]]($events | ForEach-Object { $_.ToXml() }), $utf8) }
Write-Output '--- dMSA / superseded attributes after the run ---'
$snap | Format-Table -AutoSize -Wrap
$snap | Export-Csv "$run\attributes.csv" -NoTypeInformation
$log  | Export-Csv "$run\cases.csv" -NoTypeInformation
$rows | Export-Csv "$run\events.csv" -NoTypeInformation
Write-Output "Events captured: $($events.Count) (5136/5137/5141) -> $run\dmsa-security.log"
Write-Output "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
