#Requires -RunAsAdministrator
# ADExplorer snapshot capture, run in the lab DC VM (lab.local) as a domain administrator.
# Downloads Sysmon and ADExplorer from Microsoft Sysinternals (signature-checked), installs Sysmon with adx-sysmon.xml,
# takes AD snapshots of the throw-away lab domain in several ways, and exports the Sysmon events. Snapshots stay in C:\ADLab.
param([switch]$IncludeGui)
$ErrorActionPreference = 'Stop'
$base = 'C:\ADLab'; $tools = "$base\tools"
$run = "$base\run-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force -Path $tools, $run | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-SysinternalsTool($zipName, $exeName) {
    $exe = Join-Path $tools $exeName
    if (-not (Test-Path $exe)) {
        $zip = Join-Path $tools $zipName
        Invoke-WebRequest "https://download.sysinternals.com/files/$zipName" -OutFile $zip -UseBasicParsing
        Expand-Archive $zip -DestinationPath $tools -Force
    }
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { throw "Signature check failed for $exe : $($sig.Status) $($sig.SignerCertificate.Subject)" }
    $exe
}
$sysmon = Get-SysinternalsTool 'Sysmon.zip' 'Sysmon64.exe'
$adx    = Get-SysinternalsTool 'AdExplorer.zip' 'ADExplorer64.exe'
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) { & $sysmon -accepteula -i "$PSScriptRoot\adx-sysmon.xml" | Out-Host }
else { & $sysmon -c "$PSScriptRoot\adx-sysmon.xml" | Out-Host }
Start-Sleep -Seconds 3

$cases = [System.Collections.Generic.List[object]]::new()
function Run-Case($name, $exe, $argLine, $outFile, $timeout = 120) {
    Write-Host "Running $name ..."
    $t = Get-Date
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -PassThru
    if (-not $p.WaitForExit($timeout * 1000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $state = 'timeout (killed)' } else { $state = "exit $($p.ExitCode)" }
    $size = if ($outFile -and (Test-Path $outFile)) { (Get-Item $outFile).Length } else { 0 }
    $cases.Add([pscustomobject]@{ Case = $name; Started = $t.ToString('HH:mm:ss'); State = $state; Output = $outFile; Bytes = $size })
}
$start = (Get-Date).AddSeconds(-2)
# EULA accepted up front (as the tool itself would after the first prompt) so command-line runs do not block.
New-Item 'HKCU:\Software\Sysinternals\Active Directory Explorer' -Force | Out-Null
Set-ItemProperty 'HKCU:\Software\Sysinternals\Active Directory Explorer' -Name EulaAccepted -Value 1 -Type DWord

# 1. Documented command-line snapshot of the current domain to a .dat file
Run-Case 'cli_snapshot_dat' $adx "-snapshot `"`" `"$run\snap-cli.dat`"" "$run\snap-cli.dat"
# 2. Same, but a non-.dat file name (tests rules that assume .dat)
Run-Case 'cli_snapshot_tmp_ext' $adx "-snapshot `"`" `"$run\cache-0001.tmp`"" "$run\cache-0001.tmp"
# 3. Renamed copy of ADExplorer (tests image-name based rules)
$renamed = Join-Path $run 'svc-helper.exe'; Copy-Item $adx $renamed
Run-Case 'renamed_cli_snapshot' $renamed "-snapshot `"`" `"$run\snap-renamed.dat`"" "$run\snap-renamed.dat"
# 4. Control: ADExplorer started without a snapshot (GUI opens; closed after 8 s)
Write-Host 'Running gui_launch_no_snapshot ...'
$p = Start-Process -FilePath $adx -PassThru; Start-Sleep 8; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
$cases.Add([pscustomobject]@{ Case = 'gui_launch_no_snapshot'; Started = (Get-Date).ToString('HH:mm:ss'); State = 'closed'; Output = ''; Bytes = 0 })
# 5. Optional: snapshot taken through the GUI menu (no "snapshot" on the command line)
if ($IncludeGui) {
    $gui = "$run\snap-gui.dat"
    Write-Host "`nGUI CASE: ADExplorer will open. Click OK in the Connect dialog (current domain), then File > Create Snapshot,"
    Write-Host "save to: $gui  - wait until it finishes, close ADExplorer, then come back here and press Enter." -ForegroundColor Yellow
    $p = Start-Process -FilePath $adx -PassThru
    [void](Read-Host 'Press Enter when the GUI snapshot is done and ADExplorer is closed')
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $cases.Add([pscustomobject]@{ Case = 'gui_menu_snapshot'; Started = ''; State = 'manual'; Output = $gui; Bytes = $(if (Test-Path $gui) { (Get-Item $gui).Length } else { 0 }) })
}
# 6. Negative: ordinary LDAP enumeration with the AD PowerShell module (no ADExplorer)
Write-Host 'Running negative_powershell_ldap ...'
$n = @(Get-ADUser -Filter * -Properties description).Count
$cases.Add([pscustomobject]@{ Case = 'negative_powershell_ldap'; Started = (Get-Date).ToString('HH:mm:ss'); State = "$n users"; Output = ''; Bytes = 0 })

Start-Sleep -Seconds 6
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3, 11, 12, 13; StartTime = $start } -ErrorAction SilentlyContinue)
$rows = foreach ($e in $events) {
    $d = @{}; foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
    if ($e.Id -eq 1 -and -not ($d['OriginalFileName'] -eq 'AdExp' -or $d['Image'] -like "$base\*")) { continue }
    [pscustomobject]@{ Id = $e.Id; Image = (Split-Path $d['Image'] -Leaf); OFN = $d['OriginalFileName']
        Detail = if ($e.Id -eq 1) { $d['CommandLine'] } elseif ($e.Id -eq 11) { $d['TargetFilename'] } elseif ($e.Id -eq 3) { "$($d['DestinationIp']):$($d['DestinationPort'])" } else { "$($d['TargetObject']) = $($d['Details'])" } }
}
$cases | Format-Table -AutoSize
Write-Output '--- Key Sysmon events (process creations limited to ADExplorer / C:\ADLab images) ---'
$rows | Format-Table Id, Image, OFN, Detail -AutoSize -Wrap
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllLines("$run\adx-sysmon.log", [string[]]($events | ForEach-Object { $_.ToXml() }), $utf8)
$cases | Export-Csv "$run\cases.csv" -NoTypeInformation
Write-Output "ADExplorer version: $((Get-Item $adx).VersionInfo.FileVersion)  OriginalFilename: $((Get-Item $adx).VersionInfo.OriginalFilename)"
Write-Output "Events exported: $($events.Count) -> $run\adx-sysmon.log"
