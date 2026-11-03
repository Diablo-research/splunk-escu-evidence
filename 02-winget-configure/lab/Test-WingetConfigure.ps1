#Requires -RunAsAdministrator
# WinGet configuration (winget configure) detection lab.
# Uses ONLY a read-only assertion configuration (Microsoft Learn sample: OS version check). Nothing is installed or changed,
# apart from WinGet downloading the Microsoft.Windows.Developer DSC module from PowerShell Gallery into its own module cache.
# Captures Sysmon events for the full process tree so Splunk analytics can be built and replayed.
param(
    # Optional https URL of a copy of lab.winget (remote-file case).
    [string]$RemoteUrl = ''
)
$ErrorActionPreference = 'Stop'

$winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
if (-not $winget) { throw 'winget.exe not found (install/update App Installer from the Microsoft Store).' }
$version = (& $winget --version | Out-String).Trim()

$lab = Join-Path $env:USERPROFILE ('Downloads\WingetGapLab\run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path "$lab\out" | Out-Null

# Read-only assertion (Microsoft Learn sample). The same content is copied with a .txt extension to show extension is irrelevant.
$config = @'
# yaml-language-server: $schema=https://aka.ms/configuration-dsc-schema/0.2
properties:
  assertions:
    - resource: Microsoft.Windows.Developer/OsVersion
      directives:
        description: Verify min OS version requirement
        allowPrerelease: true
      settings:
        MinVersion: '10.0.17763'
  configurationVersion: 0.2.0
'@
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText("$lab\lab.winget", ($config -replace "`r`n", "`n"), $utf8)
[IO.File]::WriteAllText("$lab\lab-config.txt", ($config -replace "`r`n", "`n"), $utf8)

$agree = '--accept-configuration-agreements --disable-interactivity'
$cases = [ordered]@{
    'negative_version'       = '--version'
    'negative_list'          = 'list --count 1 --accept-source-agreements --disable-interactivity'
    'configure_validate'     = "configure validate -f `"$lab\lab.winget`" --disable-interactivity"
    'configure_show'         = "configure show -f `"$lab\lab.winget`" --disable-interactivity"
    'configure_local_f'      = "configure -f `"$lab\lab.winget`" $agree"
    'configure_local_file'   = "configure --file `"$lab\lab.winget`" $agree"
    'configure_local_txt'    = "configure -f `"$lab\lab-config.txt`" $agree"
}
if ($RemoteUrl) {
    if ($RemoteUrl -notmatch '^https://') { throw 'RemoteUrl must be https:// (winget only accepts https for remote files).' }
    $cases['configure_remote'] = "configure -f $RemoteUrl $agree"
}

$start = (Get-Date).AddSeconds(-2)
$runs = foreach ($name in $cases.Keys) {
    Write-Host "Running $name ..."
    $p = Start-Process -FilePath $winget -ArgumentList $cases[$name] -WorkingDirectory $lab -NoNewWindow -Wait -PassThru `
         -RedirectStandardOutput "$lab\out\$name.stdout.txt" -RedirectStandardError "$lab\out\$name.stderr.txt"
    [pscustomobject]@{ Case = $name; ProcessId = $p.Id; Exit = $p.ExitCode; Args = $cases[$name] }
}
Start-Sleep -Seconds 8   # let Sysmon flush

# ---- collect Sysmon events for the process trees we launched ----
$all = foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $start } -ErrorAction SilentlyContinue) {
    $xml = $e.ToXml(); $d = @{}
    foreach ($n in ([xml]$xml).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{ Id = $e.Id; D = $d; Xml = $xml }
}
$procCreate = @($all | Where-Object { $_.Id -eq 1 })
# Diagnostics: Sysmon coverage of the launched processes
$wingetSeen = @($procCreate | Where-Object { $_.D['Image'] -like '*winget*' -or $_.D['Image'] -like '*ConfigurationRemotingServer*' })
Write-Host ("Sysmon events since start: {0} total, {1} process creations, {2} of them winget/ConfigurationRemotingServer" -f @($all).Count, $procCreate.Count, $wingetSeen.Count)
$wingetSeen | Select-Object -First 3 | ForEach-Object { Write-Host ("  seen: PID {0}  {1}" -f $_.D['ProcessId'], $_.D['Image']) }
$runs | ForEach-Object { Write-Host ("  launched: {0} PID {1}" -f $_.Case, $_.ProcessId) }
$used = New-Object System.Collections.Generic.HashSet[string]
$report = foreach ($r in $runs) {
    $root = $procCreate | Where-Object { $_.D['ProcessId'] -eq [string]$r.ProcessId -and $_.D['Image'] -like '*\winget.exe' } | Select-Object -First 1
    if (-not $root) {   # fallback: match on the command-line arguments (app execution alias can change the PID)
        $root = $procCreate | Where-Object { $_.D['Image'] -like '*\winget.exe' -and -not $used.Contains($_.D['ProcessGuid']) -and
                    ($_.D['CommandLine'] -replace '\s+', ' ').TrimEnd().EndsWith(($r.Args -replace '\s+', ' ').Trim()) } | Select-Object -First 1
    }
    if ($root) { [void]$used.Add($root.D['ProcessGuid']) }
    $guids = New-Object System.Collections.Generic.HashSet[string]
    if ($root) {
        [void]$guids.Add($root.D['ProcessGuid'])
        do {   # walk descendants
            $added = 0
            foreach ($pc in $procCreate) { if ($guids.Contains($pc.D['ParentProcessGuid']) -and $guids.Add($pc.D['ProcessGuid'])) { $added++ } }
        } while ($added -gt 0)
    }
    $tree  = @($procCreate | Where-Object { $guids.Contains($_.D['ProcessGuid']) -and $_ -ne $root })
    $crs   = @($tree | Where-Object { $_.D['Image'] -like '*\ConfigurationRemotingServer.exe' })
    $crsG  = @($crs | ForEach-Object { $_.D['ProcessGuid'] })
    $net   = @($all | Where-Object { $_.Id -eq 3 -and $guids.Contains($_.D['ProcessGuid']) })
    $crsKids = @($procCreate | Where-Object { $crsG -contains $_.D['ParentProcessGuid'] })
    foreach ($ev in $all) { if ($guids.Contains([string]$ev.D['ProcessGuid'])) { $ev | Add-Member -NotePropertyName Case -NotePropertyValue $r.Case -Force } }
    [pscustomobject]@{
        Case                        = $r.Case
        ExitCode                    = $r.Exit
        WingetCommandLine           = if ($root) { $root.D['CommandLine'] } else { '(no Sysmon EID 1 found)' }
        DescendantProcesses         = ($tree | ForEach-Object { Split-Path $_.D['Image'] -Leaf }) -join ', '
        ConfigurationRemotingServer = $crs.Count
        CRS_CommandLine             = ($crs | Select-Object -First 1 | ForEach-Object { $_.D['CommandLine'] })
        CRS_Children                = ($crsKids | ForEach-Object { Split-Path $_.D['Image'] -Leaf }) -join ', '
        NetworkConnections          = $net.Count
        NetworkByImage              = (($net | ForEach-Object { (Split-Path $_.D['Image'] -Leaf) + '->' + $_.D['DestinationHostname'] + '/' + $_.D['DestinationIp'] + ':' + $_.D['DestinationPort'] }) | Sort-Object -Unique) -join '; '
    }
}
$report | Format-List
$report | Export-Csv -LiteralPath "$lab\winget-report.csv" -NoTypeInformation

# Events for every launched tree (all Sysmon event types), one XML event per line.
$treeEvents = @($all | Where-Object { $_.PSObject.Properties['Case'] })
if ($treeEvents.Count -gt 0) {
    [IO.File]::WriteAllLines("$lab\winget-sysmon.log", [string[]]($treeEvents | ForEach-Object { $_.Xml }), $utf8)
} else {
    Write-Host 'No Sysmon events matched the launched winget processes; winget-sysmon.log was not written.' -ForegroundColor Yellow
}
Write-Host "First lines of configure_local_f output:"
Get-Content "$lab\out\configure_local_f.stdout.txt" -TotalCount 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
$byId = $treeEvents | Group-Object Id | ForEach-Object { "EID $($_.Name)=$($_.Count)" }

$hist = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\State\Configuration\History'
Write-Output "winget version: $version"
Write-Output "Folder:  $lab"
Write-Output "Events:  $($treeEvents.Count) ($($byId -join ', ')) -> winget-sysmon.log"
Write-Output ("Config history DB present: " + (Test-Path (Join-Path $hist 'config.db')))
Write-Output "Outputs per case are in $lab\out (stdout/stderr)."
