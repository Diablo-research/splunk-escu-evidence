#Requires -RunAsAdministrator
# Chromium remote-debugging capture. Starts Edge (and Chrome, if installed) with new, empty temporary profiles only.
# The only DevTools request is GET /json/version; no cookies or page data are read.
# Only browser processes using this run's temporary profiles are stopped.
$ErrorActionPreference = 'Stop'
$edge   = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$chrome = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw 'msedge.exe not found.' }
$run = Join-Path $env:USERPROFILE ('Downloads\CookieLab\run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $run | Out-Null

function Stop-LabBrowser($profileDir) {
    Get-CimInstance Win32_Process -Filter "Name='msedge.exe' OR Name='chrome.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profileDir) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
function Test-DebugPort($port) {
    if (-not $port) { return '' }
    try { (Invoke-WebRequest "http://127.0.0.1:$port/json/version" -UseBasicParsing -TimeoutSec 4).StatusCode } catch { 'closed' }
}
$cases = [System.Collections.Generic.List[object]]::new()
function Add-Case($name, $exe, [string]$argTemplate, $port, $waitSec) {
    $cases.Add([pscustomobject]@{ Name = $name; Exe = $exe; ArgTemplate = $argTemplate; Port = $port; Wait = $waitSec })
}
# Negative controls (must NOT match the new rule)
Add-Case 'negative_user_data_dir_only' $edge '--user-data-dir="{P}" --no-first-run --no-default-browser-check about:blank' $null 4
Add-Case 'negative_headless_dump_dom'  $edge '--headless --disable-gpu --user-data-dir="{P}" --dump-dom about:blank' $null 4
# Positive cases
Add-Case 'debug_port_headless'         $edge '--headless=new --remote-debugging-port=9222 --user-data-dir="{P}" about:blank' 9222 5
Add-Case 'debug_port_offscreen'        $edge '--remote-debugging-port=9223 --window-position=-32000,-32000 --no-first-run --user-data-dir="{P}" about:blank' 9223 5
Add-Case 'debug_port_zero_automation'  $edge '--headless=new --remote-debugging-port=0 --user-data-dir="{P}" about:blank' $null 4
Add-Case 'debug_pipe_headless'         $edge '--headless=new --remote-debugging-pipe --user-data-dir="{P}" about:blank' $null 4
if ($chrome) { Add-Case 'chrome_debug_port_headless' $chrome '--headless=new --remote-debugging-port=9224 --user-data-dir="{P}" about:blank' 9224 5 }

$start = (Get-Date).AddSeconds(-2)
$results = foreach ($c in $cases) {
    Write-Host "Running $($c.Name) ..."
    $profileDir = Join-Path $run ("profile-" + $c.Name)
    New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
    $argLine = $c.ArgTemplate.Replace('{P}', $profileDir)
    $p = Start-Process -FilePath $c.Exe -ArgumentList $argLine -PassThru
    Start-Sleep -Seconds $c.Wait
    $status = Test-DebugPort $c.Port
    Stop-LabBrowser $profileDir
    Start-Sleep -Seconds 1
    [pscustomobject]@{ Case = $c.Name; Browser = (Split-Path $c.Exe -Leaf); Pid = $p.Id; DebugPort = $c.Port; VersionQuery = $status; Profile = $profileDir }
}
Start-Sleep -Seconds 5

$events = foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3; StartTime = $start } -ErrorAction SilentlyContinue) {
    $xml = $e.ToXml(); $d = @{}
    foreach ($n in ([xml]$xml).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $keep = ($e.Id -eq 1 -and $d['Image'] -match '\\(msedge|chrome)\.exe$' -and $d['CommandLine'] -like "*$run*") -or
            ($e.Id -eq 3 -and $d['DestinationPort'] -in '9222', '9223', '9224')
    if ($keep) { [pscustomobject]@{ Id = $e.Id; D = $d; Xml = $xml } }
}
$events = @($events)
$results | Format-Table Case, Browser, DebugPort, VersionQuery -AutoSize
Write-Output '--- Browser main processes logged (child processes with --type= are excluded) ---'
$events | Where-Object { $_.Id -eq 1 -and $_.D['CommandLine'] -notmatch '--type=' } | ForEach-Object {
    $cl = $_.D['CommandLine']
    [pscustomobject]@{ Image = (Split-Path $_.D['Image'] -Leaf); Parent = (Split-Path $_.D['ParentImage'] -Leaf)
        Flags = (([regex]::Matches($cl, '--(remote-debugging-[a-z]+(=\S+)?|headless(=\w+)?|window-position=\S+|disable-gpu|dump-dom)') | ForEach-Object Value) -join ' ') }
} | Format-Table -AutoSize -Wrap
Write-Output '--- Connections to debugging ports ---'
$events | Where-Object { $_.Id -eq 3 } | ForEach-Object {
    [pscustomobject]@{ Image = (Split-Path $_.D['Image'] -Leaf); Dest = "$($_.D['DestinationIp']):$($_.D['DestinationPort'])" }
} | Format-Table -AutoSize
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($events.Count) { [IO.File]::WriteAllLines("$run\cookie-sysmon.log", [string[]]($events | ForEach-Object { $_.Xml }), $utf8) }
$results | Export-Csv "$run\cases.csv" -NoTypeInformation
Write-Output "Edge: $((Get-Item $edge).VersionInfo.ProductVersion)  Chrome: $(if ($chrome) { (Get-Item $chrome).VersionInfo.ProductVersion } else { 'not installed' })"
Write-Output "Events: $($events.Count) -> $run\cookie-sysmon.log"
