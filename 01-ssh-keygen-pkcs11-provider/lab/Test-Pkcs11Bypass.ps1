#Requires -RunAsAdministrator
# Runs ssh-keygen -D with nine argument forms of the benign provider-marker.dll and exports the Sysmon EID 1/7 events.
# Elevation is required to read the Sysmon log. Output goes to a new bypass-<time> folder.

$ErrorActionPreference = 'Stop'
$keygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
$lab    = Join-Path $env:USERPROFILE 'Downloads\SplunkPkcs11Lab'
$src    = Get-ChildItem -LiteralPath $lab -Recurse -Filter 'provider-marker.dll' | Select-Object -First 1
if (-not $src) { throw "provider-marker.dll not found under $lab" }

$dir = Join-Path $lab ("bypass-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path "$dir\sub", "$dir\markers", "$dir\out" | Out-Null
Copy-Item $src.FullName "$dir\evil.dll"
Copy-Item $src.FullName "$dir\signed.dll"
$full = "$dir\evil.dll"

# Self-signed code-signing cert (NOT trusted, removed at the end) to see what Sysmon reports for Signed/SignatureStatus
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=PKCS11 Lab Self-Signed' -CertStoreLocation Cert:\CurrentUser\My
try {
    Set-AuthenticodeSignature -FilePath "$dir\signed.dll" -Certificate $cert | Out-Null

    $cases = [ordered]@{
        'baseline_absolute' = "-D `"$full`""
        'relative_dot'      = '-D .\evil.dll'
        'bare_name_cwd'     = '-D evil.dll'
        'no_extension'      = '-D evil'
        'forward_slashes'   = "-D `"$($full -replace '\\','/')`""
        'dot_dot_segment'   = "-D `"$dir\sub\..\evil.dll`""
        'cluster_qD'        = "-qD `"$full`""
        'cluster_vvvD'      = "-vvvD `"$full`""
        'self_signed'       = "-D `"$dir\signed.dll`""
    }

    $start = (Get-Date).AddSeconds(-2)
    $runs = foreach ($name in $cases.Keys) {
        $marker = "$dir\markers\$name.txt"
        $env:SPLUNK_PKCS11_LAB_MARKER = $marker
        $p = Start-Process -FilePath $keygen -ArgumentList $cases[$name] -WorkingDirectory $dir `
             -NoNewWindow -Wait -PassThru `
             -RedirectStandardOutput "$dir\out\$name.stdout.txt" -RedirectStandardError "$dir\out\$name.stderr.txt"
        [pscustomobject]@{ Case = $name; ProcessId = $p.Id; Exit = $p.ExitCode; CallbackRan = (Test-Path -LiteralPath $marker) }
    }
    Remove-Item Env:\SPLUNK_PKCS11_LAB_MARKER -ErrorAction SilentlyContinue
}
finally {
    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 5   # let Sysmon flush

$parsed = foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 7; StartTime = $start }) {
    $xml = $e.ToXml()
    $d = @{}
    foreach ($n in ([xml]$xml).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    if ($d['Image'] -like '*\ssh-keygen.exe') { [pscustomobject]@{ Id = $e.Id; D = $d; Xml = $xml } }
}

$report = foreach ($r in $runs) {
    $pc    = $parsed | Where-Object { $_.Id -eq 1 -and $_.D['ProcessId'] -eq [string]$r.ProcessId } | Select-Object -First 1
    $guid  = if ($pc) { $pc.D['ProcessGuid'] } else { $null }
    $loads = @($parsed | Where-Object { $_.Id -eq 7 -and $guid -and $_.D['ProcessGuid'] -eq $guid -and
                 $_.D['ImageLoaded'] -notmatch '^[a-z]:\\(windows|program files[^\\]*)\\' })
    [pscustomobject]@{
        Case            = $r.Case
        CallbackRan     = $r.CallbackRan
        ExitCode        = $r.Exit
        SysmonEvent1    = [bool]$pc
        CommandLine     = if ($pc) { $pc.D['CommandLine'] } else { '' }
        ImageLoaded     = ($loads | ForEach-Object { $_.D['ImageLoaded'] }) -join '; '
        Signed          = ($loads | ForEach-Object { $_.D['Signed'] }) -join '; '
        SignatureStatus = ($loads | ForEach-Object { $_.D['SignatureStatus'] }) -join '; '
    }
}

$report | Format-List
$report | Export-Csv -LiteralPath "$dir\bypass-report.csv" -NoTypeInformation

# Raw events, one XML event per line.
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllLines("$dir\bypass-sysmon.log", [string[]]($parsed | ForEach-Object { $_.Xml }), $utf8)

Write-Output "Folder:  $dir"
Write-Output "Events:  $(@($parsed).Count) ssh-keygen Sysmon 1/7 events -> bypass-sysmon.log"
