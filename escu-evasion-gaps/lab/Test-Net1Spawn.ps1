<#
.SYNOPSIS
  Tests whether `net <verb>` spawns net1.exe on this Windows host.
  Evidence for the process_net macro finding (net1-only coverage is OS-dependent).
  Run in an ADMINISTRATOR PowerShell (Win32_ProcessStartTrace needs elevation).
  All verbs below are READ-ONLY (they list, they don't change anything).
#>
function Test-Net1Spawn($verb) {
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='net1.exe'" -SourceIdentifier n1 -ErrorAction SilentlyContinue | Out-Null
    cmd /c "net $verb" > $null 2>&1
    Start-Sleep -Milliseconds 400
    $spawned = (Get-Event -SourceIdentifier n1 -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
    Unregister-Event n1 -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier n1 -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
    "{0,-12} -> net1 spawned: {1}" -f $verb, $spawned
}
"OS: " + (Get-CimInstance Win32_OperatingSystem).Caption + " build " + [System.Environment]::OSVersion.Version
"user","localgroup","accounts","share","use","view","session" | ForEach-Object { Test-Net1Spawn $_ }
