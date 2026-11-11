<#
.SYNOPSIS
    Fills the rename_runs / signer / original_file_name columns of the ESCU
    rename-gap tracker. For each binary it records:
        - its real signer and OriginalFileName (read-only, always collected)
        - whether a RENAMED copy still runs (only when you pass -Probe)

.WHY
    The ESCU "name_only" gap: a rule matches a process by file name, so a
    renamed copy of a Microsoft binary slips past. The fix is to also match
    OriginalFileName -- a value baked into the PE version resource that a
    rename does NOT change. This script reads that value for you (it is
    exactly what goes into the fix) and, optionally, confirms the renamed
    copy still executes.

.SAFETY (fail-closed)
    Defensive research for your own lab VM. Run as a NORMAL user (not admin).
      * Default run executes NOTHING -- it only reads file metadata and
        signatures. Run this first.
      * -Probe executes ONLY binaries on an explicit safe allowlist ($SafeArg),
        each with a harmless help/version flag, from a throwaway temp copy,
        with stdin closed (so REPLs cannot hang), output discarded, and a hard
        timeout that kills anything still running. ANY binary not on that
        allowlist is marked "manual" and never launched -- so destructive
        tools, GUI apps and interactive shells are skipped by default.

.OUTPUT
    rename_lab_results.csv with the columns the tracker reads:
        binary, found_path, signer, original_file_name, rename_runs
    plus product_name, probe_arg, note.
    rename_runs: yes | no | manual | notfound | (blank = metadata-only run)

.EXAMPLE
    .\Test-RenamedBinaries.ps1 -List .\rename_test_list.txt          # safe, no execution
    .\Test-RenamedBinaries.ps1 -List .\rename_test_list.txt -Probe   # run the safe allowlist
#>

[CmdletBinding()]
param(
    [string]$List = "rename_test_list.txt",
    [string]$Out  = "rename_lab_results.csv",
    [switch]$Probe,
    [int]$TimeoutSec = 6
)

$ErrorActionPreference = "Stop"

# --- ONLY these are ever executed. Everything else -> "manual". ---------------
# Pure information/help tools that print and exit. Value is the harmless arg.
$SafeArg = @{
    "whoami.exe"   = "/?"; "hostname.exe" = "/?"; "ipconfig.exe" = "/?"
    "getmac.exe"   = "/?"; "findstr.exe"  = "/?"; "find.exe"     = "/?"
    "attrib.exe"   = "/?"; "choice.exe"   = "/?"; "icacls.exe"   = "/?"
    "cacls.exe"    = "/?"; "xcacls.exe"   = "/?"; "takeown.exe"  = "/?"
    "certutil.exe" = "-?"; "bitsadmin.exe"= "/?"; "reg.exe"      = "/?"
    "sc.exe"       = "/?"; "arp.exe"      = "/?"; "route.exe"    = "/?"
    "netstat.exe"  = "/?"; "nbtstat.exe"  = "/?"; "tracert.exe"  = "/?"
    "pathping.exe" = "/?"; "w32tm.exe"    = "/?"; "klist.exe"    = "/?"
    "tasklist.exe" = "/?"; "setspn.exe"   = "/?"; "dsquery.exe"  = "/?"
    "dsget.exe"    = "/?"; "nltest.exe"   = "/?"; "gacutil.exe"  = "/?"
    "expand.exe"   = "/?"; "wevtutil.exe" = "/?"; "qwinsta.exe"  = "/?"
    "quser.exe"    = "/?"; "qprocess.exe" = "/?"; "query.exe"    = "/?"
    "net.exe"      = "/?"; "net1.exe"     = "/?"; "dism.exe"     = "/?"
    "vssadmin.exe" = "/?"; "regasm.exe"   = "/?"; "regsvcs.exe"  = "/?"
    "installutil.exe"="/?"; "cmdkey.exe"  = "/?"; "fltmc.exe"    = "/?"
    "appcmd.exe"   = "/?"; "systeminfo.exe"="/?"; "sfc.exe"      = "/?"
    "netdom.exe"   = "/?"; "curl.exe"     = "--version"
    "azcopy.exe"   = "--version"; "java.exe" = "-version"; "msbuild.exe" = "-version"
}

# Optional friendlier notes for the common binaries we deliberately skip.
# (Not required for safety -- anything missing here is still skipped.)
$SkipReason = @{}
foreach ($pair in @(
    @("logoff.exe","ends the session"), @("wusa.exe","installs updates"),
    @("sdbinst.exe","installs shim db"), @("msdt.exe","can execute (Follina)"),
    @("cmstp.exe","installs INF, executes"), @("infdefaultinstall.exe","installs INF"),
    @("pnputil.exe","driver install"), @("runonce.exe","runs RunOnce"),
    @("gpupdate.exe","forces policy refresh"), @("gpscript.exe","runs logon scripts"),
    @("wuauclt.exe","update client"), @("diskshadow.exe","shadow copy ops / interactive"),
    @("pcalua.exe","compat launcher"), @("pcwrun.exe","compat launcher"),
    @("scriptrunner.exe","runs a command"), @("syncappvpublishingserver.exe","runs PowerShell"),
    @("ieexec.exe","downloads+runs .NET"), @("presentationhost.exe","runs XBAP"),
    @("forfiles.exe","executes a command"), @("at.exe","schedules tasks"),
    @("schtasks.exe","schedules tasks"), @("verclsid.exe","COM init"),
    @("xwizard.exe","runs COM"), @("certoc.exe","loads DLL"),
    @("odbcconf.exe","loads DLL / regsvr"), @("mavinject.exe","DLL injection"),
    @("microsoft.workflow.compiler.exe","compiles+runs"), @("mofcomp.exe","compiles MOF"),
    @("regini.exe","writes registry"), @("ldifde.exe","imports to AD"),
    @("sqldumper.exe","process dump"), @("certreq.exe","cert enrollment"),
    @("aspnet_compiler.exe","compiles/executes"), @("addinutil.exe","loads add-ins"),
    @("ntdsutil.exe","AD DB tool (interactive)"), @("bcdedit.exe","edits boot config"),
    @("cipher.exe","can wipe free space"), @("fsutil.exe","some ops destructive"),
    @("vbc.exe","compiler"), @("dnscmd.exe","DNS admin"), @("rasautou.exe","dials"),
    @("msiexec.exe","installer"), @("runscripthelper.exe","runs scripts"),
    # GUI
    @("calc.exe","GUI"), @("win32calc.exe","GUI"), @("calculatorapp.exe","GUI"),
    @("notepad.exe","GUI"), @("wordpad.exe","GUI"), @("write.exe","GUI"),
    @("mspaint.exe","GUI"), @("taskmgr.exe","GUI"), @("msconfig.exe","GUI"),
    @("control.exe","GUI"), @("mstsc.exe","GUI"), @("dialer.exe","GUI"),
    @("dxdiag.exe","GUI"), @("msra.exe","GUI"), @("slui.exe","activation GUI"),
    @("hh.exe","help GUI"), @("winproj.exe","Project GUI"), @("wt.exe","Terminal GUI"),
    @("openconsole.exe","console host"), @("colorcpl.exe","GUI"),
    @("storageexplorer.exe","GUI"), @("mmc.exe","GUI console"), @("winhlp32.exe","legacy help GUI"),
    @("bitlockertogo.exe","BitLocker reader"), @("onedrivesetup.exe","installer"),
    @("pkgmgr.exe","package manager"),
    # interactive shells / REPLs / clients
    @("cmd.exe","interactive shell"), @("powershell.exe","interactive shell"),
    @("pwsh.exe","interactive shell"), @("powershell_ise.exe","GUI shell"),
    @("wmic.exe","interactive if no args"), @("nslookup.exe","interactive"),
    @("ftp.exe","interactive"), @("telnet.exe","interactive"), @("tftp.exe","network client"),
    @("python.exe","REPL"), @("pythonw.exe","no console"), @("py.exe","REPL"),
    @("pypy.exe","REPL"), @("perl.exe","reads stdin"), @("php.exe","reads stdin"),
    @("phpdbg.exe","debugger REPL"), @("ksh.exe","shell"), @("zsh.exe","shell"),
    @("tcc.exe","shell"), @("bash.exe","shell"), @("wsl.exe","launches Linux"),
    @("frankenphp.exe","server"), @("javaw.exe","no console output"),
    @("netsh.exe","interactive if no args"),
    # dialog-popping execution
    @("rundll32.exe","runs DLL / error dialog"), @("regsvr32.exe","runs DLL / dialog"),
    @("mshta.exe","renders HTA"), @("wscript.exe","GUI script host"),
    @("cscript.exe","runs scripts"), @("taskkill.exe","kills processes"),
    @("wab.exe","loads DLL"), @("extexport.exe","loads DLL"),
    @("settingsynchost.exe","runs cmd"), @("workfolders.exe","executes"),
    @("stordiag.exe","runs systeminfo/schtasks"), @("ttdinject.exe","TTD inject"),
    @("tttracer.exe","TTD trace"), @("appvlp.exe","App-V launcher"),
    @("offlinescannershell.exe","loads DLL"), @("atbroker.exe","switches assistive tech"),
    @("ie4uinit.exe","runs IE setup"), @("imewdbld.exe","downloads dictionary")
)) { $SkipReason[$pair[0]] = $pair[1] }

# --- resolve a binary to a real path -----------------------------------------
$SearchDirs = @(
    "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot",
    "$env:SystemRoot\System32\wbem", "$env:SystemRoot\System32\WindowsPowerShell\v1.0",
    "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319", "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319",
    "$env:SystemRoot\Microsoft.NET\Framework64\v2.0.50727", "$env:SystemRoot\Microsoft.NET\Framework\v2.0.50727"
)
function Resolve-Binary([string]$name) {
    foreach ($d in $SearchDirs) {
        $p = Join-Path $d $name
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandType -eq 'Application' } | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

# --- probe: does a renamed copy run? -----------------------------------------
function Test-RenamedRun([string]$srcPath, [string]$arg) {
    $tmp = Join-Path $env:TEMP ("rnm_{0}.exe" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    try {
        Copy-Item -LiteralPath $srcPath -Destination $tmp -Force
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName  = $tmp
        $psi.Arguments = $arg
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardInput  = $true
        $psi.CreateNoWindow         = $true
        $p = [Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill($true) } catch { try { $p.Kill() } catch {} }
            return @{ runs = "no"; note = "timeout/hang -> verify manually" }
        }
        return @{ runs = "yes"; note = "exit $($p.ExitCode)" }
    } catch {
        return @{ runs = "no"; note = "launch failed: $($_.Exception.Message)" }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# --- main --------------------------------------------------------------------
if ($List -match '\.xlsx$') {
    throw "Point -List at the plain-text rename_test_list.txt, not the .xlsx tracker."
}
if (-not (Test-Path -LiteralPath $List)) { throw "List not found: $List" }
$names = Get-Content -LiteralPath $List | ForEach-Object { $_.Trim() } |
         Where-Object { $_ -and -not $_.StartsWith('#') }

if (-not $Probe) {
    Write-Host "Metadata-only pass (no execution). Add -Probe to test renamed execution." -ForegroundColor Cyan
}

$rows = foreach ($name in $names) {
    $path = Resolve-Binary $name
    $signer = ""; $ofn = ""; $raw_ofn = ""; $product = ""; $runs = ""; $arg = ""; $note = ""

    if (-not $path) {
        $runs = "notfound"; $note = "not on this host"
    } else {
        try {
            $vi = (Get-Item -LiteralPath $path).VersionInfo
            $raw_ofn = $vi.OriginalFilename
            # PowerShell reads the version resource through MUI, which appends
            # ".MUI" (e.g. Cmd.Exe.MUI). Sysmon/EDR log the value WITHOUT it
            # (Cmd.Exe). Strip the suffix so the field matches real telemetry.
            $ofn = if ($raw_ofn) { $raw_ofn -replace '\.mui$','' } else { "" }
            $product = $vi.ProductName
        } catch { $note = "no version info"; $raw_ofn = "" }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $path
            $cn = ""
            if ($sig.SignerCertificate) {
                $cn = ($sig.SignerCertificate.Subject -split ',' |
                       Where-Object { $_ -match 'CN=' } | Select-Object -First 1) -replace '.*CN=',''
            }
            $signer = "$($sig.Status)$(if($cn){" / $cn"})"
        } catch { $signer = "unknown" }

        if ($Probe) {
            if ($SafeArg.ContainsKey($name)) {
                $arg = $SafeArg[$name]
                $r = Test-RenamedRun $path $arg
                $runs = $r.runs; $note = $r.note
            } else {
                $runs = "manual"
                $note = "not auto-run: " + $(if ($SkipReason.ContainsKey($name)) { $SkipReason[$name] } else { "not on safe allowlist -> test by hand" })
            }
        }
    }

    Write-Host ("{0,-28} {1,-8} {2}" -f $name, $runs, $ofn)
    [pscustomobject]@{
        binary             = $name
        found_path         = $path
        signer             = $signer
        original_file_name = $ofn
        raw_ofn            = $raw_ofn
        product_name       = $product
        rename_runs        = $runs
        probe_arg          = $arg
        note               = $note
    }
}

$rows | Export-Csv -LiteralPath $Out -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Wrote $Out ($($rows.Count) rows)." -ForegroundColor Green
$done   = ($rows | Where-Object { $_.rename_runs -in 'yes','no' }).Count
$manual = ($rows | Where-Object { $_.rename_runs -eq 'manual' }).Count
$nf     = ($rows | Where-Object { $_.rename_runs -eq 'notfound' }).Count
Write-Host "Probed: $done   Manual: $manual   Not on host: $nf"
Write-Host "Next: copy $Out next to rename_tracker.py and rerun it."
