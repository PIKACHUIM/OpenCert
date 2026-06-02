$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$bat  = Join-Path $here 'diag_plan_a.bat'
$log  = Join-Path $here 'diag_a_run.log'
if (Test-Path $log) { Remove-Item $log -Force }
$p = Start-Process -FilePath 'cmd.exe' `
    -ArgumentList @('/c', "$bat > `"$log`" 2>&1") `
    -Verb RunAs -PassThru -WindowStyle Hidden
$p.WaitForExit()
Write-Host "ExitCode=$($p.ExitCode)"
if (Test-Path $log) {
    Write-Host '----- diag_a_run.log -----'
    Get-Content $log
}
