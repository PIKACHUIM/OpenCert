$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$bat  = Join-Path $here 'reinstall_admin.bat'
$log  = Join-Path $here 'reinstall_admin.log'
if (Test-Path $log) { Remove-Item $log -Force }

Write-Host "Running reinstall_admin.bat as Administrator..."
$p = Start-Process -FilePath 'cmd.exe' `
    -ArgumentList @('/c', "`"$bat`" > `"$log`" 2>&1") `
    -Verb RunAs -PassThru -WindowStyle Hidden
$p.WaitForExit()
Write-Host "ExitCode=$($p.ExitCode)"
if (Test-Path $log) {
    Write-Host '----- reinstall_admin.log -----'
    Get-Content $log
}
