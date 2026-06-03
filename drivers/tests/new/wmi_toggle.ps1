$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$log  = Join-Path $here 'wmi_toggle.log'

$script = @'
$dev = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -eq "ROOT\OPENCERTFIDO\0000" }
if ($dev) {
    Write-Host "Found: $($dev.Name)"
    Write-Host "Status: $($dev.Status)"
    $r1 = $dev.Disable()
    Write-Host "Disable result: $($r1.ReturnValue)"
    Start-Sleep 2
    $r2 = $dev.Enable()
    Write-Host "Enable result: $($r2.ReturnValue)"
    Start-Sleep 3
    $dev2 = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -eq "ROOT\OPENCERTFIDO\0000" }
    Write-Host "New Status: $($dev2.Status)"
} else {
    Write-Host "Device not found"
}
'@

Write-Host "Running WMI toggle as Administrator..."
$p = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $script, '>', "`"$log`"", '2>&1') `
    -Verb RunAs -PassThru -WindowStyle Hidden
$p.WaitForExit()
Write-Host "ExitCode=$($p.ExitCode)"
if (Test-Path $log) {
    Get-Content $log
}
