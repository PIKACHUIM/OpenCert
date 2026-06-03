$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$bat  = Join-Path $here 'toggle_device.bat'
$log  = Join-Path $here 'toggle_device.log'
if (Test-Path $log) { Remove-Item $log -Force }

Write-Host "Running toggle_device.bat as Administrator..."
$p = Start-Process -FilePath 'cmd.exe' `
    -ArgumentList @('/c', "`"$bat`" > `"$log`" 2>&1") `
    -Verb RunAs -PassThru -WindowStyle Hidden
$p.WaitForExit()
Write-Host "ExitCode=$($p.ExitCode)"
if (Test-Path $log) {
    Write-Host '----- toggle_device.log -----'
    Get-Content $log
}

# 再次检查 PC/SC 读卡器
Write-Host ""
Write-Host "=== PC/SC Reader List ==="
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public class WinSCard4 {
    [DllImport("winscard.dll")] public static extern int SCardEstablishContext(uint s, IntPtr r1, IntPtr r2, out IntPtr h);
    [DllImport("winscard.dll")] public static extern int SCardListReaders(IntPtr h, string g, StringBuilder b, ref uint l);
    [DllImport("winscard.dll")] public static extern int SCardReleaseContext(IntPtr h);
}
'@
$ctx = [IntPtr]::Zero
[WinSCard4]::SCardEstablishContext(2, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ctx) | Out-Null
$len = [uint32]4096; $sb = New-Object System.Text.StringBuilder 4096
[WinSCard4]::SCardListReaders($ctx, $null, $sb, [ref]$len) | Out-Null
$sb.ToString().Split([char]0) | Where-Object { $_ -ne '' } | ForEach-Object { Write-Host "  - $_" }
[WinSCard4]::SCardReleaseContext($ctx) | Out-Null
