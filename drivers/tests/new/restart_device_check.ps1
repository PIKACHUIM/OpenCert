Write-Host "=== Step 1: Restart device ==="
pnputil /restart-device "ROOT\OPENCERTFIDO\0000" 2>&1
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "=== Step 2: Check Exclusive registry value ==="
$excl = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\OPENCERTFIDO\0000\Device Parameters\WUDF" -Name "Exclusive" -ErrorAction SilentlyContinue
if ($excl) {
    Write-Host "  Exclusive = $($excl.Exclusive)"
} else {
    Write-Host "  Exclusive key not found"
}

Write-Host ""
Write-Host "=== Step 3: PC/SC Reader List ==="
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinSCard3 {
    [DllImport("winscard.dll")]
    public static extern int SCardEstablishContext(uint dwScope, IntPtr r1, IntPtr r2, out IntPtr phContext);
    [DllImport("winscard.dll")]
    public static extern int SCardListReaders(IntPtr hContext, string mszGroups, StringBuilder mszReaders, ref uint pcchReaders);
    [DllImport("winscard.dll")]
    public static extern int SCardReleaseContext(IntPtr hContext);
}
'@

$ctx = [IntPtr]::Zero
[WinSCard3]::SCardEstablishContext(2, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ctx) | Out-Null
$len = [uint32]4096
$sb  = New-Object System.Text.StringBuilder 4096
$r   = [WinSCard3]::SCardListReaders($ctx, $null, $sb, [ref]$len)
Write-Host ("  ListReaders: 0x{0:X8}" -f $r)
$sb.ToString().Split([char]0) | Where-Object { $_ -ne '' } | ForEach-Object { Write-Host "  - $_" }
[WinSCard3]::SCardReleaseContext($ctx) | Out-Null
