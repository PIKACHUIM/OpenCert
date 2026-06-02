Restart-Service SCardSvr -Force
Start-Sleep -Seconds 2
Write-Host "SCardSvr restarted"

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinSCard2 {
    [DllImport("winscard.dll")]
    public static extern int SCardEstablishContext(uint dwScope, IntPtr r1, IntPtr r2, out IntPtr phContext);
    [DllImport("winscard.dll")]
    public static extern int SCardListReaders(IntPtr hContext, string mszGroups, StringBuilder mszReaders, ref uint pcchReaders);
    [DllImport("winscard.dll")]
    public static extern int SCardReleaseContext(IntPtr hContext);
}
'@

$ctx = [IntPtr]::Zero
[WinSCard2]::SCardEstablishContext(2, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ctx) | Out-Null

$len = [uint32]4096
$sb  = New-Object System.Text.StringBuilder 4096
$r   = [WinSCard2]::SCardListReaders($ctx, $null, $sb, [ref]$len)
Write-Host ("ListReaders result: 0x{0:X8}" -f $r)

$readers = $sb.ToString().Split([char]0) | Where-Object { $_ -ne '' }
Write-Host "Readers ($($readers.Count)):"
$readers | ForEach-Object { Write-Host "  - $_" }

[WinSCard2]::SCardReleaseContext($ctx) | Out-Null
