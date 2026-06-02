Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinSCard {
    [DllImport("winscard.dll")]
    public static extern int SCardEstablishContext(uint dwScope, IntPtr r1, IntPtr r2, out IntPtr phContext);
    [DllImport("winscard.dll")]
    public static extern int SCardListReaders(IntPtr hContext, string mszGroups, StringBuilder mszReaders, ref uint pcchReaders);
    [DllImport("winscard.dll")]
    public static extern int SCardReleaseContext(IntPtr hContext);
}
'@

$ctx = [IntPtr]::Zero
$r = [WinSCard]::SCardEstablishContext(2, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ctx)
Write-Host ("EstablishContext: 0x{0:X8}" -f $r)

$len = [uint32]4096
$sb  = New-Object System.Text.StringBuilder 4096
$r2  = [WinSCard]::SCardListReaders($ctx, $null, $sb, [ref]$len)
Write-Host ("ListReaders: 0x{0:X8}" -f $r2)

if ($r2 -eq 0) {
    $raw     = $sb.ToString()
    $readers = $raw.Split([char]0) | Where-Object { $_ -ne '' }
    Write-Host "Readers ($($readers.Count)):"
    $readers | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "No readers or error"
}

[WinSCard]::SCardReleaseContext($ctx) | Out-Null
