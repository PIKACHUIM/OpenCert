Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class QuickTest {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
}
"@

$h = [IntPtr]::Zero
$r = [QuickTest]::NCryptOpenStorageProvider([ref]$h, "OpenCert Key Storage Provider", 0)
Write-Host ("NCryptOpenStorageProvider Result: 0x{0:X8}" -f $r)
if ($r -eq 0) {
    Write-Host "[OK] SUCCESS!" -ForegroundColor Green
    [QuickTest]::NCryptFreeObject($h) | Out-Null
} else {
    Write-Host "[FAIL]" -ForegroundColor Red
}

# Also test certutil
Write-Host ""
Write-Host "certutil test:" -ForegroundColor Yellow
certutil -csp "OpenCert Key Storage Provider" -key 2>&1
