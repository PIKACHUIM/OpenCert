# fix_registry_final.ps1 - Fix the last registry differences
# Must run as Administrator

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider"

Write-Host "=== Fixing Registry (matching SimplySign structure) ===" -ForegroundColor Cyan
Write-Host ""

# 1. Delete the empty (Default) value
Write-Host "[1] Removing empty (Default) value..." -ForegroundColor Yellow
try {
    # PowerShell can't easily delete default values, use reg.exe
    $null = reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider" /ve /f 2>&1
    Write-Host "    [OK]" -ForegroundColor Green
} catch {
    Write-Host "    [INFO] $($_.Exception.Message)"
}

# 2. Add Aliases value (like SimplySign has "SimplySign CSP")
Write-Host "[2] Adding Aliases value..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path $regPath -Name "Aliases" -Value @("OpenCert CSP") -Type MultiString
    Write-Host "    [OK] Aliases = OpenCert CSP" -ForegroundColor Green
} catch {
    Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Verify
Write-Host ""
Write-Host "[3] Verifying..." -ForegroundColor Yellow
$key = Get-Item $regPath
Write-Host "    Values: $($key.GetValueNames() -join ', ')"
foreach ($vn in $key.GetValueNames()) {
    $val = $key.GetValue($vn)
    $dn = if ($vn -eq "") { "(Default)" } else { $vn }
    Write-Host "      $dn = $val"
}

# 4. Test
Write-Host ""
Write-Host "[4] Testing..." -ForegroundColor Yellow
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FinalTest2 {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
}
"@

$h = [IntPtr]::Zero
$r = [FinalTest2]::NCryptOpenStorageProvider([ref]$h, "OpenCert Key Storage Provider", 0)
Write-Host ("    NCryptOpenStorageProvider: 0x{0:X8}" -f $r)
if ($r -eq 0) {
    Write-Host "    [OK] SUCCESS!" -ForegroundColor Green
    [FinalTest2]::NCryptFreeObject($h) | Out-Null
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}
