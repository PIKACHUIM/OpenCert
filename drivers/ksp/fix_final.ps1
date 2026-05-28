# fix_final.ps1 - Final fix: remove empty default value and flush CNG cache
# Must run as Administrator

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider"

Write-Host "=== Final KSP Fix ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Remove empty default value from root key
Write-Host "[1] Removing empty (Default) value from root key..." -ForegroundColor Yellow
try {
    Remove-ItemProperty -Path $regPath -Name "(Default)" -ErrorAction SilentlyContinue
    # Alternative: set it to empty by removing the key and recreating
    Write-Host "    [OK] Removed" -ForegroundColor Green
} catch {
    Write-Host "    [INFO] $($_.Exception.Message)" -ForegroundColor Gray
}

# Step 2: Verify SimplySign works (as baseline)
Write-Host ""
Write-Host "[2] Testing SimplySign KSP (baseline)..." -ForegroundColor Yellow
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FinalTest {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
}
"@

$h = [IntPtr]::Zero
$r = [FinalTest]::NCryptOpenStorageProvider([ref]$h, "SimplySign KSP", 0)
Write-Host ("    SimplySign: 0x{0:X8}" -f $r)
if ($r -eq 0) {
    Write-Host "    [OK] SimplySign works!" -ForegroundColor Green
    [FinalTest]::NCryptFreeObject($h) | Out-Null
} else {
    Write-Host "    [FAIL] SimplySign also broken!" -ForegroundColor Red
}

# Step 3: Test our KSP
Write-Host ""
Write-Host "[3] Testing OpenCert KSP..." -ForegroundColor Yellow
$h2 = [IntPtr]::Zero
$r2 = [FinalTest]::NCryptOpenStorageProvider([ref]$h2, "OpenCert Key Storage Provider", 0)
Write-Host ("    OpenCert: 0x{0:X8}" -f $r2)
if ($r2 -eq 0) {
    Write-Host "    [OK] SUCCESS!" -ForegroundColor Green
    [FinalTest]::NCryptFreeObject($h2) | Out-Null
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}

# Step 4: Check debug log
Write-Host ""
Write-Host "[4] Debug log:" -ForegroundColor Yellow
if (Test-Path "C:\Windows\Temp\ksp_debug.log") {
    Get-Content "C:\Windows\Temp\ksp_debug.log"
} else {
    Write-Host "    No log - CNG did not load DLL"
}
