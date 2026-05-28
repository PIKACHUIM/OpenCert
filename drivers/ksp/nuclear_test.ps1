# nuclear_test.ps1 - Nuclear option: completely recreate registry from scratch
# and test with a renamed copy of SimplySign's DLL to isolate the issue
# Must run as Administrator

Start-Transcript -Path "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\ksp\nuclear_test_output.txt" -Force

Write-Host "=== Nuclear KSP Test ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This test will:" -ForegroundColor Yellow
Write-Host "  1. Create a test KSP using SimplySign's DLL (to verify registry works)"
Write-Host "  2. Then swap in our DLL (to verify DLL works)"
Write-Host ""

$testKspName = "TestKSP Provider"
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers"
$configBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\Default\00010001\KEY_STORAGE"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NuclearTest {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptAddContextFunctionProvider(uint t, string c, uint i, string f, string p, uint pos);
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptRemoveContextFunctionProvider(uint t, string c, uint i, string f, string p);
}
"@

# Step 1: Test with SimplySign's DLL under a different name
Write-Host "[1] Creating test copy of SimplySign DLL..." -ForegroundColor Yellow
Copy-Item "C:\WINDOWS\System32\SimplySignKSP.dll" "C:\WINDOWS\System32\TestKSP.dll" -Force
Write-Host "    [OK] TestKSP.dll created"

# Step 2: Register test KSP
Write-Host "[2] Registering test KSP..." -ForegroundColor Yellow
$testPath = "$regBase\$testKspName"
if (Test-Path $testPath) { Remove-Item $testPath -Recurse -Force }
New-Item -Path "$testPath\UM\00010001" -Force | Out-Null
Set-ItemProperty -Path "$testPath\UM" -Name "Image" -Value "TestKSP.dll" -Type String
Set-ItemProperty -Path "$testPath\UM\00010001" -Name "Flags" -Value 1 -Type DWord
Set-ItemProperty -Path "$testPath\UM\00010001" -Name "Functions" -Value @("KEY_STORAGE") -Type MultiString
Write-Host "    [OK] Registry created"

# Step 3: Add to CNG config
Write-Host "[3] Adding to CNG config..." -ForegroundColor Yellow
# CRYPT_PRIORITY_BOTTOM = 0xFFFFFFFF, use [uint32]::MaxValue
$status = [NuclearTest]::BCryptAddContextFunctionProvider(1, "Default", 0x00010001, "KEY_STORAGE", $testKspName, [uint32]::MaxValue)
Write-Host "    BCryptAddContextFunctionProvider: 0x$($status.ToString('X8'))"

# Step 4: Test
Write-Host "[4] Testing TestKSP (SimplySign DLL)..." -ForegroundColor Yellow
$h = [IntPtr]::Zero
$r = [NuclearTest]::NCryptOpenStorageProvider([ref]$h, $testKspName, 0)
Write-Host ("    Result: 0x{0:X8}" -f $r)
if ($r -eq 0) {
    Write-Host "    [OK] TestKSP with SimplySign DLL works!" -ForegroundColor Green
    [NuclearTest]::NCryptFreeObject($h) | Out-Null
} else {
    Write-Host "    [FAIL] Even SimplySign DLL fails under new name!" -ForegroundColor Red
    Write-Host "    This means the issue is NOT with our DLL but with registration!" -ForegroundColor Red
}

# Step 5: Now swap in our DLL
Write-Host ""
Write-Host "[5] Swapping in OpenCertKSP.dll..." -ForegroundColor Yellow
Copy-Item "C:\WINDOWS\System32\OpenCertKSP.dll" "C:\WINDOWS\System32\TestKSP.dll" -Force
Write-Host "    [OK] Swapped"

# Step 6: Test again
Write-Host "[6] Testing TestKSP (OpenCert DLL)..." -ForegroundColor Yellow
$h2 = [IntPtr]::Zero
$r2 = [NuclearTest]::NCryptOpenStorageProvider([ref]$h2, $testKspName, 0)
Write-Host ("    Result: 0x{0:X8}" -f $r2)
if ($r2 -eq 0) {
    Write-Host "    [OK] Our DLL works under test name!" -ForegroundColor Green
    [NuclearTest]::NCryptFreeObject($h2) | Out-Null
} else {
    Write-Host "    [FAIL] Our DLL fails even under test name!" -ForegroundColor Red
}

# Cleanup
Write-Host ""
Write-Host "[7] Cleaning up..." -ForegroundColor Yellow
[NuclearTest]::BCryptRemoveContextFunctionProvider(1, "Default", 0x00010001, "KEY_STORAGE", $testKspName) | Out-Null
Remove-Item $testPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\WINDOWS\System32\TestKSP.dll" -Force -ErrorAction SilentlyContinue
Write-Host "    [OK] Cleaned up"

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan

Stop-Transcript
