# Check if NCrypt loads KSP in-process or via lsass
# Also check loaded modules

Write-Host "=== Checking where CNG loads KSP DLLs ===" -ForegroundColor Cyan

# First, call NCryptOpenStorageProvider for SimplySign and check if DLL is loaded in our process
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ProcTest {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr GetModuleHandleW(string lpModuleName);
}
"@

Write-Host ""
Write-Host "[1] Before NCryptOpenStorageProvider:" -ForegroundColor Yellow
$hSimply = [ProcTest]::GetModuleHandleW("SimplySignKSP.dll")
$hOurs = [ProcTest]::GetModuleHandleW("OpenCertKSP.dll")
Write-Host "    SimplySignKSP.dll loaded: $($hSimply -ne [IntPtr]::Zero) (0x$($hSimply.ToString('X')))"
Write-Host "    OpenCertKSP.dll loaded: $($hOurs -ne [IntPtr]::Zero) (0x$($hOurs.ToString('X')))"

Write-Host ""
Write-Host "[2] Calling NCryptOpenStorageProvider('SimplySign KSP')..." -ForegroundColor Yellow
$h = [IntPtr]::Zero
$r = [ProcTest]::NCryptOpenStorageProvider([ref]$h, "SimplySign KSP", 0)
Write-Host ("    Result: 0x{0:X8}" -f $r)

Write-Host ""
Write-Host "[3] After SimplySign open:" -ForegroundColor Yellow
$hSimply = [ProcTest]::GetModuleHandleW("SimplySignKSP.dll")
Write-Host "    SimplySignKSP.dll loaded: $($hSimply -ne [IntPtr]::Zero) (0x$($hSimply.ToString('X')))"
if ($r -eq 0) { [ProcTest]::NCryptFreeObject($h) | Out-Null }

Write-Host ""
Write-Host "[4] Calling NCryptOpenStorageProvider('OpenCert Key Storage Provider')..." -ForegroundColor Yellow
$h2 = [IntPtr]::Zero
$r2 = [ProcTest]::NCryptOpenStorageProvider([ref]$h2, "OpenCert Key Storage Provider", 0)
Write-Host ("    Result: 0x{0:X8}" -f $r2)

Write-Host ""
Write-Host "[5] After OpenCert open:" -ForegroundColor Yellow
$hOurs = [ProcTest]::GetModuleHandleW("OpenCertKSP.dll")
Write-Host "    OpenCertKSP.dll loaded: $($hOurs -ne [IntPtr]::Zero) (0x$($hOurs.ToString('X')))"

# Check debug log
Write-Host ""
Write-Host "[6] Debug log:" -ForegroundColor Yellow
if (Test-Path "C:\Windows\Temp\ksp_debug.log") {
    Get-Content "C:\Windows\Temp\ksp_debug.log"
} else {
    Write-Host "    No log"
}
