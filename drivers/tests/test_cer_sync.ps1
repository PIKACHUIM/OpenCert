$sig = Get-AuthenticodeSignature "C:\WINDOWS\System32\SimplySignKSP.dll"
Write-Host "=== SimplySign KSP Certificate ===" -ForegroundColor Cyan
Write-Host "Subject: $($sig.SignerCertificate.Subject)"
Write-Host "Issuer: $($sig.SignerCertificate.Issuer)"
Write-Host ""

Write-Host "EKU:" -ForegroundColor Yellow
$eku = $sig.SignerCertificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
if ($eku) {
    Write-Host $eku.Format(1)
} else {
    Write-Host "  (none)"
}

Write-Host ""
Write-Host "=== Our KSP Certificate ===" -ForegroundColor Cyan
$sig2 = Get-AuthenticodeSignature "C:\WINDOWS\System32\OpenCertKSP.dll"
Write-Host "Subject: $($sig2.SignerCertificate.Subject)"
Write-Host "Issuer: $($sig2.SignerCertificate.Issuer)"
Write-Host ""

Write-Host "EKU:" -ForegroundColor Yellow
$eku2 = $sig2.SignerCertificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
if ($eku2) {
    Write-Host $eku2.Format(1)
} else {
    Write-Host "  (none)"
}

# Also check if CNG is caching - try to load our DLL manually and see if GetKeyStorageInterface is called
Write-Host ""
Write-Host "=== Manual DLL test (to confirm DLL works) ===" -ForegroundColor Cyan
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ManualTest {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryW(string lpFileName);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr hModule);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=CharSet.Unicode)]
    public delegate int GetKSIDelegate(string name, out IntPtr table, uint flags);
}
"@

$h = [ManualTest]::LoadLibraryW("C:\WINDOWS\System32\OpenCertKSP.dll")
Write-Host "DLL loaded: 0x$($h.ToString('X'))"
$pfn = [ManualTest]::GetProcAddress($h, "GetKeyStorageInterface")
Write-Host "GetKeyStorageInterface: 0x$($pfn.ToString('X'))"
$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pfn, [ManualTest+GetKSIDelegate])
$tbl = [IntPtr]::Zero
$ret = $del.Invoke("OpenCert Key Storage Provider", [ref]$tbl, 0)
Write-Host "Result: 0x$($ret.ToString('X8')), table: 0x$($tbl.ToString('X'))"
[ManualTest]::FreeLibrary($h) | Out-Null

# Check if log was created
Write-Host ""
Write-Host "=== Debug log after manual call ===" -ForegroundColor Cyan
if (Test-Path "C:\ksp_debug.log") {
    Get-Content "C:\ksp_debug.log"
} else {
    Write-Host "No log file"
}
