# sign_and_deploy.ps1 - Sign DLL and deploy to System32
# Run as Administrator

$dllPath = "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\ksp\build\OpenCertKSP.dll"
$destPath = "C:\WINDOWS\System32\OpenCertKSP.dll"

# Find Finnox cert
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -like "*Finnox*" }
if (-not $cert) {
    Write-Host "[FAIL] Finnox certificate not found!" -ForegroundColor Red
    exit 1
}
Write-Host "[1] Using certificate: $($cert.Subject.Substring(0, 60))..." -ForegroundColor Green
Write-Host "    Thumbprint: $($cert.Thumbprint)"

# Sign
Write-Host "[2] Signing DLL..." -ForegroundColor Yellow
$result = Set-AuthenticodeSignature -FilePath $dllPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256
Write-Host "    Status: $($result.Status)"
if ($result.Status -ne "Valid") {
    Write-Host "[FAIL] Signing failed!" -ForegroundColor Red
    exit 1
}

# Deploy
Write-Host "[3] Deploying to System32..." -ForegroundColor Yellow
Copy-Item $dllPath $destPath -Force
Write-Host "    [OK] Deployed" -ForegroundColor Green

# Verify
Write-Host "[4] Verifying..." -ForegroundColor Yellow
$sig = Get-AuthenticodeSignature $destPath
Write-Host "    Status: $($sig.Status), Type: $($sig.SignatureType)"

# Clean old log
Remove-Item "C:\ksp_debug.log" -ErrorAction SilentlyContinue

# Test
Write-Host "[5] Testing NCryptOpenStorageProvider..." -ForegroundColor Yellow
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NTest2 {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
}
"@

$h = [IntPtr]::Zero
$r = [NTest2]::NCryptOpenStorageProvider([ref]$h, "OpenCert Key Storage Provider", 0)
Write-Host ("    Result: 0x{0:X8}" -f $r)
if ($r -eq 0) {
    Write-Host "    [OK] SUCCESS!" -ForegroundColor Green
    [NTest2]::NCryptFreeObject($h) | Out-Null
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}

# Check debug log
Write-Host "[6] Debug log:" -ForegroundColor Yellow
if (Test-Path "C:\ksp_debug.log") {
    Get-Content "C:\ksp_debug.log"
} else {
    Write-Host "    No log - DLL was NOT loaded by CNG"
}
