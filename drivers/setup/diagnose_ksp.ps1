# diagnose_ksp.ps1 - Diagnose OpenCert KSP registration and signing issues
# Usage: powershell -ExecutionPolicy Bypass -File diagnose_ksp.ps1
# Must run as Administrator

param(
    [string]$KspName = "OpenCert Key Storage Provider",
    [string]$KspDll = "OpenCertKSP.dll"
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  OpenCert KSP Diagnostic Tool" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$errors = 0

# ---- Test 1: DLL exists in System32 ----
Write-Host "[1/6] Checking KSP DLL..." -ForegroundColor Yellow
$dllPath = "$env:SystemRoot\System32\$KspDll"
if (Test-Path $dllPath) {
    $dll = Get-Item $dllPath
    Write-Host "      [OK] $dllPath ($($dll.Length) bytes)" -ForegroundColor Green
} else {
    Write-Host "      [FAIL] $dllPath NOT FOUND" -ForegroundColor Red
    $errors++
}

# ---- Test 2: Registry structure ----
Write-Host ""
Write-Host "[2/6] Checking CNG registry..." -ForegroundColor Yellow
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$KspName"
if (Test-Path $regPath) {
    Write-Host "      [OK] Provider key exists" -ForegroundColor Green
    $umPath = "$regPath\UM"
    if (Test-Path $umPath) {
        $image = (Get-ItemProperty $umPath -ErrorAction SilentlyContinue).Image
        if ($image) {
            Write-Host "      [OK] UM\Image = $image" -ForegroundColor Green
        } else {
            Write-Host "      [WARN] UM\Image not set" -ForegroundColor Yellow
        }
    } else {
        Write-Host "      [WARN] UM subkey not found (may use BCrypt registration)" -ForegroundColor Yellow
    }
} else {
    Write-Host "      [FAIL] Provider registry key NOT FOUND" -ForegroundColor Red
    Write-Host "      Expected: $regPath" -ForegroundColor Red
    $errors++
}

# ---- Test 3: NCryptOpenStorageProvider ----
Write-Host ""
Write-Host "[3/6] Testing NCryptOpenStorageProvider..." -ForegroundColor Yellow

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NCryptTest {
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptEnumKeys(IntPtr hProvider, string pszScope, out IntPtr ppKeyName, ref IntPtr ppEnumState, int dwFlags);
}
"@

$hProv = [IntPtr]::Zero
$status = [NCryptTest]::NCryptOpenStorageProvider([ref]$hProv, $KspName, 0)
if ($status -eq 0) {
    Write-Host "      [OK] NCryptOpenStorageProvider succeeded (handle=0x$($hProv.ToString('X')))" -ForegroundColor Green
} else {
    Write-Host "      [FAIL] NCryptOpenStorageProvider failed: 0x$($status.ToString('X8'))" -ForegroundColor Red
    $errors++
    if ($status -eq 0x80090013) {
        Write-Host "      -> NTE_BAD_PROVIDER: KSP not properly registered" -ForegroundColor Red
        Write-Host "      -> Run install.bat as Administrator to re-register" -ForegroundColor Yellow
    }
}

# ---- Test 4: NCryptEnumKeys ----
Write-Host ""
Write-Host "[4/6] Testing NCryptEnumKeys..." -ForegroundColor Yellow
if ($hProv -ne [IntPtr]::Zero) {
    $pKeyName = [IntPtr]::Zero
    $pEnumState = [IntPtr]::Zero
    $status2 = [NCryptTest]::NCryptEnumKeys($hProv, $null, [ref]$pKeyName, [ref]$pEnumState, 0)
    if ($status2 -eq 0) {
        Write-Host "      [OK] NCryptEnumKeys returned a key" -ForegroundColor Green
    } elseif ($status2 -eq [int]0x8009002A) {
        Write-Host "      [OK] NCryptEnumKeys: NTE_NO_MORE_ITEMS (no keys, but function works)" -ForegroundColor Green
    } elseif ($status2 -eq [int]0x80090035) {
        Write-Host "      [WARN] NCryptEnumKeys: NTE_DEVICE_NOT_FOUND (client-card backend not running?)" -ForegroundColor Yellow
    } elseif ($status2 -eq [int]0xC00000BB) {
        Write-Host "      [WARN] NCryptEnumKeys: NTE_NOT_SUPPORTED (old DLL without EnumKeys)" -ForegroundColor Yellow
    } else {
        Write-Host "      [WARN] NCryptEnumKeys returned: 0x$($status2.ToString('X8'))" -ForegroundColor Yellow
    }
    [NCryptTest]::NCryptFreeObject($hProv) | Out-Null
} else {
    Write-Host "      [SKIP] Provider not available" -ForegroundColor Gray
}

# ---- Test 5: Named Pipe availability ----
Write-Host ""
Write-Host "[5/6] Checking IPC Named Pipe..." -ForegroundColor Yellow
$pipePath = "\\.\pipe\clients"
$pipeExists = [System.IO.Directory]::GetFiles("\\.\pipe\", "clients")
if ($pipeExists.Count -gt 0) {
    Write-Host "      [OK] Named Pipe '$pipePath' is available (client-card is running)" -ForegroundColor Green
} else {
    Write-Host "      [WARN] Named Pipe '$pipePath' NOT available" -ForegroundColor Yellow
    Write-Host "      -> Start client-card backend first!" -ForegroundColor Yellow
}

# ---- Test 6: Certificate KeyProvInfo ----
Write-Host ""
Write-Host "[6/6] Checking certificates with OpenCert KSP..." -ForegroundColor Yellow
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("MY", "CurrentUser")
$store.Open("ReadOnly")
$found = 0
foreach ($cert in $store.Certificates) {
    # Check if cert has our KSP in its friendly name or issuer
    if ($cert.FriendlyName -like "OpenCert:*") {
        $found++
        Write-Host "      Found: $($cert.Subject) (FriendlyName: $($cert.FriendlyName))" -ForegroundColor White
        if ($cert.HasPrivateKey) {
            Write-Host "        -> HasPrivateKey = True" -ForegroundColor Green
        } else {
            Write-Host "        -> HasPrivateKey = False (KeyProvInfo may be missing or KSP unavailable)" -ForegroundColor Yellow
        }
    }
}
$store.Close()
if ($found -eq 0) {
    Write-Host "      [INFO] No OpenCert-managed certificates found in MY store" -ForegroundColor Gray
} else {
    Write-Host "      [INFO] Found $found OpenCert-managed certificate(s)" -ForegroundColor White
}

# ---- Summary ----
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($errors -eq 0) {
    Write-Host "  Result: ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host ""
    Write-Host "  If signing still fails (0x80092006), try:" -ForegroundColor White
    Write-Host "    1. Ensure client-card backend is running" -ForegroundColor White
    Write-Host "    2. Remove and re-add the certificate:" -ForegroundColor White
    Write-Host "       certutil -delstore -user My <thumbprint>" -ForegroundColor Gray
    Write-Host "       Then trigger cert sync in client-card" -ForegroundColor Gray
    Write-Host "    3. Check KSP debug log:" -ForegroundColor White
    Write-Host "       type C:\Windows\Temp\ksp_debug.log" -ForegroundColor Gray
} else {
    Write-Host "  Result: $errors ERROR(S) FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Fix steps:" -ForegroundColor White
    Write-Host "    1. Run install.bat as Administrator" -ForegroundColor White
    Write-Host "    2. Rebuild KSP DLL if needed (drivers\ksp\build.bat)" -ForegroundColor White
    Write-Host "    3. Re-run this diagnostic" -ForegroundColor White
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
