# test_sign.ps1 - 直接通过 NCrypt API 测试 KSP 签名
# 用法: powershell -ExecutionPolicy Bypass -File test_sign.ps1
# 必须在 client-card 后端运行时执行

param(
    [string]$KspName = "OpenCert Key Storage Provider"
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  OpenCert KSP Direct Sign Test" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# 查找 OpenCert 管理的证书
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("MY", "CurrentUser")
$store.Open("ReadOnly")

$targetCert = $null
foreach ($cert in $store.Certificates) {
    if ($cert.FriendlyName -like "OpenCert*" -and $cert.HasPrivateKey) {
        $targetCert = $cert
        Write-Host "[INFO] Using certificate: $($cert.Subject)" -ForegroundColor White
        Write-Host "       Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
        break
    }
}
$store.Close()

if (-not $targetCert) {
    Write-Host "[FAIL] No OpenCert certificate with private key found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[1/4] Testing NCryptOpenStorageProvider..." -ForegroundColor Yellow

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NCryptSignTest {
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptSignHash(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, int cbSignature, out int pcbResult, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

    // BCRYPT_PAD_PKCS1 = 2
    public const int BCRYPT_PAD_PKCS1 = 2;
}
"@

$hProv = [IntPtr]::Zero
$status = [NCryptSignTest]::NCryptOpenStorageProvider([ref]$hProv, $KspName, 0)
if ($status -ne 0) {
    Write-Host "       [FAIL] NCryptOpenStorageProvider: 0x$($status.ToString('X8'))" -ForegroundColor Red
    exit 1
}
Write-Host "       [OK] Provider opened" -ForegroundColor Green

# 获取证书的容器名
Write-Host ""
Write-Host "[2/4] Getting container name from certificate..." -ForegroundColor Yellow

# 从 KeyProvInfo 中提取容器名
$handle = $targetCert.Handle
$size = 0
[CertHelper]::CertGetCertificateContextProperty($handle, 2, [IntPtr]::Zero, [ref]$size) | Out-Null
if ($size -gt 0) {
    $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    [CertHelper]::CertGetCertificateContextProperty($handle, 2, $buf, [ref]$size) | Out-Null
    $containerPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($buf, 0)
    $containerName = [Runtime.InteropServices.Marshal]::PtrToStringUni($containerPtr)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    Write-Host "       Container: $containerName" -ForegroundColor White
} else {
    Write-Host "       [FAIL] Cannot get KeyProvInfo" -ForegroundColor Red
    [NCryptSignTest]::NCryptFreeObject($hProv) | Out-Null
    exit 1
}

Write-Host ""
Write-Host "[3/4] Testing NCryptOpenKey..." -ForegroundColor Yellow

$hKey = [IntPtr]::Zero
$status = [NCryptSignTest]::NCryptOpenKey($hProv, [ref]$hKey, $containerName, 0, 0)
if ($status -ne 0) {
    Write-Host "       [FAIL] NCryptOpenKey: 0x$($status.ToString('X8'))" -ForegroundColor Red
    if ($status -eq [int]0x80090035) {
        Write-Host "       -> NTE_DEVICE_NOT_FOUND: client-card backend not running!" -ForegroundColor Yellow
    }
    [NCryptSignTest]::NCryptFreeObject($hProv) | Out-Null
    exit 1
}
Write-Host "       [OK] Key opened (handle=0x$($hKey.ToString('X')))" -ForegroundColor Green

Write-Host ""
Write-Host "[4/4] Testing NCryptSignHash..." -ForegroundColor Yellow

# 创建一个测试 SHA-256 哈希值（32 字节）
$testHash = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($testHash)

# 先查询签名大小
$sigSize = 0
$status = [NCryptSignTest]::NCryptSignHash($hKey, [IntPtr]::Zero, $testHash, 32, $null, 0, [ref]$sigSize, [NCryptSignTest]::BCRYPT_PAD_PKCS1)
if ($status -ne 0) {
    Write-Host "       [FAIL] NCryptSignHash (size query): 0x$($status.ToString('X8'))" -ForegroundColor Red
    if ($status -eq [int]0x80090035) {
        Write-Host "       -> NTE_DEVICE_NOT_FOUND: client-card backend not running!" -ForegroundColor Yellow
    }
    [NCryptSignTest]::NCryptFreeObject($hKey) | Out-Null
    [NCryptSignTest]::NCryptFreeObject($hProv) | Out-Null
    exit 1
}

Write-Host "       Expected signature size: $sigSize bytes" -ForegroundColor Gray

# 执行签名
$signature = New-Object byte[] $sigSize
$actualSize = 0
$status = [NCryptSignTest]::NCryptSignHash($hKey, [IntPtr]::Zero, $testHash, 32, $signature, $sigSize, [ref]$actualSize, [NCryptSignTest]::BCRYPT_PAD_PKCS1)
if ($status -eq 0) {
    Write-Host "       [OK] Signature successful! ($actualSize bytes)" -ForegroundColor Green
    Write-Host "       First 16 bytes: $([BitConverter]::ToString($signature, 0, [Math]::Min(16, $actualSize)))" -ForegroundColor Gray
} else {
    Write-Host "       [FAIL] NCryptSignHash: 0x$($status.ToString('X8'))" -ForegroundColor Red
    if ($status -eq [int]0x80090035) {
        Write-Host "       -> NTE_DEVICE_NOT_FOUND: client-card backend not running!" -ForegroundColor Yellow
    } elseif ($status -eq [int]0x80090020) {
        Write-Host "       -> NTE_INTERNAL_ERROR: IPC communication failed" -ForegroundColor Yellow
    }
}

# 清理
[NCryptSignTest]::NCryptFreeObject($hKey) | Out-Null
[NCryptSignTest]::NCryptFreeObject($hProv) | Out-Null

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KSP Debug Log (last 10 lines):" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$logPath = "$env:TEMP\ksp_debug.log"
if (Test-Path $logPath) {
    Get-Content $logPath -Tail 10
} else {
    Write-Host "  No log file found at $logPath" -ForegroundColor Yellow
}
Write-Host ""
