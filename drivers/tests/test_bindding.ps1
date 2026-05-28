# check_keyprov.ps1 - 检查证书的 KeyProvInfo 属性
# 用法: powershell -ExecutionPolicy Bypass -File check_keyprov.ps1

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CertHelper {
    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CertGetCertificateContextProperty(
        IntPtr pCertContext, int dwPropId, IntPtr pvData, ref int pcbData);

    // CERT_KEY_PROV_INFO_PROP_ID = 2
    public const int CERT_KEY_PROV_INFO_PROP_ID = 2;

    public static string GetKeyProvInfo(IntPtr certCtx) {
        int size = 0;
        CertGetCertificateContextProperty(certCtx, CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref size);
        if (size == 0) return "NO KeyProvInfo property!";

        IntPtr buf = Marshal.AllocHGlobal(size);
        try {
            if (!CertGetCertificateContextProperty(certCtx, CERT_KEY_PROV_INFO_PROP_ID, buf, ref size)) {
                return "GetProperty FAILED: " + Marshal.GetLastWin32Error();
            }
            // CRYPT_KEY_PROV_INFO layout on x64:
            // offset 0:  LPWSTR pwszContainerName (8 bytes)
            // offset 8:  LPWSTR pwszProvName      (8 bytes)
            // offset 16: DWORD  dwProvType        (4 bytes)
            // offset 20: DWORD  dwFlags           (4 bytes)
            // offset 24: DWORD  cProvParam        (4 bytes)
            // offset 28: [4 bytes padding]
            // offset 32: PCRYPT_KEY_PROV_PARAM rgProvParam (8 bytes)
            // offset 40: DWORD  dwKeySpec         (4 bytes)
            IntPtr containerPtr = Marshal.ReadIntPtr(buf, 0);
            IntPtr provNamePtr = Marshal.ReadIntPtr(buf, 8);
            int provType = Marshal.ReadInt32(buf, 16);
            int flags = Marshal.ReadInt32(buf, 20);
            int paramCount = Marshal.ReadInt32(buf, 24);
            IntPtr paramsPtr = Marshal.ReadIntPtr(buf, 32);
            int keySpec = Marshal.ReadInt32(buf, 40);

            string container = containerPtr != IntPtr.Zero ? Marshal.PtrToStringUni(containerPtr) : "(null)";
            string provName = provNamePtr != IntPtr.Zero ? Marshal.PtrToStringUni(provNamePtr) : "(null)";

            return string.Format("Container={0}, Provider={1}, ProvType={2}, Flags={3}, ParamCount={4}, KeySpec=0x{5:X} (size={6})",
                container, provName, provType, flags, paramCount, (uint)keySpec, size);
        } finally {
            Marshal.FreeHGlobal(buf);
        }
    }
}
"@

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Certificate KeyProvInfo Inspector" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("MY", "CurrentUser")
$store.Open("ReadOnly")

$found = 0
foreach ($cert in $store.Certificates) {
    if ($cert.FriendlyName -like "OpenCert*") {
        $found++
        Write-Host "Certificate: $($cert.Subject)" -ForegroundColor White
        Write-Host "  FriendlyName: $($cert.FriendlyName)" -ForegroundColor Gray
        Write-Host "  Thumbprint:   $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "  HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor $(if($cert.HasPrivateKey){'Green'}else{'Red'})

        # 获取底层 CERT_CONTEXT 句柄
        $handle = $cert.Handle
        if ($handle -ne [IntPtr]::Zero) {
            $info = [CertHelper]::GetKeyProvInfo($handle)
            Write-Host "  KeyProvInfo:  $info" -ForegroundColor Yellow
        }

        # 尝试获取私钥
        try {
            $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($key) {
                Write-Host "  GetRSAPrivateKey: SUCCESS ($($key.GetType().Name))" -ForegroundColor Green
            } else {
                Write-Host "  GetRSAPrivateKey: returned NULL" -ForegroundColor Red
            }
        } catch {
            Write-Host "  GetRSAPrivateKey: EXCEPTION - $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

if ($found -eq 0) {
    Write-Host "  No OpenCert certificates found in MY store" -ForegroundColor Yellow
}

$store.Close()

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KSP Debug Log:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$logPath = "$env:TEMP\ksp_debug.log"
if (Test-Path $logPath) {
    Write-Host "  Log file: $logPath" -ForegroundColor Gray
    Get-Content $logPath -Tail 30
} else {
    $oldLogPath = "C:\Windows\Temp\ksp_debug.log"
    Write-Host "  Log not found at: $logPath" -ForegroundColor Yellow
    Write-Host "  Trying: $oldLogPath" -ForegroundColor Yellow
    if (Test-Path $oldLogPath -ErrorAction SilentlyContinue) {
        Get-Content $oldLogPath -Tail 30
    } else {
        Write-Host "  No KSP debug log found anywhere" -ForegroundColor Red
    }
}
