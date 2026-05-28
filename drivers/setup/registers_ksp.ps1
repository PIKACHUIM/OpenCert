# register_ksp.ps1 - Register OpenCert KSP with CNG using BCryptAddContextFunctionProvider
# Must be run as Administrator

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CngReg {
    // BCryptAddContextFunctionProvider
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptAddContextFunctionProvider(
        uint dwTable,
        string pszContext,
        uint dwInterface,
        string pszFunction,
        string pszProvider,
        uint dwPosition
    );

    // BCryptRemoveContextFunctionProvider
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptRemoveContextFunctionProvider(
        uint dwTable,
        string pszContext,
        uint dwInterface,
        string pszFunction,
        string pszProvider
    );

    // BCryptEnumContextFunctionProviders
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptEnumContextFunctionProviders(
        uint dwTable,
        string pszContext,
        uint dwInterface,
        string pszFunction,
        ref uint pcbBuffer,
        out IntPtr ppBuffer
    );

    // BCryptFreeBuffer
    [DllImport("bcrypt.dll")]
    public static extern void BCryptFreeBuffer(IntPtr pvBuffer);

    // NCryptOpenStorageProvider
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);

    // Constants
    public const uint CRYPT_LOCAL = 1;
    public const uint NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001;
    public const uint CRYPT_PRIORITY_BOTTOM = 0xFFFFFFFF;
}
"@

$KSP_NAME = "OpenCert Key Storage Provider"

Write-Host "=== OpenCert KSP CNG Registration ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Register with BCryptAddContextFunctionProvider
Write-Host "[1] Registering KSP with CNG context..." -ForegroundColor Yellow
Write-Host "    Provider: $KSP_NAME"
Write-Host "    Context: Default"
Write-Host "    Interface: NCRYPT_KEY_STORAGE_INTERFACE"
Write-Host "    Function: KEY_STORAGE"
Write-Host ""

$status = [CngReg]::BCryptAddContextFunctionProvider(
    [CngReg]::CRYPT_LOCAL,          # dwTable
    "Default",                       # pszContext
    [CngReg]::NCRYPT_KEY_STORAGE_INTERFACE,  # dwInterface
    "KEY_STORAGE",                   # pszFunction
    $KSP_NAME,                       # pszProvider
    [CngReg]::CRYPT_PRIORITY_BOTTOM  # dwPosition
)

if ($status -eq 0) {
    Write-Host "    [OK] Successfully registered!" -ForegroundColor Green
} elseif ($status -eq [int]0xC0000035) {
    Write-Host "    [OK] Already registered (STATUS_OBJECT_NAME_COLLISION)" -ForegroundColor Green
} elseif ($status -eq [int]0xC0000022) {
    Write-Host "    [FAIL] Access denied! Please run as Administrator!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "    [FAIL] BCryptAddContextFunctionProvider: 0x$($status.ToString('X8'))" -ForegroundColor Red
    exit 1
}

# Step 2: Verify
Write-Host ""
Write-Host "[2] Verifying registration..." -ForegroundColor Yellow
$cbBuffer = [uint32]0
$pBuffer = [IntPtr]::Zero
$enumStatus = [CngReg]::BCryptEnumContextFunctionProviders(
    [CngReg]::CRYPT_LOCAL,
    "Default",
    [CngReg]::NCRYPT_KEY_STORAGE_INTERFACE,
    "KEY_STORAGE",
    [ref]$cbBuffer,
    [ref]$pBuffer
)

if ($enumStatus -eq 0 -and $pBuffer -ne [IntPtr]::Zero) {
    # CRYPT_CONTEXT_FUNCTION_PROVIDERS structure:
    # ULONG cProviders (offset 0)
    # PWSTR rgpszProviders[] (offset 8 on x64)
    $cProviders = [System.Runtime.InteropServices.Marshal]::ReadInt32($pBuffer, 0)
    Write-Host "    Registered KEY_STORAGE providers ($cProviders):" -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $cProviders; $i++) {
        $pStr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pBuffer, 8 + ($i * 8))
        $provName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pStr)
        $marker = if ($provName -eq $KSP_NAME) { " <-- OURS" } else { "" }
        Write-Host "      [$i] $provName$marker"
    }
    
    [CngReg]::BCryptFreeBuffer($pBuffer)
} else {
    Write-Host "    [WARN] Could not enumerate: 0x$($enumStatus.ToString('X8'))" -ForegroundColor Yellow
}

# Step 3: Test NCryptOpenStorageProvider
Write-Host ""
Write-Host "[3] Testing NCryptOpenStorageProvider..." -ForegroundColor Yellow
$hProv = [IntPtr]::Zero
$result = [CngReg]::NCryptOpenStorageProvider([ref]$hProv, $KSP_NAME, 0)
if ($result -eq 0) {
    Write-Host "    [OK] NCryptOpenStorageProvider SUCCESS!" -ForegroundColor Green
    [CngReg]::NCryptFreeObject($hProv) | Out-Null
} else {
    Write-Host "    [FAIL] NCryptOpenStorageProvider: 0x$($result.ToString('X8'))" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
