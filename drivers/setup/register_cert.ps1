# register_cert.ps1 - 注册 OpenCert KSP 到 Windows CNG
# 实际职责：通过 BCryptAddContextFunctionProvider 注册 KSP，并验证 NCryptOpenStorageProvider
#
# 必须以管理员身份运行。

param(
    [string]$KspName = "OpenCert Key Storage Provider",
    [string]$KspDll  = "OpenCertKSP.dll"
)

# ================================================================
# 辅助函数（统一 6 空格缩进）
# ================================================================
function Write-Ok   { param([string]$Msg) Write-Host "      [DONE] $Msg" -ForegroundColor Green  }
function Write-Warn { param([string]$Msg) Write-Host "      [WARN] $Msg" -ForegroundColor Yellow }
function Write-Info { param([string]$Msg) Write-Host "      [INFO] $Msg" -ForegroundColor Cyan   }
function Write-Fail { param([string]$Msg) Write-Host "      [FAIL] $Msg" -ForegroundColor Red    }

# ================================================================
# P/Invoke 定义
# ================================================================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CngReg {
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptAddContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider, uint dwPosition);

    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptRemoveContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider);

    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptEnumContextFunctionProviders(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, ref uint pcbBuffer, out IntPtr ppBuffer);

    [DllImport("bcrypt.dll")]
    public static extern void BCryptFreeBuffer(IntPtr pvBuffer);

    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);

    public const uint CRYPT_LOCAL = 1;
    public const uint NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001;
    public const uint CRYPT_PRIORITY_BOTTOM = 0xFFFFFFFF;
}
"@

# ================================================================
# Step 1: 注册 KSP
# ================================================================
Write-Info "Registering KSP: $KspName"

$status = [CngReg]::BCryptAddContextFunctionProvider(
    [CngReg]::CRYPT_LOCAL,
    "Default",
    [CngReg]::NCRYPT_KEY_STORAGE_INTERFACE,
    "KEY_STORAGE",
    $KspName,
    [CngReg]::CRYPT_PRIORITY_BOTTOM
)

if ($status -eq 0) {
    Write-Ok "BCryptAddContextFunctionProvider OK"
} elseif ($status -eq [int]0xC0000035) {
    Write-Ok "Already registered (NAME_COLLISION)"
} elseif ($status -eq [int]0xC0000022) {
    Write-Fail "Access denied! Run as Administrator"
    exit 1
} else {
    Write-Fail "BCryptAddContextFunctionProvider: 0x$($status.ToString('X8'))"
    exit 1
}

# ================================================================
# Step 2: 验证注册
# ================================================================
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
    $cProviders = [System.Runtime.InteropServices.Marshal]::ReadInt32($pBuffer, 0)
    $ourFound = $false
    for ($i = 0; $i -lt $cProviders; $i++) {
        $pStr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pBuffer, 8 + ($i * 8))
        $provName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pStr)
        if ($provName -eq $KspName) { $ourFound = $true }
    }
    [CngReg]::BCryptFreeBuffer($pBuffer)

    if ($ourFound) {
        Write-Ok "KSP found in provider list ($cProviders providers)"
    } else {
        Write-Warn "KSP not found in provider list"
    }
} else {
    Write-Warn "Cannot enumerate providers: 0x$($enumStatus.ToString('X8'))"
}

# ================================================================
# Step 3: 测试 NCryptOpenStorageProvider
# ================================================================
$hProv = [IntPtr]::Zero
$result = [CngReg]::NCryptOpenStorageProvider([ref]$hProv, $KspName, 0)
if ($result -eq 0) {
    Write-Ok "NCryptOpenStorageProvider verified"
    [CngReg]::NCryptFreeObject($hProv) | Out-Null
} else {
    Write-Fail "NCryptOpenStorageProvider: 0x$($result.ToString('X8'))"
    exit 1
}
