# register_proper.ps1 - Register KSP using BCryptRegisterProvider (the correct way)
# Must run as Administrator

Start-Transcript -Path "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\ksp\register_output.txt" -Force

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CngRegister {
    // CRYPT_IMAGE_REG
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPT_IMAGE_REG {
        public IntPtr pszImage;       // PWSTR
        public uint cInterfaces;
        public IntPtr rgpInterfaces;  // PCRYPT_INTERFACE_REG*
    }

    // CRYPT_INTERFACE_REG
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPT_INTERFACE_REG {
        public uint dwInterface;
        public uint dwFlags;
        public uint cFunctions;
        public IntPtr rgpszFunctions; // PWSTR*
    }

    // CRYPT_PROVIDER_REG
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPT_PROVIDER_REG {
        public uint cAliases;
        public IntPtr rgpszAliases;   // PWSTR*
        public IntPtr pUM;            // PCRYPT_IMAGE_REG
        public IntPtr pKM;            // PCRYPT_IMAGE_REG (NULL for user-mode only)
    }

    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptRegisterProvider(
        string pszProvider,
        uint dwFlags,
        ref CRYPT_PROVIDER_REG pReg
    );

    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptUnregisterProvider(string pszProvider);

    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptAddContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider, uint dwPosition
    );

    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int BCryptRemoveContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider
    );

    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);

    public const uint CRYPT_LOCAL = 1;
    public const uint NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001;
}
"@

$KSP_NAME = "OpenCert Key Storage Provider"
$KSP_IMAGE = "OpenCertKSP.dll"

Write-Host "=== Proper KSP Registration using BCryptRegisterProvider ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Unregister first (clean slate)
Write-Host "[1] Unregistering existing provider..." -ForegroundColor Yellow
$unregStatus = [CngRegister]::BCryptUnregisterProvider($KSP_NAME)
Write-Host ("    BCryptUnregisterProvider: 0x{0:X8}" -f $unregStatus)

# Also remove from context
[CngRegister]::BCryptRemoveContextFunctionProvider(
    [CngRegister]::CRYPT_LOCAL, "Default",
    [CngRegister]::NCRYPT_KEY_STORAGE_INTERFACE,
    "KEY_STORAGE", $KSP_NAME) | Out-Null

# Step 2: Build registration structures
Write-Host ""
Write-Host "[2] Building registration structures..." -ForegroundColor Yellow

# Allocate function name string
$funcName = "KEY_STORAGE"
$pFuncName = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($funcName)

# Array of function name pointers (1 element)
$pFuncArray = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($pFuncArray, $pFuncName)

# CRYPT_INTERFACE_REG
$interfaceReg = New-Object CngRegister+CRYPT_INTERFACE_REG
$interfaceReg.dwInterface = [CngRegister]::NCRYPT_KEY_STORAGE_INTERFACE
$interfaceReg.dwFlags = 0
$interfaceReg.cFunctions = 1
$interfaceReg.rgpszFunctions = $pFuncArray

$pInterfaceReg = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
    [System.Runtime.InteropServices.Marshal]::SizeOf($interfaceReg))
[System.Runtime.InteropServices.Marshal]::StructureToPtr($interfaceReg, $pInterfaceReg, $false)

# Array of interface pointers (1 element)
$pInterfaceArray = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($pInterfaceArray, $pInterfaceReg)

# CRYPT_IMAGE_REG
$imageReg = New-Object CngRegister+CRYPT_IMAGE_REG
$pImageName = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($KSP_IMAGE)
$imageReg.pszImage = $pImageName
$imageReg.cInterfaces = 1
$imageReg.rgpInterfaces = $pInterfaceArray

$pImageReg = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
    [System.Runtime.InteropServices.Marshal]::SizeOf($imageReg))
[System.Runtime.InteropServices.Marshal]::StructureToPtr($imageReg, $pImageReg, $false)

# CRYPT_PROVIDER_REG
$provReg = New-Object CngRegister+CRYPT_PROVIDER_REG
$provReg.cAliases = 0
$provReg.rgpszAliases = [IntPtr]::Zero
$provReg.pUM = $pImageReg
$provReg.pKM = [IntPtr]::Zero

Write-Host "    [OK] Structures built"
Write-Host "    Image: $KSP_IMAGE"
Write-Host "    Interface: NCRYPT_KEY_STORAGE_INTERFACE"
Write-Host "    Function: KEY_STORAGE"

# Step 3: Register
Write-Host ""
Write-Host "[3] Calling BCryptRegisterProvider..." -ForegroundColor Yellow
$regStatus = [CngRegister]::BCryptRegisterProvider($KSP_NAME, 0, [ref]$provReg)
Write-Host ("    Result: 0x{0:X8}" -f $regStatus)
if ($regStatus -eq 0) {
    Write-Host "    [OK] Provider registered!" -ForegroundColor Green
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}

# Step 4: Add to default context
Write-Host ""
Write-Host "[4] Adding to default context..." -ForegroundColor Yellow
$addStatus = [CngRegister]::BCryptAddContextFunctionProvider(
    [CngRegister]::CRYPT_LOCAL, "Default",
    [CngRegister]::NCRYPT_KEY_STORAGE_INTERFACE,
    "KEY_STORAGE", $KSP_NAME, [uint32]::MaxValue)
Write-Host ("    Result: 0x{0:X8}" -f $addStatus)
if ($addStatus -eq 0) {
    Write-Host "    [OK] Added to context!" -ForegroundColor Green
} elseif ($addStatus -eq [int]0xC0000035) {
    Write-Host "    [OK] Already in context" -ForegroundColor Green
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}

# Step 5: Test
Write-Host ""
Write-Host "[5] Testing NCryptOpenStorageProvider..." -ForegroundColor Yellow
$hProv = [IntPtr]::Zero
$testResult = [CngRegister]::NCryptOpenStorageProvider([ref]$hProv, $KSP_NAME, 0)
Write-Host ("    Result: 0x{0:X8}" -f $testResult)
if ($testResult -eq 0) {
    Write-Host "    [OK] SUCCESS! KSP is working!" -ForegroundColor Green
    [CngRegister]::NCryptFreeObject($hProv) | Out-Null
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}

# Cleanup allocated memory
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pFuncName)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pFuncArray)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pInterfaceReg)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pInterfaceArray)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pImageName)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pImageReg)

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan

Stop-Transcript
