# register_ksp.ps1 - Register OpenCert KSP via BCryptRegisterProvider API
# Usage: powershell -ExecutionPolicy Bypass -File register_ksp.ps1 -KspName "..." -KspDll "..."
param(
    [string]$KspName = "OpenCert Key Storage Provider",
    [string]$KspDll = "OpenCertKSP.dll"
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class KspReg {
    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_IMAGE_REG {
        public IntPtr pszImage;
        public uint cInterfaces;
        public IntPtr rgpInterfaces;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_INTERFACE_REG {
        public uint dwInterface;
        public uint dwFlags;
        public uint cFunctions;
        public IntPtr rgpszFunctions;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_PROVIDER_REG {
        public uint cAliases;
        public IntPtr rgpszAliases;
        public IntPtr pUM;
        public IntPtr pKM;
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptUnregisterProvider(string pszProvider);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptRegisterProvider(string pszProvider, uint dwFlags, ref CRYPT_PROVIDER_REG pReg);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptAddContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider, uint dwPosition);
}
"@

# Step 1: Unregister existing provider (ignore errors)
[KspReg]::BCryptUnregisterProvider($KspName) | Out-Null

# Step 2: Build registration structures
# Function name: KEY_STORAGE
$fnPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni('KEY_STORAGE')
$fnArray = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
[Runtime.InteropServices.Marshal]::WriteIntPtr($fnArray, $fnPtr)

# Interface: NCRYPT_KEY_STORAGE_INTERFACE (0x00010001)
$ifc = New-Object KspReg+CRYPT_INTERFACE_REG
$ifc.dwInterface = 0x00010001
$ifc.dwFlags = 0
$ifc.cFunctions = 1
$ifc.rgpszFunctions = $fnArray

$ifcPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($ifc))
[Runtime.InteropServices.Marshal]::StructureToPtr($ifc, $ifcPtr, $false)

$ifcArray = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
[Runtime.InteropServices.Marshal]::WriteIntPtr($ifcArray, $ifcPtr)

# Image registration (User Mode)
$img = New-Object KspReg+CRYPT_IMAGE_REG
$img.pszImage = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($KspDll)
$img.cInterfaces = 1
$img.rgpInterfaces = $ifcArray

$imgPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($img))
[Runtime.InteropServices.Marshal]::StructureToPtr($img, $imgPtr, $false)

# Provider registration
$prv = New-Object KspReg+CRYPT_PROVIDER_REG
$prv.cAliases = 0
$prv.rgpszAliases = [IntPtr]::Zero
$prv.pUM = $imgPtr
$prv.pKM = [IntPtr]::Zero

# Step 3: Register provider
$status = [KspReg]::BCryptRegisterProvider($KspName, 0, [ref]$prv)
if ($status -ne 0) {
    Write-Host "BCryptRegisterProvider failed: 0x$($status.ToString('X8'))"
    exit 1
}

# Step 4: Add to Default context
# STATUS_OBJECT_NAME_COLLISION (0xC0000035) means already exists, which is OK
$status2 = [KspReg]::BCryptAddContextFunctionProvider(
    1,              # CRYPT_LOCAL (local machine)
    'Default',      # Default context
    0x00010001,     # NCRYPT_KEY_STORAGE_INTERFACE
    'KEY_STORAGE',  # Function name
    $KspName,       # Provider name
    [uint32]::MaxValue  # CRYPT_PRIORITY_BOTTOM
)

if ($status2 -ne 0 -and $status2 -ne 0xC0000035) {
    Write-Host "BCryptAddContextFunctionProvider failed: 0x$($status2.ToString('X8'))"
    exit 1
}

Write-Host "KSP '$KspName' registered successfully (DLL: $KspDll)"
exit 0