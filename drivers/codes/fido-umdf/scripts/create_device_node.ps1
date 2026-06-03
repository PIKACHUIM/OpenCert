# create_device_node.ps1
# Creates ROOT\OPENCERTFIDO virtual device node (replaces devcon.exe)
# Must run as Administrator

param(
    [string]$HardwareId = "ROOT\OPENCERTFIDO",
    [string]$InfFile = ""
)

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Please run as Administrator!" -ForegroundColor Red
    exit 1
}

# Auto-locate INF file
if ($InfFile -eq "") {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    # 优先使用 build\ 目录（DLL 和 INF 在同一目录，CopyFiles 才能找到 DLL）
    $buildInf = Join-Path $scriptDir "..\..\..\build\FidoMdfDriver.inf"
    $buildInf = [System.IO.Path]::GetFullPath($buildInf)
    if (Test-Path $buildInf) {
        $InfFile = $buildInf
    } else {
        # 回退到 inf\ 目录（仅用于调试，CopyFiles 会失败）
        $InfFile = Join-Path $scriptDir "..\inf\FidoMdfDriver.inf"
        $InfFile = [System.IO.Path]::GetFullPath($InfFile)
        Write-Host "[WARN] build\FidoMdfDriver.inf not found, using source inf (DLL copy may fail)" -ForegroundColor Yellow
    }
}

Write-Host "HardwareId : $HardwareId"
Write-Host "INF File   : $InfFile"

if (-not (Test-Path $InfFile)) {
    Write-Host "[ERROR] INF file not found: $InfFile" -ForegroundColor Red
    exit 1
}

# Load Win32 API via Add-Type
# NOTE: here-string terminator '@' must be at column 0 with no leading spaces
$csharpCode = @'
using System;
using System.Runtime.InteropServices;

public class DevNodeHelper
{
    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern IntPtr SetupDiCreateDeviceInfoList(
        ref Guid ClassGuid,
        IntPtr hwndParent);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool SetupDiCreateDeviceInfo(
        IntPtr DeviceInfoSet,
        string DeviceName,
        ref Guid ClassGuid,
        string DeviceDescription,
        IntPtr hwndParent,
        uint CreationFlags,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool SetupDiSetDeviceRegistryProperty(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        uint Property,
        byte[] PropertyBuffer,
        uint PropertyBufferSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiCallClassInstaller(
        uint InstallFunction,
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    [DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool UpdateDriverForPlugAndPlayDevices(
        IntPtr hwndParent,
        string HardwareId,
        string FullInfPath,
        uint InstallFlags,
        ref bool bRebootRequired);

    public const uint DICD_GENERATE_ID   = 0x00000001;
    public const uint SPDRP_HARDWAREID   = 0x00000001;
    public const uint DIF_REGISTERDEVICE = 0x00000019;
    public const uint INSTALLFLAG_FORCE  = 0x00000001;
    public static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public uint   cbSize;
        public Guid   ClassGuid;
        public uint   DevInst;
        public IntPtr Reserved;
    }
}
'@

Add-Type -TypeDefinition $csharpCode -Language CSharp

# SmartCardReader class GUID
$classGuid = [Guid]"50DD5230-BA8A-11D1-BF5D-0000F805F530"

# Step 1: Create device info set
Write-Host ""
Write-Host "[1/4] Creating device info set..." -ForegroundColor Yellow
$devInfoSet = [DevNodeHelper]::SetupDiCreateDeviceInfoList([ref]$classGuid, [IntPtr]::Zero)
if ($devInfoSet -eq [DevNodeHelper]::INVALID_HANDLE) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "[ERROR] SetupDiCreateDeviceInfoList failed, error: $err" -ForegroundColor Red
    exit 1
}
Write-Host "[DONE] Device info set created"

try {
    # Step 2: Create device node
    Write-Host "[2/4] Creating device node $HardwareId ..." -ForegroundColor Yellow

    $devData = New-Object DevNodeHelper+SP_DEVINFO_DATA
    $devData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($devData)

    $ok = [DevNodeHelper]::SetupDiCreateDeviceInfo(
        $devInfoSet,
        "OPENCERTFIDO",
        [ref]$classGuid,
        "OpenCert FIDO2 Virtual SmartCard Reader",
        [IntPtr]::Zero,
        [DevNodeHelper]::DICD_GENERATE_ID,
        [ref]$devData)

    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq 183) {
            # ERROR_ALREADY_EXISTS - not a real error
            Write-Host "[INFO] Device node already exists, skipping creation" -ForegroundColor Yellow
        } else {
            Write-Host "[ERROR] SetupDiCreateDeviceInfo failed, error: $err" -ForegroundColor Red
            exit 1
        }
    } else {
        # Set hardware ID (multi-string, double NUL terminated)
        $hwIdBytes = [System.Text.Encoding]::Unicode.GetBytes("$HardwareId`0`0")
        $ok2 = [DevNodeHelper]::SetupDiSetDeviceRegistryProperty(
            $devInfoSet,
            [ref]$devData,
            [DevNodeHelper]::SPDRP_HARDWAREID,
            $hwIdBytes,
            [uint32]$hwIdBytes.Length)
        if (-not $ok2) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "[WARN] SetDeviceRegistryProperty failed, error: $err" -ForegroundColor Yellow
        } else {
            Write-Host "[DONE] HardwareId set: $HardwareId"
        }

        # Register device with PnP manager
        $ok3 = [DevNodeHelper]::SetupDiCallClassInstaller(
            [DevNodeHelper]::DIF_REGISTERDEVICE,
            $devInfoSet,
            [ref]$devData)
        if (-not $ok3) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "[WARN] SetupDiCallClassInstaller failed, error: $err" -ForegroundColor Yellow
        } else {
            Write-Host "[DONE] Device registered with PnP manager"
        }
    }

    # Step 3: Bind driver (equivalent to devcon install)
    Write-Host "[3/4] Installing driver to device node..." -ForegroundColor Yellow
    $reboot = $false
    $fullInf = [System.IO.Path]::GetFullPath($InfFile)
    $ok4 = [DevNodeHelper]::UpdateDriverForPlugAndPlayDevices(
        [IntPtr]::Zero,
        $HardwareId,
        $fullInf,
        [DevNodeHelper]::INSTALLFLAG_FORCE,
        [ref]$reboot)

    if (-not $ok4) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[ERROR] UpdateDriverForPlugAndPlayDevices failed, error: $err (0x$($err.ToString('X8')))" -ForegroundColor Red
        Write-Host ""
        Write-Host "Common error codes:" -ForegroundColor Yellow
        Write-Host "  0xE0000247 = Driver signature verification failed (enable test signing: bcdedit /set testsigning on)"
        Write-Host "  0xE0000003 = No matching driver found in INF"
        Write-Host "  0x00000005 = Access denied (need Administrator)"
    } else {
        Write-Host "[DONE] Driver installed to device node" -ForegroundColor Green
        if ($reboot) {
            Write-Host "[INFO] Reboot required to complete installation" -ForegroundColor Yellow
        }
    }
} finally {
    [DevNodeHelper]::SetupDiDestroyDeviceInfoList($devInfoSet) | Out-Null
}

# Step 4: Verify
Write-Host ""
Write-Host "[4/4] Verifying SmartCardReader devices..." -ForegroundColor Yellow
Write-Host ""
pnputil /enum-devices /class SmartCardReader
