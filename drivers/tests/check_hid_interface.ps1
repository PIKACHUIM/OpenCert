# check_hid_interface.ps1 - 检查 HID 设备接口注册情况
# WebAuthn API 通过 HID 接口 GUID {4D1E55B2-F16F-11CF-88CB-001111000030} 枚举 FIDO2 设备

$csCode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class HidCheck {
    [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, string Enumerator, IntPtr hwndParent, uint Flags);

    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern bool SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid, uint MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

    [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData, IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize, ref uint RequiredSize, IntPtr DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    public const uint DIGCF_PRESENT = 0x02;
    public const uint DIGCF_DEVICEINTERFACE = 0x10;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
}

[StructLayout(LayoutKind.Sequential)]
public struct SP_DEVICE_INTERFACE_DATA {
    public uint cbSize;
    public Guid InterfaceClassGuid;
    public uint Flags;
    public IntPtr Reserved;
}
'@

Add-Type -TypeDefinition $csCode -ErrorAction Stop

# HID class interface GUID
$hidGuid = [Guid]"{4D1E55B2-F16F-11CF-88CB-001111000030}"

Write-Host "=== HID Device Interface Check ===" -ForegroundColor Cyan
Write-Host "HID Interface GUID: $hidGuid"
Write-Host ""

$devInfoSet = [HidCheck]::SetupDiGetClassDevs(
    [ref]$hidGuid,
    $null,
    [IntPtr]::Zero,
    ([HidCheck]::DIGCF_PRESENT -bor [HidCheck]::DIGCF_DEVICEINTERFACE)
)

if ($devInfoSet -eq [HidCheck]::INVALID_HANDLE_VALUE) {
    Write-Host "[FAIL] SetupDiGetClassDevs failed" -ForegroundColor Red
    exit 1
}

$index = 0u
$ifData = New-Object SP_DEVICE_INTERFACE_DATA
$ifData.cbSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($ifData)

Write-Host "Registered HID interfaces:" -ForegroundColor Yellow

while ([HidCheck]::SetupDiEnumDeviceInterfaces($devInfoSet, [IntPtr]::Zero, [ref]$hidGuid, $index, [ref]$ifData)) {
    $requiredSize = 0u
    [HidCheck]::SetupDiGetDeviceInterfaceDetail($devInfoSet, [ref]$ifData, [IntPtr]::Zero, 0, [ref]$requiredSize, [IntPtr]::Zero) | Out-Null

    $detailData = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$requiredSize)
    try {
        # cbSize: 6 on x64, 5 on x86
        [System.Runtime.InteropServices.Marshal]::WriteInt32($detailData, 6)
        if ([HidCheck]::SetupDiGetDeviceInterfaceDetail($devInfoSet, [ref]$ifData, $detailData, $requiredSize, [ref]$requiredSize, [IntPtr]::Zero)) {
            $path = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([IntPtr]::Add($detailData, 4))
            $color = "White"
            if ($path -match "opencert|fido" -or $path -match "OPENCERT|FIDO") { $color = "Green" }
            Write-Host ("  [{0}] {1}" -f $index, $path) -ForegroundColor $color
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($detailData)
    }
    $index++
}

[HidCheck]::SetupDiDestroyDeviceInfoList($devInfoSet) | Out-Null

Write-Host ""
Write-Host ("Total HID interfaces: {0}" -f $index) -ForegroundColor Yellow

# Check device stack
Write-Host ""
Write-Host "=== Device Stack ===" -ForegroundColor Cyan
$stackProp = Get-PnpDeviceProperty -InstanceId "ROOT\HIDCLASS\0000" -KeyName "DEVPKEY_Device_Stack" -ErrorAction SilentlyContinue
if ($stackProp -and $stackProp.Data) {
    Write-Host ("Stack: {0}" -f ($stackProp.Data -join " -> "))
} else {
    Write-Host "Stack: (not available)"
}

# Check children devices (hidclass.sys creates child HID collection devices)
Write-Host ""
Write-Host "=== Child Devices ===" -ForegroundColor Cyan
$children = Get-PnpDeviceProperty -InstanceId "ROOT\HIDCLASS\0000" -KeyName "DEVPKEY_Device_Children" -ErrorAction SilentlyContinue
if ($children -and $children.Data) {
    foreach ($child in $children.Data) {
        Write-Host ("  Child: {0}" -f $child) -ForegroundColor Green
        $childDev = Get-PnpDevice -InstanceId $child -ErrorAction SilentlyContinue
        if ($childDev) {
            Write-Host ("    Status: {0}, Class: {1}, Name: {2}" -f $childDev.Status, $childDev.Class, $childDev.FriendlyName)
        }
    }
} else {
    Write-Host "  No child devices found" -ForegroundColor Red
    Write-Host "  NOTE: hidclass.sys should create child HID collection devices" -ForegroundColor Red
    Write-Host "        If no children, the HID report descriptor may not be read correctly" -ForegroundColor Red
}