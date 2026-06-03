Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DevTest2 {
    public const uint GENERIC_READ  = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ  = 0x1;
    public const uint FILE_SHARE_WRITE = 0x2;
    public const uint OPEN_EXISTING = 3;
    public const uint IOCTL_SMARTCARD_GET_STATE = 0x00310008;

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
        byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    public static IntPtr Open(string path) {
        return CreateFile(path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
    }
}
'@

$devPath = "\\?\ROOT#OPENCERTFIDO#0000#{50dd5230-ba8a-11d1-bf5d-0000f805f530}"
Write-Host "Opening: $devPath"

$h = [DevTest2]::Open($devPath)
$err = [DevTest2]::GetLastError()
$INVALID = [IntPtr]::new(-1)

Write-Host ("Handle: 0x{0:X16}" -f $h.ToInt64())
Write-Host ("LastError: $err")

if ($h -ne $INVALID -and $h -ne [IntPtr]::Zero) {
    Write-Host "SUCCESS: Device opened!"
    
    $outBuf = New-Object byte[] 4
    $bytesRet = [uint32]0
    $ok = [DevTest2]::DeviceIoControl($h, [DevTest2]::IOCTL_SMARTCARD_GET_STATE,
        $null, 0, $outBuf, 4, [ref]$bytesRet, [IntPtr]::Zero)
    $ioErr = [DevTest2]::GetLastError()
    $state = [BitConverter]::ToUInt32($outBuf, 0)
    Write-Host "GET_STATE: ok=$ok, bytes=$bytesRet, err=$ioErr, state=$state"
    
    [DevTest2]::CloseHandle($h) | Out-Null
} else {
    Write-Host "FAILED to open device (err=$err)"
    switch ($err) {
        5   { Write-Host "  -> Access Denied (Exclusive mode or permissions)" }
        2   { Write-Host "  -> File Not Found (device interface not active)" }
        32  { Write-Host "  -> Sharing Violation" }
        default { Write-Host "  -> Error code: $err" }
    }
}
