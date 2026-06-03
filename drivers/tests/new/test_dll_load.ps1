Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NativeLoader {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr hModule);
}
"@

$dllPath = "C:\Windows\System32\drivers\UMDF\FidoMdfDriver.dll"

# LOAD_LIBRARY_AS_DATAFILE = 0x2, DONT_RESOLVE_DLL_REFERENCES = 0x1
Write-Host "=== Test 1: LoadLibraryEx (DATAFILE) ==="
$h = [NativeLoader]::LoadLibraryEx($dllPath, [IntPtr]::Zero, 0x2)
if ($h -eq [IntPtr]::Zero) {
    Write-Host "FAILED: error=$([NativeLoader]::GetLastError())"
} else {
    Write-Host "SUCCESS (datafile mode)"
    [NativeLoader]::FreeLibrary($h) | Out-Null
}

Write-Host ""
Write-Host "=== Test 2: LoadLibraryEx (full load) ==="
$h2 = [NativeLoader]::LoadLibraryEx($dllPath, [IntPtr]::Zero, 0x0)
if ($h2 -eq [IntPtr]::Zero) {
    $err = [NativeLoader]::GetLastError()
    Write-Host "FAILED: Win32Error=$err (0x$($err.ToString('X8')))"
} else {
    Write-Host "SUCCESS (full load)"
    [NativeLoader]::FreeLibrary($h2) | Out-Null
}
