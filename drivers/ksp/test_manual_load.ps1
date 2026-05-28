Remove-Item "C:\Windows\Temp\ksp_debug.log" -ErrorAction SilentlyContinue

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ManualLoad {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr LoadLibraryW(string f);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr h);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=CharSet.Unicode)]
    public delegate int GKSIDelegate(string name, out IntPtr table, uint flags);
}
"@

$h = [ManualLoad]::LoadLibraryW("C:\WINDOWS\System32\OpenCertKSP.dll")
Write-Host "DLL loaded: 0x$($h.ToString('X'))"
$p = [ManualLoad]::GetProcAddress($h, "GetKeyStorageInterface")
Write-Host "GetKeyStorageInterface: 0x$($p.ToString('X'))"
$d = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, [ManualLoad+GKSIDelegate])
$t = [IntPtr]::Zero
$r = $d.Invoke("OpenCert Key Storage Provider", [ref]$t, 0)
Write-Host ("Call result: 0x{0:X8}" -f $r)
[ManualLoad]::FreeLibrary($h) | Out-Null

Write-Host ""
Write-Host "--- Debug Log ---"
if (Test-Path "C:\Windows\Temp\ksp_debug.log") {
    Get-Content "C:\Windows\Temp\ksp_debug.log"
} else {
    Write-Host "NO LOG - logging not working in deployed DLL"
    Write-Host "(DLL in System32 may be the old version without logging)"
}
