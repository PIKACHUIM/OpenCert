Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class KSPTest2 {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);
    
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr hModule);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=CharSet.Unicode)]
    public delegate int GetKeyStorageInterfaceDelegate(
        string pszProviderName,
        out IntPtr ppFunctionTable,
        uint dwFlags
    );
}
"@

Write-Host "=== OpenCert KSP Deep Diagnostic v2 ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Load DLL the way CNG does (LOAD_LIBRARY_SEARCH_SYSTEM32)
Write-Host "[1] Loading DLL with LOAD_LIBRARY_SEARCH_SYSTEM32 (0x00000800)..." -ForegroundColor Yellow
$hDll = [KSPTest2]::LoadLibraryExW("OpenCertKSP.dll", [IntPtr]::Zero, 0x00000800)
if ($hDll -eq [IntPtr]::Zero) {
    $err = [KSPTest2]::GetLastError()
    Write-Host "    [FAIL] LoadLibraryExW failed, error: $err (0x$($err.ToString('X8')))" -ForegroundColor Red
    
    # Try with full path
    Write-Host "[1b] Trying full path..." -ForegroundColor Yellow
    $hDll = [KSPTest2]::LoadLibraryExW("C:\WINDOWS\System32\OpenCertKSP.dll", [IntPtr]::Zero, 0)
    if ($hDll -eq [IntPtr]::Zero) {
        $err = [KSPTest2]::GetLastError()
        Write-Host "    [FAIL] Full path also failed, error: $err" -ForegroundColor Red
        exit
    }
}
Write-Host "    [OK] DLL loaded at 0x$($hDll.ToString('X'))" -ForegroundColor Green

# Test 2: Get export
$pfn = [KSPTest2]::GetProcAddress($hDll, "GetKeyStorageInterface")
Write-Host "[2] GetKeyStorageInterface at 0x$($pfn.ToString('X'))" -ForegroundColor Green

# Test 3: Call with exact provider name from registry
Write-Host "[3] Calling GetKeyStorageInterface..." -ForegroundColor Yellow
$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pfn, [KSPTest2+GetKeyStorageInterfaceDelegate])
$pTable = [IntPtr]::Zero
$ntstatus = $del.Invoke("OpenCert Key Storage Provider", [ref]$pTable, 0)
Write-Host "    NTSTATUS: 0x$($ntstatus.ToString('X8'))"
Write-Host "    pTable: 0x$($pTable.ToString('X'))"

if ($ntstatus -eq 0 -and $pTable -ne [IntPtr]::Zero) {
    # Read Version field
    $verMajor = [System.Runtime.InteropServices.Marshal]::ReadInt16($pTable, 0)
    $verMinor = [System.Runtime.InteropServices.Marshal]::ReadInt16($pTable, 2)
    Write-Host "    Version: $verMajor.$verMinor" -ForegroundColor Green
    
    # Dump first 8 function pointers
    Write-Host "    Function table dump:" -ForegroundColor Cyan
    $funcNames = @("OpenProvider","OpenKey","CreatePersistedKey","GetProviderProperty",
                   "GetKeyProperty","SetProviderProperty","SetKeyProperty","FinalizeKey")
    for ($i = 0; $i -lt 8; $i++) {
        $ptr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pTable, 8 + ($i * 8))
        Write-Host "      [$i] $($funcNames[$i]): 0x$($ptr.ToString('X'))"
    }
}

[KSPTest2]::FreeLibrary($hDll) | Out-Null

# Test 4: Check if there's a DLL loading issue with CNG's search path
Write-Host ""
Write-Host "[4] Checking CNG's DLL search behavior..." -ForegroundColor Yellow

# Check if the DLL has any dependencies that might fail
Write-Host "[5] Checking DLL dependencies..." -ForegroundColor Yellow
$dllPath = "C:\WINDOWS\System32\OpenCertKSP.dll"
$pe = [System.Reflection.Assembly]::LoadFile($dllPath) 2>$null
# Use dumpbin instead
Write-Host "    (Use dumpbin /dependents to check)" -ForegroundColor Gray

# Test 5: Try NCryptOpenStorageProvider with NCRYPT_SILENT_FLAG
Write-Host ""
Write-Host "[6] NCryptOpenStorageProvider (normal)..." -ForegroundColor Yellow
$hProv = [IntPtr]::Zero
$result = [KSPTest2]::NCryptOpenStorageProvider([ref]$hProv, "OpenCert Key Storage Provider", 0)
Write-Host "    Result: 0x$($result.ToString('X8'))"
if ($result -eq 0) {
    Write-Host "    [OK] SUCCESS!" -ForegroundColor Green
    [KSPTest2]::NCryptFreeObject($hProv) | Out-Null
} else {
    Write-Host "    [FAIL]" -ForegroundColor Red
}

# Test 6: Try with NCRYPT_SILENT_FLAG (0x40)
Write-Host "[7] NCryptOpenStorageProvider (SILENT_FLAG=0x40)..." -ForegroundColor Yellow
$hProv2 = [IntPtr]::Zero
$result2 = [KSPTest2]::NCryptOpenStorageProvider([ref]$hProv2, "OpenCert Key Storage Provider", 0x40)
Write-Host "    Result: 0x$($result2.ToString('X8'))"
if ($result2 -eq 0) {
    Write-Host "    [OK] SUCCESS!" -ForegroundColor Green
    [KSPTest2]::NCryptFreeObject($hProv2) | Out-Null
}

# Test 7: Check if the issue is with the UM default value
Write-Host ""
Write-Host "[8] Registry analysis..." -ForegroundColor Yellow
$umKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider\UM" -ErrorAction SilentlyContinue
if ($umKey) {
    $vals = $umKey.GetValueNames()
    Write-Host "    UM key values: $($vals -join ', ')"
    foreach ($v in $vals) {
        $kind = $umKey.GetValueKind($v)
        $val = $umKey.GetValue($v)
        $displayName = if ($v -eq '') { '(Default)' } else { $v }
        Write-Host "      $displayName [$kind] = $val"
    }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
