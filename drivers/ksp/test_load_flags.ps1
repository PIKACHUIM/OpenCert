Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class LoadTest {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FreeLibrary(IntPtr hModule);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    
    public const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
    public const uint LOAD_LIBRARY_REQUIRE_SIGNED_MODULE = 0x00000080;
}
"@

Write-Host "=== DLL Loading Flag Test ===" -ForegroundColor Cyan
Write-Host ""

$dllName = "OpenCertKSP.dll"

# Test 1: Normal load
Write-Host "[1] LoadLibraryExW('$dllName', 0) - Normal" -ForegroundColor Yellow
$h = [LoadTest]::LoadLibraryExW($dllName, [IntPtr]::Zero, 0)
$err = [LoadTest]::GetLastError()
if ($h -ne [IntPtr]::Zero) {
    Write-Host "    [OK] Loaded at 0x$($h.ToString('X'))" -ForegroundColor Green
    [LoadTest]::FreeLibrary($h) | Out-Null
} else {
    Write-Host "    [FAIL] Error: $err" -ForegroundColor Red
}

# Test 2: LOAD_LIBRARY_SEARCH_SYSTEM32
Write-Host "[2] LoadLibraryExW('$dllName', SEARCH_SYSTEM32)" -ForegroundColor Yellow
$h = [LoadTest]::LoadLibraryExW($dllName, [IntPtr]::Zero, [LoadTest]::LOAD_LIBRARY_SEARCH_SYSTEM32)
$err = [LoadTest]::GetLastError()
if ($h -ne [IntPtr]::Zero) {
    Write-Host "    [OK] Loaded at 0x$($h.ToString('X'))" -ForegroundColor Green
    [LoadTest]::FreeLibrary($h) | Out-Null
} else {
    Write-Host "    [FAIL] Error: $err (0x$($err.ToString('X')))" -ForegroundColor Red
}

# Test 3: LOAD_LIBRARY_REQUIRE_SIGNED_MODULE
Write-Host "[3] LoadLibraryExW('$dllName', REQUIRE_SIGNED_MODULE=0x80)" -ForegroundColor Yellow
$h = [LoadTest]::LoadLibraryExW($dllName, [IntPtr]::Zero, 0x00000080)
$err = [LoadTest]::GetLastError()
if ($h -ne [IntPtr]::Zero) {
    Write-Host "    [OK] Loaded at 0x$($h.ToString('X'))" -ForegroundColor Green
    [LoadTest]::FreeLibrary($h) | Out-Null
} else {
    Write-Host "    [FAIL] Error: $err (0x$($err.ToString('X')))" -ForegroundColor Red
    if ($err -eq 0x1E7) {
        Write-Host "    ERROR_INVALID_IMAGE_HASH - DLL signature not trusted!" -ForegroundColor Red
    }
}

# Test 4: SEARCH_SYSTEM32 + REQUIRE_SIGNED
Write-Host "[4] LoadLibraryExW('$dllName', SEARCH_SYSTEM32 | REQUIRE_SIGNED)" -ForegroundColor Yellow
$flags = [LoadTest]::LOAD_LIBRARY_SEARCH_SYSTEM32 -bor 0x00000080
$h = [LoadTest]::LoadLibraryExW($dllName, [IntPtr]::Zero, $flags)
$err = [LoadTest]::GetLastError()
if ($h -ne [IntPtr]::Zero) {
    Write-Host "    [OK] Loaded at 0x$($h.ToString('X'))" -ForegroundColor Green
    [LoadTest]::FreeLibrary($h) | Out-Null
} else {
    Write-Host "    [FAIL] Error: $err (0x$($err.ToString('X')))" -ForegroundColor Red
    if ($err -eq 0x1E7) {
        Write-Host "    ERROR_INVALID_IMAGE_HASH - DLL signature not trusted by system!" -ForegroundColor Red
        Write-Host "    THIS IS THE ROOT CAUSE!" -ForegroundColor Red
        Write-Host "    CNG uses LOAD_LIBRARY_REQUIRE_SIGNED_MODULE to load KSP DLLs" -ForegroundColor Red
    }
}

# Test 5: Compare with SimplySign
Write-Host ""
Write-Host "[5] Compare: SimplySignKSP.dll with REQUIRE_SIGNED" -ForegroundColor Yellow
$h = [LoadTest]::LoadLibraryExW("SimplySignKSP.dll", [IntPtr]::Zero, 0x00000080)
$err = [LoadTest]::GetLastError()
if ($h -ne [IntPtr]::Zero) {
    Write-Host "    [OK] SimplySign loads with REQUIRE_SIGNED!" -ForegroundColor Green
    [LoadTest]::FreeLibrary($h) | Out-Null
} else {
    Write-Host "    [FAIL] SimplySign also fails: $err (0x$($err.ToString('X')))" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
