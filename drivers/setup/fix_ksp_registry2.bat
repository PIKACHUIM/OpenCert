@echo off
chcp 65001 >nul 2>&1

:: Must run as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run as Administrator!
    pause
    exit /b 1
)

set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider"

echo ============================================================
echo   Fixing OpenCert KSP Registry (based on SimplySign/SafeNet)
echo ============================================================
echo.

echo [1/4] Removing old registry entries completely...
reg delete "%REG_KSP%" /f >nul 2>&1
echo       [OK] Old entries removed

echo [2/4] Creating correct registry structure...

:: Root key (no Aliases needed for now)
reg add "%REG_KSP%" /f >nul 2>&1

:: UM key with Image
reg add "%REG_KSP%\UM" /v "Image" /t REG_SZ /d "OpenCertKSP.dll" /f >nul 2>&1

:: 00010001 subkey - NO default value, Flags=1, Functions=KEY_STORAGE
reg add "%REG_KSP%\UM\00010001" /v "Flags" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%REG_KSP%\UM\00010001" /v "Functions" /t REG_MULTI_SZ /d "KEY_STORAGE\0" /f >nul 2>&1

echo       [OK] Registry created

echo [3/4] Verifying...
echo.
reg query "%REG_KSP%" /s
echo.

echo [4/4] Comparing with working KSP (SimplySign)...
echo.
echo --- SimplySign KSP ---
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SimplySign KSP" /s
echo.
echo --- Our KSP ---
reg query "%REG_KSP%" /s
echo.

echo ============================================================
echo   Done! Now test with:
echo   certutil -csp "OpenCert Key Storage Provider" -key
echo ============================================================
pause
