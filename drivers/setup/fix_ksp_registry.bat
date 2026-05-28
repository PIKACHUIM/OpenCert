@echo off
chcp 65001 >nul 2>&1
setlocal

:: ============================================================
:: Fix OpenCert KSP Registry Structure
:: Must run as Administrator!
:: ============================================================

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run as Administrator!
    pause
    exit /b 1
)

set "KSP_NAME=OpenCert Key Storage Provider"
set "KSP_DLL=OpenCertKSP.dll"
set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"

echo.
echo ============================================================
echo   Fixing OpenCert KSP Registry Structure
echo ============================================================
echo.

:: Step 1: Delete old incorrect registry
echo [1/3] Removing old incorrect registry entries...
reg delete "%REG_KSP%" /f >nul 2>&1
echo       [OK] Old entries removed

:: Step 2: Create correct structure (matching Windows built-in KSPs)
:: Reference: Microsoft Software Key Storage Provider registry layout:
::   Providers\<Name>\UM\Image = <DLL filename>
::   Providers\<Name>\UM\00010001\(default) = CRYPT_KEY_STORAGE_INTERFACE
::   Providers\<Name>\UM\00010001\Flags = 0 (third-party KSP must use 0)
::   Providers\<Name>\UM\00010001\Functions = KEY_STORAGE (REG_MULTI_SZ)
echo.
echo [2/3] Creating correct registry structure...
reg add "%REG_KSP%" /f >nul 2>&1
reg add "%REG_KSP%\UM" /f >nul 2>&1
reg add "%REG_KSP%\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
:: CNG Interface registration (NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001)
reg add "%REG_KSP%\UM\00010001" /f >nul 2>&1
reg add "%REG_KSP%\UM\00010001" /ve /t REG_SZ /d "CRYPT_KEY_STORAGE_INTERFACE" /f >nul 2>&1
reg add "%REG_KSP%\UM\00010001" /v "Flags" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "%REG_KSP%\UM\00010001" /v "Functions" /t REG_MULTI_SZ /d "KEY_STORAGE\0" /f >nul 2>&1
echo       [OK] Registry created:
echo            %REG_KSP%\UM\Image = %KSP_DLL%
echo            %REG_KSP%\UM\00010001\(default) = CRYPT_KEY_STORAGE_INTERFACE
echo            %REG_KSP%\UM\00010001\Flags = 0
echo            %REG_KSP%\UM\00010001\Functions = KEY_STORAGE

:: Step 3: Verify
echo.
echo [3/3] Verifying...
reg query "%REG_KSP%\UM" /v "Image"
reg query "%REG_KSP%\UM\00010001"
if %errorlevel% equ 0 (
    echo.
    echo       [OK] KSP registry is now correct!
) else (
    echo       [FAILED] Registry verification failed!
    pause
    exit /b 1
)

:: Step 4: Verify DLL exists in System32
echo.
if exist "%SystemRoot%\System32\%KSP_DLL%" (
    echo [OK] DLL exists: %SystemRoot%\System32\%KSP_DLL%
) else (
    echo [WARNING] DLL not found: %SystemRoot%\System32\%KSP_DLL%
    echo          Please copy the DLL to System32 first!
)

echo.
echo ============================================================
echo   Done! Now test with:
echo   certutil -csp "OpenCert Key Storage Provider" -key
echo ============================================================
echo.
pause
exit /b 0
