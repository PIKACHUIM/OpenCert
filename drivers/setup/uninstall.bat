@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: ============================================================
:: OpenCert PKCS#11 Smart Card Minidriver - Uninstall Script
:: ============================================================

:: ---- Configuration (must match install.bat) ----
set "CARD_NAME=Pikachu Secure SmartCard"
set "DLL_NAME=pkcs11-mock-x64.dll"
set "MINIDRIVER_DLL=PikachuMD.dll"
set "CSP_NAME=Pikachu SmartCard Crypto Provider"

set "REG_CALAIS=HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\%CARD_NAME%"
set "REG_CSP=HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\%CSP_NAME%"
set "REG_PKCS11=HKLM\SOFTWARE\OpenCert\PKCS11"

:: ---- Check admin privileges ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    echo         Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   OpenCert PKCS#11 Smart Card Minidriver - Uninstaller
echo ============================================================
echo.
echo   Will remove:
echo     - %SystemRoot%\System32\%MINIDRIVER_DLL%
echo     - %SystemRoot%\System32\%DLL_NAME%
echo     - Registry: %REG_CALAIS%
echo     - Registry: %REG_CSP%
echo     - Registry: %REG_PKCS11%
echo.

set /p confirm=Confirm uninstall? (Y/N): 
if /i not "%confirm%"=="Y" (
    echo Cancelled.
    pause
    exit /b 0
)

echo.

:: ============================================================
:: Step 1: Delete registry keys
:: ============================================================
echo [1/3] Deleting registry keys...

reg delete "%REG_CALAIS%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo       [OK] Calais\SmartCards entry removed
) else (
    echo       [SKIP] Calais\SmartCards entry not found
)

reg delete "%REG_CSP%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo       [OK] CSP entry removed
) else (
    echo       [SKIP] CSP entry not found
)

reg delete "%REG_PKCS11%" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo       [OK] PKCS#11 entry removed
) else (
    echo       [SKIP] PKCS#11 entry not found
)

:: ============================================================
:: Step 2: Delete DLLs from System32
:: ============================================================
echo.
echo [2/3] Deleting DLL files from System32...

if exist "%SystemRoot%\System32\%MINIDRIVER_DLL%" (
    del /f "%SystemRoot%\System32\%MINIDRIVER_DLL%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo       [OK] %MINIDRIVER_DLL% deleted
    ) else (
        echo       [WARN] Cannot delete %MINIDRIVER_DLL% (may be in use)
    )
) else (
    echo       [SKIP] %MINIDRIVER_DLL% not found
)

if exist "%SystemRoot%\System32\%DLL_NAME%" (
    del /f "%SystemRoot%\System32\%DLL_NAME%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo       [OK] %DLL_NAME% deleted
    ) else (
        echo       [WARN] Cannot delete %DLL_NAME% (may be in use)
    )
) else (
    echo       [SKIP] %DLL_NAME% not found
)

:: ============================================================
:: Step 3: Refresh Smart Card service
:: ============================================================
echo.
echo [3/3] Refreshing Smart Card service...

net stop SCardSvr >nul 2>&1
net start SCardSvr >nul 2>&1
echo       [OK] Smart Card service refreshed

:: ============================================================
:: Done
:: ============================================================
echo.
echo ============================================================
echo   Uninstall Complete!
echo ============================================================
echo.
echo   Note: If you loaded this PKCS#11 module in Firefox,
echo         please manually remove it from Security Devices.
echo.
pause
exit /b 0
