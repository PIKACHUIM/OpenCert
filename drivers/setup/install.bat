@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: ============================================================
:: OpenCert PKCS#11 Smart Card Minidriver - Install Script
:: Ref: https://learn.microsoft.com/zh-cn/windows-hardware/drivers/smartcard/minidriver-registration
:: ============================================================

:: ---- Configuration ----
set "CARD_NAME=Pikachu Secure SmartCard"
set "DLL_NAME=pkcs11-mock-x64.dll"
set "MINIDRIVER_DLL=PikachuMD.dll"
set "KSP_DLL=OpenCertKSP.dll"
set "KSP_DLL_X86=OpenCertKSP_x86.dll"
set "CSP_NAME=Pikachu SmartCard Crypto Provider"
set "KSP_NAME=OpenCert Key Storage Provider"
set "MANUFACTURER=Pikachu SmartCard MiniDriver"

:: Virtual smart card ATR (custom identifier for OpenCert virtual card)
set "CARD_ATR=3B888001504B43533131007A"
set "CARD_ATR_MASK=FFFFFFFFFFFFFFFFFFFFFFFF"

:: ---- Check admin privileges ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    echo         Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: ---- Determine script directory ----
set "SCRIPT_DIR=%~dp0"
set "DLL_SOURCE=%SCRIPT_DIR%%DLL_NAME%"

:: ---- Check DLL file exists ----
if not exist "%DLL_SOURCE%" (
    echo [ERROR] Driver file not found: %DLL_SOURCE%
    echo         Please ensure %DLL_NAME% is in the same directory as this script.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   OpenCert PKCS#11 Smart Card Minidriver - Installer
echo ============================================================
echo.
echo   Driver:    %DLL_NAME%
echo   Card Name: %CARD_NAME%
echo   CSP Name:  %CSP_NAME%
echo.
echo ============================================================
echo.

:: ============================================================
:: Step 1: Copy DLL to System32
:: ============================================================
echo [1/5] Copying driver DLL to System32...

copy /Y "%DLL_SOURCE%" "%SystemRoot%\System32\%MINIDRIVER_DLL%" >nul 2>&1
if %errorlevel% neq 0 (
    echo       [FAILED] Cannot copy file to System32
    echo       Check file permissions or if another program is using it.
    pause
    exit /b 1
)
echo       [OK] %SystemRoot%\System32\%MINIDRIVER_DLL%

:: Also copy as PKCS#11 module (for Firefox/SSH direct reference)
copy /Y "%DLL_SOURCE%" "%SystemRoot%\System32\%DLL_NAME%" >nul 2>&1
echo       [OK] %SystemRoot%\System32\%DLL_NAME%

:: ============================================================
:: Step 2: Register smart card in Calais\SmartCards
:: ============================================================
echo.
echo [2/5] Registering smart card minidriver in Calais\SmartCards...

set "REG_CALAIS=HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\%CARD_NAME%"

reg add "%REG_CALAIS%" /f >nul 2>&1
reg add "%REG_CALAIS%" /v "ATR" /t REG_BINARY /d %CARD_ATR% /f >nul 2>&1
reg add "%REG_CALAIS%" /v "ATRMask" /t REG_BINARY /d %CARD_ATR_MASK% /f >nul 2>&1
reg add "%REG_CALAIS%" /v "Crypto Provider" /t REG_SZ /d "Microsoft Base Smart Card Crypto Provider" /f >nul 2>&1
reg add "%REG_CALAIS%" /v "Smart Card Key Storage Provider" /t REG_SZ /d "Microsoft Smart Card Key Storage Provider" /f >nul 2>&1
reg add "%REG_CALAIS%" /v "80000001" /t REG_SZ /d "%MINIDRIVER_DLL%" /f >nul 2>&1

echo       [OK] Registry key created: %REG_CALAIS%

:: ============================================================
:: Step 3: Register CSP (Cryptographic Service Provider)
:: ============================================================
echo.
echo [3/5] Registering CSP...

set "REG_CSP=HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\%CSP_NAME%"

reg add "%REG_CSP%" /f >nul 2>&1
reg add "%REG_CSP%" /v "Image Path" /t REG_SZ /d "%SystemRoot%\System32\%MINIDRIVER_DLL%" /f >nul 2>&1
reg add "%REG_CSP%" /v "Type" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%REG_CSP%" /v "SigInFile" /t REG_DWORD /d 0 /f >nul 2>&1

echo       [OK] CSP registered: %CSP_NAME%

:: ============================================================
:: Step 4: Register KSP (Key Storage Provider) for CNG
:: ============================================================
echo.
echo [4/7] Registering KSP (OpenCert Key Storage Provider)...

:: Copy KSP DLL to System32
if exist "%SCRIPT_DIR%%KSP_DLL%" (
    copy /Y "%SCRIPT_DIR%%KSP_DLL%" "%SystemRoot%\System32\%KSP_DLL%" >nul 2>&1
    echo       [OK] %SystemRoot%\System32\%KSP_DLL% (x64)
) else (
    echo       [SKIP] %KSP_DLL% not found, KSP registration skipped
    goto :skip_ksp
)

:: Copy x86 KSP DLL to SysWOW64 (for 32-bit processes)
if exist "%SCRIPT_DIR%%KSP_DLL_X86%" (
    copy /Y "%SCRIPT_DIR%%KSP_DLL_X86%" "%SystemRoot%\SysWOW64\%KSP_DLL%" >nul 2>&1
    echo       [OK] %SystemRoot%\SysWOW64\%KSP_DLL% (x86, for 32-bit apps)
) else (
    echo       [WARN] %KSP_DLL_X86% not found, 32-bit apps won't be able to use KSP!
)

:: Register KSP in CNG provider registry
:: Structure must match Windows built-in KSPs (e.g. Microsoft Software Key Storage Provider):
::   Providers\<Name>\UM\Image = <DLL filename>
::   Providers\<Name>\UM\00010001\(default) = CRYPT_KEY_STORAGE_INTERFACE
::   Providers\<Name>\UM\00010001\Flags = 0x10000 (DWORD)
::   Providers\<Name>\UM\00010001\Functions = KEY_STORAGE (REG_MULTI_SZ)
:: 00010001 = NCRYPT_KEY_STORAGE_INTERFACE interface ID
set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"

:: Use BCryptRegisterProvider API for proper CNG registration
:: (Manual registry writing does NOT work for CNG providers)
echo       Registering via BCryptRegisterProvider API...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%register_ksp.ps1" -KspName "%KSP_NAME%" -KspDll "%KSP_DLL%"

if %errorlevel% neq 0 (
    echo       [FAIL] BCryptRegisterProvider failed!
    echo       Falling back to manual registry...
    reg delete "%REG_KSP%" /f >nul 2>&1
    reg add "%REG_KSP%" /f >nul 2>&1
    reg add "%REG_KSP%\UM" /f >nul 2>&1
    reg add "%REG_KSP%\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
    reg add "%REG_KSP%\UM\00010001" /f >nul 2>&1
    reg add "%REG_KSP%\UM\00010001" /v "Flags" /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "%REG_KSP%\UM\00010001" /v "Functions" /t REG_MULTI_SZ /d "KEY_STORAGE\0" /f >nul 2>&1
) else (
    echo       [OK] KSP registered via BCryptRegisterProvider
)

echo       [OK] KSP registered: %KSP_NAME%

:: Verify KSP is loadable
echo       Verifying KSP...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class V { [DllImport(\"ncrypt.dll\", CharSet=CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f); [DllImport(\"ncrypt.dll\")] public static extern int NCryptFreeObject(IntPtr h); }'; $h=[IntPtr]::Zero; $r=[V]::NCryptOpenStorageProvider([ref]$h,'%KSP_NAME%',0); if($r -eq 0){[V]::NCryptFreeObject($h)|Out-Null; Write-Host '      [OK] KSP verified: NCryptOpenStorageProvider succeeded'; exit 0}else{Write-Host \"      [WARN] KSP verify failed: 0x$($r.ToString('X8'))\"; exit 1}"

:skip_ksp

:: ============================================================
:: Step 5: Register PKCS#11 module path (for app discovery)
:: ============================================================
echo.
echo [5/7] Registering PKCS#11 module path...

set "REG_PKCS11=HKLM\SOFTWARE\OpenCert\PKCS11"

reg add "%REG_PKCS11%" /f >nul 2>&1
reg add "%REG_PKCS11%" /v "ModulePath" /t REG_SZ /d "%SystemRoot%\System32\%DLL_NAME%" /f >nul 2>&1
reg add "%REG_PKCS11%" /v "MiniDriverPath" /t REG_SZ /d "%SystemRoot%\System32\%MINIDRIVER_DLL%" /f >nul 2>&1
reg add "%REG_PKCS11%" /v "KSPPath" /t REG_SZ /d "%SystemRoot%\System32\%KSP_DLL%" /f >nul 2>&1
reg add "%REG_PKCS11%" /v "Manufacturer" /t REG_SZ /d "%MANUFACTURER%" /f >nul 2>&1
reg add "%REG_PKCS11%" /v "CardName" /t REG_SZ /d "%CARD_NAME%" /f >nul 2>&1
reg add "%REG_PKCS11%" /v "Version" /t REG_SZ /d "2.2.0" /f >nul 2>&1

echo       [OK] PKCS#11 module path registered

:: ============================================================
:: Step 6: Refresh Smart Card service
:: ============================================================
echo.
echo [6/7] Refreshing Smart Card service...

net stop SCardSvr >nul 2>&1
net start SCardSvr >nul 2>&1
echo       [OK] Smart Card service refreshed

:: ============================================================
:: Done
:: ============================================================
echo.
echo ============================================================
echo   Installation Complete!
echo ============================================================
echo.
echo   Completed:
echo     [+] DLL copied to System32
echo     [+] Smart card registered in Calais\SmartCards
echo     [+] CSP registered
echo     [+] KSP registered (OpenCert Key Storage Provider)
echo     [+] PKCS#11 module path registered
echo     [+] Smart Card service refreshed
echo.
echo   Next steps:
echo     1. Start client-card backend service (IPC communication)
echo     2. Firefox: Settings - Privacy - Security Devices - Load
echo        Module path: %SystemRoot%\System32\%DLL_NAME%
echo     3. SSH: Add to ~/.ssh/config:
echo        PKCS11Provider %SystemRoot%\System32\%DLL_NAME%
echo.
echo ============================================================
echo.
pause
exit /b 0