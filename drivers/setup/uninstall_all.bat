@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert Drivers - 一键卸载 (管理员权限)
:: ============================================================
setlocal enabledelayedexpansion

set "KSP_NAME=OpenCert Key Storage Provider"
set "KSP_DLL=OpenCertKSP.dll"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    pause & exit /b 1
)

echo.
echo ============================================================
echo   OpenCert Drivers - Uninstall
echo ============================================================
echo.

:: ================================================================
:: [1/4] 卸载 USB/IP VHCI 驱动
:: ================================================================
echo [1/4] Removing USB/IP VHCI Driver...

:: 查找 devcon.exe
set "DEVCON="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\Tools\*") do (
    if exist "%%V\x64\devcon.exe" if "!DEVCON!"=="" set "DEVCON=%%V\x64\devcon.exe"
)

:: 使用 pnputil 移除设备节点（root\vhci_ude 和 USBIPWIN\vhci）
echo       Removing device nodes...
if "!DEVCON!" neq "" (
    "!DEVCON!" remove "root\vhci_ude" >nul 2>&1
    "!DEVCON!" remove "USBIPWIN\vhci" >nul 2>&1
    echo       [DONE] Device nodes removed (devcon)
) else (
    :: 使用 pnputil 作为备选
    for /f "tokens=*" %%I in ('pnputil /enum-devices /deviceid "root\vhci_ude" /connected 2^>nul ^| findstr /i "Instance ID"') do (
        for /f "tokens=3*" %%A in ("%%I") do (
            pnputil /remove-device "%%A %%B" >nul 2>&1
        )
    )
    for /f "tokens=*" %%I in ('pnputil /enum-devices /deviceid "USBIPWIN\vhci" /connected 2^>nul ^| findstr /i "Instance ID"') do (
        for /f "tokens=3*" %%A in ("%%I") do (
            pnputil /remove-device "%%A %%B" >nul 2>&1
        )
    )
    echo       [DONE] Device nodes removed (pnputil)
)

:: 使用 pnputil 删除驱动包
echo       Removing driver packages...
set "REMOVED_DRV=0"
for /f "tokens=*" %%L in ('pnputil /enum-drivers 2^>nul') do (
    set "LINE=%%L"
    :: Published Name detection
    set "_IS_PUB="
    if "!LINE:Published Name=!" neq "!LINE!" set "_IS_PUB=1"
    if defined _IS_PUB (
        for /f "tokens=3 delims=: " %%N in ("!LINE!") do set "CURRENT_OEM=%%N"
    )
    :: usbip driver detection
    set "_IS_USBIP="
    if "!LINE:usbip_vhci_ude=!" neq "!LINE!" set "_IS_USBIP=1"
    if "!LINE:usbip_vhci=!" neq "!LINE!" set "_IS_USBIP=1"
    if "!LINE:usbip_root=!" neq "!LINE!" set "_IS_USBIP=1"
    if "!LINE:usbip_stub=!" neq "!LINE!" set "_IS_USBIP=1"
    if defined _IS_USBIP (
        if defined CURRENT_OEM (
            pnputil /delete-driver !CURRENT_OEM! /force >nul 2>&1
            set /a REMOVED_DRV+=1
            set "CURRENT_OEM="
        )
    )
)
if !REMOVED_DRV! gtr 0 (
    echo       [DONE] Removed !REMOVED_DRV! driver package^(s^)
) else (
    echo       [SKIP] No USB/IP driver packages found
)

:: ================================================================
:: [2/4] 删除 KSP DLLs
:: ================================================================
echo.
echo [2/4] Removing KSP DLLs...
del /F "%SystemRoot%\System32\%KSP_DLL%" >nul 2>&1
del /F "%SystemRoot%\SysWOW64\%KSP_DLL%" >nul 2>&1
echo       [DONE] KSP DLLs removed

:: ================================================================
:: [3/4] 删除 CSP + FIDO DLLs
:: ================================================================
echo.
echo [3/4] Removing CSP + FIDO DLLs...
del /F "%SystemRoot%\System32\OpenCertCSP.dll" >nul 2>&1
del /F "%SystemRoot%\SysWOW64\OpenCertCSP.dll" >nul 2>&1
del /F "%SystemRoot%\System32\OpenCertFIDO.dll" >nul 2>&1
del /F "%SystemRoot%\SysWOW64\OpenCertFIDO.dll" >nul 2>&1
echo       [DONE] CSP + FIDO DLLs removed

:: ================================================================
:: [4/4] 删除注册表项
:: ================================================================
echo.
echo [4/4] Removing registry entries...

:: KSP 注册表
set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
reg delete "%REG_KSP%" /f >nul 2>&1
echo       [DONE] KSP unregistered

:: FIDO CCID 注册表（如果有）
set "REG_CCID=HKLM\SOFTWARE\OpenCert\FIDO"
reg delete "%REG_CCID%" /f >nul 2>&1
echo       [DONE] FIDO CCID registry cleaned

echo.
echo ============================================================
echo   Uninstall Complete!
echo ============================================================
echo.
echo   Note: A system reboot may be required to fully remove
echo         the USB/IP VHCI driver.
echo.
pause
exit /b 0
