@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert FIDO2 HID 驱动卸载脚本
:: ============================================================
setlocal enabledelayedexpansion

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   OpenCert FIDO2 HID 驱动卸载
echo ============================================================

:: ---- Step 1: 查找并删除设备节点 ----
echo.
echo [1/2] 删除设备节点...

set "DEVCON="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\Tools\*") do (
    if exist "%%V\x64\devcon.exe" if "!DEVCON!"=="" set "DEVCON=%%V\x64\devcon.exe"
)
if "!DEVCON!"=="" (
    where devcon >nul 2>&1
    if !errorlevel! equ 0 set "DEVCON=devcon"
)

if not "!DEVCON!"=="" (
    "!DEVCON!" remove "ROOT\FidoHidDriver" >nul 2>&1
    echo [DONE] 设备节点已删除（或不存在）
) else (
    echo [WARN] 未找到 devcon.exe，跳过设备节点删除
    echo        请手动在设备管理器中卸载 "OpenCert FIDO2 Authenticator (HID)"
)

:: ---- Step 2: 从驱动存储删除驱动包 ----
echo.
echo [2/2] 从驱动存储删除驱动包...

:: 查找 oem*.inf 中匹配 FidoHidDriver 的条目
for /f "tokens=1" %%I in ('pnputil /enum-drivers 2^>nul ^| findstr /i "FidoHidDriver"') do (
    set "OEM_INF=%%I"
)

if defined OEM_INF (
    pnputil /delete-driver "!OEM_INF!" /uninstall /force
    echo [DONE] 驱动包 !OEM_INF! 已删除
) else (
    echo [INFO] 未找到已安装的 HID 驱动包，可能已卸载
)

echo.
echo ============================================================
echo   卸载完成！
echo ============================================================
echo.
pause
exit /b 0
