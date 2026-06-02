@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: uninstall_driver.bat - OpenCert FIDO2 UMDF 驱动卸载脚本
:: ============================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "WDK_BIN="

echo.
echo ============================================================
echo   OpenCert FIDO2 UMDF Driver Uninstaller
echo ============================================================

:: ---- 检查管理员权限 ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    pause
    exit /b 1
)

:: ---- 查找 WDK 工具 ----
for %%P in (
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\x64"
) do if exist "%%~P\devcon.exe" if "!WDK_BIN!"=="" set "WDK_BIN=%%~P"

:: ---- 停止 Smart Card 服务 ----
echo [1/4] 停止 Smart Card 服务...
net stop SCardSvr >nul 2>&1
echo [OK] Smart Card 服务已停止

:: ---- 移除设备节点 ----
echo [2/4] 移除虚拟设备节点...
if not "!WDK_BIN!"=="" (
    "!WDK_BIN!\devcon.exe" remove ROOT\OPENCERTFIDO >nul 2>&1
    echo [OK] 设备节点已移除
) else (
    echo [WARN] 未找到 devcon.exe，跳过设备节点移除
    echo        请手动在设备管理器中卸载 "OpenCert FIDO2 Virtual SmartCard Reader"
)

:: ---- 从驱动存储中删除驱动 ----
echo [3/4] 从驱动存储中删除驱动...
for /f "tokens=1,2 delims= " %%A in ('pnputil /enum-drivers ^| findstr /i "opencert"') do (
    if "%%A"=="Published" (
        pnputil /delete-driver %%B /uninstall >nul 2>&1
        echo [OK] 已删除驱动: %%B
    )
)

:: ---- 删除 UMDF DLL ----
echo [4/4] 删除驱动 DLL...
set "UMDF_DLL=%SystemRoot%\System32\drivers\UMDF\OpenCertFIDODriver.dll"
if exist "%UMDF_DLL%" (
    del /F /Q "%UMDF_DLL%" >nul 2>&1
    echo [OK] 已删除 %UMDF_DLL%
) else (
    echo [INFO] DLL 不存在，跳过
)

:: ---- 重启 Smart Card 服务 ----
net start SCardSvr >nul 2>&1
echo [OK] Smart Card 服务已重启

echo.
echo ============================================================
echo   卸载完成！
echo ============================================================
pause
exit /b 0
