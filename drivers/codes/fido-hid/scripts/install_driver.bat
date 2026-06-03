@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "BUILD_DIR=%SCRIPT_DIR%..\..\..\build\FidoHidDriver"
set "INF_FILE=%BUILD_DIR%\FidoHidDriver.inf"
set "DLL_FILE=%BUILD_DIR%\FidoHidDriver.dll"

echo.
echo ============================================================
echo   OpenCert FIDO2 HID 驱动安装
echo ============================================================

if not exist "!DLL_FILE!" (
    echo [ERROR] 未找到驱动 DLL: !DLL_FILE!
    echo         请先运行 builds.bat 构建驱动
    pause
    exit /b 1
)
if not exist "!INF_FILE!" (
    echo [ERROR] 未找到 INF 文件: !INF_FILE!
    pause
    exit /b 1
)

echo [INFO] DLL: !DLL_FILE!
echo [INFO] INF: !INF_FILE!

:: Find devcon.exe
set "DEVCON="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\Tools\*") do (
    if exist "%%V\x64\devcon.exe" if "!DEVCON!"=="" set "DEVCON=%%V\x64\devcon.exe"
)
if "!DEVCON!"=="" (
    where devcon >nul 2>&1
    if !errorlevel! equ 0 set "DEVCON=devcon"
)

:: Step 1: Create device node
echo.
echo [1/3] 创建虚拟设备节点...
if "!DEVCON!"=="" (
    echo [WARN] 未找到 devcon.exe，跳过设备节点创建
    goto :install_driver
)

"!DEVCON!" find "ROOT\FidoHidDriver" >nul 2>&1
if !errorlevel! equ 0 (
    echo [INFO] 设备节点已存在，跳过创建
) else (
    echo [INFO] 创建设备节点...
    "!DEVCON!" install "!INF_FILE!" "ROOT\FidoHidDriver"
    if !errorlevel! neq 0 (
        echo [ERROR] 设备节点创建失败
        pause
        exit /b 1
    )
    echo [DONE] 设备节点已创建
)

:install_driver
:: Step 2: Add driver to store
echo.
echo [2/3] 安装驱动包到驱动存储...
pnputil /add-driver "!INF_FILE!" /install
if !errorlevel! neq 0 (
    echo [WARN] pnputil 返回非零，可能已安装或需要重启
)
echo [DONE] 驱动包已添加

:: Step 3: Update device driver
echo.
echo [3/3] 更新设备驱动...
if not "!DEVCON!"=="" (
    "!DEVCON!" update "!INF_FILE!" "ROOT\FidoHidDriver"
    if !errorlevel! neq 0 (
        echo [WARN] devcon update 失败，尝试 pnputil 强制更新...
        pnputil /add-driver "!INF_FILE!" /install /force
        if !errorlevel! neq 0 (
            echo [WARN] 强制更新失败，请重启后重试
        ) else (
            echo [DONE] 驱动已强制更新
        )
    ) else (
        echo [DONE] 设备驱动已更新
    )
) else (
    echo [INFO] 无 devcon，驱动将在设备枚举时自动加载
)

echo.
echo ============================================================
echo   安装完成！
echo   验证：设备管理器 -^> 人体学输入设备
echo         -^> "OpenCert FIDO2 Authenticator (HID)"
echo ============================================================
echo.
pause
exit /b 0
