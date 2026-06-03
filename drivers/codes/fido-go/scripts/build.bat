@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

echo ============================================================
echo  OpenCert FIDO2 虚拟设备 - 构建脚本
echo ============================================================
echo.

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set OUTPUT_DIR=%PROJECT_DIR%\bin

:: 检查 Go 环境
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 找不到 go 命令，请安装 Go 1.22+
    pause
    exit /b 1
)

echo [1/3] 下载依赖...
cd /d "%PROJECT_DIR%"
go mod tidy
if %errorlevel% neq 0 (
    echo [错误] go mod tidy 失败
    pause
    exit /b 1
)

echo [2/3] 编译 fido-go.exe...
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
go build -o "%OUTPUT_DIR%\fido-go.exe" ./cmd/fido-go
if %errorlevel% neq 0 (
    echo [错误] 编译失败
    pause
    exit /b 1
)

echo [3/3] 复制 usbip 工具...
:: 从 virtual-fido-ref 复制 usbip 工具（如果存在）
set USBIP_SRC=G:\Codes\GlobalTrusts\virtual-fido-ref\cmd\demo\usbip\bin
set USBIP_DST=%OUTPUT_DIR%\usbip

if exist "%USBIP_SRC%" (
    if not exist "%USBIP_DST%" mkdir "%USBIP_DST%"
    copy /Y "%USBIP_SRC%\usbip.exe" "%USBIP_DST%\" >nul 2>&1
    copy /Y "%USBIP_SRC%\usbip_vhci.inf" "%USBIP_DST%\" >nul 2>&1
    copy /Y "%USBIP_SRC%\usbip_vhci.sys" "%USBIP_DST%\" >nul 2>&1
    copy /Y "%USBIP_SRC%\usbip_vhci.cat" "%USBIP_DST%\" >nul 2>&1
    echo [成功] usbip 工具已复制到 %USBIP_DST%
) else (
    echo [提示] 未找到 virtual-fido-ref usbip 工具，请手动复制到 %USBIP_DST%
)

echo.
echo ============================================================
echo  构建完成！
echo  输出目录: %OUTPUT_DIR%
echo.
echo  使用方法:
echo    1. 首次安装: scripts\install_usbip.bat  (需要管理员权限)
echo    2. 启动后端: 运行 client-card.exe
echo    3. 启动设备: bin\fido-go.exe
echo ============================================================
