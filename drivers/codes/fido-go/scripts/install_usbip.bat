@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

echo ============================================================
echo  OpenCert FIDO2 虚拟设备 - USB/IP 驱动安装
echo  (基于 usbip-win 项目)
echo ============================================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 需要管理员权限，请右键以管理员身份运行
    pause
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set USBIP_DIR=%SCRIPT_DIR%..\bin\usbip

echo 驱动目录: %USBIP_DIR%
echo.

:: ---- 检查文件 ----
if not exist "%USBIP_DIR%\usbip.exe" (
    echo [错误] 找不到 %USBIP_DIR%\usbip.exe
    pause
    exit /b 1
)
if not exist "%USBIP_DIR%\usbip_test.pfx" (
    echo [错误] 找不到 %USBIP_DIR%\usbip_test.pfx
    pause
    exit /b 1
)

:: ---- 步骤1：安装测试证书 ----
echo [1/3] 安装 usbip 测试证书...
echo   安装到"受信任的根证书颁发机构"...
certutil -addstore -f "Root" "%USBIP_DIR%\usbip_test.pfx" >nul 2>&1
if %errorlevel% neq 0 (
    :: certutil 对 pfx 用 -importpfx
    certutil -f -importpfx -p usbip Root "%USBIP_DIR%\usbip_test.pfx" >nul 2>&1
)
echo   安装到"受信任的发布者"...
certutil -f -importpfx -p usbip TrustedPublisher "%USBIP_DIR%\usbip_test.pfx" >nul 2>&1

:: 用 PowerShell 方式安装（更可靠）
powershell -Command "$pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2; $pfx.Import('%USBIP_DIR%\usbip_test.pfx', 'usbip', 'PersistKeySet'); $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); $store.Open('ReadWrite'); $store.Add($pfx); $store.Close(); $store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine'); $store2.Open('ReadWrite'); $store2.Add($pfx); $store2.Close(); Write-Host '证书安装成功'" 2>&1
echo.

:: ---- 步骤2：开启测试签名 ----
echo [2/3] 开启 Windows 测试签名模式...
bcdedit /set TESTSIGNING ON
if %errorlevel% neq 0 (
    echo [警告] 开启测试签名失败（可能已开启或需要关闭安全启动）
) else (
    echo [成功] 测试签名已开启，需要重启后生效
)
echo.

:: ---- 步骤3：安装 VHCI 驱动 ----
echo [3/3] 安装 usbip VHCI 驱动...
cd /d "%USBIP_DIR%"
usbip.exe install
if %errorlevel% neq 0 (
    echo [警告] usbip install 失败，尝试手动 pnputil 方式...
    pnputil /add-driver "%USBIP_DIR%\usbip_vhci_ude.inf" /install
    if !errorlevel! neq 0 (
        pnputil /add-driver "%USBIP_DIR%\usbip_vhci.inf" /install
    )
)
echo.

:: ---- 验证 ----
echo 验证驱动状态...
sc query usbip_vhci_ude >nul 2>&1
if %errorlevel% equ 0 (
    echo [成功] usbip_vhci_ude 驱动已安装
    goto :done
)
sc query usbip_vhci >nul 2>&1
if %errorlevel% equ 0 (
    echo [成功] usbip_vhci 驱动已安装
    goto :done
)
echo [提示] 驱动可能需要重启后生效

:done
echo.
echo ============================================================
echo  安装完成！
echo.
echo  ⚠️  重要：如果这是首次安装，请重启计算机后再使用
echo.
echo  重启后使用方法：
echo    1. 启动 client-card 后端
echo    2. 运行 fido-go.exe
echo    3. 或手动: cd bin\usbip ^&^& usbip.exe attach -r 127.0.0.1 -b 2-2
echo ============================================================
pause
