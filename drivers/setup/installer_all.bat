@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert Drivers - 一键安装 (管理员权限)
:: ============================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "BUILD_DIR=%SCRIPT_DIR%..\build"
set "KSP_NAME=OpenCert Key Storage Provider"
set "KSP_DLL=OpenCertKSP.dll"

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    pause & exit /b 1
)

echo.
echo ============================================================
echo   OpenCert Drivers - Install
echo ============================================================
echo.

:: Step 1: 部署 KSP DLL
echo [1/3] Deploying KSP DLLs...

if not exist "%BUILD_DIR%\OpenCertKSP_x64.dll" (
    echo       [SKIP] build\OpenCertKSP_x64.dll not found
) else (
    copy /Y "%BUILD_DIR%\OpenCertKSP_x64.dll" "%SystemRoot%\System32\%KSP_DLL%" >nul 2>&1
    echo       [DONE] %SystemRoot%\System32\%KSP_DLL% ^(x64^)
)

if not exist "%BUILD_DIR%\OpenCertKSP_x86.dll" (
    echo       [WARN] build\OpenCertKSP_x86.dll not found
) else (
    copy /Y "%BUILD_DIR%\OpenCertKSP_x86.dll" "%SystemRoot%\SysWOW64\%KSP_DLL%" >nul 2>&1
    echo       [DONE] %SystemRoot%\SysWOW64\%KSP_DLL% ^(x86^)
)

:: Step 2: 部署 CSP DLL
echo.
echo [2/3] Deploying CSP DLLs...

if not exist "%BUILD_DIR%\OpenCertCSP_x64.dll" (
    echo       [WARN] build\OpenCertCSP_x64.dll not found
) else (
    copy /Y "%BUILD_DIR%\OpenCertCSP_x64.dll" "%SystemRoot%\System32\OpenCertCSP.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\System32\OpenCertCSP.dll ^(x64^)
)

if not exist "%BUILD_DIR%\OpenCertCSP_x86.dll" (
    echo       [WARN] build\OpenCertCSP_x86.dll not found
) else (
    copy /Y "%BUILD_DIR%\OpenCertCSP_x86.dll" "%SystemRoot%\SysWOW64\OpenCertCSP.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\SysWOW64\OpenCertCSP.dll ^(x86^)
)

:: Step 3: 注册 KSP
echo.
echo [3/5] Registering KSP...

if exist "%SCRIPT_DIR%registers_ksp.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%registers_ksp.ps1" -KspName "%KSP_NAME%" -KspDll "%KSP_DLL%"
    if %errorlevel% neq 0 (
        echo       [WARN] BCryptRegisterProvider failed, using manual registry...
        set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
        reg add "!REG_KSP!\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
    )
) else (
    set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
    reg add "!REG_KSP!" /f >nul 2>&1
    reg add "!REG_KSP!\UM" /f >nul 2>&1
    reg add "!REG_KSP!\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
)
echo       [DONE] KSP registered: %KSP_NAME%

:: Step 4: 部署并注册 FIDO2 CCID DLL
echo.
echo [4/5] Deploying and registering FIDO2 CCID...

if not exist "%BUILD_DIR%\OpenCertFIDO_x64.dll" (
    echo       [WARN] build\OpenCertFIDO_x64.dll not found, skipping FIDO2
) else (
    copy /Y "%BUILD_DIR%\OpenCertFIDO_x64.dll" "%SystemRoot%\System32\OpenCertFIDO.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\System32\OpenCertFIDO.dll ^(x64^)
)

if not exist "%BUILD_DIR%\OpenCertFIDO_x86.dll" (
    echo       [WARN] build\OpenCertFIDO_x86.dll not found
) else (
    copy /Y "%BUILD_DIR%\OpenCertFIDO_x86.dll" "%SystemRoot%\SysWOW64\OpenCertFIDO.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\SysWOW64\OpenCertFIDO.dll ^(x86^)
)

if exist "%SCRIPT_DIR%register_fido.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%register_fido.ps1"
    if %errorlevel% neq 0 (
        echo       [WARN] FIDO2 registration failed
    ) else (
        echo       [DONE] FIDO2 CCID registered
    )
) else (
    echo       [WARN] register_fido.ps1 not found, skipping FIDO2 registration
)

:: Step 5: 安装 UMDF FIDO2 驱动（SmartCardReader 虚拟设备）
echo.
echo [5/5] Installing UMDF FIDO2 Driver...

set "UMDF_INF=%BUILD_DIR%\OpenCertFIDODriver.inf"
set "UMDF_PS1=%SCRIPT_DIR%..\codes\fido-umdf\scripts\create_device_node.ps1"

if not exist "%UMDF_INF%" (
    echo       [WARN] build\OpenCertFIDODriver.inf not found, skipping UMDF driver
    goto :verify
)

:: 移除旧设备节点（忽略失败，设备可能不存在）
echo       Removing old device node...
pnputil /remove-device "ROOT\OPENCERTFIDO\0000" >nul 2>&1

:: 查找并删除旧驱动包（oem*.inf 中匹配 OpenCertFIDODriver 的）
echo       Removing old driver package...
for /f "tokens=2 delims=: " %%N in ('pnputil /enum-drivers 2^>nul ^| findstr /i "OpenCertFIDODriver"') do (
    pnputil /delete-driver %%N /uninstall /force >nul 2>&1
)

:: 安装新驱动包
echo       Installing driver package...
pnputil /add-driver "%UMDF_INF%" /install
if %errorlevel% neq 0 (
    echo       [WARN] pnputil /add-driver failed
    goto :verify
)
echo       [DONE] Driver package installed

:: 创建设备节点
if not exist "%UMDF_PS1%" (
    echo       [WARN] create_device_node.ps1 not found, skipping device node creation
    goto :verify
)
echo       Creating device node...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%UMDF_PS1%" -InfFile "%UMDF_INF%"
if %errorlevel% neq 0 (
    echo       [WARN] Device node creation failed
) else (
    echo       [DONE] UMDF FIDO2 driver installed
)

:verify
:: 验证
echo.
echo   Verifying KSP...
powershell.exe -NoProfile -Command "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class V { [DllImport(\"ncrypt.dll\", CharSet=CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f); [DllImport(\"ncrypt.dll\")] public static extern int NCryptFreeObject(IntPtr h); }'; $h=[IntPtr]::Zero; $r=[V]::NCryptOpenStorageProvider([ref]$h,'%KSP_NAME%',0); if($r -eq 0){[V]::NCryptFreeObject($h)|Out-Null; Write-Host '      [DONE] KSP verified successfully'; exit 0}else{Write-Host \"      [WARN] KSP verify failed: 0x$($r.ToString('X8'))\"; exit 1}"

echo.
echo ============================================================
echo   Installation Complete!
echo ============================================================
echo.
pause
exit /b 0
