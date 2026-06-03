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

:: Step 5: 安装 HID FIDO2 驱动（虚拟 HID 设备）
echo.
echo [5/5] Installing HID FIDO2 Driver...

set "HID_INF=%BUILD_DIR%\OpenCertFIDOHidDriver.inf"
set "HID_DLL=%BUILD_DIR%\OpenCertFIDOHidDriver.dll"

:: ---- 注释掉旧的 UMDF 驱动安装 ----
:: set "UMDF_INF=%BUILD_DIR%\OpenCertFIDODriver.inf"
:: set "UMDF_PS1=%SCRIPT_DIR%..\codes\fido-umdf\scripts\create_device_node.ps1"
:: if not exist "%UMDF_INF%" goto :verify
:: pnputil /remove-device "ROOT\OPENCERTFIDO\0000" >nul 2>&1
:: for /f "tokens=2 delims=: " %%N in ('pnputil /enum-drivers 2^>nul ^| findstr /i "OpenCertFIDODriver"') do (
::     pnputil /delete-driver %%N /uninstall /force >nul 2>&1
:: )
:: pnputil /add-driver "%UMDF_INF%" /install
:: powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%UMDF_PS1%" -InfFile "%UMDF_INF%"
:: ---- 旧 UMDF 安装结束 ----

if not exist "!HID_DLL!" (
    echo       [WARN] build\OpenCertFIDOHidDriver.dll not found, skipping HID driver
    goto :verify
)
if not exist "!HID_INF!" (
    echo       [WARN] build\OpenCertFIDOHidDriver.inf not found, skipping HID driver
    goto :verify
)

:: Find devcon.exe
set "DEVCON="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\Tools\*") do (
    if exist "%%V\x64\devcon.exe" if "!DEVCON!"=="" set "DEVCON=%%V\x64\devcon.exe"
)
if "!DEVCON!"=="" (
    where devcon >nul 2>&1
    if !errorlevel! equ 0 set "DEVCON=devcon"
)

:: Create device node
if "!DEVCON!"=="" (
    echo       [WARN] devcon.exe not found, skipping device node creation
    goto :hid_install_pkg
)
"!DEVCON!" find "ROOT\OPENCERTFIDOHID" >nul 2>&1
if !errorlevel! equ 0 (
    echo       [INFO] Device node already exists
) else (
    "!DEVCON!" install "!HID_INF!" "ROOT\OPENCERTFIDOHID"
    if !errorlevel! neq 0 (
        echo       [WARN] Device node creation failed
        goto :hid_install_pkg
    )
    echo       [DONE] Device node created
)

:hid_install_pkg
:: Add driver package
pnputil /add-driver "!HID_INF!" /install
if !errorlevel! neq 0 (
    echo       [WARN] pnputil /add-driver returned non-zero
) else (
    echo       [DONE] HID driver package installed
)

:: Update device driver
if not "!DEVCON!"=="" (
    "!DEVCON!" update "!HID_INF!" "ROOT\OPENCERTFIDOHID"
    if !errorlevel! neq 0 (
        pnputil /add-driver "!HID_INF!" /install /force >nul 2>&1
        echo       [WARN] devcon update failed, forced update attempted
    ) else (
        echo       [DONE] HID FIDO2 driver updated
    )
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
