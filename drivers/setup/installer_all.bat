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

:: 结果变量
set "RESULT_KSP=SKIP"
set "RESULT_CSP=SKIP"
set "RESULT_REG=SKIP"
set "RESULT_CCID=SKIP"
set "RESULT_HID=SKIP"
set "RESULT_USBIP=SKIP"

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo       [FAIL] Please run as Administrator!
    pause & exit /b 1
)

echo.
echo ============================================================
echo   OpenCert Drivers - Install
echo ============================================================

:: ================================================================
:: [Pre-check] 环境与组件检查
:: ================================================================
echo.
echo [Pre-check] Checking environment and components...

if not exist "%BUILD_DIR%" (
    echo       [FAIL] build/ directory not found: %BUILD_DIR%
    pause & exit /b 1
)
echo       [DONE] build/ directory

:: KSP
set "HAS_KSP_X64=0"
set "HAS_KSP_X86=0"
if exist "%BUILD_DIR%\OpenCertKSP_x64.dll" (set "HAS_KSP_X64=1" & echo       [DONE] OpenCertKSP_x64.dll) else (echo       [MISSING] OpenCertKSP_x64.dll)
if exist "%BUILD_DIR%\OpenCertKSP_x86.dll" (set "HAS_KSP_X86=1" & echo       [DONE] OpenCertKSP_x86.dll) else (echo       [MISSING] OpenCertKSP_x86.dll)

:: CSP
set "HAS_CSP_X64=0"
set "HAS_CSP_X86=0"
if exist "%BUILD_DIR%\OpenCertCSP_x64.dll" (set "HAS_CSP_X64=1" & echo       [DONE] OpenCertCSP_x64.dll) else (echo       [MISSING] OpenCertCSP_x64.dll)
if exist "%BUILD_DIR%\OpenCertCSP_x86.dll" (set "HAS_CSP_X86=1" & echo       [DONE] OpenCertCSP_x86.dll) else (echo       [MISSING] OpenCertCSP_x86.dll)

:: FIDO CCID
set "HAS_FIDO_X64=0"
set "HAS_FIDO_X86=0"
if exist "%BUILD_DIR%\OpenFIDOLib_x64.dll" (set "HAS_FIDO_X64=1" & echo       [DONE] OpenFIDOLib_x64.dll) else (echo       [MISSING] OpenFIDOLib_x64.dll)
if exist "%BUILD_DIR%\OpenFIDOLib_x86.dll" (set "HAS_FIDO_X86=1" & echo       [DONE] OpenFIDOLib_x86.dll) else (echo       [MISSING] OpenFIDOLib_x86.dll)

:: HID (disabled - 已切换到 USB/IP 方案)
:: set "HAS_HID=0"
:: if exist "%BUILD_DIR%\FidoHidDriver\FidoHidDriver.dll" (
::     if exist "%BUILD_DIR%\FidoHidDriver\FidoHidDriver.inf" (
::         set "HAS_HID=1"
::         echo       [DONE] FidoHidDriver.dll + .inf
::     ) else (
::         echo       [MISSING] FidoHidDriver.inf
::     )
:: ) else (
::     echo       [MISSING] FidoHidDriver.dll
:: )

:: USB/IP VHCI
set "HAS_USBIP=0"
if exist "%BUILD_DIR%\FidoUsbIpVhci\usbip_vhci_ude.sys" (
    if exist "%BUILD_DIR%\FidoUsbIpVhci\usbip_vhci_ude.inf" (
        set "HAS_USBIP=1"
        echo       [DONE] FidoUsbIpVhci\usbip_vhci_ude.sys + .inf
    ) else (
        echo       [MISSING] FidoUsbIpVhci\usbip_vhci_ude.inf
    )
) else (
    echo       [MISSING] FidoUsbIpVhci\usbip_vhci_ude.sys
)

:: fido-go
set "HAS_FIDOGO=0"
if exist "%BUILD_DIR%\fido-go.exe" (
    set "HAS_FIDOGO=1"
    echo       [DONE] fido-go.exe
) else (
    echo       [MISSING] fido-go.exe
)

:: 组件开关
set "RUN_KSP=0"
if "!HAS_KSP_X64!"=="1" set "RUN_KSP=1"
if "!HAS_KSP_X86!"=="1" set "RUN_KSP=1"

set "RUN_CSP=0"
if "!HAS_CSP_X64!"=="1" set "RUN_CSP=1"
if "!HAS_CSP_X86!"=="1" set "RUN_CSP=1"

set "RUN_FIDO=0"
if "!HAS_FIDO_X64!"=="1" set "RUN_FIDO=1"
if "!HAS_FIDO_X86!"=="1" set "RUN_FIDO=1"

:: set "RUN_HID=!HAS_HID!"
set "RUN_USBIP=!HAS_USBIP!"

:: ================================================================
:: [1/5] 部署 KSP DLL
:: ================================================================
echo.
echo [1/5] Deploying KSP DLLs...

if "!RUN_KSP!"=="0" (
    echo       [SKIP] KSP DLLs not found
    set "RESULT_KSP=SKIP"
    goto :step2
)

set "RESULT_KSP=OK"
if "!HAS_KSP_X64!"=="1" (
    copy /Y "%BUILD_DIR%\OpenCertKSP_x64.dll" "%SystemRoot%\System32\%KSP_DLL%" >nul 2>&1
    echo       [DONE] %SystemRoot%\System32\%KSP_DLL% ^(x64^)
)
if "!HAS_KSP_X86!"=="1" (
    copy /Y "%BUILD_DIR%\OpenCertKSP_x86.dll" "%SystemRoot%\SysWOW64\%KSP_DLL%" >nul 2>&1
    echo       [DONE] %SystemRoot%\SysWOW64\%KSP_DLL% ^(x86^)
)

:step2
:: ================================================================
:: [2/5] 部署 CSP DLL
:: ================================================================
echo.
echo [2/5] Deploying CSP DLLs...

if "!RUN_CSP!"=="0" (
    echo       [SKIP] CSP DLLs not found
    set "RESULT_CSP=SKIP"
    goto :step3
)

set "RESULT_CSP=OK"
if "!HAS_CSP_X64!"=="1" (
    copy /Y "%BUILD_DIR%\OpenCertCSP_x64.dll" "%SystemRoot%\System32\OpenCertCSP.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\System32\OpenCertCSP.dll ^(x64^)
)
if "!HAS_CSP_X86!"=="1" (
    copy /Y "%BUILD_DIR%\OpenCertCSP_x86.dll" "%SystemRoot%\SysWOW64\OpenCertCSP.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\SysWOW64\OpenCertCSP.dll ^(x86^)
)

:step3
:: ================================================================
:: [3/5] 注册 KSP (CNG)
:: ================================================================
echo.
echo [3/5] Registering KSP (CNG)...

if "!RUN_KSP!"=="0" (
    echo       [SKIP] KSP not deployed, skipping registration
    set "RESULT_REG=SKIP"
    goto :step4
)

if exist "%SCRIPT_DIR%register_cert.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%register_cert.ps1" -KspName "%KSP_NAME%" -KspDll "%KSP_DLL%"
    if !errorlevel! neq 0 (
        echo       [WARN] register_cert.ps1 failed, using manual registry...
        set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
        reg add "!REG_KSP!\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
        set "RESULT_REG=OK"
    ) else (
        set "RESULT_REG=OK"
    )
) else (
    echo       [WARN] register_cert.ps1 not found, using manual registry...
    set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
    reg add "!REG_KSP!" /f >nul 2>&1
    reg add "!REG_KSP!\UM" /f >nul 2>&1
    reg add "!REG_KSP!\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
    set "RESULT_REG=OK"
)

:step4
:: ================================================================
:: [4/5] 部署并注册 FIDO2 CCID
:: ================================================================
echo.
echo [4/5] Deploying and registering FIDO2 CCID...

if "!RUN_FIDO!"=="0" (
    echo       [SKIP] FIDO2 DLLs not found
    set "RESULT_CCID=SKIP"
    goto :step5
)

if "!HAS_FIDO_X64!"=="1" (
    copy /Y "%BUILD_DIR%\OpenFIDOLib_x64.dll" "%SystemRoot%\System32\OpenCertFIDO.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\System32\OpenCertFIDO.dll ^(x64^)
)
if "!HAS_FIDO_X86!"=="1" (
    copy /Y "%BUILD_DIR%\OpenFIDOLib_x86.dll" "%SystemRoot%\SysWOW64\OpenCertFIDO.dll" >nul 2>&1
    echo       [DONE] %SystemRoot%\SysWOW64\OpenCertFIDO.dll ^(x86^)
)

if exist "%SCRIPT_DIR%register_ccid.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%register_ccid.ps1"
    if !errorlevel! neq 0 (
        echo       [WARN] FIDO2 CCID registration failed
        set "RESULT_CCID=FAIL"
    ) else (
        set "RESULT_CCID=OK"
    )
) else (
    echo       [WARN] register_ccid.ps1 not found
    set "RESULT_CCID=FAIL"
)

:step5
:: ================================================================
:: [5/5] 安装 HID FIDO2 驱动 (disabled - 已切换到 USB/IP 方案)
:: ================================================================
:: echo.
:: echo [5/5] Installing HID FIDO2 Driver...
:: if "!RUN_HID!"=="0" (
::     echo       [SKIP] HID driver files not found
::     set "RESULT_HID=SKIP"
::     goto :step6
:: )
:: if exist "%SCRIPT_DIR%register_fido.ps1" (
::     powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%register_fido.ps1"
::     if !errorlevel! neq 0 (
::         echo       [WARN] HID driver installation returned non-zero
::         set "RESULT_HID=FAIL"
::     ) else (
::         set "RESULT_HID=OK"
::     )
:: ) else (
::     echo       [WARN] register_fido.ps1 not found
::     set "RESULT_HID=FAIL"
:: )

:step6
:: ================================================================
:: [5/5] 安装 USB/IP VHCI 驱动 + 启动 fido-go
:: ================================================================
echo.
echo [5/5] Installing USB/IP VHCI Driver...

if "!RUN_USBIP!"=="0" (
    echo       [SKIP] USB/IP driver files not found
    set "RESULT_USBIP=SKIP"
    goto :summary
)

if exist "%SCRIPT_DIR%register_vhci.ps1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%register_vhci.ps1" -BuildDir "%BUILD_DIR%\FidoUsbIpVhci"
    if !errorlevel! neq 0 (
        echo       [WARN] USB/IP driver installation returned non-zero
        set "RESULT_USBIP=FAIL"
    ) else (
        set "RESULT_USBIP=OK"
    )
) else (
    echo       [WARN] register_vhci.ps1 not found
    set "RESULT_USBIP=FAIL"
)

:summary
:: ================================================================
:: 验证 KSP
:: ================================================================
echo.
echo   Verifying KSP...
powershell.exe -NoProfile -Command "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class V { [DllImport(\"ncrypt.dll\", CharSet=CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f); [DllImport(\"ncrypt.dll\")] public static extern int NCryptFreeObject(IntPtr h); }'; $h=[IntPtr]::Zero; $r=[V]::NCryptOpenStorageProvider([ref]$h,'%KSP_NAME%',0); if($r -eq 0){[V]::NCryptFreeObject($h)|Out-Null; Write-Host '      [DONE] KSP verified successfully'; exit 0}else{Write-Host \"      [WARN] KSP verify failed: 0x$($r.ToString('X8'))\"; exit 1}"

:: ================================================================
:: Installation Summary
:: ================================================================
echo.
echo ============================================================
echo   Installation Summary
echo ============================================================
echo   KSP DLLs           : [!RESULT_KSP!]
echo   CSP DLLs           : [!RESULT_CSP!]
echo   KSP CNG Register   : [!RESULT_REG!]
echo   FIDO2 CCID         : [!RESULT_CCID!]
echo   HID FIDO2 Driver   : [!RESULT_HID!] (disabled)
echo   USB/IP VHCI Driver : [!RESULT_USBIP!]
echo ============================================================
echo.
echo   Next steps:
echo     1. Start client-card backend service
echo     2. Open WebAuthn test site in browser
echo     3. Verify device in Device Manager (devmgmt.msc)
echo.

:: 计算退出码
set "EXIT_CODE=0"
if "!RESULT_KSP!"=="FAIL" set "EXIT_CODE=1"
if "!RESULT_CSP!"=="FAIL" set "EXIT_CODE=1"
if "!RESULT_REG!"=="FAIL" set "EXIT_CODE=1"
if "!RESULT_CCID!"=="FAIL" set "EXIT_CODE=1"
:: if "!RESULT_HID!"=="FAIL" set "EXIT_CODE=1"
if "!RESULT_USBIP!"=="FAIL" set "EXIT_CODE=1"

pause
exit /b !EXIT_CODE!