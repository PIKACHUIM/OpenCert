@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert Drivers - 一键安装 (管理员权限)
:: DLL 从 build/ 目录读取
:: ============================================================
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "BUILD_DIR=%ROOT%build"
set "KSP_NAME=OpenCert Key Storage Provider"
set "KSP_DLL=OpenCertKSP.dll"

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

:: Step 1: KSP
echo [1/3] Deploying KSP...
if exist "%BUILD_DIR%\OpenCertKSP_x64.dll" (
    copy /Y "%BUILD_DIR%\OpenCertKSP_x64.dll" "%SystemRoot%\System32\%KSP_DLL%" >nul 2>&1
    echo       [DONE] System32\%KSP_DLL% (x64)
) else (echo       [SKIP] OpenCertKSP_x64.dll not found in build\)

if exist "%BUILD_DIR%\OpenCertKSP_x86.dll" (
    copy /Y "%BUILD_DIR%\OpenCertKSP_x86.dll" "%SystemRoot%\SysWOW64\%KSP_DLL%" >nul 2>&1
    echo       [DONE] SysWOW64\%KSP_DLL% (x86)
) else (echo       [WARN] OpenCertKSP_x86.dll not found - 32-bit apps won't work)

:: Step 2: CSP
echo.
echo [2/3] Deploying CSP...
if exist "%BUILD_DIR%\OpenCertCSP_x64.dll" (
    copy /Y "%BUILD_DIR%\OpenCertCSP_x64.dll" "%SystemRoot%\System32\OpenCertCSP.dll" >nul 2>&1
    echo       [DONE] System32\OpenCertCSP.dll (x64)
) else (echo       [SKIP] OpenCertCSP_x64.dll not found)

if exist "%BUILD_DIR%\OpenCertCSP_x86.dll" (
    copy /Y "%BUILD_DIR%\OpenCertCSP_x86.dll" "%SystemRoot%\SysWOW64\OpenCertCSP.dll" >nul 2>&1
    echo       [DONE] SysWOW64\OpenCertCSP.dll (x86)
) else (echo       [WARN] OpenCertCSP_x86.dll not found)

:: Step 3: 注册 KSP
echo.
echo [3/3] Registering KSP...
set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
reg add "%REG_KSP%" /f >nul 2>&1
reg add "%REG_KSP%\UM" /f >nul 2>&1
reg add "%REG_KSP%\UM" /v "Image" /t REG_SZ /d "%KSP_DLL%" /f >nul 2>&1
echo       [DONE] KSP registered: %KSP_NAME%

:: 验证
echo.
powershell.exe -NoProfile -Command "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class V { [DllImport(\"ncrypt.dll\", CharSet=CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f); [DllImport(\"ncrypt.dll\")] public static extern int NCryptFreeObject(IntPtr h); }'; $h=[IntPtr]::Zero; $r=[V]::NCryptOpenStorageProvider([ref]$h,'OpenCert Key Storage Provider',0); if($r -eq 0){[V]::NCryptFreeObject($h)|Out-Null; Write-Host '  [DONE] KSP verified'}else{Write-Host \"  [WARN] KSP verify failed: 0x$($r.ToString('X8'))\"}"

echo.
echo ============================================================
echo   Installation Complete!
echo ============================================================
pause
exit /b 0
