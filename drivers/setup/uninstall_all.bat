@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert Drivers - 一键卸载 (管理员权限)
:: ============================================================
setlocal

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

:: 删除 DLL
echo [1/2] Removing DLLs...
del /F "%SystemRoot%\System32\%KSP_DLL%" >nul 2>&1
del /F "%SystemRoot%\SysWOW64\%KSP_DLL%" >nul 2>&1
del /F "%SystemRoot%\System32\OpenCertCSP.dll" >nul 2>&1
del /F "%SystemRoot%\SysWOW64\OpenCertCSP.dll" >nul 2>&1
echo       [OK] DLLs removed

:: 删除注册表
echo [2/2] Removing registry entries...
set "REG_KSP=HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\%KSP_NAME%"
reg delete "%REG_KSP%" /f >nul 2>&1
echo       [OK] KSP unregistered

echo.
echo ============================================================
echo   Uninstall Complete!
echo ============================================================
pause
exit /b 0
