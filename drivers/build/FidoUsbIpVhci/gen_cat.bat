@echo off
chcp 65001 >nul 2>&1
setlocal

set "INF2CAT=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\Inf2Cat.exe"
set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
set "DRIVER_DIR=%~dp0"
set "PFX=%~dp0usbip_test.pfx"

:: 移除末尾反斜杠
if "%DRIVER_DIR:~-1%"=="\" set "DRIVER_DIR=%DRIVER_DIR:~0,-1%"

echo [1/2] 生成 .cat 文件...
"%INF2CAT%" /driver:"%DRIVER_DIR%" /os:10_X64 /verbose
if %errorlevel% neq 0 (
    echo [FAIL] Inf2Cat 失败
    pause & exit /b 1
)
echo [DONE] .cat 文件已生成

echo.
echo [2/2] 签名 .cat 文件...
if exist "%PFX%" (
    "%SIGNTOOL%" sign /f "%PFX%" /t http://timestamp.digicert.com /fd sha256 "%DRIVER_DIR%\usbip_vhci.cat"
    "%SIGNTOOL%" sign /f "%PFX%" /t http://timestamp.digicert.com /fd sha256 "%DRIVER_DIR%\usbip_vhci_ude.cat"
    echo [DONE] 签名完成
) else (
    echo [SKIP] 未找到 usbip_test.pfx，跳过签名
)

echo.
echo 完成！
pause
