@echo off
chcp 65001 >nul 2>&1

:: Sign and deploy OpenCertKSP.dll
:: Must run as Administrator

set "DLL_SRC=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\ksp\build\OpenCertKSP.dll"
set "DLL_DST=C:\WINDOWS\System32\OpenCertKSP.dll"

echo [1] Signing DLL...
signtool sign /n "Finnox" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "%DLL_SRC%"
if %errorlevel% neq 0 (
    echo [FAIL] Signing failed!
    exit /b 1
)

echo [2] Deploying to System32...
copy /Y "%DLL_SRC%" "%DLL_DST%"

echo [3] Verifying signature...
signtool verify /pa "%DLL_DST%"

echo [4] Testing KSP...
certutil -csp "OpenCert Key Storage Provider" -key

echo.
echo [5] Checking debug log...
if exist C:\ksp_debug.log (
    type C:\ksp_debug.log
) else (
    echo No debug log found
)
