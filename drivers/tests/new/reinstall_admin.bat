@echo off
chcp 65001 >nul 2>&1
setlocal

set "BUILD_DIR=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build"
set "UMDF_DIR=C:\Windows\System32\drivers\UMDF"

echo ============================================================
echo   UMDF Driver Reinstall (Admin)
echo ============================================================

echo [1/5] 禁用设备...
pnputil /disable-device "ROOT\OPENCERTFIDO\0000"

echo [2/5] 删除旧驱动包（保留最新）...
for /f "tokens=1" %%O in ('pnputil /enum-drivers 2^>nul ^| findstr /i "FidoMdfDriver" ^| findstr /i "oem"') do (
    echo   Checking %%O...
)

echo [3/5] 更新 DLL...
copy /Y "%BUILD_DIR%\FidoMdfDriver.dll" "%UMDF_DIR%\FidoMdfDriver.dll"
if %errorlevel% neq 0 (echo [FAILED] DLL copy & exit /b 1)
echo [DONE] DLL updated

echo [4/5] 更新驱动包（覆盖安装）...
pnputil /add-driver "%BUILD_DIR%\FidoMdfDriver.inf" /install
if %errorlevel% neq 0 (echo [WARN] add-driver returned error, continuing...)

echo [5/5] 启用设备...
pnputil /enable-device "ROOT\OPENCERTFIDO\0000"
timeout /t 3 /nobreak >nul

echo.
echo --- 设备状态 ---
pnputil /enum-devices /instanceid "ROOT\OPENCERTFIDO\0000"

echo.
echo --- Calais Readers 注册表 ---
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\Calais\Readers" /s

echo.
echo Done.
