@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

set "BUILD_DIR=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build"
set "UMDF_PS1=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\codes\fido-umdf\scripts\create_device_node.ps1"
set "UMDF_DIR=C:\Windows\System32\drivers\UMDF"

echo ============================================================
echo   UMDF Driver Full Reinstall
echo ============================================================
echo.

echo [1/6] 移除旧设备节点...
pnputil /remove-device "ROOT\OPENCERTFIDO\0000" 2>&1
echo.

echo [2/6] 删除所有 OpenCertFIDO 驱动包...
powershell -NoProfile -Command "$out = pnputil /enum-drivers 2>&1 | Out-String; $blocks = $out -split '\r?\n\r?\n'; foreach ($b in $blocks) { if ($b -match 'FidoMdfDriver' -and $b -match '(oem\d+\.inf)') { $oem = $matches[1]; Write-Host \"  Deleting: $oem\"; pnputil /delete-driver $oem /uninstall /force 2>&1 | Write-Host } }"
echo.

echo [3/6] 强制更新 UMDF 目录中的 DLL...
if not exist "%UMDF_DIR%" mkdir "%UMDF_DIR%"
copy /Y "%BUILD_DIR%\FidoMdfDriver.dll" "%UMDF_DIR%\FidoMdfDriver.dll"
if %errorlevel% neq 0 (
    echo [FAILED] 无法复制 DLL 到 UMDF 目录！
    pause & exit /b 1
)
echo [DONE] DLL 已更新到 %UMDF_DIR%
echo.

echo [4/6] 安装新驱动包...
pnputil /add-driver "%BUILD_DIR%\FidoMdfDriver.inf" /install
if %errorlevel% neq 0 (
    echo [FAILED] pnputil add-driver failed!
    pause & exit /b 1
)
echo.

echo [5/6] 创建设备节点...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%UMDF_PS1%" -InfFile "%BUILD_DIR%\FidoMdfDriver.inf"
echo.

echo [6/6] 验证设备状态...
pnputil /enum-devices /class SmartCardReader
echo.

echo --- 验证 UMDF 目录中的 DLL 依赖 ---
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\dumpbin.exe" /dependents "%UMDF_DIR%\FidoMdfDriver.dll" 2>&1

pause
