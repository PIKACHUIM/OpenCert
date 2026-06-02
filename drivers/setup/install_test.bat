@echo off
chcp 65001 >nul 2>&1
set "BUILD_DIR=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build"
set "UMDF_PS1=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\codes\fido-umdf\scripts\create_device_node.ps1"
set "UMDF_DIR=C:\Windows\System32\drivers\UMDF"

echo [1] 移除所有旧设备节点...
pnputil /remove-device "ROOT\OPENCERTFIDO\0000" 2>&1
pnputil /remove-device "ROOT\OPENCERTFIDO\0001" 2>&1
pnputil /remove-device "ROOT\OPENCERTFIDO\0002" 2>&1

echo [2] 删除所有旧驱动包...
powershell -NoProfile -Command "$out = pnputil /enum-drivers 2>&1 | Out-String; $blocks = $out -split '\r?\n\r?\n'; foreach ($b in $blocks) { if ($b -match 'opencertfidodriver' -and $b -match '(oem\d+\.inf)') { $oem = $matches[1]; Write-Host \"  Deleting: $oem\"; pnputil /delete-driver $oem /uninstall /force 2>&1 | Write-Host } }"

echo [3] 复制新 DLL 到 UMDF 目录...
copy /Y "%BUILD_DIR%\OpenCertFIDODriver.dll" "%UMDF_DIR%\OpenCertFIDODriver.dll"

echo [4] 安装新驱动包...
pnputil /add-driver "%BUILD_DIR%\OpenCertFIDODriver.inf" /install

echo [5] 创建设备节点...
powershell -NoProfile -ExecutionPolicy Bypass -File "%UMDF_PS1%" -InfFile "%BUILD_DIR%\OpenCertFIDODriver.inf"

echo [6] 验证...
pnputil /enum-devices /class SmartCardReader
pause
