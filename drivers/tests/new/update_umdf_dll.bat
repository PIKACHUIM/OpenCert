@echo off
chcp 65001 >nul 2>&1
:: 需要管理员权限运行
:: 将已签名的 FidoMdfDriver.dll 复制到 UMDF 目录并重新触发设备加载

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    echo         右键 -> 以管理员身份运行
    pause
    exit /b 1
)

set "SRC=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build\FidoMdfDriver.dll"
set "DST=C:\Windows\System32\drivers\UMDF\FidoMdfDriver.dll"

echo [1/3] 复制已签名的 DLL 到 UMDF 目录...
copy /Y "%SRC%" "%DST%"
if %errorlevel% neq 0 (
    echo [FAILED] 复制失败，请确认源文件存在且有管理员权限
    pause
    exit /b 1
)
echo [DONE] DLL 已更新: %DST%

echo [2/3] 重新触发设备加载（禁用再启用）...
pnputil /disable-device "ROOT\OPENCERTFIDO\0000" >nul 2>&1
timeout /t 1 /nobreak >nul
pnputil /enable-device "ROOT\OPENCERTFIDO\0000" >nul 2>&1
timeout /t 2 /nobreak >nul
echo [DONE] 设备已重新启用

echo [3/3] 验证设备状态...
pnputil /enum-devices /class SmartCardReader

echo.
echo 完成！如果状态显示"已启动"则驱动加载成功。
pause
