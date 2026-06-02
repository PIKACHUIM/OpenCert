@echo off
chcp 65001 >nul 2>&1
echo [1] 启用 UMDF 详细日志...
wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true /ms:10485760
echo [OK] 日志已启用

echo [2] 清空旧日志...
wevtutil cl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" 2>nul

echo [3] 触发设备重新加载...
pnputil /disable-device "ROOT\OPENCERTFIDO\0000" >nul 2>&1
timeout /t 2 /nobreak >nul
pnputil /enable-device "ROOT\OPENCERTFIDO\0000" >nul 2>&1
timeout /t 3 /nobreak >nul

echo [4] 导出日志到文件...
wevtutil qe "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /f:text > "%TEMP%\umdf_log.txt" 2>&1
echo [OK] 日志已保存到 %TEMP%\umdf_log.txt

echo [5] 显示关键错误...
type "%TEMP%\umdf_log.txt" | findstr /i "error\|fail\|0xC\|OpenCert\|OPENCERTFIDO\|cannot\|unable"

echo.
echo 完整日志: %TEMP%\umdf_log.txt
pause
