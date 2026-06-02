@echo off
chcp 65001 >nul 2>&1

echo === UMDF DriverFrameworks 错误日志 ===
powershell -NoProfile -Command ^
  "$events = Get-WinEvent -LogName 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' -MaxEvents 500 -EA SilentlyContinue;" ^
  "if ($events) {" ^
  "  $filtered = $events | Where-Object { $_.Level -le 3 -or $_.Message -match 'OpenCert|OPENCERTFIDO|WUDFHost|oem135' };" ^
  "  $filtered | Select-Object -First 20 | ForEach-Object { Write-Host ('---[' + $_.TimeCreated + '] ID=' + $_.Id + ' Level=' + $_.LevelDisplayName); Write-Host $_.Message; Write-Host '' }" ^
  "} else { Write-Host 'No events found' }"

echo.
echo === System 日志中 UMDF 相关错误 ===
powershell -NoProfile -Command ^
  "$events = Get-WinEvent -LogName 'System' -MaxEvents 500 -EA SilentlyContinue;" ^
  "$filtered = $events | Where-Object { $_.Message -match 'UMDF|WUDFHost|OpenCert|OPENCERTFIDO|WUDFRd' } | Select-Object -First 10;" ^
  "$filtered | ForEach-Object { Write-Host ('---[' + $_.TimeCreated + '] ID=' + $_.Id); Write-Host $_.Message; Write-Host '' }"

echo.
echo === Kernel-PnP 日志中 OPENCERTFIDO 相关 ===
powershell -NoProfile -Command ^
  "$events = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 500 -EA SilentlyContinue;" ^
  "$filtered = $events | Where-Object { $_.Message -match 'OPENCERTFIDO|OpenCert' } | Select-Object -First 10;" ^
  "$filtered | ForEach-Object { Write-Host ('---[' + $_.TimeCreated + '] ID=' + $_.Id); Write-Host $_.Message; Write-Host '' }"

echo DONE
