@echo off
chcp 65001 >nul 2>&1
setlocal

echo [1/3] Disable device...
pnputil /disable-device "ROOT\OPENCERTFIDO\0000"
timeout /t 2 /nobreak >nul

echo [2/3] Enable device...
pnputil /enable-device "ROOT\OPENCERTFIDO\0000"
timeout /t 3 /nobreak >nul

echo [3/3] Check device status...
pnputil /enum-devices /instanceid "ROOT\OPENCERTFIDO\0000"

echo.
echo --- Calais Readers ---
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\Calais\Readers" /s

echo Done.
