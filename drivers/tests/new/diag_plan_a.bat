@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

set "ROOT=G:\Codes\GlobalTrusts\PKCS11Driver\drivers"
set "BUILD_DIR=%ROOT%\build"
set "UMDF_DIR=C:\Windows\System32\drivers\UMDF"
set "DIAG_DIR=%ROOT%\setup\diag_a"
set "TRACE_LOG=C:\ProgramData\opencertfido_trace.log"

if not exist "%DIAG_DIR%" mkdir "%DIAG_DIR%"

echo.
echo ============================================================
echo  Step 1: Take ownership and replace target DLL
echo ============================================================
takeown /F "%UMDF_DIR%\FidoMdfDriver.dll" /A >nul 2>&1
icacls "%UMDF_DIR%\FidoMdfDriver.dll" /grant Administrators:F >nul 2>&1
copy /Y "%BUILD_DIR%\FidoMdfDriver.dll" "%UMDF_DIR%\FidoMdfDriver.dll"
if %errorlevel% neq 0 (
    echo [FAILED] Cannot replace DLL
    exit /b 1
)
set "src_size=0"
set "tgt_size=0"
for %%F in ("%BUILD_DIR%\FidoMdfDriver.dll")  do set "src_size=%%~zF"
for %%F in ("%UMDF_DIR%\FidoMdfDriver.dll")   do set "tgt_size=%%~zF"
echo [DONE] Replaced %UMDF_DIR%\FidoMdfDriver.dll
echo      target=!tgt_size! bytes, source=!src_size! bytes

echo.
echo ============================================================
echo  Step 2: Start ETW WUDF + PnP traces
echo ============================================================
wevtutil sl Microsoft-Windows-WUDF-Reflector/Operational /e:true >nul 2>&1
logman create trace "wudf_diag" -p {6214b4d8-1a3e-4a4e-b7e3-d5f7a3e5c5b2} -o "%DIAG_DIR%\wudf.etl" -ow >nul 2>&1
logman start "wudf_diag" >nul 2>&1
echo The command completed successfully.

echo.
echo ============================================================
echo  Step 3: Trigger device disable/enable
echo ============================================================
echo Disabling ROOT\OPENCERTFIDO\0000 ...
pnputil /disable-device "ROOT\OPENCERTFIDO\0000"
timeout /t 2 /nobreak >nul

echo Enabling ROOT\OPENCERTFIDO\0000 ...
pnputil /enable-device "ROOT\OPENCERTFIDO\0000"
timeout /t 3 /nobreak >nul

echo.
echo ============================================================
echo  Step 4: Stop ETW and export to text
echo ============================================================
logman stop "wudf_diag" >nul 2>&1
logman delete "wudf_diag" >nul 2>&1
if exist "%DIAG_DIR%\wudf.etl" (
    tracerpt "%DIAG_DIR%\wudf.etl" -o "%DIAG_DIR%\wudf.xml" -of XML >nul 2>&1
    echo [DONE] WUDF ETW exported to %DIAG_DIR%\wudf.xml
) else (
    echo [WARN] No ETL file found
)

echo.
echo ============================================================
echo  Step 5: Dump device status
echo ============================================================
pnputil /enum-devices /instanceid "ROOT\OPENCERTFIDO\0000"

echo.
echo ============================================================
echo  Step 6: Capture System event log (last 5 minutes)
echo ============================================================
powershell -NoProfile -Command "Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and ($_.Message -like '*OPENCERTFIDO*' -or $_.Message -like '*WUDFRd*' -or $_.Message -like '*SmartCard*') } | Format-List TimeCreated,Id,Message" 2>nul

echo.
echo ============================================================
echo  Diagnostics complete. Outputs in %DIAG_DIR%
echo ============================================================

echo.
echo ============================================================
echo  Step 7: Driver self-trace from %TRACE_LOG%
echo ============================================================
if exist "%TRACE_LOG%" (
    type "%TRACE_LOG%"
) else (
    echo [WARN] Trace log not found: %TRACE_LOG%
)
