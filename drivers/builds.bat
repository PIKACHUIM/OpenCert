@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert Drivers - Build Script
:: Output: build/ directory
:: ============================================================
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"

:: ============================================================
:: Environment Detection
:: ============================================================
set "VSBASE="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build"
) do if exist %%P if "!VSBASE!"=="" set "VSBASE=%%~P"

if "!VSBASE!"=="" (echo [FAIL] Visual Studio not found! & exit /b 1)

:: Find signtool.exe
set "SIGNTOOL="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x64\signtool.exe" if "!SIGNTOOL!"=="" set "SIGNTOOL=%%V\x64\signtool.exe"
)

:: EV Certificate Thumbprint (Finnox Technology)
set "EV_THUMBPRINT=929F16F67222DCFA6A3C15A774F5F460FA79FED1"

if not exist "build" mkdir build

echo.
echo ============================================================
echo   OpenCert Drivers Build
echo ============================================================

:: ============================================================
:: [1/3] Build KSP + CSP + FIDO DLLs (cl.exe)
:: ============================================================
echo.
echo [1/3] Building KSP + CSP + FIDO DLLs...

:: ---- x64 ----
echo       [x64] Initializing VC environment...
call "!VSBASE!\vcvars64.bat" >nul 2>&1

:: --- KSP x64 (uncomment to enable) ---
:: cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
::     codes\ksp\codes\opencert_ksp.c /Fe"build\OpenCertKSP_x64.dll" /Fo"build\ksp_x64.obj" ^
::     /link /DEF:codes\ksp\codes\OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib user32.lib ole32.lib /NOLOGO /DLL /MACHINE:X64
:: if %errorlevel% neq 0 (echo       [FAIL] KSP x64 & exit /b 1)
:: echo       [DONE] build\OpenCertKSP_x64.dll

:: --- CSP x64 (uncomment to enable) ---
:: cl.exe /nologo /O2 /W4 /LD /utf-8 /DWIN32 /D_WINDOWS /D_USRDLL /DCRYPTOKI_EXPORTS /D_CRT_SECURE_NO_WARNINGS ^
::     /Icodes\csp\codes codes\csp\codes\pkcs11-mock.c codes\csp\codes\ipc_client.c codes\csp\codes\ipc_json.c ^
::     /Fe"build\OpenCertCSP_x64.dll" ^
::     /link Advapi32.lib /NOLOGO /DLL /MACHINE:X64
:: if %errorlevel% neq 0 (echo       [FAIL] CSP x64 & exit /b 1)
:: echo       [DONE] build\OpenCertCSP_x64.dll

:: --- FIDO x64 (uncomment to enable) ---
:: cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
::     /Icodes\csp\codes codes\fido\codes\opencert_fido.c codes\csp\codes\ipc_client.c ^
::     /Fe"build\OpenFIDOLib_x64.dll" ^
::     /link /DEF:codes\fido\codes\OpenCertFIDO.def winscard.lib kernel32.lib advapi32.lib /NOLOGO /DLL /MACHINE:X64
:: if %errorlevel% neq 0 (echo       [FAIL] FIDO x64 & exit /b 1)
:: echo       [DONE] build\OpenFIDOLib_x64.dll

:: ---- x86 ----
echo       [x86] Initializing VC environment...
call "!VSBASE!\vcvars32.bat" >nul 2>&1

:: --- KSP x86 (uncomment to enable) ---
:: cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
::     codes\ksp\codes\opencert_ksp.c /Fe"build\OpenCertKSP_x86.dll" /Fo"build\ksp_x86.obj" ^
::     /link /DEF:codes\ksp\codes\OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib user32.lib ole32.lib /NOLOGO /DLL /MACHINE:X86
:: if %errorlevel% neq 0 (echo       [FAIL] KSP x86 & exit /b 1)
:: echo       [DONE] build\OpenCertKSP_x86.dll

:: --- CSP x86 (uncomment to enable) ---
:: cl.exe /nologo /O2 /W4 /LD /utf-8 /DWIN32 /D_WINDOWS /D_USRDLL /DCRYPTOKI_EXPORTS /D_CRT_SECURE_NO_WARNINGS ^
::     /Icodes\csp\codes codes\csp\codes\pkcs11-mock.c codes\csp\codes\ipc_client.c codes\csp\codes\ipc_json.c ^
::     /Fe"build\OpenCertCSP_x86.dll" ^
::     /link Advapi32.lib /NOLOGO /DLL /MACHINE:X86
:: if %errorlevel% neq 0 (echo       [FAIL] CSP x86 & exit /b 1)
:: echo       [DONE] build\OpenCertCSP_x86.dll

:: --- FIDO x86 (uncomment to enable) ---
:: cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
::     /Icodes\csp\codes codes\fido\codes\opencert_fido.c codes\csp\codes\ipc_client.c ^
::     /Fe"build\OpenFIDOLib_x86.dll" ^
::     /link /DEF:codes\fido\codes\OpenCertFIDO.def winscard.lib kernel32.lib advapi32.lib /NOLOGO /DLL /MACHINE:X86
:: if %errorlevel% neq 0 (echo       [FAIL] FIDO x86 & exit /b 1)
:: echo       [DONE] build\OpenFIDOLib_x86.dll

:: Clean intermediate files
del /Q build\*.obj build\*.exp build\*.lib *.obj *.exp *.lib >nul 2>&1

echo       [NOT] KSP/CSP/FIDO cl.exe builds are commented out

:: ============================================================
:: [2/4] Build UMDF FIDO2 Driver (disabled - 方案已废弃)
:: ============================================================
:: echo.
:: echo [2/4] Building UMDF FIDO2 Driver...
:: call "%ROOT%setup\build_mdf_dll.bat"
:: if !errorlevel! neq 0 (
::     echo       [WARN] UMDF driver build failed
:: )

:: ============================================================
:: [3/4] Build HID FIDO2 Driver (disabled - 已切换到 USB/IP 方案)
:: ============================================================
:: echo.
:: echo [2/4] Building HID FIDO2 Driver...
:: call "%ROOT%setup\build_hid_dll.bat" --quiet
:: if !errorlevel! neq 0 (
::     echo       [WARN] HID driver build failed
:: )

:: ============================================================
:: [3/4] Build USB/IP VHCI Driver + fido-go
:: ============================================================
echo.
echo [2/3] Building USB/IP VHCI Driver + fido-go...

call "%ROOT%setup\build_usb_sys.bat" --quiet
if !errorlevel! neq 0 (
    echo       [WARN] USB/IP build failed
)

:: ============================================================
:: [3/3] Sign all files in build/
:: ============================================================
echo.
echo [3/3] Signing all files in build/...

if "!SIGNTOOL!"=="" (
    echo       [WARN] signtool.exe not found, skipping
    goto :summary
)

set "SIGN_COUNT=0"
set "SIGN_FAIL=0"

:: Sign root-level DLLs (KSP, CSP, FIDO)
for %%F in (build\*.dll) do (
    call :sign_file "%%F"
)

if !SIGN_COUNT! equ 0 echo       [INFO] No files to sign
if !SIGN_COUNT! gtr 0 echo       [DONE] Signed !SIGN_COUNT! file^(s^), !SIGN_FAIL! failed

:summary
:: ============================================================
:: Build Summary
:: ============================================================
echo.
echo ============================================================
echo   Build Complete! Output in build\
echo ============================================================

set "FILE_COUNT=0"
for %%F in (build\*.dll) do (
    echo       %%~nxF
    set /a FILE_COUNT+=1
)
if exist "build\FidoUsbIpVhci\usbip_vhci_ude.sys" (
    echo       FidoUsbIpVhci\usbip_vhci_ude.sys
    set /a FILE_COUNT+=1
)
if exist "build\FidoUsbIpVhci\usbip_vhci_ude.inf" (
    echo       FidoUsbIpVhci\usbip_vhci_ude.inf
    set /a FILE_COUNT+=1
)
if exist "build\FidoUsbIpVhci\usbip_vhci_ude.cat" (
    echo       FidoUsbIpVhci\usbip_vhci_ude.cat
    set /a FILE_COUNT+=1
)
if exist "build\FidoUsbIpVhci\usbip.exe" (
    echo       FidoUsbIpVhci\usbip.exe
    set /a FILE_COUNT+=1
)
if exist "build\fido-go.exe" (
    echo       fido-go.exe
    set /a FILE_COUNT+=1
)

echo.
echo   Total: !FILE_COUNT! file(s)
echo ============================================================
exit /b 0

:: ================================================================
:: Subroutine: sign_file - Sign a single file with EV certificate
:: ================================================================
:sign_file
set "_SF_FILE=%~1"
set "_SF_NAME=%~nx1"

"!SIGNTOOL!" verify /pa "!_SF_FILE!" >nul 2>&1
if !errorlevel! equ 0 (
    echo       [SKIP] !_SF_NAME! ^(already signed^)
    exit /b 0
)

"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!_SF_FILE!" >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] !_SF_NAME! sign failed ^(EV cert may not be inserted^)
    set /a SIGN_FAIL+=1
    exit /b 1
)
echo       [DONE] !_SF_NAME!
set /a SIGN_COUNT+=1
exit /b 0