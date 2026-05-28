@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert Drivers - 一键构建 (CSP + KSP, x64 + x86)
:: 输出到 build/ 目录
:: ============================================================
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"

set "VSBASE="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build"
) do if exist %%P if "!VSBASE!"=="" set "VSBASE=%%~P"

if "!VSBASE!"=="" (echo [ERROR] Visual Studio not found! & exit /b 1)

if not exist "build" mkdir build

echo.
echo ============================================================
echo   OpenCert Drivers Build (CSP + KSP, x64 + x86)
echo ============================================================

:: ---- x64 ----
echo.
echo [x64] Initializing...
call "!VSBASE!\vcvars64.bat" >nul 2>&1

echo [x64] Building KSP...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    codes\ksp\codes\opencert_ksp.c /Fe"build\OpenCertKSP_x64.dll" /Fo"build\ksp_x64.obj" ^
    /link /DEF:codes\ksp\codes\OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% neq 0 (echo [FAILED] KSP x64 & exit /b 1)
echo [OK] build\OpenCertKSP_x64.dll

echo [x64] Building CSP...
cl.exe /nologo /O2 /W4 /LD /utf-8 /DWIN32 /D_WINDOWS /D_USRDLL /DCRYPTOKI_EXPORTS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\csp\codes\pkcs11-mock.c codes\csp\codes\ipc_client.c codes\csp\codes\ipc_json.c ^
    /Fe"build\OpenCertCSP_x64.dll" ^
    /link Advapi32.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% neq 0 (echo [FAILED] CSP x64 & exit /b 1)
echo [OK] build\OpenCertCSP_x64.dll

:: ---- x86 ----
echo.
echo [x86] Initializing...
call "!VSBASE!\vcvars32.bat" >nul 2>&1

echo [x86] Building KSP...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    codes\ksp\codes\opencert_ksp.c /Fe"build\OpenCertKSP_x86.dll" /Fo"build\ksp_x86.obj" ^
    /link /DEF:codes\ksp\codes\OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib /NOLOGO /DLL /MACHINE:X86
if %errorlevel% neq 0 (echo [FAILED] KSP x86 & exit /b 1)
echo [OK] build\OpenCertKSP_x86.dll

echo [x86] Building CSP...
cl.exe /nologo /O2 /W4 /LD /utf-8 /DWIN32 /D_WINDOWS /D_USRDLL /DCRYPTOKI_EXPORTS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\csp\codes\pkcs11-mock.c codes\csp\codes\ipc_client.c codes\csp\codes\ipc_json.c ^
    /Fe"build\OpenCertCSP_x86.dll" ^
    /link Advapi32.lib /NOLOGO /DLL /MACHINE:X86
if %errorlevel% neq 0 (echo [FAILED] CSP x86 & exit /b 1)
echo [OK] build\OpenCertCSP_x86.dll

:: 清理中间文件
del /Q build\*.obj build\*.exp build\*.lib *.obj *.exp *.lib >nul 2>&1

echo.
echo ============================================================
echo   Build Complete! Output in build\
echo     OpenCertKSP_x64.dll  OpenCertKSP_x86.dll
echo     OpenCertCSP_x64.dll  OpenCertCSP_x86.dll
echo ============================================================
exit /b 0
