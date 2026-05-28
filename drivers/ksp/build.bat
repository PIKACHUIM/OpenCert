@echo off
chcp 65001 >nul 2>&1

:: ============================================================
:: OpenCert KSP DLL - Build Script (MSVC x64 + x86)
:: ============================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

if not exist "build\x64" mkdir "build\x64"
if not exist "build\x86" mkdir "build\x86"

:: ---- 查找 VS 安装路径 ----
set "VSBASE="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build" set "VSBASE=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build" set "VSBASE=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build"
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build" set "VSBASE=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build"
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build" if "!VSBASE!"=="" set "VSBASE=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build"
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build" if "!VSBASE!"=="" set "VSBASE=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"

if "!VSBASE!"=="" (
    echo [ERROR] Cannot find Visual Studio or Build Tools!
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   Building OpenCertKSP.dll (x64 + x86)
echo ============================================================
echo.

:: Build x64
echo [1/2] Building x64...
call "!VSBASE!\vcvars64.bat" >nul 2>&1
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    opencert_ksp.c /Fe"build\x64\OpenCertKSP.dll" /Fo"build\x64\opencert_ksp.obj" ^
    /link /DEF:OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% neq 0 (echo [FAILED] x64 build failed! & exit /b 1)
echo [OK] build\x64\OpenCertKSP.dll
del /Q build\x64\*.obj build\x64\*.exp build\x64\*.lib >nul 2>&1

:: Build x86
echo.
echo [2/2] Building x86...
call "!VSBASE!\vcvars32.bat" >nul 2>&1
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    opencert_ksp.c /Fe"build\x86\OpenCertKSP.dll" /Fo"build\x86\opencert_ksp.obj" ^
    /link /DEF:OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib /NOLOGO /DLL /MACHINE:X86
if %errorlevel% neq 0 (echo [FAILED] x86 build failed! & exit /b 1)
echo [OK] build\x86\OpenCertKSP.dll
del /Q build\x86\*.obj build\x86\*.exp build\x86\*.lib >nul 2>&1

:: Copy to setup
copy /Y "build\x64\OpenCertKSP.dll" "build\OpenCertKSP.dll" >nul 2>&1
if exist "..\setup" (
    copy /Y "build\x64\OpenCertKSP.dll" "..\setup\OpenCertKSP.dll" >nul 2>&1
    copy /Y "build\x86\OpenCertKSP.dll" "..\setup\OpenCertKSP_x86.dll" >nul 2>&1
    echo.
    echo [OK] Copied to ..\setup\
)

echo.
echo ============================================================
echo   Build Complete!
echo     x64: build\x64\OpenCertKSP.dll
echo     x86: build\x86\OpenCertKSP.dll
echo ============================================================
exit /b 0
