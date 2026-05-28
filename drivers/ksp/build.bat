@echo off
chcp 65001 >nul 2>&1

:: ============================================================
:: OpenCert KSP DLL - Build Script (MSVC)
:: ============================================================
:: 使用方法：
::   1. 打开 "x64 Native Tools Command Prompt for VS 2022"
::   2. cd 到本目录
::   3. 运行 build.bat
::
:: 或者直接双击运行（会自动查找 VS 环境）
:: ============================================================

setlocal enabledelayedexpansion

:: 检查 cl.exe 是否可用
where cl.exe >nul 2>&1
if %errorlevel% equ 0 goto :do_build

:: 尝试自动查找 VS 环境
echo [INFO] cl.exe not found, searching for Visual Studio...

:: VS 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)

:: VS 2019
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)

:: VS Build Tools
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :do_build
)

echo.
echo [ERROR] Cannot find Visual Studio or Build Tools!
echo.
echo Please install one of:
echo   - Visual Studio 2022 (with "Desktop development with C++" workload)
echo   - Visual Studio Build Tools 2022
echo     https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
echo.
echo Or open "x64 Native Tools Command Prompt for VS" and run this script.
echo.
pause
exit /b 1

:do_build
echo.
echo ============================================================
echo   Building OpenCertKSP.dll (x64 Release)
echo ============================================================
echo.

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: 创建输出目录
if not exist "build" mkdir build

:: 编译
cl.exe /nologo /O2 /W3 /LD ^
    /utf-8 ^
    /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    opencert_ksp.c ^
    /Fe"build\OpenCertKSP.dll" ^
    /Fo"build\opencert_ksp.obj" ^
    /link /DEF:OpenCertKSP.def ^
    ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib ^
    /NOLOGO /DLL /MACHINE:X64

if %errorlevel% neq 0 (
    echo.
    echo [FAILED] Build failed!
    exit /b 1
)

echo.
echo [OK] Build successful!
echo     Output: %SCRIPT_DIR%build\OpenCertKSP.dll
echo.

:: 复制到 setup 目录
if exist "..\setup" (
    copy /Y "build\OpenCertKSP.dll" "..\setup\OpenCertKSP.dll" >nul 2>&1
    echo [OK] Copied to: ..\setup\OpenCertKSP.dll
)

echo.
echo ============================================================
echo   Done! Next: run drivers\setup\install.bat as Administrator
echo ============================================================
echo.
exit /b 0
