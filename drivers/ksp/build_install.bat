@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
)
cd /d G:\Codes\GlobalTrusts\PKCS11Driver\drivers\ksp
if not exist "build" mkdir build
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS opencert_ksp.c /Fe"build\OpenCertKSP.dll" /Fo"build\opencert_ksp.obj" /link /DEF:OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% equ 0 (
    echo [OK] Build successful
    copy /Y "build\OpenCertKSP.dll" "C:\WINDOWS\System32\OpenCertKSP.dll" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Copied to System32
    ) else (
        echo [WARN] Copy to System32 failed - run as admin
    )
) else (
    echo [FAIL] Build failed
)
