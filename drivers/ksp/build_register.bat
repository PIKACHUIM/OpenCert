@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\ksp"
if not exist build mkdir build
cl /nologo /O2 /utf-8 register_ksp.c /Fe:"build\register_ksp.exe" /Fo:"build\register_ksp.obj" /link bcrypt.lib ncrypt.lib
if %errorlevel% equ 0 (
    echo.
    echo [OK] Build successful: build\register_ksp.exe
) else (
    echo [FAIL] Build failed
)
