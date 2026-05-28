@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cl /nologo /W3 /Fe:test_ksp_load.exe test_ksp_load.c /link ncrypt.lib
if %errorlevel% equ 0 (
    echo.
    echo === Running test ===
    test_ksp_load.exe
)
pause
