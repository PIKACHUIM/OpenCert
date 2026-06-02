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
echo   OpenCert Drivers Build (CSP + KSP + FIDO, x64 + x86)
echo ============================================================

:: ---- x64 ----
echo.
echo [x64] Initializing...
call "!VSBASE!\vcvars64.bat" >nul 2>&1

echo [x64] Building KSP...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    codes\ksp\codes\opencert_ksp.c /Fe"build\OpenCertKSP_x64.dll" /Fo"build\ksp_x64.obj" ^
    /link /DEF:codes\ksp\codes\OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib user32.lib ole32.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% neq 0 (echo [FAILED] KSP x64 & exit /b 1)
echo [OK] build\OpenCertKSP_x64.dll

echo [x64] Building CSP...
cl.exe /nologo /O2 /W4 /LD /utf-8 /DWIN32 /D_WINDOWS /D_USRDLL /DCRYPTOKI_EXPORTS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\csp\codes\pkcs11-mock.c codes\csp\codes\ipc_client.c codes\csp\codes\ipc_json.c ^
    /Fe"build\OpenCertCSP_x64.dll" ^
    /link Advapi32.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% neq 0 (echo [FAILED] CSP x64 & exit /b 1)
echo [OK] build\OpenCertCSP_x64.dll

echo [x64] Building FIDO...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\fido\codes\opencert_fido.c codes\csp\codes\ipc_client.c ^
    /Fe"build\OpenCertFIDO_x64.dll" ^
    /link /DEF:codes\fido\codes\OpenCertFIDO.def winscard.lib kernel32.lib advapi32.lib /NOLOGO /DLL /MACHINE:X64
if %errorlevel% neq 0 (echo [FAILED] FIDO x64 & exit /b 1)
echo [OK] build\OpenCertFIDO_x64.dll

:: ---- x86 ----
echo.
echo [x86] Initializing...
call "!VSBASE!\vcvars32.bat" >nul 2>&1

echo [x86] Building KSP...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    codes\ksp\codes\opencert_ksp.c /Fe"build\OpenCertKSP_x86.dll" /Fo"build\ksp_x86.obj" ^
    /link /DEF:codes\ksp\codes\OpenCertKSP.def ncrypt.lib bcrypt.lib crypt32.lib kernel32.lib advapi32.lib credui.lib user32.lib ole32.lib /NOLOGO /DLL /MACHINE:X86
if %errorlevel% neq 0 (echo [FAILED] KSP x86 & exit /b 1)
echo [OK] build\OpenCertKSP_x86.dll

echo [x86] Building CSP...
cl.exe /nologo /O2 /W4 /LD /utf-8 /DWIN32 /D_WINDOWS /D_USRDLL /DCRYPTOKI_EXPORTS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\csp\codes\pkcs11-mock.c codes\csp\codes\ipc_client.c codes\csp\codes\ipc_json.c ^
    /Fe"build\OpenCertCSP_x86.dll" ^
    /link Advapi32.lib /NOLOGO /DLL /MACHINE:X86
if %errorlevel% neq 0 (echo [FAILED] CSP x86 & exit /b 1)
echo [OK] build\OpenCertCSP_x86.dll

echo [x86] Building FIDO...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\fido\codes\opencert_fido.c codes\csp\codes\ipc_client.c ^
    /Fe"build\OpenCertFIDO_x86.dll" ^
    /link /DEF:codes\fido\codes\OpenCertFIDO.def winscard.lib kernel32.lib advapi32.lib /NOLOGO /DLL /MACHINE:X86
if %errorlevel% neq 0 (echo [FAILED] FIDO x86 & exit /b 1)
echo [OK] build\OpenCertFIDO_x86.dll

:: 清理中间文件
del /Q build\*.obj build\*.exp build\*.lib *.obj *.exp *.lib >nul 2>&1

:: ---- UMDF 驱动（需要 WDK + MSBuild） ----
echo.
echo [UMDF] Building FIDO2 Driver (requires WDK)...
call :build_umdf_driver
if !errorlevel! neq 0 (
    echo [WARN] UMDF 驱动构建失败（可能未安装 WDK VS 扩展），跳过
    echo        安装 WDK VS 扩展: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
) else (
    call :package_umdf_driver
)

echo.
echo ============================================================
echo   Build Complete! Output in build\
echo     OpenCertKSP_x64.dll  OpenCertKSP_x86.dll
echo     OpenCertCSP_x64.dll  OpenCertCSP_x86.dll
echo     OpenCertFIDO_x64.dll OpenCertFIDO_x86.dll
echo     OpenCertFIDODriver.dll + .inf + .cat  (UMDF Driver Package)
echo ============================================================
exit /b 0

:: ================================================================
:: 子程序：构建 UMDF 驱动
:: 使用 MSBuild + WDK 工具集（WindowsUserModeDriver10.0）
:: ================================================================
:build_umdf_driver
setlocal enabledelayedexpansion

:: 查找 MSBuild
set "MSBUILD="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do if exist "%%~P" if "!MSBUILD!"=="" set "MSBUILD=%%~P"

if "!MSBUILD!"=="" (
    echo [WARN] 未找到 MSBuild.exe
    endlocal
    exit /b 1
)

:: 检查 WDK 是否安装（动态枚举版本目录，不依赖固定版本号）
set "WDK_PROPS="
set "WDK_BUILD_ROOT=C:\Program Files (x86)\Windows Kits\10\build"
if exist "!WDK_BUILD_ROOT!" (
    for /d %%V in ("!WDK_BUILD_ROOT!\*") do (
        if exist "%%V\WindowsDriver.Common.props" (
            if "!WDK_PROPS!"=="" set "WDK_PROPS=%%V\WindowsDriver.Common.props"
        )
    )
)

if "!WDK_PROPS!"=="" (
    echo [WARN] 未找到 WDK，跳过 UMDF 驱动构建
    echo        请安装 WDK: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
    endlocal
    exit /b 1
)
echo [OK] WDK: !WDK_PROPS!

:: 创建输出目录
if not exist "build\fido-driver" mkdir "build\fido-driver"

:: 构建 x64 Release
echo [UMDF x64] Building...
"!MSBUILD!" "codes\fido-umdf\OpenCertFIDODriver.vcxproj" ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir="%~dp0build\fido-driver\x64\Release\\" ^
    /p:IntDir="%~dp0build\fido-driver\x64\Release\int\\" ^
    /nologo /verbosity:minimal
if !errorlevel! neq 0 (
    echo [FAILED] UMDF Driver x64
    endlocal
    exit /b 1
)
echo [OK] build\fido-driver\x64\Release\OpenCertFIDODriver.dll

endlocal
exit /b 0

:: ================================================================
:: 子程序：打包 UMDF 驱动 - 复制到 build\，生成 .cat 并签名
:: ================================================================
:package_umdf_driver
setlocal enabledelayedexpansion

set "BUILD_DIR=%~dp0build"
set "INF_SRC=%~dp0codes\fido-umdf\inf"
set "DLL_SRC=%BUILD_DIR%\fido-driver\x64\Release\OpenCertFIDODriver.dll"

echo.
echo [Package] 打包 UMDF 驱动到 build\...

:: 检查 DLL 是否存在
if not exist "!DLL_SRC!" (
    echo [ERROR] 未找到构建输出: !DLL_SRC!
    endlocal & exit /b 1
)

:: Step 1: 复制 DLL 和 INF 到 build\
echo [1/4] 复制驱动文件到 build\...
copy /Y "!DLL_SRC!" "!BUILD_DIR!\OpenCertFIDODriver.dll" >nul
copy /Y "!INF_SRC!\OpenCertFIDODriver.inf" "!BUILD_DIR!\OpenCertFIDODriver.inf" >nul
echo [OK] OpenCertFIDODriver.dll + .inf 已复制到 build\

:: Step 2: 删除临时构建目录
echo [2/4] 清理临时目录 build\fido-driver\...
if exist "!BUILD_DIR!\fido-driver" (
    rmdir /S /Q "!BUILD_DIR!\fido-driver"
    echo [OK] build\fido-driver\ 已删除
)

:: Step 3: 查找 inf2cat（只在 x86 目录下）
echo [3/4] 生成 .cat 目录文件...
set "INF2CAT="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x86\Inf2Cat.exe" if "!INF2CAT!"=="" set "INF2CAT=%%V\x86\Inf2Cat.exe"
)
if "!INF2CAT!"=="" (
    echo [WARN] 未找到 Inf2Cat.exe，跳过 .cat 生成
    echo        请安装 WDK: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
    endlocal & exit /b 0
)

"!INF2CAT!" /driver:"!BUILD_DIR!" /os:10_x64 /verbose 2>&1
if !errorlevel! neq 0 (
    echo [WARN] Inf2Cat 生成 .cat 失败，请检查 INF 文件
    endlocal & exit /b 0
)
if not exist "!BUILD_DIR!\OpenCertFIDODriver.cat" (
    echo [WARN] .cat 文件未生成
    endlocal & exit /b 0
)
echo [OK] build\OpenCertFIDODriver.cat 已生成

:: Step 4: 自动签名（DLL + .cat，查找 EV 证书）
echo [4/4] 签名 DLL 和 .cat 文件...
set "SIGNTOOL="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x64\signtool.exe" if "!SIGNTOOL!"=="" set "SIGNTOOL=%%V\x64\signtool.exe"
)
if "!SIGNTOOL!"=="" (
    echo [WARN] 未找到 signtool.exe，跳过签名
    endlocal & exit /b 0
)

:: 使用固定 EV 证书指纹（Finnox Technology）
set "EV_THUMBPRINT=929F16F67222DCFA6A3C15A774F5F460FA79FED1"

:: 先签名 DLL（UMDF 驱动 DLL 必须有代码签名，否则 WUDFRd 拒绝加载）
"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 /v "!BUILD_DIR!\OpenCertFIDODriver.dll" 2>&1
if !errorlevel! neq 0 (
    echo [WARN] DLL 签名失败（EV 证书可能未插入），跳过
    echo        手动签名: signtool sign /sha1 !EV_THUMBPRINT! /fd sha256 /tr http://timestamp.digicert.com /td sha256 build\OpenCertFIDODriver.dll
) else (
    echo [OK] build\OpenCertFIDODriver.dll 签名成功
)

:: 再签名 .cat
"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 /v "!BUILD_DIR!\OpenCertFIDODriver.cat" 2>&1
if !errorlevel! neq 0 (
    echo [WARN] .cat 签名失败（EV 证书可能未插入），跳过
    echo        手动签名: signtool sign /sha1 !EV_THUMBPRINT! /fd sha256 /tr http://timestamp.digicert.com /td sha256 build\OpenCertFIDODriver.cat
) else (
    echo [OK] build\OpenCertFIDODriver.cat 签名成功
)

endlocal & exit /b 0
