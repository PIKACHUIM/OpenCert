@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert UMDF FIDO2 Driver - Build & Package & Sign
:: 构建 UMDF FIDO2 驱动（通过 WUDFRd 被 PC/SC 框架识别）
::
:: 正确顺序：编译DLL → 签名DLL → 生成CAT → 签名CAT
:: （CAT 必须基于已签名的 DLL 生成哈希）
::
:: 输出: build\FidoMdfDriver\
::   - FidoMdfDriver.dll (signed)
::   - FidoMdfDriver.inf
::   - FidoMdfDriver.cat (signed)
::
:: 必须在 drivers\ 根目录下运行，或通过 builds.bat 调用
:: ============================================================
setlocal enabledelayedexpansion

:: 确定 drivers 根目录（脚本在 setup\ 下）
set "DRIVERS_ROOT=%~dp0.."
pushd "%DRIVERS_ROOT%"
set "DRIVERS_ROOT=%CD%"
popd

set "BUILD_DIR=%DRIVERS_ROOT%\build\FidoMdfDriver"
set "VCXPROJ=%DRIVERS_ROOT%\codes\fido-umdf\FidoMdfDriver.vcxproj"
set "INF_SRC=%DRIVERS_ROOT%\codes\fido-umdf\inf\FidoMdfDriver.inf"

echo.
echo ============================================================
echo   UMDF FIDO2 Driver - Build ^& Package
echo ============================================================

:: ================================================================
:: [1/4] 查找工具链
:: ================================================================
echo.
echo [1/4] Detecting build tools...

:: MSBuild
set "MSBUILD="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do if exist "%%~P" if "!MSBUILD!"=="" set "MSBUILD=%%~P"

if "!MSBUILD!"=="" (
    echo       [FAIL] MSBuild.exe not found
    exit /b 1
)
echo       [DONE] MSBuild: !MSBUILD!

:: WDK
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
    echo       [FAIL] WDK not found
    echo              Install: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
    exit /b 1
)
echo       [DONE] WDK: !WDK_PROPS!

:: Inf2Cat
set "INF2CAT="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x86\Inf2Cat.exe" if "!INF2CAT!"=="" set "INF2CAT=%%V\x86\Inf2Cat.exe"
)
if "!INF2CAT!"=="" (
    echo       [WARN] Inf2Cat.exe not found, .cat generation will be skipped
) else (
    echo       [DONE] Inf2Cat: !INF2CAT!
)

:: 检查源文件
if not exist "!VCXPROJ!" (
    echo       [FAIL] vcxproj not found: !VCXPROJ!
    exit /b 1
)
if not exist "!INF_SRC!" (
    echo       [FAIL] INF not found: !INF_SRC!
    exit /b 1
)

:: ================================================================
:: [2/4] MSBuild 编译
:: ================================================================
echo.
echo [2/4] Building UMDF driver (x64 Release)...

if not exist "!BUILD_DIR!" mkdir "!BUILD_DIR!"

set "_LOG=%TEMP%\opencert_mdf_build.log"

"!MSBUILD!" "!VCXPROJ!" ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:SkipPackageVerification=true ^
    /p:OutDir="!BUILD_DIR!\x64\Release\\" ^
    /p:IntDir="!BUILD_DIR!\x64\Release\int\\" ^
    /nologo /verbosity:quiet > "!_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [FAIL] MSBuild failed. Log:
    type "!_LOG!"
    del /Q "!_LOG!" >nul 2>&1
    exit /b 1
)
del /Q "!_LOG!" >nul 2>&1
echo       [DONE] FidoMdfDriver.dll compiled

:: ================================================================
:: [3/4] 打包（复制 DLL+INF，清理中间目录）
:: ================================================================
echo.
echo [3/4] Packaging...

set "DLL_SRC=!BUILD_DIR!\x64\Release\FidoMdfDriver.dll"
if not exist "!DLL_SRC!" (
    echo       [FAIL] Build output not found: !DLL_SRC!
    exit /b 1
)

:: 复制 DLL + INF
copy /Y "!DLL_SRC!" "!BUILD_DIR!\FidoMdfDriver.dll" >nul
copy /Y "!INF_SRC!" "!BUILD_DIR!\FidoMdfDriver.inf" >nul
echo       [DONE] DLL + INF copied to build\FidoMdfDriver\

:: 清理中间构建目录
if exist "!BUILD_DIR!\x64" (
    rmdir /S /Q "!BUILD_DIR!\x64"
)

:: ================================================================
:: [4/4] 签名 DLL → 生成 CAT → 签名 CAT
:: 正确顺序：CAT 必须基于已签名的 DLL 生成哈希
:: ================================================================
echo.
echo [4/4] Signing and cataloging...

:: 查找 signtool.exe
set "SIGNTOOL="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x64\signtool.exe" if "!SIGNTOOL!"=="" set "SIGNTOOL=%%V\x64\signtool.exe"
)

:: EV Certificate Thumbprint (Finnox Technology)
set "EV_THUMBPRINT=929F16F67222DCFA6A3C15A774F5F460FA79FED1"

:: 步骤1: 签名 DLL
if "!SIGNTOOL!"=="" (
    echo       [WARN] signtool.exe not found, skipping sign
    goto :gen_cat
)

"!SIGNTOOL!" verify /pa "!BUILD_DIR!\FidoMdfDriver.dll" >nul 2>&1
if !errorlevel! equ 0 (
    echo       [SKIP] FidoMdfDriver.dll ^(already signed^)
) else (
    "!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!BUILD_DIR!\FidoMdfDriver.dll" >nul 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] DLL sign failed ^(EV cert may not be inserted^)
    ) else (
        echo       [DONE] FidoMdfDriver.dll signed
    )
)

:: 步骤2: 生成 CAT（基于已签名的 DLL）
:gen_cat
if "!INF2CAT!"=="" (
    echo       [SKIP] .cat generation ^(Inf2Cat not found^)
    goto :done
)

"!INF2CAT!" /driver:"!BUILD_DIR!" /os:10_x64 >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] Inf2Cat failed, .cat not generated
    goto :done
)
if not exist "!BUILD_DIR!\FidoMdfDriver.cat" (
    echo       [WARN] .cat file not generated
    goto :done
)
echo       [DONE] FidoMdfDriver.cat generated

:: 步骤3: 签名 CAT
if "!SIGNTOOL!"=="" goto :done

"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!BUILD_DIR!\FidoMdfDriver.cat" >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] CAT sign failed
) else (
    echo       [DONE] FidoMdfDriver.cat signed
)

:done
echo.
echo ============================================================
echo   UMDF Driver Build Complete!
echo   Output: build\FidoMdfDriver\
echo ============================================================
exit /b 0