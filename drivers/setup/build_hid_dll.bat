@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert HID FIDO2 Driver - Build & Package & Sign
:: 构建 HID FIDO2 驱动（MSBuild + WDK），签名，打包并生成 .cat
::
:: 正确顺序：编译DLL → 签名DLL → 生成CAT → 签名CAT
:: （CAT 必须基于已签名的 DLL 生成哈希）
::
:: 输出: build\FidoHidDriver\
::   - FidoHidDriver.dll (signed)
::   - FidoHidDriver.inf
::   - FidoHidDriver.cat (signed)
::
:: 必须在 drivers\ 根目录下运行，或通过 builds.bat 调用
:: ============================================================
setlocal enabledelayedexpansion

:: 确定 drivers 根目录（脚本在 setup\ 下）
set "DRIVERS_ROOT=%~dp0.."
pushd "%DRIVERS_ROOT%"
set "DRIVERS_ROOT=%CD%"
popd

set "BUILD_DIR=%DRIVERS_ROOT%\build\FidoHidDriver"
set "VCXPROJ=%DRIVERS_ROOT%\codes\fido-hid\FidoHidDriver.vcxproj"
set "INF_SRC=%DRIVERS_ROOT%\codes\fido-hid\inf\FidoHidDriver.inf"

:: 如果被 builds.bat 调用，不打印独立横幅
if "%~1"=="--quiet" (
    set "QUIET=1"
) else (
    set "QUIET=0"
    echo.
    echo ============================================================
    echo   HID FIDO2 Driver - Build ^& Package
    echo ============================================================
)

:: ================================================================
:: [1/4] 查找工具链
:: ================================================================
if "!QUIET!"=="0" (
    echo.
    echo [1/4] Detecting build tools...
) else (
    echo       [INFO] Detecting build tools...
)

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
if "!QUIET!"=="0" (
    echo.
    echo [2/4] Building HID driver ^(x64 Release^)...
) else (
    echo       [INFO] Compiling HID driver ^(x64 Release^)...
)

if not exist "!BUILD_DIR!" mkdir "!BUILD_DIR!"

:: 将 MSBuild 输出重定向到临时文件，保持控制台干净
set "_MSBUILD_LOG=%TEMP%\opencert_hid_build.log"
"!MSBUILD!" "!VCXPROJ!" ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:SkipPackageVerification=true ^
    /p:OutDir="!BUILD_DIR!\x64\Release\\" ^
    /p:IntDir="!BUILD_DIR!\x64\Release\int\\" ^
    /nologo /verbosity:quiet > "!_MSBUILD_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [FAIL] MSBuild failed. Build log:
    type "!_MSBUILD_LOG!"
    del /Q "!_MSBUILD_LOG!" >nul 2>&1
    exit /b 1
)
del /Q "!_MSBUILD_LOG!" >nul 2>&1
echo       [DONE] FidoHidDriver.dll compiled

:: ================================================================
:: [3/4] 打包（复制 DLL+INF，清理中间目录）
:: ================================================================
if "!QUIET!"=="0" (
    echo.
    echo [3/4] Packaging...
) else (
    echo       [INFO] Packaging...
)

set "DLL_SRC=!BUILD_DIR!\x64\Release\FidoHidDriver.dll"
if not exist "!DLL_SRC!" (
    echo       [FAIL] Build output not found: !DLL_SRC!
    exit /b 1
)

:: 复制 DLL + INF
copy /Y "!DLL_SRC!" "!BUILD_DIR!\FidoHidDriver.dll" >nul
copy /Y "!INF_SRC!" "!BUILD_DIR!\FidoHidDriver.inf" >nul
echo       [DONE] DLL + INF copied to build\FidoHidDriver\

:: 清理中间构建目录
if exist "!BUILD_DIR!\x64" (
    rmdir /S /Q "!BUILD_DIR!\x64"
)

:: ================================================================
:: [4/4] 签名 DLL → 生成 CAT → 签名 CAT
:: 正确顺序：CAT 必须基于已签名的 DLL 生成哈希
:: ================================================================
if "!QUIET!"=="0" (
    echo.
    echo [4/4] Signing and cataloging...
) else (
    echo       [INFO] Signing and cataloging...
)

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

"!SIGNTOOL!" verify /pa "!BUILD_DIR!\FidoHidDriver.dll" >nul 2>&1
if !errorlevel! equ 0 (
    echo       [SKIP] FidoHidDriver.dll ^(already signed^)
) else (
    "!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!BUILD_DIR!\FidoHidDriver.dll" >nul 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] DLL sign failed ^(EV cert may not be inserted^)
    ) else (
        echo       [DONE] FidoHidDriver.dll signed
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
if not exist "!BUILD_DIR!\FidoHidDriver.cat" (
    echo       [WARN] .cat file not generated
    goto :done
)
echo       [DONE] FidoHidDriver.cat generated

:: 步骤3: 签名 CAT
if "!SIGNTOOL!"=="" goto :done

"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!BUILD_DIR!\FidoHidDriver.cat" >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] CAT sign failed
) else (
    echo       [DONE] FidoHidDriver.cat signed
)

:done
if "!QUIET!"=="0" (
    echo.
    echo ============================================================
    echo   HID Driver Build Complete!
    echo   Output: build\FidoHidDriver\
    echo ============================================================
)
exit /b 0
