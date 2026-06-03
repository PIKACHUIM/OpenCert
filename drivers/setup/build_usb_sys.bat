@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: OpenCert USB/IP VHCI Driver + fido-go - Build & Package & Sign
:: 构建 USB/IP VHCI 驱动（MSBuild + WDK）和 fido-go.exe（Go）
::
:: 正确顺序：编译 → 签名 SYS/EXE → 生成 CAT → 签名 CAT
::
:: 输出:
::   build\FidoUsbIpVhci\
::     - usbip_vhci_ude.sys  (signed)
::     - usbip_vhci_ude.inf
::     - usbip_vhci_ude.cat  (signed)
::     - usbip.exe           (signed)
::   build\fido-go.exe       (signed)
::
:: 必须在 drivers\ 根目录下运行，或通过 builds.bat 调用
:: ============================================================
setlocal enabledelayedexpansion

:: 确定 drivers 根目录（脚本在 setup\ 下）
set "DRIVERS_ROOT=%~dp0.."
pushd "%DRIVERS_ROOT%"
set "DRIVERS_ROOT=%CD%"
popd

set "BUILD_DIR=%DRIVERS_ROOT%\build\FidoUsbIpVhci"
set "USBIP_WIN=%DRIVERS_ROOT%\codes\usbip-win"
set "FIDO_GO=%DRIVERS_ROOT%\codes\fido-go"
set "VCXPROJ_VHCI=%USBIP_WIN%\driver\vhci_ude\usbip_vhci_ude.vcxproj"
set "VCXPROJ_USBIP=%USBIP_WIN%\userspace\src\usbip\usbip.vcxproj"
set "INF_SRC=%USBIP_WIN%\driver\vhci_ude\usbip_vhci_ude.inf"

:: 如果被 builds.bat 调用，不打印独立横幅
if "%~1"=="--quiet" (
    set "QUIET=1"
) else (
    set "QUIET=0"
    echo.
    echo ============================================================
    echo   USB/IP VHCI Driver + fido-go - Build ^& Package
    echo ============================================================
)

:: ================================================================
:: [1/5] 查找工具链
:: ================================================================
if "!QUIET!"=="0" (echo. & echo [1/5] Detecting build tools...) else (echo       [INFO] Detecting build tools...)

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

:: signtool
set "SIGNTOOL="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x64\signtool.exe" if "!SIGNTOOL!"=="" set "SIGNTOOL=%%V\x64\signtool.exe"
)
if "!SIGNTOOL!"=="" (
    echo       [WARN] signtool.exe not found, signing will be skipped
) else (
    echo       [DONE] signtool: !SIGNTOOL!
)

:: EV Certificate Thumbprint (Finnox Technology)
set "EV_THUMBPRINT=929F16F67222DCFA6A3C15A774F5F460FA79FED1"

:: Go
set "GO_EXE="
where go >nul 2>&1
if !errorlevel! equ 0 set "GO_EXE=go"
if "!GO_EXE!"=="" (
    echo       [WARN] go not found, fido-go.exe build will be skipped
) else (
    echo       [DONE] Go: !GO_EXE!
)

:: 检查源文件
if not exist "!VCXPROJ_VHCI!" (
    echo       [FAIL] vhci_ude vcxproj not found: !VCXPROJ_VHCI!
    exit /b 1
)
if not exist "!INF_SRC!" (
    echo       [FAIL] INF not found: !INF_SRC!
    exit /b 1
)

:: ================================================================
:: [2/5] MSBuild 编译 VHCI 驱动 + usbip.exe
:: /p:SpectreMitigation=false 强制禁用 Spectre 缓解，避免 MSB8040
:: ================================================================
if "!QUIET!"=="0" (echo. & echo [2/5] Building USB/IP VHCI driver ^(x64 Release^)...) else (echo       [INFO] Compiling USB/IP VHCI driver ^(x64 Release^)...)

if not exist "!BUILD_DIR!" mkdir "!BUILD_DIR!"

set "_LOG=%TEMP%\opencert_usbip_build.log"

REM 先单独编译 libdrv（ProjectReference），指定独立 IntDir 避免 MSB8028 冲突
set "VCXPROJ_LIBDRV=!USBIP_WIN!\driver\lib\libdrv.vcxproj"
set "OUTDIR_RELEASE=!BUILD_DIR!\x64\Release"
set "INTDIR_LIBDRV=!BUILD_DIR!\x64\Release\int\libdrv"
set "INTDIR_VHCI=!BUILD_DIR!\x64\Release\int\vhci_ude"
set "INTDIR_USBIP=!BUILD_DIR!\x64\Release\int\usbip"

"!MSBUILD!" "!VCXPROJ_LIBDRV!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_LIBDRV!\ /nologo /verbosity:quiet > "!_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [FAIL] libdrv MSBuild failed. Log:
    type "!_LOG!"
    del /Q "!_LOG!" >nul 2>&1
    exit /b 1
)
echo       [DONE] libdrv compiled

REM 编译 vhci_ude.sys
"!MSBUILD!" "!VCXPROJ_VHCI!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:RunInfVerif=false /p:EnableInf2cat=false /p:PostBuildEventUseInBuild=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_VHCI!\ /nologo /verbosity:quiet > "!_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [FAIL] vhci_ude MSBuild failed. Log:
    type "!_LOG!"
    del /Q "!_LOG!" >nul 2>&1
    exit /b 1
)
echo       [DONE] usbip_vhci_ude.sys compiled

:: 编译 usbip.exe（如果 vcxproj 存在）
if exist "!VCXPROJ_USBIP!" (
    "!MSBUILD!" "!VCXPROJ_USBIP!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:RunInfVerif=false /p:EnableInf2cat=false /p:PostBuildEventUseInBuild=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_USBIP!\ /nologo /verbosity:quiet >> "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] usbip.exe MSBuild failed ^(non-fatal^)
    ) else (
        echo       [DONE] usbip.exe compiled
    )
)
del /Q "!_LOG!" >nul 2>&1

:: ================================================================
:: [3/5] 打包（复制 SYS + INF + EXE，清理中间目录）
:: ================================================================
if "!QUIET!"=="0" (echo. & echo [3/5] Packaging...) else (echo       [INFO] Packaging...)

set "SYS_SRC=!BUILD_DIR!\x64\Release\usbip_vhci_ude.sys"
if not exist "!SYS_SRC!" (
    echo       [FAIL] Build output not found: !SYS_SRC!
    exit /b 1
)

copy /Y "!SYS_SRC!" "!BUILD_DIR!\usbip_vhci_ude.sys" >nul
copy /Y "!INF_SRC!" "!BUILD_DIR!\usbip_vhci_ude.inf" >nul
echo       [DONE] SYS + INF copied to build\FidoUsbIpVhci\

:: 复制 usbip.exe（如果编译成功）
if exist "!BUILD_DIR!\x64\Release\usbip.exe" (
    copy /Y "!BUILD_DIR!\x64\Release\usbip.exe" "!BUILD_DIR!\usbip.exe" >nul
    echo       [DONE] usbip.exe copied to build\FidoUsbIpVhci\
)

:: 清理中间构建目录
if exist "!BUILD_DIR!\x64" rmdir /S /Q "!BUILD_DIR!\x64"

:: ================================================================
:: [4/5] 编译 fido-go.exe
:: ================================================================
if "!QUIET!"=="0" (echo. & echo [4/5] Building fido-go.exe...) else (echo       [INFO] Building fido-go.exe...)

if "!GO_EXE!"=="" (
    echo       [SKIP] Go not found, skipping fido-go.exe
    goto :sign
)

if not exist "!FIDO_GO!\go.mod" (
    echo       [WARN] fido-go go.mod not found: !FIDO_GO!\go.mod
    goto :sign
)

pushd "!FIDO_GO!"
go mod tidy >nul 2>&1
go build -o "%DRIVERS_ROOT%\build\fido-go.exe" ./cmd/fido-go
if !errorlevel! neq 0 (
    echo       [WARN] fido-go.exe build failed
) else (
    echo       [DONE] fido-go.exe compiled to build\fido-go.exe
)
popd

:: ================================================================
:: [5/5] 签名 SYS/EXE → 生成 CAT → 签名 CAT
:: 正确顺序：CAT 必须基于已签名的文件生成哈希
:: ================================================================
:sign
if "!QUIET!"=="0" (echo. & echo [5/5] Signing and cataloging...) else (echo       [INFO] Signing and cataloging...)

if "!SIGNTOOL!"=="" (
    echo       [SKIP] signtool not found, skipping all signing
    goto :done
)

:: 步骤1: 签名 usbip_vhci_ude.sys
call :sign_one "!BUILD_DIR!\usbip_vhci_ude.sys" "usbip_vhci_ude.sys"

:: 步骤2: 签名 usbip.exe（如果存在）
if exist "!BUILD_DIR!\usbip.exe" (
    call :sign_one "!BUILD_DIR!\usbip.exe" "usbip.exe"
)

:: 步骤3: 签名 fido-go.exe（如果存在）
if exist "%DRIVERS_ROOT%\build\fido-go.exe" (
    call :sign_one "%DRIVERS_ROOT%\build\fido-go.exe" "fido-go.exe"
)

:: 步骤4: 生成 CAT（基于已签名的文件）
if "!INF2CAT!"=="" (
    echo       [SKIP] .cat generation ^(Inf2Cat not found^)
    goto :done
)

"!INF2CAT!" /driver:"!BUILD_DIR!" /os:10_x64 >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] Inf2Cat failed, .cat not generated
    goto :done
)
if not exist "!BUILD_DIR!\usbip_vhci_ude.cat" (
    echo       [WARN] .cat file not generated
    goto :done
)
echo       [DONE] usbip_vhci_ude.cat generated

:: 步骤5: 签名 CAT
"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!BUILD_DIR!\usbip_vhci_ude.cat" >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] CAT sign failed ^(EV cert may not be inserted^)
) else (
    echo       [DONE] usbip_vhci_ude.cat signed
)

:done
if "!QUIET!"=="0" (
    echo.
    echo ============================================================
    echo   USB/IP Build Complete!
    echo   Output: build\FidoUsbIpVhci\  ^&  build\fido-go.exe
    echo ============================================================
)
exit /b 0

:: ================================================================
:: Subroutine: sign_one - 签名单个文件（已签名则跳过）
:: ================================================================
:sign_one
set "_FILE=%~1"
set "_NAME=%~2"
"!SIGNTOOL!" verify /pa "!_FILE!" >nul 2>&1
if !errorlevel! equ 0 (
    echo       [SKIP] !_NAME! ^(already signed^)
    exit /b 0
)
"!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "!_FILE!" >nul 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] !_NAME! sign failed ^(EV cert may not be inserted^)
    exit /b 1
)
echo       [DONE] !_NAME! signed
exit /b 0
