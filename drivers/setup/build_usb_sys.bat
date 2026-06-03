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
::     - usbip_vhci_ude.sys  (signed)  UDE 驱动
::     - usbip_vhci_ude.pdb            调试符号
::     - usbip_vhci_ude.inf
::     - usbip_vhci_ude.cat  (signed)
::     - usbip_vhci.sys      (signed)  旧版 WDM KMDF 驱动
::     - usbip_vhci.pdb
::     - usbip_vhci.inf
::     - usbip_vhci.cat      (signed)
::     - usbip_stub.sys      (signed)  USB stub 驱动
::     - usbip_stub.pdb
::     - usbip.exe           (signed)
::     - usbip.pdb
::     - usbipd.exe          (signed)  USB/IP 服务端
::     - usbipd.pdb
::     - attacher.exe        (signed)
::     - attacher.pdb
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
set "VCXPROJ_VHCI_UDE=%USBIP_WIN%\driver\vhci_ude\usbip_vhci_ude.vcxproj"
set "VCXPROJ_VHCI=%USBIP_WIN%\driver\vhci\usbip_vhci.vcxproj"
set "VCXPROJ_STUB=%USBIP_WIN%\driver\stub\usbip_stub.vcxproj"
set "VCXPROJ_USBIP=%USBIP_WIN%\userspace\src\usbip\usbip.vcxproj"
set "VCXPROJ_USBIPD=%USBIP_WIN%\userspace\src\usbipd\usbipd.vcxproj"
set "VCXPROJ_ATTACHER=%USBIP_WIN%\userspace\src\attacher\attacher.vcxproj"
set "VCXPROJ_COMMON=%USBIP_WIN%\userspace\lib\usbip_common.vcxproj"
set "INF_SRC_UDE=%USBIP_WIN%\driver\vhci_ude\usbip_vhci_ude.inf"
set "INF_SRC_VHCI=%USBIP_WIN%\driver\vhci\usbip_vhci.inf"
set "INF_SRC_ROOT=%USBIP_WIN%\driver\vhci\usbip_root.inf"

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
if not exist "!VCXPROJ_VHCI_UDE!" (
    echo       [FAIL] vhci_ude vcxproj not found: !VCXPROJ_VHCI_UDE!
    exit /b 1
)
if not exist "!INF_SRC_UDE!" (
    echo       [FAIL] INF not found: !INF_SRC_UDE!
    exit /b 1
)

:: ================================================================
:: [2/5] MSBuild 编译 VHCI 驱动 + usbip.exe
:: /p:SpectreMitigation=false 强制禁用 Spectre 缓解，避免 MSB8040
:: ================================================================
if "!QUIET!"=="0" (echo. & echo [2/5] Building USB/IP VHCI driver ^(x64 Release^)...) else (echo       [INFO] Compiling USB/IP VHCI driver ^(x64 Release^)...)

if not exist "!BUILD_DIR!" mkdir "!BUILD_DIR!"

set "_LOG=%TEMP%\opencert_usbip_build.log"

REM Build libdrv first (ProjectReference) with separate IntDir to avoid MSB8028
set "VCXPROJ_LIBDRV=!USBIP_WIN!\driver\lib\libdrv.vcxproj"
set "OUTDIR_RELEASE=!BUILD_DIR!\x64\Release"
set "INTDIR_LIBDRV=!BUILD_DIR!\x64\Release\int\libdrv"
set "INTDIR_VHCI_UDE=!BUILD_DIR!\x64\Release\int\vhci_ude"
set "INTDIR_VHCI=!BUILD_DIR!\x64\Release\int\vhci"
set "INTDIR_STUB=!BUILD_DIR!\x64\Release\int\stub"
set "INTDIR_USBIP=!BUILD_DIR!\x64\Release\int\usbip"

"!MSBUILD!" "!VCXPROJ_LIBDRV!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_LIBDRV!\ /nologo /verbosity:quiet > "!_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [FAIL] libdrv MSBuild failed. Log:
    type "!_LOG!"
    del /Q "!_LOG!" >nul 2>&1
    exit /b 1
)
echo       [DONE] libdrv compiled

REM Build vhci_ude.sys (UDE driver, BuildProjectReferences=false skips libdrv rebuild)
"!MSBUILD!" "!VCXPROJ_VHCI_UDE!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:SkipPackageVerification=true /p:EnableInf2cat=false /p:PostBuildEventUseInBuild=false /p:BuildProjectReferences=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_VHCI_UDE!\ /nologo /verbosity:quiet > "!_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [FAIL] vhci_ude MSBuild failed. Log:
    type "!_LOG!"
    del /Q "!_LOG!" >nul 2>&1
    exit /b 1
)
echo       [DONE] usbip_vhci_ude.sys compiled

REM Build usbip_vhci.sys (legacy WDM KMDF driver)
if exist "!VCXPROJ_VHCI!" (
    "!MSBUILD!" "!VCXPROJ_VHCI!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningAsError=false /p:TreatWarningsAsErrors=false /p:SkipPackageVerification=true /p:RunInfVerif=false /p:EnableInf2cat=false /p:PostBuildEventUseInBuild=false /p:SignMode=Off /p:EnableTestSign=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_VHCI!\ /nologo /verbosity:quiet > "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] usbip_vhci.sys MSBuild failed ^(non-fatal^). Log:
        type "!_LOG!"
    ) else (
        echo       [DONE] usbip_vhci.sys compiled
    )
)

REM Build usbip_stub.sys (USB stub driver)
if exist "!VCXPROJ_STUB!" (
    "!MSBUILD!" "!VCXPROJ_STUB!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningAsError=false /p:TreatWarningsAsErrors=false /p:SkipPackageVerification=true /p:RunInfVerif=false /p:EnableInf2cat=false /p:PostBuildEventUseInBuild=false /p:SignMode=Off /p:EnableTestSign=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_STUB!\ /nologo /verbosity:quiet > "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] usbip_stub.sys MSBuild failed ^(non-fatal^). Log:
        type "!_LOG!"
    ) else (
        echo       [DONE] usbip_stub.sys compiled
    )
)

:: 编译 usbip_common.lib（usbip.exe 和 attacher.exe 的共同依赖，先编译）
set "INTDIR_COMMON=!BUILD_DIR!\x64\Release\int\usbip_common"
if exist "!VCXPROJ_COMMON!" (
    "!MSBUILD!" "!VCXPROJ_COMMON!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_COMMON!\ /nologo /verbosity:quiet >> "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] usbip_common.lib MSBuild failed ^(non-fatal^)
    ) else (
        echo       [DONE] usbip_common.lib compiled
    )
)

:: 编译 usbip.exe
if exist "!VCXPROJ_USBIP!" (
    "!MSBUILD!" "!VCXPROJ_USBIP!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:SkipPackageVerification=true /p:EnableInf2cat=false /p:PostBuildEventUseInBuild=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_USBIP!\ /nologo /verbosity:quiet >> "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] usbip.exe MSBuild failed ^(non-fatal^)
    ) else (
        echo       [DONE] usbip.exe compiled
    )
)

:: 编译 usbipd.exe
set "INTDIR_USBIPD=!BUILD_DIR!\x64\Release\int\usbipd"
if exist "!VCXPROJ_USBIPD!" (
    "!MSBUILD!" "!VCXPROJ_USBIPD!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_USBIPD!\ /nologo /verbosity:quiet >> "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] usbipd.exe MSBuild failed ^(non-fatal^)
    ) else (
        echo       [DONE] usbipd.exe compiled
    )
)

:: 编译 attacher.exe
set "INTDIR_ATTACHER=!BUILD_DIR!\x64\Release\int\attacher"
if exist "!VCXPROJ_ATTACHER!" (
    "!MSBUILD!" "!VCXPROJ_ATTACHER!" /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:TreatWarningsAsErrors=false /p:OutDir=!OUTDIR_RELEASE!\ /p:IntDir=!INTDIR_ATTACHER!\ /nologo /verbosity:quiet >> "!_LOG!" 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] attacher.exe MSBuild failed ^(non-fatal^)
    ) else (
        echo       [DONE] attacher.exe compiled
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
copy /Y "!INF_SRC_UDE!" "!BUILD_DIR!\usbip_vhci_ude.inf" >nul
echo       [DONE] usbip_vhci_ude.sys + .inf copied

REM Patch usbip_vhci_ude.inf: replace $ARCH$ with AMD64, fill DriverVer, remove CoInstaller sections
powershell -NoProfile -Command ^
    "$inf = Get-Content '!BUILD_DIR!\usbip_vhci_ude.inf' -Raw;" ^
    "$date = (Get-Date).ToString('MM/dd/yyyy');" ^
    "$inf = $inf -replace '\$ARCH\$', 'AMD64';" ^
    "$inf = $inf -replace 'DriverVer=\s*\r?\n', ('DriverVer=' + $date + ',1.0.0.0`r`n');" ^
    "$inf = $inf -replace '(?ms)\[vhci_Device\.NT\.CoInstallers\].*?(?=\n\[)', '';" ^
    "$inf = $inf -replace '(?ms)\[vhci_Device_CoInstaller_AddReg\].*?(?=\n\[)', '';" ^
    "$inf = $inf -replace '(?ms)\[vhci_Device_CoInstaller_CopyFiles\].*?(?=\n\[)', '';" ^
    "$inf = $inf -replace '(?ms)\[vhci_Device\.NT\.Wdf\].*?(?=\n\[)', '';" ^
    "$inf = $inf -replace '(?ms)\[usbip_vhci_wdfsect\].*?(?=\n\[|\z)', '';" ^
    "$inf = $inf -replace 'vhci_Device_CoInstaller_CopyFiles = 11\r?\n', '';" ^
    "$inf = $inf -replace 'WdfCoInstaller\$KMDFCOINSTALLERVERSION\$\.dll=1[^\r\n]*\r?\n', '';" ^
    "Set-Content '!BUILD_DIR!\usbip_vhci_ude.inf' $inf -NoNewline" >nul 2>&1
echo       [DONE] usbip_vhci_ude.inf patched ^(ARCH/DriverVer/CoInstaller^)

:: 复制 usbip_vhci.inf（已在源文件中固定 NTAMD64 和 DriverVer）
if exist "!INF_SRC_VHCI!" (
    copy /Y "!INF_SRC_VHCI!" "!BUILD_DIR!\usbip_vhci.inf" >nul
    echo       [DONE] usbip_vhci.inf copied
)

:: 复制 usbip_root.inf（已在源文件中固定 NTAMD64 和 DriverVer）
if exist "!INF_SRC_ROOT!" (
    copy /Y "!INF_SRC_ROOT!" "!BUILD_DIR!\usbip_root.inf" >nul
    echo       [DONE] usbip_root.inf copied
)

:: 复制 SYS 文件及其 PDB
for %%F in (usbip_vhci_ude usbip_vhci usbip_stub) do (
    if exist "!BUILD_DIR!\x64\Release\%%F.sys" (
        copy /Y "!BUILD_DIR!\x64\Release\%%F.sys" "!BUILD_DIR!\%%F.sys" >nul
        echo       [DONE] %%F.sys copied
    )
    if exist "!BUILD_DIR!\x64\Release\%%F.pdb" (
        copy /Y "!BUILD_DIR!\x64\Release\%%F.pdb" "!BUILD_DIR!\%%F.pdb" >nul
        echo       [DONE] %%F.pdb copied
    )
)

:: 复制 EXE 文件及其 PDB
for %%F in (usbip usbipd attacher) do (
    if exist "!BUILD_DIR!\x64\Release\%%F.exe" (
        copy /Y "!BUILD_DIR!\x64\Release\%%F.exe" "!BUILD_DIR!\%%F.exe" >nul
        echo       [DONE] %%F.exe copied
    )
    if exist "!BUILD_DIR!\x64\Release\%%F.pdb" (
        copy /Y "!BUILD_DIR!\x64\Release\%%F.pdb" "!BUILD_DIR!\%%F.pdb" >nul
        echo       [DONE] %%F.pdb copied
    )
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
go build -o "%DRIVERS_ROOT%\build\fido-go.exe" ./cmd/fido-go 2>"!_LOG!"
if !errorlevel! neq 0 (
    echo       [WARN] fido-go.exe build failed. Log:
    type "!_LOG!"
    del /Q "!_LOG!" >nul 2>&1
) else (
    echo       [DONE] fido-go.exe compiled to build\fido-go.exe
    del /Q "!_LOG!" >nul 2>&1
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

:: 步骤1: 签名所有 SYS（必须在 Inf2Cat 之前完成）
for %%F in (usbip_vhci_ude usbip_vhci usbip_stub) do (
    if exist "!BUILD_DIR!\%%F.sys" call :sign_one "!BUILD_DIR!\%%F.sys" "%%F.sys"
)

:: 步骤2: 签名所有 EXE
for %%F in (usbip usbipd attacher) do (
    if exist "!BUILD_DIR!\%%F.exe" call :sign_one "!BUILD_DIR!\%%F.exe" "%%F.exe"
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

REM Inf2Cat scans the whole directory and generates one CAT per INF
set "_INF2CAT_LOG=%TEMP%\opencert_inf2cat.log"
"!INF2CAT!" /driver:"!BUILD_DIR!" /os:10_x64 > "!_INF2CAT_LOG!" 2>&1
if !errorlevel! neq 0 (
    echo       [WARN] Inf2Cat failed, .cat not generated. Log:
    type "!_INF2CAT_LOG!"
    del /Q "!_INF2CAT_LOG!" >nul 2>&1
    goto :done
)
del /Q "!_INF2CAT_LOG!" >nul 2>&1

set "CAT_COUNT=0"
for %%C in ("!BUILD_DIR!\*.cat") do set /a CAT_COUNT+=1
if !CAT_COUNT! equ 0 (
    echo       [WARN] No .cat files generated
    goto :done
)
echo       [DONE] CAT files generated ^(!CAT_COUNT! file^(s^)^)

:: 步骤5: 签名所有 CAT
for %%C in ("!BUILD_DIR!\*.cat") do (
    "!SIGNTOOL!" sign /sha1 "!EV_THUMBPRINT!" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "%%C" >nul 2>&1
    if !errorlevel! neq 0 (
        echo       [WARN] %%~nxC sign failed ^(EV cert may not be inserted^)
    ) else (
        echo       [DONE] %%~nxC signed
    )
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
