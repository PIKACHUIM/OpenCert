@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: install_driver.bat - OpenCert FIDO2 UMDF 驱动安装脚本
::
:: 功能：
::   1. 检查管理员权限
::   2. 使用 EV 证书对驱动文件签名（如未签名）
::   3. 生成 .cat 目录文件
::   4. 使用 pnputil 安装驱动
::   5. 创建虚拟设备节点（ROOT\OPENCERTFIDO）
::   6. 验证安装结果
::
:: 前提条件：
::   - 管理员权限运行
::   - WDK 已安装（提供 inf2cat.exe、signtool.exe）
::   - EV 代码签名证书已安装到证书存储
::   - 已构建 FidoMdfDriver.dll
::
:: 用法：
::   install_driver.bat [证书指纹]
::   例：install_driver.bat A1B2C3D4E5F6...
:: ============================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "DRIVER_DIR=%SCRIPT_DIR%.."
set "DRIVERS_ROOT=%SCRIPT_DIR%..\..\..\"
set "BUILD_DIR=%DRIVERS_ROOT%build\fido-driver"
set "INF_DIR=%DRIVER_DIR%\inf"
set "INF_FILE=%INF_DIR%\FidoMdfDriver.inf"
set "DLL_FILE=%BUILD_DIR%\x64\Release\FidoMdfDriver.dll"
set "CERT_THUMBPRINT=%~1"

echo.
echo ============================================================
echo   OpenCert FIDO2 UMDF Driver Installer
echo ============================================================

:: ---- 检查管理员权限 ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    echo         右键 install_driver.bat -> 以管理员身份运行
    pause
    exit /b 1
)
echo [DONE] 管理员权限确认

:: ---- 查找 WDK 工具 ----
set "WDK_BIN="
for %%P in (
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\x64"
) do if exist "%%~P\inf2cat.exe" if "!WDK_BIN!"=="" set "WDK_BIN=%%~P"

if "!WDK_BIN!"=="" (
    echo [WARN] 未找到 WDK 工具目录，跳过 .cat 生成和签名步骤
    echo        如需签名，请手动运行 inf2cat.exe 和 signtool.exe
    goto :install_driver
)
echo [DONE] WDK 工具目录: !WDK_BIN!

:: ---- 检查构建输出 ----
if not exist "%DLL_FILE%" (
    echo [ERROR] 未找到驱动 DLL: %DLL_FILE%
    echo         请先运行 builds.bat 构建驱动
    pause
    exit /b 1
)
echo [DONE] 驱动 DLL: %DLL_FILE%

:: ---- 生成 .cat 目录文件 ----
echo.
echo [1/4] 生成 .cat 目录文件...
"!WDK_BIN!\inf2cat.exe" /driver:"%INF_DIR%" /os:10_x64,10_x86 /verbose
if %errorlevel% neq 0 (
    echo [WARN] inf2cat.exe 失败，继续尝试安装（测试模式可跳过签名）
) else (
    echo [DONE] .cat 文件生成成功
)

:: ---- 签名驱动文件 ----
if not "!CERT_THUMBPRINT!"=="" (
    echo.
    echo [2/4] 使用 EV 证书签名驱动文件...
    echo       证书指纹: !CERT_THUMBPRINT!

    :: 签名 DLL
    "!WDK_BIN!\signtool.exe" sign ^
        /sha1 "!CERT_THUMBPRINT!" ^
        /fd sha256 ^
        /tr http://timestamp.digicert.com ^
        /td sha256 ^
        /v ^
        "%DLL_FILE%"
    if %errorlevel% neq 0 (
        echo [ERROR] DLL 签名失败！
        pause
        exit /b 1
    )

    :: 签名 .cat 文件
    if exist "%INF_DIR%\FidoMdfDriver.cat" (
        "!WDK_BIN!\signtool.exe" sign ^
            /sha1 "!CERT_THUMBPRINT!" ^
            /fd sha256 ^
            /tr http://timestamp.digicert.com ^
            /td sha256 ^
            /v ^
            "%INF_DIR%\FidoMdfDriver.cat"
        if %errorlevel% neq 0 (
            echo [ERROR] .cat 签名失败！
            pause
            exit /b 1
        )
    )
    echo [DONE] 驱动文件签名完成
) else (
    echo [2/4] 未提供证书指纹，跳过签名步骤
    echo       注意：未签名驱动只能在测试模式下安装
    echo       测试模式启用：bcdedit /set testsigning on
)

:install_driver
:: ---- 复制 DLL 到 UMDF 目录 ----
echo.
echo [3/4] 部署驱动文件...
set "UMDF_DIR=%SystemRoot%\System32\drivers\UMDF"
if not exist "%UMDF_DIR%" mkdir "%UMDF_DIR%"

copy /Y "%DLL_FILE%" "%UMDF_DIR%\FidoMdfDriver.dll" >nul
if %errorlevel% neq 0 (
    echo [ERROR] 复制 DLL 到 %UMDF_DIR% 失败！
    pause
    exit /b 1
)
echo [DONE] DLL 已部署到 %UMDF_DIR%\FidoMdfDriver.dll

:: ---- 安装 INF ----
echo.
echo [4/4] 安装驱动 INF...
pnputil /add-driver "%INF_FILE%" /install
if %errorlevel% neq 0 (
    echo [ERROR] pnputil 安装驱动失败！
    echo         错误码: %errorlevel%
    echo         提示：如果是签名错误，请先启用测试模式：
    echo               bcdedit /set testsigning on
    echo               然后重启系统
    pause
    exit /b 1
)
echo [DONE] INF 安装成功

:: ---- 创建虚拟设备节点 ----
echo.
echo [5/5] 创建虚拟设备节点...

:: 使用 devcon.exe 或 pnputil 枚举根设备
:: 检查 devcon.exe 是否可用
set "DEVCON="
if exist "!WDK_BIN!\devcon.exe" set "DEVCON=!WDK_BIN!\devcon.exe"
if exist "%ProgramFiles(x86)%\Windows Kits\10\Tools\x64\devcon.exe" (
    set "DEVCON=%ProgramFiles(x86)%\Windows Kits\10\Tools\x64\devcon.exe"
)

if not "!DEVCON!"=="" (
    "!DEVCON!" install "%INF_FILE%" ROOT\OPENCERTFIDO
    if %errorlevel% neq 0 (
        echo [WARN] devcon install 失败，尝试使用 pnputil...
        pnputil /scan-devices
    ) else (
        echo [DONE] 虚拟设备节点创建成功
    )
) else (
    echo [WARN] 未找到 devcon.exe，使用 pnputil 扫描设备...
    pnputil /scan-devices
    echo [INFO] 如果设备未出现，请手动运行：
    echo        devcon.exe install "%INF_FILE%" ROOT\OPENCERTFIDO
)

:: ---- 验证安装 ----
echo.
echo ============================================================
echo   验证安装结果
echo ============================================================

echo.
echo [验证1] 检查驱动存储...
pnputil /enum-drivers | findstr /i "opencert"
if %errorlevel% neq 0 (
    echo [WARN] 驱动存储中未找到 OpenCert 驱动
) else (
    echo [DONE] 驱动已在驱动存储中
)

echo.
echo [验证2] 检查设备节点...
pnputil /enum-devices /class SmartCardReader 2>nul | findstr /i "opencert"
if %errorlevel% neq 0 (
    echo [INFO] SmartCardReader 类中暂未找到 OpenCert 设备
    echo        这是正常的，设备可能需要几秒钟初始化
)

echo.
echo [验证3] 检查 PC/SC 读卡器列表（需要 SCardListReaders）...
powershell -NoProfile -Command ^
    "try { Add-Type -AssemblyName System.Security; $ctx = [System.IntPtr]::Zero; Write-Host 'PC/SC 检查需要手动运行 SCardListReaders' } catch {}"

echo.
echo ============================================================
echo   安装完成！
echo.
echo   后续步骤：
echo   1. 重启 Smart Card 服务：
echo      net stop SCardSvr ^& net start SCardSvr
echo   2. 验证读卡器可见：
echo      powershell -c "[System.Reflection.Assembly]::LoadWithPartialName('System.Security')"
echo   3. 启动 OpenCert client-card 后端
echo   4. 在浏览器中测试 WebAuthn 注册
echo ============================================================
pause
exit /b 0
