@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: install_driver_ev.bat - OpenCert FIDO2 UMDF 驱动安装（EV证书）
::
:: 修复的问题：
::   1. inf2cat.exe 只在 x86 目录，不在 x64
::   2. DLL 必须和 INF 在同一目录才能生成 .cat
::   3. pnputil 安装需要管理员权限（右键以管理员身份运行）
::
:: 用法：右键 -> 以管理员身份运行
:: ============================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "DRIVER_DIR=%SCRIPT_DIR%.."
set "DRIVERS_ROOT=%SCRIPT_DIR%..\..\.."
set "BUILD_DLL=%DRIVERS_ROOT%build\fido-driver\x64\Release\FidoMdfDriver.dll"
set "INF_DIR=%DRIVER_DIR%\inf"
set "INF_FILE=%INF_DIR%\FidoMdfDriver.inf"
set "CAT_FILE=%INF_DIR%\FidoMdfDriver.cat"
set "INF_DLL=%INF_DIR%\FidoMdfDriver.dll"

:: EV 证书指纹（Finnox Technology）
set "EV_THUMBPRINT=929F16F67222DCFA6A3C15A774F5F460FA79FED1"

echo.
echo ============================================================
echo   OpenCert FIDO2 UMDF Driver Installer (EV Certificate)
echo ============================================================

:: ---- 检查管理员权限 ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    echo         右键 install_driver_ev.bat -^> 以管理员身份运行
    pause & exit /b 1
)
echo [DONE] 管理员权限确认

:: ---- 检查构建输出 ----
if not exist "%BUILD_DLL%" (
    echo [ERROR] 未找到驱动 DLL: %BUILD_DLL%
    echo         请先运行 builds.bat 构建驱动
    pause & exit /b 1
)
echo [DONE] 驱动 DLL: %BUILD_DLL%

:: ---- 查找 WDK 工具（inf2cat 在 x86 目录，signtool 在 x64 目录）----
set "INF2CAT="
set "SIGNTOOL="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x86\Inf2Cat.exe"   if "!INF2CAT!"==""  set "INF2CAT=%%V\x86\Inf2Cat.exe"
    if exist "%%V\x64\signtool.exe"  if "!SIGNTOOL!"=="" set "SIGNTOOL=%%V\x64\signtool.exe"
)
if "!INF2CAT!"=="" (
    echo [ERROR] 未找到 Inf2Cat.exe，请安装 WDK
    pause & exit /b 1
)
if "!SIGNTOOL!"=="" (
    echo [ERROR] 未找到 signtool.exe，请安装 WDK
    pause & exit /b 1
)
echo [DONE] Inf2Cat:  !INF2CAT!
echo [DONE] signtool: !SIGNTOOL!

:: ---- Step 1: 复制 DLL 到 INF 目录（inf2cat 要求源文件与 INF 同目录）----
echo.
echo [1/5] 复制 DLL 到 INF 目录...
copy /Y "%BUILD_DLL%" "%INF_DLL%" >nul
if %errorlevel% neq 0 (
    echo [ERROR] 复制 DLL 失败！
    pause & exit /b 1
)
echo [DONE] DLL 已复制到 INF 目录

:: ---- Step 2: 生成 .cat 目录文件 ----
echo.
echo [2/5] 生成 .cat 目录文件...
"!INF2CAT!" /driver:"%INF_DIR%" /os:10_x64 /verbose 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Inf2Cat 失败！请检查 INF 文件格式
    pause & exit /b 1
)
if not exist "%CAT_FILE%" (
    echo [ERROR] .cat 文件未生成！
    pause & exit /b 1
)
echo [DONE] .cat 文件生成成功

:: ---- Step 3: 签名 .cat 文件（EV 证书）----
echo.
echo [3/5] 签名 .cat 文件（EV 证书）...
"!SIGNTOOL!" sign /sha1 "%EV_THUMBPRINT%" /fd sha256 /tr http://timestamp.digicert.com /td sha256 /v "%CAT_FILE%" 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] .cat 签名失败！请确认 EV 证书已插入/可用
    pause & exit /b 1
)
echo [DONE] .cat 签名成功

:: ---- Step 4: 安装驱动包 ----
echo.
echo [4/5] 安装驱动包（pnputil）...
pnputil /add-driver "%INF_FILE%" /install 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pnputil 安装失败！错误码: %errorlevel%
    echo.
    echo   查看详细错误：
    echo   eventvwr.msc -^> Windows 日志 -^> 系统 -^> 筛选 SetupAPI
    pause & exit /b 1
)
echo [DONE] 驱动包安装成功

:: ---- Step 5: 创建虚拟设备节点 ----
echo.
echo [5/5] 创建虚拟设备节点 ROOT\OPENCERTFIDO...
set "DEVCON="
for %%P in (
    "C:\Program Files (x86)\Windows Kits\10\Tools\x64\devcon.exe"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\devcon.exe"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\devcon.exe"
) do if exist "%%~P" if "!DEVCON!"=="" set "DEVCON=%%~P"

if not "!DEVCON!"=="" (
    "!DEVCON!" install "%INF_FILE%" ROOT\OPENCERTFIDO 2>&1
    if !errorlevel! neq 0 (
        echo [WARN] devcon install 返回非零，设备可能已存在（可忽略）
    ) else (
        echo [DONE] 虚拟设备节点已创建
    )
) else (
    echo [WARN] 未找到 devcon.exe，手动创建设备节点...
    echo        正在使用 pnputil /scan-devices 触发枚举...
    pnputil /scan-devices >nul 2>&1
    echo.
    echo [INFO] 如果设备未出现，请下载 devcon.exe 后手动运行：
    echo        devcon.exe install "%INF_FILE%" ROOT\OPENCERTFIDO
    echo.
    echo [INFO] devcon.exe 下载：WDK 安装目录 Tools\x64\ 或
    echo        https://github.com/nicowillis/devcon/releases
)

:: ---- 验证 ----
echo.
echo ============================================================
echo   验证安装结果
echo ============================================================
echo.
echo [验证1] 驱动存储：
pnputil /enum-drivers 2>&1 | findstr /i "opencert"
if %errorlevel% neq 0 echo        (未在驱动存储中找到 OpenCert)

echo.
echo [验证2] SmartCardReader 设备：
pnputil /enum-devices /class SmartCardReader 2>&1

echo.
echo ============================================================
echo   安装完成！后续步骤：
echo   1. net stop SCardSvr ^& net start SCardSvr
echo   2. 启动 client-card 后端
echo   3. 浏览器测试 WebAuthn 注册
echo ============================================================
pause
exit /b 0
