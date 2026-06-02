@echo off
chcp 65001 >nul 2>&1
:: ============================================================
:: install_test.bat - OpenCert FIDO2 UMDF 驱动测试模式安装脚本
::
:: 前提条件：
::   1. 已开启测试签名模式：bcdedit /set testsigning on（需重启）
::   2. 已构建驱动：builds.bat
::   3. 以管理员身份运行
:: ============================================================
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "DRIVER_DIR=%SCRIPT_DIR%.."
set "DRIVERS_ROOT=%SCRIPT_DIR%..\..\.."
set "BUILD_DIR=%DRIVERS_ROOT%build\fido-driver\x64\Release"
set "INF_DIR=%DRIVER_DIR%\inf"
set "INF_FILE=%INF_DIR%\OpenCertFIDODriver.inf"
set "DLL_FILE=%BUILD_DIR%\OpenCertFIDODriver.dll"

echo.
echo ============================================================
echo   OpenCert FIDO2 UMDF Driver - 测试模式安装
echo ============================================================

:: ---- 检查管理员权限 ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员身份运行此脚本！
    pause & exit /b 1
)

:: ---- 检查测试签名模式 ----
bcdedit /enum {current} 2>nul | findstr /i "testsigning.*Yes" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 测试签名模式未开启！
    echo.
    echo   请以管理员身份运行以下命令，然后重启：
    echo     bcdedit /set testsigning on
    echo.
    pause & exit /b 1
)
echo [OK] 测试签名模式已开启

:: ---- 查找 WDK 工具 ----
set "WDK_BIN="
for /d %%V in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%V\x64\inf2cat.exe" if "!WDK_BIN!"=="" set "WDK_BIN=%%V\x64"
)
if "!WDK_BIN!"=="" (
    echo [ERROR] 未找到 WDK 工具（inf2cat.exe），请安装 WDK
    pause & exit /b 1
)
echo [OK] WDK 工具: !WDK_BIN!

:: ---- 检查构建输出 ----
if not exist "%DLL_FILE%" (
    echo [ERROR] 未找到驱动 DLL: %DLL_FILE%
    echo         请先运行 builds.bat 构建驱动
    pause & exit /b 1
)
echo [OK] 驱动 DLL: %DLL_FILE%

:: ---- 生成/复用测试证书 ----
echo.
echo [1/5] 准备测试签名证书...
set "CERT_STORE=OpenCertTestSign"
set "CERT_SUBJECT=OpenCert FIDO2 Test"

:: 检查证书是否已存在
certutil -store -user TrustedPublisher "%CERT_SUBJECT%" >nul 2>&1
if %errorlevel% neq 0 (
    echo       生成新的测试证书...
    :: 生成自签名证书
    "!WDK_BIN!\makecert.exe" -r -pe -ss "%CERT_STORE%" -n "CN=%CERT_SUBJECT%" ^
        -eku 1.3.6.1.5.5.7.3.3 -sv "%TEMP%\opencert_test.pvk" "%TEMP%\opencert_test.cer" >nul 2>&1
    if !errorlevel! neq 0 (
        :: makecert 可能不在 WDK bin，尝试 New-SelfSignedCertificate
        powershell -NoProfile -Command ^
            "$cert = New-SelfSignedCertificate -Subject 'CN=OpenCert FIDO2 Test' -CertStoreLocation 'Cert:\LocalMachine\My' -KeyUsage DigitalSignature -Type CodeSigningCert; $thumb = $cert.Thumbprint; Write-Host $thumb" > "%TEMP%\cert_thumb.txt"
        set /p CERT_THUMBPRINT=<"%TEMP%\cert_thumb.txt"
        :: 将证书添加到受信任发布者
        powershell -NoProfile -Command ^
            "$cert = Get-Item 'Cert:\LocalMachine\My\!CERT_THUMBPRINT!'; $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher','LocalMachine'); $store.Open('ReadWrite'); $store.Add($cert); $store.Close(); $store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine'); $store2.Open('ReadWrite'); $store2.Add($cert); $store2.Close()"
    )
) else (
    echo       复用已有测试证书
)

:: 获取证书指纹
for /f "tokens=*" %%T in ('powershell -NoProfile -Command "Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*OpenCert FIDO2 Test*' } | Select-Object -First 1 -ExpandProperty Thumbprint"') do set "CERT_THUMBPRINT=%%T"

if "!CERT_THUMBPRINT!"=="" (
    echo [ERROR] 无法获取测试证书指纹
    pause & exit /b 1
)
echo [OK] 证书指纹: !CERT_THUMBPRINT!

:: ---- 复制 DLL 到 UMDF 目录 ----
echo.
echo [2/5] 部署 DLL 到 UMDF 目录...
set "UMDF_DIR=%SystemRoot%\System32\drivers\UMDF"
if not exist "%UMDF_DIR%" mkdir "%UMDF_DIR%"
copy /Y "%DLL_FILE%" "%UMDF_DIR%\OpenCertFIDODriver.dll" >nul
if %errorlevel% neq 0 (
    echo [ERROR] 复制 DLL 失败！
    pause & exit /b 1
)
echo [OK] DLL -> %UMDF_DIR%\OpenCertFIDODriver.dll

:: ---- 签名 DLL ----
echo.
echo [3/5] 签名驱动文件...
"!WDK_BIN!\signtool.exe" sign /sha1 "!CERT_THUMBPRINT!" /fd sha256 /v "%UMDF_DIR%\OpenCertFIDODriver.dll" 2>&1
if %errorlevel% neq 0 (
    echo [WARN] DLL 签名失败，继续尝试...
)

:: ---- 生成 .cat 并签名 ----
echo.
echo [4/5] 生成并签名 .cat 目录文件...
"!WDK_BIN!\inf2cat.exe" /driver:"%INF_DIR%" /os:10_x64 /verbose 2>&1
if %errorlevel% neq 0 (
    echo [WARN] inf2cat 失败，尝试直接安装 INF...
) else (
    if exist "%INF_DIR%\OpenCertFIDODriver.cat" (
        "!WDK_BIN!\signtool.exe" sign /sha1 "!CERT_THUMBPRINT!" /fd sha256 /v "%INF_DIR%\OpenCertFIDODriver.cat" 2>&1
    )
)

:: ---- 安装驱动 + 创建设备节点 ----
echo.
echo [5/5] 安装驱动并创建虚拟设备节点...

:: 先卸载旧版本（忽略错误）
pnputil /delete-driver oem*.inf /uninstall /force >nul 2>&1

:: 安装 INF
pnputil /add-driver "%INF_FILE%" /install 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pnputil 安装驱动失败！错误码: %errorlevel%
    echo.
    echo   可能原因：
    echo   1. 测试签名模式未生效（需要重启后再运行）
    echo   2. .cat 文件签名无效
    echo   3. INF 文件格式错误
    pause & exit /b 1
)
echo [OK] INF 安装成功

:: 创建虚拟设备节点
set "DEVCON="
for %%P in (
    "!WDK_BIN!\devcon.exe"
    "%ProgramFiles(x86)%\Windows Kits\10\Tools\x64\devcon.exe"
) do if exist "%%~P" if "!DEVCON!"=="" set "DEVCON=%%~P"

if not "!DEVCON!"=="" (
    echo       使用 devcon 创建设备节点...
    "!DEVCON!" install "%INF_FILE%" ROOT\OPENCERTFIDO 2>&1
    if !errorlevel! neq 0 (
        echo [WARN] devcon install 返回错误，设备可能已存在
    ) else (
        echo [OK] 虚拟设备节点已创建
    )
) else (
    echo [WARN] 未找到 devcon.exe
    echo        请从以下地址下载 WDK Tools 或手动运行：
    echo        devcon.exe install "%INF_FILE%" ROOT\OPENCERTFIDO
)

:: ---- 验证 ----
echo.
echo ============================================================
echo   验证安装结果
echo ============================================================
echo.
echo [验证] SmartCardReader 设备列表：
pnputil /enum-devices /class SmartCardReader 2>&1
echo.
echo [验证] 驱动存储：
pnputil /enum-drivers 2>&1 | findstr /i "opencert"

echo.
echo ============================================================
echo   完成！后续步骤：
echo   1. net stop SCardSvr ^& net start SCardSvr
echo   2. 启动 client-card 后端
echo   3. 在浏览器测试 WebAuthn
echo ============================================================
pause
exit /b 0
