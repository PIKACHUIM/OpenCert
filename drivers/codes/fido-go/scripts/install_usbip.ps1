# install_usbip.ps1 - 以管理员身份安装 usbip VHCI 驱动
# 用法：以管理员身份运行此脚本

$ErrorActionPreference = "Continue"
$usbipDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$usbipDir = Join-Path (Split-Path -Parent $usbipDir) "bin\usbip"

Write-Host "============================================================"
Write-Host " OpenCert FIDO2 - USB/IP 驱动安装"
Write-Host " 驱动目录: $usbipDir"
Write-Host "============================================================"
Write-Host ""

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[错误] 需要管理员权限，正在提权重新运行..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Wait
    exit
}

# 步骤1：安装测试证书
Write-Host "[1/3] 安装 usbip 测试证书..."
$pfxPath = Join-Path $usbipDir "usbip_test.pfx"
try {
    $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxPath, "usbip", "PersistKeySet,MachineKeySet")
    
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($pfx)
    $rootStore.Close()
    Write-Host "  [OK] 已添加到受信任的根证书颁发机构"
    
    $tpStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
    $tpStore.Open("ReadWrite")
    $tpStore.Add($pfx)
    $tpStore.Close()
    Write-Host "  [OK] 已添加到受信任的发布者"
} catch {
    Write-Host "  [警告] 证书安装失败: $_"
}
Write-Host ""

# 步骤2：开启测试签名
Write-Host "[2/3] 开启 Windows 测试签名模式..."
$result = bcdedit /set TESTSIGNING ON 2>&1
Write-Host "  $result"
Write-Host ""

# 步骤3：安装 VHCI 驱动
Write-Host "[3/3] 安装 usbip VHCI 驱动..."
Push-Location $usbipDir
try {
    $output = & ".\usbip.exe" install 2>&1
    Write-Host $output
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [提示] 尝试 pnputil 方式..."
        pnputil /add-driver "$usbipDir\usbip_vhci_ude.inf" /install
        if ($LASTEXITCODE -ne 0) {
            pnputil /add-driver "$usbipDir\usbip_vhci.inf" /install
        }
    }
} finally {
    Pop-Location
}
Write-Host ""

Write-Host "============================================================"
Write-Host " 安装完成！"
Write-Host ""
Write-Host " ⚠️  重要：请重启计算机后再使用 fido-go"
Write-Host ""
Write-Host " 重启后："
Write-Host "   1. 启动 client-card 后端"
Write-Host "   2. 运行 fido-go.exe"
Write-Host "============================================================"
Write-Host ""
Read-Host "按 Enter 键退出"
