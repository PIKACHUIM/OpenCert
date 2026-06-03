# install_usbip_ev.ps1
# 适用于已用 EV 证书签名的驱动，跳过 usbip.exe install 的测试证书检查
# 直接用 pnputil + devcon 安装 VHCI 驱动
# 用法：以管理员身份运行

$ErrorActionPreference = "Continue"

# 路径
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$usbipDir  = Join-Path (Split-Path -Parent $scriptDir) "bin\usbip"

Write-Host "============================================================"
Write-Host " OpenCert FIDO2 - USB/IP 驱动安装（EV 证书版）"
Write-Host " 驱动目录: $usbipDir"
Write-Host "============================================================"
Write-Host ""

# 检查管理员权限，不足则提权重跑
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[提权] 需要管理员权限，正在重新以管理员身份运行..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Wait
    exit
}

# ---- 步骤1：pnputil 注册驱动 ----
Write-Host "[1/2] 用 pnputil 注册 VHCI 驱动..."

$infUde = Join-Path $usbipDir "usbip_vhci_ude.inf"
$infWdm = Join-Path $usbipDir "usbip_vhci.inf"

$installed = $false

if (Test-Path $infUde) {
    Write-Host "  安装 usbip_vhci_ude.inf (UDE 版本)..."
    $out = pnputil /add-driver "$infUde" /install 2>&1
    Write-Host "  $out"
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {  # exit 1 = 已存在，也算成功
        $installed = $true
        $hwid = "ROOT\VHCI_ude"
        $infFile = $infUde
    }
}

if (-not $installed -and (Test-Path $infWdm)) {
    Write-Host "  安装 usbip_vhci.inf (WDM 版本)..."
    $out = pnputil /add-driver "$infWdm" /install 2>&1
    Write-Host "  $out"
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
        $installed = $true
        $hwid = "USBIPWIN\vhci"
        $infFile = $infWdm
    }
}

if (-not $installed) {
    Write-Host "[错误] 驱动注册失败，请检查 inf 文件和签名"
    Read-Host "按 Enter 退出"
    exit 1
}

Write-Host "  [OK] 驱动已注册，HardwareID: $hwid"
Write-Host ""

# ---- 步骤2：创建根设备节点 ----
Write-Host "[2/2] 创建虚拟设备节点..."

# 优先用 devcon（WDK 工具）
$devconPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\devcon.exe",
    "C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\devcon.exe",
    "C:\Program Files (x86)\Windows Kits\10\Tools\x64\devcon.exe",
    "C:\Program Files (x86)\Windows Kits\10\Tools\x86\devcon.exe",
    (Join-Path $usbipDir "devcon.exe")
)
$devcon = $devconPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($devcon) {
    Write-Host "  使用 devcon: $devcon"
    $out = & $devcon install "$infFile" $hwid 2>&1
    Write-Host "  $out"
} else {
    # 没有 devcon，用 PowerShell P/Invoke 方式创建根枚举设备
    Write-Host "  未找到 devcon.exe，尝试通过设备管理器方式..."
    Write-Host ""
    Write-Host "  *** 请手动操作（仅需一次）: ***"
    Write-Host "  1. 打开设备管理器 (devmgmt.msc)"
    Write-Host "  2. 菜单 -> 操作 -> 添加过时硬件"
    Write-Host "  3. 选择「安装我手动从列表选择的硬件」"
    Write-Host "  4. 点击「从磁盘安装」，选择目录: $usbipDir"
    Write-Host "  5. 选择「usbip-win VHCI(ude)」，点击下一步完成"
    Write-Host ""
    
    # 自动打开设备管理器
    Start-Process devmgmt.msc
}

Write-Host ""
Write-Host "============================================================"
Write-Host " 完成！"
Write-Host ""
Write-Host " 验证：运行以下命令检查驱动是否加载"
Write-Host "   cd $usbipDir"
Write-Host "   .\usbip.exe attach -r 127.0.0.1 -b 2-2"
Write-Host "============================================================"
Write-Host ""
Read-Host "按 Enter 退出"
