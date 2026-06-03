# register_usbip.ps1 - 安装 USB/IP VHCI 驱动（EV 证书版）
# 使用 pnputil 注册驱动，devcon 创建设备节点
# 必须以管理员身份运行

param(
    [string]$BuildDir = ""   # 可选：手动指定驱动目录（含 .inf/.sys/.cat）
)

$ErrorActionPreference = "Continue"

# ================================================================
# 辅助函数
# ================================================================
function Write-Ok   { param([string]$Msg) Write-Host "      [DONE] $Msg" -ForegroundColor Green  }
function Write-Warn { param([string]$Msg) Write-Host "      [WARN] $Msg" -ForegroundColor Yellow }
function Write-Info { param([string]$Msg) Write-Host "      [INFO] $Msg" -ForegroundColor Cyan   }
function Write-Fail { param([string]$Msg) Write-Host "      [FAIL] $Msg" -ForegroundColor Red    }

# ================================================================
# 管理员权限检查
# ================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "This script requires Administrator privileges!"
    exit 1
}

# ================================================================
# 解析路径
# ================================================================
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($BuildDir -eq "") {
    $BuildDir = Join-Path $scriptDir "..\build\FidoUsbIpVhci"
}
$resolved = Resolve-Path $BuildDir -ErrorAction SilentlyContinue
$BuildDir = if ($resolved) { $resolved.Path } else { $null }
if (-not $BuildDir -or -not (Test-Path $BuildDir)) {
    Write-Fail "BuildDir not found: $BuildDir"
    exit 1
}

$infUde = Join-Path $BuildDir "usbip_vhci_ude.inf"
$infWdm = Join-Path $BuildDir "usbip_vhci.inf"

Write-Info "Driver directory: $BuildDir"

# ================================================================
# 前置检查
# ================================================================
if (-not (Test-Path $infUde) -and -not (Test-Path $infWdm)) {
    Write-Fail "No INF file found in $BuildDir"
    exit 1
}

# ================================================================
# 步骤1：pnputil 注册驱动包
# ================================================================
Write-Info "[1/2] Registering driver package with pnputil..."

$installed = $false
$hwid      = ""
$infFile   = ""

if (Test-Path $infUde) {
    Write-Info "  Adding usbip_vhci_ude.inf (UDE version)..."
    $out = pnputil /add-driver "$infUde" /install 2>&1
    Write-Host "  $out"
    # exit 0 = 成功，exit 1 = 已存在（也算成功）
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
        $installed = $true
        $hwid    = "root\vhci_ude"
        $infFile = $infUde
    }
}

if (-not $installed -and (Test-Path $infWdm)) {
    Write-Info "  Adding usbip_vhci.inf (WDM version)..."
    $out = pnputil /add-driver "$infWdm" /install 2>&1
    Write-Host "  $out"
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
        $installed = $true
        $hwid    = "USBIPWIN\vhci"
        $infFile = $infWdm
    }
}

if (-not $installed) {
    Write-Fail "Driver registration failed"
    exit 1
}
Write-Ok "Driver registered, HardwareID: $hwid"

# ================================================================
# 步骤2：创建虚拟设备节点
# ================================================================
Write-Info "[2/2] Creating virtual device node..."

# 查找 devcon.exe
$devcon = $null
$wdkToolsRoot = "C:\Program Files (x86)\Windows Kits\10\Tools"
if (Test-Path $wdkToolsRoot) {
    Get-ChildItem -Path $wdkToolsRoot -Directory | ForEach-Object {
        $candidate = Join-Path $_.FullName "x64\devcon.exe"
        if ((Test-Path $candidate) -and ($null -eq $devcon)) {
            $devcon = $candidate
        }
    }
}
if ($null -eq $devcon) {
    $cmd = Get-Command devcon -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { $devcon = $cmd.Source }
}

# 检查设备是否已存在
$existingDevice = Get-PnpDevice -InstanceId "ROOT\USB\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.HardwareID -like "*vhci_ude*" -or $_.HardwareID -like "*USBIPWIN*" } |
    Select-Object -First 1

if ($null -ne $existingDevice) {
    Write-Info "Device already exists: $($existingDevice.InstanceId)"
    if ($null -ne $devcon) {
        Write-Info "Updating driver on existing device..."
        $out = & $devcon update "$infFile" $hwid 2>&1
        $out | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Driver updated"
        } else {
            Write-Warn "devcon update returned $LASTEXITCODE (may need reboot)"
        }
    } else {
        Write-Warn "devcon.exe not found, skipping device update"
    }
} else {
    if ($null -ne $devcon) {
        Write-Info "Using devcon: $devcon"
        $out = & $devcon install "$infFile" $hwid 2>&1
        $out | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "devcon install returned $LASTEXITCODE (may need reboot)"
        } else {
            Write-Ok "USB/IP VHCI device installed"
        }
    } else {
        Write-Warn "devcon.exe not found. Please install manually:"
        Write-Host ""
        Write-Host "  1. 打开设备管理器 (devmgmt.msc)" -ForegroundColor Yellow
        Write-Host "  2. 菜单 -> 操作 -> 添加过时硬件" -ForegroundColor Yellow
        Write-Host "  3. 选择「安装我手动从列表选择的硬件」" -ForegroundColor Yellow
        Write-Host "  4. 点击「从磁盘安装」，选择目录: $BuildDir" -ForegroundColor Yellow
        Write-Host "  5. 选择「usbip-win VHCI(ude)」，点击下一步完成" -ForegroundColor Yellow
        Start-Process devmgmt.msc
    }
}

# ================================================================
# 验证
# ================================================================
Write-Info "Verifying driver installation..."
$enumOutput = pnputil /enum-drivers 2>$null
if ($enumOutput) {
    $currentOem = $null
    foreach ($line in $enumOutput) {
        if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
            $currentOem = $Matches[1]
        }
        if ($line -match "Original Name\s*:.*usbip_vhci" -and $null -ne $currentOem) {
            Write-Ok "Driver in store: $currentOem"
            $currentOem = $null
        }
    }
}

Write-Ok "USB/IP VHCI driver installation complete"
Write-Info "Next: run fido-go.exe, then: usbip.exe attach -r 127.0.0.1 -b 2-2"
exit 0
