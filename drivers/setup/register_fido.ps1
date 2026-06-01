# register_fido.ps1 - 注册 OpenCert FIDO2 虚拟智能卡到 Windows
#
# 必须以管理员身份运行。

param(
    [string]$FidoDll = "OpenCertFIDO.dll",
    [string]$CardName = "OpenCert FIDO2",
    [string]$ReaderName = "OpenCert FIDO2 Reader 0"
)

# 检查管理员权限
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] 请以管理员身份运行此脚本！" -ForegroundColor Red
    exit 1
}

Write-Host "=== OpenCert FIDO2 CCID 虚拟智能卡注册 ===" -ForegroundColor Cyan
Write-Host ""

# ================================================================
# Step 1: 部署 DLL
# ================================================================
Write-Host "[1/4] 部署 FIDO2 DLL..." -ForegroundColor Yellow

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir  = Join-Path $scriptDir "..\build"
$dll64 = Join-Path $buildDir "OpenCertFIDO_x64.dll"
$dll86 = Join-Path $buildDir "OpenCertFIDO_x86.dll"

if (Test-Path $dll64) {
    Copy-Item -Force $dll64 "$env:SystemRoot\System32\$FidoDll"
    Write-Host "    [DONE] $env:SystemRoot\System32\$FidoDll (x64)" -ForegroundColor Green
} else {
    Write-Host "    [WARN] $dll64 不存在，跳过 x64 部署" -ForegroundColor Yellow
}

if (Test-Path $dll86) {
    Copy-Item -Force $dll86 "$env:SystemRoot\SysWOW64\$FidoDll"
    Write-Host "    [DONE] $env:SystemRoot\SysWOW64\$FidoDll (x86)" -ForegroundColor Green
} else {
    Write-Host "    [WARN] $dll86 不存在，跳过 x86 部署" -ForegroundColor Yellow
}

# ================================================================
# Step 2: 注册虚拟智能卡读卡器（PC/SC Reader）
# ================================================================
Write-Host ""
Write-Host "[2/4] 注册虚拟 CCID 读卡器..." -ForegroundColor Yellow

$readerRegPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers\$ReaderName"

try {
    if (-not (Test-Path $readerRegPath)) {
        New-Item -Path $readerRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $readerRegPath -Name "Vendor Name" -Value "GlobalTrusts" -Type String
    Set-ItemProperty -Path $readerRegPath -Name "IFD Type"    -Value "Virtual CCID" -Type String
    Set-ItemProperty -Path $readerRegPath -Name "Device Unit" -Value 0              -Type DWord
    Set-ItemProperty -Path $readerRegPath -Name "Port"        -Value 0              -Type DWord
    Write-Host "    [DONE] 读卡器已注册: $ReaderName" -ForegroundColor Green
} catch {
    Write-Host "    [FAIL] 注册读卡器失败: $_" -ForegroundColor Red
    exit 1
}

# ================================================================
# Step 3: 注册 FIDO2 智能卡（SmartCard ATR 匹配）
# ================================================================
Write-Host ""
Write-Host "[3/4] 注册 FIDO2 智能卡提供程序..." -ForegroundColor Yellow

$cardRegPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\$CardName"
$atr     = [byte[]]@(0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x68)
$atrMask = [byte[]]@(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)

try {
    if (-not (Test-Path $cardRegPath)) {
        New-Item -Path $cardRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $cardRegPath -Name "ATR"              -Value $atr     -Type Binary
    Set-ItemProperty -Path $cardRegPath -Name "ATRMask"          -Value $atrMask -Type Binary
    Set-ItemProperty -Path $cardRegPath -Name "Crypto Provider"  -Value $FidoDll -Type String
    Set-ItemProperty -Path $cardRegPath -Name "Primary Provider" -Value "{36FF7169-B0D5-4B83-B9B5-E9C5B8B9B9B9}" -Type String
    Write-Host "    [DONE] 智能卡已注册: $CardName" -ForegroundColor Green
} catch {
    Write-Host "    [FAIL] 注册智能卡失败: $_" -ForegroundColor Red
    exit 1
}

# ================================================================
# Step 4: 确保 PC/SC 服务运行
# ================================================================
Write-Host ""
Write-Host "[4/4] 确保 PC/SC 服务运行..." -ForegroundColor Yellow

$svcStatus = (Get-Service -Name "SCardSvr" -ErrorAction SilentlyContinue).Status
if ($svcStatus -eq "Running") {
    Write-Host "    [DONE] PC/SC 服务 (SCardSvr) 正在运行" -ForegroundColor Green
} else {
    Write-Host "    [WARN] PC/SC 服务未运行，尝试启动..." -ForegroundColor Yellow
    try {
        Start-Service -Name "SCardSvr"
        Write-Host "    [DONE] PC/SC 服务已启动" -ForegroundColor Green
    } catch {
        Write-Host "    [FAIL] 无法启动 PC/SC 服务: $_" -ForegroundColor Red
    }
}

Write-Host "    重启 PC/SC 服务以加载新读卡器..." -ForegroundColor Gray
try {
    Restart-Service -Name "SCardSvr" -Force -ErrorAction SilentlyContinue
    Write-Host "    [DONE] PC/SC 服务已重启" -ForegroundColor Green
} catch {
    Write-Host "    [WARN] 重启 PC/SC 服务失败（可能需要手动重启）" -ForegroundColor Yellow
}

# ================================================================
# 验证
# ================================================================
Write-Host ""
Write-Host "=== 验证注册结果 ===" -ForegroundColor Cyan

$readerExists = Test-Path $readerRegPath
$cardExists   = Test-Path $cardRegPath
$dllExists    = Test-Path "$env:SystemRoot\System32\$FidoDll"

Write-Host "  读卡器注册表: $(if ($readerExists) {'[OK]'} else {'[MISSING]'})" -ForegroundColor $(if ($readerExists) {'Green'} else {'Red'})
Write-Host "  智能卡注册表: $(if ($cardExists) {'[OK]'} else {'[MISSING]'})" -ForegroundColor $(if ($cardExists) {'Green'} else {'Red'})
Write-Host "  DLL 文件:     $(if ($dllExists) {'[OK]'} else {'[MISSING]'})" -ForegroundColor $(if ($dllExists) {'Green'} else {'Red'})

# 通过注册表枚举已注册的 PC/SC 读卡器
Write-Host ""
Write-Host "  已注册的 PC/SC 读卡器:" -ForegroundColor Cyan
$readersBase = "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers"
if (Test-Path $readersBase) {
    $readerKeys = Get-ChildItem -Path $readersBase -ErrorAction SilentlyContinue
    if ($readerKeys) {
        foreach ($rk in $readerKeys) {
            $rdName = $rk.PSChildName
            if ($rdName -like "*OpenCert*") {
                Write-Host "    - $rdName  [OUR DEVICE]" -ForegroundColor Green
            } else {
                Write-Host "    - $rdName"
            }
        }
    } else {
        Write-Host "    (暂无已注册读卡器)" -ForegroundColor Gray
    }
} else {
    Write-Host "    (无法访问读卡器注册表)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== 注册完成 ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "下一步：" -ForegroundColor White
Write-Host "  1. 启动 client-card 后端服务" -ForegroundColor Gray
Write-Host "  2. 在浏览器中访问支持 WebAuthn 的网站" -ForegroundColor Gray
Write-Host "  3. 选择 'OpenCert FIDO2' 作为认证器" -ForegroundColor Gray
Write-Host ""
