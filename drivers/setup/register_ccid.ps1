# register_ccid.ps1 - 注册 OpenCert FIDO2 虚拟智能卡到 Windows
# 实际职责：FIDO2 CCID 虚拟智能卡注册（与 UMDF 无关）
#   - 注册 PC/SC 虚拟读卡器
#   - 注册 SmartCard ATR 匹配
#   - 重启 PC/SC 服务
#
# 必须以管理员身份运行。
# DLL 部署由主脚本 installer_all.bat 负责，本脚本不再重复部署。

param(
    [string]$FidoDll = "OpenCertFIDO.dll",
    [string]$CardName = "OpenCert FIDO2",
    [string]$ReaderName = "OpenCert FIDO2 Reader 0"
)

# ================================================================
# 辅助函数（统一 6 空格缩进）
# ================================================================
function Write-Ok   { param([string]$Msg) Write-Host "      [DONE] $Msg" -ForegroundColor Green  }
function Write-Warn { param([string]$Msg) Write-Host "      [WARN] $Msg" -ForegroundColor Yellow }
function Write-Info { param([string]$Msg) Write-Host "      [INFO] $Msg" -ForegroundColor Cyan   }
function Write-Fail { param([string]$Msg) Write-Host "      [FAIL] $Msg" -ForegroundColor Red    }

# ================================================================
# Step 1: 注册虚拟智能卡读卡器（PC/SC Reader）
# ================================================================
$readerRegPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers\$ReaderName"

try {
    if (-not (Test-Path $readerRegPath)) {
        New-Item -Path $readerRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $readerRegPath -Name "Vendor Name" -Value "GlobalTrusts" -Type String
    Set-ItemProperty -Path $readerRegPath -Name "IFD Type"    -Value "Virtual CCID" -Type String
    Set-ItemProperty -Path $readerRegPath -Name "Device Unit" -Value 0              -Type DWord
    Set-ItemProperty -Path $readerRegPath -Name "Port"        -Value 0              -Type DWord
    Write-Ok "Reader registered: $ReaderName"
} catch {
    Write-Fail "Register reader failed: $_"
    exit 1
}

# ================================================================
# Step 2: 注册 FIDO2 智能卡（SmartCard ATR 匹配）
# ================================================================
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
    Write-Ok "SmartCard registered: $CardName"
} catch {
    Write-Fail "Register SmartCard failed: $_"
    exit 1
}

# ================================================================
# Step 3: 确保 PC/SC 服务运行
# ================================================================
$svcStatus = (Get-Service -Name "SCardSvr" -ErrorAction SilentlyContinue).Status
if ($svcStatus -eq "Running") {
    Write-Info "PC/SC service (SCardSvr) is running"
} else {
    Write-Warn "PC/SC service not running, starting..."
    try {
        Start-Service -Name "SCardSvr"
        Write-Ok "PC/SC service started"
    } catch {
        Write-Fail "Cannot start PC/SC service: $_"
    }
}

try {
    Restart-Service -Name "SCardSvr" -Force -ErrorAction SilentlyContinue
    Write-Ok "PC/SC service restarted"
} catch {
    Write-Warn "Restart PC/SC service failed (may need manual restart)"
}

# ================================================================
# 验证
# ================================================================
$readerExists = Test-Path $readerRegPath
$cardExists   = Test-Path $cardRegPath
$dllExists    = Test-Path "$env:SystemRoot\System32\$FidoDll"

if ($readerExists) { Write-Ok "Reader registry: OK" } else { Write-Fail "Reader registry: MISSING" }
if ($cardExists)   { Write-Ok "SmartCard registry: OK" } else { Write-Fail "SmartCard registry: MISSING" }
if ($dllExists)    { Write-Ok "DLL file: OK" } else { Write-Warn "DLL file: MISSING (not yet deployed)" }

# 枚举已注册的 PC/SC 读卡器
$readersBase = "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers"
if (Test-Path $readersBase) {
    $readerKeys = Get-ChildItem -Path $readersBase -ErrorAction SilentlyContinue
    if ($readerKeys) {
        foreach ($rk in $readerKeys) {
            $rdName = $rk.PSChildName
            if ($rdName -like "*OpenCert*") {
                Write-Ok "PC/SC Reader: $rdName"
            }
        }
    }
}
