# register_fido.ps1 - 注册 OpenCert FIDO2 虚拟 HID 驱动到 Windows
# 实际职责：安装 HID FIDO2 驱动（虚拟 HID 设备，通过 HID Usage Page 0xF1D0 被 WebAuthn API 识别）
#
# 必须以管理员身份运行。
#
# 策略：
#   - 如果设备已存在 → 更新驱动（devcon update），不创建新设备
#   - 如果设备不存在 → 清理旧驱动包 + devcon install 创建设备

param(
    [string]$InfFile = "",   # 可选：手动指定 INF 路径
    [string]$DllFile = ""    # 可选：手动指定 DLL 路径
)

# ================================================================
# 管理员权限检查
# ================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "      [FAIL] This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "      Please run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# ================================================================
# 辅助函数（统一 6 空格缩进，标签：[DONE]/[WARN]/[FAIL]/[INFO]/[SKIP]）
# ================================================================
function Write-Ok   { param([string]$Msg) Write-Host "      [DONE] $Msg" -ForegroundColor Green  }
function Write-Warn { param([string]$Msg) Write-Host "      [WARN] $Msg" -ForegroundColor Yellow }
function Write-Info { param([string]$Msg) Write-Host "      [INFO] $Msg" -ForegroundColor Cyan   }
function Write-Fail { param([string]$Msg) Write-Host "      [FAIL] $Msg" -ForegroundColor Red    }

# ================================================================
# 解析路径
# ================================================================
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir  = Join-Path $scriptDir "..\build\FidoHidDriver"

if ($InfFile -eq "") { $InfFile = Join-Path $buildDir "FidoHidDriver.inf" }
if ($DllFile -eq "") { $DllFile = Join-Path $buildDir "FidoHidDriver.dll" }

$HW_ID = "ROOT\FidoHidDriver"

# ================================================================
# 前置检查
# ================================================================
Write-Info "INF: $InfFile"
Write-Info "DLL: $DllFile"

if (-not (Test-Path $DllFile)) {
    Write-Fail "DLL not found: $DllFile"
    exit 1
}

if (-not (Test-Path $InfFile)) {
    Write-Fail "INF not found: $InfFile"
    exit 1
}

# 查找 devcon.exe（兼容 PowerShell 5.x，不使用 ?. 操作符）
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
    if ($null -ne $cmd) {
        $devcon = $cmd.Source
    }
}

if ($null -ne $devcon) {
    Write-Info "devcon.exe: $devcon"
} else {
    Write-Fail "devcon.exe not found, cannot install HID driver"
    exit 1
}

# ================================================================
# 检测设备是否已存在（通过硬件 ID 精确匹配）
# ================================================================
$existingDeviceCount = 0
$existingDevices = @()

# 先查 ROOT\FidoHidDriver\* （devcon install 创建的节点）
$directDevices = Get-PnpDevice -InstanceId "ROOT\FidoHidDriver\*" -ErrorAction SilentlyContinue
if ($directDevices) {
    foreach ($dev in @($directDevices)) {
        $existingDevices += $dev
        $existingDeviceCount++
    }
}

# 再查 ROOT\HIDCLASS\* （少数情况下可能在这里）
if ($existingDeviceCount -eq 0) {
    $allHidDevices = Get-PnpDevice -InstanceId "ROOT\HIDCLASS\*" -ErrorAction SilentlyContinue
    if ($allHidDevices) {
        foreach ($dev in @($allHidDevices)) {
            $hwIds = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue
            if ($hwIds -and $hwIds.Data -contains "ROOT\FidoHidDriver") {
                $existingDevices += $dev
                $existingDeviceCount++
            }
        }
    }
}

Write-Info "Existing FIDO2 HID device(s): $existingDeviceCount"

if ($existingDeviceCount -gt 0) {
    # ============================================================
    # 设备已存在 → 更新驱动（不创建新设备）
    # ============================================================
    
    # 如果有多余的设备，先移除到只剩 1 个
    if ($existingDeviceCount -gt 1) {
        Write-Warn "Multiple devices detected ($existingDeviceCount), cleaning duplicates..."
        $kept = $false
        foreach ($dev in $existingDevices) {
            if ($kept) {
                Write-Info "Removing duplicate: $($dev.InstanceId)"
                pnputil /remove-device "$($dev.InstanceId)" 2>&1 | Out-Null
            } else {
                $kept = $true
            }
        }
        Start-Sleep -Milliseconds 500
    }

    # 先清理旧驱动包（避免版本冲突）
    $enumOutput = pnputil /enum-drivers 2>$null
    if ($enumOutput) {
        $currentOem = $null
        foreach ($line in $enumOutput) {
            if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
                $currentOem = $Matches[1]
            }
            if ($line -match "Original Name\s*:.*FidoHidDriver" -and $null -ne $currentOem) {
                Write-Info "Removing old driver package: $currentOem"
                pnputil /delete-driver $currentOem /force 2>&1 | Out-Null
                $currentOem = $null
            }
        }
    }

    # 添加新驱动包到存储
    Write-Info "Adding new driver package..."
    pnputil /add-driver "$InfFile" 2>&1 | Out-Null

    # 使用 devcon update 更新驱动
    Write-Info "Updating driver on existing device..."
    $updateOutput = & $devcon update "$InfFile" $HW_ID 2>&1
    $updateOutput | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }

    if ($LASTEXITCODE -ne 0) {
        Write-Warn "devcon update failed (exit=$LASTEXITCODE), driver may need reboot"
    } else {
        Write-Ok "HID FIDO2 driver updated"
    }

} else {
    # ============================================================
    # 设备不存在 → 清理旧驱动包 + 创建新设备
    # ============================================================
    
    # 清理旧驱动包
    $enumOutput = pnputil /enum-drivers 2>$null
    if ($enumOutput) {
        $currentOem = $null
        foreach ($line in $enumOutput) {
            if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
                $currentOem = $Matches[1]
            }
            if ($line -match "Original Name\s*:.*FidoHidDriver" -and $null -ne $currentOem) {
                Write-Info "Removing old driver package: $currentOem"
                pnputil /delete-driver $currentOem /force 2>&1 | Out-Null
                $currentOem = $null
            }
        }
    }

    # devcon install 一步完成：添加驱动到存储 + 创建设备节点
    Write-Info "Creating new device node..."
    $installOutput = & $devcon install "$InfFile" $HW_ID 2>&1
    $installOutput | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "devcon install failed (exit=$LASTEXITCODE)"
        exit 1
    } else {
        Write-Ok "HID FIDO2 device installed"
    }
}

# ================================================================
# 验证
# ================================================================
$finalCount = 0
$finalDevices = Get-PnpDevice -InstanceId "ROOT\HIDCLASS\*" -ErrorAction SilentlyContinue
if ($finalDevices) {
    foreach ($dev in $finalDevices) {
        $hwIds = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue
        if ($hwIds -and $hwIds.Data -contains "ROOT\FidoHidDriver") {
            $finalCount++
            Write-Ok "Device: $($dev.InstanceId) [Status: $($dev.Status)]"
        }
    }
}

if ($finalCount -eq 0) {
    Write-Warn "No device found (may need reboot)"
}

$enumAfter = pnputil /enum-drivers 2>$null
if ($enumAfter) {
    $currentOem = $null
    foreach ($line in $enumAfter) {
        if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
            $currentOem = $Matches[1]
        }
        if ($line -match "Original Name\s*:.*FidoHidDriver" -and $null -ne $currentOem) {
            Write-Ok "Driver in store: $currentOem"
            $currentOem = $null
        }
    }
}

# ================================================================
# Fix device stack: set MsHidUmdf as LowerFilter
# hidclass.sys needs MsHidUmdf.sys as lower filter to expose HID interface
# ================================================================
Write-Info "Fixing HID device stack (MsHidUmdf LowerFilter)..."

$devRegKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\HIDCLASS\0000"
if (-not (Test-Path $devRegKey)) {
    # Also try the direct hardware ID path
    $devRegKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\FidoHidDriver\0000"
}

if (Test-Path $devRegKey) {
    $currentLF = (Get-ItemProperty $devRegKey -ErrorAction SilentlyContinue).LowerFilters
    if ($currentLF -notcontains "MsHidUmdf") {
        Set-ItemProperty -Path $devRegKey -Name "LowerFilters" -Value @("MsHidUmdf") -Type MultiString
        Write-Ok "Set LowerFilters = MsHidUmdf on $devRegKey"
    } else {
        Write-Ok "LowerFilters already contains MsHidUmdf"
    }

    # Restart device to apply LowerFilter
    Write-Info "Restarting device to apply LowerFilter..."
    if ($null -ne $devcon) {
        & $devcon restart $HW_ID 2>&1 | Out-Null
    } else {
        Disable-PnpDevice -InstanceId "ROOT\HIDCLASS\0000" -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
        Enable-PnpDevice -InstanceId "ROOT\HIDCLASS\0000" -Confirm:$false -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 1500

    $stack = (Get-PnpDeviceProperty -InstanceId "ROOT\HIDCLASS\0000" -KeyName "DEVPKEY_Device_Stack" -ErrorAction SilentlyContinue).Data
    if ($stack) {
        Write-Ok "Device Stack: $($stack -join ' -> ')"
        if ($stack -contains "\Driver\MsHidUmdf") {
            Write-Ok "MsHidUmdf is in stack - HID interface will be registered"
        } else {
            Write-Warn "MsHidUmdf not in stack yet - reboot may be required"
        }
    }
} else {
    Write-Warn "Device registry key not found, skipping LowerFilter fix"
}