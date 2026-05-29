# verify-tpm-keys.ps1 — 验证 TPM/CNG 密钥存储情况
# 用法：在管理员 PowerShell 中运行

Write-Host "`n=== TPM 设备状态 ===" -ForegroundColor Cyan
try {
    $tpm = Get-Tpm -ErrorAction Stop
    Write-Host "  TPM Present:  $($tpm.TpmPresent)"
    Write-Host "  TPM Ready:    $($tpm.TpmReady)"
    Write-Host "  TPM Enabled:  $($tpm.TpmEnabled)"
    Write-Host "  Manufacturer: $($tpm.ManufacturerIdTxt) v$($tpm.ManufacturerVersion)"
} catch {
    Write-Host "  (需要管理员权限)" -ForegroundColor Yellow
}

Write-Host "`n=== Microsoft Platform Crypto Provider 密钥容器 ===" -ForegroundColor Cyan
Write-Host "  (运行 certutil -csp `"Microsoft Platform Crypto Provider`" -key)"
$keyOutput = & certutil -csp "Microsoft Platform Crypto Provider" -key 2>&1
$globalTrustsKeys = $keyOutput | Select-String "GlobalTrusts"
if ($globalTrustsKeys) {
    Write-Host "  发现 GlobalTrusts 密钥容器:" -ForegroundColor Green
    $globalTrustsKeys | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "  未发现 GlobalTrusts 密钥容器（尚未创建 high 卡片或密钥）" -ForegroundColor Yellow
    Write-Host "  全部密钥:"
    $keyOutput | Select-String "^  " | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" }
}

Write-Host "`n=== NV 域文件（medium 模式 TPM 证书密钥存储） ===" -ForegroundColor Cyan
$nvDir = "$env:APPDATA\GlobalTrusts\client-card\tpm\nv"
if (Test-Path $nvDir) {
    $files = Get-ChildItem $nvDir
    if ($files.Count -eq 0) {
        Write-Host "  NV 目录为空（尚未创建 medium 卡片）" -ForegroundColor Yellow
    } else {
        Write-Host "  NV 文件列表:" -ForegroundColor Green
        foreach ($f in $files) {
            $format = if ($f.Extension -eq '.dpapi') { "DPAPI加密" } elseif ($f.Extension -eq '.json') { "sw-stub(明文JSON)" } else { "未知" }
            Write-Host "    $($f.Name)  ($($f.Length) bytes)  [$format]"
            
            # 对 .json 文件可以读取 label
            if ($f.Extension -eq '.json') {
                try {
                    $content = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    Write-Host "      Label: $($content.label)"
                    Write-Host "      Size:  $($content.size) bytes"
                    Write-Host "      Has Data: $($null -ne $content.wrap -and $content.wrap.Length -gt 0)"
                } catch {}
            }
        }
    }
} else {
    Write-Host "  NV 目录不存在：$nvDir" -ForegroundColor Yellow
}

Write-Host "`n=== bind.key 状态（sw-stub SRK） ===" -ForegroundColor Cyan
$bindKeyPath = "$env:APPDATA\GlobalTrusts\client-card\tpm\bind.key"
if (Test-Path $bindKeyPath) {
    $bk = Get-Item $bindKeyPath
    Write-Host "  存在: $bindKeyPath ($($bk.Length) bytes)" -ForegroundColor Green
    Write-Host "  注意: 如果 Provider=windows-cng，此文件仅用于旧 sw-stub 兼容" -ForegroundColor Gray
} else {
    Write-Host "  不存在（正常 — CNG 模式不需要此文件）" -ForegroundColor Green
}

Write-Host "`n=== 操作建议 ===" -ForegroundColor Cyan
Write-Host "  1. 创建 high 卡 + 生成密钥 → 重新运行此脚本，观察 PCP 密钥容器增加"
Write-Host "  2. 创建 medium 卡 → 观察 NV 文件增加（.dpapi 格式 = DPAPI 保护）"
Write-Host "  3. 删除卡片 → 观察 PCP 容器 / NV 文件消失"
Write-Host "  4. 拷贝 NV .dpapi 文件到另一台机器 → CryptUnprotectData 失败（绑定本机用户）"
Write-Host ""
