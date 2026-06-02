$umdfDll = "C:\Windows\System32\drivers\UMDF\OpenCertFIDODriver.dll"
$buildDll = "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build\OpenCertFIDODriver.dll"

Write-Host "=== UMDF Driver Diagnostics ===" -ForegroundColor Cyan

# 1. 检查签名
Write-Host "`n[1] Signature Check:" -ForegroundColor Yellow
foreach ($dll in @($umdfDll, $buildDll)) {
    if (Test-Path $dll) {
        $sig = Get-AuthenticodeSignature $dll
        Write-Host "  $dll"
        Write-Host "    Status: $($sig.Status)"
        Write-Host "    Message: $($sig.StatusMessage)"
        if ($sig.SignerCertificate) {
            Write-Host "    Signer: $($sig.SignerCertificate.Subject)"
        }
    } else {
        Write-Host "  NOT FOUND: $dll" -ForegroundColor Red
    }
}

# 2. 检查 DLL 是否可以加载（检查依赖项）
Write-Host "`n[2] DLL Load Test:" -ForegroundColor Yellow
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DllCheck {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FreeLibrary(IntPtr hModule);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetLastError();
}
"@

$LOAD_LIBRARY_AS_DATAFILE = 0x00000002
$h = [DllCheck]::LoadLibraryEx($umdfDll, [IntPtr]::Zero, $LOAD_LIBRARY_AS_DATAFILE)
if ($h -ne [IntPtr]::Zero) {
    Write-Host "  LoadLibraryEx (DATAFILE): SUCCESS" -ForegroundColor Green
    [DllCheck]::FreeLibrary($h) | Out-Null
} else {
    $err = [DllCheck]::GetLastError()
    Write-Host "  LoadLibraryEx (DATAFILE): FAILED, Error=$err (0x$($err.ToString('X8')))" -ForegroundColor Red
}

# 3. 检查 INF 中的 UmdfLibraryVersion
Write-Host "`n[3] INF UmdfLibraryVersion Check:" -ForegroundColor Yellow
$infPath = "C:\Windows\INF\oem135.inf"
if (Test-Path $infPath) {
    $content = Get-Content $infPath
    $verLine = $content | Where-Object { $_ -match "UmdfLibraryVersion" }
    Write-Host "  $verLine"
    
    # 检查系统 UMDF 版本
    $wudfVer = (Get-Item "C:\Windows\System32\WUDFx02000.dll").VersionInfo
    Write-Host "  System WUDFx02000.dll: $($wudfVer.FileVersion)"
    Write-Host "  System Build: $($wudfVer.FileBuildPart)"
    
    # Win11 24H2 (26100) 对应 UMDF 2.33
    if ($wudfVer.FileBuildPart -ge 26100) {
        Write-Host "  System UMDF version: 2.33 (Win11 24H2)" -ForegroundColor Cyan
    } elseif ($wudfVer.FileBuildPart -ge 22621) {
        Write-Host "  System UMDF version: 2.31 (Win11 22H2)" -ForegroundColor Cyan
    }
}

# 4. 检查 WUDFRd 服务状态
Write-Host "`n[4] WUDFRd Service Status:" -ForegroundColor Yellow
$svc = Get-Service -Name "WUDFRd" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  Status: $($svc.Status)"
    Write-Host "  StartType: $($svc.StartType)"
} else {
    Write-Host "  WUDFRd service NOT FOUND" -ForegroundColor Red
}

# 5. 检查设备问题详情
Write-Host "`n[5] Device Problem Details:" -ForegroundColor Yellow
$dev = Get-PnpDevice -InstanceId "ROOT\OPENCERTFIDO\0000" -ErrorAction SilentlyContinue
if ($dev) {
    Write-Host "  Status: $($dev.Status)"
    Write-Host "  Problem: $($dev.Problem)"
    Write-Host "  ConfigManagerErrorCode: $($dev.ConfigManagerErrorCode)"
    
    # 获取更多属性
    $props = Get-PnpDeviceProperty -InstanceId "ROOT\OPENCERTFIDO\0000" -ErrorAction SilentlyContinue
    $problemStatus = $props | Where-Object { $_.KeyName -like "*ProblemStatus*" }
    if ($problemStatus) {
        Write-Host "  ProblemStatus: $($problemStatus.Data)"
    }
}

# 6. 检查 UMDF 日志（如果已启用）
Write-Host "`n[6] Recent System Events (PnP/Driver):" -ForegroundColor Yellow
$events = Get-WinEvent -LogName 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) {
    Write-Host "[WARN] 无法读取 DriverFrameworks 日志（可能需要启用）"
} else {
    foreach ($e in $events) {
        $msg = $e.Message
        if ($msg -match 'OpenCert|OPENCERTFIDO|oem135|WUDFHost|failed|error|0xC000' -or $e.Level -le 2) {
            Write-Host "[$($e.TimeCreated)] ID=$($e.Id) Level=$($e.LevelDisplayName)"
            Write-Host $msg.Substring(0, [Math]::Min(500, $msg.Length))
            Write-Host "---"
        }
    }
}

Write-Host ""
Write-Host "=== 系统日志中的 PnP 错误 ==="
$sysEvents = Get-WinEvent -LogName 'System' -MaxEvents 200 -ErrorAction SilentlyContinue
foreach ($e in $sysEvents) {
    $msg = $e.Message
    if ($msg -match 'OpenCert|OPENCERTFIDO|oem135|WUDFRd|WUDFHost') {
        Write-Host "[$($e.TimeCreated)] ID=$($e.Id) Source=$($e.ProviderName)"
        Write-Host $msg.Substring(0, [Math]::Min(500, $msg.Length))
        Write-Host "---"
    }
}

Write-Host ""
Write-Host "=== 设备 ProblemStatus 详情 ==="
$dev = Get-PnpDevice -InstanceId 'ROOT\OPENCERTFIDO\0000' -ErrorAction SilentlyContinue
if ($dev) {
    $dev | Format-List *
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan