$dll = "C:\Windows\System32\drivers\UMDF\OpenCertFIDODriver.dll"
$buildDll = "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build\OpenCertFIDODriver.dll"

Write-Host "=== UMDF DLL Check ===" -ForegroundColor Cyan

# Check UMDF DLL
if (Test-Path $dll) {
    $item = Get-Item $dll
    Write-Host "UMDF DLL: EXISTS ($($item.Length) bytes, $($item.LastWriteTime))"
    $sig = Get-AuthenticodeSignature $dll
    Write-Host "Signature Status: $($sig.Status)"
    Write-Host "Signature Message: $($sig.StatusMessage)"
    if ($sig.SignerCertificate) {
        Write-Host "Signer: $($sig.SignerCertificate.Subject)"
    }
} else {
    Write-Host "UMDF DLL: NOT FOUND" -ForegroundColor Red
}

Write-Host ""

# Check build DLL
if (Test-Path $buildDll) {
    $item = Get-Item $buildDll
    Write-Host "Build DLL: EXISTS ($($item.Length) bytes, $($item.LastWriteTime))"
    $sig = Get-AuthenticodeSignature $buildDll
    Write-Host "Signature Status: $($sig.Status)"
    Write-Host "Signature Message: $($sig.StatusMessage)"
} else {
    Write-Host "Build DLL: NOT FOUND" -ForegroundColor Red
}

Write-Host ""

# Check if they are the same file
if ((Test-Path $dll) -and (Test-Path $buildDll)) {
    $hash1 = (Get-FileHash $dll -Algorithm MD5).Hash
    $hash2 = (Get-FileHash $buildDll -Algorithm MD5).Hash
    Write-Host "UMDF DLL MD5:  $hash1"
    Write-Host "Build DLL MD5: $hash2"
    if ($hash1 -eq $hash2) {
        Write-Host "Files are IDENTICAL" -ForegroundColor Green
    } else {
        Write-Host "Files are DIFFERENT" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Device Problem Status ===" -ForegroundColor Cyan
$dev = Get-PnpDevice -InstanceId "ROOT\OPENCERTFIDO\0000" -ErrorAction SilentlyContinue
if ($dev) {
    Write-Host "Status: $($dev.Status)"
    Write-Host "Problem: $($dev.Problem)"
    Write-Host "ConfigManagerErrorCode: $($dev.ConfigManagerErrorCode)"
}

Write-Host ""
Write-Host "=== Recent System Events (UMDF related) ===" -ForegroundColor Cyan
Get-WinEvent -LogName System -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(7000,7001,7009,7011,7023,7024,7026,7034,7043) -and
                   ($_.TimeCreated -gt (Get-Date).AddMinutes(-10)) } |
    Select-Object TimeCreated, Id, Message |
    Format-List
