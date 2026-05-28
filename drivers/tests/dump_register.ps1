function Dump-RegKey {
    param($path, $indent = "")
    $key = Get-Item $path -ErrorAction SilentlyContinue
    if (-not $key) { return }
    Write-Host ($indent + $key.Name)
    foreach ($vn in $key.GetValueNames()) {
        $kind = $key.GetValueKind($vn)
        $val = $key.GetValue($vn)
        $dn = if ($vn -eq "") { "(Default)" } else { $vn }
        if ($val -is [string[]]) {
            Write-Host ($indent + "  " + $dn + " [" + $kind + "] = [" + ($val -join "|") + "]")
        } else {
            Write-Host ($indent + "  " + $dn + " [" + $kind + "] = " + $val)
        }
    }
    foreach ($sub in $key.GetSubKeyNames()) {
        Dump-RegKey -path ($path + "\" + $sub) -indent ($indent + "  ")
    }
}

Write-Host "=== SimplySign KSP (FULL) ===" -ForegroundColor Cyan
Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SimplySign KSP"

Write-Host ""
Write-Host "=== OpenCert KSP (FULL) ===" -ForegroundColor Yellow
Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider"

# Also check Configuration
Write-Host ""
Write-Host "=== CNG Configuration ===" -ForegroundColor Cyan
Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\Default\00010001"
