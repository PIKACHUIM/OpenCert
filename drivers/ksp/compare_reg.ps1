$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider\UM\00010001"
$refPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Software Key Storage Provider\UM\00010001"

Write-Host "=== Reference (Microsoft Software KSP) ===" -ForegroundColor Cyan
$refKey = Get-Item $refPath
Write-Host "Functions type: $($refKey.GetValueKind('Functions'))"
Write-Host "Functions value: [$($refKey.GetValue('Functions') -join ', ')]"
Write-Host "Functions raw bytes:"
$rawRef = $refKey.GetValue('Functions', $null, 'DoNotExpandEnvironmentNames')
Write-Host "  $rawRef"
Write-Host ""

Write-Host "=== Our KSP ===" -ForegroundColor Yellow
if (Test-Path $regPath) {
    $ourKey = Get-Item $regPath
    Write-Host "Functions type: $($ourKey.GetValueKind('Functions'))"
    Write-Host "Functions value: [$($ourKey.GetValue('Functions') -join ', ')]"
    Write-Host "(default) type: $($ourKey.GetValueKind(''))"
    Write-Host "(default) value: $($ourKey.GetValue(''))"
    Write-Host "Flags type: $($ourKey.GetValueKind('Flags'))"
    Write-Host "Flags value: $($ourKey.GetValue('Flags'))"
} else {
    Write-Host "[FAIL] Key not found: $regPath" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Parent UM key ===" -ForegroundColor Cyan
$umPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider\UM"
$umKey = Get-Item $umPath
Write-Host "Image type: $($umKey.GetValueKind('Image'))"
Write-Host "Image value: $($umKey.GetValue('Image'))"

Write-Host ""
Write-Host "=== Reference UM key ===" -ForegroundColor Cyan
$refUmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Software Key Storage Provider\UM"
$refUmKey = Get-Item $refUmPath
Write-Host "Image type: $($refUmKey.GetValueKind('Image'))"
Write-Host "Image value: $($refUmKey.GetValue('Image'))"

Write-Host ""
Write-Host "=== Root key comparison ===" -ForegroundColor Cyan
$ourRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider"
$refRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Software Key Storage Provider"
Write-Host "Our root values:"
Get-ItemProperty $ourRoot | Select-Object * -ExcludeProperty PS* | Format-List
Write-Host "Ref root values:"
Get-ItemProperty $refRoot | Select-Object * -ExcludeProperty PS* | Format-List
