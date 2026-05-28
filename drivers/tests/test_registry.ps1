$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Software Key Storage Provider\UM\00010001"
$key = Get-Item $regPath
Write-Host "Functions type: $($key.GetValueKind('Functions'))"
Write-Host "Functions value: $($key.GetValue('Functions'))"
Write-Host "Flags type: $($key.GetValueKind('Flags'))"
Write-Host "Flags value: $($key.GetValue('Flags'))"
Write-Host "(default) type: $($key.GetValueKind(''))"
Write-Host "(default) value: $($key.GetValue(''))"
