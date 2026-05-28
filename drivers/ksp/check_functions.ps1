$path = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider\UM\00010001"
$val = (Get-ItemProperty -Path $path).Functions
Write-Host "Our Functions:"
Write-Host "  Type: $($val.GetType().FullName)"
Write-Host "  Count: $($val.Count)"
for ($i = 0; $i -lt $val.Count; $i++) {
    Write-Host "  [$i] = `"$($val[$i])`" (len=$($val[$i].Length))"
}

Write-Host ""
$refPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SimplySign KSP\UM\00010001"
$refVal = (Get-ItemProperty -Path $refPath).Functions
Write-Host "SimplySign Functions:"
Write-Host "  Type: $($refVal.GetType().FullName)"
Write-Host "  Count: $($refVal.Count)"
for ($i = 0; $i -lt $refVal.Count; $i++) {
    Write-Host "  [$i] = `"$($refVal[$i])`" (len=$($refVal[$i].Length))"
}

# Also check the raw bytes
Write-Host ""
Write-Host "Raw comparison:"
$ourKey = Get-Item $path
$refKey = Get-Item $refPath
$ourRaw = $ourKey.GetValue("Functions", $null, "DoNotExpandEnvironmentNames")
$refRaw = $refKey.GetValue("Functions", $null, "DoNotExpandEnvironmentNames")
Write-Host "  Ours: [$($ourRaw -join '|')]"
Write-Host "  Ref:  [$($refRaw -join '|')]"
