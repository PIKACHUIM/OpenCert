# fix_hid_stack.ps1
# Directly set MsHidUmdf as LowerFilter for the virtual HID device
# Run as Administrator

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[FAIL] Run as Administrator" -ForegroundColor Red; exit 1 }

$devKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\HIDCLASS\0000"
$devcon = $null
foreach ($v in Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Tools" -ErrorAction SilentlyContinue) {
    $c = Join-Path $v.FullName "x64\devcon.exe"
    if (Test-Path $c) { $devcon = $c; break }
}

Write-Host "=== Fix HID Device Stack ===" -ForegroundColor Cyan

# Step 1: Ensure MsHidUmdf service exists
$svc = Get-Service MsHidUmdf -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "[FAIL] MsHidUmdf service not found. Run installer_all.bat first." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] MsHidUmdf service exists" -ForegroundColor Green

# Step 2: Check device exists
if (-not (Test-Path $devKey)) {
    Write-Host "[FAIL] Device ROOT\HIDCLASS\0000 not found" -ForegroundColor Red
    exit 1
}

# Step 3: Set LowerFilters = MsHidUmdf
$current = (Get-ItemProperty $devKey -ErrorAction SilentlyContinue).LowerFilters
Write-Host "Current LowerFilters: $current"
Set-ItemProperty -Path $devKey -Name "LowerFilters" -Value @("MsHidUmdf") -Type MultiString
Write-Host "[OK] Set LowerFilters = MsHidUmdf" -ForegroundColor Green

# Step 4: Restart device to apply
Write-Host "Restarting device..." -ForegroundColor Yellow
if ($devcon) {
    & $devcon restart "ROOT\FidoHidDriver"
} else {
    # Fallback: disable then enable
    Disable-PnpDevice -InstanceId "ROOT\HIDCLASS\0000" -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 1000
    Enable-PnpDevice -InstanceId "ROOT\HIDCLASS\0000" -Confirm:$false -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 2000

# Step 5: Verify
$stack = (Get-PnpDeviceProperty -InstanceId "ROOT\HIDCLASS\0000" -KeyName "DEVPKEY_Device_Stack" -ErrorAction SilentlyContinue).Data
Write-Host "Device Stack: $($stack -join ' -> ')" -ForegroundColor Cyan

$children = (Get-PnpDeviceProperty -InstanceId "ROOT\HIDCLASS\0000" -KeyName "DEVPKEY_Device_Children" -ErrorAction SilentlyContinue).Data
if ($children) {
    Write-Host "[OK] Child devices created:" -ForegroundColor Green
    foreach ($c in $children) { Write-Host "  $c" }
} else {
    Write-Host "[WARN] No child devices yet (may need reboot)" -ForegroundColor Yellow
}

if ($stack -contains "\Driver\MsHidUmdf") {
    Write-Host "[SUCCESS] MsHidUmdf is in device stack!" -ForegroundColor Green
} else {
    Write-Host "[WARN] MsHidUmdf not in stack yet, try rebooting" -ForegroundColor Yellow
}
