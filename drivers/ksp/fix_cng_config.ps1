# fix_cng_config.ps1 - Add OpenCert KSP to CNG Configuration
# Must run as Administrator

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\Default\00010001\KEY_STORAGE"

Write-Host "=== Fix CNG Configuration ===" -ForegroundColor Cyan
Write-Host ""

# Read current providers
$currentProviders = (Get-ItemProperty -Path $regPath -Name "Providers").Providers
Write-Host "Current providers:" -ForegroundColor Yellow
for ($i = 0; $i -lt $currentProviders.Count; $i++) {
    Write-Host "  [$i] $($currentProviders[$i])"
}

$kspName = "OpenCert Key Storage Provider"

# Check if already registered
if ($currentProviders -contains $kspName) {
    Write-Host ""
    Write-Host "[OK] Already registered in CNG configuration!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Adding '$kspName'..." -ForegroundColor Yellow
    
    # Add to the list
    $newProviders = $currentProviders + $kspName
    
    try {
        Set-ItemProperty -Path $regPath -Name "Providers" -Value $newProviders -Type MultiString
        Write-Host "[OK] Successfully added!" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please run as Administrator!" -ForegroundColor Red
        exit 1
    }
}

# Verify
Write-Host ""
Write-Host "Updated providers:" -ForegroundColor Yellow
$updatedProviders = (Get-ItemProperty -Path $regPath -Name "Providers").Providers
for ($i = 0; $i -lt $updatedProviders.Count; $i++) {
    $marker = if ($updatedProviders[$i] -eq $kspName) { " <-- OURS" } else { "" }
    Write-Host "  [$i] $($updatedProviders[$i])$marker"
}

# Test
Write-Host ""
Write-Host "Testing NCryptOpenStorageProvider..." -ForegroundColor Yellow

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NTest {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr p, string n, int f);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr h);
}
"@

$h = [IntPtr]::Zero
$r = [NTest]::NCryptOpenStorageProvider([ref]$h, $kspName, 0)
Write-Host ("  Result: 0x{0:X8}" -f $r)
if ($r -eq 0) {
    Write-Host "  [OK] SUCCESS!" -ForegroundColor Green
    [NTest]::NCryptFreeObject($h) | Out-Null
} else {
    Write-Host "  [FAIL]" -ForegroundColor Red
}
