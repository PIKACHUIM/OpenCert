# Check ACL differences between SimplySign and our KSP registry keys
Write-Host "=== Registry ACL Comparison ===" -ForegroundColor Cyan
Write-Host ""

$simplyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\SimplySign KSP"
$ourPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider"

Write-Host "--- SimplySign KSP ACL ---" -ForegroundColor Yellow
$simplyAcl = Get-Acl $simplyPath
$simplyAcl.Access | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize

Write-Host ""
Write-Host "--- Our KSP ACL ---" -ForegroundColor Yellow
$ourAcl = Get-Acl $ourPath
$ourAcl.Access | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize

# Also check owner
Write-Host ""
Write-Host "Owners:" -ForegroundColor Cyan
Write-Host "  SimplySign: $($simplyAcl.Owner)"
Write-Host "  Ours: $($ourAcl.Owner)"

# Check UM subkey ACL
Write-Host ""
Write-Host "--- SimplySign UM ACL ---" -ForegroundColor Yellow
$simplyUmAcl = Get-Acl "$simplyPath\UM"
$simplyUmAcl.Access | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize

Write-Host ""
Write-Host "--- Our UM ACL ---" -ForegroundColor Yellow
$ourUmAcl = Get-Acl "$ourPath\UM"
$ourUmAcl.Access | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize
