# unregister_ksp.ps1 - Unregister OpenCert KSP via BCryptUnregisterProvider API
# Usage: powershell -ExecutionPolicy Bypass -File unregister_ksp.ps1 -KspName "..."
param(
    [string]$KspName = "OpenCert Key Storage Provider"
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class KspUnreg {
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptUnregisterProvider(string pszProvider);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptRemoveContextFunctionProvider(
        uint dwTable, string pszContext, uint dwInterface,
        string pszFunction, string pszProvider);
}
"@

# Remove from Default context
$status = [KspUnreg]::BCryptRemoveContextFunctionProvider(
    1,              # CRYPT_LOCAL
    'Default',      # Default context
    0x00010001,     # NCRYPT_KEY_STORAGE_INTERFACE
    'KEY_STORAGE',  # Function name
    $KspName        # Provider name
)

if ($status -ne 0 -and $status -ne 0xC0000034) {
    # 0xC0000034 = STATUS_OBJECT_NAME_NOT_FOUND (already removed, OK)
    Write-Host "BCryptRemoveContextFunctionProvider warning: 0x$($status.ToString('X8'))"
}

# Unregister provider
$status2 = [KspUnreg]::BCryptUnregisterProvider($KspName)
if ($status2 -ne 0 -and $status2 -ne 0xC0000034) {
    Write-Host "BCryptUnregisterProvider failed: 0x$($status2.ToString('X8'))"
    exit 1
}

Write-Host "KSP '$KspName' unregistered successfully"
exit 0
