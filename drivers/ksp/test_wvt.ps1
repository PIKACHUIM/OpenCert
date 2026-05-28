# Verify DLL with WinVerifyTrust (same as CNG uses)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WVT {
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode)]
    public static extern int WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        ref WINTRUST_DATA pWVTData
    );

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct WINTRUST_FILE_INFO {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = 
        new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    
    public const uint WTD_UI_NONE = 2;
    public const uint WTD_CHOICE_FILE = 1;
    public const uint WTD_REVOKE_NONE = 0;
    public const uint WTD_STATEACTION_VERIFY = 1;
}
"@

function Test-WinVerifyTrust($filePath) {
    $fileInfo = New-Object WVT+WINTRUST_FILE_INFO
    $fileInfo.cbStruct = [System.Runtime.InteropServices.Marshal]::SizeOf($fileInfo)
    $fileInfo.pcwszFilePath = $filePath
    $fileInfo.hFile = [IntPtr]::Zero
    $fileInfo.pgKnownSubject = [IntPtr]::Zero

    $pFileInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($fileInfo))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($fileInfo, $pFileInfo, $false)

    $trustData = New-Object WVT+WINTRUST_DATA
    $trustData.cbStruct = [System.Runtime.InteropServices.Marshal]::SizeOf($trustData)
    $trustData.dwUIChoice = [WVT]::WTD_UI_NONE
    $trustData.fdwRevocationChecks = [WVT]::WTD_REVOKE_NONE
    $trustData.dwUnionChoice = [WVT]::WTD_CHOICE_FILE
    $trustData.pFile = $pFileInfo
    $trustData.dwStateAction = [WVT]::WTD_STATEACTION_VERIFY

    $guid = [WVT]::WINTRUST_ACTION_GENERIC_VERIFY_V2
    $result = [WVT]::WinVerifyTrust([IntPtr]::Zero, [ref]$guid, [ref]$trustData)
    
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pFileInfo)
    return $result
}

Write-Host "=== WinVerifyTrust Test ===" -ForegroundColor Cyan
Write-Host ""

$files = @(
    "C:\WINDOWS\System32\SimplySignKSP.dll",
    "C:\WINDOWS\System32\OpenCertKSP.dll"
)

foreach ($f in $files) {
    $result = Test-WinVerifyTrust $f
    $status = if ($result -eq 0) { "[TRUSTED]" } else { "[NOT TRUSTED]" }
    $color = if ($result -eq 0) { "Green" } else { "Red" }
    Write-Host "$status $f (0x$($result.ToString('X8')))" -ForegroundColor $color
}
