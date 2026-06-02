$logFile = "G:\Codes\GlobalTrusts\PKCS11Driver\drivers\setup\umdf_diag_output.txt"
$output = @()

$output += "=== UMDF DriverFrameworks Log ==="
$events = Get-WinEvent -LogName 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue
if ($events) {
    foreach ($e in $events) {
        if ($e.Level -le 3) {  # Error=2, Warning=3
            $output += "[$($e.TimeCreated)] ID=$($e.Id) Level=$($e.Level)"
            $output += $e.Message
            $output += "---"
        }
    }
    $output += "Total events: $($events.Count)"
} else {
    $output += "[WARN] Log not available or empty"
}

$output += ""
$output += "=== Kernel-PnP Log ==="
$pnpEvents = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 100 -ErrorAction SilentlyContinue
if ($pnpEvents) {
    foreach ($e in $pnpEvents) {
        if ($e.Message -match 'OpenCert|OPENCERTFIDO|oem135') {
            $output += "[$($e.TimeCreated)] ID=$($e.Id)"
            $output += $e.Message
            $output += "---"
        }
    }
}

$output += ""
$output += "=== System Log (Driver Errors) ==="
$sysEvents = Get-WinEvent -LogName 'System' -MaxEvents 500 -ErrorAction SilentlyContinue
if ($sysEvents) {
    foreach ($e in $sysEvents) {
        if ($e.Level -le 3 -and ($e.Message -match 'WUDFRd|WUDFHost|OpenCert|OPENCERTFIDO|oem135')) {
            $output += "[$($e.TimeCreated)] ID=$($e.Id) Source=$($e.ProviderName)"
            $output += $e.Message
            $output += "---"
        }
    }
}

$output | Out-File -FilePath $logFile -Encoding UTF8
Write-Host "Log saved to: $logFile"
Write-Host ""
$output | Select-Object -First 100 | ForEach-Object { Write-Host $_ }
