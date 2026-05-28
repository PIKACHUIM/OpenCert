@echo off
chcp 65001 >nul 2>&1

:: Must run as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run as Administrator!
    pause
    exit /b 1
)

echo === Fix KSP Flags: Change from 0x10000 to 0x0 ===
echo.
echo The Flags value 0x10000 is used by Microsoft's own KSPs.
echo Third-party KSPs should use Flags=0 (like Microsoft Smart Card KSP).
echo.

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider\UM\00010001" /v "Flags" /t REG_DWORD /d 0 /f

echo.
echo === Verifying ===
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\OpenCert Key Storage Provider\UM\00010001"

echo.
echo === Now test with: ===
echo certutil -csp "OpenCert Key Storage Provider" -key
echo.
pause
