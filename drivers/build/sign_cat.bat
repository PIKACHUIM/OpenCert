@echo off
set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
set "PFX=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build\FidoUsbIpVhci\usbip_test.pfx"
set "DIR=G:\Codes\GlobalTrusts\PKCS11Driver\drivers\build\FidoUsbIpVhci"

echo Signing usbip_vhci.cat...
"%SIGNTOOL%" sign /f "%PFX%" /t http://timestamp.digicert.com /fd sha256 "%DIR%\usbip_vhci.cat"
echo Exit code: %errorlevel%

echo Signing usbip_vhci_ude.cat...
"%SIGNTOOL%" sign /f "%PFX%" /t http://timestamp.digicert.com /fd sha256 "%DIR%\usbip_vhci_ude.cat"
echo Exit code: %errorlevel%

echo Done!
