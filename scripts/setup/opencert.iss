#ifndef AppVersion
  #define AppVersion "0.0.1-dev"
#endif
#ifndef PkgDir
  #define PkgDir "..\..\pkg"
#endif

#define AppName      "OpenCert"
#define AppPublisher "GlobalTrusts"
#define SvcName      "opencert-client"

[Setup]
AppId={{B8E5F4D2-1C3A-4E7F-9B0D-6A2C5E8F1D4B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\..\dist
OutputBaseFilename=opencert-setup-{#AppVersion}
Compression=lzma2/ultra
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Client service binary
Source: "{#PkgDir}\client\client-card.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
; Native client binary
Source: "{#PkgDir}\native\native-client.exe"; DestDir: "{app}"; Flags: ignoreversion
; Desktop（Go + Wails 客户端，单文件可执行程序）
Source: "{#PkgDir}\desktop\OpenCertManager.exe"; DestDir: "{app}\desktop"; Flags: ignoreversion
; Drivers — preserve setup/ + build/ sibling structure (installer_all.bat uses %SCRIPT_DIR%..\build)
Source: "{#PkgDir}\drivers\build\*"; DestDir: "{app}\drivers\build"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PkgDir}\drivers\setup\*"; DestDir: "{app}\drivers\setup"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{commondesktop}\OpenCert Manager"; Filename: "{app}\desktop\OpenCertManager.exe"
Name: "{commondesktop}\OpenCert Native"; Filename: "{app}\native-client.exe"
Name: "{commonstartmenu}\{#AppName}\OpenCert Manager"; Filename: "{app}\desktop\OpenCertManager.exe"
Name: "{commonstartmenu}\{#AppName}\OpenCert Native"; Filename: "{app}\native-client.exe"
Name: "{commonstartmenu}\{#AppName}\Uninstall"; Filename: "{uninstallexe}"

[Run]
; Install drivers (wrapper redirects stdin to suppress pause)
Filename: "{cmd}"; Parameters: "/C ""{app}\drivers\setup\install-drivers.bat"""; WorkingDir: "{app}\drivers"; Flags: runhidden waituntilterminated; StatusMsg: "Installing drivers..."
; Register and start client Windows service
Filename: "{sys}\sc.exe"; Parameters: "create {#SvcName} binPath= ""{app}\bin\client-card.exe"" start= auto DisplayName= ""OpenCert Client"""; Flags: runhidden waituntilterminated; StatusMsg: "Creating service..."
Filename: "{sys}\sc.exe"; Parameters: "start {#SvcName}"; Flags: runhidden waituntilterminated; StatusMsg: "Starting service..."

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#SvcName}"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete {#SvcName}"; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/C ""{app}\drivers\setup\uninstall-drivers.bat"""; WorkingDir: "{app}\drivers"; Flags: runhidden waituntilterminated
