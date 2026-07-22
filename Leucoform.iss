#define AppName "Leucoform"
#define AppVersion "0.1.0"
#define AppPublisher "Leucoform contributors"

[Setup]
AppId={{56B54F95-A7B3-49A4-ABCA-C9E6E0EFD8C2}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Leucoform
DefaultGroupName=Leucoform
OutputDir=..\..\dist\installer
OutputBaseFilename=Leucoform-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayName=Leucoform, powered by NoTUG
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\..\dist\Leucoform.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Leucoform"; Filename: "{app}\Leucoform.exe"
Name: "{autodesktop}\Leucoform"; Filename: "{app}\Leucoform.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Run]
Filename: "{app}\Leucoform.exe"; Description: "Launch Leucoform"; Flags: nowait postinstall skipifsilent
