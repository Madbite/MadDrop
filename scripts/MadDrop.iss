#define AppName "MadDrop"
#define AppVersion "0.2.0"
#define SourceDir AddBackslash(SourcePath) + "..\dist\MadDrop"
#define OutputDir AddBackslash(SourcePath) + "..\dist\installer"
#define LogoPath AddBackslash(SourcePath) + "..\src\maddrop\assets\maddrop.ico"

[Setup]
AppId={{0B7F26A1-0BE2-4F97-97F7-6DAD4FBAA6D1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=MadDrop
DefaultDirName={localappdata}\Programs\MadDrop
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir={#OutputDir}
OutputBaseFilename=MadDrop-Setup-{#AppVersion}
SetupIconFile={#LogoPath}
UninstallDisplayIcon={app}\MadDrop.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\MadDrop"; Filename: "{app}\MadDrop.exe"
Name: "{autodesktop}\MadDrop"; Filename: "{app}\MadDrop.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\MadDrop.exe"; Description: "Launch MadDrop"; Flags: postinstall nowait skipifsilent
