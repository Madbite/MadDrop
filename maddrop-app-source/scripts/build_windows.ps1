param(
    [switch]$PortableOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $ProjectRoot

try {
    $Python = (Get-Command python -ErrorAction Stop).Source
    $EntryPoint = Join-Path $ProjectRoot "scripts\maddrop_launcher.py"
    $AssetDirectory = Join-Path $ProjectRoot "src\maddrop\assets"
    $Icon = Join-Path $AssetDirectory "maddrop.ico"

    if (-not (Test-Path $Icon)) {
        throw "MadDrop icon is missing: $Icon"
    }

    & $Python -m PyInstaller --version
    if ($LASTEXITCODE -ne 0) {
        throw 'PyInstaller is not installed. Run: python -m pip install -e ".[windows-build]"'
    }

    $BuildArguments = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name", "MadDrop",
        "--icon", $Icon,
        "--add-data", "$AssetDirectory;assets",
        "--collect-all", "zeroconf",
        $EntryPoint
    )
    & $Python @BuildArguments
    if ($LASTEXITCODE -ne 0) {
        throw "The Windows app build failed."
    }

    $AppFolder = Join-Path $ProjectRoot "dist\MadDrop"
    Write-Host "Portable app folder: $AppFolder"
    if ($PortableOnly) {
        return
    }

    $InnoSetup = (Get-Command ISCC.exe -ErrorAction SilentlyContinue)
    if ($InnoSetup) {
        $Compiler = $InnoSetup.Source
    }
    else {
        $Candidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        )
        $Compiler = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }

    if (-not $Compiler) {
        throw "The app folder is ready, but Inno Setup 6 is required for the installer. Install Inno Setup 6, then rerun this script."
    }

    $InstallerScript = Join-Path $ProjectRoot "scripts\MadDrop.iss"
    & $Compiler $InstallerScript
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup could not create the installer."
    }

    Write-Host "Installer created in dist\installer."
}
finally {
    Pop-Location
}
