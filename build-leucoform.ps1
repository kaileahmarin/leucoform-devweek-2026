[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipInstall,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distRoot = Join-Path $projectRoot "dist"
$buildRoot = Join-Path $projectRoot "build\leucoform"
$testVault = Join-Path $buildRoot "test-vault"
$pyinstallerConfig = Join-Path $buildRoot "pyinstaller-config"

Push-Location $projectRoot
try {
    New-Item -ItemType Directory -Force -Path $testVault, $pyinstallerConfig | Out-Null
    $env:NOTUG_HOME = $testVault
    $env:PYINSTALLER_CONFIG_DIR = $pyinstallerConfig
    if (-not $SkipInstall) {
        & $Python -m pip install --disable-pip-version-check ".[desktop,dev]" "pyinstaller>=6.10,<7"
    }
    & $Python -m ruff check src tests
    & $Python -m mypy src/notug_protocol
    $env:QT_QPA_PLATFORM = "offscreen"
    & $Python -m pytest -q -p no:cacheprovider
    & $Python -m PyInstaller --noconfirm --clean --distpath $distRoot --workpath $buildRoot packaging/Leucoform.spec

    $executable = Join-Path $distRoot "Leucoform.exe"
    if (-not (Test-Path -LiteralPath $executable)) {
        throw "PyInstaller did not create $executable"
    }
    $selfTest = Start-Process -FilePath $executable -ArgumentList "--self-test" -Wait -PassThru -WindowStyle Hidden
    if ($selfTest.ExitCode -ne 0) {
        throw "Frozen Leucoform self-test failed with exit code $($selfTest.ExitCode)"
    }
    $repositorySelfTest = Start-Process -FilePath $executable -ArgumentList @(
        "--self-test",
        "--self-test-repository",
        $projectRoot
    ) -Wait -PassThru -WindowStyle Hidden
    if ($repositorySelfTest.ExitCode -ne 0) {
        throw (
            "Frozen Leucoform repository self-test failed with exit code " +
            $repositorySelfTest.ExitCode
        )
    }

    $env:PYTHONIOENCODING = "utf-8"
    $env:NO_COLOR = "1"
    $rawSbom = Join-Path $buildRoot "pip-inspect-private.json"
    & $Python -m pip inspect --local |
        Set-Content -LiteralPath $rawSbom -Encoding utf8
    & $Python scripts/sanitize_sbom.py $rawSbom (Join-Path $distRoot "leucoform-sbom.json")
    Remove-Item -LiteralPath $rawSbom -Force
    Get-Content -LiteralPath (Join-Path $distRoot "leucoform-sbom.json") -Raw |
        ConvertFrom-Json | Out-Null
    Copy-Item -LiteralPath LICENSE, THIRD-PARTY-NOTICES.md -Destination $distRoot -Force

    if (-not $SkipInstaller) {
        $iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        $isccPath = if ($iscc) { $iscc.Source } else { $null }
        if (-not $iscc) {
            $candidates = @(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
            )
            foreach ($candidate in $candidates) {
                if (Test-Path -LiteralPath $candidate) {
                    $isccPath = (Get-Item -LiteralPath $candidate).FullName
                    break
                }
            }
        }
        if (-not $isccPath) {
            throw "Inno Setup 6 is required to create Leucoform-Setup.exe"
        }
        & $isccPath packaging/windows/Leucoform.iss
    }

    $artifacts = Get-ChildItem -LiteralPath $distRoot -File -Recurse |
        Where-Object { $_.Name -ne "SHA256SUMS.json" } |
        Sort-Object FullName
    $hashes = foreach ($artifact in $artifacts) {
        $hash = Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256
        [ordered]@{
            path = $artifact.FullName.Substring($distRoot.Length + 1).Replace("\", "/")
            sha256 = $hash.Hash.ToLowerInvariant()
            bytes = $artifact.Length
        }
    }
    $hashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $distRoot "SHA256SUMS.json") -Encoding utf8
    Write-Host "Leucoform Windows artifacts are in $distRoot"
}
finally {
    Pop-Location
}
