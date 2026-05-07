$ErrorActionPreference = "Stop"

$Repo = "tyneaung-cto/tyssldoc"
$BinName = "tyssldoc.exe"
$InstallDir = Join-Path $env:USERPROFILE "bin"
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"

function Write-Info([string]$Message) {
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

function Get-Arch {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        "X64" { return "amd64" }
        default { Write-Fail "Unsupported Windows architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture). Supported: X64" }
    }
}

function Ensure-PathContainsInstallDir {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }

    $paths = $userPath -split ";" | Where-Object { $_ -ne "" }
    if ($paths -notcontains $InstallDir) {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Info "Added $InstallDir to user PATH."
    }
}

function Install-Tyssldoc {
    if (-not (Get-Command Invoke-RestMethod -ErrorAction SilentlyContinue)) {
        Write-Fail "Invoke-RestMethod is required."
    }

    $arch = Get-Arch
    $release = Invoke-RestMethod -Uri $ApiUrl
    if (-not $release.tag_name) {
        Write-Fail "Unable to determine latest release tag"
    }

    $tag = $release.tag_name
    $version = $tag.TrimStart('v')
    $archive = "tyssldoc_${version}_windows_${arch}.zip"
    $url = "https://github.com/$Repo/releases/download/$tag/$archive"

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tyssldoc-install-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -Path $tmpDir -ItemType Directory | Out-Null

    try {
        $zipPath = Join-Path $tmpDir $archive
        Write-Info "Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $zipPath

        Write-Info "Extracting archive"
        Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

        $binPath = Join-Path $tmpDir $BinName
        if (-not (Test-Path $binPath)) {
            Write-Fail "Binary not found in archive"
        }

        New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
        Copy-Item -Path $binPath -Destination (Join-Path $InstallDir $BinName) -Force

        Ensure-PathContainsInstallDir

        $installed = Join-Path $InstallDir $BinName
        if (-not (Test-Path $installed)) {
            Write-Fail "Installation failed"
        }

        Write-Info "tyssldoc installed successfully at $installed"
        & $installed --version
    }
    finally {
        if (Test-Path $tmpDir) {
            Remove-Item -Path $tmpDir -Recurse -Force
        }
    }
}

Install-Tyssldoc
