# Install srvs (https://github.com/srvscripts/srvs-cli) on Windows from the GitHub releases, checking the SHA-256 checksum.
#   irm https://raw.githubusercontent.com/srvscripts/srvs-cli/main/scripts/install.ps1 | iex
# Installs to %LOCALAPPDATA%\Programs\srvs and adds it to your user PATH. Set $env:SRVS_VERSION = "v0.1.0" to pin a version.
$ErrorActionPreference = 'Stop'
$repo = 'srvscripts/srvs-cli'
$version = if ($env:SRVS_VERSION) { $env:SRVS_VERSION } else { 'latest' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
if ($version -eq 'latest') {
    $rel = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$repo/releases/latest"
    $version = $rel.tag_name
}
if ($version -notmatch '^v') { throw "Could not find the latest release (got '$version')." }

$name = "srvs_$($version.TrimStart('v'))_windows_$arch"
$base = "https://github.com/$repo/releases/download/$version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("srvs-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading srvs $version for windows/$arch..."
    Invoke-WebRequest -UseBasicParsing "$base/$name.zip" -OutFile "$tmp\$name.zip"
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
    $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match " $([regex]::Escape("$name.zip"))$" }
    if (-not $line) { throw "No checksum for $name.zip" }
    $want = ($line -split '\s+')[0].ToLower()
    $got = (Get-FileHash -Algorithm SHA256 "$tmp\$name.zip").Hash.ToLower()
    if ($want -ne $got) { throw "Checksum mismatch: expected $want, got $got" }

    Expand-Archive -Path "$tmp\$name.zip" -DestinationPath $tmp -Force
    $dest = Join-Path $env:LOCALAPPDATA 'Programs\srvs'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item "$tmp\$name\srvs.exe" "$dest\srvs.exe" -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $dest) {
        [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$dest"), 'User')
        Write-Host "Added $dest to your user PATH (open a new terminal to use it)."
    }
    & "$dest\srvs.exe" version
    Write-Host 'Try: srvs check example.com'
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
