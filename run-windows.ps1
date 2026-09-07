[CmdletBinding()]
param(
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [ValidateSet("Debug", "Release", "RelWithDebInfo")]
    [string]$Configuration = "Release",
    [ValidateSet("x64-windows", "arm64-windows")]
    [string]$Triplet = "x64-windows",
    [string]$InstallPrefix = "",
    [switch]$Install
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = $PSScriptRoot
& git -C $ProjectRoot submodule update --init --recursive
if ($LASTEXITCODE -ne 0) { throw "Git submodule initialization failed." }

if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
    $VcpkgRoot = $env:VCPKG_INSTALLATION_ROOT
}
if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
    throw "Set VCPKG_ROOT or pass -VcpkgRoot with the path to a vcpkg checkout."
}

$Toolchain = Join-Path $VcpkgRoot "scripts/buildsystems/vcpkg.cmake"
if (-not (Test-Path -LiteralPath $Toolchain -PathType Leaf)) {
    throw "The vcpkg CMake toolchain was not found at: $Toolchain"
}

$BuildDirectory = Join-Path $ProjectRoot "build-windows-$Triplet"
$ConfigureArguments = @(
    "-S", $ProjectRoot,
    "-B", $BuildDirectory,
    "-A", $(if ($Triplet -eq "arm64-windows") { "ARM64" } else { "x64" }),
    "-DCMAKE_TOOLCHAIN_FILE=$Toolchain",
    "-DVCPKG_TARGET_TRIPLET=$Triplet",
    "-DPQXDH_BUILD_TESTS=ON"
)
if (-not [string]::IsNullOrWhiteSpace($InstallPrefix)) {
    $ConfigureArguments += "-DCMAKE_INSTALL_PREFIX=$InstallPrefix"
}

& cmake @ConfigureArguments
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }

& cmake --build $BuildDirectory --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) { throw "PQXDH build failed." }

& ctest --test-dir $BuildDirectory -C $Configuration --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "PQXDH tests failed." }

if ($Install) {
    & cmake --install $BuildDirectory --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw "PQXDH installation failed." }
}
